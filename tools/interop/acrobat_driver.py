#!/usr/bin/env python3
"""Open each PDF of the interop packet in Adobe Acrobat Reader and record what it shows (HRD-03).

Runs only on a GitHub Actions Windows runner (`.github/workflows/acrobat.yml`), never on a
desktop where a window could pop up unasked (docs/04 rule 17): it refuses to start unless
`GITHUB_ACTIONS=true` on Windows. The workflow has already installed Reader, set its
preferences and put the packet's test root in the machine's trusted root store
(`acrobat-setup.ps1`).

For each file in `manifest.tsv` the driver starts Reader on it, waits for validation to
finish, and records the screen: the document message bar (the banner), then the Signature
Panel, widened and expanded, then Signature Properties of each signature in it. Reader draws
its banner and panel itself, so UI Automation has no text there (only the panel's node
boxes, which tell the driver where to click); the driver reads the text from the screenshots
with Tesseract, region by region, and adds whatever UI Automation does expose (menus,
dialogs). The B-LTA files and the tampered one are opened with no PKI served (the long-term
material alone); the B-T files with `interop.py serve` answering the packet's OCSP, CRL and
AIA URLs on 127.0.0.1:47380, as the checklist's step 5.

    python -I tools/interop/acrobat_driver.py fixtures/interop --out acrobat-out

writes `acrobat-out/acrobat-report.json` (read by `acrobat_report.py`, which judges it),
`acrobat-out/*.png` (the screenshots), `*.ocr.txt` (what OCR read, by region) and
`uia-*.txt` (the UI Automation trees with element boxes). The driver itself judges nothing;
it exits non-zero only when it could not run Reader at all.
"""

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
SCHEMA = 1
READER_MAIN = ("Acrobat.exe", "AcroRd32.exe")
READER_PROCESSES = READER_MAIN + ("AcroCEF.exe", "RdrCEF.exe", "AdobeCollabSync.exe")
READER_CANDIDATES = (
    r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
    r"C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
    r"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
)
TESSERACT_CANDIDATES = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
)
# Buttons that close Reader's first-run, restore-session and upsell prompts. Never "Cancel":
# Reader's own "Progress" window (signature validation) has one.
DISMISS = ("No, thanks", "No thanks", "Not now", "Maybe later", "Skip", "Got it", "Dismiss")
BANNER_HINTS = ("signatures are valid", "certified by", "signature is invalid", "signatures is invalid",
                "has problems", "is unknown", "signed and")
BANNER_RX = re.compile("|".join(re.escape(h) for h in BANNER_HINTS), re.I)
MAX_ELEMENTS = 6000
SERVE_PORT = 47380
OCR_SCALE = 3


def log(msg):
    print(f"[acrobat {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def find_exe(given, names, candidates, what):
    if given:
        return pathlib.Path(given)
    import winreg
    for exe in names:
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}") as k:
                    p = pathlib.Path(winreg.QueryValue(k, None).strip('"'))
                    if p.is_file():
                        return p
            except OSError:
                pass
        found = shutil.which(exe)
        if found:
            return pathlib.Path(found)
    for c in candidates:
        if pathlib.Path(c).is_file():
            return pathlib.Path(c)
    sys.exit(f"acrobat_driver: {what} is not installed")


def file_version(path):
    ps = f"(Get-Item -LiteralPath '{path}').VersionInfo.ProductVersion"
    run = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    return run.stdout.strip() or "unknown"


def pids_of(names):
    run = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True)
    pids = set()
    for line in run.stdout.splitlines():
        cells = [c.strip('"') for c in line.split('","')]
        if len(cells) > 1 and cells[0] in names:
            try:
                pids.add(int(cells[1]))
            except ValueError:
                pass
    return pids


def reader_windows(desktop):
    pids = pids_of(READER_PROCESSES)
    out = []
    for w in desktop.windows():
        try:
            if w.process_id() in pids:
                out.append(w)
        except Exception:
            pass
    return out


def close_reader(desktop):
    """Quit Reader as a user would (so it does not offer to restore a crashed session next
    time), then make sure nothing of it is left."""
    from pywinauto import keyboard
    for w in reader_windows(desktop):
        try:
            if w.window_text().lower().endswith(("adobe acrobat reader (64-bit)", "adobe acrobat reader")):
                keyboard.send_keys("{ESC}")
                w.set_focus()
                keyboard.send_keys("^q")
        except Exception:
            pass
    for _ in range(30):
        if not pids_of(READER_MAIN):
            break
        for w in reader_windows(desktop):
            try:
                for b in w.descendants(control_type="Button"):
                    if (b.element_info.name or "") in ("No", "Don't Save"):
                        b.invoke()
            except Exception:
                pass
        time.sleep(1)
    for name in READER_PROCESSES:
        subprocess.run(["taskkill", "/F", "/T", "/IM", name], capture_output=True)
    time.sleep(2)


# --- what the screen says ------------------------------------------------------------------


def rect_of(el):
    r = el.element_info.rectangle
    return (r.left, r.top, r.right, r.bottom)


def elements(win):
    out = []
    try:
        items = [win] + win.descendants()
    except Exception as e:
        return [("error", f"descendants failed: {type(e).__name__}", "", "")]
    for el in items[:MAX_ELEMENTS]:
        try:
            info = el.element_info
            out.append((info.control_type or "", info.name or "", info.automation_id or "",
                        ",".join(str(v) for v in rect_of(el))))
        except Exception:
            continue
        try:
            value = el.iface_value.CurrentValue if info.control_type in ("Edit", "Document", "Text") else ""
            if value and value != info.name:
                out.append((info.control_type + ".value", value, info.automation_id or "", ""))
        except Exception:
            pass
    return out


def snapshot(desktop):
    seen = []
    for w in reader_windows(desktop):
        try:
            title = w.window_text()
        except Exception:
            title = "?"
        seen.append((title, elements(w)))
    return seen


def uia_strings(snap):
    out = []
    for title, els in snap:
        for s in [title] + [e[1] for e in els]:
            s = " ".join(str(s).split())
            if s and s not in out and not s.startswith("http") and not s.startswith("AV"):
                out.append(s)
    return out


def dump(path, label, snap):
    with open(path, "a", encoding="utf8") as f:
        f.write(f"===== {label}\n")
        for title, els in snap:
            f.write(f"--- window: {title}\n")
            for e in els:
                f.write("\t".join(e) + "\n")


def panes(win, name):
    """Reader's own views by class-like name (AVTreeNodeSimpleView, PrimaryHostView, ...)."""
    out = []
    try:
        for el in win.descendants(control_type="Pane"):
            if (el.element_info.name or "") == name:
                r = rect_of(el)
                if r[2] > r[0] and r[3] > r[1]:
                    out.append(r)
    except Exception:
        pass
    return out


class Screen:
    """Screenshots, read with Tesseract into lines with their boxes (screen coordinates).
    A region (left, top, right, bottom) is read on its own, so a narrow panel's lines are
    not merged with the page beside it."""

    def __init__(self, out_dir, tesseract):
        self.out_dir = out_dir
        self.tesseract = tesseract

    def grab(self, name=None):
        from PIL import ImageGrab
        image = ImageGrab.grab(all_screens=True)
        if name:
            image.save(self.out_dir / f"{name}.png")
        return image

    def read(self, image, region=None, label=None):
        crop = image.crop(region) if region else image
        dx, dy = (region[0], region[1]) if region else (0, 0)
        big = crop.resize((max(1, crop.width * OCR_SCALE), max(1, crop.height * OCR_SCALE))).convert("L")
        tmp = self.out_dir / "_ocr.png"
        big.save(tmp)
        run = subprocess.run([str(self.tesseract), str(tmp), "stdout", "--psm", "3", "-l", "eng", "tsv"],
                             capture_output=True, text=True, encoding="utf8", errors="replace")
        tmp.unlink()
        lines = {}
        for row in run.stdout.splitlines()[1:]:
            cells = row.split("\t")
            if len(cells) < 12 or not cells[11].strip():
                continue
            try:
                key = (int(cells[2]), int(cells[3]), int(cells[4]))
                left, top, width, height = (int(c) // OCR_SCALE for c in cells[6:10])
            except ValueError:
                continue
            lines.setdefault(key, []).append(
                (cells[11], (left + dx, top + dy, left + dx + width, top + dy + height)))
        out = []
        for words in lines.values():
            boxes = [b for _w, b in words]
            out.append({"text": " ".join(w for w, _b in words), "words": words,
                        "box": (min(b[0] for b in boxes), min(b[1] for b in boxes),
                                max(b[2] for b in boxes), max(b[3] for b in boxes))})
        if label:
            with open(self.out_dir / f"{label}.ocr.txt", "a", encoding="utf8") as f:
                f.write(f"# region {region or 'screen'}\n" + "".join(f"{ln['box']}\t{ln['text']}\n" for ln in out))
        return out

    @staticmethod
    def find_words(lines, pattern):
        """The box spanning the words of the first line matching `pattern`."""
        rx = re.compile(pattern, re.I)
        for ln in lines:
            m = rx.search(ln["text"])
            if not m:
                continue
            pos, hit = 0, []
            for w, b in ln["words"]:
                if pos + len(w) > m.start() and pos < m.end():
                    hit.append(b)
                pos += len(w) + 1
            if hit:
                return (min(b[0] for b in hit), min(b[1] for b in hit),
                        max(b[2] for b in hit), max(b[3] for b in hit))
        return None


def centre(box):
    return ((box[0] + box[2]) // 2, (box[1] + box[3]) // 2)


# --- driving Reader ------------------------------------------------------------------------


def dismiss_prompts(desktop, notes):
    """Close first-run, restore-session and upsell prompts. In the document window, only the
    restore-session prompt's own button (Reader's web view, automation id `skip-button`)."""
    for w in reader_windows(desktop):
        try:
            title = w.window_text()
            if "progress" in title.lower() or not w.is_visible():
                continue
            in_doc = title.lower().endswith(("adobe acrobat reader (64-bit)", "adobe acrobat reader"))
            for b in w.descendants(control_type="Button"):
                name = (b.element_info.name or "").strip()
                if in_doc and (b.element_info.automation_id or "") != "skip-button":
                    continue
                if name in DISMISS:
                    try:
                        b.invoke()
                    except Exception:
                        b.click_input()
                    notes.append(f"dismissed {title!r} with {name!r}")
                    time.sleep(1)
                    break
        except Exception:
            continue


def doc_window(desktop, name):
    for w in reader_windows(desktop):
        try:
            if name.lower() in w.window_text().lower():
                return w
        except Exception:
            pass
    return None


def validating(desktop):
    for w in reader_windows(desktop):
        try:
            if "progress" in w.window_text().lower():
                return True
        except Exception:
            pass
    return False


def menu_items(desktop):
    out = []
    for w in list(desktop.windows()):
        try:
            if w.element_info.control_type == "Menu" or w.element_info.class_name == "#32768":
                out += w.descendants(control_type="MenuItem")
        except Exception:
            pass
    for w in reader_windows(desktop):
        try:
            for m in w.descendants(control_type="Menu"):
                out += m.descendants(control_type="MenuItem")
        except Exception:
            pass
    return out


def context_menu_choose(desktop, pattern, notes):
    """In an open context menu, invoke the first item matching `pattern`; Escape if none."""
    from pywinauto import keyboard
    rx = re.compile(pattern, re.I)
    seen = set()
    for _ in range(4):
        for m in menu_items(desktop):
            name = m.element_info.name or ""
            seen.add(name)
            if rx.search(name):
                try:
                    m.invoke()
                except Exception:
                    m.click_input()
                notes.append(f"menu: {name!r}")
                return True
        time.sleep(1)
    notes.append(f"no menu item like {pattern!r} (saw {sorted(seen)[:25]})")
    keyboard.send_keys("{ESC}")
    return False


def run_file(desktop, screen, exe, pdf, row, served):
    from pywinauto import keyboard, mouse
    stem = pdf.stem
    entry = {"file": pdf.name, "expect": row["expect"], "level": row["level"], "served_pki": served,
             "banner": "", "texts": [], "properties": [], "screenshots": [], "notes": []}
    notes = entry["notes"]
    uia_file = screen.out_dir / f"uia-{stem}.txt"

    def shot(step, regions=()):
        """Screenshot, OCR of the whole screen and of each region, UI Automation dump."""
        name = f"{stem}-{step}"
        image = screen.grab(name)
        entry["screenshots"].append(f"{name}.png")
        lines = screen.read(image, None, name)
        for r in regions:
            lines += screen.read(image, r, name)
        snap = snapshot(desktop)
        dump(uia_file, step, snap)
        return lines, snap

    close_reader(desktop)
    subprocess.Popen([str(exe), str(pdf)])
    win, deadline = None, time.time() + 150
    while time.time() < deadline:
        dismiss_prompts(desktop, notes)
        win = doc_window(desktop, pdf.name)
        if win is not None:
            break
        time.sleep(3)
    if win is None:
        lines, snap = shot("0-nowindow")
        entry["texts"] = [ln["text"] for ln in lines] + uia_strings(snap)
        entry["error"] = "Reader's document window never appeared"
        return entry
    try:
        win.set_focus()
        win.maximize()
    except Exception:
        pass

    # Reader validates on open (bValidateOnOpen) and then writes its verdict in the message
    # bar above the page; wait for it.
    header = None
    banner = None
    t0 = time.time()
    while time.time() - t0 < 150:
        dismiss_prompts(desktop, notes)
        if not validating(desktop):
            heads = panes(win, "AVDocumentHeaderView")
            header = heads[0] if heads else None
            if header:
                lines = screen.read(screen.grab(), header)
                banner = next((ln for ln in lines if BANNER_RX.search(ln["text"])), None)
                if banner:
                    break
        time.sleep(3)
    notes.append(f"banner after {time.time() - t0:.0f} s" if banner else "no banner within 150 s")
    time.sleep(2)
    lines, snap = shot("1-opened", [header] if header else [])
    texts = [ln["text"] for ln in lines]
    entry["banner"] = " ".join(ln["text"] for ln in (screen.read(screen.grab(), header) if header else [])
                               if BANNER_RX.search(ln["text"]) or "unknown" in ln["text"].lower())

    # The Signature Panel: the banner's button, found by OCR; else View > Show/Hide.
    button = Screen.find_words(lines, r"signature\s*panel|signature\s*p")
    if button is not None:
        mouse.click(coords=centre(button))
        notes.append("opened the panel from the banner's button")
    else:
        try:
            win.menu_select("View->Show/Hide->Navigation Panes->Signatures")
            notes.append("opened the panel from the View menu")
        except Exception as e:
            notes.append(f"could not open the panel: {type(e).__name__}: {e}")
    time.sleep(4)
    # Widen it, so its lines are not cut off: drag its right edge most of the way across.
    hosts = panes(win, "PrimaryHostView")
    if hosts:
        left, top, right, bottom = hosts[0]
        target = max(right, int(win.rectangle().width() * 0.72))
        y = (top + bottom) // 2
        mouse.press(coords=(right + 1, y))
        for x in range(right + 1, target, 40):
            mouse.move(coords=(x, y))
        mouse.release(coords=(target, y))
        time.sleep(2)
        notes.append(f"panel widened from {right} to {target}")
    hosts = panes(win, "PrimaryHostView")
    lines, snap = shot("2-panel", hosts[:1])
    texts += [ln["text"] for ln in lines]

    # Expand every signature: click each top-level node's chevron, bottom first so the
    # positions above do not move.
    nodes = panes(win, "AVTreeNodeSimpleView")
    if nodes:
        indent = min(n[0] for n in nodes)
        tops = sorted((n for n in nodes if n[0] == indent), key=lambda n: -n[1])
        for n in tops:
            mouse.click(coords=(n[0] + 12, (n[1] + n[3]) // 2))
            time.sleep(1.5)
        notes.append(f"expanded {len(tops)} signature node(s)")
        time.sleep(3)
    hosts = panes(win, "PrimaryHostView")
    lines, snap = shot("3-expanded", hosts[:1])
    texts += [ln["text"] for ln in lines]

    # Signature Properties of each top-level node (the seal, the document timestamp).
    nodes = panes(win, "AVTreeNodeSimpleView")
    if nodes:
        indent = min(n[0] for n in nodes)
        tops = sorted((n for n in nodes if n[0] == indent), key=lambda n: n[1])
        for i, n in enumerate(tops[:3]):
            mouse.right_click(coords=((n[0] + n[2]) // 2, (n[1] + n[3]) // 2))
            time.sleep(1.5)
            if not context_menu_choose(desktop, r"signature properties|^properties|show .*properties", notes):
                continue
            time.sleep(5)
            plines, psnap = shot(f"4-properties-{i}")
            entry["properties"] += [ln["text"] for ln in plines] + uia_strings(psnap)
            keyboard.send_keys("{ESC}")
            time.sleep(1.5)
            # Positions shift if a dialog changed the panel; read them again.
            nodes = panes(win, "AVTreeNodeSimpleView")
            if not nodes:
                break
    entry["texts"] = texts + uia_strings(snap)
    return entry


def start_serve(packet, out_dir):
    logf = open(out_dir / "serve.log", "w", encoding="utf8")
    proc = subprocess.Popen([sys.executable, "-I", "-u", str(HERE / "interop.py"), "serve", str(packet)],
                            stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", SERVE_PORT), timeout=1).close()
            return proc
        except OSError:
            time.sleep(1)
    proc.kill()
    sys.exit("acrobat_driver: interop.py serve did not start (see serve.log)")


def main(argv):
    ap = argparse.ArgumentParser(prog="acrobat_driver.py", description=__doc__.splitlines()[0])
    ap.add_argument("packet")
    ap.add_argument("--out", required=True)
    ap.add_argument("--reader", help="Reader's executable (default: found from the registry)")
    ap.add_argument("--tesseract", help="tesseract.exe (default: found on PATH or in Program Files)")
    ap.add_argument("--trust-method", default="unknown", help="how the test root was trusted (recorded)")
    args = ap.parse_args(argv[1:])
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        sys.exit("acrobat_driver: runs only on a GitHub Actions Windows runner (docs/04 rule 17)")
    from pywinauto import Desktop

    packet = pathlib.Path(args.packet).resolve()
    out_dir = pathlib.Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    head, *lines = [ln for ln in (packet / "manifest.tsv").read_text(encoding="utf8").splitlines() if ln]
    rows = [dict(zip(head.split("\t"), ln.split("\t"))) for ln in lines]
    exe = find_exe(args.reader, READER_MAIN, READER_CANDIDATES, "Acrobat Reader")
    tesseract = find_exe(args.tesseract, ("tesseract.exe",), TESSERACT_CANDIDATES, "Tesseract OCR")
    screen = Screen(out_dir, tesseract)
    size = screen.grab().size
    report = {"schema": SCHEMA, "reader": str(exe), "reader_version": file_version(exe),
              "os": f"{platform.system()} {platform.version()}", "screen": list(size),
              "trust": {"method": args.trust_method},
              "text_source": "Tesseract OCR of screenshots, and UI Automation", "files": []}
    log(f"Reader {report['reader_version']} at {exe}; OCR {tesseract}; screen {size}")
    desktop = Desktop(backend="uia")
    # Long-term material alone first (B-LTA, tampered), then B-T with the PKI served.
    offline = [r for r in rows if r["level"] != "B-T"]
    online = [r for r in rows if r["level"] == "B-T"]
    for r in offline:
        log(f"open {r['file']} (no PKI served)")
        report["files"].append(run_file(desktop, screen, exe, packet / r["file"], r, False))
    if online:
        serve = start_serve(packet, out_dir)
        try:
            for r in online:
                log(f"open {r['file']} (PKI served on 127.0.0.1:{SERVE_PORT})")
                report["files"].append(run_file(desktop, screen, exe, packet / r["file"], r, True))
        finally:
            serve.terminate()
    close_reader(desktop)
    (out_dir / "acrobat-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                                 encoding="utf8")
    for e in report["files"]:
        log(f"{e['file']}: banner {e['banner']!r}; {'; '.join(e['notes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
