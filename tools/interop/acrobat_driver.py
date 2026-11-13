#!/usr/bin/env python3
"""Open each PDF of the interop packet in Adobe Acrobat Reader and record what it shows (HRD-03).

Runs only on a GitHub Actions Windows runner (`.github/workflows/acrobat.yml`), never on a
desktop where a window could pop up unasked (docs/04 rule 17): it refuses to start unless
`GITHUB_ACTIONS=true` on Windows. The workflow has already installed Reader, set its
preferences and put the packet's test root in the machine's trusted root store
(`acrobat-setup.ps1`).

For each file in `manifest.tsv` the driver starts Reader on it, waits for validation to
finish, and records the screen: the document message bar (the banner), then the Signature
Panel, expanded, then Signature Properties of each signature in it. Reader draws its banner
and panel itself, so UI Automation sees no text there; the driver reads them from the
screenshots with Tesseract OCR (word boxes also tell it where to click), and adds whatever
UI Automation does expose (menus, dialogs). The B-LTA files and the tampered one are opened
with no PKI served (the long-term material alone); the B-T files with `interop.py serve`
answering the packet's OCSP, CRL and AIA URLs on 127.0.0.1:47380, as the checklist's step 5.

    python -I tools/interop/acrobat_driver.py fixtures/interop --out acrobat-out

writes `acrobat-out/acrobat-report.json` (read by `acrobat_report.py`, which judges it),
`acrobat-out/*.png` (the screenshots), `*.ocr.txt` (what OCR read from each) and
`uia-*.txt` (the raw UI Automation trees). The driver itself judges nothing; it exits
non-zero only when it could not run Reader at all.
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
READER_PROCESSES = ("Acrobat.exe", "AcroRd32.exe", "AcroCEF.exe", "RdrCEF.exe", "AdobeCollabSync.exe")
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
DISMISS = ("No, thanks", "No thanks", "Not now", "Maybe later", "Skip", "Got it", "Dismiss", "Close", "No")
NEVER_DISMISS = ("progress",)
BANNER_HINTS = ("signatures are valid", "certified by", "signature is invalid", "signatures is invalid",
                "has problems", "validity is unknown", "signed and")
MAX_ELEMENTS = 6000
SERVE_PORT = 47380
OCR_SCALE = 2


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


def reader_pids():
    run = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True)
    pids = set()
    for line in run.stdout.splitlines():
        cells = [c.strip('"') for c in line.split('","')]
        if len(cells) > 1 and cells[0] in READER_PROCESSES:
            try:
                pids.add(int(cells[1]))
            except ValueError:
                pass
    return pids


def reader_windows(desktop):
    pids = reader_pids()
    out = []
    for w in desktop.windows():
        try:
            if w.process_id() in pids:
                out.append(w)
        except Exception:
            pass
    return out


def close_reader(desktop):
    """Close Reader as a user would (so it does not offer to restore a crashed session next
    time), then make sure nothing of it is left."""
    for w in reader_windows(desktop):
        try:
            w.close()
        except Exception:
            pass
    for _ in range(10):
        if not reader_pids():
            return
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


def elements(win):
    out = []
    try:
        items = [win] + win.descendants()
    except Exception as e:
        return [("error", f"descendants failed: {type(e).__name__}", "", "")]
    for el in items[:MAX_ELEMENTS]:
        try:
            info = el.element_info
            r = info.rectangle
            out.append((info.control_type or "", info.name or "", info.automation_id or "",
                        f"{r.left},{r.top},{r.right},{r.bottom}"))
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
            if s and s not in out and not s.startswith("http"):
                out.append(s)
    return out


def dump(path, label, snap):
    with open(path, "a", encoding="utf8") as f:
        f.write(f"===== {label}\n")
        for title, els in snap:
            f.write(f"--- window: {title}\n")
            for e in els:
                f.write("\t".join(e) + "\n")


class Screen:
    """Screenshots, OCR'd with Tesseract into lines with their boxes (screen coordinates)."""

    def __init__(self, out_dir, tesseract):
        self.out_dir = out_dir
        self.tesseract = tesseract

    def capture(self, name):
        from PIL import ImageGrab
        path = self.out_dir / f"{name}.png"
        image = ImageGrab.grab(all_screens=True)
        image.save(path)
        big = image.resize((image.width * OCR_SCALE, image.height * OCR_SCALE)).convert("L")
        big_path = self.out_dir / f"_{name}.ocr.png"
        big.save(big_path)
        run = subprocess.run([str(self.tesseract), str(big_path), "stdout", "--psm", "3", "-l", "eng", "tsv"],
                             capture_output=True, text=True, encoding="utf8", errors="replace")
        big_path.unlink()
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
            line = lines.setdefault(key, {"words": [], "boxes": []})
            line["words"].append(cells[11])
            line["boxes"].append((left, top, left + width, top + height))
        out = []
        for line in lines.values():
            text = " ".join(line["words"])
            box = (min(b[0] for b in line["boxes"]), min(b[1] for b in line["boxes"]),
                   max(b[2] for b in line["boxes"]), max(b[3] for b in line["boxes"]))
            out.append({"text": text, "box": box, "words": list(zip(line["words"], line["boxes"]))})
        (self.out_dir / f"{name}.ocr.txt").write_text(
            "\n".join(f"{ln['box']}\t{ln['text']}" for ln in out) + "\n", encoding="utf8")
        return path.name, out

    @staticmethod
    def find(lines, pattern, region=None):
        """The first OCR line matching `pattern` (inside `region` if given): (text, box)."""
        rx = re.compile(pattern, re.I)
        for ln in lines:
            x0, y0, x1, y1 = ln["box"]
            if region and not (region[0] <= x0 and x1 <= region[2] and region[1] <= y0 and y1 <= region[3]):
                continue
            if rx.search(ln["text"]):
                return ln
        return None


def centre(box):
    return ((box[0] + box[2]) // 2, (box[1] + box[3]) // 2)


# --- driving Reader ------------------------------------------------------------------------


def dismiss_prompts(desktop, notes):
    """Close first-run, restore-session and upsell prompts, wherever they are drawn."""
    for w in reader_windows(desktop):
        try:
            title = w.window_text()
            if any(n in title.lower() for n in NEVER_DISMISS) or not w.is_visible():
                continue
            for b in w.descendants(control_type="Button"):
                name = (b.element_info.name or "").strip()
                aid = b.element_info.automation_id or ""
                in_doc = title.lower().endswith(("adobe acrobat reader (64-bit)", "adobe acrobat reader"))
                # In the document window only the web-view prompts' own buttons (restore session).
                if in_doc and aid not in ("skip-button",):
                    continue
                if name in DISMISS:
                    b.invoke()
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


def menu_texts(desktop):
    out = []
    for w in reader_windows(desktop) + list(desktop.windows(control_type="Menu")):
        try:
            for m in w.descendants(control_type="MenuItem"):
                out.append(m)
        except Exception:
            pass
    return out


def context_menu_choose(desktop, pattern, notes):
    """In an open context menu, invoke the first item matching `pattern`; Escape if none."""
    from pywinauto import keyboard
    rx = re.compile(pattern, re.I)
    for _ in range(5):
        items = menu_texts(desktop)
        for m in items:
            name = m.element_info.name or ""
            if rx.search(name):
                try:
                    m.invoke()
                except Exception:
                    m.click_input()
                notes.append(f"menu: {name!r}")
                return True
        time.sleep(1)
    names = sorted({m.element_info.name or "" for m in menu_texts(desktop)})
    notes.append(f"no menu item like {pattern!r} (saw {names[:30]})")
    keyboard.send_keys("{ESC}")
    return False


def run_file(desktop, screen, exe, pdf, row, served):
    from pywinauto import keyboard, mouse
    stem = pdf.stem
    out_dir = screen.out_dir
    entry = {"file": pdf.name, "expect": row["expect"], "level": row["level"], "served_pki": served,
             "banner": "", "texts": [], "properties": [], "screenshots": [], "notes": []}
    notes = entry["notes"]
    uia_file = out_dir / f"uia-{stem}.txt"

    def shot(step):
        name, lines = screen.capture(f"{stem}-{step}")
        entry["screenshots"].append(name)
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
    # Reader validates on open (bValidateOnOpen) behind a "Progress" window; let it finish.
    deadline = time.time() + 90
    time.sleep(5)
    while time.time() < deadline and validating(desktop):
        time.sleep(2)
    time.sleep(3)
    dismiss_prompts(desktop, notes)
    time.sleep(1)
    lines, snap = shot("1-opened")
    texts = [ln["text"] for ln in lines]
    banner = Screen.find(lines, "|".join(re.escape(h) for h in BANNER_HINTS))
    entry["banner"] = banner["text"] if banner else ""

    # The Signature Panel: the banner's button, found by OCR; else View > Show/Hide.
    button = Screen.find(lines, r"signature\s*panel")
    opened = False
    if button is not None:
        mouse.click(coords=centre(button["box"]))
        notes.append("opened the panel from the banner's button")
        opened = True
    else:
        try:
            win.menu_select("View->Show/Hide->Navigation Panes->Signatures")
            notes.append("opened the panel from the View menu")
            opened = True
        except Exception as e:
            notes.append(f"could not open the panel: {type(e).__name__}: {e}")
    time.sleep(4)
    lines, snap = shot("2-panel")
    texts += [ln["text"] for ln in lines]
    # The panel's rows: "Rev. 1: Signed by …", "Certified by …", the document timestamp.
    width = win.rectangle().width() if opened else 0
    panel = (0, 150, max(420, width // 2), 760)
    rows = [ln for ln in lines if re.search(r"^\s*rev\.?\s*\d|signed by|certified by|timestamp", ln["text"], re.I)
            and panel[0] <= ln["box"][0] <= panel[2] and ln["box"][1] >= panel[1]]
    notes.append(f"panel rows: {[r['text'] for r in rows]}")
    if rows:
        # Expand everything: the panel's context menu has "Expand All".
        mouse.right_click(coords=centre(rows[0]["box"]))
        time.sleep(1.5)
        if context_menu_choose(desktop, r"expand all|^expand$", notes):
            time.sleep(3)
        lines, snap = shot("3-expanded")
        texts += [ln["text"] for ln in lines]
        rows = [ln for ln in lines if re.search(r"^\s*rev\.?\s*\d|certified by|signed by", ln["text"], re.I)
                and panel[0] <= ln["box"][0] <= panel[2] and ln["box"][1] >= panel[1]]
        # Signature Properties of each signature row (the seal, then the document timestamp).
        for i, r in enumerate(rows[:3]):
            mouse.right_click(coords=centre(r["box"]))
            time.sleep(1.5)
            if not context_menu_choose(desktop, r"properties", notes):
                continue
            time.sleep(4)
            plines, psnap = shot(f"4-properties-{i}")
            entry["properties"] += [ln["text"] for ln in plines] + uia_strings(psnap)
            keyboard.send_keys("{ESC}")
            time.sleep(1.5)
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
    exe = find_exe(args.reader, ("Acrobat.exe", "AcroRd32.exe"), READER_CANDIDATES, "Acrobat Reader")
    tesseract = find_exe(args.tesseract, ("tesseract.exe",), TESSERACT_CANDIDATES, "Tesseract OCR")
    report = {"schema": SCHEMA, "reader": str(exe), "reader_version": file_version(exe),
              "os": f"{platform.system()} {platform.version()}", "trust": {"method": args.trust_method},
              "text_source": "Tesseract OCR of screenshots, and UI Automation", "files": []}
    log(f"Reader {report['reader_version']} at {exe}; OCR {tesseract}")
    desktop = Desktop(backend="uia")
    screen = Screen(out_dir, tesseract)
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
