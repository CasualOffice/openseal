#!/usr/bin/env python3
"""Open each PDF of the interop packet in Adobe Acrobat Reader and record what it shows (HRD-03).

Runs only on a GitHub Actions Windows runner (`.github/workflows/acrobat.yml`), never on a
desktop where a window could pop up unasked (docs/04 rule 17): it refuses to start unless
`GITHUB_ACTIONS=true` on Windows. The workflow has already installed Reader, set its
preferences and put the packet's test root in the machine's trusted root store
(`acrobat-setup.ps1`).

For each file in `manifest.tsv`, the driver starts Reader on it, waits for the signature
banner, opens the Signature Panel, expands it, opens Signature Properties of each signature,
and records every string Reader's windows expose through UI Automation, with screenshots of
the whole screen at each step. The B-LTA files and the tampered one are opened with no PKI
served (the long-term material alone); the B-T files with `interop.py serve` answering the
packet's OCSP, CRL and AIA URLs on 127.0.0.1:47380, as the checklist's step 5.

    python -I tools/interop/acrobat_driver.py fixtures/interop --out acrobat-out

writes `acrobat-out/acrobat-report.json` (read by `acrobat_report.py`, which judges it),
`acrobat-out/*.png` and `acrobat-out/uia-*.txt` (the raw UI Automation trees, for when a
Reader release words things differently). The driver itself judges nothing; it exits
non-zero only when it could not run Reader at all.
"""

import argparse
import json
import os
import pathlib
import platform
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
    r"C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
)
# Buttons that close Reader's first-run and upsell prompts; never anything that changes trust.
DISMISS = ("Accept", "No", "Not now", "No, thanks", "No thanks", "Maybe later", "Skip", "Close",
           "Continue", "Got it", "OK", "Dismiss", "Cancel")
BANNER_HINTS = ("signatures are valid", "certified by", "signature is invalid", "signatures is invalid",
                "has problems", "validity is unknown", "signed and")
MAX_ELEMENTS = 6000
SERVE_PORT = 47380


def log(msg):
    print(f"[acrobat {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def find_reader(given):
    if given:
        return pathlib.Path(given)
    import winreg
    for exe in ("Acrobat.exe", "AcroRd32.exe"):
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}") as k:
                    p = pathlib.Path(winreg.QueryValue(k, None).strip('"'))
                    if p.is_file():
                        return p
            except OSError:
                pass
    for c in READER_CANDIDATES:
        if pathlib.Path(c).is_file():
            return pathlib.Path(c)
    sys.exit("acrobat_driver: Acrobat Reader is not installed")


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


def kill_reader():
    for name in READER_PROCESSES:
        subprocess.run(["taskkill", "/F", "/T", "/IM", name], capture_output=True)
    time.sleep(2)


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


def elements(win):
    """(control type, name, automation id) for the window and its descendants, in tree order."""
    out = []
    try:
        items = [win] + win.descendants()
    except Exception as e:
        return [("error", f"descendants failed: {type(e).__name__}", "")]
    for el in items[:MAX_ELEMENTS]:
        try:
            info = el.element_info
            out.append((info.control_type or "", info.name or "", info.automation_id or ""))
        except Exception:
            continue
        try:
            value = el.iface_value.CurrentValue if info.control_type in ("Edit", "Document", "Text") else ""
            if value and value != info.name:
                out.append((info.control_type + ".value", value, info.automation_id or ""))
        except Exception:
            pass
    return out


def snapshot(desktop):
    """Every Reader window's title and element strings."""
    seen = []
    for w in reader_windows(desktop):
        try:
            title = w.window_text()
        except Exception:
            title = "?"
        seen.append((title, elements(w)))
    return seen


def strings(snap):
    out = []
    for title, els in snap:
        for s in [title] + [name for _t, name, _a in els]:
            s = " ".join(str(s).split())
            if s and s not in out:
                out.append(s)
    return out


def dump(path, label, snap):
    with open(path, "a", encoding="utf8") as f:
        f.write(f"===== {label}\n")
        for title, els in snap:
            f.write(f"--- window: {title}\n")
            for t, name, aid in els:
                f.write(f"{t}\t{name}\t{aid}\n")


def screenshot(path):
    try:
        from PIL import ImageGrab
        ImageGrab.grab(all_screens=True).save(path)
        return path.name
    except Exception as e:
        log(f"screenshot {path.name} failed: {e}")
        return None


def click(el):
    try:
        el.invoke()
        return True
    except Exception:
        pass
    try:
        el.click_input()
        return True
    except Exception:
        return False


def dismiss_prompts(desktop, doc_title, notes):
    """Close first-run, sign-in and upsell prompts: windows other than the document's."""
    for w in reader_windows(desktop):
        try:
            title = w.window_text()
            if doc_title and doc_title.lower() in title.lower():
                continue
            if not w.is_visible():
                continue
            for b in w.descendants(control_type="Button"):
                name = (b.element_info.name or "").strip()
                if name in DISMISS and click(b):
                    notes.append(f"dismissed prompt {title!r} with {name!r}")
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


def expand_all(win, notes, rounds=4):
    expanded = 0
    for _ in range(rounds):
        changed = False
        try:
            items = win.descendants(control_type="TreeItem")
        except Exception:
            items = []
        for it in items:
            try:
                if it.is_expanded():
                    continue
                it.expand()
                expanded += 1
                changed = True
            except Exception:
                continue
        if not changed:
            break
        time.sleep(1)
    notes.append(f"expanded {expanded} tree item(s)")


def open_signature_panel(win, notes):
    import re
    pat = re.compile(r"signature panel|^signatures$|view signatures", re.I)
    try:
        for b in win.descendants():
            name = b.element_info.name or ""
            if pat.search(name) and b.element_info.control_type in ("Button", "Hyperlink", "MenuItem", "TabItem"):
                if click(b):
                    notes.append(f"opened the panel with {b.element_info.control_type} {name!r}")
                    return True
    except Exception as e:
        notes.append(f"panel search failed: {type(e).__name__}")
    notes.append("no Signature Panel control found")
    return False


def signature_properties(desktop, win, out_dir, stem, notes, entry):
    """Right-click each signature in the panel and open Signature Properties; record its text."""
    import re
    from pywinauto import keyboard
    pat = re.compile(r"^(rev\.\s*\d+|.*signed by|.*certified by|.*timestamp)", re.I)
    try:
        sigs = [t for t in win.descendants(control_type="TreeItem") if pat.match(t.element_info.name or "")]
    except Exception:
        sigs = []
    for i, item in enumerate(sigs[:3]):
        try:
            item.select()
        except Exception:
            pass
        try:
            item.click_input(button="right")
            time.sleep(1.5)
            menu_items = [m for w in reader_windows(desktop) for m in w.descendants(control_type="MenuItem")]
            target = next((m for m in menu_items if "properties" in (m.element_info.name or "").lower()), None)
            if target is None:
                keyboard.send_keys("{ESC}")
                notes.append(f"no properties item in the menu of {item.element_info.name!r}")
                continue
            click(target)
            time.sleep(4)
            snap = snapshot(desktop)
            dump(out_dir / f"uia-{stem}.txt", f"properties {i}", snap)
            entry["properties"] += [s for s in strings(snap) if s not in entry["properties"]]
            shot = screenshot(out_dir / f"{stem}-3-properties-{i}.png")
            if shot:
                entry["screenshots"].append(shot)
            for w in reader_windows(desktop):
                if "properties" in w.window_text().lower():
                    for b in w.descendants(control_type="Button"):
                        if (b.element_info.name or "") in ("Close", "OK"):
                            click(b)
                            break
            time.sleep(1)
        except Exception as e:
            notes.append(f"properties {i} failed: {type(e).__name__}: {e}")


def run_file(desktop, exe, pdf, out_dir, row, served):
    from pywinauto import keyboard
    stem = pdf.stem
    entry = {"file": pdf.name, "expect": row["expect"], "level": row["level"], "served_pki": served,
             "banner": "", "texts": [], "properties": [], "screenshots": [], "notes": []}
    notes = entry["notes"]
    kill_reader()
    subprocess.Popen([str(exe), str(pdf)])
    win, deadline = None, time.time() + 150
    while time.time() < deadline:
        dismiss_prompts(desktop, pdf.name, notes)
        win = doc_window(desktop, pdf.name)
        if win is not None:
            break
        time.sleep(3)
    if win is None:
        snap = snapshot(desktop)
        dump(out_dir / f"uia-{stem}.txt", "no document window", snap)
        entry["texts"] = strings(snap)
        shot = screenshot(out_dir / f"{stem}-0-nowindow.png")
        entry["screenshots"] += [shot] if shot else []
        entry["error"] = "Reader's document window never appeared"
        return entry
    try:
        win.set_focus()
        win.maximize()
    except Exception:
        pass
    # Reader validates on open (bValidateOnOpen); wait until the banner says something.
    deadline = time.time() + 60
    while time.time() < deadline:
        dismiss_prompts(desktop, pdf.name, notes)
        texts = strings(snapshot(desktop))
        if any(h in t.lower() for t in texts for h in BANNER_HINTS):
            break
        time.sleep(3)
    time.sleep(3)
    snap = snapshot(desktop)
    dump(out_dir / f"uia-{stem}.txt", "opened", snap)
    shot = screenshot(out_dir / f"{stem}-1-opened.png")
    entry["screenshots"] += [shot] if shot else []
    win = doc_window(desktop, pdf.name) or win
    if open_signature_panel(win, notes):
        time.sleep(4)
    expand_all(win, notes)
    time.sleep(2)
    snap = snapshot(desktop)
    dump(out_dir / f"uia-{stem}.txt", "panel", snap)
    shot = screenshot(out_dir / f"{stem}-2-panel.png")
    entry["screenshots"] += [shot] if shot else []
    entry["texts"] = strings(snap)
    signature_properties(desktop, win, out_dir, stem, notes, entry)
    banners = [t for t in entry["texts"] if any(h in t.lower() for h in BANNER_HINTS)]
    entry["banner"] = banners[0] if banners else ""
    try:
        keyboard.send_keys("{ESC}")
    except Exception:
        pass
    return entry


def start_serve(packet, out_dir):
    logf = open(out_dir / "serve.log", "w", encoding="utf8")
    proc = subprocess.Popen([sys.executable, "-I", str(HERE / "interop.py"), "serve", str(packet)],
                            stdout=logf, stderr=subprocess.STDOUT)
    import socket
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
    exe = find_reader(args.reader)
    report = {"schema": SCHEMA, "reader": str(exe), "reader_version": file_version(exe),
              "os": f"{platform.system()} {platform.version()}", "trust": {"method": args.trust_method},
              "files": []}
    log(f"Reader {report['reader_version']} at {exe}")
    desktop = Desktop(backend="uia")
    # Long-term material alone first (B-LTA, tampered), then B-T with the PKI served.
    offline = [r for r in rows if r["level"] != "B-T"]
    online = [r for r in rows if r["level"] == "B-T"]
    for r in offline:
        log(f"open {r['file']} (no PKI served)")
        report["files"].append(run_file(desktop, exe, packet / r["file"], out_dir, r, False))
    if online:
        serve = start_serve(packet, out_dir)
        try:
            for r in online:
                log(f"open {r['file']} (PKI served on 127.0.0.1:{SERVE_PORT})")
                report["files"].append(run_file(desktop, exe, packet / r["file"], out_dir, r, True))
        finally:
            serve.terminate()
    kill_reader()
    (out_dir / "acrobat-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                                 encoding="utf8")
    for e in report["files"]:
        log(f"{e['file']}: banner {e['banner']!r}; {'; '.join(e['notes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
