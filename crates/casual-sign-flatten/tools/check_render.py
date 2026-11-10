"""Independent check of flattened outputs (T-1E, FILL-01): PDFium renders, pypdf reads.

    FLATTEN_DUMP_DIR=<dir> cargo test -p casual-sign-flatten
    <venv>/bin/python -I crates/casual-sign-flatten/tools/check_render.py <dir> [<png-dir>]

Needs pypdfium2 (PDFium, BSD-3-Clause/Apache-2.0) and pypdf (BSD-3-Clause) in a venv;
nothing is installed into the system Python. For each entry of every <dir>/manifest*.json the
input and the output are rendered at 2x and compared pixel by pixel:

- every field that should show a value has changed pixels inside its rectangle;
- every field that should show nothing has none;
- no pixel changed outside the fields' rectangles (2 px of anti-aliasing allowed);
- pypdf extracts every expected string from the output (so ToUnicode works).

For fill-in-place entries ("fill": true) it also checks that pypdf reads each field's
/V and that the AcroForm is still there. Exits non-zero naming every failure.
"""

import json
import sys
from pathlib import Path

import pypdf
import pypdfium2 as pdfium

SCALE = 2.0
MARGIN = 3  # pixels of anti-aliasing allowed around a field
THRESHOLD = 40  # a channel difference that counts as ink
MIN_INK = 4  # pixels that make "ink"


def render(path):
    pdf = pdfium.PdfDocument(str(path))
    # Widgets are drawn only with the form environment initialised.
    pdf.init_forms()
    page = pdf[0]
    # may_draw_forms renders widget appearances, as a viewer does.
    bitmap = page.render(scale=SCALE, may_draw_forms=True)
    img = bitmap.to_pil().convert("RGB")
    pdf.close()
    return img


def changed(a, b):
    """Set of (x, y) pixels that differ."""
    w, h = a.size
    pa, pb = a.load(), b.load()
    out = set()
    for y in range(h):
        for x in range(w):
            p, q = pa[x, y], pb[x, y]
            if max(abs(p[0] - q[0]), abs(p[1] - q[1]), abs(p[2] - q[2])) > THRESHOLD:
                out.add((x, y))
    return out


def squash(s):
    return "".join(s.split())


def check(entry, base, png_dir):
    fails = []
    a = render(base / entry["in"])
    b = render(base / entry["out"])
    if a.size != b.size:
        return [f"{entry['name']}: page size changed {a.size} -> {b.size}"]
    sx = a.size[0] / entry["size"][0]
    sy = a.size[1] / entry["size"][1]
    diff = changed(a, b)
    boxes = []
    for f in entry["fields"]:
        x, y, w, h = (float(v) for v in f["rect"])
        box = (
            int(x * sx) - MARGIN,
            int(y * sy) - MARGIN,
            int((x + w) * sx) + MARGIN,
            int((y + h) * sy) + MARGIN,
        )
        boxes.append(box)
        inside = sum(1 for (px, py) in diff if box[0] <= px <= box[2] and box[1] <= py <= box[3])
        if f["ink"] and inside < MIN_INK:
            fails.append(f"{entry['name']}: field {f['id']} has no ink ({inside} px)")
        if not f["ink"] and inside:
            fails.append(f"{entry['name']}: field {f['id']} should be blank, {inside} px changed")
    outside = [p for p in diff if not any(b0 <= p[0] <= b2 and b1 <= p[1] <= b3 for (b0, b1, b2, b3) in boxes)]
    if outside:
        fails.append(f"{entry['name']}: {len(outside)} px changed outside the fields, e.g. {sorted(outside)[:3]}")
    reader = pypdf.PdfReader(str(base / entry["out"]))
    text = squash(reader.pages[0].extract_text())
    for t in entry.get("texts", []):
        if squash(t) not in text:
            fails.append(f"{entry['name']}: text {t!r} not extracted")
    if entry.get("fill"):
        got = reader.get_fields() or {}
        for name, want in entry.get("values", {}).items():
            v = got.get(name, {}).get("/V")
            if str(v) != want:
                fails.append(f"{entry['name']}: /V of {name!r} is {v!r}, want {want!r}")
        if "/AcroForm" not in reader.trailer["/Root"]:
            fails.append(f"{entry['name']}: AcroForm gone")
    if png_dir:
        b.save(Path(png_dir) / (entry["name"] + ".png"))
    return fails, len(diff)


def main():
    base = Path(sys.argv[1])
    png_dir = sys.argv[2] if len(sys.argv) > 2 else None
    if png_dir:
        Path(png_dir).mkdir(parents=True, exist_ok=True)
    manifest = []
    for m in sorted(base.glob("manifest*.json")):
        manifest.extend(json.loads(m.read_text()))
    all_fails = []
    for entry in manifest:
        result = check(entry, base, png_dir)
        if isinstance(result, list):
            fails, n = result, 0
        else:
            fails, n = result
        ink = sum(1 for f in entry["fields"] if f["ink"])
        status = "ok" if not fails else "FAIL"
        print(f"{status:4} {entry['name']}: {ink} fields with ink, {len(entry['fields']) - ink} blank, "
              f"{n} px changed, {len(entry.get('texts', []))} texts")
        all_fails.extend(fails)
    for f in all_fails:
        print("  " + f)
    print(f"{len(manifest)} documents, {len(all_fails)} failures")
    sys.exit(1 if all_fails else 0)


if __name__ == "__main__":
    main()
