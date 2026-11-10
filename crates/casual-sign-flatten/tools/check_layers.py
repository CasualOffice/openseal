"""Independent check of optional content and annotation flattening (FLT-03, FLT-04).

    FLATTEN_DUMP_DIR=<dir> cargo test -p casual-sign-flatten --test optional
    <venv>/bin/python -I crates/casual-sign-flatten/tools/check_layers.py <dir>

Needs pypdfium2 and pypdf in a venv (as check_render.py). For each entry of
<dir>/layers.json:

- PDFium renders the input (which honours its optional content and annotation flags)
  and the output (which has neither): the pages must look the same, so the sealed page
  is what a viewer showed the signer;
- PDFium's and pypdf's text of the output hold every "shown" word and no "hidden" one.

For each entry of <dir>/checkbox.json: PDFium draws the box's own colour (blue) inside
its rectangle. Exits non-zero naming every failure.
"""

import json
import logging
import sys
from pathlib import Path

import pypdf
import pypdfium2 as pdfium

logging.disable(logging.WARNING)

SCALE = 2.0
THRESHOLD = 40
# Anti-aliasing can differ where glyphs are drawn through another path.
MAX_DIFF_PX = 40


def render(path):
    pdf = pdfium.PdfDocument(str(path))
    pdf.init_forms()
    page = pdf[0]
    img = page.render(scale=SCALE, may_draw_forms=True).to_pil().convert("RGB")
    text = page.get_textpage().get_text_range()
    pdf.close()
    return img, text


def differing(a, b, ignore):
    """Pixels that differ, outside the `ignore` rectangles (PDF points, y up)."""
    if a.size != b.size:
        return -1
    pa, pb = a.load(), b.load()
    w, h = a.size
    skip = [(x0 * SCALE, h - y1 * SCALE, x1 * SCALE, h - y0 * SCALE) for x0, y0, x1, y1 in ignore]
    n = 0
    for y in range(h):
        for x in range(w):
            if any(l <= x <= r and t <= y <= b for l, t, r, b in skip):
                continue
            p, q = pa[x, y], pb[x, y]
            if max(abs(p[i] - q[i]) for i in range(3)) > THRESHOLD:
                n += 1
    return n


def words(text):
    return set(text.replace("\r", " ").replace("\n", " ").split())


def check_layers(base, entry):
    fails = []
    img_in, _ = render(base / entry["in"])
    img_out, text_out = render(base / entry["out"])
    # "ignore": rectangles where PDFium itself does not follow the standard (it draws an
    # annotation whatever its /OC says), so its rendering of the input is no reference.
    n = differing(img_in, img_out, entry.get("ignore", []))
    if n < 0 or n > MAX_DIFF_PX:
        fails.append(f"{entry['out']}: renders differently from its input ({n} px)")
    pdfium_words = words(text_out)
    reader = pypdf.PdfReader(str(base / entry["out"]))
    pypdf_words = words(reader.pages[0].extract_text())
    for tool, got in (("pdfium", pdfium_words), ("pypdf", pypdf_words)):
        for w in entry["shown"]:
            if w not in got:
                fails.append(f"{entry['out']}: {tool} misses shown {w}")
        for w in entry["hidden"]:
            if w in got:
                fails.append(f"{entry['out']}: {tool} finds hidden {w}")
    print(f"{'ok' if not fails else 'FAIL':4} {entry['out']}: {n} px differ from input, "
          f"{len(entry['shown'])} shown, {len(entry['hidden'])} hidden")
    return fails


def check_box(base, entry):
    img, _ = render(base / entry["out"])
    x0, y0, x1, y1 = entry["rect"]
    h = img.size[1]
    px = img.load()
    blue = 0
    for y in range(int(h - y1 * SCALE), int(h - y0 * SCALE)):
        for x in range(int(x0 * SCALE), int(x1 * SCALE)):
            r, g, b = px[x, y]
            if b > 150 and r < 100 and g < 100:
                blue += 1
    ok = blue >= entry.get("min", 10)
    print(f"{'ok' if ok else 'FAIL':4} {entry['out']}: {blue} blue px in {entry['rect']}")
    return [] if ok else [f"{entry['out']}: own appearance not drawn ({blue} blue px)"]


def main():
    base = Path(sys.argv[1])
    fails = []
    layers = base / "layers.json"
    boxes = base / "checkbox.json"
    if not layers.exists() and not boxes.exists():
        print(f"nothing to check in {base}", file=sys.stderr)
        sys.exit(2)
    if layers.exists():
        for e in json.loads(layers.read_text()):
            fails += check_layers(base, e)
    if boxes.exists():
        for e in json.loads(boxes.read_text()):
            fails += check_box(base, e)
    for f in fails:
        print("  " + f)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
