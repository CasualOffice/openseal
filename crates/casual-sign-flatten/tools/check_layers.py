"""Independent check of optional content and annotation flattening (FLT-03, FLT-04).

    FLATTEN_DUMP_DIR=<dir> cargo test -p casual-sign-flatten --test optional
    # optionally the corpus: OPENSEAL_CORPUS_SWEEP=1 ... --test corpus_layers
    <venv>/bin/python -I crates/casual-sign-flatten/tools/check_layers.py <dir>

Needs pypdfium2 and pypdf in a venv (as check_render.py). For each entry of every
<dir>/layers*.json:

- PDFium renders the input (which honours its optional content and annotation flags)
  and the output (which has neither), the first "pages" pages (default 1): they must
  look the same, so the sealed page is what a viewer showed the signer. "ignore" lists
  rectangles (PDF points) where PDFium itself does not follow the standard;
- PDFium's and pypdf's text of the output's first page hold every "shown" word and no
  "hidden" one.

For each entry of <dir>/checkbox.json: PDFium draws the box's own colour (blue) inside
its rectangle. Exits non-zero naming every failure.
"""

import json
import logging
import sys
from pathlib import Path

import pypdf
import pypdfium2 as pdfium
from PIL import ImageChops

logging.disable(logging.WARNING)

SCALE = 2.0
THRESHOLD = 40
# Anti-aliasing can differ where an annotation is drawn as page content.
MAX_DIFF_PX = 40


def render(path, pages=1):
    pdf = pdfium.PdfDocument(str(path))
    pdf.init_forms()
    imgs = []
    for i in range(min(pages, len(pdf))):
        page = pdf[i]
        imgs.append(page.render(scale=SCALE, may_draw_forms=True).to_pil().convert("RGB"))
    text = pdf[0].get_textpage().get_text_range()
    pdf.close()
    return imgs, text


def differing(a, b, ignore):
    """Pixels that differ, outside the `ignore` rectangles (PDF points, y up)."""
    if a.size != b.size:
        return -1
    w, h = a.size
    diff = ImageChops.difference(a, b)
    for x0, y0, x1, y1 in ignore:
        box = (int(x0 * SCALE), int(h - y1 * SCALE), int(x1 * SCALE) + 1, int(h - y0 * SCALE) + 1)
        diff.paste((0, 0, 0), box)
    # Largest channel difference per pixel, then pixels over the threshold.
    r, g, b2 = diff.split()
    m = ImageChops.lighter(ImageChops.lighter(r, g), b2)
    hist = m.histogram()
    return sum(hist[THRESHOLD + 1:])


def words(text):
    return set(text.replace("\r", " ").replace("\n", " ").split())


def check_layers(base, entry):
    fails = []
    pages = entry.get("pages", 1)
    imgs_in, _ = render(base / entry["in"], pages)
    imgs_out, text_out = render(base / entry["out"], pages)
    counts = [differing(a, b, entry.get("ignore", [])) for a, b in zip(imgs_in, imgs_out)]
    for i, n in enumerate(counts):
        if n < 0 or n > entry.get("tolerance", MAX_DIFF_PX):
            fails.append(f"{entry['out']}: page {i + 1} renders differently from its input ({n} px)")
    if entry["shown"] or entry["hidden"]:
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
    print(f"{'ok' if not fails else 'FAIL':4} {entry['out']}: px differing per page {counts}, "
          f"{len(entry['shown'])} shown, {len(entry['hidden'])} hidden")
    return fails


def check_box(base, entry):
    imgs, _ = render(base / entry["out"])
    img = imgs[0]
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
    manifests = sorted(base.glob("layers*.json"))
    boxes = base / "checkbox.json"
    if not manifests and not boxes.exists():
        print(f"nothing to check in {base}", file=sys.stderr)
        sys.exit(2)
    for m in manifests:
        for e in json.loads(m.read_text()):
            try:
                fails += check_layers(base, e)
            except Exception as err:  # noqa: BLE001 - a file PDFium cannot open is a failure to report
                fails.append(f"{e['out']}: {type(err).__name__}: {err}")
    if boxes.exists():
        for e in json.loads(boxes.read_text()):
            fails += check_box(base, e)
    for f in fails:
        print("  " + f)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
