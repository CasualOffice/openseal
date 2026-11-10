"""Write the small test images in tests/data (T-1E). Needs Pillow.

    python3 -I crates/casual-sign-flatten/tools/gen_images.py crates/casual-sign-flatten/tests/data

Every image is a dark mark on white (or on transparency), so a renderer that draws it
leaves ink inside the field. Output is deterministic for one Pillow version.
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw


def mark(mode, size, bg):
    im = Image.new(mode, size, bg)
    d = ImageDraw.Draw(im)
    w, h = size
    ink = 0 if mode == "L" else (20, 30, 120) if mode == "RGB" else (0, 0, 0, 0)
    d.rectangle([w // 8, h // 4, w - w // 8, h - h // 4], fill=ink)
    return im


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    mark("RGB", (80, 40), (255, 255, 255)).save(out / "stamp-rgb.jpg", quality=85)
    mark("L", (80, 40), 255).save(out / "stamp-gray.jpg", quality=85, progressive=True)
    cmyk = Image.new("CMYK", (80, 40), (0, 0, 0, 0))
    ImageDraw.Draw(cmyk).rectangle([10, 10, 70, 30], fill=(0, 0, 0, 255))
    cmyk.save(out / "stamp-cmyk.jpg", quality=85)
    # Stored rotated: orientation 6 says "turn 90 degrees clockwise to show".
    tall = mark("RGB", (40, 80), (255, 255, 255))
    exif = Image.Exif()
    exif[0x0112] = 6
    exif[0x8825] = {2: (1.0, 2.0, 3.0)}  # GPS IFD: must not reach the PDF.
    tall.save(out / "stamp-exif6.jpg", quality=85, exif=exif)


if __name__ == "__main__":
    main(sys.argv[1])
