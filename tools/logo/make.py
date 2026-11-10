"""Build the OpenSeal logo SVGs (docs/assets/): a wax-seal badge with a spiral, and the wordmark
as glyph outlines so it renders the same everywhere, with no font needed.

The wordmark is Lexend SemiBold (wght 600), SIL Open Font License 1.1, by Thomas Jockin and the
Lexend project (https://github.com/googlefonts/lexend); see NOTICE. The font is not committed:

    python3 -m venv /tmp/logo-venv && /tmp/logo-venv/bin/pip install fonttools
    mkdir -p tools/logo/font && curl -sL -o tools/logo/font/Lexend.ttf \
      "https://github.com/google/fonts/raw/main/ofl/lexend/Lexend%5Bwght%5D.ttf"
    /tmp/logo-venv/bin/python tools/logo/make.py docs/assets
"""
import math
import sys
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

OUT = Path(sys.argv[1])
FONT = Path(__file__).parent / "font" / "Lexend.ttf"
RED_TOP, RED_BOTTOM = "#c01622", "#8e0b14"


def f(x):
    return f"{x:.2f}".rstrip("0").rstrip(".")


def badge_outline(cx, cy, r, bumps=10, depth=0.075, steps=720):
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        rr = r * (1 - depth / 2 + depth / 2 * math.cos(bumps * t))
        pts.append((cx + rr * math.cos(t), cy + rr * math.sin(t)))
    return "M" + " L".join(f"{f(x)} {f(y)}" for x, y in pts) + " Z"


def spiral(cx, cy, r_out, turns=2.0, start_r=0.12, steps=400):
    """An Archimedean spiral from near the centre outwards, as a polyline path."""
    pts = []
    total = turns * 2 * math.pi
    for i in range(steps + 1):
        a = total * i / steps
        rr = r_out * (start_r + (1 - start_r) * a / total)
        theta = a + math.pi * 0.85  # rotate so the open end sits at the lower left, as drawn
        pts.append((cx + rr * math.cos(theta), cy - rr * math.sin(theta)))
    return "M" + " L".join(f"{f(x)} {f(y)}" for x, y in pts)


def mark(cx, cy, r, gid):
    sw = r * 0.17
    return (
        f'<path d="{badge_outline(cx, cy, r)}" fill="url(#{gid})"/>'
        f'<path d="{spiral(cx, cy, r * 0.70)}" fill="none" stroke="#fff" '
        f'stroke-width="{f(sw)}" stroke-linecap="round" stroke-linejoin="round"/>'
    )


def gradient(gid):
    return (
        f'<linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{RED_TOP}"/><stop offset="1" stop-color="{RED_BOTTOM}"/>'
        "</linearGradient>"
    )


def words(font, parts, x0, baseline, size):
    """Glyph outlines for each (text, fill) part; returns (svg, end x)."""
    upm = font["head"].unitsPerEm
    scale = size / upm
    cmap, gs, hmtx = font.getBestCmap(), font.getGlyphSet(), font["hmtx"]
    out, x = [], x0
    for text, fill in parts:
        pen = SVGPathPen(gs)
        for ch in text:
            name = cmap[ord(ch)]
            gs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
            x += hmtx[name][0] * scale - size * 0.01  # a touch tighter, as the original
        out.append(f'<path d="{pen.getCommands()}" fill="{fill}"/>')
    return "".join(out), x


def svg(w, h, body, title):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f(w)} {f(h)}" '
        f'width="{f(w)}" height="{f(h)}" role="img" aria-label="{title}"><title>{title}</title>'
        f"{body}</svg>\n"
    )


def main():
    font = instancer.instantiateVariableFont(TTFont(FONT), {"wght": 600})
    OUT.mkdir(parents=True, exist_ok=True)
    size, r = 120, 64
    cx, cy = 8 + r, 8 + r
    for name, ink in (("logo.svg", "#1d1d1f"), ("logo-dark.svg", "#f5f5f7")):
        text, end = words(font, [("Open", ink), ("Seal", "url(#seal-word)")], cx + r + 26, cy + 42, size)
        defs = "<defs>" + gradient("seal-badge") + gradient("seal-word") + "</defs>"
        (OUT / name).write_text(svg(end + 8, 2 * (8 + r), defs + mark(cx, cy, r, "seal-badge") + text, "OpenSeal"))
    (OUT / "mark.svg").write_text(
        svg(144, 144, "<defs>" + gradient("seal-badge") + "</defs>" + mark(72, 72, 64, "seal-badge"), "OpenSeal")
    )


main()
