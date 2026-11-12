#!/usr/bin/env python3
"""Synthetic scanned forms for the ML evaluation (`ML-02`, `ML-05`; docs/33 §11, ADR-029 piece E).

    python3 -I tools/ml/make-scans.py            # write fixtures/ml/{vector,scans,truth}/ and manifest.tsv
    python3 -I tools/ml/make-scans.py --check    # regenerate in memory; fail unless every file is byte-identical

Standard library only; nothing is downloaded and nothing third-party is executed. Every form is synthetic: this
script lays it out (labels, underscore runs, painted rules, boxes, check boxes, AcroForm fields), then writes it twice
from the same layout:

- `vector/<form>.pdf`, a vector PDF with a text layer (and AcroForm fields on `latin-acroform`), for
  `detect_fields` on the text layer (the "before" of the ML-02 exit);
- `scans/<form>--<variant>.pdf`, an image-only PDF: the layout rasterised by this script (TrueType outlines,
  4x vertical supersampling, exact horizontal coverage) at 150, 200 or 300 DPI, then degraded from a fixed seed:
  paper and ink tone, skew (three integer shears), a [1 2 1] blur, speckle and dropouts, a 180-degree page, a
  page stored sideways with `/Rotate 90`, and either baseline JPEG at quality 60 to 75 or a binarised fax look.

`truth/<name>.json` gives, per page, every field (kind, rectangle, label, how it is drawn) and every word (text,
script, rectangle), in displayed page space (ADR-019: points, origin top left) after the degradation, plus the
rectangle on the clean form. Field kinds use the `FieldType` wire names.

Byte-identical output on any machine: no zlib (its bytes differ between zlib and zlib-ng), our own JPEG and
RunLength encoders, integer pixel arithmetic, IEEE float layout only (no libm transcendental feeds a pixel; the skew
uses a Taylor series), a SplitMix64 generator, sorted JSON. Fonts are inputs pinned by SHA-256; the Arabic and
Devanagari words were shaped once with HarfBuzz (uharfbuzz 0.51.1) against those exact files and are stored below
as glyph ids and positions, so no shaper runs here.

All personal-looking values (names, e-mail, phone) are invented: e-mail under example.com (RFC 2606), the phone
number in the fictional +1 555-01xx range.
"""
import hashlib
import json
import math
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "fixtures" / "ml"
MANIFEST = "manifest.tsv"
GENERATED_DIRS = ("vector", "scans", "truth")
BUDGET = 15 * 1000 * 1000  # the whole of fixtures/ml, bytes
MASTER_SEED = 0x0E5EA1_0029
PAGE_W, PAGE_H = 612.0, 792.0  # US Letter, points

# Input fonts: path relative to the repository, SHA-256, licence, provenance.
FONTS = {
    "sans": ("crates/casual-sign-flatten/fonts/liberation/LiberationSans-Regular.ttf",
             "76d04c18ea243f426b7de1f3ad208e927008f961dc5945e5aad352d0dfde8ee8", "OFL-1.1",
             "Liberation Sans, vendored by casual-sign-flatten (its fonts/PROVENANCE.md)"),
    "script": ("crates/casual-sign-flatten/fonts/script/GreatVibes-Regular.ttf",
               "8d509802186f1b51572531ecf313e8098f9a5bfdfaca93f0c9b34467f9982d15", "OFL-1.1",
               "Great Vibes, vendored by casual-sign-flatten (its fonts/PROVENANCE.md)"),
    "arab": ("fixtures/ml/fonts/NotoSansArabic-Regular.ttf",
             "bd86ca02f087d7f3c3788ba458fb6b73744c7639ed276b8d870dba6def6c40d0", "OFL-1.1",
             "https://github.com/notofonts/arabic/releases/download/NotoSansArabic-v2.013/NotoSansArabic-v2.013.zip "
             "(zip sha256 1301aceaea84c501cf2e6dcfb3182e2328c8eae5725817fcb239672bda7154f1), "
             "NotoSansArabic/unhinted/ttf/NotoSansArabic-Regular.ttf"),
    "deva": ("fixtures/ml/fonts/NotoSansDevanagari-Regular.ttf",
             "9c7d935139ea6a1e6ad9dbac4f6d27ece1e04bca8123c8888d00a0f9df4724cd", "OFL-1.1",
             "https://github.com/notofonts/devanagari/releases/download/NotoSansDevanagari-v2.007/"
             "NotoSansDevanagari-v2.007.zip (zip sha256 "
             "820c7da45b1e63562cb41c0a8cac5d9a4202312043a3a040ed1325857ef469b1), "
             "NotoSansDevanagari/unhinted/ttf/NotoSansDevanagari-Regular.ttf"),
}
# Committed inputs listed in the manifest besides the fonts above.
LICENCE_FILES = {
    "fonts/OFL-1.1-NotoSansArabic.txt": ("OFL-1.1", "OFL.txt from the NotoSansArabic-v2.013 zip"),
    "fonts/OFL-1.1-NotoSansDevanagari.txt": ("OFL-1.1", "OFL.txt from the NotoSansDevanagari-v2.007 zip"),
}

# Words shaped with uharfbuzz 0.51.1 (HarfBuzz default features, guessed script and direction) against the two
# Noto fonts pinned above, NFC input. Per glyph: [glyph id, x advance, x offset, y offset, cluster], font units
# (units per em 1000), glyphs in visual order (left to right, also for Arabic). Regenerate only with the fonts.
SHAPED = {
    "طلب": [[316,0,387,-23,2],[15,1093,0,0,2],[70,300,0,0,1],[45,677,0,0,0]],
    "توظيف": [[282,0,774,-48,4],[51,1098,0,0,4],[318,0,39,-5,3],[18,373,0,0,3],[282,0,330,-94,2],[45,677,0,0,2],[100,472,0,0,1],[287,0,5,-59,0],[21,299,0,0,0]],
    "الاسم": [[77,562,0,0,4],[37,784,0,0,3],[10,363,0,0,2],[73,219,0,0,1],[8,238,0,0,0]],
    "التاريخ": [[282,0,236,-47,6],[24,649,0,0,6],[318,0,-28,-5,5],[21,299,0,0,5],[30,337,-30,0,4],[9,291,0,0,3],[287,0,54,-180,2],[18,373,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "التوقيع": [[47,531,0,0,6],[318,0,39,-5,5],[18,373,0,0,5],[287,0,80,38,4],[53,447,0,0,4],[100,472,0,0,3],[287,0,54,-180,2],[18,373,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "الشركة": [[287,0,101,65,5],[85,486,0,0,5],[61,412,0,0,4],[31,356,-40,0,3],[292,0,286,-131,2],[36,850,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "المسمى": [[104,736,0,0,5],[78,578,0,0,4],[36,850,0,0,3],[78,578,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "الوظيفي": [[318,0,185,-232,6],[104,736,0,0,6],[282,0,171,-48,5],[52,495,0,0,5],[318,0,39,-5,4],[18,373,0,0,4],[282,0,330,-94,3],[45,677,0,0,3],[100,472,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "أوافق": [[287,0,426,-132,4],[55,808,0,0,4],[282,0,147,38,3],[53,447,0,0,3],[8,238,0,0,2],[98,447,0,0,1],[297,0,-16,126,0],[12,235,0,0,0]],
    "على": [[104,736,0,0,2],[70,300,0,0,1],[49,503,0,0,0]],
    "الشروط": [[42,788,0,0,5],[98,447,0,0,4],[31,396,0,0,3],[292,0,286,-131,2],[36,850,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "يرجى": [[104,736,0,0,3],[316,0,203,2,2],[27,589,0,0,2],[31,356,-40,0,1],[318,0,-28,-5,0],[21,299,0,0,0]],
    "تعبئة": [[287,0,101,65,4],[85,486,0,0,4],[297,0,26,-235,3],[16,343,0,0,3],[316,0,94,-3,2],[16,343,0,0,2],[48,521,0,0,1],[287,0,5,-59,0],[21,299,0,0,0]],
    "هذا": [[8,238,0,0,2],[282,0,145,-6,1],[29,532,0,0,1],[87,574,0,0,0]],
    "النموذج": [[333,0,275,-66,6],[22,639,0,0,6],[282,0,140,-6,5],[28,477,0,0,5],[100,472,0,0,4],[78,578,0,0,3],[282,0,80,-180,2],[16,343,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "بخط": [[43,831,0,0,2],[282,0,81,-111,1],[26,637,0,0,1],[316,0,31,-3,0],[19,269,0,0,0]],
    "واضح": [[24,649,0,0,3],[282,0,576,-94,2],[41,903,0,0,2],[8,238,0,0,1],[98,447,0,0,0]],
    "ليلى": [[104,736,0,0,3],[70,300,0,0,2],[318,0,39,-5,1],[18,373,0,0,1],[72,260,0,0,0]],
    "الأمثلة": [[287,0,101,65,6],[85,486,0,0,6],[70,300,0,0,5],[292,0,54,-180,4],[18,373,0,0,4],[79,525,0,0,3],[297,0,-6,50,2],[10,363,0,0,2],[73,219,0,0,1],[8,238,0,0,0]],
    "شركة": [[287,0,101,65,3],[85,486,0,0,3],[61,412,0,0,2],[31,356,-40,0,1],[292,0,286,-131,0],[37,784,0,0,0]],
    "المثال": [[68,695,0,0,5],[9,291,0,0,4],[292,0,54,-180,3],[18,373,0,0,3],[78,578,0,0,2],[72,260,0,0,1],[8,238,0,0,0]],
    "आवेदन": [[6,1022,0,0,0],[84,556,0,0,1],[40,0,0,0,1],[73,531,0,0,3],[75,555,0,0,4]],
    "पत्र": [[76,568,0,0,0],[304,552,0,0,1]],
    "नाम": [[75,555,0,0,0],[31,259,0,0,0],[80,598,0,0,2]],
    "दिनांक": [[544,259,0,0,0],[73,531,0,0,0],[75,555,0,0,2],[31,259,0,0,2],[100,0,0,0,2],[56,768,0,0,5]],
    "हस्ताक्षर": [[88,531,0,0,0],[256,389,0,0,1],[71,570,0,0,3],[31,259,0,0,3],[90,717,0,0,5],[82,409,0,0,8]],
    "कंपनी": [[56,768,0,0,0],[100,0,-221,0,0],[76,568,0,0,2],[75,555,0,0,3],[33,259,0,0,3]],
    "पद": [[76,568,0,0,0],[73,531,0,0,1]],
    "मैं": [[80,598,0,0,0],[517,0,0,0,0]],
    "शर्तों": [[85,680,0,0,0],[71,570,0,0,1],[31,259,0,0,1],[515,0,0,0,1]],
    "से": [[87,676,0,0,0],[40,0,0,0,0]],
    "सहमत": [[87,676,0,0,0],[88,531,0,0,1],[80,598,0,0,2],[71,570,0,0,3]],
    "हूँ": [[499,531,0,0,0],[101,0,13,0,0]],
    "कृपया": [[56,768,0,0,0],[36,0,-221,0,0],[76,568,0,0,2],[81,580,0,0,3],[31,259,0,0,3]],
    "यह": [[81,580,0,0,0],[88,531,0,0,1]],
    "फ़ॉर्म": [[228,771,0,0,0],[45,259,0,0,0],[80,598,0,0,3],[506,0,0,0,3]],
    "साफ़": [[87,676,0,0,0],[31,259,0,0,0],[228,771,0,0,2]],
    "अक्षरों": [[5,764,0,0,0],[90,717,0,0,1],[82,409,0,0,4],[31,259,0,0,4],[512,0,0,0,4]],
    "में": [[80,598,0,0,0],[512,0,0,0,0]],
    "भरें": [[79,703,0,0,0],[82,409,0,0,1],[512,0,-10,0,1]],
}


class Problem(Exception):
    """A generation or check failure, named for the operator."""


# ---------------------------------------------------------------------------------------------- arithmetic


def _sin(x):
    """sin by Taylor series: only + - * /, so every machine gets the same bits (|x| < 0.1 here)."""
    term, total, n = x, x, 1
    while n < 19:
        term = -term * x * x / ((n + 1) * (n + 2))
        total += term
        n += 2
    return total


def _cos(x):
    term, total, n = 1.0, 1.0, 0
    while n < 18:
        term = -term * x * x / ((n + 1) * (n + 2))
        total += term
        n += 2
    return total


def _round(v):
    """Half away from zero, the same everywhere."""
    return math.floor(v + 0.5) if v >= 0 else -math.floor(-v + 0.5)


class Rng:
    """SplitMix64, seeded from the master seed and a name."""

    MASK = (1 << 64) - 1

    def __init__(self, name):
        digest = hashlib.sha256(f"{MASTER_SEED}:{name}".encode()).digest()
        self.state = int.from_bytes(digest[:8], "big")

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & self.MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASK
        return z ^ (z >> 31)

    def below(self, n):
        return self.next() % n


def fmt(v):
    """A PDF number: at most three decimals, no trailing zeros."""
    s = "%.3f" % v
    s = s.rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def r2(v):
    return round(v, 2) + 0.0


# ---------------------------------------------------------------------------------------------- TrueType


def _u16(b, o):
    return (b[o] << 8) | b[o + 1]


def _i16(b, o):
    v = _u16(b, o)
    return v - 65536 if v >= 32768 else v


def _u32(b, o):
    return int.from_bytes(b[o:o + 4], "big")


def _f2dot14(b, o):
    return _i16(b, o) / 16384.0


class TrueType:
    """The parts of a glyf-flavoured TrueType font this generator needs: metrics, cmap, outlines."""

    def __init__(self, key, data):
        self.key = key
        self.data = data
        tables = {}
        for i in range(_u16(data, 4)):
            rec = 12 + 16 * i
            tables[data[rec:rec + 4].decode("latin-1")] = (_u32(data, rec + 8), _u32(data, rec + 12))
        for need in ("head", "hhea", "hmtx", "maxp", "loca", "glyf", "cmap"):
            if need not in tables:
                raise Problem(f"font {key}: no {need} table (only glyf TrueType fonts are supported)")
        self.tables = tables
        head = tables["head"][0]
        self.upem = _u16(data, head + 18)
        self.bbox = [_i16(data, head + 36 + 2 * i) for i in range(4)]
        long_loca = _i16(data, head + 50) == 1
        self.num_glyphs = _u16(data, tables["maxp"][0] + 4)
        hhea = tables["hhea"][0]
        self.ascender = _i16(data, hhea + 4)
        self.descender = _i16(data, hhea + 6)
        n_hm = _u16(data, hhea + 34)
        hmtx = tables["hmtx"][0]
        adv = [_u16(data, hmtx + 4 * i) for i in range(n_hm)]
        self.advances = adv + [adv[-1]] * (self.num_glyphs - n_hm)
        loca = tables["loca"][0]
        if long_loca:
            self.loca = [_u32(data, loca + 4 * i) for i in range(self.num_glyphs + 1)]
        else:
            self.loca = [2 * _u16(data, loca + 2 * i) for i in range(self.num_glyphs + 1)]
        self.glyf = tables["glyf"][0]
        self.cmap = self._read_cmap(tables["cmap"][0])
        self._outlines = {}

    def _read_cmap(self, base):
        data = self.data
        best = None
        for i in range(_u16(data, base + 2)):
            rec = base + 4 + 8 * i
            pid, eid, off = _u16(data, rec), _u16(data, rec + 2), _u32(data, rec + 4)
            fmt_ = _u16(data, base + off)
            if pid == 3 and eid == 10 and fmt_ == 12:
                best = (12, base + off)
            elif pid == 3 and eid == 1 and fmt_ == 4 and best is None:
                best = (4, base + off)
        if best is None:
            raise Problem(f"font {self.key}: no Windows Unicode cmap")
        kind, sub = best
        table = {}
        if kind == 12:
            for g in range(_u32(data, sub + 12)):
                rec = sub + 16 + 12 * g
                start, end, gid = _u32(data, rec), _u32(data, rec + 4), _u32(data, rec + 8)
                for cp in range(start, min(end, 0x2FFFF) + 1):
                    table[cp] = gid + cp - start
            return table
        segs = _u16(data, sub + 6) // 2
        ends = sub + 14
        starts = ends + 2 * segs + 2
        deltas = starts + 2 * segs
        ranges = deltas + 2 * segs
        for s in range(segs):
            end, start = _u16(data, ends + 2 * s), _u16(data, starts + 2 * s)
            delta, ro = _u16(data, deltas + 2 * s), _u16(data, ranges + 2 * s)
            for cp in range(start, min(end, 0xFFFE) + 1):
                if ro == 0:
                    gid = (cp + delta) & 0xFFFF
                else:
                    gid = _u16(data, ranges + 2 * s + ro + 2 * (cp - start))
                    gid = (gid + delta) & 0xFFFF if gid else 0
                if gid:
                    table[cp] = gid
        return table

    def gid(self, ch):
        g = self.cmap.get(ord(ch))
        if not g:
            raise Problem(f"font {self.key}: no glyph for U+{ord(ch):04X}")
        return g

    def outline(self, gid, depth=0):
        """Contours as lists of (x, y, on_curve) in font units."""
        if gid in self._outlines:
            return self._outlines[gid]
        if depth > 8:
            raise Problem(f"font {self.key}: composite glyph {gid} nests too deep")
        data = self.data
        off, end = self.glyf + self.loca[gid], self.glyf + self.loca[gid + 1]
        contours = []
        if end > off:
            n = _i16(data, off)
            if n >= 0:
                contours = self._simple(off, n)
            else:
                contours = self._composite(off, depth)
        self._outlines[gid] = contours
        return contours

    def _simple(self, off, n):
        data = self.data
        p = off + 10
        ends = [_u16(data, p + 2 * i) for i in range(n)]
        p += 2 * n
        p += 2 + _u16(data, p)
        npts = ends[-1] + 1 if n else 0
        flags = []
        while len(flags) < npts:
            f = data[p]
            p += 1
            flags.append(f)
            if f & 8:
                flags.extend([f] * data[p])
                p += 1
        flags = flags[:npts]
        coords = []
        for short, same in ((2, 16), (4, 32)):
            v, out = 0, []
            for f in flags:
                if f & short:
                    d = data[p]
                    p += 1
                    v += d if f & same else -d
                elif not f & same:
                    v += _i16(data, p)
                    p += 2
                out.append(v)
            coords.append(out)
        xs, ys = coords
        contours, start = [], 0
        for e in ends:
            contours.append([(xs[i], ys[i], bool(flags[i] & 1)) for i in range(start, e + 1)])
            start = e + 1
        return contours

    def _composite(self, off, depth):
        data = self.data
        p = off + 10
        contours = []
        while True:
            flags, gi = _u16(data, p), _u16(data, p + 2)
            p += 4
            if flags & 1:
                a1, a2 = _i16(data, p), _i16(data, p + 2)
                p += 4
            else:
                a1, a2 = data[p] - 256 * (data[p] > 127), data[p + 1] - 256 * (data[p + 1] > 127)
                p += 2
            if not flags & 2:
                raise Problem(f"font {self.key}: composite glyph uses point matching (unsupported)")
            xx, yx, xy, yy = 1.0, 0.0, 0.0, 1.0
            if flags & 8:
                xx = yy = _f2dot14(data, p)
                p += 2
            elif flags & 0x40:
                xx, yy = _f2dot14(data, p), _f2dot14(data, p + 2)
                p += 4
            elif flags & 0x80:
                xx, yx, xy, yy = (_f2dot14(data, p + 2 * i) for i in range(4))
                p += 8
            for c in self.outline(gi, depth + 1):
                contours.append([(xx * x + xy * y + a1, yx * x + yy * y + a2, on) for x, y, on in c])
            if not flags & 0x20:
                break
        return contours


def load_fonts():
    fonts = {}
    for key, (rel, sha, _, _) in FONTS.items():
        path = ROOT / rel
        if not path.is_file():
            raise Problem(f"font {key}: {rel} is missing")
        data = path.read_bytes()
        got = hashlib.sha256(data).hexdigest()
        if got != sha:
            raise Problem(f"font {key}: {rel} has SHA-256 {got}, expected {sha}")
        fonts[key] = TrueType(key, data)
    return fonts


# ---------------------------------------------------------------------------------------------- rasteriser


def _flatten(contour):
    """A closed TrueType contour (device coordinates) as a polygon."""
    n = len(contour)
    if n < 2:
        return []
    pts = []
    for i in range(n):
        x, y, on = contour[i]
        nx, ny, non = contour[(i + 1) % n]
        pts.append((x, y, on))
        if not on and not non:
            pts.append(((x + nx) / 2, (y + ny) / 2, True))
    k = next((i for i, p in enumerate(pts) if p[2]), None)
    if k is None:
        return []
    pts = pts[k:] + pts[:k]
    m = len(pts)
    out = [(pts[0][0], pts[0][1])]
    i = 1
    while i <= m:
        p = pts[i % m]
        if p[2]:
            out.append((p[0], p[1]))
            i += 1
            continue
        q = pts[(i + 1) % m]
        x0, y0 = out[-1]
        length = abs(p[0] - x0) + abs(p[1] - y0) + abs(q[0] - p[0]) + abs(q[1] - p[1])
        steps = max(2, min(16, int(length / 2) + 1))
        for s in range(1, steps + 1):
            t = s / steps
            u = 1 - t
            out.append((u * u * x0 + 2 * u * t * p[0] + t * t * q[0], u * u * y0 + 2 * u * t * p[1] + t * t * q[1]))
        i += 2
    return out


SUB = 4  # sub-scanlines per pixel row


def coverage(polys):
    """Non-zero-winding coverage of polygons (device px): (x0, y0, w, h, alpha bytes) or None."""
    pts = [pt for poly in polys for pt in poly]
    if not pts:
        return None
    x0 = math.floor(min(p[0] for p in pts))
    y0 = math.floor(min(p[1] for p in pts))
    w = math.floor(max(p[0] for p in pts)) - x0 + 1
    h = math.floor(max(p[1] for p in pts)) - y0 + 1
    edges = []
    for poly in polys:
        for (xa, ya), (xb, yb) in zip(poly, poly[1:] + poly[:1]):
            if ya == yb:
                continue
            d = 1
            if ya > yb:
                xa, ya, xb, yb, d = xb, yb, xa, ya, -1
            edges.append((ya - y0, yb - y0, xa - x0, (xb - xa) / (yb - ya), d))
    acc = [0.0] * (w * h)
    part = 1.0 / SUB
    for row in range(h):
        live = [e for e in edges if e[0] < row + 1 and e[1] > row]
        if not live:
            continue
        base = row * w
        for s in range(SUB):
            yy = row + (s + 0.5) * part
            xs = sorted((e[2] + (yy - e[0]) * e[3], e[4]) for e in live if e[0] <= yy < e[1])
            wind = 0
            for j in range(len(xs) - 1):
                wind += xs[j][1]
                if wind == 0:
                    continue
                xa, xb = max(0.0, xs[j][0]), min(float(w), xs[j + 1][0])
                if xb <= xa:
                    continue
                ia, ib = int(xa), int(xb)
                if ia == ib:
                    acc[base + ia] += (xb - xa) * part
                    continue
                acc[base + ia] += (ia + 1 - xa) * part
                for i in range(ia + 1, ib):
                    acc[base + i] += part
                if ib < w:
                    acc[base + ib] += (xb - ib) * part
    alpha = bytes(255 if a >= 1.0 else int(a * 255 + 0.5) for a in acc)
    return x0, y0, w, h, alpha


class Canvas:
    """An 8-bit grey page, white 255, ink composited by coverage."""

    def __init__(self, dpi):
        self.dpi = dpi
        self.scale = dpi / 72.0
        self.w = _round(PAGE_W * self.scale)
        self.h = _round(PAGE_H * self.scale)
        self.pix = bytearray(b"\xff" * (self.w * self.h))
        self._glyphs = {}

    def blit(self, cov, dx=0, dy=0):
        if cov is None:
            return
        x0, y0, w, h, alpha = cov
        x0 += dx
        y0 += dy
        for r in range(h):
            y = y0 + r
            if not 0 <= y < self.h:
                continue
            arow = alpha[r * w:(r + 1) * w]
            if arow.count(0) == w:
                continue
            lo, hi = max(0, x0), min(self.w, x0 + w)
            if lo >= hi:
                continue
            arow = arow[lo - x0:hi - x0]
            base = y * self.w
            seg = self.pix[base + lo:base + hi]
            self.pix[base + lo:base + hi] = bytes(v - (v * a + 127) // 255 for v, a in zip(seg, arow))

    def polys(self, polys_pt):
        s = self.scale
        self.blit(coverage([[(x * s, y * s) for x, y in poly] for poly in polys_pt]))

    def rect(self, x, y, w, h):
        self.polys([[(x, y), (x + w, y), (x + w, y + h), (x, y + h)]])

    def glyph(self, font, gid, size, x, y):
        """Glyph `gid` of `font` at `size` points, pen at (x, y) points (y down, baseline)."""
        s = self.scale
        px, py = x * s, y * s
        ix, iy = math.floor(px), math.floor(py + 0.5)
        phase = int((px - ix) * 4)
        key = (font.key, gid, size, phase)
        cov = self._glyphs.get(key)
        if key not in self._glyphs:
            k = size * s / font.upem
            ox = phase / 4
            polys = [_flatten([(ox + gx * k, -gy * k, on) for gx, gy, on in c]) for c in font.outline(gid)]
            cov = coverage([p for p in polys if p])
            self._glyphs[key] = cov
        self.blit(cov, ix, iy)


# ---------------------------------------------------------------------------------------------- layout


class Page:
    """One page of a form: drawing items, fields and words, in points with the origin top left."""

    def __init__(self):
        self.items = []  # ("glyphs", font, size, [(gid, x, y)], word) | ("rect", x, y, w, h)
        self.fields = []
        self.words = []
        self.widgets = []


class Form:
    def __init__(self, name, title, fonts):
        self.name = name
        self.title = title
        self.fonts = fonts
        self.pages = [Page()]

    @property
    def page(self):
        return self.pages[-1]

    def new_page(self):
        self.pages.append(Page())

    # -- text

    def _word_box(self, font, size, x0, x1, baseline):
        top = baseline - font.ascender * size / font.upem
        bottom = baseline - font.descender * size / font.upem
        return [x0, top, x1 - x0, bottom - top]

    def latin(self, text, x, baseline, size=10.5, font="sans", role="label"):
        """Left-aligned Latin text; returns the end x. Underscore runs are drawn, not counted as words."""
        f = self.fonts[font]
        k = size / f.upem
        pen = x
        space = f.advances[f.gid(" ")] * k
        for i, word in enumerate(text.split(" ")):
            if i:
                pen += space
            if not word:
                continue
            start = pen
            glyphs = []
            for ch in word:
                g = f.gid(ch)
                glyphs.append((g, pen, baseline))
                pen += f.advances[g] * k
            self.page.items.append(("glyphs", font, size, glyphs, word))
            if word.strip("_"):
                self.page.words.append({"text": word, "script": "Latn", "role": role,
                                        "rect": self._word_box(f, size, start, pen, baseline)})
        return pen

    def latin_width(self, text, size=10.5, font="sans"):
        f = self.fonts[font]
        return sum(f.advances[f.gid(ch)] for ch in text) * size / f.upem

    def shaped(self, text, x, baseline, size, font, script, rtl, role="label"):
        """Pre-shaped words (SHAPED). LTR: x is the left edge; RTL: x is the right edge. Returns the far edge."""
        f = self.fonts[font]
        k = size / f.upem
        space = f.advances[f.gid(" ")] * k
        pen = x
        for i, word in enumerate(text.split(" ")):
            run = SHAPED[word]
            width = sum(g[1] for g in run) * k
            if rtl:
                if i:
                    pen -= space
                start = pen - width
            else:
                if i:
                    pen += space
                start = pen
            glyphs = []
            gx = start
            for gid, adv, xo, yo, _ in run:
                glyphs.append((gid, gx + xo * k, baseline - yo * k))
                gx += adv * k
            self.page.items.append(("glyphs", font, size, glyphs, word))
            self.page.words.append({"text": word, "script": script, "role": role,
                                    "rect": self._word_box(f, size, start, start + width, baseline)})
            pen = start if rtl else start + width
        return pen

    def shaped_width(self, text, size, font):
        f = self.fonts[font]
        words = text.split(" ")
        units = sum(g[1] for w in words for g in SHAPED[w]) + f.advances[f.gid(" ")] * (len(words) - 1)
        return units * size / f.upem

    # -- drawing and fields

    def rule(self, x0, x1, y, width=0.75):
        self.page.items.append(("rect", x0, y - width / 2, x1 - x0, width))

    def box(self, x, y, w, h, width=0.75):
        p = self.page
        p.items.append(("rect", x, y, w, width))
        p.items.append(("rect", x, y + h - width, w, width))
        p.items.append(("rect", x, y, width, h))
        p.items.append(("rect", x + w - width, y, width, h))

    def field(self, kind, rect, label, drawn, name):
        self.page.fields.append({"kind": kind, "rect": list(rect), "label": label, "drawn": drawn, "name": name})

    def line_field(self, kind, x0, x1, y, label, drawn, name):
        """A field standing on a line from x0 to x1 at y: 24 pt tall for a signature or initials, else 16."""
        h = 24.0 if kind in ("signature", "initials") else 16.0
        self.field(kind, (x0, y - h, x1 - x0, h), label, drawn, name)

    def checkbox(self, x, y, label_words, name, drawn="box"):
        self.box(x, y, 10, 10)
        self.field("checkbox", (x, y, 10, 10), label_words, drawn, name)

    # -- filled values (scans only)

    def fill_text(self, text, x, baseline, size=11.0):
        self.latin(text, x, baseline, size=size, role="value")

    def fill_shaped(self, text, x, baseline, size, font, script, rtl):
        self.shaped(text, x, baseline, size, font, script, rtl, role="value")

    def fill_signature(self, text, x, baseline, size=22.0):
        """A signature in Great Vibes: drawn, recorded as a `signature_ink` word."""
        self.latin(text, x, baseline, size=size, font="script", role="signature_ink")

    def fill_check(self, x, y):
        """An X in a 10 pt check box at (x, y)."""
        for (ax, ay, bx, by) in ((x + 2, y + 2, x + 8, y + 8), (x + 8, y + 2, x + 2, y + 8)):
            dx, dy = bx - ax, by - ay
            n = (dx * dx + dy * dy) ** 0.5
            ox, oy = -dy / n * 0.6, dx / n * 0.6
            self.page.items.append(("poly", [(ax + ox, ay + oy), (bx + ox, by + oy), (bx - ox, by - oy),
                                             (ax - ox, ay - oy)]))


LOREM = [
    "The participant named below agrees to take part in the activity described in this form and",
    "confirms that the organiser has explained its purpose, its duration and the risks it carries.",
    "The participant may withdraw at any time by telling the organiser, without giving a reason.",
    "Records made during the activity are kept for twelve months and then destroyed.",
]

CLAUSES = [
    "1. Services. The Provider will perform the services described in Schedule A with due care",
    "and skill, using suitably qualified staff, and will keep the Client informed of progress.",
    "2. Fees. The Client will pay the fees in Schedule B within thirty days of each invoice.",
    "Late amounts carry interest at two percent above the base rate from the due date.",
    "3. Term. This agreement starts on the effective date and continues for twelve months,",
    "after which it renews for further periods of twelve months unless either party gives",
    "sixty days written notice before the end of the current period.",
    "4. Confidentiality. Each party keeps the other party's confidential information secret",
    "and uses it only to perform this agreement. This clause survives termination.",
    "5. Liability. Neither party is liable for indirect or consequential loss. Each party's",
    "total liability in any year is limited to the fees paid in the previous twelve months.",
    "6. Termination. Either party may end this agreement at once by written notice if the",
    "other commits a material breach and does not remedy it within thirty days of notice.",
    "7. Notices. Notices are given in writing to the addresses set out in Schedule C.",
    "8. Assignment. Neither party may assign this agreement without the other's consent.",
    "9. Entire agreement. This agreement and its schedules are the whole agreement between",
    "the parties and replace every earlier understanding about its subject matter.",
    "10. Governing law. This agreement is governed by the law of the place in Schedule C.",
]


def form_latin_consent(fonts, filled):
    """Underscore-run fields with labels beside them, check boxes, initials."""
    f = Form("latin-consent", "Consent and Release Form", fonts)
    f.latin("Consent and Release Form", 72, 96, size=18, role="title")
    y = 132
    for line in LOREM:
        f.latin(line, 72, y)
        y += 15
    y = 230
    for label, kind, name, under, value in (
        ("Participant name:", "name", "participant_name", 34, "Jordan Sample"),
        ("Date of birth:", "text", "date_of_birth", 22, "1990-04-12"),
        ("Emergency contact name:", "name", "contact_name", 30, "Casey Placeholder"),
    ):
        x = f.latin(label, 72, y) + 6
        x1 = f.latin("_" * under, x, y)
        f.line_field(kind, x, x1, y + 1.5, label.rstrip(":"), "underscores", name)
        if filled:
            f.fill_text(value, x + 4, y - 2)
        y += 34
    y += 6
    for i, text in enumerate(("I have read the information above.", "I agree to take part.",
                              "I agree that photographs may be taken.")):
        f.checkbox(72, y - 9, text, f"consent_{i + 1}")
        f.latin(text, 90, y)
        if filled and i < 2:
            f.fill_check(72, y - 9)
        y += 22
    y += 30
    x = f.latin("Signature:", 72, y) + 6
    x1 = f.latin("_" * 30, x, y)
    f.line_field("signature", x, x1, y + 1.5, "Signature", "underscores", "signature")
    if filled:
        f.fill_signature("Jordan Sample", x + 8, y - 3)
    x = f.latin("Date:", x1 + 24, y) + 6
    x2 = f.latin("_" * 16, x, y)
    f.line_field("date_signed", x, x2, y + 1.5, "Date", "underscores", "date_signed")
    if filled:
        f.fill_text("2026-03-14", x + 4, y - 2)
    y += 40
    x = f.latin("Initials:", 72, y) + 6
    x1 = f.latin("_" * 10, x, y)
    f.line_field("initials", x, x1, y + 1.5, "Initials", "underscores", "initials")
    if filled:
        f.fill_signature("JS", x + 8, y - 3, size=20)
    return f


def form_latin_services(fonts, filled):
    """Two pages: clauses, then a two-column signature block of painted rules with labels under them."""
    f = Form("latin-services", "Services Agreement", fonts)
    f.latin("Services Agreement", 72, 96, size=18, role="title")
    f.latin("This agreement is made between the Provider and the Client named on page 2.", 72, 124)
    y = 156
    for line in CLAUSES[:12]:
        f.latin(line, 72, y)
        y += 16
    f.latin("Page 1 of 2", 276, 740, size=9, role="footer")
    f.new_page()
    y = 96
    for line in CLAUSES[12:]:
        f.latin(line, 72, y)
        y += 16
    y += 20
    f.latin("Signed by the parties on the dates below.", 72, y)
    values = {
        "Provider": ("Alex Example", "Director", "Example Services Ltd", "2026-02-01"),
        "Client": ("Sam Placeholder", "Manager", "Fictional Client LLC", "2026-02-03"),
    }
    for col, (party, x0) in enumerate((("Provider", 72.0), ("Client", 324.0))):
        x1 = x0 + 216
        yy = y + 40
        f.latin(party, x0, yy, size=12, role="heading")
        yy += 46
        for label, kind in (("Signature", "signature"), ("Print name", "name"), ("Title", "title"),
                            ("Company", "company"), ("Date", "date_signed")):
            f.rule(x0, x1, yy)
            f.line_field(kind, x0, x1, yy, label, "rule", f"{party.lower()}_{kind}")
            f.latin(label, x0, yy + 12, size=9)
            if filled:
                name, title, company, date = values[party]
                value = {"name": name, "title": title, "company": company, "date_signed": date}.get(kind)
                if kind == "signature":
                    f.fill_signature(name, x0 + 6, yy - 4)
                else:
                    f.fill_text(value, x0 + 4, yy - 3)
            yy += 44
    f.latin("Page 2 of 2", 276, 740, size=9, role="footer")
    return f


def form_latin_acroform(fonts, filled):
    """Labelled boxes that are also AcroForm fields in the source PDF."""
    f = Form("latin-acroform", "Vendor Registration", fonts)
    f.latin("Vendor Registration", 72, 96, size=18, role="title")
    f.latin("Complete every box in block capitals and sign at the bottom of the page.", 72, 122)
    rows = [
        (("First name", "first_name", "Robin", 72, 228), ("Last name", "last_name", "Testcase", 312, 228)),
        (("Email", "email_address", "robin@example.com", 72, 228), ("Phone", "phone", "+1 555 0100", 312, 228)),
        (("Company", "company", "Example Trading Co", 72, 228), ("Title", "title", "Buyer", 312, 228)),
    ]
    y = 160
    for row in rows:
        for label, kind, value, x, w in row:
            f.latin(label, x, y, size=9)
            f.box(x, y + 6, w, 22)
            f.field(kind, (x, y + 6, w, 22), label, "box", kind)
            f.page.widgets.append(("Tx", kind, (x, y + 6, w, 22)))
            if filled:
                f.fill_text(value, x + 5, y + 22)
        y += 52
    y += 10
    f.checkbox(72, y - 9, "I confirm the information above is correct.", "confirm")
    f.page.widgets.append(("Btn", "confirm", (72, y - 9, 10, 10)))
    f.latin("I confirm the information above is correct.", 90, y)
    if filled:
        f.fill_check(72, y - 9)
    y += 40
    f.latin("Signature", 72, y, size=9)
    f.box(72, y + 6, 288, 44)
    f.field("signature", (72, y + 6, 288, 44), "Signature", "box", "signature")
    f.page.widgets.append(("Sig", "signature", (72, y + 6, 288, 44)))
    f.latin("Date", 384, y, size=9)
    f.box(384, y + 6, 156, 22)
    f.field("date_signed", (384, y + 6, 156, 22), "Date", "box", "date_signed")
    f.page.widgets.append(("Tx", "date_signed", (384, y + 6, 156, 22)))
    if filled:
        f.fill_signature("Robin Testcase", 84, y + 38, size=24)
        f.fill_text("2026-05-20", 389, y + 22)
    return f


def form_arabic(fonts, filled):
    """Right-to-left labels with a rule to their left (Arabic, Noto Sans Arabic)."""
    f = Form("arabic-application", "طلب توظيف", fonts)
    right = 540.0
    f.shaped("طلب توظيف", right, 100, 20, "arab", "Arab", True, role="title")
    f.shaped("يرجى تعبئة هذا النموذج بخط واضح", right, 136, 12, "arab", "Arab", True)
    values = {"name": "ليلى الأمثلة", "company": "شركة المثال"}
    y = 200
    for label, kind in (("الاسم", "name"), ("الشركة", "company"), ("المسمى الوظيفي", "title"),
                        ("التاريخ", "date_signed"), ("التوقيع", "signature")):
        left = f.shaped(label, right, y, 13, "arab", "Arab", True)
        x0, x1 = 300.0, left - 10
        f.rule(x0, x1, y + 4)
        f.line_field(kind, x0, x1, y + 4, label, "rule", kind)
        if filled and kind in values:
            f.fill_shaped(values[kind], x1 - 8, y, 13, "arab", "Arab", True)
        y += 52
    y += 10
    f.shaped("أوافق على الشروط", right - 18, y, 12, "arab", "Arab", True)
    f.checkbox(right - 10, y - 9, "أوافق على الشروط", "agree")
    if filled:
        f.fill_check(right - 10, y - 9)
    return f


def form_devanagari(fonts, filled):
    """Left-to-right Hindi labels with a rule to their right (Noto Sans Devanagari)."""
    f = Form("devanagari-application", "आवेदन पत्र", fonts)
    f.shaped("आवेदन पत्र", 72, 100, 20, "deva", "Deva", False, role="title")
    f.shaped("कृपया यह फ़ॉर्म साफ़ अक्षरों में भरें", 72, 136, 12, "deva", "Deva", False)
    y = 200
    for label, kind in (("नाम", "name"), ("कंपनी", "company"), ("पद", "title"), ("दिनांक", "date_signed"),
                        ("हस्ताक्षर", "signature")):
        x = f.shaped(label, 72, y, 13, "deva", "Deva", False)
        x0, x1 = max(x + 10, 150.0), 360.0
        f.rule(x0, x1, y + 4)
        f.line_field(kind, x0, x1, y + 4, label, "rule", kind)
        if filled and kind == "date_signed":
            f.fill_text("2026-06-30", x0 + 6, y)
        y += 52
    y += 10
    f.checkbox(72, y - 9, "मैं शर्तों से सहमत हूँ", "agree")
    f.shaped("मैं शर्तों से सहमत हूँ", 90, y, 12, "deva", "Deva", False)
    if filled:
        f.fill_check(72, y - 9)
    return f


FORMS = {
    "latin-consent": form_latin_consent,
    "latin-services": form_latin_services,
    "latin-acroform": form_latin_acroform,
    "arabic-application": form_arabic,
    "devanagari-application": form_devanagari,
}

# name, form, filled, dpi, skew degrees, JPEG quality or "fax", blur, speckles, rotate 180, stored sideways
VARIANTS = [
    ("200dpi-q75-skew+0.6", "latin-consent", False, 200, 0.6, 75, True, 40, False, False),
    ("150dpi-q60-skew-2.0", "latin-consent", False, 150, -2.0, 60, True, 150, False, False),
    ("300dpi-fax-skew+1.2", "latin-consent", False, 300, 1.2, "fax", False, 300, False, False),
    ("200dpi-q60-rot180", "latin-consent", False, 200, 0.4, 60, True, 60, True, False),
    ("filled-200dpi-q70-skew-0.9", "latin-consent", True, 200, -0.9, 70, True, 60, False, False),
    ("200dpi-q75-skew-1.1", "latin-services", False, 200, -1.1, 75, True, 40, False, False),
    ("filled-200dpi-q60-skew+0.5", "latin-services", True, 200, 0.5, 60, True, 80, False, False),
    ("200dpi-q75-rot90", "latin-services", False, 200, 0.3, 75, True, 40, False, True),
    ("200dpi-q75-skew+1.5", "latin-acroform", False, 200, 1.5, 75, True, 40, False, False),
    ("300dpi-fax-skew-0.7", "latin-acroform", False, 300, -0.7, "fax", False, 250, False, False),
    ("filled-150dpi-q60-skew+0.8", "latin-acroform", True, 150, 0.8, 60, True, 120, False, False),
    ("filled-200dpi-q75-skew-0.8", "arabic-application", True, 200, -0.8, 75, True, 40, False, False),
    ("300dpi-fax-skew+0.5", "arabic-application", False, 300, 0.5, "fax", False, 200, False, False),
    ("filled-200dpi-q70-skew+1.0", "devanagari-application", True, 200, 1.0, 70, True, 60, False, False),
    ("150dpi-q60-skew-1.6", "devanagari-application", False, 150, -1.6, 60, True, 120, False, False),
]


# ---------------------------------------------------------------------------------------------- raster pipeline


def render(page, fonts, dpi):
    c = Canvas(dpi)
    for item in page.items:
        if item[0] == "rect":
            c.rect(*item[1:])
        elif item[0] == "poly":
            c.polys([item[1]])
        else:
            _, font, size, glyphs, _ = item
            for gid, x, y in glyphs:
                c.glyph(fonts[font], gid, size, x, y)
    return c


class Shears:
    """Rotation by three integer shears about the page centre (Paeth): x, then y, then x.

    Pixels and ground-truth points move by the same integer shifts, so the truth matches the image.
    """

    def __init__(self, degrees, w, h):
        theta = degrees * math.pi / 180.0
        self.a = -(_sin(theta / 2) / _cos(theta / 2))
        self.b = _sin(theta)
        self.cx, self.cy = w / 2.0, h / 2.0
        self.w, self.h = w, h

    def sx(self, row):
        return _round(self.a * (row + 0.5 - self.cy))

    def sy(self, col):
        return _round(self.b * (col + 0.5 - self.cx))

    def point(self, x, y):
        x += self.sx(math.floor(y))
        y += self.sy(math.floor(x))
        x += self.sx(math.floor(y))
        return x, y

    def image(self, pix, paper):
        w, h = self.w, self.h
        fill = bytes([paper])

        def shear_x(src):
            out = bytearray(len(src))
            for r in range(h):
                s = self.sx(r)
                row = src[r * w:(r + 1) * w]
                if s > 0:
                    row = fill * s + row[:w - s]
                elif s < 0:
                    row = row[-s:] + fill * (-s)
                out[r * w:(r + 1) * w] = row
            return out

        def shear_y(src):
            out = bytearray(len(src))
            for col in range(w):
                t = self.sy(col)
                column = src[col::w]
                if t > 0:
                    column = fill * t + column[:h - t]
                elif t < 0:
                    column = column[-t:] + fill * (-t)
                out[col::w] = column
            return out

        return shear_x(shear_y(shear_x(pix)))


def tone(pix, paper, ink):
    table = bytes(ink + (v * (paper - ink) + 127) // 255 for v in range(256))
    return bytearray(pix.translate(table))


def blur(pix, w, h):
    """A [1 2 1] blur in x then y; uniform rows are passed through."""
    out = bytearray(pix)
    for r in range(h):
        row = pix[r * w:(r + 1) * w]
        if row.count(row[0]) == w:
            continue
        left = row[:1] + row[:-1]
        right = row[1:] + row[-1:]
        out[r * w:(r + 1) * w] = bytes((a + 2 * b + c + 2) >> 2 for a, b, c in zip(left, row, right))
    src = out
    out = bytearray(src)
    for r in range(h):
        up = src[max(0, r - 1) * w:max(0, r - 1) * w + w]
        row = src[r * w:(r + 1) * w]
        down = src[min(h - 1, r + 1) * w:min(h - 1, r + 1) * w + w]
        if up == row == down:
            continue
        out[r * w:(r + 1) * w] = bytes((a + 2 * b + c + 2) >> 2 for a, b, c in zip(up, row, down))
    return out


def speckle(pix, w, h, n, rng, paper, ink):
    """n dark specks and, one in four, light dropouts: squares of 1 to 3 pixels."""
    for _ in range(n):
        x, y, size = rng.below(w - 3), rng.below(h - 3), 1 + rng.below(3)
        value = paper - 20 - rng.below(40) if rng.below(4) == 0 else ink + rng.below(60)
        for dy in range(size):
            base = (y + dy) * w + x
            pix[base:base + size] = bytes([value]) * size


def rotate90_ccw(pix, w, h):
    """The image turned a quarter counter-clockwise (stored with /Rotate 90 it displays upright)."""
    out = bytearray(len(pix))
    for r in range(w):
        out[r * h:(r + 1) * h] = pix[w - 1 - r::w]
    return out


# ---------------------------------------------------------------------------------------------- encoders

ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7,
          14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46,
          53, 60, 61, 54, 47, 55, 62, 63]
# ITU-T T.81 Annex K: luminance quantisation (natural order) and the typical Huffman tables.
QUANT = [16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22,
         29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103,
         121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99]
DC_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
DC_VALS = list(range(12))
AC_BITS = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D]
AC_VALS = [0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71,
           0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
           0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A]
for _hi in (0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0):
    AC_VALS += [_hi + lo for lo in (range(4, 11) if _hi == 0x30 else range(3, 11) if _hi < 0x90
                                    else range(2, 11) if _hi < 0xE0 else range(1, 11))]


def _huffman(bits, vals):
    table, code, k = {}, 0, 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            table[vals[k]] = (code, length)
            k += 1
            code += 1
        code <<= 1
    return table


def _dct_matrix():
    """M[u][x] = round(4096 * C(u)/2 * cos((2x+1)u pi/16)), from the series, not libm."""
    def cos16(k):  # cos(k pi / 16), reduced to [0, pi/2] for the series
        k %= 32
        if k > 16:
            k = 32 - k
        return -_cos((16 - k) * math.pi / 16) if k > 8 else _cos(k * math.pi / 16)

    m = []
    for u in range(8):
        cu = 1 / math.sqrt(2) if u == 0 else 1.0
        m.append([_round(4096 * cu / 2 * cos16((2 * x + 1) * u)) for x in range(8)])
    return m


def jpeg_gray(pix, w, h, quality, dpi):
    """Baseline sequential greyscale JPEG (JFIF, dpi recorded), integer DCT and quantisation."""
    if len(AC_VALS) != 162 or sum(AC_BITS) != 162:
        raise Problem("JPEG AC table is not the 162 values of T.81 Annex K")
    scale = 5000 // quality if quality < 50 else 200 - 2 * quality
    q = [min(255, max(1, (t * scale + 50) // 100)) for t in QUANT]
    dc_t, ac_t = _huffman(DC_BITS, DC_VALS), _huffman(AC_BITS, AC_VALS)
    m = _dct_matrix()
    one = 1 << 24
    half = 1 << 23
    wp, hp = (w + 7) // 8 * 8, (h + 7) // 8 * 8
    rows = []
    for r in range(hp):
        row = bytes(pix[min(r, h - 1) * w:min(r, h - 1) * w + w])
        rows.append(row + row[-1:] * (wp - w))
    out = bytearray()
    acc = nbits = 0
    prev_dc = 0
    m00 = m[0][0] * m[0][0] * 64

    def emit(code, length):
        nonlocal acc, nbits
        acc = (acc << length) | code
        nbits += length
        while nbits >= 8:
            nbits -= 8
            byte = (acc >> nbits) & 0xFF
            out.append(byte)
            if byte == 0xFF:
                out.append(0)
        acc &= (1 << nbits) - 1

    def quant(n, qq):
        d = qq * one
        return (abs(n) + qq * half) // d * (1 if n >= 0 else -1)

    for by in range(0, hp, 8):
        band = rows[by:by + 8]
        for bx in range(0, wp, 8):
            blk = [r[bx:bx + 8] for r in band]
            first = blk[0]
            if first.count(first[0]) == 8 and all(b == first for b in blk):
                coef = [0] * 64
                coef[0] = quant(m00 * (first[0] - 128), q[0])
            else:
                f = [[v - 128 for v in r] for r in blk]
                tmp = [[sum(mu[x] * fy[x] for x in range(8)) for mu in m] for fy in f]
                coef = [0] * 64
                for v in range(8):
                    mv = m[v]
                    for u in range(8):
                        n = sum(mv[y] * tmp[y][u] for y in range(8))
                        coef[v * 8 + u] = quant(n, q[v * 8 + u])
            diff = coef[0] - prev_dc
            prev_dc = coef[0]
            size = abs(diff).bit_length()
            emit(*dc_t[size])
            if size:
                emit(diff if diff > 0 else diff + (1 << size) - 1, size)
            run = 0
            for k in range(1, 64):
                c = coef[ZIGZAG[k]]
                if c == 0:
                    run += 1
                    continue
                while run > 15:
                    emit(*ac_t[0xF0])
                    run -= 16
                size = abs(c).bit_length()
                emit(*ac_t[(run << 4) | size])
                emit(c if c > 0 else c + (1 << size) - 1, size)
                run = 0
            if run:
                emit(*ac_t[0x00])
    if nbits:
        emit((1 << (8 - nbits)) - 1, 8 - nbits)

    def seg(marker, body):
        return bytes([0xFF, marker]) + (len(body) + 2).to_bytes(2, "big") + body

    def dht(cls_id, bits, vals):
        return bytes([cls_id]) + bytes(bits) + bytes(vals)

    head = b"\xff\xd8"
    head += seg(0xE0, b"JFIF\x00\x01\x01\x01" + dpi.to_bytes(2, "big") * 2 + b"\x00\x00")
    head += seg(0xDB, b"\x00" + bytes(q[i] for i in ZIGZAG))
    head += seg(0xC0, b"\x08" + h.to_bytes(2, "big") + w.to_bytes(2, "big") + b"\x01\x01\x11\x00")
    head += seg(0xC4, dht(0x00, DC_BITS, DC_VALS) + dht(0x10, AC_BITS, AC_VALS))
    head += seg(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    return head + bytes(out) + b"\xff\xd9"


def bilevel(pix, w, h, threshold):
    """1 bit per pixel, 1 = white (DeviceGray), rows padded to whole bytes."""
    table = bytes(0x31 if v >= threshold else 0x30 for v in range(256))
    pad = b"1" * ((-w) % 8)
    nbytes = (w + 7) // 8
    out = bytearray()
    for r in range(h):
        bits = pix[r * w:(r + 1) * w].translate(table) + pad
        out += int(bits, 2).to_bytes(nbytes, "big")
    return bytes(out)


def runlength(data):
    """PDF RunLengthDecode encoding."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = i + 1
        while j < n and j - i < 128 and data[j] == data[i]:
            j += 1
        if j - i >= 2:
            out += bytes((257 - (j - i), data[i]))
            i = j
            continue
        j = i + 1
        while j < n and j - i < 128 and not (j + 1 < n and data[j] == data[j + 1]):
            j += 1
        out.append(j - i - 1)
        out += data[i:j]
        i = j
    out.append(128)
    return bytes(out)


# ---------------------------------------------------------------------------------------------- PDF writers


def pdf_file(bodies):
    """bodies[i] is object i + 1; object 1 is the catalogue. Classic xref, no compression, no dates."""
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, body in enumerate(bodies):
        offs.append(len(out))
        out += b"%d 0 obj\n" % (i + 1) + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(bodies) + 1)
    for o in offs:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (len(bodies) + 1, xref)
    return bytes(out)


def stream(dict_body, data):
    return b"<<" + dict_body + b"/Length %d>>\nstream\n" % len(data) + data + b"\nendstream"


def pdf_string(text):
    return "(" + text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


def utf16_hex(text):
    return "<FEFF" + text.encode("utf-16-be").hex().upper() + ">"


def source_pdf(form, fonts):
    """The vector form: text layer (Helvetica for Latin, embedded Noto as Identity-H for the scripts with
    ActualText per word), rules and boxes as filled rectangles, AcroForm fields where the form has them."""
    bodies = [None, None]  # catalogue, pages
    script_fonts = {}  # font key -> (font resource name, used gids, tounicode map)
    for page in form.pages:
        for item in page.items:
            if item[0] == "glyphs" and item[1] in ("arab", "deva"):
                entry = script_fonts.setdefault(item[1], ("F%d" % (len(script_fonts) + 2), {}, {}))
                for gid, *_ in item[3]:
                    entry[1][gid] = fonts[item[1]].advances[gid] * 1000 // fonts[item[1]].upem
                # ToUnicode is best effort (ActualText per word is exact): the first glyph of each cluster,
                # in logical order, maps to the cluster's text.
                run = SHAPED[item[4]]
                starts = sorted({g[4] for g in run})
                seen = set()
                for g in (run[::-1] if item[1] == "arab" else run):
                    if g[4] in seen:
                        continue
                    seen.add(g[4])
                    nxt = [s for s in starts if s > g[4]]
                    entry[2].setdefault(g[0], item[4][g[4]:nxt[0] if nxt else len(item[4])])
    font_refs = {}
    helv = len(bodies) + 1
    bodies.append(b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>")
    font_refs["F1"] = helv
    for key in sorted(script_fonts):
        res, used, tounicode = script_fonts[key]
        ft = fonts[key]
        name = {"arab": "NotoSansArabic-Regular", "deva": "NotoSansDevanagari-Regular"}[key].encode()
        n0 = len(bodies) + 1  # type0, cid font, descriptor, font file, tounicode
        widths = b" ".join(b"%d[%d]" % (g, used[g]) for g in sorted(used))
        cmap_lines = "\n".join("<%04X> %s" % (g, utf16_hex(tounicode[g])[5:-1].join("<>")) for g in sorted(tounicode))
        cmap = ("/CIDInit/ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo<</Registry(Adobe)"
                "/Ordering(UCS)/Supplement 0>>def\n/CMapName/Adobe-Identity-UCS def\n/CMapType 2 def\n"
                "1 begincodespacerange\n<0000><FFFF>\nendcodespacerange\n%d beginbfchar\n%s\nendbfchar\n"
                "endcmap\nCMapName currentdict/CMap defineresource pop\nend\nend" % (len(tounicode), cmap_lines))
        bodies.append(b"<</Type/Font/Subtype/Type0/BaseFont/%s/Encoding/Identity-H/DescendantFonts[%d 0 R]"
                      b"/ToUnicode %d 0 R>>" % (name, n0 + 1, n0 + 4))
        bodies.append(b"<</Type/Font/Subtype/CIDFontType2/BaseFont/%s/CIDSystemInfo<</Registry(Adobe)"
                      b"/Ordering(Identity)/Supplement 0>>/FontDescriptor %d 0 R/CIDToGIDMap/Identity/DW 0/W[%s]>>"
                      % (name, n0 + 2, widths))
        k = 1000 / ft.upem
        bodies.append(("<</Type/FontDescriptor/FontName/%s/Flags 4/FontBBox[%s]/ItalicAngle 0/Ascent %d"
                       "/Descent %d/CapHeight %d/StemV 80/FontFile2 %d 0 R>>"
                       % (name.decode(), " ".join(str(_round(v * k)) for v in ft.bbox), _round(ft.ascender * k),
                          _round(ft.descender * k), _round(ft.ascender * k), n0 + 3)).encode())
        bodies.append(stream(b"/Length1 %d" % len(ft.data), ft.data))
        bodies.append(stream(b"", cmap.encode()))
        font_refs[res] = n0
    font_dict = b"<<" + b"".join(b"/%s %d 0 R" % (k.encode(), v) for k, v in sorted(font_refs.items())) + b">>"
    page_refs, all_widgets = [], []
    for page in form.pages:
        ops = []
        for item in page.items:
            if item[0] == "rect":
                _, x, y, w, h = item
                ops.append("%s %s %s %s re f" % (fmt(x), fmt(PAGE_H - y - h), fmt(w), fmt(h)))
            elif item[0] == "poly":
                pts = item[1]
                ops.append(" ".join("%s %s %s" % (fmt(x), fmt(PAGE_H - y), "m" if i == 0 else "l")
                                    for i, (x, y) in enumerate(pts)) + " h f")
            elif item[1] in ("sans", "script"):
                _, font, size, glyphs, word = item
                if font == "script":
                    continue  # filled values are never in the source PDF
                x, y = glyphs[0][1], glyphs[0][2]
                ops.append("BT /F1 %s Tf 1 0 0 1 %s %s Tm %s Tj ET" % (fmt(size), fmt(x), fmt(PAGE_H - y),
                                                                       pdf_string(word)))
            else:
                _, font, size, glyphs, word = item
                res = script_fonts[font][0]
                ops.append("/Span<</ActualText %s>>BDC BT /%s %s Tf" % (utf16_hex(word), res, fmt(size)))
                for gid, x, y in (glyphs[::-1] if font == "arab" else glyphs):  # logical order in the stream
                    ops.append("1 0 0 1 %s %s Tm <%04X> Tj" % (fmt(x), fmt(PAGE_H - y), gid))
                ops.append("ET EMC")
        content = ("\n".join(ops) + "\n").encode()
        content_ref = len(bodies) + 1
        bodies.append(stream(b"", content))
        page_ref = len(bodies) + 1
        bodies.append(None)
        annots = []
        for kind, name, (x, y, w, h) in page.widgets:
            rect = "[%s %s %s %s]" % (fmt(x), fmt(PAGE_H - y - h), fmt(x + w), fmt(PAGE_H - y))
            ref = len(bodies) + 1
            if kind == "Btn":
                on = ref + 1
                off = ref + 2
                body = ("<</Type/Annot/Subtype/Widget/FT/Btn/T%s/Rect%s/F 4/P %d 0 R/V/Off/AS/Off"
                        "/AP<</N<</Yes %d 0 R/Off %d 0 R>>>>>>" % (pdf_string(name), rect, page_ref, on, off))
                bodies.append(body.encode())
                bbox = b"/Type/XObject/Subtype/Form/BBox[0 0 %s %s]" % (fmt(w).encode(), fmt(h).encode())
                bodies.append(stream(bbox, b"q 1 w 2 2 m 8 8 l 8 2 m 2 8 l S Q"))
                bodies.append(stream(bbox, b""))
            else:
                extra = "/DA(/Helv 10 Tf 0 g)" if kind == "Tx" else ""
                bodies.append(("<</Type/Annot/Subtype/Widget/FT/%s/T%s/Rect%s/F 4/P %d 0 R%s>>"
                               % (kind, pdf_string(name), rect, page_ref, extra)).encode())
            annots.append(ref)
        all_widgets += annots
        annot_part = (b"/Annots[" + b" ".join(b"%d 0 R" % a for a in annots) + b"]") if annots else b""
        bodies[page_ref - 1] = (b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font %s>>"
                                b"/Contents %d 0 R%s>>" % (font_dict, content_ref, annot_part))
        page_refs.append(page_ref)
    acro = b""
    if all_widgets:
        acro = (b"/AcroForm<</Fields[" + b" ".join(b"%d 0 R" % a for a in all_widgets) +
                b"]/DA(/Helv 10 Tf 0 g)/DR<</Font<</Helv %d 0 R>>>>>>" % helv)
    bodies[0] = b"<</Type/Catalog/Pages 2 0 R%s>>" % acro
    bodies[1] = b"<</Type/Pages/Kids[" + b" ".join(b"%d 0 R" % p for p in page_refs) + \
        b"]/Count %d>>" % len(page_refs)
    return pdf_file(bodies)


def scan_pdf(pages):
    """Image-only PDF: pages = [(w_px, h_px, dpi, filter, bits, data, rotate)]."""
    bodies = [b"<</Type/Catalog/Pages 2 0 R>>", None]
    refs = []
    for w, h, dpi, filt, bits, data, rotate in pages:
        wpt, hpt = w * 72.0 / dpi, h * 72.0 / dpi
        img = len(bodies) + 1
        bodies.append(stream(b"/Type/XObject/Subtype/Image/Width %d/Height %d/ColorSpace/DeviceGray"
                             b"/BitsPerComponent %d/Filter/%s" % (w, h, bits, filt.encode()), data))
        content = ("q %s 0 0 %s 0 0 cm /Im0 Do Q\n" % (fmt(wpt), fmt(hpt))).encode()
        bodies.append(stream(b"", content))
        rot = b"/Rotate %d" % rotate if rotate else b""
        bodies.append(b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 %s %s]%s/Resources<</XObject<</Im0 %d 0 R>>>>"
                      b"/Contents %d 0 R>>" % (fmt(wpt).encode(), fmt(hpt).encode(), rot, img, img + 1))
        refs.append(len(bodies))
    bodies[1] = b"<</Type/Pages/Kids[" + b" ".join(b"%d 0 R" % r for r in refs) + b"]/Count %d>>" % len(refs)
    return pdf_file(bodies)


# ---------------------------------------------------------------------------------------------- truth


def _map_rect(rect, mapper):
    x, y, w, h = rect
    pts = [mapper(px, py) for px, py in ((x, y), (x + w, y), (x, y + h), (x + w, y + h))]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return [r2(min(xs)), r2(min(ys)), r2(max(xs) - min(xs)), r2(max(ys) - min(ys))]


def truth_page(page, mapper):
    fields = []
    for f in page.fields:
        fields.append({"kind": f["kind"], "name": f["name"], "label": f["label"], "drawn": f["drawn"],
                       "rect": _map_rect(f["rect"], mapper), "form_rect": [r2(v) for v in f["rect"]]})
    words = [{"text": w["text"], "script": w["script"], "role": w["role"], "rect": _map_rect(w["rect"], mapper)}
             for w in page.words]
    return {"fields": fields, "words": words}


def dump_json(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------------------------- build


def build_scan(variant, fonts):
    name, form_name, filled, dpi, skew, quality, do_blur, specks, rot180, sideways = variant
    form = FORMS[form_name](fonts, filled)
    rng = Rng(f"{form_name}--{name}")
    paper, ink = 236 + rng.below(10), 18 + rng.below(25)
    pages_pdf, pages_truth = [], []
    for index, page in enumerate(form.pages):
        canvas = render(page, fonts, dpi)
        w, h = canvas.w, canvas.h
        pix = tone(canvas.pix, paper, ink)
        shears = Shears(skew, w, h)
        pix = shears.image(pix, paper)
        if do_blur:
            pix = blur(pix, w, h)
        speckle(pix, w, h, specks, rng, paper, ink)
        if rot180:
            pix = pix[::-1]
        s = dpi / 72.0

        def mapper(x, y, shears=shears, w=w, h=h, s=s):
            px, py = shears.point(x * s, y * s)
            if rot180:
                px, py = w - px, h - py
            return px / s, py / s

        if quality == "fax":
            data = runlength(bilevel(pix, w, h, (paper + ink) // 2))
            filt, bits = "RunLengthDecode", 1
        else:
            filt, bits = "DCTDecode", 8
        sw, sh = w, h
        if sideways:
            pix = rotate90_ccw(pix, w, h)
            sw, sh = h, w
        if quality != "fax":
            data = jpeg_gray(pix, sw, sh, quality, dpi)
        elif sideways:
            raise Problem(f"{name}: a sideways fax page is not built")
        pages_pdf.append((sw, sh, dpi, filt, bits, data, 90 if sideways else 0))
        tp = truth_page(page, mapper)
        tp["page"] = index
        pages_truth.append(tp)
    file_name = f"{form_name}--{name}"
    truth = {
        "schema": 1,
        "synthetic": True,
        "file": f"scans/{file_name}.pdf",
        "form": form_name,
        "template": form_name,
        "filled": filled,
        "source": f"vector/{form_name}.pdf",
        "coordinates": "displayed page space, points, origin top left (ADR-019); form_rect is the clean form",
        "image": {"dpi": dpi, "width_px": pages_pdf[0][0], "height_px": pages_pdf[0][1],
                  "filter": pages_pdf[0][3], "bits_per_component": pages_pdf[0][4]},
        "degradation": {"seed": f"{MASTER_SEED}:{form_name}--{name}", "paper": paper, "ink": ink,
                        "skew_degrees": skew, "blur": "[1 2 1] x and y" if do_blur else None,
                        "jpeg_quality": None if quality == "fax" else quality,
                        "binarised": quality == "fax", "speckles_per_page": specks, "rotated_180": rot180,
                        "page_rotate": 90 if sideways else 0},
        "pages": pages_truth,
    }
    return file_name, scan_pdf(pages_pdf), dump_json(truth)


def build_all():
    """Every generated file: {path relative to fixtures/ml: (bytes, provenance)}."""
    fonts = load_fonts()
    files = {}
    for form_name, maker in FORMS.items():
        form = maker(fonts, False)
        files[f"vector/{form_name}.pdf"] = (source_pdf(form, fonts), f"make-scans.py form={form_name} (vector)")
        truth = {"schema": 1, "synthetic": True, "file": f"vector/{form_name}.pdf", "form": form_name,
                 "template": form_name, "filled": False,
                 "coordinates": "displayed page space, points, origin top left (ADR-019)",
                 "pages": []}
        for index, page in enumerate(form.pages):
            tp = truth_page(page, lambda x, y: (x, y))
            tp["page"] = index
            truth["pages"].append(tp)
        files[f"truth/{form_name}.json"] = (dump_json(truth), f"make-scans.py form={form_name} (truth)")
    for variant in VARIANTS:
        file_name, pdf, truth = build_scan(variant, fonts)
        prov = f"make-scans.py form={variant[1]} variant={variant[0]}"
        files[f"scans/{file_name}.pdf"] = (pdf, prov)
        files[f"truth/{file_name}.json"] = (truth, prov + " (truth)")
    return files


def manifest(files):
    rows = ["file\tsha256\tbytes\torigin\tlicence\tprovenance"]
    for key, (rel, sha, licence, prov) in sorted(FONTS.items(), key=lambda kv: kv[1][0]):
        if rel.startswith("fixtures/ml/"):
            size = (ROOT / rel).stat().st_size
            rows.append(f"{rel[len('fixtures/ml/'):]}\t{sha}\t{size}\tthird-party\t{licence}\t{prov}")
    for rel, (licence, prov) in sorted(LICENCE_FILES.items()):
        data = (OUT / rel).read_bytes()
        rows.append(f"{rel}\t{hashlib.sha256(data).hexdigest()}\t{len(data)}\tthird-party\t{licence}\t{prov}")
    for rel in sorted(files):
        data, prov = files[rel]
        rows.append(f"{rel}\t{hashlib.sha256(data).hexdigest()}\t{len(data)}\tsynthetic\tApache-2.0\t{prov}")
    return ("\n".join(rows) + "\n").encode()


def write():
    files = build_all()
    for d in GENERATED_DIRS:
        (OUT / d).mkdir(parents=True, exist_ok=True)
        for old in (OUT / d).iterdir():
            if old.is_file() and old.relative_to(OUT).as_posix() not in files:
                old.unlink()
    for rel, (data, _) in files.items():
        (OUT / rel).write_bytes(data)
    (OUT / MANIFEST).write_bytes(manifest(files))
    total = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    print(f"fixtures/ml: {len(files)} generated files, {total} bytes in all")


def check():
    files = build_all()
    problems = []
    expected = dict((rel, data) for rel, (data, _) in files.items())
    expected[MANIFEST] = manifest(files)
    for rel, data in sorted(expected.items()):
        path = OUT / rel
        if not path.is_file():
            problems.append(f"{rel}: missing (run tools/ml/make-scans.py)")
        elif path.read_bytes() != data:
            problems.append(f"{rel}: differs from what make-scans.py generates")
    for d in GENERATED_DIRS:
        for p in sorted((OUT / d).glob("*")) if (OUT / d).is_dir() else []:
            if p.relative_to(OUT).as_posix() not in expected:
                problems.append(f"{p.relative_to(OUT).as_posix()}: not generated by make-scans.py")
    total = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
    if total > BUDGET:
        problems.append(f"fixtures/ml is {total} bytes, over the {BUDGET}-byte budget")
    for line in expected[MANIFEST].decode().splitlines()[1:]:
        origin = line.split("\t")[3]
        if origin not in ("synthetic", "third-party"):
            problems.append(f"manifest row with origin {origin!r}")
    if problems:
        print("scan fixtures out of step (tools/ml/make-scans.py --check):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"scan fixtures: {len(files)} files byte-identical, {total} bytes, every generated file synthetic")
    return 0


def main(argv):
    try:
        if argv[1:] == ["--check"]:
            return check()
        if argv[1:]:
            print("usage: make-scans.py [--check]", file=sys.stderr)
            return 2
        write()
        return 0
    except Problem as e:
        print(f"make-scans.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
