#!/usr/bin/env python3
"""Describe a PDF by scanning its bytes: producer, creator, version, pages, features (`F-004`).

    python3 -I fixtures/corpus/pdfscan.py FILE.pdf [...]     # file, family, version, pages, features,
                                                              # producer, creator, page note
    python3 -I fixtures/corpus/pdfscan.py --json FILE.pdf    # the same, as JSON

Standard library only. The file is untrusted data: it is read, never run, and every
step is bounded (50 MiB input, 16 MiB per inflated stream, 96 MiB inflated in all).
Only object streams, xref streams and XMP metadata streams are inflated, which is where
/Producer, /Type /Page and /AcroForm hide in files that compress their objects.

This is a heuristic describer for the corpus manifest, not a PDF reader:
- `pages` is the /Count of the root page-tree node (the /Pages object with no /Parent,
  last revision wins), checked against the number of distinct /Type /Page objects;
  `pages_note` says when they disagree. Encrypted files hide object streams and strings,
  so their pages and producer may be blank here (README.md says how the manifest was
  completed for them).
- `features` come from byte patterns; see FEATURES below for each rule.
"""
import json
import re
import sys
import zlib

MAX_FILE = 50 * 1024 * 1024
MAX_STREAM = 16 * 1024 * 1024
MAX_INFLATED = 96 * 1024 * 1024

OBJ = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj\b")
STREAM = re.compile(rb"stream\r?\n")
SCANNER_WORDS = re.compile(
    r"(?i)scan|capture|paperport|omnipage|abbyy|finereader|xerox|canon|ricoh|kofax|fujitsu|epson|"
    r"brother|kodak|hp digital sending|imagerunner|bizhub|konica|sharp|tesseract|ocrmypdf|internet archive|"
    r"luratech|luradocument|image alchemy"
)

# feature -> what sets it. The rules are in scan().
FEATURES = {
    "acroform": "the catalog names an /AcroForm with a /Fields array",
    "signed": "a signature dictionary with /ByteRange that is not only Reader usage rights",
    "usage-rights": "a /UR or /UR3 usage-rights signature (Reader extensions), not a signer's signature",
    "certified": "a signature with a /DocMDP transform (certification signature)",
    "encrypted": "the trailer (or xref stream) has /Encrypt",
    "xref-stream": "a /Type /XRef stream is present",
    "objstm": "a /Type /ObjStm stream is present",
    "incremental": "more %%EOF markers than a plain (or linearized) file has",
    "linearized": "/Linearized in the first 1024 bytes",
    "pdfa": "XMP metadata carries pdfaid:part",
    "scanned": "an image per page and no fonts or only an OCR font, or a scanner or OCR producer",
    "rotated-pages": "a page has /Rotate 90, 180 or 270",
    "cropbox": "a /CropBox differs from every /MediaBox",
    "xfa": "an /XFA entry is present",
    "javascript": "/JavaScript or /JS action present",
    "embedded-files": "/EmbeddedFiles name tree or /Type /EmbeddedFile stream",
    "tagged": "/MarkInfo with /Marked true",
}


# Producer family: the first rule whose pattern matches "Producer | Creator" wins. Authoring
# apps that write through Adobe's engine (InDesign, PDFMaker for Office, LiveCycle) are
# named by the app, because that is what shapes the file; everything else by its writer.
FAMILY_RULES = [
    (r"InDesign", "Adobe InDesign"),
    (r"Illustrator", "Adobe Illustrator"),
    (r"FrameMaker", "Adobe FrameMaker"),
    (r"PageMaker", "Adobe PageMaker"),
    (r"LiveCycle Designer|^Designer \d", "Adobe LiveCycle Designer"),
    (r"PDFMaker", "Microsoft Office via Acrobat PDFMaker"),
    (r"^Microsoft.{0,3} (Office )?Word|^Microsoft Word", "Microsoft Word"),
    (r"^Microsoft.{0,3} (Office )?PowerPoint", "Microsoft PowerPoint"),
    (r"^Microsoft.{0,3} (Office )?Excel", "Microsoft Excel"),
    (r"^Microsoft: Print To PDF", "Microsoft Print to PDF"),
    (r"LibreOffice|OpenOffice", "LibreOffice / OpenOffice"),
    (r"Acrobat (Net )?Distiller", "Adobe Acrobat Distiller"),
    (r"Acrobat PDFWriter", "Adobe Acrobat PDFWriter"),
    (r"Paper Capture|Pdf\.Capture|Image Alchemy|ScanSoft|Kofax|OmniPage|ABBYY|FineReader|LuraDocument|LuraTech|Internet Archive|"
     r"Canon|RICOH|Xerox|KONICA|bizhub|ScanSnap|Fujitsu|EPSON|Brother|HP Digital Sending|tesseract|OCRmyPDF",
     "Scanner or OCR software"),
    (r"Adobe Acrobat|Adobe PDF [Ll]ibrary|Acrobat Pro", "Adobe Acrobat / PDF Library"),
    (r"APJavaScript|OneForm", "Amgraf OneForm Designer"),
    (r"pdfe?TeX", "pdfTeX"),
    (r"Lua(HB)?TeX", "LuaTeX"),
    (r"dvipdfm|XeTeX|xdvipdfmx", "XeTeX / dvipdfmx"),
    (r"Ghostscript", "Ghostscript"),
    (r"Quartz PDFContext", "Quartz PDFContext (macOS)"),
    (r"Skia/PDF", "Skia/PDF (Chrome, Google Docs)"),
    (r"^ \| Google$", "Google Slides"),  # no /Producer, /Creator (Google)
    (r"iText", "iText"),
    (r"Apache FOP", "Apache FOP"),
    (r"^Qt \d|wkhtmltopdf", "Qt (wkhtmltopdf)"),
    (r"3-Heights", "PDF Tools 3-Heights"),
    (r"Prince", "Prince"),
    (r"WeasyPrint", "WeasyPrint"),
    (r"ReportLab", "ReportLab"),
    (r"ImageMagick|imagemagick", "ImageMagick"),
    (r"FPDF", "FPDF"),
    (r"cairo", "cairo"),
    (r"PyPDF2|pypdf", "pypdf"),
    (r"(?i)pyHanko", "pyHanko"),
    (r"pikepdf", "pikepdf"),
    (r"iLovePDF", "iLovePDF"),
    (r"ComSquare|IrfanView", "IrfanView"),
    (r"Apex PDFWriter", "Apex PDFWriter"),
    (r"ArcGIS", "Esri ArcGIS"),
    (r"PDF Annotator", "PDF Annotator"),
    (r"calibre", "calibre"),
    (r"PDFCreator", "PDFCreator"),
    (r"adlibsoftware", "Adlib PDF"),
    (r"Nitro PDF", "Nitro PDF"),
    (r"Foxit", "Foxit"),
    (r"Datalogics", "Datalogics APDFL"),
    (r"^By hand", "Hand-written"),
    (r"^Ipe ", "Ipe"),
]
NO_PRODUCER = "No /Producer recorded"
FAMILIES = [f for _, f in FAMILY_RULES] + [NO_PRODUCER]


def family(producer, creator):
    """The producer family for the manifest's producer column."""
    key = f"{producer} | {creator}"
    for pattern, fam in FAMILY_RULES:
        if re.search(pattern, key):
            return fam
    return NO_PRODUCER if not producer else "Other: " + producer


class Budget:
    def __init__(self):
        self.left = MAX_INFLATED


def inflate(data, budget):
    if budget.left <= 0:
        return b""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, min(MAX_STREAM, budget.left))
    except zlib.error:
        return b""
    budget.left -= len(out)
    return out


def stream_body(buf, dict_end):
    """The raw stream data after a dictionary that ends at dict_end, using /Length when direct."""
    m = STREAM.match(buf, dict_end) or STREAM.match(buf, dict_end + 1) or STREAM.match(buf, dict_end + 2)
    if not m:
        return None
    start = m.end()
    end = buf.find(b"endstream", start)
    if end < 0:
        end = min(len(buf), start + MAX_STREAM)
    return buf[start:end]


def dict_span(buf, start, limit=1 << 16):
    """End offset of the << ... >> dictionary starting at start (bounded)."""
    depth, i, n = 0, start, min(len(buf), start + limit)
    while i < n - 1:
        two = buf[i:i + 2]
        if two == b"<<":
            depth += 1
            i += 2
            continue
        if two == b">>":
            depth -= 1
            i += 2
            if depth == 0:
                return i
            continue
        i += 1
    return None


def objects(buf, budget):
    """{object number: body bytes}, objstm members included. The definition later in the file wins
    (an object stream's members count as defined where the stream is), as in an incremental update."""
    objs, where = {}, {}
    positions = [(m.start(), m.end(), int(m.group(1))) for m in OBJ.finditer(buf)]
    for k, (s, e, num) in enumerate(positions):
        nxt = positions[k + 1][0] if k + 1 < len(positions) else len(buf)
        end = buf.find(b"endobj", e, nxt)
        objs[num], where[num] = buf[e:end if end >= 0 else nxt], s
    for num, body in sorted(objs.items(), key=lambda kv: where[kv[0]]):
        if b"/ObjStm" not in body[:4096]:
            continue
        ds = body.find(b"<<")
        de = dict_span(body, ds) if ds >= 0 else None
        if de is None:
            continue
        head = body[ds:de]
        raw = stream_body(body, de)
        if raw is None or b"/FlateDecode" not in head:
            continue
        data = inflate(raw, budget)
        first = re.search(rb"/First\s+(\d+)", head)
        if not data or not first:
            continue
        first = int(first.group(1))
        nums = [int(x) for x in re.findall(rb"\d+", data[:first])]
        pairs = list(zip(nums[0::2], nums[1::2]))
        for j, (onum, off) in enumerate(pairs):
            a = first + off
            b = first + pairs[j + 1][1] if j + 1 < len(pairs) else len(data)
            if where.get(onum, -1) < where[num]:
                objs[onum], where[onum] = data[a:b], where[num]
    return objs


def pdf_string(raw):
    """Decode a PDF literal or hex string's bytes (PDFDocEncoding approximated as Latin-1)."""
    if raw.startswith(b"<"):
        try:
            raw = bytes.fromhex(re.sub(rb"\s", b"", raw[1:-1]).decode("ascii"))
        except ValueError:
            return ""
    else:
        body, out, i = raw[1:-1], bytearray(), 0
        esc = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}
        while i < len(body):
            c = body[i:i + 1]
            if c == b"\\" and i + 1 < len(body):
                n = body[i + 1:i + 2]
                oct_m = re.match(rb"[0-7]{1,3}", body[i + 1:i + 4])
                if oct_m:
                    out.append(int(oct_m.group(0), 8) & 0xFF)
                    i += 1 + len(oct_m.group(0))
                    continue
                out += esc.get(n, n if n not in b"\r\n" else b"")
                i += 2
                continue
            out += c
            i += 1
        raw = bytes(out)
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf8", "replace")
    return raw.decode("latin-1")


def string_value(blob, key):
    """The last /Key (string) or /Key <hex> value in blob."""
    found = None
    for m in re.finditer(rb"/" + key + rb"\s*(\((?:\\.|[^\\)]|\([^)]*\))*\)|<[0-9A-Fa-f\s]*>)", blob, re.S):
        found = m.group(1)
    return pdf_string(found).strip() if found else ""


def xmp_value(xmp, tag):
    m = re.search(rb"<" + tag + rb">\s*(?:<rdf:Alt>\s*<rdf:li[^>]*>)?([^<]*)<", xmp) or \
        re.search(rb"\b" + tag + rb"=\"([^\"]*)\"", xmp)
    return m.group(1).decode("utf8", "replace").strip() if m else ""


def scan(data):
    if len(data) > MAX_FILE:
        raise ValueError(f"over {MAX_FILE} bytes")
    budget = Budget()
    head = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    version = head.group(1).decode() if head else "?"
    objs = objects(data, budget)
    # XMP: often an uncompressed stream; inflate compressed /Metadata streams too.
    xmp = b""
    for m in re.finditer(rb"<x:xmpmeta.*?</x:xmpmeta>", data, re.S):
        xmp += m.group(0)
    for body in objs.values():
        if b"/Metadata" in body[:512] and b"/XML" in body[:512] and b"/FlateDecode" in body[:512]:
            ds = body.find(b"<<")
            de = dict_span(body, ds) if ds >= 0 else None
            raw = stream_body(body, de) if de else None
            if raw:
                xmp += inflate(raw, budget)
    # Dictionaries only: each object cut before its stream data, plus the trailers. Byte
    # patterns are matched here, never inside compressed or binary stream data.
    heads = {n: re.split(rb"\bstream\r?\n", b, 1)[0] for n, b in objs.items()}
    trailers = b"\n".join(data[m.end():m.end() + 4096] for m in re.finditer(rb"\btrailer\b", data))
    dicts = b"\n".join(heads.values()) + b"\n" + trailers
    encrypted = bool(re.search(rb"/Encrypt\s+\d+\s+\d+\s+R|/Encrypt\s*<<", dicts))
    cat_ver = re.search(rb"/Type\s*/Catalog[^>]*?/Version\s*/(\d\.\d)|/Version\s*/(\d\.\d)[^>]*?/Type\s*/Catalog", dicts)
    if cat_ver:
        v = (cat_ver.group(1) or cat_ver.group(2)).decode()
        if v > version:
            version = v
    info = b""
    for t in re.finditer(rb"/Info\s+(\d+)\s+\d+\s+R", dicts):
        info = heads.get(int(t.group(1)), info)

    def info_string(key):
        ref = re.search(rb"/" + key + rb"\s+(\d+)\s+\d+\s+R", info)
        if ref:
            return string_value(b"/" + key + b" " + heads.get(int(ref.group(1)), b"").strip(), key)
        return string_value(info, key)

    producer = info_string(b"Producer") if info else ""
    creator = info_string(b"Creator") if info else ""
    if encrypted:  # Info strings are ciphertext
        producer = creator = ""
    producer = producer or xmp_value(xmp, b"pdf:Producer")
    creator = creator or xmp_value(xmp, b"xmp:CreatorTool")

    page_objs = [n for n, b in heads.items() if re.search(rb"/Type\s*/Page(?![a-zA-Z])", b)]
    roots = [b for b in heads.values() if re.search(rb"/Type\s*/Pages\b", b) and b"/Parent" not in b]
    counts = [int(c.group(1)) for b in roots for c in [re.search(rb"/Count\s+(\d+)", b)] if c]
    pages = max(counts) if counts else len(page_objs)
    note = ""
    if counts and len(page_objs) != pages:
        note = f"page tree /Count {pages}, {len(page_objs)} /Type /Page objects"
    if not counts and not page_objs:
        pages, note = "", "no page tree readable (encrypted or damaged)"

    f = set()
    if re.search(rb"/AcroForm\b", dicts) and re.search(rb"/Fields\s*\[\s*\d", dicts):
        f.add("acroform")
    for body in heads.values():
        sigs = len(re.findall(rb"/ByteRange\s*\[", body))
        ur = len(re.findall(rb"/TransformMethod\s*/UR3?\b", body))
        if ur:
            f.add("usage-rights")
        if sigs > ur:  # a signature that is not only Reader usage rights
            f.add("signed")
        if sigs and re.search(rb"/TransformMethod\s*/DocMDP\b", body):
            f.add("certified")
    if encrypted:
        f.add("encrypted")
    if re.search(rb"/Type\s*/XRef\b", dicts):
        f.add("xref-stream")
    if re.search(rb"/Type\s*/ObjStm\b", dicts):
        f.add("objstm")
    linear = b"/Linearized" in data[:1024]
    if linear:
        f.add("linearized")
    eofs = len(re.findall(rb"%%EOF", data))
    if eofs > (2 if linear else 1):
        f.add("incremental")
    if re.search(rb"pdfaid:part", xmp):
        f.add("pdfa")
    if re.search(rb"/Rotate\s+(90|180|270|-90)\b", dicts):
        f.add("rotated-pages")
    boxes = lambda k: {tuple(round(float(x), 1) for x in m.group(1).split())
                       for m in re.finditer(rb"/" + k + rb"\s*\[\s*([-0-9.\s]+?)\s*\]", dicts)
                       if len(m.group(1).split()) == 4 and all(re.match(rb"^-?[0-9.]+$", x) for x in m.group(1).split())}
    crop, media = boxes(b"CropBox"), boxes(b"MediaBox")
    if crop - media:
        f.add("cropbox")
    if re.search(rb"/XFA\b", dicts):
        f.add("xfa")
    if re.search(rb"/JavaScript\b|/JS\s*[(<\d]", dicts):
        f.add("javascript")
    if re.search(rb"/EmbeddedFiles\b|/Type\s*/EmbeddedFile\b", dicts):
        f.add("embedded-files")
    if re.search(rb"/Marked\s+true", dicts):
        f.add("tagged")
    images = len(re.findall(rb"/Subtype\s*/Image\b", dicts))
    fonts = len([b for b in heads.values() if re.search(rb"/Type\s*/Font\b", b)])
    ocr_font = bool(re.search(rb"GlyphLessFont|/BaseFont\s*/(Invisible|OCR)", dicts))
    n_pages = pages if isinstance(pages, int) else 0
    hidden = encrypted and "objstm" in f  # fonts may sit in encrypted object streams
    if n_pages and images >= n_pages and (fonts == 0 and not hidden or ocr_font) or SCANNER_WORDS.search(producer + " " + creator):
        f.add("scanned")
    return {
        "version": version, "producer": producer, "creator": creator, "pages": pages,
        "pages_note": note, "features": sorted(f), "bytes": len(data),
    }


def main(argv):
    as_json = "--json" in argv
    paths = [a for a in argv[1:] if a != "--json"]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    status = 0
    for p in paths:
        try:
            with open(p, "rb") as fh:
                r = scan(fh.read(MAX_FILE + 1))
        except (OSError, ValueError) as e:
            print(f"{p}: {e}", file=sys.stderr)
            status = 1
            continue
        r["file"] = p
        r["family"] = family(r["producer"], r["creator"])
        if as_json:
            print(json.dumps(r))
        else:
            print("\t".join([p, r["family"], r["version"], str(r["pages"]), ",".join(r["features"]) or "-",
                             r["producer"], r["creator"], r["pages_note"]]))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
