#!/usr/bin/env python3
"""SPK-01: generate the hostile PDF set into fixtures/ (standard library only).

    python3 -I gen_fixtures.py [outdir]

Every file is synthetic; nothing is downloaded. Large outputs (over 1 MB) are
.gitignored; this script is the committed source of truth for all of them.
"""
import os
import pathlib
import sys
import zlib

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).parent / "fixtures")
HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"


def stream_obj(dict_body: bytes, data: bytes) -> bytes:
    return b"<<" + dict_body + b"/Length %d>>\nstream\n" % len(data) + data + b"\nendstream"


def classic(objs, trailer_extra=b"", header=HEADER):
    """objs: list of (num, body). Returns bytes with a classic xref table. Returns (bytes, offsets, xref_pos)."""
    out = bytearray(header)
    offs = {}
    for num, body in objs:
        offs[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    size = max(offs) + 1
    xref_pos = len(out)
    out += b"xref\n0 %d\n" % size
    out += b"0000000000 65535 f \n"
    for n in range(1, size):
        out += (b"%010d 00000 n \n" % offs[n]) if n in offs else b"0000000000 65535 f \n"
    out += b"trailer\n<</Size %d/Root 1 0 R%s>>\nstartxref\n%d\n%%%%EOF\n" % (size, trailer_extra, xref_pos)
    return bytes(out), offs, xref_pos


def pages_objs(n_pages=3):
    kids = b" ".join(b"%d 0 R" % (3 + 2 * i) for i in range(n_pages))
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[%s]/Count %d>>" % (kids, n_pages))]
    for i in range(n_pages):
        content = zlib.compress(b"BT /F1 12 Tf 72 720 Td (Page %d) Tj ET" % (i + 1))
        objs.append((3 + 2 * i, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents %d 0 R>>" % (4 + 2 * i)))
        objs.append((4 + 2 * i, stream_obj(b"/Filter/FlateDecode", content)))
    return objs


def xref_stream_file(objs, compressed=None, extra_dict=b"", size_override=None, index_override=None, header=HEADER):
    """objs: plain objects (num, body). compressed: {num: (objstm_num, idx)}. Writes an xref stream (W [1 4 2])."""
    compressed = compressed or {}
    out = bytearray(header)
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
    data = zlib.compress(bytes(rows))
    size_txt = size_override if size_override is not None else b"%d" % size
    index = index_override if index_override is not None else b"[0 %d]" % size
    d = b"/Type/XRef/Size %s/Index%s/W[1 4 2]/Root 1 0 R/Filter/FlateDecode%s" % (size_txt, index, extra_dict)
    out += b"%d 0 obj\n" % xref_num + stream_obj(d, data) + b"\nendobj\n"
    out += b"startxref\n%d\n%%%%EOF\n" % offs[xref_num]
    return bytes(out)


def zeros_deflate(prefix: bytes, n_zero: int) -> bytes:
    c = zlib.compressobj(9)
    parts = [c.compress(prefix)]
    chunk = b"\0" * (1 << 20)
    left = n_zero
    while left > 0:
        take = min(left, len(chunk))
        parts.append(c.compress(chunk[:take]))
        left -= take
    parts.append(c.flush())
    return b"".join(parts)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    w = lambda name, data: (OUT / name).write_bytes(data)  # noqa: E731

    valid, offs, xref_pos = classic(pages_objs(3))
    w("valid.pdf", valid)
    w("valid_xrefstream.pdf", xref_stream_file(pages_objs(3)))

    # 1. 10^5 nested arrays in the catalog.
    depth = 100_000
    deep = pages_objs(1)
    deep[0] = (1, b"<</Type/Catalog/Pages 2 0 R/Deep " + b"[" * depth + b"]" * depth + b">>")
    w("deep_nesting.pdf", classic(deep)[0])
    deep[0] = (1, b"<</Type/Catalog/Pages 2 0 R/Deep " + b"<</A " * depth + b"1" + b">>" * depth + b">>")
    w("deep_nesting_dict.pdf", classic(deep)[0])
    # Same depth inside a page content stream (what text extraction for anchors would parse).
    deep = pages_objs(1)
    deep[3] = (4, stream_obj(b"", b"[" * depth + b"]" * depth + b" TJ"))
    w("deep_nesting_content.pdf", classic(deep)[0])

    # 2. /Prev loop: the update's trailer points at the original xref, whose trailer points back at the update.
    base_objs = pages_objs(1)
    # Place-holder width so the forward /Prev can be patched without moving bytes.
    body, offs1, xpos1 = classic(base_objs, trailer_extra=b"/Prev 0000000000")
    upd_obj_pos = len(body)
    upd = bytearray(body)
    upd += b"1 0 obj\n<</Type/Catalog/Pages 2 0 R/Updated true>>\nendobj\n"
    upd_xref = len(upd)
    upd += b"xref\n0 1\n0000000000 65535 f \n1 1\n%010d 00000 n \n" % upd_obj_pos
    upd += b"trailer\n<</Size 5/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n" % (xpos1, upd_xref)
    loop = bytes(upd).replace(b"/Prev 0000000000", b"/Prev %010d" % upd_xref, 1)
    w("prev_loop.pdf", loop)
    # Self loop variant.
    w("prev_self_loop.pdf", body.replace(b"/Prev 0000000000", b"/Prev %010d" % xpos1, 1))

    # 3. /Size 2^31, in a classic trailer and in an xref stream (/Size and /Index).
    w("xref_size_2g_table.pdf", valid.replace(b"/Size 9/", b"/Size 2147483648/", 1))
    w("xref_size_2g_stream.pdf", xref_stream_file(pages_objs(1), size_override=b"2147483648",
                                                  index_override=b"[0 2147483648]"))

    # 4. Flate bomb: 1 GiB of zeros. (a) in a page content stream; (b) in an object stream that
    #    holds the page object, so it must be inflated just to read the page tree.
    gib = 1 << 30
    bomb = zeros_deflate(b"", gib)
    objs = pages_objs(1)
    objs[3] = (4, stream_obj(b"/Filter/FlateDecode", bomb))
    w("flate_bomb_content.pdf", classic(objs)[0])
    page = b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"
    hdr = b"3 0 "
    objstm = zeros_deflate(hdr + page, gib)  # NUL is PDF white space, so the tail is legal padding
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            (5, stream_obj(b"/Type/ObjStm/N 1/First %d/Filter/FlateDecode" % len(hdr), objstm))]
    w("flate_bomb_objstm.pdf", xref_stream_file(objs, compressed={3: (5, 0)}))
    # (c) Eight object streams, each inflating to 250 MiB: every one is under a 256 MiB
    #     per-stream cap, 2 GiB in total (docs/21 sets a 1 GiB per-document budget).
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"), (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")]
    compressed = {}
    for k in range(8):
        hdr = b"%d 0 " % (10 + k)
        data = zeros_deflate(hdr + b"null", 250 << 20)
        objs.append((20 + k, stream_obj(b"/Type/ObjStm/N 1/First %d/Filter/FlateDecode" % len(hdr), data)))
        compressed[10 + k] = (20 + k, 0)
    w("flate_bomb_many.pdf", xref_stream_file(objs, compressed=compressed))

    # 5. Object stream that references itself: obj 5 (the ObjStm) is listed as compressed inside obj 5,
    #    and its /Extends points at itself. The page tree root (2) lives in it.
    inner = b"<</Type/Pages/Kids[3 0 R]/Count 1>>"
    hdr = b"2 0 5 %d " % len(inner)
    payload = zlib.compress(hdr + inner + b"<</Type/ObjStm>>")
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"),
            (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>"),
            (5, stream_obj(b"/Type/ObjStm/N 2/First %d/Extends 5 0 R/Filter/FlateDecode" % len(hdr), payload))]
    w("objstm_self.pdf", xref_stream_file(objs, compressed={2: (5, 0), 5: (5, 1)}))

    # 6. Page tree cycle: Pages 2 -> Pages 3 -> Pages 2.
    objs = [(1, b"<</Type/Catalog/Pages 2 0 R>>"),
            (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
            (3, b"<</Type/Pages/Parent 2 0 R/Kids[2 0 R 4 0 R]/Count 1>>"),
            (4, b"<</Type/Page/Parent 3 0 R/MediaBox[0 0 612 792]>>")]
    w("page_tree_cycle.pdf", classic(objs)[0])

    # 7. Truncated: the 3-page file cut at 60 % (no xref, no trailer).
    w("truncated.pdf", valid[: len(valid) * 6 // 10])

    # 8. Broken xref offsets: every in-use offset shifted by +5. Also used for the recovery test.
    head, _, tail = valid.partition(b"xref\n")
    lines = tail.split(b"\n")
    fixed = []
    for ln in lines:
        if len(ln) == 19 and ln.endswith(b" n "):
            ln = b"%010d" % (int(ln[:10]) + 5) + ln[10:]
        fixed.append(ln)
    w("broken_xref_offsets.pdf", head + b"xref\n" + b"\n".join(fixed))
    # Variant: startxref points into the middle of an object.
    w("broken_startxref.pdf", valid.replace(b"startxref\n%d" % xref_pos, b"startxref\n%d" % (xref_pos - 40), 1))

    # 9. 10^6 tiny objects, all reachable from one array so lazy readers must touch them too.
    n = 1_000_000
    out = bytearray(HEADER)
    offs = {}
    for i in range(10, 10 + n):
        offs[i] = len(out)
        out += b"%d 0 obj %d endobj\n" % (i, i)
    arr_num = 10 + n
    offs[arr_num] = len(out)
    out += b"%d 0 obj [" % arr_num + b" ".join(b"%d 0 R" % i for i in range(10, 10 + n)) + b"] endobj\n"
    for num, body in [(1, b"<</Type/Catalog/Pages 2 0 R/Many %d 0 R>>" % arr_num),
                      (2, b"<</Type/Pages/Kids[3 0 R]/Count 1>>"),
                      (3, b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>")]:
        offs[num] = len(out)
        out += b"%d 0 obj\n" % num + body + b"\nendobj\n"
    size = arr_num + 1
    xp = len(out)
    out += b"xref\n0 %d\n" % size
    out += b"".join((b"%010d 00000 n \n" % offs[i]) if i in offs else b"0000000000 65535 f \n" for i in range(size))
    out += b"trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (size, xp)
    w("many_objects.pdf", bytes(out))

    for p in sorted(OUT.glob("*.pdf")):
        print(f"{p.name:28} {os.path.getsize(p):>12,}")


if __name__ == "__main__":
    main()
