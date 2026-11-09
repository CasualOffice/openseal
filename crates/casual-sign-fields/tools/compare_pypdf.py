"""Compare our extracted strings with pypdf's (BSD-3), the independent check of T-1C.

    T1C_DUMP_DIR=target/t1c-pdfs cargo test -p casual-sign-fields
    cargo run --release -p casual-sign-fields --example extract_dir -- target/t1c-pdfs target/t1c-ours
    target/pyvenv/bin/python -I crates/casual-sign-fields/tools/compare_pypdf.py target/t1c-pdfs target/t1c-ours

Strings are compared after NFKC with all whitespace removed: the two extractors infer
spaces and line breaks differently, and positions are not compared. Prints one line per
file and a summary; exits non-zero when any file differs and --strict is given.
"""
import difflib
import pathlib
import sys
import unicodedata

from pypdf import PdfReader


def norm(s):
    return "".join(unicodedata.normalize("NFKC", s).split())


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strict = "--strict" in sys.argv
    pdfs, ours = pathlib.Path(args[0]), pathlib.Path(args[1])
    same = differ = skipped = 0
    ratios = []
    for pdf in sorted(pdfs.iterdir()):
        mine = ours / (pdf.name + ".txt")
        if not mine.exists():
            skipped += 1
            continue
        try:
            theirs = "".join(p.extract_text() or "" for p in PdfReader(str(pdf)).pages)
        except Exception as e:  # pypdf's own failure is not ours
            print(f"{pdf.name}\tpypdf failed: {type(e).__name__}")
            skipped += 1
            continue
        a, b = norm(mine.read_text(encoding="utf-8")), norm(theirs)
        if a == b:
            same += 1
            print(f"{pdf.name}\tsame\t{len(a)} chars")
        else:
            differ += 1
            r = difflib.SequenceMatcher(None, a[:20000], b[:20000], autojunk=False).ratio()
            ratios.append(r)
            print(f"{pdf.name}\tdiffer\tours {len(a)} pypdf {len(b)} similarity {r:.3f}")
    mean = sum(ratios) / len(ratios) if ratios else 1.0
    print(f"SUMMARY same {same} differ {differ} skipped {skipped} mean_similarity_of_differing {mean:.3f}")
    if strict and differ:
        sys.exit(1)


main()
