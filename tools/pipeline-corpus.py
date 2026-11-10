#!/usr/bin/env python3
"""The Phase 1 gate run over the corpus (`P1-GATE-01`, docs/06 Phase 1 exit item 2).

For every corpus PDF that admits: fill + flatten + certificate + seal (B-T) + verify,
judged by rungs 1 to 3 of the verification ladder (docs/31): ours, pyHanko and EU DSS,
with `sealed.starts_with(delivered)` checked after every step. Our side is the Rust
example `crates/casual-sign-sdk/examples/pipeline_corpus.rs` (through the SDK facade,
the code the `openseal` CLI runs); this script runs it, then pyHanko and EU DSS over each
sealed file with the checks of `tools/verify-sealed.py`, and writes one row per file to
`fixtures/corpus/pipeline/results.tsv` and the counts to `summary.tsv`.

    python3 -I tools/pipeline-corpus.py --work DIR --dss openseal-eu-dss \\
        [--corpus fixtures/corpus/files] [--python VENV_PYTHON] [--no-build] [--batch 40]
        [--print-to-new] [--level B-T|B-LT] [--present-only] [--results DIR]

Options off by default, so the gate's own run does not change: `--print-to-new` prints
signed input certified at DocMDP P1 to a new document (`NORM-02`) and judges it as
unsigned input (class `printed`) instead of excluding it; `--level B-LT` seals at B-LT,
so pyHanko and EU DSS also judge the DSS revision after the seal (`NORM-03`);
`--present-only` runs only the manifest's files present in `--corpus` (a subset), not
counting the others as missing.

`--work` holds the sealed files while they are judged (about 650 MB at most; each DSS
batch is deleted once judged). pyHanko runs in `--python` (a virtualenv with
`pyhanko==0.38.1` and `cryptography`, as tools/ci-local.sh makes), so this script needs
nothing beyond the standard library. EU DSS is the image built from tools/eu-dss.

How each row is judged:

* `form`, `plain` and `printed` (unsigned input, normalized; or signed input printed to
  new): ours with the test PKI's CRLs
  supplied must say TOTAL_PASSED for the seal with the whole file covered; offline
  (no revocation data) ours says INDETERMINATE/TRY_LATER, as DSS does offline. pyHanko:
  `pyhanko_sealed(.., "B-T")` (intact, valid, trusted, no change it calls OTHER, the
  last signature covering the whole file). DSS: `dss_judge(.., "B-T")` (intact, valid,
  PAdES-BASELINE-T detected, 0 undefined changes, never TOTAL_FAILED).
* `signed` (signed input kept as it is, docs/30 §2, sealed by appending a second
  signature): our signature is held to the above; each earlier signature only to what
  our revision did to it. pyHanko: ours (the last) intact, valid, trusted and covering
  the file; each earlier one exactly as intact as in the input, with no change after it
  that pyHanko calls OTHER that was not there before, and DocMDP not violated. DSS: one
  more signature than in the input, one of them intact, valid, PAdES-BASELINE-T with 0
  undefined changes, and no more undefined changes in total than in the input.

A row that fails carries its named cause. Causes excluded by a documented rule
(EXCLUDED below) count as excluded, not failed; the gate is met when every admitted
file passes or is excluded.
"""

import argparse
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "fixtures" / "corpus" / "pipeline"

# Owner-reviewable exclusion rules: a failure cause (prefix of the `failure` column) and
# why the file cannot pass this gate by design, with the row that removes the exclusion.
EXCLUDED = {
    "keep-signed CS-WRT-0004": (
        "DocMDP P1: the certification signature permits no change at all, another "
        "signature included (ISO 32000-2 §12.8.2.2.2); sealing such a file needs "
        "print-to-new (NORM-02)"
    ),
}

# Failures with a named cause outside this task's files: the proposed tracker row.
KNOWN = {
    "flatten CS-FLT-0001": "FLD-RADIO-NAME (proposed): radio state names that are not UTF-8 are converted lossily",
    "flatten CS-FLD-0002": "FLD-RADIO-NOOPT (proposed): a radio group with no on-state converts with no options",
}

PYHANKO_CHILD = r"""
import importlib.util, io, json, logging, sys
spec = importlib.util.spec_from_file_location("verify_sealed", sys.argv[1])
vs = importlib.util.module_from_spec(spec); spec.loader.exec_module(vs)
logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext
root = load_cert_from_pemder(sys.argv[2])

def each(data):
    out = []
    try:
        sigs = PdfFileReader(io.BytesIO(data), strict=False).embedded_signatures
    except Exception as e:
        return [{"error": type(e).__name__}]
    for sig in sigs:
        ctx = ValidationContext(trust_roots=[root], allow_fetching=False, revocation_mode="soft-fail")
        try:
            doc_ts = sig.sig_object_type == "/DocTimeStamp"
            st = validate_pdf_timestamp(sig, validation_context=ctx) if doc_ts else validate_pdf_signature(sig, ctx, ctx)
            out.append({"intact": bool(st.intact), "valid": bool(st.valid), "trusted": bool(st.trusted),
                        "coverage": st.coverage.name,
                        "mod": st.modification_level.name if st.modification_level else "-",
                        "docmdp_ok": None if doc_ts else st.docmdp_ok})
        except Exception as e:
            out.append({"error": type(e).__name__})
    return out

for line in sys.stdin:
    job = json.loads(line)
    data = open(job["sealed"], "rb").read()
    if job["class"] == "signed":
        res = {"before": each(open(job["input"], "rb").read()), "after": each(data)}
    else:
        try:
            problems, summary = vs.pyhanko_sealed(data, root, job["level"])
        except Exception as e:
            problems, summary = [f"pyHanko raised {type(e).__name__}"], "-"
        res = {"problems": problems, "summary": summary}
    print(json.dumps(res), flush=True)
"""


def load_verify_sealed():
    spec = importlib.util.spec_from_file_location("verify_sealed", ROOT / "tools" / "verify-sealed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_tsv(path):
    lines = [ln for ln in path.read_text(encoding="utf8").splitlines() if ln.strip()]
    head = lines[0].split("\t")
    return [dict(zip(head, ln.split("\t"))) for ln in lines[1:]]


def judge_pyhanko_signed(res):
    """Signed input: ours (last) intact, valid, trusted, whole file; earlier ones as before."""
    before, after = res["before"], res["after"]
    if len(after) != len(before) + 1:
        return [f"pyHanko sees {len(after)} signatures, the input had {len(before)}"]
    problems = []
    ours = after[-1]
    if "error" in ours or not (ours["intact"] and ours["valid"] and ours["trusted"]):
        problems.append(f"our signature: {ours}")
    elif ours["coverage"] != "ENTIRE_FILE":
        problems.append(f"our signature covers {ours['coverage']}")
    for i, (b, a) in enumerate(zip(before, after)):
        if "error" in a and "error" not in b:
            problems.append(f"signature {i}: pyHanko now raises {a['error']}")
            continue
        if "error" in a:
            continue
        if a["intact"] != b.get("intact"):
            problems.append(f"signature {i}: intact {b.get('intact')} -> {a['intact']}")
        if a["mod"] == "OTHER" and b.get("mod") != "OTHER":
            problems.append(f"signature {i}: our revision is a change pyHanko calls OTHER")
        if a["docmdp_ok"] is False and b.get("docmdp_ok") is not False:
            problems.append(f"signature {i}: DocMDP violated by our revision")
    return problems


def judge_dss_signed(before, after):
    problems = []
    if len(after) != len(before) + 1:
        return [f"EU DSS sees {len(after)} signatures, the input had {len(before)}"]

    def undefined(rows):
        return sum(int(r.get("undefined_changes")) for r in rows if (r.get("undefined_changes") or "-").isdigit())

    ours = [r for r in after if r.get("intact") == "true" and r.get("valid") == "true"
            and r.get("format") == "PAdES-BASELINE-T" and r.get("undefined_changes") == "0"
            and r.get("indication") != "TOTAL_FAILED"]
    if not ours:
        problems.append("EU DSS finds no intact, valid PAdES-BASELINE-T signature with 0 undefined changes")
    if undefined(after) > undefined(before):
        problems.append(f"EU DSS undefined changes {undefined(before)} -> {undefined(after)}")
    intact_before = sorted((r.get("intact"), r.get("valid")) for r in before)
    intact_after = sorted((r.get("intact"), r.get("valid")) for r in after)
    for pair in intact_before:
        if pair in intact_after:
            intact_after.remove(pair)
        else:
            problems.append(f"EU DSS: an earlier signature changed from intact/valid {pair}")
    return problems


def dss_text(rows):
    """Our signature's EU DSS verdict: the last PAdES-BASELINE-T row (the only row for
    unsigned input)."""
    ours = [r for r in rows if r.get("format") == "PAdES-BASELINE-T"] or rows
    if not ours:
        return "-"
    r = ours[-1]
    return f"{r.get('indication')}/{r.get('subindication')} {r.get('format')} undefined={r.get('undefined_changes')}"


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--work", required=True, type=pathlib.Path)
    p.add_argument("--corpus", type=pathlib.Path,
                   default=pathlib.Path(os.environ.get("OPENSEAL_CORPUS_DIR", ROOT / "fixtures/corpus/files")))
    p.add_argument("--dss", required=True, help="EU DSS image (docker build -t openseal-eu-dss tools/eu-dss)")
    p.add_argument("--python", default=str(ROOT / "target/tools-venv/bin/python"),
                   help="a Python with pyhanko==0.38.1 and cryptography")
    p.add_argument("--no-build", action="store_true", help="reuse the work dir's run of our side")
    p.add_argument("--batch", type=int, default=40)
    p.add_argument("--results", type=pathlib.Path, default=OUT_DIR)
    p.add_argument("--print-to-new", action="store_true",
                   help="print DocMDP P1 signed input to new (NORM-02) instead of excluding it")
    p.add_argument("--level", choices=["B-T", "B-LT"], default="B-T")
    p.add_argument("--present-only", action="store_true",
                   help="run only the manifest's files present in --corpus")
    args = p.parse_args(argv[1:])

    out = args.work / "out"
    if not args.no_build:
        if out.exists():
            shutil.rmtree(out)
        extra = ["--level", args.level] + (["--print-to-new"] if args.print_to_new else [])
        if args.present_only:
            listed = [r["file"] for r in read_tsv(ROOT / "fixtures/corpus/manifest.tsv")]
            extra += [n for n in listed if (args.corpus / n).is_file()]
        done = subprocess.run(
            ["cargo", "run", "--release", "-q", "-p", "casual-sign-sdk", "--example", "pipeline_corpus", "--",
             str(args.corpus), str(ROOT / "fixtures/corpus/manifest.tsv"), str(out)] + extra,
            cwd=ROOT, check=False, capture_output=True, text=True)
        print(done.stdout.strip().splitlines()[-1] if done.stdout.strip() else done.stderr[-500:])
        if done.returncode != 0:
            return 1
    ours = read_tsv(out / "ours.tsv")
    root_pem = out / "trust-root.pem"
    vs = load_verify_sealed()

    # pyHanko in its own interpreter (the virtualenv), one JSON line per file.
    child = subprocess.Popen([args.python, "-I", "-c", PYHANKO_CHILD, str(ROOT / "tools/verify-sealed.py"),
                              str(root_pem)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    sealed = [r for r in ours if (out / r["file"]).is_file()]
    results = {}
    for start in range(0, len(sealed), args.batch):
        batch = sealed[start:start + args.batch]
        with tempfile.TemporaryDirectory(dir=args.work) as tmp:
            work = pathlib.Path(tmp)
            shutil.copy(root_pem, work / "trust-root.pem")
            names = []
            for r in batch:
                shutil.move(str(out / r["file"]), work / r["file"])
                names.append(r["file"])
                if r["class"] == "signed":
                    shutil.copy(args.corpus / r["file"], work / ("input-" + r["file"]))
                    names.append("input-" + r["file"])
            dss = vs.dss_rows_by_file(args.dss, work, names)
            for r in batch:
                name = r["file"]
                job = {"sealed": str(work / name), "class": r["class"], "input": str(args.corpus / name),
                       "level": args.level}
                child.stdin.write(json.dumps(job) + "\n")
                child.stdin.flush()
                ph = json.loads(child.stdout.readline())
                if r["class"] == "signed":
                    ph_problems = judge_pyhanko_signed(ph)
                    ph_text = f"before={len(ph['before'])} after={len(ph['after'])} ours={ph['after'][-1] if ph['after'] else '-'}"
                    d_problems = judge_dss_signed(dss.get("input-" + name, []), dss.get(name, []))
                else:
                    ph_problems, ph_text = ph["problems"], ph["summary"]
                    d_problems = vs.dss_judge(dss.get(name, []), args.level)
                results[name] = (ph_problems, ph_text, d_problems, dss_text(dss.get(name, [])))
        print(f"judged {min(start + args.batch, len(sealed))}/{len(sealed)}", flush=True)
    child.stdin.close()
    child.wait()

    rows = ["file\tclass\tsteps\tours\tours_offline\tpyhanko\tdss\tprefix\tms\toutcome\tcause"]
    counts = {}
    for r in ours:
        name, cls = r["file"], r["class"]
        ours_ok = r["failure"] == "-" and r["prefix"] == "ok"
        ph_problems, ph_text, d_problems, d_text = results.get(name, (["not sealed"], "-", ["not sealed"], "-"))
        if cls == "refused":
            outcome, cause = "not-admitted", r["failure"]
        elif cls in ("missing", "PANIC"):
            outcome, cause = "fail", r["failure"]
        elif ours_ok and not ph_problems and not d_problems:
            outcome, cause = "pass", "-"
        else:
            failure = r["failure"]
            rule = next((v for k, v in EXCLUDED.items() if failure.startswith(k)), None)
            if rule:
                outcome, cause = "excluded", f"{failure}: {rule.split(':')[0]} (fixtures/corpus/pipeline/README.md, exclusion rules)"
            else:
                outcome = "fail"
                known = next((v for k, v in KNOWN.items() if failure.startswith(k)), None)
                parts = [failure if failure != "-" else None, known,
                         "pyHanko: " + "; ".join(ph_problems) if ph_problems and ours_ok else None,
                         "EU DSS: " + "; ".join(d_problems) if d_problems and ours_ok else None,
                         "prefix violated" if r["prefix"] == "VIOLATED" else None]
                cause = " | ".join(x for x in parts if x)
        ph_cell = "-" if name not in results else ("pass" if not ph_problems else "FAIL")
        d_cell = "-" if name not in results else ("pass " if not d_problems else "FAIL ") + d_text
        counts[(cls, outcome)] = counts.get((cls, outcome), 0) + 1
        rows.append("\t".join([name, cls, r["steps"], r["ours"], r["ours_offline"], ph_cell,
                               d_cell, r["prefix"], r["ms"], outcome, cause.replace("\t", " ")]))
    args.results.mkdir(parents=True, exist_ok=True)
    (args.results / "results.tsv").write_text("\n".join(rows) + "\n", encoding="utf8")
    summary = ["class\toutcome\tfiles"] + [f"{c}\t{o}\t{n}" for (c, o), n in sorted(counts.items())]
    admitted = sum(n for (c, _), n in counts.items() if c in ("form", "plain", "signed", "printed"))
    passed = sum(n for (c, o), n in counts.items() if o == "pass")
    excluded = sum(n for (c, o), n in counts.items() if o == "excluded")
    failed = sum(n for (c, o), n in counts.items() if o == "fail")
    summary.append(f"admitted\tall\t{admitted}")
    summary.append(f"gate\tmet={'yes' if failed == 0 else 'no'}\tpassed {passed}, excluded {excluded}, failed {failed}")
    (args.results / "summary.tsv").write_text("\n".join(summary) + "\n", encoding="utf8")
    print("\n".join(summary))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
