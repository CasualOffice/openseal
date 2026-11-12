#!/usr/bin/env python3
"""Golden vectors and the fp16 trial for multilingual-e5-small (ML-05; docs/33 §5.2, owner instruction 34).

    python3 -I tools/ml/export-e5.py check                              # golden file shape; no network, standard library
    VENV/bin/python -I tools/ml/export-e5.py export --src DIR --bundle DIR --work DIR   # fp16 ONNX from the pinned fp32 (offline)
    VENV/bin/python -I tools/ml/export-e5.py golden --src DIR --bundle DIR --work DIR   # reference and ONNX vectors (offline)

Inputs come from the hash-pinned manifest, never from here:

    python3 -I tools/ml/fetch-models.py --profile export-e5 --dest SRC      # safetensors and sentence-transformers configs
    python3 -I tools/ml/fetch-models.py --profile templates --dest BUNDLE   # the shipped fp32 ONNX and tokenizer.json

and `export`/`golden` re-hash every file they read against tools/ml/models.toml. They need the hash-pinned
environment from tools/ml/requirements.txt (`pip install --require-hashes --no-deps -r ...`), and re-run
themselves in a user and network namespace (`unshare -rn`) so nothing they import can reach the network
(`--no-sandbox` overrides).

**The reference** is the sentence-transformers pipeline the checkpoint declares (modules.json: Transformer,
Pooling, Normalize; 1_Pooling/config.json: mean of token embeddings under the attention mask;
sentence_bert_config.json: 512 tokens), computed in fp32 PyTorch from `model.safetensors` with `transformers`.
The script refuses to run if those configuration files say anything else. The `sentence-transformers`
package itself is not installed: it would add scipy and scikit-learn to the pinned environment to compute
the same three steps. Texts get e5's `query: ` or `passage: ` prefix, as modeld adds it.

**fp16 trial (owner instruction 34: fp16 only where it equals the reference).** `export` converts the pinned
fp32 ONNX with `onnxruntime.transformers.float16.convert_float_to_float16(keep_io_types=True)` (fp16
weights and compute, fp32 inputs and outputs; as tools/ml/export-gliner.py). `golden` runs the fp32 and fp16
ONNX files with ONNX Runtime (CPU, one intra-op thread, ORT_ENABLE_ALL, the settings modeld uses) and
records each one's lowest cosine against the reference. A variant passes when that is >= 1 - 1e-3.

`golden` writes fixtures/ml/e5-golden/e5-small.json: per text, the token ids the reference tokenizer gave
(modeld's tokenizer must give exactly these) and the reference vector (384 floats, 8 significant digits),
plus the trial's results and the hashes of every file used. Texts are synthetic, in
fixtures/ml/e5-golden/texts.json. Exits non-zero naming the problem.
"""
import argparse
import hashlib
import json
import math
import os
import pathlib
import shutil
import socket
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
GOLDEN = ROOT / "fixtures" / "ml" / "e5-golden"
TEXTS = GOLDEN / "texts.json"
OUT = GOLDEN / "e5-small.json"
SANDBOX_ENV = "OPENSEAL_E5_SANDBOXED"
DIM = 384
MAX_TOKENS = 512
TOLERANCE = 1e-3  # cosine distance; the ML-05 acceptance bound
PREFIX = {"query": "query: ", "passage": "passage: "}
# The manifest ids each input must match (tools/ml/models.toml).
SRC_IDS = {
    "e5-small-src": "model.safetensors", "e5-small-src-config": "config.json",
    "e5-small-src-tokenizer": "tokenizer.json", "e5-small-src-tokenizer-config": "tokenizer_config.json",
    "e5-small-src-special-tokens": "special_tokens_map.json", "e5-small-src-modules": "modules.json",
    "e5-small-src-st-config": "sentence_bert_config.json", "e5-small-src-pooling": "1_Pooling/config.json",
}
BUNDLE_IDS = {"e5-small": "templates/e5-small/model.onnx", "e5-small-tokenizer": "templates/e5-small/tokenizer.json"}
ALLOWED_DOMAINS = {"", "ai.onnx", "ai.onnx.ml", "com.microsoft"}


class Refused(Exception):
    """A pin, configuration or golden-file problem; the message names it."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def manifest_pins():
    """id -> (sha256, bytes) from tools/ml/models.toml, read with fetch-models.py's own strict reader."""
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("fetch_models", HERE / "fetch-models.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    entries = mod.load()
    return {e["id"]: (e["sha256"], e["bytes"]) for e in entries}


def verify_inputs(src, bundle):
    pins = manifest_pins()
    used = {}
    for ids, base in ((SRC_IDS, src / "e5-small"), (BUNDLE_IDS, bundle)):
        for eid, rel in ids.items():
            path = base / rel
            if not path.is_file():
                raise Refused(f"{eid}: {path} missing (fetch it with tools/ml/fetch-models.py)")
            sha, size = pins[eid]
            if path.stat().st_size != size or sha256_file(path) != sha:
                raise Refused(f"{eid}: {path} does not match tools/ml/models.toml")
            used[eid] = {"sha256": sha, "bytes": size}
    st = src / "e5-small"
    modules = [m["type"] for m in json.loads((st / "modules.json").read_text(encoding="utf8"))]
    if modules != ["sentence_transformers.models.Transformer", "sentence_transformers.models.Pooling",
                   "sentence_transformers.models.Normalize"]:
        raise Refused(f"modules.json declares {modules}; the reference implements Transformer, Pooling, Normalize")
    pooling = json.loads((st / "1_Pooling/config.json").read_text(encoding="utf8"))
    modes = sorted(k for k, v in pooling.items() if k.startswith("pooling_mode") and v)
    if modes != ["pooling_mode_mean_tokens"] or pooling.get("word_embedding_dimension") != DIM:
        raise Refused(f"1_Pooling/config.json: {pooling}")
    stc = json.loads((st / "sentence_bert_config.json").read_text(encoding="utf8"))
    if stc != {"max_seq_length": MAX_TOKENS, "do_lower_case": False}:
        raise Refused(f"sentence_bert_config.json: {stc}")
    return used


def ensure_sandbox(args):
    """Re-run in a user and network namespace (copied from tools/ml/export-gliner.py, ensure_sandbox)."""
    if os.environ.get(SANDBOX_ENV) == "1" or args.no_sandbox:
        os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1",
                          TOKENIZERS_PARALLELISM="false")
        if os.environ.get(SANDBOX_ENV) == "1":
            interfaces = sorted(name for _, name in socket.if_nameindex())
            if interfaces != ["lo"]:
                raise Refused(f"network interfaces {interfaces} present; refusing to load model code")
        return None
    unshare = shutil.which("unshare")
    if not unshare:
        raise Refused("unshare not found: cannot isolate from the network (use --no-sandbox to override)")
    env = {**os.environ, SANDBOX_ENV: "1"}
    return subprocess.call([unshare, "--user", "--map-root-user", "--net", "--", sys.executable, "-I", *sys.argv], env=env)


def check_onnx(path):
    """Refuse external data and operator domains outside ONNX and ONNX Runtime built-ins (as export-gliner.py)."""
    import onnx  # noqa: PLC0415

    model = onnx.load(str(path), load_external_data=False)
    for init in model.graph.initializer:
        if init.data_location == onnx.TensorProto.EXTERNAL:
            raise Refused(f"{path.name}: initializer {init.name} uses external data")
    domains = {op.domain for op in model.opset_import} | {n.domain for n in model.graph.node}
    bad = domains - ALLOWED_DOMAINS
    if bad:
        raise Refused(f"{path.name}: operator domains {sorted(bad)} not allowed")
    return {"inputs": [i.name for i in model.graph.input], "outputs": [o.name for o in model.graph.output]}


def versions():
    import onnx  # noqa: PLC0415
    import onnxruntime  # noqa: PLC0415
    import tokenizers  # noqa: PLC0415
    import torch  # noqa: PLC0415
    import transformers  # noqa: PLC0415

    return {"torch": torch.__version__, "transformers": transformers.__version__, "tokenizers": tokenizers.__version__,
            "onnx": onnx.__version__, "onnxruntime": onnxruntime.__version__, "python": sys.version.split()[0]}


def fp16_path(work):
    return work / "e5-small.fp16.onnx"


def cmd_export(args):
    verify_inputs(args.src, args.bundle)
    import onnx  # noqa: PLC0415
    from onnxruntime.transformers.float16 import convert_float_to_float16  # noqa: PLC0415

    args.work.mkdir(parents=True, exist_ok=True)
    out = fp16_path(args.work)
    src = args.bundle / BUNDLE_IDS["e5-small"]
    onnx.save(convert_float_to_float16(onnx.load(str(src)), keep_io_types=True), str(out))
    graph = check_onnx(out)
    print(f"{out.name}  {out.stat().st_size}  {sha256_file(out)}  {graph}")
    return 0


def load_texts():
    texts = json.loads(TEXTS.read_text(encoding="utf8"))
    for t in texts:
        if set(t) != {"id", "kind", "lang", "text"} or t["kind"] not in PREFIX:
            raise Refused(f"texts.json: bad entry {t.get('id')}")
    return texts


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb)


def cmd_golden(args):
    used = verify_inputs(args.src, args.bundle)
    import numpy as np  # noqa: PLC0415
    import onnxruntime as ort  # noqa: PLC0415
    import torch  # noqa: PLC0415
    from transformers import AutoModel, XLMRobertaTokenizerFast  # noqa: PLC0415

    torch.manual_seed(0)
    torch.set_num_threads(1)
    st = args.src / "e5-small"
    tok = XLMRobertaTokenizerFast(tokenizer_file=str(st / "tokenizer.json"), model_max_length=MAX_TOKENS)
    model = AutoModel.from_pretrained(str(st), dtype=torch.float32).eval()

    variants = {"onnx_fp32": args.bundle / BUNDLE_IDS["e5-small"]}
    fp16 = fp16_path(args.work)
    if fp16.is_file():
        variants["onnx_fp16"] = fp16
    sessions = {}
    for name, path in variants.items():
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1
        so.inter_op_num_threads = 1
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        sessions[name] = ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])

    records, lowest = [], {n: 1.0 for n in variants}
    for t in load_texts():
        enc = tok(PREFIX[t["kind"]] + t["text"], truncation=True, max_length=MAX_TOKENS, return_tensors="pt")
        with torch.no_grad():
            hidden = model(**enc).last_hidden_state
        mask = enc["attention_mask"].unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        ref = torch.nn.functional.normalize(pooled, p=2, dim=1)[0].tolist()
        ids = enc["input_ids"][0].tolist()
        feeds = {"input_ids": np.array([ids], dtype=np.int64),
                 "attention_mask": np.ones((1, len(ids)), dtype=np.int64),
                 "token_type_ids": np.zeros((1, len(ids)), dtype=np.int64)}
        cos = {}
        for name, sess in sessions.items():
            wanted = {i.name for i in sess.get_inputs()}
            h = sess.run(None, {k: v for k, v in feeds.items() if k in wanted})[0][0]
            v = h.mean(axis=0)
            v = v / np.linalg.norm(v)
            cos[name] = round(float(cosine(ref, v.tolist())), 7)
            lowest[name] = min(lowest[name], cos[name])
        records.append({"id": t["id"], "kind": t["kind"], "tokens": len(ids), "input_ids": ids,
                        "vector": [float(f"{x:.8g}") for x in ref], "onnx_cosine": cos})
    trial = {n: {"file": str(p.name), "sha256": sha256_file(p), "bytes": p.stat().st_size,
                 "lowest_cosine": round(lowest[n], 7), "passes": lowest[n] >= 1 - TOLERANCE}
             for n, p in variants.items()}
    doc = {
        "model": "intfloat/multilingual-e5-small@614241f622f53c4eeff9890bdc4f31cfecc418b3",
        "reference": "sentence-transformers pipeline (Transformer, mean Pooling, Normalize; 512 tokens) in fp32 "
                     "PyTorch from model.safetensors; texts prefixed 'query: ' or 'passage: '",
        "tolerance_cosine_distance": TOLERANCE, "dim": DIM, "max_tokens": MAX_TOKENS,
        "inputs": used, "tools": versions(), "onnx_trial": trial, "texts": records,
    }
    GOLDEN.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf8")
    for n, r in trial.items():
        print(f"{n}: lowest cosine {r['lowest_cosine']} -> {'passes' if r['passes'] else 'FAILS'} ({r['bytes']} B)")
    return 0


def cmd_check(_args):
    """The committed golden file's shape: every text present, ids in range, unit vectors of DIM floats."""
    texts = {t["id"]: t for t in load_texts()}
    doc = json.loads(OUT.read_text(encoding="utf8"))
    problems = []
    ids = [r["id"] for r in doc["texts"]]
    if ids != list(texts):
        problems.append("golden texts differ from texts.json")
    for r in doc["texts"]:
        v = r["vector"]
        if len(v) != DIM or abs(math.sqrt(sum(x * x for x in v)) - 1) > 1e-5:
            problems.append(f"{r['id']}: vector is not a unit vector of {DIM}")
        if not (2 <= len(r["input_ids"]) <= MAX_TOKENS) or r["input_ids"][0] != 0 or r["input_ids"][-1] != 2:
            problems.append(f"{r['id']}: input_ids not <s> ... </s> within {MAX_TOKENS}")
        if r["kind"] != texts.get(r["id"], {}).get("kind"):
            problems.append(f"{r['id']}: kind differs")
    if not doc["onnx_trial"]["onnx_fp32"]["passes"]:
        problems.append("the shipped fp32 ONNX does not equal the reference")
    for p in problems:
        print(f"export-e5: {p}", file=sys.stderr)
    return 1 if problems else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=("check", "export", "golden"))
    ap.add_argument("--src", type=pathlib.Path, help="directory of the fetched export-e5 profile")
    ap.add_argument("--bundle", type=pathlib.Path, help="directory of the fetched templates profile")
    ap.add_argument("--work", type=pathlib.Path, help="scratch directory for the fp16 file")
    ap.add_argument("--no-sandbox", action="store_true")
    args = ap.parse_args()
    try:
        if args.command == "check":
            return cmd_check(args)
        if not (args.src and args.bundle and args.work):
            raise Refused("export and golden need --src, --bundle and --work")
        rc = ensure_sandbox(args)
        if rc is not None:
            return rc
        return cmd_export(args) if args.command == "export" else cmd_golden(args)
    except Refused as e:
        print(f"export-e5: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
