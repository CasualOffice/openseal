#!/usr/bin/env python3
"""Export the pinned GLiNER checkpoints to ONNX and record golden spans (ML-07, ML-08; docs/33 §8, piece X).

    python3 -I tools/ml/export-gliner.py --self-test             # the refusals below; no network, standard library
    python3 -I tools/ml/export-gliner.py check                   # golden files' shape and offsets; no network
    python3 -I tools/ml/export-gliner.py fetch  --work DIR [MODEL ...]   # download pinned sources (network)
    VENV/bin/python -I tools/ml/export-gliner.py export --work DIR [MODEL ...]   # ONNX fp32, fp16, quint8 (offline)
    VENV/bin/python -I tools/ml/export-gliner.py golden --work DIR [MODEL ...]   # golden spans (offline)

MODEL is a slug from SOURCES (default: all). `fetch` needs only the standard library. `export` and `golden`
need the hash-pinned environment from tools/ml/requirements.txt:

    python3.12 -m venv VENV
    VENV/bin/pip install --require-hashes --no-deps -r tools/ml/requirements.txt

Every source file is pinned to a Hugging Face revision commit, a size and a SHA-256, and a download is kept
only when both match. The weights licence is read from the model card (README.md front matter) at that
revision, at fetch and again at export, and must be in deny.toml's allow list; the v0 and v1 GLiNER
checkpoints (CC-BY-NC-4.0) are refused by repo id whatever their card says. Pickle weights
(`pytorch_model.bin`) are opened only with `torch.load(weights_only=True)` and converted to safetensors
before GLiNER sees them. `export` and `golden` re-run themselves in a user and network namespace
(`unshare -rn`) so nothing they import can reach the network; they refuse to run without one unless
`--no-sandbox` is given.

`export` writes, per model, `<slug>.onnx` (fp32), `<slug>.fp16.onnx` (fp16 weights, fp32 inputs and outputs),
`<slug>.quint8.onnx` (ONNX Runtime dynamic quantization, QUInt8 weights, as `gliner`'s own export) and the
tokenizer files, refuses a graph with external data or an
operator domain outside the ONNX and ONNX Runtime built-ins, and writes `export-record.json` with the size
and SHA-256 of every file for the model manifest (tools/ml/models.toml, piece B).

`golden` runs the Python `gliner` package (pinned) on the 50 synthetic texts in fixtures/ml/gliner-golden/
texts.json: once with PyTorch on the source weights, once on each ONNX file with ONNX Runtime (one intra-op
thread, ORT_ENABLE_ALL). It records the spans, scores and the exact ONNX inputs, with offsets both in code
points and in UTF-8 bytes of the NFC text. Large files stay in DIR; only the golden JSON is committed.

Exits non-zero and names every problem.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DENY_TOML = ROOT / "deny.toml"
GOLDEN = ROOT / "fixtures" / "ml" / "gliner-golden"
TEXTS = GOLDEN / "texts.json"
HF = "https://huggingface.co"
UA = "OpenSeal-ml-export/1 (+https://github.com/CasualOffice/openseal; offline model export, ML-07)"
MAX_FILE = 2 * 1024 * 1024 * 1024  # ONNX protobuf limit; a source over it is refused before download
GLINER_VERSION = "0.2.29"
TEXT_COUNT = 50
SANDBOX_ENV = "OPENSEAL_ML_SANDBOXED"

# Hugging Face card licence ids -> SPDX. Only ids whose SPDX form is in deny.toml's allow list pass.
CARD_TO_SPDX = {
    "apache-2.0": "Apache-2.0", "mit": "MIT", "bsd-2-clause": "BSD-2-Clause", "bsd-3-clause": "BSD-3-Clause",
    "isc": "ISC", "unlicense": "Unlicense", "zlib": "Zlib", "ncsa": "NCSA",
}
# GLiNER v0 and v1 checkpoints are CC-BY-NC-4.0 (docs/33 §5.3); refused by id even if a card were edited.
REFUSED_REPOS = re.compile(
    r"^urchade/gliner_(base|multi|small|medium|large)(-v1(\.0)?)?$|^urchade/gliner_(small|medium|large|multi)-v1(\.0)?$"
)

# Backbones whose config and tokenizer the urchade checkpoints load by name (gliner_config.json model_name).
BACKBONES = {
    "mdeberta-v3-base": {
        "repo": "microsoft/mdeberta-v3-base", "revision": "a0484667b22365f84929a935b5e50a51f71f159d",
        "files": {
            "README.md": (3667, "90d5e535e04fc9ac4f39336ed33c1adc7d0136b8ce3bbe211c18a0d47b72342f"),
            "config.json": (579, "bcffcd343dc5efa5ef2d5a58d2b405eed108f01cc45b48d0a907b333ec41801f"),
            "tokenizer_config.json": (52, "3f3978e0c036f2c2588cac34a6047cbb0af0b0dc1814254e291028529805496d"),
            "spm.model": (4305025, "13c8d666d62a7bc4ac8f040aab68e942c861f93303156cc28f5c7e885d86d6e3"),
        },
    },
    "deberta-v3-small": {
        "repo": "microsoft/deberta-v3-small", "revision": "a36c739020e01763fe789b4b85e2df55d6180012",
        "files": {
            "README.md": (3585, "9aa2d47666370a87d20422ed68a1ee80d79d66b4447b6f9925d97d11f4605d24"),
            "config.json": (578, "b0bb1caf90a50aa67d1085130508dfbf8646ac5a11928305e280b07a36e100ae"),
            "tokenizer_config.json": (52, "3f3978e0c036f2c2588cac34a6047cbb0af0b0dc1814254e291028529805496d"),
            "spm.model": (2464616, "c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd"),
        },
    },
}

ML07_LABELS = ["party organization", "person", "effective date", "date", "monetary amount", "duration", "address"]
# Label names as the knowledgator card lists them (its 60+ categories); English only (critique-029 row 7).
ML08_LABELS = ["name", "email address", "phone number", "location address", "dob", "account number",
               "credit card", "ssn", "passport number", "ip address"]

SOURCES = {
    "gliner_multi-v2.1": {
        "repo": "urchade/gliner_multi-v2.1", "revision": "443d26d654e0324125a96bebd8e796c14ff2efe6",
        "rows": "ML-07", "profile": "extraction", "backbone": "mdeberta-v3-base", "labels": ML07_LABELS,
        "files": {
            "README.md": (4770, "820125f2ea897716cc38645d94f73f390ec9dfd392980c436be1d25c2e106b55"),
            "gliner_config.json": (477, "e25f61d91620df84aae8076811ee592e926e94d341b82e7bc1be359718f83017"),
            "model.safetensors": (1155830112, "2100142f31627531497850659dcb3821c99d5e71c08a8e01a98e4b11ef32a199"),
        },
    },
    "gliner_small-v2.1": {
        "repo": "urchade/gliner_small-v2.1", "revision": "4e091416cf7c3481db542c2a3d26156916f3a47f",
        "rows": "ML-07", "profile": "extraction", "backbone": "deberta-v3-small", "labels": ML07_LABELS,
        "files": {
            "README.md": (4756, "5f665c0a6a0e7431ecf0ff59555a418e27601c4c3e8bc1616087a25490294a30"),
            "gliner_config.json": (477, "eb963bd7182a1eaed4d170a87348ab62de6fc4eb30cfa7130c80846fee43d0ac"),
            "pytorch_model.bin": (610652234, "1d4e83e4e4ae4ae0a4fbc81a32ee6de480fb341650d73e808088bb2800312de4"),
        },
    },
    "gliner-pii-base-v1.0": {
        "repo": "knowledgator/gliner-pii-base-v1.0", "revision": "61726e0ad791dcab3e29339bbec3ad42ded65641",
        "rows": "ML-08", "profile": "personal_data", "backbone": None, "labels": ML08_LABELS,
        "files": {
            "README.md": (15896, "f715f1ad8ff24c0f6f1b2745684a587dfe7390f8a1f0621deec57243b34a8b5a"),
            "gliner_config.json": (3902, "e33d3da38e0d369fa7574668d3798ca6c7d2b23cba7d628507112eeb426aaccb"),
            "added_tokens.json": (65, "c358eb74586ab438484d8acf4534f67283b33041bc5ffee6b20a4a075cdc3cd6"),
            "special_tokens_map.json": (970, "b2f1b2f15f29a6b6d9d6ea4eca1675d2c231a71477f151d48f79cc83a625ba21"),
            "tokenizer.json": (8649232, "ee028763434d18611c1c36356ea1d050e90a9fa94ede57fac48b39f85f818ad1"),
            "tokenizer_config.json": (1691, "3ec8a90d8758fbc56d50831990c3a3a65660f020c5b06534adf43b04091ffa9e"),
            "spm.model": (2464616, "c679fbf93643d19aab7ee10c0b99e460bdbc02fedf34b92b05af343b4af586fd"),
            "pytorch_model.bin": (664140735, "da21d12e61e3da22cb93d2663b8593e752c440479a68a647b061447bcd8f9e42"),
        },
        # The repo also ships ONNX files made by knowledgator; recorded for comparison, not used.
        "upstream_onnx": {
            "onnx/model.onnx": (664764803, "c6ccec44625d46bfe3191152e41d6564b69bc9d4313b7f3e419e8372679e9fed"),
            "onnx/model_fp16.onnx": (332958160, "774b8c5d909266c9ebdc43afd819ef0354d636ed4f401a1eef1491b578e2e256"),
            "onnx/model_quint8.onnx": (196757174, "0514c8fd86d0513ce5351a3267f132b57d5bcd8f99a90d43cde1228092881d19"),
        },
    },
}
ALLOWED_DOMAINS = {"", "ai.onnx", "com.microsoft", "ai.onnx.ml"}


class Refused(Exception):
    """A pinned source, licence or output check failed; the message names the file and the reason."""


# --- pure checks (standard library; exercised by --self-test) ----------------------------------------------

def allowed_licences(deny_text):
    """The SPDX ids in deny.toml's [licenses] allow list."""
    section = re.search(r"\[licenses\][^\[]*?allow\s*=\s*\[(.*?)\]", deny_text, re.S)
    if not section:
        raise Refused("deny.toml: no [licenses] allow list")
    return set(re.findall(r'"([^"]+)"', section.group(1)))


def card_licence(readme_text):
    """The `license:` value of a model card's YAML front matter, lower-cased, or None."""
    m = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", readme_text, re.S)
    if not m:
        return None
    for line in m.group(1).splitlines():
        lm = re.match(r"^license:\s*['\"]?([A-Za-z0-9.+-]+)['\"]?\s*$", line)
        if lm:
            return lm.group(1).lower()
    return None


def check_licence(repo, readme_text, allowed):
    """Return the SPDX id of a card's licence, or raise Refused naming the repo and the licence."""
    if REFUSED_REPOS.match(repo):
        raise Refused(f"{repo}: GLiNER v0/v1 checkpoints are CC-BY-NC-4.0 and refused by id")
    card = card_licence(readme_text)
    if card is None:
        raise Refused(f"{repo}: model card has no license in its front matter")
    spdx = CARD_TO_SPDX.get(card)
    if spdx is None or spdx not in allowed:
        raise Refused(f"{repo}: weights licence {card!r} is not in deny.toml's allow list")
    return spdx


def check_bytes(name, data_len, digest, pin):
    """Raise Refused unless the size and SHA-256 match the pin."""
    size, sha = pin
    if data_len != size:
        raise Refused(f"{name}: {data_len} bytes, pinned {size}")
    if digest != sha:
        raise Refused(f"{name}: sha256 {digest}, pinned {sha}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_golden_record(text, span):
    """Problems with one golden span: offsets must index the NFC text in code points and in UTF-8 bytes."""
    problems = []
    s, e = span.get("start"), span.get("end")
    if not (isinstance(s, int) and isinstance(e, int) and 0 <= s < e <= len(text)):
        return [f"span offsets {s}..{e} outside the text"]
    if text[s:e] != span.get("text"):
        problems.append(f"span {s}..{e} does not match its text")
    bs, be = len(text[:s].encode("utf8")), len(text[:e].encode("utf8"))
    if (span.get("start_byte"), span.get("end_byte")) != (bs, be):
        problems.append(f"span {s}..{e}: byte offsets {span.get('start_byte')}..{span.get('end_byte')}, expected {bs}..{be}")
    if not isinstance(span.get("score"), float) or not 0.0 <= span["score"] <= 1.0:
        problems.append(f"span {s}..{e}: score not in [0, 1]")
    return problems


def check_golden(golden_dir):
    """Problems with the committed golden directory (texts.json and one JSON per model)."""
    problems = []
    texts_path = golden_dir / "texts.json"
    if not texts_path.is_file():
        return [f"{texts_path}: missing"]
    raw = texts_path.read_bytes()
    texts = json.loads(raw)["texts"]
    if len(texts) != TEXT_COUNT:
        problems.append(f"texts.json: {len(texts)} texts, expected {TEXT_COUNT}")
    by_id = {}
    for t in texts:
        if unicodedata.normalize("NFC", t["text"]) != t["text"]:
            problems.append(f"texts.json {t['id']}: not NFC")
        by_id[t["id"]] = t["text"]
    texts_sha = hashlib.sha256(raw).hexdigest()
    for slug in SOURCES:
        path = golden_dir / f"{slug}.json"
        if not path.is_file():
            problems.append(f"{path.name}: missing")
            continue
        doc = json.loads(path.read_text(encoding="utf8"))
        if doc.get("texts_sha256") != texts_sha:
            problems.append(f"{path.name}: made from another texts.json")
        if doc.get("gliner_version") != GLINER_VERSION:
            problems.append(f"{path.name}: gliner {doc.get('gliner_version')}, expected {GLINER_VERSION}")
        records = doc.get("records", [])
        if [r.get("id") for r in records] != list(by_id):
            problems.append(f"{path.name}: records do not cover texts.json in order")
        for r in records:
            text = by_id.get(r.get("id"), "")
            if set(r.get("spans", {})) != {"torch", *VARIANTS}:
                problems.append(f"{path.name} {r.get('id')}: variants {sorted(r.get('spans', {}))}")
            for variant, spans in r.get("spans", {}).items():
                for span in spans:
                    if span.get("label") not in doc.get("labels", []):
                        problems.append(f"{path.name} {r['id']} {variant}: label {span.get('label')!r} not asked for")
                    problems += [f"{path.name} {r['id']} {variant}: {p}" for p in check_golden_record(text, span)]
    return problems


def self_test():
    """Each refusal must fire; a refusal that does not is a failure."""
    failures = []
    allowed = allowed_licences(DENY_TOML.read_text(encoding="utf8"))

    def expect_refused(what, fn):
        try:
            fn()
        except Refused:
            return
        failures.append(f"not refused: {what}")

    card = "---\nlicense: {}\nlibrary_name: gliner\n---\n# card\n"
    expect_refused("a CC-BY-NC-4.0 card", lambda: check_licence("example/nc", card.format("cc-by-nc-4.0"), allowed))
    expect_refused("a GPL-3.0 card", lambda: check_licence("example/gpl", card.format("gpl-3.0"), allowed))
    expect_refused("a card with no licence", lambda: check_licence("example/none", "# card\n", allowed))
    expect_refused("GLiNER v1 by id", lambda: check_licence("urchade/gliner_multi-v1", card.format("apache-2.0"), allowed))
    expect_refused("GLiNER v0 by id", lambda: check_licence("urchade/gliner_base", card.format("apache-2.0"), allowed))
    expect_refused("a wrong SHA-256", lambda: check_bytes("f", 3, hashlib.sha256(b"abd").hexdigest(),
                                                         (3, hashlib.sha256(b"abc").hexdigest())))
    expect_refused("a wrong size", lambda: check_bytes("f", 4, hashlib.sha256(b"abc").hexdigest(),
                                                      (3, hashlib.sha256(b"abc").hexdigest())))
    try:
        if check_licence("urchade/gliner_multi-v2.1", card.format("apache-2.0"), allowed) != "Apache-2.0":
            failures.append("an Apache-2.0 card did not map to Apache-2.0")
        check_licence("urchade/gliner_multi_pii-v1", card.format("apache-2.0"), allowed)
    except Refused as e:
        failures.append(f"refused a permitted source: {e}")
    text = "Pay قدره 50 to Zoë."
    good = {"start": 15, "end": 18, "text": "Zoë", "start_byte": 19, "end_byte": 23, "score": 0.9}
    if check_golden_record(text, good):
        failures.append(f"a correct golden span was refused: {check_golden_record(text, good)}")
    if not check_golden_record(text, {**good, "start_byte": 15, "end_byte": 18}):
        failures.append("code-point offsets passed as byte offsets were not refused")
    for slug, src in SOURCES.items():
        if REFUSED_REPOS.match(src["repo"]):
            failures.append(f"{slug}: a pinned source is on the refused list")
        if not re.fullmatch(r"[0-9a-f]{40}", src["revision"]):
            failures.append(f"{slug}: revision is not a commit id")
    for f in failures:
        print(f"export-gliner self-test: {f}", file=sys.stderr)
    if not failures:
        print("export-gliner self-test: ok (licence, refused ids, hash, size and offset checks all refuse)")
    return 1 if failures else 0


# --- fetch (network, standard library) ---------------------------------------------------------------------

def download(url, dest, pin):
    """Stream url to dest, refusing anything over the pinned size; keep it only when size and hash match."""
    size, _ = pin
    if size > MAX_FILE:
        raise Refused(f"{dest.name}: pinned at {size} bytes, over the {MAX_FILE}-byte cap")
    if dest.is_file() and dest.stat().st_size == size and sha256_file(dest) == pin[1]:
        return
    part = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    h, n = hashlib.sha256(), 0
    with urllib.request.urlopen(req, timeout=120) as resp, open(part, "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            n += len(chunk)
            if n > size:
                part.unlink()
                raise Refused(f"{dest.name}: more than the pinned {size} bytes")
            h.update(chunk)
            out.write(chunk)
    try:
        check_bytes(dest.name, n, h.hexdigest(), pin)
    except Refused:
        part.unlink()
        raise
    part.replace(dest)


def api_licence(repo, revision):
    """The card licence the Hub reports for this revision (a second reading of the same card)."""
    req = urllib.request.Request(f"{HF}/api/models/{repo}/revision/{revision}", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        info = json.load(resp)
    if info.get("sha") != revision:
        raise Refused(f"{repo}: the Hub reports revision {info.get('sha')}, pinned {revision}")
    return ((info.get("cardData") or {}).get("license") or "").lower() or None


def fetch_repo(repo, revision, files, dest, allowed):
    dest.mkdir(parents=True, exist_ok=True)
    for name in sorted(files, key=lambda n: (n != "README.md", files[n][0])):  # card first: refuse before big files
        target = dest / name.replace("/", "__")
        download(f"{HF}/{repo}/resolve/{revision}/{name}", target, files[name])
        if name == "README.md":
            spdx = check_licence(repo, target.read_text(encoding="utf8"), allowed)
            api = api_licence(repo, revision)
            if CARD_TO_SPDX.get(api or "") != spdx:
                raise Refused(f"{repo}: the Hub reports licence {api!r}, the card at {revision[:12]} says {spdx}")
            print(f"  {repo}@{revision[:12]}: licence {spdx} (card and Hub agree)")
    return dest


def cmd_fetch(args, allowed):
    for slug in args.models:
        src = SOURCES[slug]
        print(f"fetch {slug}")
        fetch_repo(src["repo"], src["revision"], src["files"], args.work / "src" / slug, allowed)
        if src["backbone"]:
            bb = BACKBONES[src["backbone"]]
            fetch_repo(bb["repo"], bb["revision"], bb["files"], args.work / "src" / src["backbone"], allowed)
    return 0


# --- export and golden (third-party, offline, sandboxed) ----------------------------------------------------

def ensure_sandbox(args):
    """Re-run this command in a user and network namespace, so nothing imported can reach the network."""
    if os.environ.get(SANDBOX_ENV) == "1" or args.no_sandbox:
        os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1",
                          TOKENIZERS_PARALLELISM="false")
        if os.environ.get(SANDBOX_ENV) == "1":
            interfaces = sorted(name for _, name in socket.if_nameindex())
            if interfaces != ["lo"]:  # a fresh network namespace holds only loopback
                raise Refused(f"network interfaces {interfaces} present; refusing to load model code")
        return None
    unshare = shutil.which("unshare")
    if not unshare:
        raise Refused("unshare not found: cannot isolate the export from the network (use --no-sandbox to override)")
    env = {**os.environ, SANDBOX_ENV: "1"}
    return subprocess.call([unshare, "--user", "--map-root-user", "--net", "--", sys.executable, "-I", *sys.argv], env=env)


def verify_tree(src_dir, files, repo, allowed):
    """Re-check every fetched file against its pin, and the licence on the card, before loading anything."""
    for name, pin in files.items():
        path = src_dir / name.replace("/", "__")
        if not path.is_file():
            raise Refused(f"{repo}: {name} not fetched (run fetch first)")
        check_bytes(f"{repo}/{name}", path.stat().st_size, sha256_file(path), pin)
    return check_licence(repo, (src_dir / "README.md").read_text(encoding="utf8"), allowed)


def stage(args, slug, allowed):
    """Build a local model directory GLiNER can load offline: pinned files, safetensors weights, a local backbone."""
    import torch  # noqa: PLC0415 - third-party, export environment only
    from safetensors.torch import save_file  # noqa: PLC0415

    src = SOURCES[slug]
    src_dir = args.work / "src" / slug
    licence = verify_tree(src_dir, src["files"], src["repo"], allowed)
    staged = args.work / "stage" / slug
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True)
    for name in src["files"]:
        if name not in ("pytorch_model.bin", "README.md"):
            shutil.copyfile(src_dir / name, staged / name)
    if "pytorch_model.bin" in src["files"]:
        # weights_only=True refuses any pickle that is not plain tensors and containers (critique-029 row 9).
        state = torch.load(src_dir / "pytorch_model.bin", map_location="cpu", weights_only=True)
        if not isinstance(state, dict) or not all(torch.is_tensor(v) for v in state.values()):
            raise Refused(f"{src['repo']}: pytorch_model.bin is not a plain state dict")
        save_file({k: v.contiguous().clone() for k, v in state.items()}, staged / "model.safetensors")
        del state
    config = json.loads((staged / "gliner_config.json").read_text(encoding="utf8"))
    if src["backbone"]:
        bb = BACKBONES[src["backbone"]]
        bb_dir = args.work / "src" / src["backbone"]
        verify_tree(bb_dir, bb["files"], bb["repo"], allowed)
        if config.get("model_name") != bb["repo"]:
            raise Refused(f"{src['repo']}: model_name {config.get('model_name')!r}, pinned backbone {bb['repo']}")
        config["model_name"] = str(bb_dir)
        (staged / "gliner_config.json").write_text(json.dumps(config, indent=2), encoding="utf8")
    return staged, licence, config


def load_gliner(path, onnx_file=None):
    import onnxruntime as ort  # noqa: PLC0415
    import torch  # noqa: PLC0415
    from gliner import GLiNER  # noqa: PLC0415
    from gliner.runtime import onnx as gliner_onnx  # noqa: PLC0415

    torch.set_num_threads(1)
    if onnx_file is None:
        model = GLiNER.from_pretrained(str(path), local_files_only=True, map_location="cpu")
        model.eval()
        return model

    def load_session(self, model_path):
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        return ort.InferenceSession(str(model_path), sess_options=opts, providers=["CPUExecutionProvider"])

    gliner_onnx.ONNXRuntimeModel._load_session = load_session
    return GLiNER.from_pretrained(str(path), local_files_only=True, load_onnx_model=True, onnx_model_file=onnx_file)


def check_onnx(path):
    """Refuse external data and operator domains outside ONNX and ONNX Runtime built-ins (docs/33 §8, SEC-I04)."""
    import onnx  # noqa: PLC0415

    model = onnx.load(str(path), load_external_data=False)
    for init in model.graph.initializer:
        if init.data_location == onnx.TensorProto.EXTERNAL:
            raise Refused(f"{path.name}: initializer {init.name} uses external data")
    domains = {op.domain for op in model.opset_import} | {n.domain for n in model.graph.node}
    bad = domains - ALLOWED_DOMAINS
    if bad:
        raise Refused(f"{path.name}: operator domains {sorted(bad)} not allowed")
    return {
        "opset": {op.domain or "ai.onnx": op.version for op in model.opset_import},
        "inputs": [i.name for i in model.graph.input],
        "outputs": [o.name for o in model.graph.output],
        "domains": sorted(d or "ai.onnx" for d in domains),
        "contrib_ops": sorted({f"{n.domain}.{n.op_type}" for n in model.graph.node if n.domain}),
    }


def versions():
    import gliner  # noqa: PLC0415
    import onnx  # noqa: PLC0415
    import onnxruntime  # noqa: PLC0415
    import torch  # noqa: PLC0415
    import transformers  # noqa: PLC0415

    if gliner.__version__ != GLINER_VERSION:
        raise Refused(f"gliner {gliner.__version__} installed, {GLINER_VERSION} pinned")
    return {"gliner": gliner.__version__, "torch": torch.__version__, "transformers": transformers.__version__,
            "onnx": onnx.__version__, "onnxruntime": onnxruntime.__version__, "python": sys.version.split()[0]}


def cmd_export(args, allowed):
    vers = versions()
    for slug in args.models:
        src = SOURCES[slug]
        print(f"export {slug}", flush=True)
        staged, licence, config = stage(args, slug, allowed)
        model = load_gliner(staged)
        out = args.work / "out" / slug
        if out.exists():
            shutil.rmtree(out)
        model.export_to_onnx(out, onnx_filename=f"{slug}.onnx", quantized_filename=f"{slug}.quint8.onnx",
                             quantize=True, opset=19)
        del model
        if not (out / f"{slug}.quint8.onnx").is_file():
            raise Refused(f"{slug}: quantization produced no file")
        to_fp16(out / f"{slug}.onnx", out / f"{slug}.fp16.onnx")
        # Put the backbone's repo id back, so the exported config does not name a local path.
        cfg_path = out / "gliner_config.json"
        exported = json.loads(cfg_path.read_text(encoding="utf8"))
        if src["backbone"]:
            exported["model_name"] = BACKBONES[src["backbone"]]["repo"]
        cfg_path.write_text(json.dumps(exported, indent=2, sort_keys=True) + "\n", encoding="utf8")
        files = {}
        for path in sorted(out.iterdir()):
            entry = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
            if path.suffix == ".onnx":
                entry["graph"] = check_onnx(path)
            files[path.name] = entry
        record = {
            "id": slug, "rows": src["rows"], "profile": src["profile"], "source_repo": src["repo"],
            "source_revision": src["revision"], "licence": licence,
            "licence_url": f"{HF}/{src['repo']}/blob/{src['revision']}/README.md",
            "card_url": f"{HF}/{src['repo']}", "max_len": config.get("max_len"), "max_width": config.get("max_width"),
            "backbone": BACKBONES[src["backbone"]]["repo"] + "@" + BACKBONES[src["backbone"]]["revision"]
            if src["backbone"] else config.get("model_name"),
            "source_files": {n: {"bytes": p[0], "sha256": p[1]} for n, p in src["files"].items()},
            "upstream_onnx": {n: {"bytes": p[0], "sha256": p[1]} for n, p in src.get("upstream_onnx", {}).items()},
            "variants": {
                f"{slug}.onnx": "fp32, torch.onnx.export (TorchScript exporter) through gliner export_to_onnx",
                f"{slug}.fp16.onnx": "fp16 weights and compute, fp32 inputs and outputs: "
                                     "onnxruntime.transformers.float16.convert_float_to_float16(keep_io_types=True)",
                f"{slug}.quint8.onnx": "onnxruntime.quantization.quantize_dynamic(weight_type=QUInt8), "
                                       "as gliner export_to_onnx(quantize=True)",
            },
            "opset": 19, "tools": vers, "files": files,
        }
        (out / "export-record.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf8")
        for name, entry in files.items():
            print(f"  {name}  {entry['bytes']}  {entry['sha256']}")
    return 0


VARIANTS = {"onnx_fp32": ".onnx", "onnx_fp16": ".fp16.onnx", "onnx_quint8": ".quint8.onnx"}


def to_fp16(src, dest):
    """fp16 weights, fp32 inputs and outputs: half the size, and unlike dynamic int8 it keeps GLiNER's spans."""
    import onnx  # noqa: PLC0415
    from onnxruntime.transformers.float16 import convert_float_to_float16  # noqa: PLC0415

    onnx.save(convert_float_to_float16(onnx.load(str(src)), keep_io_types=True), str(dest))


def agreement(records, variant):
    """How far one variant's (start, end, label) spans are from the torch reference, over all texts."""
    equal = matched = missing = extra = 0
    for r in records:
        ref = {(s["start"], s["end"], s["label"]) for s in r["spans"]["torch"]}
        got = {(s["start"], s["end"], s["label"]) for s in r["spans"][variant]}
        equal += ref == got
        matched, missing, extra = matched + len(ref & got), missing + len(ref - got), extra + len(got - ref)
    return {"texts_equal": equal, "torch_spans": matched + missing, "matched": matched, "missing": missing,
            "extra": extra}


def nfc_byte(text, i):
    return len(text[:i].encode("utf8"))


def spans_of(model, text, labels):
    found = model.predict_entities(text, labels, threshold=0.5, flat_ner=True, multi_label=False)
    return [{"start": s["start"], "end": s["end"], "start_byte": nfc_byte(text, s["start"]),
             "end_byte": nfc_byte(text, s["end"]), "text": s["text"], "label": s["label"], "score": float(s["score"])}
            for s in sorted(found, key=lambda s: (s["start"], s["end"], s["label"]))]


def cmd_golden(args, allowed):
    import numpy as np  # noqa: PLC0415
    from gliner.runtime import onnx as gliner_onnx  # noqa: PLC0415

    vers = versions()
    raw = TEXTS.read_bytes()
    texts = json.loads(raw)["texts"]
    for slug in args.models:
        src = SOURCES[slug]
        print(f"golden {slug}", flush=True)
        out = args.work / "out" / slug
        record = json.loads((out / "export-record.json").read_text(encoding="utf8"))
        for name, entry in record["files"].items():
            check_bytes(f"{slug}/{name}", (out / name).stat().st_size, sha256_file(out / name),
                        (entry["bytes"], entry["sha256"]))
        staged, _, _ = stage(args, slug, allowed)
        labels = src["labels"]
        results = {t["id"]: {"id": t["id"], "spans": {}} for t in texts}

        torch_model = load_gliner(staged)
        splitter = torch_model.data_processor.words_splitter
        for t in texts:
            results[t["id"]]["words"] = [[w, s, e] for w, s, e in splitter(t["text"])]
            results[t["id"]]["spans"]["torch"] = spans_of(torch_model, t["text"], labels)
        del torch_model

        captured = []
        original_run = gliner_onnx.ONNXRuntimeModel.run_inference

        def capture(self, inputs):
            captured.append({k: np.asarray(v) for k, v in inputs.items()})
            return original_run(self, inputs)

        gliner_onnx.ONNXRuntimeModel.run_inference = capture
        for variant, suffix in VARIANTS.items():
            model = load_gliner(out, onnx_file=slug + suffix)
            for t in texts:
                captured.clear()
                results[t["id"]]["spans"][variant] = spans_of(model, t["text"], labels)
                if variant == "onnx_fp32":
                    if len(captured) != 1:
                        raise Refused(f"{slug} {t['id']}: {len(captured)} runtime calls, expected 1")
                    feeds = captured[0]
                    results[t["id"]]["onnx_inputs"] = {
                        "input_ids": feeds["input_ids"][0].tolist(),
                        "attention_mask_sum": int(feeds["attention_mask"][0].sum()),
                        "words_mask": feeds["words_mask"][0].tolist(),
                        "text_lengths": int(np.asarray(feeds["text_lengths"]).reshape(-1)[0]),
                        "span_idx_shape": list(feeds["span_idx"].shape),
                        "feeds": {k: {"shape": list(v.shape), "dtype": str(v.dtype)} for k, v in sorted(feeds.items())},
                    }
            del model
        gliner_onnx.ONNXRuntimeModel.run_inference = original_run

        agree = {v: agreement(results.values(), v) for v in VARIANTS}
        doc = {
            "about": "Golden GLiNER spans for piece K (docs/33 §5.3, §5.4). Offsets index the NFC text of "
                     "texts.json: start/end in code points, start_byte/end_byte in UTF-8 bytes. 'torch' is the "
                     "PyTorch reference on the source weights; each 'onnx_*' is the Python gliner pipeline on that "
                     "exported file with ONNX Runtime. K matches the variant the bundle ships (tools/ml/models.toml). "
                     "onnx_inputs are the exact feeds of the fp32 run (every variant takes the same feeds).",
            "model": slug, "source_repo": src["repo"], "source_revision": src["revision"], "rows": src["rows"],
            "gliner_version": vers["gliner"], "tools": vers,
            "texts_sha256": hashlib.sha256(raw).hexdigest(),
            "onnx": {n: e["sha256"] for n, e in record["files"].items() if n.endswith(".onnx")},
            "tokenizer_json_sha256": record["files"].get("tokenizer.json", {}).get("sha256"),
            "labels": labels, "threshold": 0.5, "flat_ner": True, "multi_label": False,
            "max_len": record["max_len"], "max_width": record["max_width"],
            "runtime": {"intra_op_num_threads": 1, "graph_optimization_level": "ORT_ENABLE_ALL",
                        "providers": ["CPUExecutionProvider"]},
            "agreement_with_torch": agree,
            "records": [results[t["id"]] for t in texts],
        }
        GOLDEN.mkdir(parents=True, exist_ok=True)
        (GOLDEN / f"{slug}.json").write_text(json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
                                             .replace(',"records":[', ',\n"records":[\n').replace('},{"id"', '},\n{"id"')
                                             + "\n", encoding="utf8")
        for v, a in agree.items():
            print(f"  {slug} {v}: {a['texts_equal']}/{len(texts)} texts equal to torch; spans matched "
                  f"{a['matched']}/{a['torch_spans']}, missing {a['missing']}, extra {a['extra']}")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--self-test", action="store_true", help="check that every refusal fires, then exit")
    p.add_argument("command", nargs="?", choices=["fetch", "export", "golden", "check"])
    p.add_argument("models", nargs="*", help=f"slugs (default all): {', '.join(SOURCES)}")
    p.add_argument("--work", type=pathlib.Path, help="directory for sources and exports (never the repository)")
    p.add_argument("--no-sandbox", action="store_true", help="run export or golden without a network namespace")
    args = p.parse_args()
    if args.self_test:
        return self_test()
    if args.command is None:
        p.error("a command or --self-test is required")
    if args.command == "check":
        problems = check_golden(GOLDEN)
        for prob in problems:
            print(f"export-gliner check: {prob}", file=sys.stderr)
        if not problems:
            print(f"export-gliner check: ok ({TEXT_COUNT} texts, {len(SOURCES)} models)")
        return 1 if problems else 0
    unknown = [m for m in args.models if m not in SOURCES]
    if unknown:
        p.error(f"unknown model(s): {', '.join(unknown)}")
    args.models = args.models or list(SOURCES)
    if args.work is None:
        p.error("--work DIR is required")
    args.work = args.work.resolve()
    if ROOT in [args.work, *args.work.parents]:
        p.error("--work must be outside the repository; large files stay out of it")
    try:
        allowed = allowed_licences(DENY_TOML.read_text(encoding="utf8"))
        if args.command == "fetch":
            return cmd_fetch(args, allowed)
        rc = ensure_sandbox(args)
        if rc is not None:
            return rc
        return (cmd_export if args.command == "export" else cmd_golden)(args, allowed)
    except Refused as e:
        print(f"export-gliner: refused: {e}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as e:
        print(f"export-gliner: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
