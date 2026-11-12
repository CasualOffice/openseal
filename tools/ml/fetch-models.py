#!/usr/bin/env python3
"""Fetch the pinned model bundle for casual-sign-modeld (ML-01, ADR-029, docs/33 §8-9).

`tools/ml/models.toml` lists every file a profile needs: its revision-pinned source URL,
SHA-256, size and licence. This script downloads only the profiles asked for into an
empty directory, checks each file's size and SHA-256 while streaming it, refuses any
licence outside the allow list, and writes `bundle.json`. It is the only network use in
the ML path, at image build (deploy/Dockerfile `models` stage) or on an operator's
connected machine for an air-gapped install; modeld itself never fetches.

    python3 -I tools/ml/fetch-models.py --list
    python3 -I tools/ml/fetch-models.py --profile ocr --profile templates --dest DIR [--arch x86_64] [--cache DIR]
    python3 -I tools/ml/fetch-models.py --verify DIR          # re-hash a bundle against the manifest
    python3 -I tools/ml/fetch-models.py --self-test           # proves it refuses what it must

Rules (each one is exercised by --self-test):
- A licence is allowed only if it is on ALLOWED_LICENCES, the same set as deny.toml's
  `[licenses] allow` (ADR-029 review defect 18: that includes NCSA). An SPDX `A OR B` is
  allowed if any alternative is; `A AND B` only if both are. Anything else (CC-BY-NC-4.0,
  GPL, a custom model licence) refuses the whole manifest: a new licence needs an ADR.
  The one exception is LICENCE_EXCEPTIONS: an owner decision naming entry ids, which an
  entry opts into with `licence_exception`; any other entry naming it is refused, and a
  bundle holding it must also hold the notice file it names (owner instruction 32: the
  ONNX Runtime library's Eigen MPL-2.0 and Boost BSL-1.0, with ThirdPartyNotices.txt).
- A file is accepted only if its byte count and SHA-256 equal the manifest's. A mismatch
  stops the run, names the entry, and leaves nothing behind in the destination.
- Source URLs are https and pinned: a Hugging Face URL names a 40-hex commit
  (`/resolve/<commit>/`), a GitHub URL a release tag. Redirects must stay on https.
- Bundled files (profiles other than `export-*`) are never pickle (`.bin`, `.pt`, `.pth`,
  `.pkl`, `.ckpt`), each is at most MAX_FILE_BYTES and the bundle at most
  MAX_BUNDLE_BYTES (docs/33 §4; CS-ML-0002 in modeld). `export-*` profiles are inputs for
  the offline exports in tools/ml/export-*.py and are never put in an image.
- An entry whose `sha256` is empty is pending: it is produced by an offline export
  (`produced_by`) that has not been pinned yet. A profile with a pending entry is refused.
- The `runtime` profile (the ONNX Runtime shared library) is added to every bundle that
  holds a model profile. Its archive is checked, then one named member is extracted
  (`extract`, checked against `extract_sha256`); no other archive path is ever written.

Bundle id (what modeld's INFO op reports, docs/33 §3): the lowercase hex SHA-256 of the
lines `"<sha256> <bytes> <dest>\\n"`, one per file in the bundle, sorted by `dest`, where
for an extracted runtime the line is the extracted file's. modeld recomputes it from the
files it verifies, so the id names exactly the bytes being served.

The manifest is parsed by a strict reader for the subset of TOML it uses (tables,
arrays of tables, strings, integers, comments), so it runs on Python 3.10 without
`tomllib`; anything outside the subset is an error, and --self-test checks the reader
agrees with `tomllib` where that exists. Standard library only. Exits non-zero naming
the problem.
"""

import argparse
import contextlib
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
MANIFEST = HERE / "models.toml"
DENY_TOML = HERE.parent.parent / "deny.toml"

# deny.toml `[licenses] allow`, verbatim (--self-test checks they are equal). Weights and
# the ONNX Runtime binary sit outside cargo-deny, so this list is their licence gate
# (docs/33 §9, owner decision D12: inside this script, no new CI gate).
ALLOWED_LICENCES = frozenset({
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "NCSA",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
})

# Scoped licence exceptions, each an owner decision, honoured only for the entry ids it
# names (an entry elsewhere naming one is refused). owner-instruction-32 (docs/03 row 32,
# ADR-029, docs/09 §8): the unmodified ONNX Runtime library contains Eigen (MPL-2.0) and
# Boost (BSL-1.0); those two are allowed inside that binary only, and only in a bundle
# that also ships its ThirdPartyNotices.txt from the same archive.
LICENCE_EXCEPTIONS = {
    "owner-instruction-32": {
        "ids": frozenset({"onnxruntime-x86_64", "onnxruntime-aarch64"}),
        "role": "runtime",
        "licences": frozenset({"MPL-2.0", "BSL-1.0"}),
        "notice": "runtime/ThirdPartyNotices.txt",
    },
}

MAX_FILE_BYTES = 1 << 30            # 1 GiB per bundled file (docs/33 §4)
MAX_BUNDLE_BYTES = 2 << 30          # 2 GiB per bundle (docs/33 §4)
MAX_EXPORT_FILE_BYTES = 2 << 30     # an export input (e.g. a 1.16 GB safetensors)
MAX_MANIFEST_BYTES = 1 << 20
CHUNK = 1 << 20
TIMEOUT_S = 60

PROFILES = {
    "runtime": "ONNX Runtime shared library; added to every bundle with a model profile",
    "ocr": "ML-02: PP-OCRv6 small detection and recognition (50 languages)",
    "ocr-arabic": "ML-02: PP-OCRv5 Arabic recognition pack (pending export)",
    "ocr-devanagari": "ML-02: PP-OCRv5 Devanagari recognition pack (pending export)",
    "ocr-orientation": "ML-02: PP-LCNet text-line orientation (pending export)",
    "templates": "ML-05: multilingual-e5-small page embeddings (fp32, CPU-portable)",
    "templates-small": "ML-05: all-MiniLM-L6-v2 page embeddings, English (fp32)",
    "extraction": "ML-07: GLiNER multi-v2.1 entities (pending export)",
    "extraction-en": "ML-07: GLiNER small-v2.1 entities, English (pending export)",
    "personal_data": "ML-08 layer 2: knowledgator GLiNER-PII base, English (official uint8)",
    "export-gliner-multi": "export input: gliner_multi-v2.1 safetensors and mDeBERTa tokenizer",
    "export-gliner-small": "export input: gliner_small-v2.1 (pickle; weights_only, no network)",
    "export-paddle": "export input: Paddle-format OCR packs for paddle2onnx",
}
ARCHES = ("x86_64", "aarch64")
ARCH_ALIASES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".pkl", ".ckpt")
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DEST_PART_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SPDX_ID_RE = re.compile(r"^[A-Za-z0-9.+-]{1,64}$")
HF_RE = re.compile(r"^https://huggingface\.co/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/resolve/[0-9a-f]{40}/[A-Za-z0-9._/-]+$")
GH_RE = re.compile(r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/releases/download/v?[0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$")

REQUIRED = ("id", "profile", "arch", "role", "dest", "source_url", "sha256", "bytes",
            "licence", "licence_url", "card_url", "provenance")
OPTIONAL = ("produced_by", "extract", "extract_sha256", "extract_bytes", "licence_exception")
ROLES = ("runtime", "notice", "model", "tokenizer", "config", "export-input")
EXTRACT_ROLES = ("runtime", "notice")


class Refused(Exception):
    """A manifest, licence, size or hash problem; the message names the entry."""


# ---- strict TOML subset ------------------------------------------------------------

def _parse_string(s, where):
    if not s.startswith('"'):
        raise Refused(f"{where}: expected a quoted string")
    out, i = [], 1
    while i < len(s):
        c = s[i]
        if c == '"':
            return "".join(out), s[i + 1:]
        if c == "\\":
            nxt = s[i + 1:i + 2]
            if nxt not in ('"', "\\"):
                raise Refused(f"{where}: unsupported escape")
            out.append(nxt)
            i += 2
            continue
        if ord(c) < 0x20:
            raise Refused(f"{where}: control character in a string")
        out.append(c)
        i += 1
    raise Refused(f"{where}: unterminated string")


def parse_manifest(text):
    """Parse the subset of TOML models.toml uses: `[table]`, `[[array]]`, `key = "str"`,
    `key = 123`, comments. Returns a dict like tomllib.loads would."""
    doc = {}
    current = doc
    for n, raw in enumerate(text.splitlines(), 1):
        where = f"models.toml:{n}"
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[\[([a-z_]+)\]\]\s*(#.*)?$", line)
        if m:
            arr = doc.setdefault(m.group(1), [])
            if not isinstance(arr, list):
                raise Refused(f"{where}: {m.group(1)} is not an array of tables")
            current = {}
            arr.append(current)
            continue
        m = re.match(r"^\[([a-z_]+)\]\s*(#.*)?$", line)
        if m:
            if m.group(1) in doc:
                raise Refused(f"{where}: table {m.group(1)} defined twice")
            current = doc[m.group(1)] = {}
            continue
        m = re.match(r"^([a-z_][a-z0-9_]*)\s*=\s*(.*)$", line)
        if not m:
            raise Refused(f"{where}: not in the manifest's TOML subset")
        key, rest = m.group(1), m.group(2)
        if key in current:
            raise Refused(f"{where}: key {key} repeated")
        if rest.startswith('"'):
            value, tail = _parse_string(rest, where)
        else:
            mi = re.match(r"^([0-9][0-9_]*)(.*)$", rest)
            if not mi or "__" in mi.group(1) or mi.group(1).endswith("_") or (
                    len(mi.group(1)) > 1 and mi.group(1).startswith("0")):
                raise Refused(f"{where}: value is neither a string nor an integer")
            value, tail = int(mi.group(1).replace("_", "")), mi.group(2)
        tail = tail.strip()
        if tail and not tail.startswith("#"):
            raise Refused(f"{where}: trailing text after the value")
        current[key] = value
    return doc


# ---- validation ----------------------------------------------------------------------

def licence_allowed(expr, allowed=ALLOWED_LICENCES):
    """SPDX: one id, or ids joined by a single kind of operator (all OR, or all AND)."""
    parts = expr.split()
    if not parts or any(p in ("(", ")", "WITH") or "(" in p or ")" in p for p in parts):
        return False
    ids, ops = parts[0::2], set(parts[1::2])
    if len(parts) % 2 == 0 or not ops <= {"OR", "AND"} or len(ops) > 1:
        return False
    if not all(SPDX_ID_RE.match(i) for i in ids):
        return False
    if ops == {"OR"}:
        return any(i in allowed for i in ids)
    return all(i in allowed for i in ids)


def entry_allowed_licences(e, eid):
    """The allow list for one entry: ALLOWED_LICENCES, widened only for an entry that a
    LICENCE_EXCEPTIONS item names by id and role."""
    name = e.get("licence_exception")
    if name is None:
        return ALLOWED_LICENCES
    exc = LICENCE_EXCEPTIONS.get(name)
    if exc is None:
        raise Refused(f"{eid}: unknown licence_exception {name}")
    if eid not in exc["ids"] or e.get("role") != exc["role"]:
        raise Refused(f"{eid}: licence_exception {name} does not cover this entry")
    return ALLOWED_LICENCES | exc["licences"]


def check_dest(dest, eid):
    parts = dest.split("/")
    if dest.startswith("/") or not all(DEST_PART_RE.match(p) and p not in (".", "..") for p in parts):
        raise Refused(f"{eid}: dest {dest!r} is not a plain relative path")


def validate(doc):
    """Every entry, every rule; a single bad entry refuses the manifest."""
    if doc.get("schema") != 1:
        raise Refused("models.toml: schema must be 1")
    entries = doc.get("file")
    if not isinstance(entries, list) or not entries:
        raise Refused("models.toml: no [[file]] entries")
    ids, dests = set(), set()
    for e in entries:
        eid = e.get("id", "?")
        for k in REQUIRED:
            if k not in e:
                raise Refused(f"{eid}: missing {k}")
        for k in e:
            if k not in REQUIRED and k not in OPTIONAL:
                raise Refused(f"{eid}: unknown key {k}")
        if not isinstance(eid, str) or not ID_RE.match(eid):
            raise Refused(f"{eid!r}: id must match [A-Za-z0-9._-]{{1,64}}")
        if eid in ids:
            raise Refused(f"{eid}: id repeated")
        ids.add(eid)
        if not licence_allowed(e["licence"], entry_allowed_licences(e, eid)):
            raise Refused(f"{eid}: licence {e['licence']} is not on the allow list "
                          f"({', '.join(sorted(ALLOWED_LICENCES))}); a new licence needs an ADR")
        if e["profile"] not in PROFILES:
            raise Refused(f"{eid}: unknown profile {e['profile']}")
        if e["arch"] not in ARCHES + ("any",):
            raise Refused(f"{eid}: unknown arch {e['arch']}")
        if e["role"] not in ROLES:
            raise Refused(f"{eid}: unknown role {e['role']}")
        export = e["profile"].startswith("export-")
        if export != (e["role"] == "export-input"):
            raise Refused(f"{eid}: role export-input belongs to export-* profiles only")
        check_dest(e["dest"], eid)
        key = (e["dest"], e["arch"])
        if key in dests:
            raise Refused(f"{eid}: dest {e['dest']} repeated")
        dests.add(key)
        if not isinstance(e["bytes"], int) or e["bytes"] < 0:
            raise Refused(f"{eid}: bytes must be a non-negative integer")
        pending = e["sha256"] == ""
        if pending:
            if "produced_by" not in e or e["source_url"] != "":
                raise Refused(f"{eid}: a pending entry names produced_by and no source_url")
        else:
            if not SHA_RE.match(e["sha256"]):
                raise Refused(f"{eid}: sha256 must be 64 lowercase hex characters")
            if not (HF_RE.match(e["source_url"]) or GH_RE.match(e["source_url"])):
                raise Refused(f"{eid}: source_url is not an https URL pinned to a commit or release")
            if e["bytes"] <= 0:
                raise Refused(f"{eid}: bytes must be positive")
        cap = MAX_EXPORT_FILE_BYTES if export else MAX_FILE_BYTES
        if e["bytes"] > cap:
            raise Refused(f"{eid}: {e['bytes']} bytes is over the {cap}-byte file cap")
        if not export and e["dest"].lower().endswith(PICKLE_SUFFIXES):
            raise Refused(f"{eid}: pickle file in a bundled profile; modeld never loads pickle")
        has_extract = "extract" in e
        if has_extract != (e["role"] in EXTRACT_ROLES):
            raise Refused(f"{eid}: runtime and notice entries, and only they, name an extract member")
        if has_extract:
            if not SHA_RE.match(e.get("extract_sha256", "")) or not isinstance(e.get("extract_bytes"), int):
                raise Refused(f"{eid}: extract needs extract_sha256 and extract_bytes")
            if e["extract_bytes"] > MAX_FILE_BYTES:
                raise Refused(f"{eid}: extracted member over the file cap")
        for k in ("licence_url", "card_url"):
            if not e[k].startswith("https://"):
                raise Refused(f"{eid}: {k} must be https")
    return entries


def select(entries, profiles, arch):
    """The entries a bundle of these profiles holds, with `runtime` added for any model
    profile. Refuses pending entries and over-size bundles."""
    want = set(profiles)
    if any(not p.startswith("export-") and p != "runtime" for p in want):
        want.add("runtime")
    if any(p.startswith("export-") for p in want) and any(not p.startswith("export-") for p in want):
        raise Refused("export-* profiles are fetched on their own, never into a bundle")
    chosen = [e for e in entries if e["profile"] in want and e["arch"] in (arch, "any")]
    for p in sorted(want):
        if not any(e["profile"] == p for e in chosen):
            raise Refused(f"profile {p}: no entries for arch {arch}")
    for e in chosen:
        exc = LICENCE_EXCEPTIONS.get(e.get("licence_exception", ""))
        if exc and not any(n["dest"] == exc["notice"] and n["role"] == "notice" and n["sha256"] == e["sha256"]
                           for n in chosen):
            raise Refused(f"{e['id']}: licence_exception {e['licence_exception']} ships only with "
                          f"{exc['notice']} from the same archive")
    pending = [e["id"] for e in chosen if e["sha256"] == ""]
    if pending:
        how = sorted({e["produced_by"] for e in chosen if e["sha256"] == ""})
        raise Refused(f"pending, not yet pinned: {', '.join(pending)} (produced by {', '.join(how)})")
    if not any(p.startswith("export-") for p in want):
        total = sum(e.get("extract_bytes", e["bytes"]) for e in chosen)
        if total > MAX_BUNDLE_BYTES:
            raise Refused(f"bundle of {total} bytes is over the {MAX_BUNDLE_BYTES}-byte cap")
    return chosen


# ---- fetching ------------------------------------------------------------------------

class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise Refused(f"redirect to a non-https URL refused ({code})")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_open(url):
    """The real fetcher: a readable stream for an https URL. Proxies come from the
    environment as urllib reads them; nothing else is configured."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise Refused("only https URLs are fetched")
    opener = urllib.request.build_opener(_HttpsOnly())
    req = urllib.request.Request(url, headers={"User-Agent": "openseal-fetch-models/1"})
    return opener.open(req, timeout=TIMEOUT_S)


def stream_to(entry, src, out_path):
    """Copy at most bytes+1 from src to out_path, hashing as it goes; refuse a size or
    hash mismatch. Returns nothing; raises Refused naming the entry."""
    h, n, limit = hashlib.sha256(), 0, entry["bytes"]
    with open(out_path, "wb") as out:
        while True:
            chunk = src.read(min(CHUNK, limit + 1 - n))
            if not chunk:
                break
            n += len(chunk)
            if n > limit:
                raise Refused(f"{entry['id']}: more than the manifest's {limit} bytes")
            h.update(chunk)
            out.write(chunk)
    if n != limit:
        raise Refused(f"{entry['id']}: {n} bytes, the manifest says {limit}")
    if h.hexdigest() != entry["sha256"]:
        raise Refused(f"{entry['id']}: SHA-256 {h.hexdigest()} does not match the manifest's {entry['sha256']}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def obtain(entry, cache, opener, work):
    """A verified local copy of the entry's file: from the cache when present and
    matching, else downloaded (and then cached). The cache is keyed by SHA-256 and is
    re-hashed on every use, so a poisoned cache is refused, never trusted."""
    if cache is not None:
        cached = cache / entry["sha256"]
        if cached.is_file():
            with open(cached, "rb") as src:
                try:
                    stream_to(entry, src, work / entry["sha256"])
                    return work / entry["sha256"]
                except Refused:
                    print(f"fetch-models: cached copy of {entry['id']} does not match; downloading", file=sys.stderr)
    target = work / entry["sha256"]
    with opener(entry["source_url"]) as src:
        stream_to(entry, src, target)
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        tmp = cache / (entry["sha256"] + ".part")
        shutil.copyfile(target, tmp)
        os.replace(tmp, cache / entry["sha256"])
    return target


def extract_member(entry, archive, out_path):
    """Write the one named member of a .tgz to out_path, checked; nothing else is read
    out of the archive and no archive path reaches the filesystem."""
    with tarfile.open(archive, "r:gz") as tar:
        try:
            info = tar.getmember(entry["extract"])
        except KeyError:
            raise Refused(f"{entry['id']}: archive has no member {entry['extract']}") from None
        if not info.isfile():
            raise Refused(f"{entry['id']}: member {entry['extract']} is not a regular file")
        src = tar.extractfile(info)
        sub = {"id": entry["id"] + " (extracted)", "bytes": entry["extract_bytes"], "sha256": entry["extract_sha256"]}
        stream_to(sub, src, out_path)


def bundle_id(lines):
    return hashlib.sha256("".join(f"{s} {b} {d}\n" for s, b, d in sorted(lines, key=lambda t: t[2])).encode()).hexdigest()


def fetch(entries, profiles, arch, dest, cache=None, opener=https_open):
    """Fetch a bundle into dest (absent or empty). On any refusal dest is left empty."""
    chosen = select(entries, profiles, arch)
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise Refused(f"{dest}: destination is not empty")
    try:
        with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".fetch-models-") as tmp:
            work = pathlib.Path(tmp)
            staged = work / "bundle"
            staged.mkdir()
            lines, files, obtained = [], [], {}
            for i, e in enumerate(chosen):
                # One download per source: the runtime archive feeds its library and notices.
                got = obtained.get(e["sha256"]) or obtain(e, cache, opener, work)
                obtained[e["sha256"]] = got
                reused = any(later["sha256"] == e["sha256"] for later in chosen[i + 1:])
                out = staged / e["dest"]
                out.parent.mkdir(parents=True, exist_ok=True)
                if "extract" in e:
                    extract_member(e, got, out)
                    sha, size = e["extract_sha256"], e["extract_bytes"]
                else:
                    (shutil.copyfile if reused else os.replace)(got, out)
                    sha, size = e["sha256"], e["bytes"]
                out.chmod(0o444)
                lines.append((sha, size, e["dest"]))
                files.append({"id": e["id"], "profile": e["profile"], "role": e["role"], "dest": e["dest"],
                              "sha256": sha, "bytes": size, "licence": e["licence"],
                              "source_url": e["source_url"], "source_sha256": e["sha256"]})
                if "licence_exception" in e:
                    files[-1]["licence_exception"] = e["licence_exception"]
                print(f"fetch-models: {e['id']}: {size} bytes, SHA-256 ok, {e['licence']}")
            info = {"schema": 1, "bundle_id": bundle_id(lines), "arch": arch,
                    "profiles": sorted({e["profile"] for e in chosen}),
                    "files": sorted(files, key=lambda f: f["dest"])}
            (staged / "bundle.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf8")
            (staged / "bundle.json").chmod(0o444)
            for item in staged.iterdir():
                os.replace(item, dest / item.name)
    except BaseException:
        for item in dest.iterdir():
            shutil.rmtree(item) if item.is_dir() and not item.is_symlink() else item.unlink()
        raise
    return info


def verify(entries, bundle_dir):
    """Re-hash a fetched bundle against bundle.json and the manifest (an operator's
    mounted directory, before modeld does the same at start)."""
    info = json.loads((bundle_dir / "bundle.json").read_text(encoding="utf8"))
    by_dest = {(e["dest"], e["arch"]): e for e in entries}
    lines = []
    for f in info["files"]:
        e = by_dest.get((f["dest"], info["arch"])) or by_dest.get((f["dest"], "any"))
        if e is None:
            raise Refused(f"{f['dest']}: not in the manifest")
        want = (e.get("extract_sha256", e["sha256"]), e.get("extract_bytes", e["bytes"]))
        path = bundle_dir / f["dest"]
        check_dest(f["dest"], e["id"])
        if not path.is_file() or path.stat().st_size != want[1] or sha256_file(path) != want[0]:
            raise Refused(f"{e['id']}: {f['dest']} does not match the manifest")
        lines.append((want[0], want[1], f["dest"]))
    listed = {f["dest"] for f in info["files"]} | {"bundle.json"}
    for p in bundle_dir.rglob("*"):
        if p.is_file() and str(p.relative_to(bundle_dir)) not in listed:
            raise Refused(f"{p.relative_to(bundle_dir)}: a file not in the bundle")
    if bundle_id(lines) != info["bundle_id"]:
        raise Refused("bundle.json: bundle_id does not match its files")
    return info


def load(path=MANIFEST):
    data = pathlib.Path(path).read_bytes()
    if len(data) > MAX_MANIFEST_BYTES:
        raise Refused(f"{path}: over {MAX_MANIFEST_BYTES} bytes")
    return validate(parse_manifest(data.decode("utf8")))


def host_arch(given):
    a = ARCH_ALIASES.get(given or platform.machine())
    if a is None:
        raise Refused(f"arch {given or platform.machine()} has no ONNX Runtime entry; pass --arch x86_64 or aarch64")
    return a


# ---- self-test -----------------------------------------------------------------------

def _entry(eid, profile, payload, **over):
    e = {"id": eid, "profile": profile, "arch": "any", "role": "model", "dest": f"{eid}/model.onnx",
         "source_url": f"https://huggingface.co/acme/{eid}/resolve/{'0' * 40}/model.onnx",
         "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload), "licence": "Apache-2.0",
         "licence_url": "https://example.org/LICENSE", "card_url": "https://example.org/card",
         "provenance": "synthetic self-test entry"}
    e.update(over)
    return e


def _manifest(entries):
    def q(v):
        return str(v) if isinstance(v, int) else '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    out = ["schema = 1", ""]
    for e in entries:
        out.append("[[file]]")
        out += [f"{k} = {q(v)}" for k, v in e.items()]
        out.append("")
    return "\n".join(out)


def self_test():
    """Each case must come out as stated; a fetcher that accepts everything fails here."""
    failures = []
    payload = b"onnx-model-bytes" * 64
    tar_buf = io.BytesIO()
    lib = b"\x7fELF fake onnxruntime" * 32
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo("onnxruntime-linux-x64-0.0.0/lib/libonnxruntime.so.0.0.0")
        ti.size = len(lib)
        tar.addfile(ti, io.BytesIO(lib))
        link = tarfile.TarInfo("onnxruntime-linux-x64-0.0.0/lib/libonnxruntime.so")
        link.type, link.linkname = tarfile.SYMTYPE, "libonnxruntime.so.0.0.0"
        tar.addfile(link)
        notices = tarfile.TarInfo("onnxruntime-linux-x64-0.0.0/ThirdPartyNotices.txt")
        notices.size = len(b"Eigen MPL-2.0; Boost BSL-1.0")
        tar.addfile(notices, io.BytesIO(b"Eigen MPL-2.0; Boost BSL-1.0"))
        evil = tarfile.TarInfo("../../etc/evil")
        evil.size = 4
        tar.addfile(evil, io.BytesIO(b"evil"))
    archive = tar_buf.getvalue()
    runtime = _entry("onnxruntime-x86_64", "runtime", archive, arch="x86_64", role="runtime",
                     dest="runtime/libonnxruntime.so",
                     source_url="https://github.com/microsoft/onnxruntime/releases/download/v0.0.0/ort.tgz",
                     licence="MIT", extract="onnxruntime-linux-x64-0.0.0/lib/libonnxruntime.so.0.0.0",
                     extract_sha256=hashlib.sha256(lib).hexdigest(), extract_bytes=len(lib))
    blobs = {runtime["source_url"]: archive}

    def opener_for(served):
        def opener(url):
            if url not in served:
                raise AssertionError(f"unexpected fetch {url}")
            return io.BytesIO(served[url])
        return opener

    def expect_refused(name, fn, needle):
        try:
            fn()
        except Refused as err:
            if needle not in str(err):
                failures.append(f"{name}: refused, but the message does not name {needle!r}: {err}")
            return
        failures.append(f"{name}: was accepted; it must be refused")

    def run_cli(argv):
        """The command line as an operator runs it; returns (exit code, stderr text)."""
        err = io.StringIO()
        old_err, old_out = sys.stderr, sys.stdout
        sys.stderr, sys.stdout = err, io.StringIO()
        try:
            code = main(argv, opener=opener_for(blobs))
        finally:
            sys.stderr, sys.stdout = old_err, old_out
        return code, err.getvalue()

    quiet = io.StringIO()
    with tempfile.TemporaryDirectory(prefix="fetch-models-self-test-") as tmp, \
            contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
        tmp = pathlib.Path(tmp)
        good = _entry("ocr-det", "ocr", payload)
        blobs[good["source_url"]] = payload

        # 1. A correct entry fetches; the bundle holds the model, the extracted runtime and bundle.json.
        try:
            info = fetch(validate(parse_manifest(_manifest([good, runtime]))), ["ocr"], "x86_64",
                         tmp / "ok", opener=opener_for(blobs))
            got = sorted(str(p.relative_to(tmp / "ok")) for p in (tmp / "ok").rglob("*") if p.is_file())
            if got != ["bundle.json", "ocr-det/model.onnx", "runtime/libonnxruntime.so"]:
                failures.append(f"good fetch: unexpected files {got}")
            if (tmp / "etc").exists() or (tmp / "ok" / "etc").exists():
                failures.append("good fetch: an archive path other than the named member was written")
            if verify(validate(parse_manifest(_manifest([good, runtime]))), tmp / "ok") != info:
                failures.append("good fetch: --verify disagrees with fetch")
        except Refused as err:
            failures.append(f"good fetch was refused: {err}")

        # 2. A wrong hash fails non-zero through the command line, names the file, leaves dest empty.
        bad = dict(good, sha256=hashlib.sha256(b"something else").hexdigest())
        (tmp / "bad.toml").write_text(_manifest([bad, runtime]), encoding="utf8")
        code, err = run_cli(["--manifest", str(tmp / "bad.toml"), "--profile", "ocr", "--arch", "x86_64",
                             "--dest", str(tmp / "bad")])
        if code == 0 or "ocr-det" not in err or "SHA-256" not in err:
            failures.append(f"wrong hash: exit {code}, stderr {err.strip()!r}; must be non-zero naming ocr-det")
        if (tmp / "bad").exists() and any((tmp / "bad").iterdir()):
            failures.append("wrong hash: files left in the destination")

        # 3. CC-BY-NC-4.0 weights fail non-zero through the command line, naming the entry.
        nc = dict(good, id="gliner-multi-v1", licence="CC-BY-NC-4.0")
        (tmp / "nc.toml").write_text(_manifest([nc, runtime]), encoding="utf8")
        code, err = run_cli(["--manifest", str(tmp / "nc.toml"), "--profile", "ocr", "--arch", "x86_64",
                             "--dest", str(tmp / "nc")])
        if code == 0 or "gliner-multi-v1" not in err or "CC-BY-NC-4.0" not in err:
            failures.append(f"CC-BY-NC: exit {code}, stderr {err.strip()!r}; must be non-zero naming the entry")

        # 4. The rest of the rules.
        expect_refused("size short", lambda: fetch(validate(parse_manifest(_manifest(
                       [dict(good, bytes=len(payload) + 1), runtime]))), ["ocr"], "x86_64", tmp / "short",
                       opener=opener_for(blobs)), "the manifest says")
        expect_refused("size long", lambda: fetch(validate(parse_manifest(_manifest(
                       [dict(good, bytes=len(payload) - 1), runtime]))), ["ocr"], "x86_64", tmp / "long",
                       opener=opener_for(blobs)), "more than")
        for lic in ("GPL-3.0-only", "MIT AND CC-BY-NC-4.0", "(MIT OR Apache-2.0)", "Apache-2.0 WITH LLVM-exception",
                    "MIT OR AND Apache-2.0", "NVIDIA-Open-Model-License", "CC-BY-NC-SA-4.0", ""):
            expect_refused(f"licence {lic!r}", lambda lic=lic: validate(parse_manifest(_manifest(
                           [dict(good, licence=lic)]))), "allow list")
        for lic in ("MIT OR Apache-2.0", "Apache-2.0 OR MIT", "BSD-3-Clause", "NCSA", "MIT AND Apache-2.0"):
            if not licence_allowed(lic):
                failures.append(f"licence {lic!r}: refused; it must be allowed")
        expect_refused("pickle in a bundle", lambda: validate(parse_manifest(_manifest(
                       [dict(good, dest="ocr-det/pytorch_model.bin")]))), "pickle")
        expect_refused("dest traversal", lambda: validate(parse_manifest(_manifest(
                       [dict(good, dest="../escape.onnx")]))), "plain relative path")
        expect_refused("unpinned url", lambda: validate(parse_manifest(_manifest(
                       [dict(good, source_url="https://huggingface.co/acme/x/resolve/main/model.onnx")]))), "pinned")
        expect_refused("http url", lambda: validate(parse_manifest(_manifest(
                       [dict(good, source_url=good["source_url"].replace("https", "http"))]))), "pinned")
        expect_refused("over file cap", lambda: validate(parse_manifest(_manifest(
                       [dict(good, bytes=MAX_FILE_BYTES + 1)]))), "file cap")
        pend = dict(good, id="gliner-multi", profile="extraction", sha256="", source_url="",
                    produced_by="tools/ml/export-gliner.py")
        expect_refused("pending entry", lambda: select(validate(parse_manifest(_manifest([pend, runtime]))),
                       ["extraction"], "x86_64"), "pending")
        expect_refused("unknown key", lambda: validate(parse_manifest(_manifest([dict(good, revision="x")]))),
                       "unknown key")
        expect_refused("toml outside the subset", lambda: parse_manifest("schema = 1\nx = [1, 2]\n"), "neither")
        expect_refused("non-empty dest", lambda: (
            (tmp / "full").mkdir(), (tmp / "full" / "x").write_text("x"),
            fetch(validate(parse_manifest(_manifest([good, runtime]))), ["ocr"], "x86_64", tmp / "full",
                  opener=opener_for(blobs))), "not empty")
        bad_member = dict(runtime, extract_sha256=hashlib.sha256(b"other").hexdigest())
        expect_refused("runtime member hash", lambda: fetch(validate(parse_manifest(_manifest(
                       [good, bad_member]))), ["ocr"], "x86_64", tmp / "member", opener=opener_for(blobs)),
                       "(extracted)")
        linked = dict(runtime, extract="onnxruntime-linux-x64-0.0.0/lib/libonnxruntime.so")
        expect_refused("runtime member a symlink", lambda: fetch(validate(parse_manifest(_manifest(
                       [good, linked]))), ["ocr"], "x86_64", tmp / "link", opener=opener_for(blobs)),
                       "not a regular file")
        # 5. The scoped licence exception (owner instruction 32): MPL-2.0 and BSL-1.0 only
        #    inside the named ONNX Runtime library entries, only with their notices.
        exc_lib = dict(runtime, licence="MIT AND MPL-2.0 AND BSL-1.0", licence_exception="owner-instruction-32")
        exc_notice = dict(runtime, id="onnxruntime-notices-x86_64", role="notice", dest="runtime/ThirdPartyNotices.txt",
                          extract="onnxruntime-linux-x64-0.0.0/ThirdPartyNotices.txt",
                          extract_sha256=hashlib.sha256(b"Eigen MPL-2.0; Boost BSL-1.0").hexdigest(),
                          extract_bytes=len(b"Eigen MPL-2.0; Boost BSL-1.0"))
        try:
            fetch(validate(parse_manifest(_manifest([good, exc_lib, exc_notice]))), ["ocr"], "x86_64",
                  tmp / "exc", opener=opener_for(blobs))
        except Refused as err:
            failures.append(f"licence exception: the covered runtime entry was refused: {err}")
        expect_refused("exception without its notices", lambda: select(validate(parse_manifest(_manifest(
                       [good, exc_lib]))), ["ocr"], "x86_64"), "ThirdPartyNotices")
        expect_refused("MPL-2.0 runtime without the exception", lambda: validate(parse_manifest(_manifest(
                       [{k: v for k, v in exc_lib.items() if k != "licence_exception"}]))),
                       "allow list")
        expect_refused("exception claimed by a model", lambda: validate(parse_manifest(_manifest(
                       [dict(good, licence="MPL-2.0", licence_exception="owner-instruction-32")]))), "does not cover")
        expect_refused("exception claimed by another runtime id", lambda: validate(parse_manifest(_manifest(
                       [dict(exc_lib, id="onnxruntime-riscv64")]))), "does not cover")
        expect_refused("exception claimed by a notice", lambda: validate(parse_manifest(_manifest(
                       [dict(exc_notice, licence="MPL-2.0", licence_exception="owner-instruction-32")]))),
                       "does not cover")
        expect_refused("exception widened to GPL", lambda: validate(parse_manifest(_manifest(
                       [dict(exc_lib, licence="MIT AND MPL-2.0 AND GPL-3.0-only")]))), "allow list")
        expect_refused("unknown exception", lambda: validate(parse_manifest(_manifest(
                       [dict(exc_lib, licence_exception="owner-instruction-99")]))), "unknown licence_exception")

        poisoned = tmp / "cache"
        poisoned.mkdir()
        (poisoned / good["sha256"]).write_bytes(b"poison")
        try:
            fetch(validate(parse_manifest(_manifest([good, runtime]))), ["ocr"], "x86_64", tmp / "cached",
                  cache=poisoned, opener=opener_for(blobs))
            if (poisoned / good["sha256"]).read_bytes() != payload:
                failures.append("poisoned cache: not replaced by the verified download")
        except Refused as err:
            failures.append(f"poisoned cache: refused instead of re-downloading: {err}")
        if (tmp / "ok").exists():
            (tmp / "ok" / "ocr-det" / "model.onnx").chmod(0o644)
            with open(tmp / "ok" / "ocr-det" / "model.onnx", "r+b") as f:
                f.write(b"X")
            expect_refused("verify a flipped byte", lambda: verify(validate(parse_manifest(
                           _manifest([good, runtime]))), tmp / "ok"), "does not match")

    # 6. The committed manifest: valid, every profile known, allow list equal to deny.toml,
    #    and the licence exception carried by exactly the entries it names.
    try:
        text = MANIFEST.read_text(encoding="utf8")
        entries = validate(parse_manifest(text))
        carried = {e["id"] for e in entries if "licence_exception" in e}
        named = set().union(*(x["ids"] for x in LICENCE_EXCEPTIONS.values()))
        if carried != named:
            failures.append(f"models.toml: licence_exception carried by {sorted(carried)}, named for {sorted(named)}")
        try:
            import tomllib
            if tomllib.loads(text) != parse_manifest(text):
                failures.append("models.toml: the subset reader and tomllib disagree")
        except ImportError:
            pass
        for arch in ARCHES:
            for p in PROFILES:
                if p == "runtime" or any(e["sha256"] == "" for e in entries if e["profile"] == p):
                    continue
                select(entries, [p], arch)
    except (Refused, OSError) as err:
        failures.append(f"models.toml: {err}")
    if DENY_TOML.is_file():
        m = re.search(r"\[licenses\][^\[]*?allow\s*=\s*\[(.*?)\]", DENY_TOML.read_text(encoding="utf8"), re.S)
        deny = set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()
        if deny != ALLOWED_LICENCES:
            failures.append(f"allow list differs from deny.toml: {sorted(deny ^ ALLOWED_LICENCES)}")

    if failures:
        for f in failures:
            print(f"fetch-models self-test: {f}", file=sys.stderr)
        return 1
    print("fetch-models self-test: refuses a wrong hash, CC-BY-NC and every other rule; the manifest is valid")
    return 0


# ---- command line --------------------------------------------------------------------

def main(argv=None, opener=https_open):
    ap = argparse.ArgumentParser(description="Fetch the pinned modeld bundle (ADR-029).")
    ap.add_argument("--manifest", default=str(MANIFEST))
    ap.add_argument("--profile", action="append", choices=sorted(PROFILES))
    ap.add_argument("--dest", help="an absent or empty directory")
    ap.add_argument("--arch", help="x86_64 or aarch64 (also amd64, arm64); default: this machine")
    ap.add_argument("--cache", help="a directory of earlier downloads, keyed by SHA-256, re-hashed on use")
    ap.add_argument("--verify", metavar="DIR", help="re-hash a fetched bundle against the manifest")
    ap.add_argument("--list", action="store_true", help="print the profiles and their files")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        entries = load(args.manifest)
        if args.list:
            for p, what in PROFILES.items():
                print(f"{p}: {what}")
                for e in entries:
                    if e["profile"] == p:
                        state = "pending" if not e["sha256"] else f"{e.get('extract_bytes', e['bytes'])} B"
                        print(f"  {e['id']} [{e['arch']}] {e['licence']} {state}")
            return 0
        if args.verify:
            info = verify(entries, pathlib.Path(args.verify))
            print(f"fetch-models: {args.verify} matches the manifest; bundle {info['bundle_id']}")
            return 0
        if not args.profile or not args.dest:
            ap.error("--profile and --dest are required to fetch")
        info = fetch(entries, args.profile, host_arch(args.arch), pathlib.Path(args.dest),
                     cache=pathlib.Path(args.cache) if args.cache else None, opener=opener)
        print(f"fetch-models: bundle {info['bundle_id']} ({', '.join(info['profiles'])}, {info['arch']})")
        return 0
    except Refused as err:
        print(f"fetch-models: {err}", file=sys.stderr)
        return 1
    except (OSError, tarfile.TarError, json.JSONDecodeError, KeyError, ValueError) as err:
        print(f"fetch-models: {type(err).__name__}: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
