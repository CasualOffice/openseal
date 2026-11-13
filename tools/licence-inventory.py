#!/usr/bin/env python3
"""Third-party licence inventory, and the NOTICE check against it (`LEG-01`).

Writes two files at the repository root from what the repository actually ships:

  THIRD-PARTY.md            every third-party component, with its version, licence,
                            scope and copyright lines: the Rust crates in Cargo.lock
                            (read through `cargo metadata`), the files vendored or
                            embedded outside Cargo (pdf.js, Lucide, fonts, data
                            tables), and the model weights in tools/ml/models.toml.
  THIRD-PARTY-LICENSES.txt  the licence and notice files each crate ships, verbatim,
                            one copy of each distinct text, naming the crates it covers.
                            The Apache License 2.0 text is the repository's LICENSE.

`--check` regenerates both in memory and fails, naming each problem, when:

  * either file is missing or differs from what the tree produces now;
  * NOTICE does not point to THIRD-PARTY.md;
  * NOTICE does not name a component listed below (COMPONENTS), a crate that ships a
    NOTICE file (Apache-2.0 section 4(d)), or a model repository a bundled profile of
    models.toml loads;
  * a licence file, font or vendored directory exists in a shipped folder that no
    component below accounts for (so something added later cannot go unlisted).

This is a tool for the licence review, not a repository gate: check-repo.py does not run
it (CLAUDE.md, "no new gates unless the owner asks"). It needs `cargo` on PATH and the
crates' sources in Cargo's registry (`cargo fetch`); it never downloads anything itself
beyond what `cargo metadata --locked` does. Not legal advice: counsel reviews the result.

    python3 tools/licence-inventory.py           # write both files
    python3 tools/licence-inventory.py --check   # compare, and check NOTICE
"""

import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
INVENTORY = "THIRD-PARTY.md"
TEXTS = "THIRD-PARTY-LICENSES.txt"

# Material that is not a Cargo dependency. `path` is what ships; `licence_files` must
# exist; `notice` is the text NOTICE must contain for the component to count as named.
COMPONENTS = [
    {"name": "pdf.js", "version": "4.10.38", "path": "webapp/vendor/pdfjs",
     "licence": "Apache-2.0", "holder": "Mozilla Foundation",
     "licence_files": ["webapp/vendor/pdfjs/LICENSE"], "ships": "browser (web app)",
     "notice": "pdf.js 4.10.38"},
    {"name": "pdf.js CMaps", "version": "4.10.38", "path": "webapp/vendor/pdfjs/cmaps",
     "licence": "BSD-3-Clause", "holder": "Adobe Systems Incorporated",
     "licence_files": ["webapp/vendor/pdfjs/cmaps/LICENSE"], "ships": "browser (web app)",
     "notice": "cmaps/"},
    {"name": "Foxit standard fonts (in pdf.js)", "version": "4.10.38",
     "path": "webapp/vendor/pdfjs/standard_fonts", "licence": "BSD-style (Foxit)",
     "holder": "Foxit Software Inc.",
     "licence_files": ["webapp/vendor/pdfjs/standard_fonts/LICENSE_FOXIT"],
     "ships": "browser (web app)", "notice": "LICENSE_FOXIT"},
    {"name": "Liberation Sans (in pdf.js)", "version": "4.10.38",
     "path": "webapp/vendor/pdfjs/standard_fonts", "licence": "OFL-1.1",
     "holder": "Google Corporation; Red Hat, Inc.",
     "licence_files": ["webapp/vendor/pdfjs/standard_fonts/LICENSE_LIBERATION"],
     "ships": "browser (web app)", "notice": "LICENSE_LIBERATION"},
    {"name": "Lucide icons", "version": "1.62.0", "path": "webapp/vendor/lucide",
     "licence": "ISC (parts MIT, from Feather)",
     "holder": "Lucide Icons and Contributors; Cole Bemis",
     "licence_files": ["webapp/vendor/lucide/LICENSE"], "ships": "browser (web app)",
     "notice": "Lucide icons 1.62.0"},
    {"name": "Lucide icons (site copy)", "version": "1.62.0", "path": "site/_src/lucide",
     "licence": "ISC (parts MIT, from Feather)",
     "holder": "Lucide Icons and Contributors; Cole Bemis",
     "licence_files": ["site/_src/lucide/LICENSE"], "ships": "browser (website)",
     "notice": "site/_src/lucide/"},
    {"name": "Geist and Geist Mono", "version": "1.3.1", "path": "webapp/fonts/ui",
     "licence": "OFL-1.1", "holder": "Vercel, in collaboration with basement.studio",
     "licence_files": ["webapp/fonts/ui/OFL-1.1-Geist.txt"], "ships": "browser (web app)",
     "notice": "webapp/fonts/ui/"},
    {"name": "Geist and Geist Mono (console copy)", "version": "1.3.1",
     "path": "console-ui/fonts", "licence": "OFL-1.1",
     "holder": "Vercel, in collaboration with basement.studio",
     "licence_files": ["console-ui/fonts/OFL-1.1-Geist.txt"],
     "ships": "browser (console, embedded in casual-sign-console)",
     "notice": "console-ui/fonts/"},
    {"name": "Geist and Geist Mono (site copy)", "version": "1.3.1",
     "path": "site/assets/fonts/ui", "licence": "OFL-1.1",
     "holder": "Vercel, in collaboration with basement.studio",
     "licence_files": ["site/assets/fonts/ui/OFL-1.1-Geist.txt"], "ships": "browser (website)",
     "notice": "site/assets/fonts/ui/"},
    {"name": "Great Vibes and Allura (web app copy)", "version": "see fonts/PROVENANCE.md",
     "path": "webapp/fonts/script", "licence": "OFL-1.1",
     "holder": "The Great Vibes Pro Project Authors; The Allura Project Authors",
     "licence_files": ["webapp/fonts/script/OFL-1.1-GreatVibes.txt",
                       "webapp/fonts/script/OFL-1.1-Allura.txt"],
     "ships": "browser (web app)", "notice": "webapp/fonts/script/"},
    {"name": "Liberation Sans, Serif, Mono; Great Vibes; Allura",
     "version": "see fonts/PROVENANCE.md", "path": "crates/casual-sign-flatten/fonts",
     "licence": "OFL-1.1",
     "holder": "Google Corporation; Red Hat, Inc.; The Great Vibes Pro Project Authors; "
               "The Allura Project Authors",
     "licence_files": ["crates/casual-sign-flatten/fonts/LICENSES"],
     "ships": "server and WASM binaries; subsets embedded in flattened PDFs",
     "notice": "crates/casual-sign-flatten/fonts/"},
    {"name": "Adobe Core14 AFM widths, Adobe Glyph List subset", "version": "data",
     "path": "crates/casual-sign-fields/src/tables.rs",
     "licence": "Adobe AFM notice; BSD-3-Clause (AGL)", "holder": "Adobe",
     "licence_files": [], "ships": "server and WASM binaries",
     "notice": "crates/casual-sign-fields/src/tables.rs"},
    {"name": "Presidio recogniser patterns (ported, no code)", "version": "2.2.364",
     "path": "crates/casual-sign-pii", "licence": "MIT", "holder": "Presidio Contributors",
     "licence_files": ["crates/casual-sign-pii/LICENSE-PRESIDIO"],
     "ships": "server and WASM binaries", "notice": "LICENSE-PRESIDIO"},
    {"name": "Lexend SemiBold outlines in the logo", "version": "data",
     "path": "docs/assets", "licence": "OFL-1.1", "holder": "The Lexend Project Authors",
     "licence_files": [], "ships": "logo SVGs (web app, site, docs)",
     "notice": "Lexend SemiBold"},
    {"name": "ONNX Runtime (modeld image only)", "version": "1.28.3",
     "path": "deploy/modeld", "licence": "MIT; bundles MPL-2.0 (Eigen), BSL-1.0 (Boost)",
     "holder": "Microsoft Corporation",
     "licence_files": ["deploy/modeld/NOTICE.txt"], "ships": "modeld container image",
     "notice": "ONNX Runtime 1.28.3"},
]

# Folders whose contents reach users; anything licence-like or font-like in them must
# sit under a component's path.
SHIPPED = ["webapp", "console-ui", "site", "crates", "server", "deploy"]
SKIP = {"node_modules", "target", "e2e", "tests", ".git"}
LICENCE_NAME = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|OFL|UNLICENSE)", re.I)
FONT = re.compile(r"\.(ttf|otf|woff2?|pfb|pfa)$", re.I)
CRATE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT)", re.I)
COPYRIGHT = re.compile(r"^\s*(?:%%Copyright:\s*|//\s*|#\s*|\*\s*)?(Copyright\b.*?)\s*$")
TEMPLATE = re.compile(r"\[yyyy\]|\[name of|<year>|<copyright|\{yyyy\}|\{name of|YEAR|"
                      r"Copyright \(c\) \.\.\.|Copyright notice|copyright notices?\b|"
                      r"Copyright owner|COPYRIGHT HOLDERS? AND|copyright holder", re.I)


def cargo_metadata(root):
    out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"],
                         cwd=root, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"licence-inventory: cargo metadata failed: {out.stderr.strip()[-300:]}")
    return json.loads(out.stdout)


def scopes(meta):
    """Map package id to 'shipped' (reached by normal edges from a workspace member),
    'build' (only through build-dependencies) or 'test' (only through dev-dependencies)."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    members = set(meta["workspace_members"])
    rank = {"shipped": 0, "build": 1, "test": 2}
    seen = {}
    stack = [(m, "shipped") for m in members]
    while stack:
        pid, scope = stack.pop()
        if pid in seen and rank[seen[pid]] <= rank[scope]:
            continue
        seen[pid] = scope
        for dep in nodes[pid]["deps"]:
            for kind in dep["dep_kinds"]:
                nxt = {None: scope, "build": "build", "dev": "test"}[kind["kind"]]
                if kind["kind"] == "dev" and pid not in members:
                    continue
                if rank[nxt] < rank[scope]:
                    nxt = scope
                stack.append((dep["pkg"], nxt))
    return {pid: s for pid, s in seen.items() if pid not in members}


def is_standard_apache(text):
    """True when the file is the Apache License 2.0 text and nothing else: no preamble,
    no copyright line beyond the appendix template, nothing after the appendix. Such a
    file adds nothing to the repository's LICENSE; any other file is reproduced."""
    start = text.find("Apache License")
    if start < 0 or "Version 2.0, January 2004" not in text or \
            "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" not in text:
        return False
    if text[:start].strip():
        return False
    end = text.rfind("limitations under the License.")
    tail = text[end + len("limitations under the License."):] if end >= 0 else ""
    if len(tail.strip()) > 20:
        return False
    head, _, appendix = text.partition("END OF TERMS AND CONDITIONS")
    return "Copyright" not in head and \
        all(TEMPLATE.search(m.group(1)) for m in map(COPYRIGHT.match, appendix.splitlines()) if m)


def copyright_lines(texts):
    found = []
    for text in texts:
        for line in text.splitlines():
            m = COPYRIGHT.match(line)
            if m and not TEMPLATE.search(m.group(1)) and len(m.group(1)) > 14:
                c = re.sub(r"\s+", " ", m.group(1)).strip()
                if c not in found:
                    found.append(c)
    return found[:4]


def crates(meta):
    sc = scopes(meta)
    rows, texts, problems = [], {}, []
    for p in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        if p["id"] not in sc:
            continue
        d = pathlib.Path(p["manifest_path"]).parent
        files = sorted(f for f in d.iterdir() if f.is_file() and CRATE_FILE.match(f.name))
        if p.get("license_file"):
            lf = (d / p["license_file"]).resolve()
            if lf.is_file() and lf not in [f.resolve() for f in files]:
                files.append(lf)
        bodies = []
        for f in files:
            body = f.read_text(encoding="utf8", errors="replace").replace("\r\n", "\n").strip()
            bodies.append(body)
            if is_standard_apache(body):
                continue  # the repository's LICENSE carries this text
            key = hashlib.sha256(body.encode()).hexdigest()
            texts.setdefault(key, {"body": body, "crates": []})["crates"].append(
                f"{p['name']} {p['version']} ({f.name})")
        notice = [f.name for f in files if f.name.upper().startswith("NOTICE")]
        if not files:
            problems.append(f"{p['name']} {p['version']}: ships no licence file in its package")
        rows.append({"name": p["name"], "version": p["version"],
                     "licence": p.get("license") or f"file: {p.get('license_file')}",
                     "scope": sc[p["id"]], "repo": p.get("repository") or "",
                     "copyright": copyright_lines(bodies), "notice": notice})
    return rows, texts, problems


def models(root):
    spec = importlib.util.spec_from_file_location("fetch_models", root / "tools/ml/fetch-models.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    manifest = mod.parse_manifest((root / "tools/ml/models.toml").read_text(encoding="utf8"))
    seen = {}
    for f in manifest["file"]:
        if f["profile"].startswith("export-") or f["role"] == "runtime" or f["role"] == "notice":
            continue
        repo = re.sub(r"^https://huggingface\.co/", "", f["card_url"])
        entry = seen.setdefault(repo, {"repo": repo, "profiles": [], "licences": [], "ids": []})
        for k, v in (("profiles", f["profile"]), ("licences", f["licence"]), ("ids", f["id"])):
            if v not in entry[k]:
                entry[k].append(v)
    return list(seen.values())


def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def render(rows, texts, mods):
    shipped = sum(r["scope"] == "shipped" for r in rows)
    out = [
        "# Third-party components",
        "",
        "Generated by `python3 tools/licence-inventory.py` from Cargo.lock (through `cargo metadata`),",
        "the vendored and embedded files it lists, and `tools/ml/models.toml`. Do not edit by hand;",
        "rerun the tool. [NOTICE](NOTICE) carries the attributions;",
        "[THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt) carries each crate's own licence and notice files verbatim, and the",
        "Apache License 2.0 text is [LICENSE](LICENSE). This inventory is not legal advice; `LEG-01`'s",
        "counsel review covers it (docs/09 §9).",
        "",
        "**Scope:** `shipped` is reached through normal dependencies from a workspace crate (it may be",
        "linked into a server, worker, keyd, modeld, console or the WASM engine, on some target);",
        "`build` only through build-dependencies (runs at build time, not distributed);",
        "`test` only through dev-dependencies (never distributed). Cargo.lock covers every target",
        "platform, so `shipped` over-counts for any one binary.",
        "",
        f"## Rust crates ({len(rows)}: {shipped} shipped)",
        "",
        "| Crate | Version | Licence (as declared) | Scope | Copyright lines in its licence files | NOTICE file |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        out.append(f"| {cell(r['name'])} | {r['version']} | {cell(r['licence'])} | {r['scope']} | "
                   f"{cell('; '.join(r['copyright']) or '(none stated)')} | {cell(', '.join(r['notice']))} |")
    out += ["", f"## Vendored and embedded files ({len(COMPONENTS)})", "",
            "| Component | Version | Path | Licence | Holder | Licence file | Ships in |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for c in COMPONENTS:
        out.append(f"| {cell(c['name'])} | {cell(c['version'])} | `{c['path']}` | {cell(c['licence'])} | "
                   f"{cell(c['holder'])} | {cell(', '.join(c['licence_files']) or 'NOTICE')} | {cell(c['ships'])} |")
    out += ["", f"## Model weights and tokenizers in bundled profiles ({len(mods)})", "",
            "From `tools/ml/models.toml`; export-only inputs are not bundled and not listed. Training-data",
            "notes are in docs/09 §8.", "",
            "| Repository | Licence | Profiles | Manifest ids |", "| --- | --- | --- | --- |"]
    for m in mods:
        out.append(f"| {cell(m['repo'])} | {cell(', '.join(m['licences']))} | "
                   f"{cell(', '.join(m['profiles']))} | {cell(', '.join(m['ids']))} |")
    inventory = "\n".join(out) + "\n"

    t = ["Third-party licence and notice files shipped by the Rust crates OpenSeal depends on.",
         "Generated by tools/licence-inventory.py; do not edit by hand. Each text appears once and",
         "names the crates that ship it. The Apache License 2.0 text, which many crates ship",
         "unchanged, is the repository's LICENSE file and is not repeated here.", ""]
    for key in sorted(texts, key=lambda k: (texts[k]["crates"][0], k)):
        t.append("=" * 78)
        t.append("Shipped by: " + ", ".join(texts[key]["crates"]))
        t.append("-" * 78)
        t.append(texts[key]["body"])
        t.append("")
    return inventory, "\n".join(t) + "\n"


def notice_problems(root, rows, mods):
    problems = []
    notice = (root / "NOTICE").read_text(encoding="utf8")
    flat = re.sub(r"\s+", " ", notice)
    if INVENTORY not in notice:
        problems.append(f"NOTICE does not point to {INVENTORY}")
    if TEXTS not in notice:
        problems.append(f"NOTICE does not point to {TEXTS}")
    for c in COMPONENTS:
        if c["notice"] not in flat:
            problems.append(f"NOTICE does not name {c['name']} (expected text: {c['notice']!r})")
        for lf in c["licence_files"]:
            if not (root / lf).exists():
                problems.append(f"{c['name']}: licence file {lf} is missing")
    for r in rows:
        if r["notice"] and r["scope"] == "shipped" and f"{r['name']} {r['version']}" not in flat:
            problems.append(f"NOTICE does not reproduce the NOTICE of crate {r['name']} {r['version']} "
                            f"({', '.join(r['notice'])})")
    for m in mods:
        if m["repo"] not in flat:
            problems.append(f"NOTICE does not name model {m['repo']} ({', '.join(m['licences'])})")
    covered = [c["path"] for c in COMPONENTS]
    tracked = subprocess.run(["git", "ls-files", *SHIPPED], cwd=root, capture_output=True,
                             text=True).stdout.split()
    for rel in tracked:
        parts = pathlib.PurePosixPath(rel).parts
        if SKIP & set(parts):
            continue
        name = parts[-1]
        if parts[0] == "crates" and len(parts) == 3 and name.upper().startswith("LICENSE"):
            continue  # a workspace crate's own licence file
        if (LICENCE_NAME.match(name) or FONT.search(name)) and \
                not any(rel == p or rel.startswith(p + "/") for p in covered):
            problems.append(f"{rel}: licence or font file not accounted for by any component")
    return problems


def main(argv):
    check = "--check" in argv[1:]
    meta = cargo_metadata(ROOT)
    rows, texts, crate_problems = crates(meta)
    mods = models(ROOT)
    inventory, licences = render(rows, texts, mods)
    if not check:
        (ROOT / INVENTORY).write_text(inventory, encoding="utf8")
        (ROOT / TEXTS).write_text(licences, encoding="utf8")
        print(f"licence-inventory: wrote {INVENTORY} ({len(rows)} crates, {len(COMPONENTS)} "
              f"components, {len(mods)} model repositories) and {TEXTS} ({len(texts)} texts)")
        for p in crate_problems:
            print(f"  note: {p}")
        return 0
    problems = []
    for name, want in ((INVENTORY, inventory), (TEXTS, licences)):
        path = ROOT / name
        if not path.exists():
            problems.append(f"{name} is missing; run tools/licence-inventory.py")
        elif path.read_text(encoding="utf8") != want:
            problems.append(f"{name} is out of date with the tree; run tools/licence-inventory.py")
    problems += notice_problems(ROOT, rows, mods)
    if problems:
        for p in problems:
            print(f"licence-inventory: {p}", file=sys.stderr)
        return 1
    print(f"licence-inventory: NOTICE and {INVENTORY} cover {len(rows)} crates, "
          f"{len(COMPONENTS)} components and {len(mods)} model repositories")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
