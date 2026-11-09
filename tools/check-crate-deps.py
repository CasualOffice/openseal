#!/usr/bin/env python3
"""Nothing in crates/ depends on a server, or on anything outside crates/ (`CI-01`).

[19](../docs/19-WORKSPACE-SCAFFOLD-DESIGN.md): `server/*` depends on `crates/*`, and
nothing in `crates/` depends on a server. The engine compiles to WebAssembly and runs
in a browser; a server crate brings an async runtime, sockets and a host's policy with
it, and the edge that adds one is a single line in a Cargo.toml that review can miss.
OpenCalc holds the same boundary with its wasm gate's `--exclude`; here it is checked
directly, before a server exists, so the first one cannot arrive across it.

What is checked, for every package whose manifest is under crates/:

  * a path dependency resolves inside crates/;
  * no dependency, path or registry, normal, dev or build, names a server crate: one
    defined outside crates/ in this repository, or one whose name says it is
    (`server`, or the server crates docs/19 reserves: `-host`, `-wopi`, `-mcp`,
    `-secrets`, `-collab-server`).

Dev-dependencies are included: a test that needs a server belongs to the server.

    python3 tools/check-crate-deps.py [ROOT]
"""

import json
import pathlib
import re
import subprocess
import sys

# From docs/19 server/ list. A crate of this name in crates/ would be one of these
# moved, and the move is the thing to discuss.
RESERVED_SERVER = re.compile(r"(server|^casual-sign-(server|worker|keyd|convert|mcp|secrets)$)")


def metadata(root):
    done = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if done.returncode != 0:
        return None, done.stderr.strip().splitlines()[-1:] or ["cargo metadata failed"]
    return json.loads(done.stdout), None


def manifests_outside_crates(root):
    """Package names defined anywhere in the repository outside crates/."""
    names = {}
    for manifest in root.rglob("Cargo.toml"):
        # A worktree under .claude holds a second copy of every crate.
        if ".claude" in manifest.relative_to(root).parts:
            continue
        rel = manifest.relative_to(root)
        if rel.parts[0] in {"crates", "target"} or "target" in rel.parts:
            continue
        match = re.search(r'(?m)^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', manifest.read_text(encoding="utf8"))
        if match:
            names[match.group(1)] = str(rel.parent)
    return names


def check(root):
    root = pathlib.Path(root).resolve()
    crates = root / "crates"
    meta, error = metadata(root)
    if meta is None:
        return [f"could not read the workspace: {error[0]}"], ""
    elsewhere = manifests_outside_crates(root)
    problems = []
    edges = 0
    packages = [
        p for p in meta["packages"]
        if pathlib.Path(p["manifest_path"]).resolve().is_relative_to(crates)
    ]
    for package in packages:
        for dep in package["dependencies"]:
            edges += 1
            kind = dep.get("kind") or "normal"
            where = f"{package['name']} -> {dep['name']} ({kind})"
            path = dep.get("path")
            if path and not pathlib.Path(path).resolve().is_relative_to(crates):
                problems.append(f"{where}: path {path} is outside crates/")
            if dep["name"] in elsewhere:
                problems.append(f"{where}: defined in {elsewhere[dep['name']]}, outside crates/")
            elif RESERVED_SERVER.search(dep["name"]):
                problems.append(f"{where}: the name is a server crate's")
    if not packages:
        problems.append("no package under crates/ was found, so nothing was checked")
    return problems, f"crate dependencies: {len(packages)} crates, {edges} edges, none to a server"


def main(argv):
    root = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
    problems, summary = check(root)
    if problems:
        print("crates depending on a server or outside crates/ (docs/19, CI-01):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
