#!/usr/bin/env python3
"""Pin the production profile to a release's image digests (`REL-01`, docs/65 §Releases).

    # the release workflow, from the digests it pushed and signed:
    python3 -I tools/release/pin_release.py --version 0.0.2 --out DIR \\
        --image server=ghcr.io/casualoffice/openseal-server:0.0.2@sha256:<64 hex> \\
        --image worker=...  --image keyd=...
    # an operator, from a release's images.json:
    python3 -I tools/release/pin_release.py --from images.json --out DIR

Writes three files into DIR:

- `images.json`: the release's version and, per service, repository, tag and digest;
- `compose.release.yml`: a Compose override for `deploy/compose.production.yml` that
  sets every OpenSeal service (keyd, migrate, both server replicas, worker) to
  `repository:tag@digest`,
  so Docker pulls exactly the bytes that were signed, whatever later happens to the tag;
- `openseal-release.env`: `OPENSEAL_IMAGE_PREFIX` and `OPENSEAL_VERSION`, which the
  production profile requires even when the override replaces its image lines.

Every image must be given, by digest (`sha256:` and 64 lowercase hex digits), from one
repository prefix `<prefix>-<service>`, tagged with the version. Anything else is refused,
naming the problem, and nothing is written. Same input, same bytes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# The services shipped as images, and the production profile's services that run each.
SERVICES: dict[str, tuple[str, ...]] = {
    "keyd": ("keyd",),
    # Both server replicas behind the profile's proxy (HRD-11).
    "server": ("migrate", "server", "server-2"),
    "worker": ("worker",),
}
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
# registry/path/name[:tag]@sha256:<hex>; lowercase, as OCI requires of repositories.
REFERENCE = re.compile(
    r"^(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)


class PinError(Exception):
    """A release description that cannot be pinned; the message names the problem."""


def parse_reference(service: str, ref: str) -> dict[str, str]:
    """Split `repository[:tag]@sha256:…` for one service, refusing anything not by digest."""
    m = REFERENCE.match(ref)
    if not m:
        raise PinError(f"{service}: not an image reference pinned by sha256 digest: {ref!r}")
    repository = m.group("repository")
    if not repository.endswith(f"-{service}"):
        raise PinError(f"{service}: repository {repository!r} does not end in '-{service}'")
    return {"repository": repository, "tag": m.group("tag") or "", "digest": m.group("digest")}


def build_release(version: str, images: dict[str, str]) -> dict:
    """The validated release description (the content of images.json)."""
    if not VERSION.match(version):
        raise PinError(f"version {version!r} is not MAJOR.MINOR.PATCH[-PRE]")
    missing = sorted(set(SERVICES) - set(images))
    unknown = sorted(set(images) - set(SERVICES))
    if missing:
        raise PinError(f"missing image for: {', '.join(missing)}")
    if unknown:
        raise PinError(f"unknown service: {', '.join(unknown)} (expected {', '.join(sorted(SERVICES))})")
    parsed = {svc: parse_reference(svc, images[svc]) for svc in sorted(images)}
    prefixes = {p["repository"][: -len(f"-{svc}")] for svc, p in parsed.items()}
    if len(prefixes) != 1:
        raise PinError(f"images come from more than one prefix: {', '.join(sorted(prefixes))}")
    for svc, p in parsed.items():
        if p["tag"] and p["tag"] != version:
            raise PinError(f"{svc}: tag {p['tag']!r} is not the version {version!r}")
        p["tag"] = version
    return {"version": version, "prefix": prefixes.pop(), "images": parsed}


def load_release(text: str) -> dict:
    """Read and re-validate an images.json written by this tool."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise PinError(f"images.json is not JSON: line {e.lineno}") from None
    if not isinstance(data, dict) or not isinstance(data.get("images"), dict):
        raise PinError("images.json has no 'images' object")
    version = data.get("version")
    if not isinstance(version, str):
        raise PinError("images.json has no 'version' string")
    refs = {}
    for svc, entry in data["images"].items():
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("repository", "digest")):
            raise PinError(f"{svc}: entry needs 'repository' and 'digest' strings")
        tag = entry.get("tag") or ""
        refs[svc] = f"{entry['repository']}{':' + tag if tag else ''}@{entry['digest']}"
    return build_release(version, refs)


def pinned(entry: dict[str, str]) -> str:
    """`repository:tag@digest`: the tag for people, the digest for Docker."""
    return f"{entry['repository']}:{entry['tag']}@{entry['digest']}"


def render(release: dict) -> dict[str, str]:
    """The three files, by name."""
    lines = [
        f"# OpenSeal {release['version']}: every OpenSeal service pinned to the signed image digest.",
        "# Written by tools/release/pin_release.py (REL-01); verify the digests first (docs/65 §Releases).",
        "#   docker compose -f deploy/compose.production.yml -f compose.release.yml \\",
        "#       --env-file openseal-release.env up -d --wait",
        "services:",
    ]
    for image in sorted(release["images"]):
        for svc in SERVICES[image]:
            lines += [f"  {svc}:", f"    image: {pinned(release['images'][image])}"]
    env = [
        f"# OpenSeal {release['version']} (tools/release/pin_release.py). The production profile requires",
        "# these even though compose.release.yml pins each image by digest.",
        f"OPENSEAL_IMAGE_PREFIX={release['prefix']}",
        f"OPENSEAL_VERSION={release['version']}",
    ]
    return {
        "images.json": json.dumps(release, indent=2, sort_keys=True) + "\n",
        "compose.release.yml": "\n".join(lines) + "\n",
        "openseal-release.env": "\n".join(env) + "\n",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from", dest="from_file", type=Path, help="an images.json to re-pin from")
    src.add_argument("--image", action="append", metavar="SERVICE=REF", help="one per service")
    ap.add_argument("--version", help="the release version, with --image")
    ap.add_argument("--out", type=Path, required=True, help="directory to write into")
    args = ap.parse_args(argv)
    try:
        if args.from_file:
            if args.version:
                raise PinError("--version comes from images.json with --from")
            release = load_release(args.from_file.read_text(encoding="utf-8"))
        else:
            if not args.version:
                raise PinError("--version is required with --image")
            images: dict[str, str] = {}
            for item in args.image:
                svc, sep, ref = item.partition("=")
                if not sep:
                    raise PinError(f"--image {item!r} is not SERVICE=REF")
                if svc in images:
                    raise PinError(f"{svc}: given twice")
                images[svc] = ref
            release = build_release(args.version, images)
        files = render(release)
    except (PinError, OSError) as e:
        print(f"pin_release: {e}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="utf-8")
        print(f"wrote {args.out / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
