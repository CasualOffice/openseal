#!/usr/bin/env python3
"""Build the website in site/ (SITE-01) from site/_src/, the repository's documents and
api/openapi.yaml. The output is committed; GitHub Pages publishes site/ without _src/.

    python3 tools/build-site.py                      # write every generated page and the search index
    python3 tools/build-site.py --check              # fail, naming the file, if anything is stale
    python3 tools/build-site.py --screens DIR        # turn raw captures (tools/capture-site-screens.mjs)
                                                        # into site/assets/screens/*.webp and *.png (needs Pillow)

Runs tools/build-roadmap.py (docs/06 and docs/14 to roadmap.html) and
tools/build-api-docs.py (api/openapi.yaml to docs/api.html) as part of the build.
Standard library, except Pillow for --screens and PyYAML for the API page (so run it
without -I where PyYAML is a user-site package).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sitelib  # noqa: E402

ROOT = sitelib.ROOT
SITE = sitelib.SITE
SRC = sitelib.SRC


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- Screenshots -----------------------------------------------------------------------

# raw capture name -> (site name, target width, crop height of the raw image or None)
SHOTS = {
    "home": ("home", 1280, None), "agreements": ("agreements", 1280, None), "envelope": ("envelope", 1280, None),
    "editor": ("editor", 1280, None), "templates": ("templates", 1280, None), "admin-api": ("admin-api", 1280, None),
    "verify": ("verify", 1280, None), "sign-desktop": ("sign-desktop", 1280, None),
    "adopt-desktop": ("adopt-desktop", 1280, None), "sign-done": ("sign-done", 1280, None),
    "sign-phone": ("sign-phone", 600, None), "adopt-phone": ("adopt-phone", 600, None),
    "certificate": ("certificate", 900, 1240),
}


def screens(raw: pathlib.Path) -> None:
    try:
        from PIL import Image
    except ImportError:
        raise SystemExit("build-site: --screens needs Pillow (pip install pillow)")
    out = SITE / "assets/screens"
    out.mkdir(parents=True, exist_ok=True)
    for src, (name, width, crop) in SHOTS.items():
        for scheme in ("light", "dark"):
            path = raw / f"{scheme}-{src}.png"
            if not path.exists():
                raise SystemExit(f"build-site: {path} is missing; run tools/capture-site-screens.mjs")
            if src == "certificate" and scheme == "dark":
                continue  # a PDF page looks the same in either theme
            img = Image.open(path).convert("RGB")
            if crop:
                img = img.crop((0, 0, img.width, min(crop, img.height)))
            if img.width > width:
                img = img.resize((width, round(img.height * width / img.width)), Image.LANCZOS)
            img.save(out / f"{name}-{scheme}.webp", "WEBP", quality=80, method=6)
            img.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(
                out / f"{name}-{scheme}.png", optimize=True)
            print(f"build-site: {name}-{scheme} {img.width}x{img.height}")


# ---- Pages --------------------------------------------------------------------------------

def build() -> dict[str, bytes]:
    """Every generated file, relative to site/."""
    files: dict[str, bytes] = {}
    # Assets copied from the repository, so the site matches the product and the brand files.
    files["assets/tokens.css"] = (ROOT / "webapp/tokens.css").read_bytes()
    for name in ("logo.svg", "logo-dark.svg", "mark.svg"):
        files[f"assets/{name}"] = (ROOT / "docs/assets" / name).read_bytes()

    pages: dict[str, str] = {}
    for path in sorted((SRC / "pages").glob("*.html")):
        meta, body = sitelib.read_fragment(path)
        body = sitelib.add_heading_ids(sitelib.expand(body, ""))
        pages[path.name] = sitelib.page(title=meta["title"], description=meta["description"], body=body, root="",
                                        current=meta.get("nav", ""), main_class=meta.get("main", ""))
    for slug, title, _group in sitelib.available_docs():
        if slug == "api":
            continue
        path = SRC / "docs" / f"{slug}.html"
        meta, body = sitelib.read_fragment(path)
        pages[f"docs/{slug}.html"] = sitelib.docs_page(slug, meta.get("title", title), meta["description"],
                                                       sitelib.expand(body, "../"))
    pages["changelog.html"] = changelog()
    pages["roadmap.html"] = _load("build-roadmap").render()
    pages["docs/api.html"] = _load("build-api-docs").render()

    index = []
    for rel, text in sorted(pages.items()):
        files[rel] = text.encode("utf8")
        index.extend(sitelib.index_entries(rel, text))
    files["search-index.json"] = (json.dumps(index, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf8")
    return files


def changelog() -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf8")
    lines = text.splitlines()
    body_md = "\n".join(lines[1:])  # drop the "# Changelog" title; the page has its own
    body = sitelib.markdown(body_md, shift=0)
    body = sitelib.add_heading_ids(body)
    html_ = f"""<section class="page-head"><div class="wrap narrow">
  <h1>Changelog</h1>
  <p class="lede">Every notable change, newest first, from <a href="{sitelib.REPO}/blob/main/CHANGELOG.md">CHANGELOG.md</a>. The format follows Keep a Changelog.</p>
</div></section>
<section class="section-tight"><div class="wrap narrow prose changelog">
{body}
</div></section>"""
    return sitelib.page(title="Changelog", description="What changed in OpenSeal, by date.", body=html_, root="",
                        current="")


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "--screens":
        screens(pathlib.Path(argv[1]))
        return 0
    check = argv == ["--check"]
    if argv and not check:
        print(__doc__, file=sys.stderr)
        return 2
    files = build()
    stale = []
    for rel, data in files.items():
        dest = SITE / rel
        if check:
            if not dest.exists() or dest.read_bytes() != data:
                stale.append(rel)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or dest.read_bytes() != data:
            dest.write_bytes(data)
    if check:
        if stale:
            print("build-site: stale, run python3 tools/build-site.py: " + ", ".join(stale), file=sys.stderr)
            return 1
        print(f"build-site: {len(files)} files up to date")
        return 0
    print(f"build-site: wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
