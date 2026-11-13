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

# raw capture name -> (target width of the WebP, crop height of the raw image or None).
# tools/capture-site-screens.mjs captures at device scale 2 (2880 px for a 1440 px
# window, 780 px for a 390 px phone); the WebP keeps enough of that to stay sharp on a
# high-density screen, and the PNG fallback (for browsers without WebP) is smaller.
SHOTS = {
    # Ready on the approved design (WEB-17, WEB-18, CON-17).
    "signin": (2000, None), "home": (2000, None), "palette": (2000, None), "verify": (2000, None),
    "sign-desktop": (2000, None), "adopt-desktop": (2000, None), "sign-done": (2000, None),
    "sign-phone": (780, None), "adopt-phone": (780, None), "console": (2000, None),
    "certificate": (900, 1240),
    # Written once the rebuilt screens merge (the pages show the current image until then).
    "agreements": (2000, None), "envelope": (2000, None), "editor": (2000, None), "templates": (2000, None),
    "admin-api": (2000, None), "admin-intelligence": (2000, None),
}
PNG_MAX = 1280


def screens(raw: pathlib.Path) -> None:
    """Convert every raw capture present in `raw`; a screen not captured keeps its files."""
    try:
        from PIL import Image
    except ImportError:
        raise SystemExit("build-site: --screens needs Pillow (pip install pillow)")
    out = SITE / "assets/screens"
    out.mkdir(parents=True, exist_ok=True)
    done = 0
    for name, (width, crop) in SHOTS.items():
        for scheme in ("light", "dark"):
            path = raw / f"{scheme}-{name}.png"
            if not path.exists() or (name == "certificate" and scheme == "dark"):
                continue  # not captured this run; a PDF page looks the same in either theme
            img = Image.open(path).convert("RGB")
            light = raw / f"light-{name}.png"
            if scheme == "dark" and light.exists() and Image.open(light).convert("RGB").tobytes() == img.tobytes():
                # A screen with one theme (the console): ship one image for both.
                for ext in ("webp", "png"):
                    (out / f"{name}-dark.{ext}").unlink(missing_ok=True)
                continue
            if crop:
                img = img.crop((0, 0, img.width, min(crop, img.height)))
            if img.width > width:
                img = img.resize((width, round(img.height * width / img.width)), Image.LANCZOS)
            img.save(out / f"{name}-{scheme}.webp", "WEBP", quality=82, method=6)
            small = img
            if img.width > PNG_MAX:
                small = img.resize((PNG_MAX, round(img.height * PNG_MAX / img.width)), Image.LANCZOS)
            small.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(
                out / f"{name}-{scheme}.png", optimize=True)
            done += 1
            print(f"build-site: {name}-{scheme} {img.width}x{img.height}")
    if not done:
        raise SystemExit(f"build-site: no captures in {raw}; run tools/capture-site-screens.mjs first")


# ---- Pages --------------------------------------------------------------------------------

def build() -> dict[str, bytes]:
    """Every generated file, relative to site/."""
    files: dict[str, bytes] = {}
    # Assets copied from the repository, so the site matches the product and the brand files.
    files["assets/tokens.css"] = (ROOT / "webapp/tokens.css").read_bytes()
    # tokens.css loads the UI font from fonts/ui/ relative to itself (UX-02), so the site ships it too.
    for font in sorted((ROOT / "webapp/fonts/ui").iterdir()):
        files[f"assets/fonts/ui/{font.name}"] = font.read_bytes()
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
                        current="changelog")


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
