#!/usr/bin/env python3
"""Check every internal link of the website in site/ (SITE-01).

    python3 -I tools/check-site-links.py

For each HTML page (site/_src/ excluded, as GitHub Pages does not publish it), every
href, src and srcset that is not an external URL must name a file that exists, and a
#fragment must name an id on the target page. Also refuses a page with two elements of
one id. External links (http:, https:, mailto:) are counted, not fetched: no network.
Standard library only; exits non-zero, naming each broken link and its page.
"""

from __future__ import annotations

import pathlib
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

SITE = pathlib.Path(__file__).resolve().parent.parent / "site"


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.ids: list[str] = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if v is None:
                continue
            if k == "id":
                self.ids.append(v)
            elif k in ("href", "src") or (k == "xlink:href"):
                self.links.append(v)
            elif k == "srcset":
                self.links.extend(part.strip().split(" ")[0] for part in v.split(",") if part.strip())


def pages() -> list[pathlib.Path]:
    return sorted(p for p in SITE.rglob("*.html") if "_src" not in p.relative_to(SITE).parts)


def main() -> int:
    if not SITE.is_dir():
        print("check-site-links: site/ does not exist", file=sys.stderr)
        return 1
    parsed: dict[pathlib.Path, Page] = {}
    for path in pages():
        p = Page()
        p.feed(path.read_text(encoding="utf8"))
        parsed[path.resolve()] = p
    problems: list[str] = []
    internal = external = 0
    for path, p in parsed.items():
        rel = path.relative_to(SITE.resolve())
        seen: set[str] = set()
        for i in p.ids:
            if i in seen:
                problems.append(f"{rel}: id {i!r} used twice")
            seen.add(i)
        for link in p.links:
            parts = urlsplit(link)
            if parts.scheme in ("http", "https", "mailto"):
                external += 1
                continue
            if parts.scheme or link.startswith("//"):
                problems.append(f"{rel}: unexpected link {link!r}")
                continue
            internal += 1
            target = path if not parts.path else (path.parent / unquote(parts.path)).resolve()
            if parts.path.endswith("/") or (target.is_dir()):
                target = target / "index.html"
            try:
                target.relative_to(SITE.resolve())
            except ValueError:
                problems.append(f"{rel}: {link!r} leaves site/")
                continue
            if "_src" in target.relative_to(SITE.resolve()).parts:
                problems.append(f"{rel}: {link!r} points into site/_src, which is not published")
                continue
            if not target.exists():
                problems.append(f"{rel}: broken link {link!r}")
                continue
            if parts.fragment and target.suffix == ".html":
                ids = parsed[target].ids if target in parsed else []
                if unquote(parts.fragment) not in ids:
                    problems.append(f"{rel}: {link!r}: no id {parts.fragment!r} on {target.relative_to(SITE.resolve())}")
    if problems:
        print(f"check-site-links: {len(problems)} problem(s)", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"check-site-links: {len(parsed)} pages, {internal} internal links resolve, {external} external links not fetched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
