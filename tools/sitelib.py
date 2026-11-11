"""Shared pieces of the website build (SITE-01): page layout, icons, screenshots, a small
Markdown subset, and the search index. Used by tools/build-site.py,
tools/build-roadmap.py and tools/build-api-docs.py; standard library only.

The site is static files in site/. Hand-written page bodies live in site/_src/ (pages/
and docs/), each starting with a metadata comment:

    <!--meta {"title": "...", "description": "...", "nav": "docs"} -->

and may use these placeholders, expanded here:

    {{root}}                 the relative path to the site root ("" or "../")
    {{icon:NAME}}            a Lucide icon, 20 px, decorative ({{icon:NAME:24}} for a size)
    {{shot:NAME|ALT}}        a product screenshot, light and dark, lazy-loaded
    {{shot:NAME|ALT|eager}}  the same, loaded at once (above the fold)

The header and footer shape follows OpenCalc's webapp/docs.html at b23c67c (brand,
nav links, primary action, a <details> menu on phones); see PROVENANCE.md.
"""

from __future__ import annotations

import html
import json
import pathlib
import re
import struct
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SRC = SITE / "_src"
REPO = "https://github.com/CasualOffice/openseal"

# ---- Icons -------------------------------------------------------------------------

_ICONS: dict[str, str] | None = None
_SVG_NS = "{http://www.w3.org/2000/svg}"


def _load_icons() -> dict[str, str]:
    """The inner markup of every vendored Lucide icon: the app's set plus the site's."""
    out: dict[str, str] = {}
    for folder in (ROOT / "webapp/vendor/lucide/icons", SRC / "lucide"):
        for path in sorted(folder.glob("*.svg")):
            text = re.sub(r"<!--.*?-->", "", path.read_text(encoding="utf8"), flags=re.S)
            root = ET.fromstring(text)
            parts = []
            for child in root:
                tag = child.tag.replace(_SVG_NS, "")
                attrs = " ".join(f'{k}="{html.escape(v, quote=True)}"' for k, v in child.attrib.items())
                parts.append(f"<{tag} {attrs}/>")
            out[path.stem] = "".join(parts)
    return out


def icon(name: str, size: int = 20, cls: str = "") -> str:
    """A decorative Lucide icon as inline SVG (stroke 2, or 1.75 at 24 px and above, as webapp/icons.js)."""
    global _ICONS
    if _ICONS is None:
        _ICONS = _load_icons()
    if name not in _ICONS:
        raise SystemExit(f"site: icon {name!r} is not vendored (webapp/vendor/lucide/icons or site/_src/lucide)")
    stroke = "1.75" if size >= 24 else "2"
    klass = f"i {cls}".strip()
    return (f'<svg class="{klass}" viewBox="0 0 24 24" width="{size}" height="{size}" fill="none" stroke="currentColor" '
            f'stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
            f"{_ICONS[name]}</svg>")


# ---- Screenshots ---------------------------------------------------------------------

SCREENS = SITE / "assets/screens"


def png_size(path: pathlib.Path) -> tuple[int, int]:
    """Width and height from a PNG's IHDR chunk."""
    with path.open("rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"site: {path} is not a PNG")
    return struct.unpack(">II", head[16:24])


def shot(name: str, alt: str, root: str, eager: bool = False) -> str:
    """A screenshot in both themes. The theme not shown is display:none, so a lazy image
    for it is never fetched; each has WebP with a PNG fallback and its size set."""
    loading = "eager" if eager else "lazy"
    parts = []
    themed = (SCREENS / f"{name}-dark.png").exists()
    for scheme in ("light", "dark") if themed else ("light",):
        png = SCREENS / f"{name}-{scheme}.png"
        if not png.exists():
            raise SystemExit(f"site: screenshot {png.relative_to(ROOT)} is missing; run tools/build-site.py --screens")
        w, h = png_size(png)
        cls = f"shot__{scheme}" if themed else "shot__any"
        parts.append(
            f'<picture class="{cls}"><source type="image/webp" srcset="{root}assets/screens/{name}-{scheme}.webp">'
            f'<img src="{root}assets/screens/{name}-{scheme}.png" width="{w}" height="{h}" alt="{html.escape(alt)}" '
            f'loading="{loading}" decoding="async"></picture>')
    return f'<span class="shot">{"".join(parts)}</span>'


# ---- Navigation ----------------------------------------------------------------------

NAV = [
    ("features", "Features", "index.html#features"),
    ("docs", "Docs", "docs/index.html"),
    ("api", "API", "docs/api.html"),
    ("roadmap", "Roadmap", "roadmap.html"),
    ("download", "Download", "download.html"),
]

# The documentation, in reading order: (slug, title, group).
DOCS = [
    ("index", "Documentation", "Start"),
    ("getting-started", "Getting started", "Start"),
    ("first-envelope", "Sending your first envelope", "Use"),
    ("signing", "Signing", "Use"),
    ("templates", "Templates", "Use"),
    ("verifying", "Verifying a document", "Use"),
    ("administration", "Administration", "Operate"),
    ("self-hosting", "Self-hosting and configuration", "Operate"),
    ("api", "API reference", "Build"),
    ("webhooks", "Webhooks", "Build"),
    ("security", "Security and evidence model", "Understand"),
    ("architecture", "Architecture overview", "Understand"),
    ("faq", "FAQ", "Understand"),
    ("contributing", "Contributing", "Project"),
]

def available_docs() -> list[tuple[str, str, str]]:
    """DOCS entries that have a source page (the API reference is generated)."""
    return [d for d in DOCS if d[0] == "api" or (SRC / "docs" / f"{d[0]}.html").exists()]


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'")


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def header(root: str, current: str) -> str:
    links = []
    for key, label, href in NAV:
        cur = ' aria-current="page"' if key == current else ""
        links.append(f'<a href="{root}{href}"{cur}>{label}</a>')
    nav = "".join(links)
    gh = f'<a href="{REPO}" class="nav-gh">GitHub{icon("arrow-up-right", 16)}</a>'
    return f"""<header class="site-header">
  <div class="wrap header-row">
    <a class="brand" href="{root}index.html" aria-label="OpenSeal home">
      <img class="logo-light" src="{root}assets/logo.svg" alt="" width="128" height="25" loading="lazy">
      <img class="logo-dark" src="{root}assets/logo-dark.svg" alt="" width="128" height="25" loading="lazy">
    </a>
    <nav class="nav-links" aria-label="Main">{nav}{gh}</nav>
    <div class="header-actions">
      <button type="button" class="icon-btn search-open" aria-label="Search the site" aria-keyshortcuts="/">{icon("search")}<span class="kbd" aria-hidden="true">/</span></button>
      <button type="button" class="icon-btn theme-toggle" aria-label="Use the dark theme">{icon("moon", cls="when-light")}{icon("sun", cls="when-dark")}</button>
      <a class="btn btn-primary btn-sm header-cta" href="{root}docs/getting-started.html">Get started</a>
      <details class="menu">
        <summary aria-label="Menu">{icon("menu", cls="when-closed")}{icon("x", cls="when-open")}</summary>
        <nav class="menu-panel" aria-label="Main (mobile)">{nav}{gh}<a href="{root}docs/getting-started.html">Get started</a></nav>
      </details>
    </div>
  </div>
</header>"""


def footer(root: str) -> str:
    def col(title: str, items: list[tuple[str, str]]) -> str:
        lis = "".join(f'<li><a href="{h if h.startswith("http") else root + h}">{t}</a></li>' for t, h in items)
        return f'<div class="foot-col"><h2>{title}</h2><ul>{lis}</ul></div>'
    return f"""<footer class="site-footer">
  <div class="wrap foot-grid">
    <div class="foot-brand">
      <img class="logo-light" src="{root}assets/logo.svg" alt="OpenSeal" width="128" height="25" loading="lazy">
      <img class="logo-dark" src="{root}assets/logo-dark.svg" alt="OpenSeal" width="128" height="25" loading="lazy">
      <p>Open-source electronic signatures under <span class="nowrap">Apache-2.0</span>. Part of <a href="https://github.com/CasualOffice">CasualOffice</a>.</p>
      <p class="foot-legal">Designed to support e-signature laws such as ESIGN, UETA and eIDAS. Nothing here is legal advice.</p>
    </div>
    {col("Product", [("Features", "index.html#features"), ("Roadmap", "roadmap.html"), ("Download and deploy", "download.html"), ("Changelog", "changelog.html")])}
    {col("Documentation", [("Getting started", "docs/getting-started.html"), ("API reference", "docs/api.html"), ("Webhooks", "docs/webhooks.html"), ("Security and evidence", "docs/security.html")])}
    {col("Project", [("GitHub", REPO), ("Security policy", "security.html"), ("Brand and attribution", "brand.html"), ("Contributing", "docs/contributing.html")])}
  </div>
  <div class="wrap foot-base"><p>Apache License 2.0. "Powered by OpenSeal" is welcome and never required.</p></div>
</footer>"""


SEARCH_DIALOG = """<dialog class="search-dialog" aria-label="Search the site">
  <form method="dialog" class="search-form" role="search">
    <label class="sr-only" for="search-q">Search</label>
    {icon}
    <input id="search-q" class="search-input" type="search" placeholder="Search docs and pages" autocomplete="off" spellcheck="false">
    <button type="submit" class="icon-btn search-close" aria-label="Close search">{x}</button>
  </form>
  <p class="search-status" role="status" aria-live="polite"></p>
  <ul class="search-results"></ul>
</dialog>"""


def page(*, title: str, description: str, body: str, root: str, current: str = "", main_class: str = "") -> str:
    """A whole page around `body` (the contents of <main>)."""
    full_title = "OpenSeal: open-source e-signatures" if title == "OpenSeal" else f"{title} | OpenSeal"
    search = SEARCH_DIALOG.format(icon=icon("search", cls="search-icon"), x=icon("x"))
    mc = f' class="{main_class}"' if main_class else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<title>{_esc(full_title)}</title>
<meta name="description" content="{_esc(description)}">
<meta name="theme-color" content="#b3141f">
<meta property="og:title" content="{_esc(full_title)}">
<meta property="og:description" content="{_esc(description)}">
<link rel="icon" href="{root}assets/mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="{root}assets/tokens.css">
<link rel="stylesheet" href="{root}assets/site.css">
<script src="{root}assets/theme-init.js"></script>
<script type="module" src="{root}assets/site.js"></script>
</head>
<body data-root="{root}">
<a class="skip" href="#main">Skip to content</a>
{header(root, current)}
<main id="main" tabindex="-1"{mc}>
{body}
</main>
{footer(root)}
{search}
</body>
</html>
"""


# ---- Fragments -----------------------------------------------------------------------

META = re.compile(r"^\s*<!--meta\s+(\{.*?\})\s*-->\s*", re.S)


def read_fragment(path: pathlib.Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf8")
    m = META.match(text)
    if not m:
        raise SystemExit(f"site: {path.relative_to(ROOT)} has no <!--meta {{...}} --> header")
    return json.loads(m.group(1)), text[m.end():]


def expand(text: str, root: str) -> str:
    """Expand {{root}}, {{icon:...}} and {{shot:...}}."""
    def sub(m: re.Match) -> str:
        kind, _, arg = m.group(1).partition(":")
        if kind == "root":
            return root
        if kind == "icon":
            name, _, size = arg.partition(":")
            return icon(name, int(size) if size else 20)
        if kind == "shot":
            bits = arg.split("|")
            return shot(bits[0], bits[1] if len(bits) > 1 else "", root, eager=len(bits) > 2 and bits[2] == "eager")
        raise SystemExit(f"site: unknown placeholder {{{{{m.group(1)}}}}}")
    return re.sub(r"\{\{([a-z]+(?::[^}]*)?)\}\}", sub, text)


def slugify(text: str) -> str:
    s = re.sub(r"<[^>]+>", "", text)
    s = html.unescape(s).lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "section"


def add_heading_ids(body: str) -> str:
    """Give every h2 and h3 without an id one made from its text (unique in the page)."""
    seen: set[str] = set(re.findall(r'\bid="([^"]+)"', body))

    def sub(m: re.Match) -> str:
        tag, attrs, inner = m.group(1), m.group(2), m.group(3)
        if "id=" in attrs:
            return m.group(0)
        base = slugify(inner)
        sid, n = base, 2
        while sid in seen:
            sid, n = f"{base}-{n}", n + 1
        seen.add(sid)
        return f'<{tag}{attrs} id="{sid}">{inner}</{tag}>'
    return re.sub(r"<(h[23])([^>]*)>(.*?)</\1>", sub, body, flags=re.S)


def docs_page(slug: str, title: str, description: str, article: str) -> str:
    """A documentation page: left nav, the article, on-this-page links, previous and next."""
    root = "../"
    article = add_heading_ids(article)
    docs = available_docs()
    groups: dict[str, list[str]] = {}
    for s, t, g in docs:
        cur = ' aria-current="page"' if s == slug else ""
        groups.setdefault(g, []).append(f'<li><a href="{s}.html"{cur}>{_esc(t)}</a></li>')
    side = "".join(f'<h2>{g}</h2><ul>{"".join(items)}</ul>' for g, items in groups.items())
    toc_items = re.findall(r'<h2[^>]*id="([^"]+)"[^>]*>(.*?)</h2>', article, flags=re.S)
    toc = ""
    if len(toc_items) >= 2:
        lis = "".join(f'<li><a href="#{i}">{re.sub(r"<[^>]+>", "", t)}</a></li>' for i, t in toc_items)
        toc = f'<nav class="toc" aria-label="On this page"><h2>On this page</h2><ul>{lis}</ul></nav>'
    order = [s for s, _, _ in docs]
    i = order.index(slug)
    pn = []
    if i > 0:
        ps, pt, _ = docs[i - 1]
        pn.append(f'<a class="pn pn-prev" href="{ps}.html"><span class="pn-dir">{icon("chevron-left", 16)}Previous</span><span class="pn-title">{_esc(pt)}</span></a>')
    if i + 1 < len(docs):
        ns, nt, _ = docs[i + 1]
        pn.append(f'<a class="pn pn-next" href="{ns}.html"><span class="pn-dir">Next{icon("chevron-right", 16)}</span><span class="pn-title">{_esc(nt)}</span></a>')
    body = f"""<div class="wrap docs-layout">
  <aside class="docs-side">
    <details class="docs-nav-toggle"><summary>{icon("list-tree", 16)}Documentation menu</summary><nav class="docs-nav" aria-label="Documentation (menu)">{side}</nav></details>
    <nav class="docs-nav docs-nav--wide" aria-label="Documentation">{side}</nav>
  </aside>
  <article class="docs-article prose">
{article}
    <nav class="prevnext" aria-label="Previous and next">{"".join(pn)}</nav>
  </article>
  {toc}
</div>"""
    current = "api" if slug == "api" else "docs"
    return page(title=title, description=description, body=body, root=root, current=current, main_class="docs-main")


# ---- Markdown (the subset CHANGELOG.md uses) -----------------------------------------

def md_inline(s: str, link_base: str = REPO + "/blob/main/") -> str:
    out = []
    pos = 0
    for m in re.finditer(r"`([^`]+)`", s):
        out.append(_md_text(s[pos:m.start()], link_base))
        out.append(f"<code>{html.escape(m.group(1))}</code>")
        pos = m.end()
    out.append(_md_text(s[pos:], link_base))
    return "".join(out)


def _md_text(s: str, link_base: str) -> str:
    s = html.escape(s, quote=False)

    def link(m: re.Match) -> str:
        text, href = m.group(1), m.group(2)
        if not re.match(r"[a-z]+:", href) and not href.startswith("#"):
            href = link_base + href
        return f'<a href="{html.escape(href, quote=True)}">{text}</a>'
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    return s


def markdown(text: str, shift: int = 0, link_base: str = REPO + "/blob/main/") -> str:
    """Headings, paragraphs, '-' lists (with continuation lines), fenced code."""
    out: list[str] = []
    para: list[str] = []
    items: list[str] = []
    lines = text.splitlines()
    i = 0

    def flush() -> None:
        if para:
            out.append(f"<p>{md_inline(' '.join(para), link_base)}</p>")
            para.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{md_inline(x, link_base)}</li>" for x in items) + "</ul>")
            items.clear()
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            j = i + 1
            code = []
            while j < len(lines) and not lines[j].startswith("```"):
                code.append(lines[j])
                j += 1
            out.append(f"<pre><code>{html.escape(chr(10).join(code))}</code></pre>")
            i = j + 1
            continue
        m = re.match(r"(#{1,6})\s+(.*)", line)
        if m:
            flush()
            level = min(6, len(m.group(1)) + shift)
            out.append(f"<h{level}>{md_inline(m.group(2), link_base)}</h{level}>")
        elif line.startswith("- "):
            if para:
                flush()
            items.append(line[2:].strip())
        elif line.startswith("  ") and items:
            items[-1] += " " + line.strip()
        elif not line.strip():
            flush()
        else:
            if items:
                flush()
            para.append(line.strip())
        i += 1
    flush()
    return "\n".join(out)


# ---- Search index --------------------------------------------------------------------

class _Text(HTMLParser):
    """Sections of <main>: (heading id, heading text, body text)."""

    SKIP = {"script", "style", "svg", "nav", "aside", "dialog"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_main = 0
        self.skip = 0
        self.sections: list[list[str]] = [["", "", ""]]
        self.head: str | None = None
        self.head_id = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "main":
            self.in_main += 1
        if not self.in_main:
            return
        if tag in self.SKIP:
            self.skip += 1
        elif tag in ("h1", "h2", "h3") and not self.skip:
            self.head = ""
            self.head_id = a.get("id", "") or ""

    def handle_endtag(self, tag):
        if tag == "main":
            self.in_main -= 1
        if not self.in_main:
            return
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in ("h1", "h2", "h3") and self.head is not None:
            self.sections.append([self.head_id, self.head.strip(), ""])
            self.head = None

    def handle_data(self, data):
        if not self.in_main or self.skip:
            return
        if self.head is not None:
            self.head += data
        else:
            self.sections[-1][2] += " " + data


def index_entries(rel: str, page_html: str) -> list[dict]:
    """Search entries for one page: one per heading, with up to 600 characters of text."""
    p = _Text()
    p.feed(page_html)
    title = re.search(r"<title>(.*?)</title>", page_html, re.S)
    page_title = html.unescape(title.group(1)).replace(" | OpenSeal", "") if title else rel
    out = []
    for sid, head, text in p.sections:
        text = re.sub(r"\s+", " ", text).strip()
        if not head and not text:
            continue
        out.append({"u": rel + (f"#{sid}" if sid else ""), "p": page_title, "h": head or page_title, "t": text[:600]})
    return out
