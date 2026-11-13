#!/usr/bin/env python3
"""Check that every security claim on the website carries its marking (SITE-05).

    python3 -I tools/check-site-claims.py            # the built site, site/
    python3 -I tools/check-site-claims.py --self-test

A claim block is an element with a `data-claim` attribute, or any item of a `ul.facts`
list (the site's lists of facts about the product). Each must hold exactly one marking,
written by the `{{claim:...}}` placeholder (tools/sitelib.py):

- `data-claim-mark="tested"`: a link to the test or CI workflow that proves it, in the
  repository (an https URL under the repository's blob/main/);
- `data-claim-mark="deployment"`: what the operator configures, as non-empty text.

A `ul.facts` item that is not a claim (a roadmap note) says so with `data-not-claim`.
Exits non-zero naming each claim (page and its first words) that has no marking, two, or
a malformed one. Standard library only; no network.
"""

from __future__ import annotations

import pathlib
import sys
from html.parser import HTMLParser

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
REPO_BLOB = "https://github.com/CasualOffice/openseal/blob/main/"
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr",
        "path", "circle", "line", "rect", "polyline", "polygon", "ellipse"}


class Claims(HTMLParser):
    """Collects claim blocks: their text and the markings inside them."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[dict] = []   # open elements: {tag, claim, facts}
        self.open: list[dict] = []    # open claim blocks
        self.claims: list[dict] = []
        self.mark: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        classes = (a.get("class") or "").split()
        parent_facts = bool(self.stack) and self.stack[-1]["tag"] == "ul" and self.stack[-1]["facts"]
        is_claim = "data-claim" in a or (tag == "li" and parent_facts and "data-not-claim" not in a)
        entry = {"tag": tag, "facts": tag == "ul" and "facts" in classes, "claim": None, "mark": False}
        if is_claim:
            claim = {"text": "", "marks": []}
            self.claims.append(claim)
            self.open.append(claim)
            entry["claim"] = claim
        kind = a.get("data-claim-mark")
        if kind is not None:
            mark = {"kind": kind, "href": a.get("href") or "", "text": "", "tag": tag}
            for c in self.open:
                c["marks"].append(mark)
            if not self.open:
                self.claims.append({"text": "(a marking outside any claim)", "marks": [mark], "stray": True})
            self.mark = mark
            entry["mark"] = True
        if tag not in VOID:
            self.stack.append(entry)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        while self.stack:
            entry = self.stack.pop()
            if entry["claim"] is not None and entry["claim"] in self.open:
                self.open.remove(entry["claim"])
            if entry["mark"]:
                self.mark = None
            if entry["tag"] == tag:
                break

    def handle_data(self, data):
        if self.mark is not None:
            self.mark["text"] += data
        for c in self.open:
            c["text"] += data


def problems_in(rel: str, html: str) -> tuple[int, list[str]]:
    p = Claims()
    p.feed(html)
    out = []
    for c in p.claims:
        words = " ".join(c["text"].split())
        name = f"{rel}: \"{words[:70]}{'…' if len(words) > 70 else ''}\""
        if c.get("stray"):
            out.append(f"{rel}: a claim marking outside any claim block")
            continue
        marks = c["marks"]
        if not marks:
            out.append(f"{name} has no marking: add {{{{claim:tested|WHAT|PATH}}}} or {{{{claim:deployment|WHAT}}}}")
        elif len(marks) > 1:
            out.append(f"{name} has {len(marks)} markings; give it one")
        else:
            m = marks[0]
            text = " ".join(m["text"].split())
            if m["kind"] == "tested":
                if m["tag"] != "a" or not m["href"].startswith(REPO_BLOB) or len(m["href"]) <= len(REPO_BLOB):
                    out.append(f"{name}: a tested marking must link to its test or CI workflow in the repository")
                elif not (ROOT / m["href"][len(REPO_BLOB):]).exists():
                    out.append(f"{name}: its test {m['href'][len(REPO_BLOB):]!r} is not in the repository")
            elif m["kind"] == "deployment":
                if len(text) <= len("Depends on your deployment:"):
                    out.append(f"{name}: a deployment marking must say what the operator configures")
            else:
                out.append(f"{name}: unknown marking {m['kind']!r} (tested or deployment)")
    return len([c for c in p.claims if not c.get("stray")]), out


def self_test() -> int:
    ok = '<a data-claim-mark="tested" href="' + REPO_BLOB + 'tools/check-site-claims.py">Tested: this</a>'
    dep = '<span data-claim-mark="deployment">Depends on your deployment: your HSM</span>'
    cases = [
        (f'<ul class="facts"><li><strong>A</strong>{ok}</li></ul>', 0),
        (f'<ul class="facts"><li><strong>Unmarked claim</strong></li></ul>', 1),
        (f'<ul class="facts"><li data-not-claim="roadmap">Later</li></ul>', 0),
        (f'<p data-claim>Keys {dep}</p>', 0),
        (f'<p data-claim>Two {dep}{ok}</p>', 1),
        ('<p data-claim>Empty <span data-claim-mark="deployment">Depends on your deployment:</span></p>', 1),
        ('<p data-claim>Off-repo <a data-claim-mark="tested" href="https://example.com/t">Tested</a></p>', 1),
        ('<p data-claim>Missing file <a data-claim-mark="tested" href="' + REPO_BLOB + 'no/such/test.rs">Tested</a></p>', 1),
        (f'<table><tr><td data-claim>Cell {ok}</td><td>plain</td></tr></table>', 0),
        (f'<ul class="facts"><li>Img <img src="x.png" alt="">{ok}</li><li>Next unmarked</li></ul>', 1),
    ]
    failed = 0
    for i, (html, want) in enumerate(cases):
        _, got = problems_in(f"case{i}", html)
        if len(got) != want:
            print(f"check-site-claims self-test: case {i} expected {want} problem(s), got {got}", file=sys.stderr)
            failed += 1
    if failed:
        return 1
    print(f"check-site-claims: self-test passed ({len(cases)} cases)")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    pages = sorted(p for p in SITE.rglob("*.html") if "_src" not in p.relative_to(SITE).parts)
    if not pages:
        print("check-site-claims: no pages in site/; run tools/build-site.py", file=sys.stderr)
        return 1
    total, problems = 0, []
    for path in pages:
        n, out = problems_in(str(path.relative_to(SITE)), path.read_text(encoding="utf8"))
        total += n
        problems.extend(out)
    if problems:
        print(f"check-site-claims: {len(problems)} claim(s) without a proper marking", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"check-site-claims: {total} claims on {len(pages)} pages, each marked tested or deployment-dependent")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
