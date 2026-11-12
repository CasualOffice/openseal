#!/usr/bin/env python3
"""Build the website's roadmap page, site/roadmap.html (SITE-01), from the only roadmap
(docs/06) and the only tracker (docs/14), so the page cannot drift from them.

    python3 -I tools/build-roadmap.py           # write site/roadmap.html
    python3 -I tools/build-roadmap.py --check   # fail if it is stale

What it reads:
  docs/06  each phase's "Closes when" boxes and its "closed" sign-off; the Release 1
           scope ("In:" and "Work order:"); the slice table (outcomes); release gates.
  docs/14  Phase 2 stages (T-2*), the web app rows (WEB-*), the slices (VS-*), the
           milestones (MS-*: which slices come next and which later), release gates.

No dates are printed: docs/06 sets none ("No calendar dates"). Standard library only;
fails non-zero, naming what it could not find.
"""

from __future__ import annotations

import html
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sitelib  # noqa: E402
from tracker_rows import cells, rows  # noqa: E402

ROOT = sitelib.ROOT
ROADMAP = ROOT / "docs/06-ROADMAP-AND-DELIVERY.md"
TRACKER = ROOT / "docs/14-EXECUTION-TRACKER.md"
OUT = sitelib.SITE / "roadmap.html"
ISSUES = sitelib.REPO + "/issues"

# The owner's themes for the Next and Later columns, and where each slice belongs.
THEMES = [
    ("security", "SSO and security", "lock-keyhole"),
    ("signing", "Signing features", "signature"),
    ("templates", "Templates and bulk", "layout-template"),
    ("api", "Integrations and API", "plug"),
    ("enterprise", "Enterprise and compliance", "building"),
    ("archive", "Archive and qualified signatures", "stamp"),
    ("apps", "Apps and add-on modules", "monitor-smartphone"),
]
SLICE_THEME = {
    1: "signing", 2: "signing", 3: "templates", 4: "signing", 5: "security", 6: "signing", 7: "archive",
    8: "api", 9: "api", 10: "security", 11: "templates", 12: "enterprise", 13: "api", 14: "signing",
    15: "enterprise", 16: "archive", 17: "archive", 18: "archive", 19: "enterprise", 20: "enterprise",
    21: "apps", 22: "api", 23: "apps", 24: "api", 25: "api", 26: "signing", 27: "templates", 28: "templates",
    29: "signing", 30: "apps", 31: "enterprise", 32: "apps", 33: "apps", 34: "apps", 35: "apps",
}
NEXT_MILESTONES = {"MS-3", "MS-4", "MS-5"}  # first signature, team beta, 1.0 GA
LATER_MILESTONES = {"MS-6", "MS-7", "MS-8"}
# Work after v0.0.1 shown under "Coming next" (owner instruction 36), with its status
# read from docs/14. The labels are short public names for each row.
NOW_ROWS = [
    ("UX-01", "Enterprise UI and layout pass, in packages UX-02 to UX-08"),
    ("ORG-01", "Organizations above workspaces, with organization, workspace and delegated admins"),
    ("CON-01", "Platform console for the operator: organizations, plans, keys and certificates, health"),
    ("PLAN-01", "Plans: entitlements, quotas, usage metering and export"),
    ("ML-09", "casual-sign-modeld, the separate process that hosts pretrained models"),
    ("ML-02", "Text from scanned and image-only pages (OCR)"),
    ("ML-05", "Template matching on upload"),
    ("ML-07", "Agreement extraction: parties, dates, amounts"),
    ("ML-08", "Personal-data detection with validated recognisers"),
]


def fail(msg: str) -> None:
    raise SystemExit(f"build-roadmap: {msg}")


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def plain(md: str) -> str:
    """Markdown cell text to plain text: links to their words, no emphasis or code marks."""
    s = re.sub(r"\[(\d\d)\]\([^)]+\)", r"docs/\1", md)  # [07](07-...md) names a document
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = s.replace("**", "").replace("`", "")
    return s.strip()


def first_sentence(s: str, limit: int = 160, seps: str = ".;:") -> str:
    s = plain(s)
    m = re.match(rf"(.+?[{re.escape(seps)}])(\s|$)", s)
    s = m.group(1).rstrip(";:") if m else s
    return s if len(s) <= limit else s[: limit - 1].rsplit(" ", 1)[0] + "…"


# ---- docs/06 ------------------------------------------------------------------------------

def sections(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"^## (.+?)\n(.*?)(?=^## |\Z)", text, flags=re.M | re.S):
        out[m.group(1).strip()] = m.group(2)
    return out


def phase(secs: dict[str, str], prefix: str) -> dict:
    key = next((k for k in secs if k.startswith(prefix)), None)
    if not key:
        fail(f"docs/06 has no section starting {prefix!r}")
    body = secs[key]
    done = len(re.findall(r"^\s*- \[x\]", body, flags=re.M))
    todo = [plain(x) for x in re.findall(r"^\s*- \[ \] (.+)$", body, flags=re.M)]
    gives = re.search(r"\*\*Gives:\*\*\s*(.+?)(?:\n- |\n\n)", body, flags=re.S)
    closed = re.search(r"\*\*Phase [\w ]+ closed", body) is not None
    title = key.split("—", 1)[1].strip() if "—" in key else key
    g = plain(gives.group(1).replace("\n", " ")) if gives else ""
    return {"name": key.split("—")[0].strip(), "title": title, "done": done, "todo": todo, "closed": closed,
            "gives": g[:1].upper() + g[1:]}


def release1(secs: dict[str, str]) -> dict:
    key = next((k for k in secs if k.startswith("Release 1")), None)
    if not key:
        fail("docs/06 has no Release 1 section")
    # Only the section's own text: its "### Release 1 ships as v0.0.1" subsection (the
    # gate's boxes) would otherwise run into the last field read to the end.
    own = secs[key].split("\n### ", 1)[0]
    intro = own.strip().split("\n\n")[0].replace("\n", " ")
    body = re.sub(r"\n\s+", " ", own)
    m_in = re.search(r"\*\*In:\*\*\s*(.+?)(?=\n- \*\*|\Z)", body, flags=re.S)
    m_after = re.search(r"\*\*After Release 1, in slice order:\*\*\s*(.+?)(?=\n- \*\*|\Z)", body, flags=re.S)
    m_order = re.search(r"\*\*Work order:\*\*\s*(.+?)(?=\n- \*\*|\Z)", body, flags=re.S)
    if not (m_in and m_after and m_order):
        fail("docs/06 Release 1 lacks In:, After Release 1 or Work order:")
    items = [plain(x).rstrip(".") for x in re.split(r";\s*", m_in.group(1).strip())]
    items = [x[0].upper() + x[1:] for x in items if x]
    # Published once docs/06 "Where things stand" says so in its Release 1 row.
    stand = next((v for k, v in secs.items() if k.startswith("Where things stand")), "")
    m_pub = re.search(r"^\| Release 1 / (v[\d.]+) \| \*\*Published\*\*", stand, flags=re.M)
    return {"intro": plain(intro), "items": items, "order": plain(m_order.group(1)).strip(),
            "version": m_pub.group(1) if m_pub else None}


def slice_outcomes(text: str) -> dict[int, tuple[str, str]]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\|\s*(\d+)\s*\|", line)
        if m:
            c = cells(line)
            out[int(c[0])] = (plain(c[1]), plain(c[2]))
    if len(out) < 30:
        fail(f"docs/06 slice table: found {len(out)} slices")
    return out


# ---- docs/14 -------------------------------------------------------------------------------

def tracker() -> dict[str, list[str]]:
    out = {}
    for _n, rid, line in rows(TRACKER.read_text(encoding="utf8")):
        out[rid] = cells(line)
    return out


def milestone_slices(rows_: dict[str, list[str]], ids: set[str]) -> set[int]:
    nums: set[int] = set()
    for mid in ids:
        if mid not in rows_:
            fail(f"docs/14 has no row {mid}")
        contains = rows_[mid][3]
        for a, b in re.findall(r"VS-(\d+)(?:\s+to\s+VS-(\d+))?", contains):
            lo, hi = int(a), int(b or a)
            nums.update(range(lo, hi + 1))
    return nums


# ---- Render ---------------------------------------------------------------------------------

def pill(kind: str, label: str) -> str:
    ic = {"done": "circle-check", "progress": "loader-circle", "next": "circle-dot", "later": "circle-dashed", "blocked": "circle-alert"}[kind]
    k = "next" if kind == "blocked" else kind
    return f'<span class="pill pill-{k}">{sitelib.icon(ic, 14)}{esc(label)}</span>'


def render() -> str:
    text06 = ROADMAP.read_text(encoding="utf8")
    secs = sections(text06)
    t = tracker()
    phases = [phase(secs, p) for p in ("Phase D", "Phase 0", "Phase 1", "Phase 2")]
    r1 = release1(secs)
    outcomes = slice_outcomes(text06)

    # Phase 2 stages and the web app, from docs/14.
    stages = [(rid, c) for rid, c in t.items() if re.fullmatch(r"T-2[A-F]", rid)]
    if len(stages) != 6:
        fail(f"docs/14: expected stages T-2A to T-2F, found {len(stages)}")
    web = [(rid, c) for rid, c in t.items() if re.fullmatch(r"WEB-\d+", rid)]
    web.sort(key=lambda x: int(x[0].split("-")[1]))
    if not web:
        fail("docs/14 has no WEB-* rows")

    tl = []
    for ph in phases[:3]:
        state = "done" if ph["closed"] else "progress"
        label = "Closed" if ph["closed"] else "In progress"
        tl.append(f"""<li class="tl-{state}"><span class="tl-dot">{sitelib.icon("check" if ph["closed"] else "loader-circle", 20)}</span>
<div class="tl-body"><div class="tl-title"><h3>{esc(ph["name"])}: {esc(ph["title"])}</h3>{pill(state, label)}</div>
<p>{esc(ph["gives"])} {ph["done"]} of {ph["done"] + len(ph["todo"])} exit criteria met.</p></div></li>""")

    p2 = phases[3]
    stage_items = "".join(
        f'<li>{sitelib.icon("circle-check" if c[2] == "Done" else "circle-dot", 16, "ok" if c[2] == "Done" else "wip")}<span><b>{esc(rid[2:])}</b> {esc(plain(c[1]))}</span></li>'
        for rid, c in stages)
    left = "".join(f'<li>{sitelib.icon("circle-dashed", 16, "todo")}<span>{esc(first_sentence(x, 220, "."))}</span></li>' for x in p2["todo"])
    p2_state = "done" if p2["closed"] else "progress"
    built = sum(1 for _r, c in stages if c[2] == "Done")
    tl.append(f"""<li class="tl-{p2_state}"><span class="tl-dot">{sitelib.icon("check" if p2["closed"] else "loader-circle", 20)}</span>
<div class="tl-body"><div class="tl-title"><h3>{esc(p2["name"])}: {esc(p2["title"])}</h3>{pill(p2_state, "Closed" if p2["closed"] else "In progress")}</div>
<p>{esc(p2["gives"])} {built} of {len(stages)} stages built; {p2["done"]} of {p2["done"] + len(p2["todo"])} exit criteria met.</p>
<ul class="tl-items">{stage_items}</ul>
{f'<p>Left to close the phase:</p><ul class="tl-items">{left}</ul>' if left else ""}</div></li>""")

    web_done = [(r, c) for r, c in web if c[2] == "Done"]
    web_open = [(r, c) for r, c in web if c[2] != "Done"]
    web_items = "".join(
        f'<li>{sitelib.icon("circle-check" if c[2] == "Done" else "circle-dot", 16, "ok" if c[2] == "Done" else "wip")}<span><b>{esc(r)}</b> {esc(first_sentence(c[1], 120, ";."))}</span></li>'
        for r, c in web_done + web_open)
    tl.append(f"""<li class="tl-progress"><span class="tl-dot">{sitelib.icon("monitor", 20)}</span>
<div class="tl-body"><div class="tl-title"><h3>Web app for senders and signers</h3>{pill("progress", "In progress")}</div>
<p>{len(web_done)} of {len(web)} web app rows done; the rest were found while building it.</p>
<ul class="tl-items">{web_items}</ul></div></li>""")
    if r1["version"]:
        tl.append(f"""<li class="tl-done"><span class="tl-dot">{sitelib.icon("rocket", 20)}</span>
<div class="tl-body"><div class="tl-title"><h3>Release 1</h3>{pill("done", r1["version"] + " published")}</div>
<p>The common send-and-sign case, end to end on one machine, published as the {esc(r1["version"])} pre-release for evaluation, not yet for production agreements. <a href="{sitelib.REPO}/releases/tag/{esc(r1["version"])}">Release notes</a>.</p></div></li>""")
    else:
        tl.append(f"""<li><span class="tl-dot">{sitelib.icon("rocket", 20)}</span>
<div class="tl-body"><div class="tl-title"><h3>Release 1</h3>{pill("next", "Next")}</div>
<p>{esc(r1["order"])}</p></div></li>""")

    # Work running now beside the slices, each with its tracker row's status.
    now_items = []
    for rid, label in NOW_ROWS:
        if rid not in t:
            fail(f"docs/14 has no row {rid}")
        st = t[rid][2]
        ok = st == "Done"
        now_items.append(f'<li>{sitelib.icon("circle-check" if ok else "circle-dot", 16, "ok" if ok else "wip")}'
                         f'<span><b>{esc(rid)}</b> {esc(label)} ({esc(st.lower())})</span></li>')
    tl.append(f"""<li class="tl-progress"><span class="tl-dot">{sitelib.icon("loader-circle", 20)}</span>
<div class="tl-body"><div class="tl-title"><h3>Coming next</h3>{pill("progress", "In progress")}</div>
<p>Workspaces and an admin console, assistive features from pretrained models, and a UI and workflow overhaul. Model features are off by default and are suggestions only: nothing a model says enters the sealed PDF or the audit trail.</p>
<ul class="tl-items">{"".join(now_items)}</ul></div></li>""")

    scope = "".join(f'<li>{sitelib.icon("check", 16)}<span>{esc(x)}</span></li>' for x in r1["items"])

    # Next and Later, by theme.
    nxt = milestone_slices(t, NEXT_MILESTONES)
    later = milestone_slices(t, LATER_MILESTONES)
    for n in outcomes:
        if n not in nxt and n not in later:
            later.add(n)

    def lane(title: str, kind: str, nums: set[int], blurb: str) -> str:
        groups = []
        for key, label, ic in THEMES:
            members = sorted(n for n in nums if SLICE_THEME.get(n) == key)
            if not members:
                continue
            tickets = []
            for n in members:
                name, outcome = outcomes[n]
                vs = f"VS-{n:02d}"
                st = t.get(vs, ["", "", "Open"])[2]
                badge = pill("blocked", "Blocked") if st == "Blocked" else (pill("progress", "In progress") if st == "In progress" else "")
                tickets.append(f'<li class="ticket"><div class="ticket-top"><b>{esc(name)}</b><span class="id">{vs}</span></div>'
                               f'<p>{esc(first_sentence(outcome, 150))}</p>{badge}</li>')
            groups.append(f'<section class="theme-group" aria-label="{esc(label)}"><h3>{sitelib.icon(ic, 16)}{esc(label)}</h3>'
                          f'<ul class="tl-stack">{"".join(tickets)}</ul></section>')
        return (f'<div class="lane"><h2>{esc(title)} {pill(kind, title)}</h2><p class="muted lane-blurb">{esc(blurb)}</p>'
                f'{"".join(groups)}</div>')

    gates = [(r, c) for r, c in t.items() if r in {"PV-01", "SEC-REV-01", "SEC-ASVS-01", "A11Y-01", "UXR-01", "LEG-01", "LEG-02"}]
    gate_items = "".join(
        f'<li>{sitelib.icon("circle-check" if c[2] == "Done" else "circle-dashed", 16, "ok" if c[2] == "Done" else "todo")}<span><b>{esc(r)}</b> {esc(plain(c[1]))}</span></li>'
        for r, c in gates)

    body = f"""<section class="page-head"><div class="wrap">
  <h1>Roadmap</h1>
  <p class="lede">Where OpenSeal stands and what comes next, generated from the project's own roadmap and tracker. Evidence integrity comes first, so the engine and server were built before the features on top.</p>
  <p class="callout">{sitelib.icon("info")}<span>This is the project's plan, not a commitment. No dates are promised; sizes and order can change. Ideas and requests are welcome as <a href="{ISSUES}">GitHub issues</a>.</span></p>
</div></section>

<section class="section-tight" aria-labelledby="now-h"><div class="wrap">
  <div class="sec-head"><h2 id="now-h">Done and in progress</h2></div>
  <ol class="timeline">{"".join(tl)}</ol>
</div></section>

<section class="section-tight section-alt" aria-labelledby="r1-h"><div class="wrap">
  <div class="release">
    <div class="tl-title"><h2 id="r1-h">Release 1: the common case first</h2>{pill("done", r1["version"] + " published") if r1["version"] else pill("next", "Next")}</div>
    <p class="muted">{esc(r1["intro"])}</p>
    <ul class="scope">{scope}</ul>
  </div>
</div></section>

<section class="section-tight" aria-labelledby="board-h"><div class="wrap">
  <div class="sec-head"><h2 id="board-h">After Release 1</h2><p>Work continues as vertical slices: thin features cut through every layer, then deepened. Grouped by theme; each card is a slice in the tracker.</p></div>
  <div class="board">
    {lane("Next", "next", nxt, "Toward first signature, team beta and 1.0 general availability.")}
    {lane("Later", "later", later, "Regulated industries, the ecosystem, and the agreement platform.")}
  </div>
</div></section>

<section class="section-tight section-alt" aria-labelledby="gates-h"><div class="wrap">
  <div class="sec-head"><h2 id="gates-h">Before anything is called 1.0</h2><p>Release gates that must pass first. Until then, no claim of validity in Adobe Acrobat, no certification and no legal claim is made.</p></div>
  <ul class="tl-items">{gate_items}</ul>
  <p class="note">Generated by <code>tools/build-roadmap.py</code> from <a href="{sitelib.REPO}/blob/main/docs/06-ROADMAP-AND-DELIVERY.md">docs/06</a> and <a href="{sitelib.REPO}/blob/main/docs/14-EXECUTION-TRACKER.md">docs/14</a>.</p>
</div></section>"""
    return sitelib.page(title="Roadmap", description="What OpenSeal has built, what is in progress, Release 1, and the slices that follow.",
                        body=sitelib.add_heading_ids(body), root="", current="roadmap")


def main(argv: list[str]) -> int:
    out = render()
    if argv == ["--check"]:
        if not OUT.exists() or OUT.read_text(encoding="utf8") != out:
            print("build-roadmap: site/roadmap.html is stale; run python3 -I tools/build-roadmap.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(out, encoding="utf8")
    print("build-roadmap: wrote site/roadmap.html")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
