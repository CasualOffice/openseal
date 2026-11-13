// The website's behaviour (SITE-01): theme switch, phone menu, search over the prebuilt
// index (search-index.json), copy buttons on code, scroll reveals and the docs'
// "on this page" highlight. No framework; every string set as text. The hero's entrance
// is CSS only (site.css §Motion), keyed on the `js` class theme-init.js sets.

const root = document.documentElement;
const base = document.body.dataset.root || "";
const SVG = "http://www.w3.org/2000/svg";

// ---- Theme ------------------------------------------------------------------------------
const dark = () => root.dataset.theme === "dark" || (!root.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
function labelTheme() {
  for (const b of document.querySelectorAll(".theme-toggle")) b.setAttribute("aria-label", dark() ? "Use the light theme" : "Use the dark theme");
}
for (const b of document.querySelectorAll(".theme-toggle")) {
  b.addEventListener("click", () => {
    const next = dark() ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("openseal.theme", next); } catch { /* storage off */ }
    labelTheme();
  });
}
labelTheme();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", labelTheme);

// ---- Phone menu ---------------------------------------------------------------------------
for (const menu of document.querySelectorAll("details.menu, details.docs-nav-toggle")) {
  menu.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && menu.open) { menu.open = false; menu.querySelector("summary").focus(); }
  });
  menu.addEventListener("click", (e) => { if (e.target.closest("a")) menu.open = false; });
}
document.addEventListener("click", (e) => {
  for (const menu of document.querySelectorAll("details.menu[open]")) if (!menu.contains(e.target)) menu.open = false;
});

// ---- Copy buttons ---------------------------------------------------------------------------
function svgIcon(paths, cls) {
  const s = document.createElementNS(SVG, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", width: "18", height: "18", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false", class: cls })) s.setAttribute(k, v);
  for (const [tag, attrs] of paths) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    s.append(n);
  }
  return s;
}
// Lucide "copy" and "check" (ISC), as nodes.
const COPY = [["rect", { width: "14", height: "14", x: "8", y: "8", rx: "2", ry: "2" }], ["path", { d: "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" }]];
const CHECK = [["path", { d: "M20 6 9 17l-5-5" }]];
for (const pre of document.querySelectorAll("pre")) {
  if (pre.closest(".no-copy")) continue;
  // A scrolling code block must be reachable by keyboard (WCAG 2.1.1).
  pre.tabIndex = 0;
  pre.setAttribute("role", "region");
  pre.setAttribute("aria-label", "Code");
  const wrap = document.createElement("div");
  wrap.className = "code-wrap";
  pre.replaceWith(wrap);
  wrap.append(pre);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.setAttribute("aria-label", "Copy code");
  btn.append(svgIcon(COPY, "i-copy"), svgIcon(CHECK, "i-done"));
  const status = document.createElement("span");
  status.className = "sr-only";
  status.setAttribute("role", "status");
  btn.addEventListener("click", async () => {
    const text = (pre.querySelector("code") || pre).textContent.replace(/\n$/, "");
    try {
      await navigator.clipboard.writeText(text);
      btn.classList.add("is-done");
      status.textContent = "Copied";
      setTimeout(() => { btn.classList.remove("is-done"); status.textContent = ""; }, 1600);
    } catch {
      status.textContent = "Copy failed: select the text and copy it";
    }
  });
  wrap.append(btn, status);
}

// ---- Scroll reveal ----------------------------------------------------------------------------
// Progressive: everything is visible unless this code decides to animate it. Only
// elements wholly below the fold are hidden, and only when motion is welcome and
// IntersectionObserver exists; anything already in view is never hidden.
const motionOK = matchMedia("(prefers-reduced-motion: no-preference)").matches;
const reveals = [...document.querySelectorAll(".reveal")];
if (motionOK && "IntersectionObserver" in window) {
  const fold = window.innerHeight;
  const pending = reveals.filter((el) => el.getBoundingClientRect().top > fold);
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); }
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.01 });
  for (const el of pending) { el.classList.add("reveal-pending"); io.observe(el); }
  const showAll = () => { for (const el of pending) el.classList.add("is-in"); };
  addEventListener("beforeprint", showAll);
  // A jump past content (a #link, Find, End) must not leave it hidden.
  addEventListener("hashchange", showAll);
}

// ---- On this page ----------------------------------------------------------------------------
const tocLinks = [...document.querySelectorAll(".toc a")];
if (tocLinks.length && "IntersectionObserver" in window) {
  const byId = new Map(tocLinks.map((a) => [decodeURIComponent(a.hash.slice(1)), a]));
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      for (const a of tocLinks) a.classList.toggle("is-active", a === byId.get(e.target.id));
    }
  }, { rootMargin: "-10% 0px -75% 0px" });
  for (const id of byId.keys()) { const h = document.getElementById(id); if (h) io.observe(h); }
}

// ---- Search -------------------------------------------------------------------------------------
const dialog = document.querySelector(".search-dialog");
const input = dialog?.querySelector(".search-input");
const list = dialog?.querySelector(".search-results");
const status = dialog?.querySelector(".search-status");
let index = null;

async function loadIndex() {
  if (index) return index;
  try {
    const res = await fetch(`${base}search-index.json`);
    index = res.ok ? await res.json() : [];
  } catch {
    index = [];
  }
  return index;
}

function terms(q) { return q.toLowerCase().split(/\s+/).filter((t) => t.length > 1 || /\d/.test(t)); }

function score(entry, ts) {
  const h = entry.h.toLowerCase(); const p = entry.p.toLowerCase(); const t = entry.t.toLowerCase();
  let s = 0;
  for (const term of ts) {
    const inH = h.includes(term); const inP = p.includes(term); const inT = t.includes(term);
    if (!inH && !inP && !inT) return 0;
    s += (inH ? 10 : 0) + (inP ? 4 : 0) + (inT ? 1 : 0);
  }
  return s;
}

function highlight(el, text, ts) {
  // Text nodes and <mark> elements only: nothing from the index is parsed as HTML.
  const lower = text.toLowerCase();
  let pos = 0;
  while (pos < text.length) {
    let best = -1; let len = 0;
    for (const t of ts) { const i = lower.indexOf(t, pos); if (i !== -1 && (best === -1 || i < best)) { best = i; len = t.length; } }
    if (best === -1) { el.append(text.slice(pos)); break; }
    el.append(text.slice(pos, best));
    const m = document.createElement("mark");
    m.textContent = text.slice(best, best + len);
    el.append(m);
    pos = best + len;
  }
}

function snippet(text, ts) {
  const lower = text.toLowerCase();
  const at = Math.min(...ts.map((t) => { const i = lower.indexOf(t); return i === -1 ? Infinity : i; }));
  if (!Number.isFinite(at) || at < 60) return text.slice(0, 160);
  return `…${text.slice(at - 40, at + 120)}`;
}

async function runSearch() {
  const ts = terms(input.value);
  list.replaceChildren();
  if (!ts.length) { status.textContent = "Type at least two letters."; return; }
  const all = await loadIndex();
  const hits = all.map((e) => [score(e, ts), e]).filter(([s]) => s > 0).sort((a, b) => b[0] - a[0]).slice(0, 20);
  status.textContent = hits.length ? `${hits.length} result${hits.length === 1 ? "" : "s"}` : "No results. Try other words.";
  for (const [, e] of hits) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = base + e.u;
    const page = document.createElement("span"); page.className = "r-page"; page.textContent = e.p;
    const head = document.createElement("span"); head.className = "r-head"; highlight(head, e.h, ts);
    const text = document.createElement("span"); text.className = "r-text"; highlight(text, snippet(e.t, ts), ts);
    a.append(page, head, text);
    a.addEventListener("click", () => dialog.close());
    li.append(a);
    list.append(li);
  }
}

if (dialog) {
  const open = () => {
    if (dialog.open) return;
    dialog.showModal();
    input.select();
    loadIndex();
  };
  for (const b of document.querySelectorAll(".search-open")) b.addEventListener("click", open);
  document.addEventListener("keydown", (e) => {
    const typing = e.target.closest?.("input, textarea, select, [contenteditable]");
    if (!typing && (e.key === "/" || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k"))) { e.preventDefault(); open(); }
  });
  let timer = 0;
  input.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(runSearch, 80); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); list.querySelector("a")?.focus(); }
    if (e.key === "Enter") { e.preventDefault(); const first = list.querySelector("a"); if (first) { dialog.close(); location.href = first.href; } }
  });
  list.addEventListener("keydown", (e) => {
    const links = [...list.querySelectorAll("a")];
    const i = links.indexOf(document.activeElement);
    if (e.key === "ArrowDown" && i < links.length - 1) { e.preventDefault(); links[i + 1].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); (i > 0 ? links[i - 1] : input).focus(); }
  });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });
}
