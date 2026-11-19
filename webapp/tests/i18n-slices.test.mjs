// i18n string extraction for the M3 slices' screens (docs/06 §After Phase 2: "Accessibility
// (WCAG 2.2 AA) and i18n string extraction are part of every UI slice's end point"; docs/73).
// This is that end point's own check, scoped to the screens slices 1, 2, 5 and 7 use; it is
// not a general repository gate. pure.test.mjs already fails on a key with no English
// string; this fails the other way: on user-visible text written in a module instead of
// coming from strings/ through `t()`.
//
// What counts as user-visible, in a JS module: a string or template literal (with its
// `${…}` parts removed) that holds a letter and is written to one of the sinks below. In
// an HTML page: text in an element, or a `title`, `aria-label`, `alt` or `placeholder`
// attribute, on an element without `data-i18n` (or `data-i18n-attr` naming that
// attribute), and the page's <title>. Symbols, numbers and punctuation ("#", "%", "—",
// "✓") carry no language and pass. A literal the check cannot see (built from data, or
// passed through a variable) is outside it: this is a regression check, not a proof.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const WEBAPP = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

/// The slice screens: the sender's send editor and envelope page (slices 1, 2), the
/// signer's page with its steps and recipient authentication (slices 1, 2, 5), the Verify
/// page (slice 7), and the shared components they draw with.
const SLICE_MODULES = [
  // sender: prepare, send, envelope
  "prepare.js", "prepareview.js", "routing.js", "envelope.js", "envactions.js", "agreementparts.js", "docview.js",
  // signer: the ceremony, its steps, adopting a signature, recipient authentication (sign.js)
  "sign.js", "signfields.js", "signature.js", "zoom.js", "pdfview.js",
  // templates (slice 3): the list with folders and sharing, using one or several together
  "templates.js", "templatemodel.js", "templatesync.js",
  // every field (slice 4): the editor's field logic and kinds, the mock's rules
  "fieldlogic.js", "geometry.js", "fieldrules.js",
  // verify
  "verify.js", "verifyview.js", "verifyreport.js", "trail.js",
  // shared components
  "ui/core.js", "ui/controls.js", "ui/menus.js", "ui/panel.js", "ui/palette.js", "ui/pdfpreview.js",
];
const SLICE_PAGES = ["app.html", "sign.html", "verify.html"];

/// The code before a literal that makes it text a person reads or hears, matched at the
/// end of the code since the previous literal.
const SINKS = [
  // h(tag, { text, title, placeholder, alt, label }) and option objects shown as text
  /\b(?:text|title|placeholder|alt|label|ariaLabel)\s*:\s*$/,
  // el.textContent = …, el.title = …, el.placeholder = …, document.title = …
  /\.(?:textContent|innerText|title|placeholder|alt)\s*=\s*$/,
  // el.append(…, "…") (any child), toast("…") / alert / confirm (the message, first)
  /(?:\.append|\.prepend)\(\s*(?:[^()]*,\s*)?$/,
  /(?:\btoast|\balert|\bconfirm)\(\s*$/,
];
/// Quoted attribute names whose value is read: `attrs: { "aria-label": "…" }` and
/// `setAttribute("aria-label", "…")`. `data-glyph` is text CSS draws (`content: attr()`).
const TEXT_ATTRS = new Set(["aria-label", "aria-description", "aria-valuetext", "aria-roledescription", "title", "placeholder", "alt", "data-glyph"]);

/// The top-level string and template literals of a source, in order, each with the code
/// before it (since the previous literal). A template's `${…}` may hold nested literals;
/// they belong to the template. Comments and regular expressions are skipped.
function literals(src) {
  const out = [];
  const n = src.length;
  const skipString = (q, j) => {
    for (j += 1; j < n; j += 1) {
      if (src[j] === "\\") j += 1;
      else if (src[j] === q) return j + 1;
      else if (src[j] === "\n") return j;
    }
    return n;
  };
  const skipTemplate = (j) => {
    for (j += 1; j < n; j += 1) {
      const c = src[j];
      if (c === "\\") { j += 1; continue; }
      if (c === "`") return j + 1;
      if (c === "$" && src[j + 1] === "{") {
        let depth = 1;
        j += 2;
        while (j < n && depth) {
          const d = src[j];
          if (d === '"' || d === "'") { j = skipString(d, j); continue; }
          if (d === "`") { j = skipTemplate(j); continue; }
          if (d === "{") depth += 1;
          else if (d === "}") depth -= 1;
          j += 1;
        }
        j -= 1;
      }
    }
    return n;
  };
  let i = 0;
  let codeStart = 0;
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") { const e = src.indexOf("\n", i); i = e < 0 ? n : e; continue; }
    if (c === "/" && src[i + 1] === "*") { const e = src.indexOf("*/", i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === "/" && /(?:^|[(,=:[!&|?{};]|\breturn)\s*$/.test(src.slice(Math.max(0, i - 20), i))) {
      let j = i + 1;
      let cls = false;
      for (; j < n && src[j] !== "\n"; j += 1) {
        if (src[j] === "\\") j += 1;
        else if (src[j] === "[") cls = true;
        else if (src[j] === "]") cls = false;
        else if (src[j] === "/" && !cls) break;
      }
      i = j + 1;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const end = c === "`" ? skipTemplate(i) : skipString(c, i);
      out.push({ before: src.slice(codeStart, i), text: src.slice(i, end), at: i });
      i = end;
      codeStart = end;
      continue;
    }
    i += 1;
  }
  return out;
}

/// Text with a letter in it, once a template's `${…}` parts are removed.
function hasWords(literal) {
  let body = literal.slice(1, -1);
  if (literal[0] === "`") {
    let kept = "";
    let depth = 0;
    for (let j = 0; j < body.length; j += 1) {
      if (!depth && body[j] === "$" && body[j + 1] === "{") { depth = 1; j += 1; continue; }
      if (depth) { if (body[j] === "{") depth += 1; else if (body[j] === "}") depth -= 1; continue; }
      kept += body[j];
    }
    body = kept;
  }
  return /\p{L}/u.test(body);
}

function hardCodedInModule(file, text) {
  const out = [];
  const lits = literals(text);
  const lines = text.split("\n");
  const lineOf = (at) => text.slice(0, at).split("\n").length;
  lits.forEach((l, k) => {
    if (!hasWords(l.text)) return;
    // A line that says why its literals are not text (`// i18n-ignore: icon names`).
    if (/\/\/ i18n-ignore: \S/.test(lines[lineOf(l.at) - 1])) return;
    const prev = lits[k - 1];
    const prevAttr = prev && TEXT_ATTRS.has(prev.text.slice(1, -1));
    const sink = SINKS.some((re) => re.test(l.before))
      || (prevAttr && /^\s*:\s*$/.test(l.before))
      || (prevAttr && /setAttribute\(\s*$/.test(prev.before) && /^\s*,\s*$/.test(l.before));
    if (sink) out.push(`${file}:${lineOf(l.at)}: ${l.text.slice(0, 80)}`);
  });
  return out;
}

function hardCodedInPage(file, html) {
  const out = [];
  const body = html.replace(/<!--[\s\S]*?-->/g, "").replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, "");
  // An element's own text, unless applyI18n fills it.
  for (const m of body.matchAll(/<(\w+)([^>]*)>([^<]*)</g)) {
    const [, tag, attrs, text] = m;
    if (/\p{L}/u.test(text) && !/\sdata-i18n="/.test(attrs)) out.push(`${file}: <${tag}> text ${JSON.stringify(text.trim().slice(0, 60))}`);
  }
  for (const m of body.matchAll(/<(\w+)([^>]*)>/g)) {
    const [, tag, attrs] = m;
    const translated = new Set((attrs.match(/data-i18n-attr="([^"]*)"/)?.[1] || "").split(";").map((p) => p.split(":")[0].trim()));
    for (const a of attrs.matchAll(/\s(title|aria-label|alt|placeholder)="([^"]*)"/g)) {
      if (/\p{L}/u.test(a[2]) && !translated.has(a[1])) out.push(`${file}: <${tag} ${a[1]}> ${JSON.stringify(a[2].slice(0, 60))}`);
    }
  }
  return out;
}

test("the slice screens write no user-visible text outside strings/ (M3 i18n extraction)", () => {
  const found = [];
  for (const f of SLICE_MODULES) found.push(...hardCodedInModule(f, fs.readFileSync(path.join(WEBAPP, f), "utf8")));
  for (const f of SLICE_PAGES) found.push(...hardCodedInPage(f, fs.readFileSync(path.join(WEBAPP, f), "utf8")));
  assert.deepEqual(found, []);
});

test("a field kind's letter glyph is a message; its symbol glyph is not (prepareview)", async () => {
  const { EN } = await import("../strings.en.js");
  const { LETTER_GLYPHS, kindGlyph } = await import("../prepareview.js");
  for (const k of LETTER_GLYPHS) assert.ok(`prepare.glyph-${k}` in EN, `prepare.glyph-${k}`);
  assert.equal(kindGlyph("first_name"), EN["prepare.glyph-first_name"]);
  assert.equal(kindGlyph("unknown-kind"), EN["prepare.glyph-text"]);
  assert.equal(kindGlyph("signature"), "✍");
});

test("the check sees each kind of hard-coded text it claims to (and passes keys and symbols)", () => {
  const bad = [
    `h("span", { text: "Signed" })`,
    'h("p", { text: `Signed on ${day}` })',
    `h("b", { attrs: { "aria-label": "Close" } })`,
    `el.textContent = "Saved";`,
    `b.setAttribute("aria-label", "Next field");`,
    `wrap.append("or");`,
    `toast("Copied")`,
    `h("i", { attrs: { "data-glyph": "Fn" } })`,
  ];
  for (const s of bad) assert.equal(hardCodedInModule("x.js", s).length, 1, s);
  const good = [
    `h("span", { text: t("sign.saved") })`,
    'h("span", { text: `${p}%` })',
    'h("span", { text: `${t("a.b")} ${n}` })',
    `h("span", { text: "—" })`,
    `el.textContent = "";`,
    `h("th", { text: "#" })`,
    `// a comment: text: "Not UI"`,
    `h("span", { class: "os-muted", attrs: { "data-testid": "later" } })`,
    `const re = /"text: "/; h("b", { text: t("x.y") })`,
    `toast(done, "success")`,
    `const ICON = { title: "type" }; // i18n-ignore: icon names`,
  ];
  for (const s of good) assert.deepEqual(hardCodedInModule("x.js", s), [], s);
  assert.equal(hardCodedInPage("x.html", `<title>Sign</title>`).length, 1);
  assert.equal(hardCodedInPage("x.html", `<button aria-label="Close"></button>`).length, 1);
  assert.deepEqual(hardCodedInPage("x.html", `<title data-i18n="sign.page-title">Sign</title><b data-i18n-attr="aria-label:sign.more" aria-label="More"></b><img alt="">`), []);
});
