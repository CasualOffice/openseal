// Sizes are rem (WEB-12; owner instruction 22): every length in the web app's CSS and
// in the sizes its scripts write is rem or em, so the whole UI follows the root size
// (which grows with the screen) and browser zoom. This fails on any px outside the
// allow-list below, so a new one is a decision someone writes down, not an accident.
//
// Allowed without a note:
//  - 0px and 1px: zero, and the one-pixel hairline (a border is one device-independent
//    pixel at any size; thicker borders are rem).
// Allowed with a note: a line that carries `px-ok:` and a reason in a comment, for
// px that must stay px: canvas pixel buffers, PDF points × scale, measured client
// rects written back as positions, and the WCAG floors in tokens.css.
// Images in the HTML pages size in CSS (rem), not with width/height attributes.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const WEBAPP = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

/// The app's own files of `ext` in webapp/ and webapp/ui/ (no vendored code, no tests).
function files(ext) {
  const out = [];
  for (const dir of ["", "ui"]) {
    for (const f of fs.readdirSync(path.join(WEBAPP, dir))) {
      if (f.endsWith(ext)) out.push(path.join(dir, f));
    }
  }
  return out.sort();
}

/// Every px length on `line` that is not 0 or 1.
export function pxOffenders(line) {
  const out = [];
  // A number then px (CSS, or a literal in a script), or a template's `${…}px`, or
  // the unit concatenated as a string ("px").
  for (const m of line.matchAll(/(?<![\w.-])(\d*\.?\d+)px\b|\}px\b|(["'`])px\2/g)) {
    if (m[1] !== undefined && (Number(m[1]) === 0 || Number(m[1]) === 1)) continue;
    out.push(m[0]);
  }
  return out;
}

function scan(rel) {
  const problems = [];
  const lines = fs.readFileSync(path.join(WEBAPP, rel), "utf8").split("\n");
  lines.forEach((line, i) => {
    if (line.includes("px-ok:")) return;
    const bad = pxOffenders(line);
    if (bad.length) problems.push(`${rel}:${i + 1}: ${bad.join(", ")}`);
  });
  return problems;
}

test("the px matcher finds lengths and template units, and spares hairlines and prose", () => {
  assert.deepEqual(pxOffenders("border: 1px solid; margin: 0px;"), []);
  assert.deepEqual(pxOffenders("width: 12px; top: 1.5px"), ["12px", "1.5px"]);
  assert.deepEqual(pxOffenders("el.style.left = `${x}px`;"), ["}px"]);
  assert.deepEqual(pxOffenders("el.style.top = y + \"px\";"), ['"px"']);
  assert.deepEqual(pxOffenders("// rows of 64 px or less"), []);
  assert.deepEqual(pxOffenders("--os-gutter: clamp(1rem, 2.5vw, 3rem);"), []);
});

test("no px in the app's CSS outside the allow-list", () => {
  const problems = files(".css").flatMap(scan);
  assert.deepEqual(problems, [], "use rem (or a token); a px that must stay px carries a px-ok: comment saying why");
});

test("no px in the sizes the app's scripts write outside the allow-list", () => {
  const problems = files(".js").flatMap(scan);
  assert.deepEqual(problems, [], "use rem (or a rootPx() multiple); a px that must stay px carries a px-ok: comment saying why");
});

test("the HTML pages size their images in CSS, not in px attributes", () => {
  const problems = [];
  for (const rel of files(".html")) {
    const html = fs.readFileSync(path.join(WEBAPP, rel), "utf8");
    for (const m of html.matchAll(/<(?:img|svg)\b[^>]*\b(width|height)="\d+"[^>]*>/g)) problems.push(`${rel}: ${m[0].slice(0, 80)}`);
    problems.push(...scan(rel));
  }
  assert.deepEqual(problems, []);
});
