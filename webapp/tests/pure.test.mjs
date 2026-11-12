// Pure modules (WEB-01): geometry, the command registry, the key tables, i18n
// coverage, and the design tokens' contrast. Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as geo from "../geometry.js";
import * as cmd from "../commands.js";
import { combo, commandFor, SHORTCUTS } from "../keys.js";
import { EN, PARTS } from "../strings.en.js";
import { t } from "../i18n.js";
import { locationFrom, isMockMode, toBase64 } from "../api.js";
import { makePdf, countPages } from "../mockpdf.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEBAPP = path.resolve(HERE, "..");
const page = { width: 612, height: 792 };

// ---- geometry ---------------------------------------------------------------------
test("clampRect keeps a field on its page and at least MIN_SIZE", () => {
  assert.deepEqual(geo.clampRect({ x: -10, y: 800, width: 100, height: 20 }, page), { x: 0, y: 772, width: 100, height: 20 });
  assert.deepEqual(geo.clampRect({ x: 600, y: 0, width: 2, height: 2 }, page), { x: 600, y: 0, width: 8, height: 8 });
  assert.deepEqual(geo.clampRect({ x: 0, y: 0, width: 9999, height: 9999 }, page), { x: 0, y: 0, width: 612, height: 792 });
});

test("nudge and resize move by points and stop at the edge", () => {
  const r = { x: 10, y: 10, width: 100, height: 20 };
  assert.deepEqual(geo.nudge(r, -20, 5, page), { x: 0, y: 15, width: 100, height: 20 });
  assert.deepEqual(geo.resize(r, 4, -100, page), { x: 10, y: 10, width: 104, height: 8 });
});

test("formatPoints writes the wire's decimal strings", () => {
  assert.equal(geo.formatPoints(72), "72");
  assert.equal(geo.formatPoints(10.5), "10.5");
  assert.equal(geo.formatPoints(1 / 3), "0.33");
  assert.equal(geo.formatPoints(-0.001), "0");
  assert.equal(geo.formatPoints(1e9), "14400");
  assert.throws(() => geo.formatPoints(Number.NaN), RangeError);
});

test("toWire and fromWire round-trip; fromWire refuses what the engine refuses", () => {
  const w = geo.toWire(2, { x: 72, y: 100.25, width: 160, height: 44 });
  assert.deepEqual(w, { page: 2, x: "72", y: "100.25", width: "160", height: "44" });
  assert.deepEqual(geo.fromWire(w), { page: 2, x: 72, y: 100.25, width: 160, height: 44 });
  assert.equal(geo.fromWire({ ...w, page: 0 }), null);
  assert.equal(geo.fromWire({ ...w, width: "0" }), null);
  assert.equal(geo.fromWire({ ...w, x: "-1" }), null);
  assert.equal(geo.fromWire({ ...w, y: "abc" }), null);
});

test("screen pixels and points convert by the scale alone (ADR-019)", () => {
  assert.deepEqual(geo.toPoints(150, 75, 1.5), { x: 100, y: 50 });
  assert.deepEqual(geo.toPixels({ x: 100, y: 50, width: 10, height: 4 }, 1.5), { left: 150, top: 75, width: 15, height: 6 });
});

test("placeAt centres the default size; freeSpot never covers another field", () => {
  const r = geo.placeAt("signature", 306, 396, page);
  assert.deepEqual(r, { x: 226, y: 374, width: 160, height: 44 });
  const existing = [r];
  const s = geo.freeSpot(existing, { width: 160, height: 44 }, page, 306, 396);
  assert.ok(!geo.overlaps(s, r));
  const many = [];
  for (let i = 0; i < 12; i++) many.push(geo.freeSpot(many, { width: 110, height: 22 }, page, 306, 264));
  for (let i = 0; i < many.length; i++) for (let j = i + 1; j < many.length; j++) assert.ok(!geo.overlaps(many[i], many[j], 0), `${i} and ${j} overlap`);
});

test("snap pulls to the grid only within tolerance", () => {
  assert.equal(geo.snap(9), 8);
  assert.equal(geo.snap(10), 10);
  assert.equal(geo.snap(10.1), 10.1);
});

// ---- commands and keys ------------------------------------------------------------
test("the registry runs enabled commands only, and unregisters by prefix", () => {
  let ran = 0;
  let on = false;
  cmd.register("x.a", { label: "A", run: () => { ran++; }, enabled: () => on });
  assert.equal(cmd.run("x.a"), false);
  on = true;
  assert.equal(cmd.run("x.a"), true);
  assert.equal(ran, 1);
  cmd.setPolicy((id) => ({ hidden: false, disabled: id === "x.a" }));
  assert.equal(cmd.run("x.a"), false);
  cmd.setPolicy(() => ({ hidden: false, disabled: false }));
  cmd.unregisterPrefix("x.");
  assert.equal(cmd.has("x.a"), false);
  assert.equal(cmd.run("nope"), false);
});

const key = (k, code, mods = {}) => ({ key: k, code, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...mods });

test("combo names keys the way the tables do, Cmd as Ctrl", () => {
  assert.equal(combo(key("d", "KeyD", { metaKey: true })), "Ctrl+D");
  assert.equal(combo(key("Z", "KeyZ", { ctrlKey: true, shiftKey: true })), "Ctrl+Shift+Z");
  assert.equal(combo(key("?", "Slash", { shiftKey: true })), "?");
  assert.equal(combo(key("ArrowLeft", "ArrowLeft", { shiftKey: true })), "Shift+ArrowLeft");
  assert.equal(combo(key("3", "Digit3")), "3");
});

test("the editor's table wins, and plain keys never fire while typing", () => {
  assert.equal(commandFor(key("Delete", "Delete"), ["editor", "global"]), "field.delete");
  assert.equal(commandFor(key("Delete", "Delete"), ["editor", "global"], true), null);
  assert.equal(commandFor(key("Enter", "Enter", { ctrlKey: true }), ["editor", "global"], true), "envelope.send");
  assert.equal(commandFor(key("n", "KeyN"), ["global"]), "envelope.new");
  assert.equal(commandFor(key("n", "KeyN"), ["global"], true), null);
  assert.equal(commandFor(key("Escape", "Escape"), ["editor"], true), "field.deselect");
});

test("every bound command id is one the app registers", () => {
  const src = fs.readdirSync(WEBAPP).filter((f) => f.endsWith(".js")).map((f) => fs.readFileSync(path.join(WEBAPP, f), "utf8")).join("\n");
  for (const table of Object.values(SHORTCUTS)) {
    for (const id of table.values()) {
      const base = id.replace(/-\d+$/, "-");
      assert.ok(src.includes(`"${id}"`) || src.includes(`\`${base}`) || src.includes(`"${base}`) || src.includes(`reg("${id}"`), `no registration for ${id}`);
    }
  }
});

// ---- i18n -------------------------------------------------------------------------
test("every message key used in code and HTML has an English string", () => {
  const files = [...fs.readdirSync(WEBAPP), ...fs.readdirSync(path.join(WEBAPP, "ui")).map((f) => `ui/${f}`)].filter((f) => /\.(js|html)$/.test(f) && f !== "strings.en.js");
  const missing = [];
  const prefixes = "a11y|account|action|adopt|admin|agreements|audit|cmd|empty|error|event|form|ftype|help|home|mock|nav|prepare|recipient|reports|rtype|send|sign|signin|start|status|template|templates|theme|timeline|top|use|verify|wizard|preview";
  const commandIds = new Set(["envelope.new", "envelope.refresh", "envelope.save", "envelope.send", "envelope.edit", "envelope.resend", "envelope.void", "envelope.download", "envelope.certificate", "theme.toggle", "recipient.add", "recipient.select", "recipient.select-", "help.shortcuts", "document.add", "template.new", "verify.html", "verify.js", "prepare.css", "sign.css", "admin.css"]);
  for (const f of files) {
    const text = fs.readFileSync(path.join(WEBAPP, f), "utf8");
    for (const m of text.matchAll(new RegExp(`["':](${prefixes}|envelope)\\.[A-Za-z0-9.\\-]+(?=["';])`, "g"))) {
      const k = m[0].slice(1);
      if (commandIds.has(k) || k.endsWith(".") || k.endsWith("-")) continue;
      // The server's audit event types (casual-sign-audit, `recipient.signed`) are data,
      // not message keys: sign.js maps them to strings and the mock answers them.
      if ((f === "sign.js" || f === "mock.js") && /^(envelope|recipient|document|reminder)\.[a-z_]+$/.test(k)) continue;
      if (!(k in EN)) missing.push(`${f}: ${k}`);
    }
  }
  // Families built from data.
  for (const s of ["draft", "sent", "delivered", "completing", "completed", "declined", "voided", "expired", "created"]) if (!(`status.${s}` in EN)) missing.push(`status.${s}`);
  for (const ft of geo.FIELD_TYPES) if (!(`ftype.${ft}` in EN)) missing.push(`ftype.${ft}`);
  for (const ft of geo.FIELD_TYPES.filter((x) => !geo.takesInput(x))) if (!(`prepare.auto-${ft}` in EN)) missing.push(`prepare.auto-${ft}`);
  for (const k of ["x", "y", "width", "height"]) if (!(`prepare.geo-${k}` in EN)) missing.push(`prepare.geo-${k}`);
  for (const k of ["type", "draw", "upload"]) if (!(`adopt.${k}` in EN)) missing.push(`adopt.${k}`);
  for (const k of ["voided", "declined", "expired"]) if (!(`sign.closed.${k}` in EN)) missing.push(`sign.closed.${k}`);
  assert.deepEqual(missing, []);
});

test("every message key is defined in exactly one strings/ part (UX-02)", () => {
  const seen = new Map();
  const twice = [];
  for (const [part, map] of Object.entries(PARTS)) {
    for (const k of Object.keys(map)) {
      if (seen.has(k)) twice.push(`${k}: ${seen.get(k)} and ${part}`);
      seen.set(k, part);
    }
  }
  assert.deepEqual(twice, []);
  assert.equal(seen.size, Object.keys(EN).length);
});

test("t fills placeholders as text and leaves unknown ones", () => {
  assert.equal(t("sign.progress", { done: 1, total: 3 }), "1 of 3 required");
  assert.equal(t("empty.search.text", { query: "<b>x</b>" }), "No envelope has “<b>x</b>” in its subject or recipients.");
  assert.equal(t("no.such.key"), "no.such.key");
});

// ---- tokens: contrast (WCAG 2.2 AA) -----------------------------------------------
function lum(hex) {
  const n = hex.replace("#", "");
  const c = [0, 2, 4].map((i) => parseInt(n.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

function tokens(block) {
  const out = {};
  for (const m of block.matchAll(/--(os-[a-z0-9-]+):\s*(#[0-9a-f]{6})\b/g)) out[m[1]] = m[2];
  return out;
}

test("text and control colours meet WCAG 2.2 AA in both themes", () => {
  const css = fs.readFileSync(path.join(WEBAPP, "tokens.css"), "utf8");
  const light = tokens(css.slice(css.indexOf(":root {"), css.indexOf(':root[data-theme="dark"]')));
  const dark = tokens(css.slice(css.indexOf(':root[data-theme="dark"]'), css.indexOf("@media (prefers-color-scheme: dark)")));
  const report = [];
  for (const [name, th] of [["light", light], ["dark", dark]]) {
    for (const bg of ["os-bg", "os-canvas", "os-surface", "os-raised"]) {
      for (const fg of ["os-text", "os-muted", "os-accent", "os-danger", "os-success", "os-info"]) {
        const r = ratio(th[fg], th[bg]);
        if (r < 4.5) report.push(`${name}: ${fg} on ${bg} ${r.toFixed(2)}`);
      }
      for (const ui of ["os-border-strong", "os-focus", "os-r1", "os-r2", "os-r3", "os-r4", "os-r5", "os-r6"]) {
        const r = ratio(th[ui], th[bg]);
        if (r < 3) report.push(`${name}: ${ui} on ${bg} ${r.toFixed(2)} (non-text, needs 3)`);
      }
    }
    const fill = ratio(th["os-on-accent"], th["os-accent-fill"]);
    if (fill < 4.5) report.push(`${name}: on-accent on accent-fill ${fill.toFixed(2)}`);
  }
  assert.deepEqual(report, []);
});

// CIEDE2000 between two sRGB colours: how different they look (UX-02).
function lab(hex) {
  const lin = (v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  const [r, g, b] = [1, 3, 5].map((i) => lin(parseInt(hex.slice(i, i + 2), 16) / 255));
  const f = (x) => (x > 216 / 24389 ? Math.cbrt(x) : (24389 / 27 * x + 16) / 116);
  const x = f((0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047);
  const y = f(0.2126 * r + 0.7152 * g + 0.0722 * b);
  const z = f((0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883);
  return [116 * y - 16, 500 * (x - y), 200 * (y - z)];
}
function deltaE(c1, c2) {
  const rad = Math.PI / 180;
  const [L1, a1, b1] = lab(c1); const [L2, a2, b2] = lab(c2);
  const Cb = (Math.hypot(a1, b1) + Math.hypot(a2, b2)) / 2;
  const G = 0.5 * (1 - Math.sqrt(Cb ** 7 / (Cb ** 7 + 25 ** 7)));
  const p1 = (1 + G) * a1; const p2 = (1 + G) * a2;
  const C1 = Math.hypot(p1, b1); const C2 = Math.hypot(p2, b2);
  const h1 = (Math.atan2(b1, p1) / rad + 360) % 360; const h2 = (Math.atan2(b2, p2) / rad + 360) % 360;
  let dh = h2 - h1;
  if (C1 * C2 === 0) dh = 0; else if (dh > 180) dh -= 360; else if (dh < -180) dh += 360;
  const dH = 2 * Math.sqrt(C1 * C2) * Math.sin((dh / 2) * rad);
  const Lb = (L1 + L2) / 2; const Cbp = (C1 + C2) / 2;
  let hb = h1 + h2;
  if (C1 * C2 !== 0) hb = Math.abs(h1 - h2) <= 180 ? hb / 2 : hb < 360 ? (hb + 360) / 2 : (hb - 360) / 2;
  const T = 1 - 0.17 * Math.cos((hb - 30) * rad) + 0.24 * Math.cos(2 * hb * rad) + 0.32 * Math.cos((3 * hb + 6) * rad) - 0.2 * Math.cos((4 * hb - 63) * rad);
  const Rc = 2 * Math.sqrt(Cbp ** 7 / (Cbp ** 7 + 25 ** 7));
  const Rt = -Math.sin(2 * 30 * Math.exp(-(((hb - 275) / 25) ** 2)) * rad) * Rc;
  const Sl = 1 + (0.015 * (Lb - 50) ** 2) / Math.sqrt(20 + (Lb - 50) ** 2); const Sc = 1 + 0.045 * Cbp; const Sh = 1 + 0.015 * Cbp * T;
  return Math.sqrt(((L2 - L1) / Sl) ** 2 + ((C2 - C1) / Sc) ** 2 + (dH / Sh) ** 2 + Rt * ((C2 - C1) / Sc) * (dH / Sh));
}

test("destructive colours are clearly distinct from the seal red, in both themes (UX-02)", () => {
  // Owner rule: Void, Delete, Decline and errors never read as the primary action. A
  // CIEDE2000 difference of 10 or more is clearly a different colour at a glance; the
  // old danger red (#b42318 beside #b3141f) was 3.5.
  const css = fs.readFileSync(path.join(WEBAPP, "tokens.css"), "utf8");
  const light = tokens(css.slice(css.indexOf(":root {"), css.indexOf(':root[data-theme="dark"]')));
  const dark = tokens(css.slice(css.indexOf(':root[data-theme="dark"]'), css.indexOf("@media (prefers-color-scheme: dark)")));
  const report = [];
  for (const [name, th] of [["light", light], ["dark", dark]]) {
    for (const [a, b] of [["os-accent", "os-danger"], ["os-accent-fill", "os-danger-fill"], ["os-danger", "os-warning"]]) {
      if (!th[a] || !th[b]) { report.push(`${name}: ${a} or ${b} missing`); continue; }
      const d = deltaE(th[a], th[b]);
      if (d < 10) report.push(`${name}: ${a} ${th[a]} vs ${b} ${th[b]}: ΔE ${d.toFixed(1)}`);
    }
    for (const [fg, bg] of [["os-on-danger", "os-danger-fill"], ["os-on-danger", "os-danger-hover"], ["os-on-accent", "os-accent-hover-fill"]]) {
      if (!th[fg] || !th[bg]) { report.push(`${name}: ${fg} or ${bg} missing`); continue; }
      const r = ratio(th[fg], th[bg]);
      if (r < 4.5) report.push(`${name}: ${fg} on ${bg} ${r.toFixed(2)}`);
    }
  }
  assert.deepEqual(report, []);
});

test("status badges' words meet 4.5:1 on their own tint, in both themes (UX-02)", () => {
  // A badge is `color-mix(in srgb, <colour> N%, var(--os-bg))` behind text in <colour>
  // (app.css, admin.css); 12 px text, so 4.5:1.
  const css = fs.readFileSync(path.join(WEBAPP, "tokens.css"), "utf8");
  const light = tokens(css.slice(css.indexOf(":root {"), css.indexOf(':root[data-theme="dark"]')));
  const dark = tokens(css.slice(css.indexOf(':root[data-theme="dark"]'), css.indexOf("@media (prefers-color-scheme: dark)")));
  const mix = (fg, bg, p) => `#${[1, 3, 5].map((i) => Math.round(parseInt(fg.slice(i, i + 2), 16) * p + parseInt(bg.slice(i, i + 2), 16) * (1 - p)).toString(16).padStart(2, "0")).join("")}`;
  const report = [];
  for (const [name, th] of [["light", light], ["dark", dark]]) {
    for (const c of ["os-danger", "os-success", "os-info", "os-warning"]) {
      const r = ratio(th[c], mix(th[c], th["os-bg"], 0.12));
      if (r < 4.5) report.push(`${name}: ${c} on its badge tint ${r.toFixed(2)}`);
    }
  }
  assert.deepEqual(report, []);
});

test("the OS-preference dark block is the explicit dark block", () => {
  const css = fs.readFileSync(path.join(WEBAPP, "tokens.css"), "utf8");
  const dark = tokens(css.slice(css.indexOf(':root[data-theme="dark"]'), css.indexOf("@media (prefers-color-scheme: dark)")));
  const media = tokens(css.slice(css.indexOf("@media (prefers-color-scheme: dark)"), css.indexOf("@media (prefers-reduced-motion")));
  assert.deepEqual(media, dark);
});

// ---- small helpers ----------------------------------------------------------------
test("locationFrom gives the GEO-01 member: a rounded fix, or a decline", () => {
  assert.deepEqual(locationFrom({ coords: { latitude: 52.3702157, longitude: 4.8951679, accuracy: 24.6 } }), { latitude: 52.370216, longitude: 4.895168, accuracy_m: 25 });
  assert.deepEqual(locationFrom(null), { declined: true });
  assert.deepEqual(locationFrom({ coords: { latitude: Number.NaN, longitude: 1 } }), { declined: true });
});

test("mock mode is honoured on a loopback host only", () => {
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "?mock=1" }), true);
  assert.equal(isMockMode({ hostname: "localhost", search: "?mock=1" }), true);
  assert.equal(isMockMode({ hostname: "sign.example.com", search: "?mock=1" }), false);
  assert.equal(isMockMode({ hostname: "127.0.0.1", search: "" }), false);
});

test("the mock PDF writer makes a PDF whose pages can be counted", () => {
  const pdf = makePdf([{ title: "a" }, { title: "b" }, { title: "c" }]);
  assert.equal(String.fromCharCode(...pdf.subarray(0, 5)), "%PDF-");
  assert.equal(countPages(pdf), 3);
  assert.equal(atob(toBase64(pdf)).length, pdf.length);
});
