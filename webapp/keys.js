// Keyboard shortcuts (WEB-01; docs/47 §Keyboard): one table from keys to command ids,
// run through the registry, so a key does exactly what its button does.
//
// Adapted from OpenPresent's `webapp/editor.keys.js` at `e61277d` (PROVENANCE.md):
// keys are matched on `KeyboardEvent.code` for punctuation and on `key` for letters;
// Ctrl and Cmd are one. Changed: tables per context (`global`, `editor`), and a key
// with no modifier never fires while the user types in a field.

import { command, run } from "./commands.js";
import { t } from "./i18n.js";
import { TOOL_KEYS } from "./preparemodel.js";

/// Context → key → command id. The editor's table is checked before the global one.
export const SHORTCUTS = {
  global: new Map([
    // "?" is matched without Shift (see `combo`), whichever keyboard needs Shift for it.
    ["?", "help.shortcuts"],
    // WEB-17: the command menu. app.js handles it ahead of this table (it works while
    // typing too); it is listed here so the shortcuts panel shows it.
    ["Ctrl+K", "palette.open"],
    // UX-04: search from any screen with the bar, not only Agreements.
    ["/", "search.focus"],
    ["N", "envelope.new"],
    // WEB-12 (NAV-35): G, then a letter, goes to a section (S for the admin settings).
    ["G H", "nav.home"],
    ["G A", "nav.agreements"],
    ["G T", "nav.templates"],
    ["G R", "nav.reports"],
    ["G S", "nav.admin"],
    ["Ctrl+Shift+L", "theme.toggle"],
  ]),
  editor: new Map([
    ["Delete", "field.delete"],
    ["Backspace", "field.delete"],
    ["ArrowLeft", "field.nudge-left"],
    ["ArrowRight", "field.nudge-right"],
    ["ArrowUp", "field.nudge-up"],
    ["ArrowDown", "field.nudge-down"],
    ["Shift+ArrowLeft", "field.nudge-left-10"],
    ["Shift+ArrowRight", "field.nudge-right-10"],
    ["Shift+ArrowUp", "field.nudge-up-10"],
    ["Shift+ArrowDown", "field.nudge-down-10"],
    ["Alt+ArrowRight", "field.grow-width"],
    ["Alt+ArrowLeft", "field.shrink-width"],
    ["Alt+ArrowDown", "field.grow-height"],
    ["Alt+ArrowUp", "field.shrink-height"],
    // WEB-09: the keyboard side of snapping guides and marquee selection.
    ["Alt+Shift+ArrowLeft", "field.jump-left"],
    ["Alt+Shift+ArrowRight", "field.jump-right"],
    ["Alt+Shift+ArrowUp", "field.jump-up"],
    ["Alt+Shift+ArrowDown", "field.jump-down"],
    ["Ctrl+A", "field.select-page"],
    ["Ctrl+D", "field.duplicate"],
    ["Ctrl+C", "field.copy"],
    ["Ctrl+V", "field.paste"],
    ["Ctrl+Z", "edit.undo"],
    ["Ctrl+Shift+Z", "edit.redo"],
    ["Ctrl+Y", "edit.redo"],
    ["Ctrl+S", "envelope.save"],
    ["Ctrl+Enter", "envelope.send"],
    ["Escape", "field.deselect"],
    ...[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => [String(n), `recipient.select-${n}`]),
  ]),
};

const CODES = { Slash: "/", Period: ".", Comma: ",", Space: "Space", Equal: "=", BracketLeft: "[", BracketRight: "]" };

/// The key as the tables name it: modifiers in the order Ctrl, Alt, Shift, then the key.
export function combo(e) {
  const mods = [];
  if (e.ctrlKey || e.metaKey) mods.push("Ctrl");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey && e.key !== "?") mods.push("Shift");
  let key = e.key === "?" ? "?" : CODES[e.code];
  if (!key) key = /^Key[A-Z]$/.test(e.code || "") ? e.code.slice(3) : /^Digit[0-9]$/.test(e.code || "") ? e.code.slice(5) : (e.key || "").length === 1 ? e.key.toUpperCase() : e.key;
  return [...mods, key].join("+");
}

/// When G was pressed, for a two-key sequence ("G A"); 0 when none is pending.
let leader = 0;
/// How long after G the second key still counts.
export const LEADER_MS = 1500;

/// The command id a key means in `contexts` (most specific first), or null. A key with
/// no Ctrl or Alt is ignored while typing, except Escape and Ctrl/Alt combinations.
/// A plain G starts a sequence (WEB-12): the next key within `LEADER_MS` is looked up as
/// "G <key>"; any other key, or typing, ends it. `now` is supplied for the tests.
export function commandFor(e, contexts, typing = false, now = Date.now()) {
  const k = combo(e);
  const plain = !(e.ctrlKey || e.metaKey || e.altKey);
  if (typing && plain && k !== "Escape") { leader = 0; return null; }
  if (["Shift", "Control", "Alt", "Meta"].includes(e.key)) return null;
  if (leader && now - leader <= LEADER_MS) {
    leader = 0;
    for (const c of contexts) {
      const v = SHORTCUTS[c]?.get(`G ${k}`);
      if (v) return v;
    }
  }
  leader = 0;
  if (k === "G" && plain && !contexts.some((c) => SHORTCUTS[c]?.has("G"))
    && contexts.some((c) => [...(SHORTCUTS[c]?.keys() || [])].some((key) => key.startsWith("G ")))) {
    leader = now;
    return null;
  }
  for (const c of contexts) {
    const v = SHORTCUTS[c]?.get(k);
    if (v) return v;
  }
  return null;
}

/// Run the key's command if it has one that can run now, and keep the key from the
/// browser. A key whose command is absent or disabled falls through to the browser
/// (Tab keeps moving focus when no field is selected, for instance).
export function handle(e, contexts, typing = false) {
  const id = commandFor(e, contexts, typing);
  if (!id) return false;
  const c = command(id);
  if (!c || (c.enabled && !c.enabled())) return false;
  e.preventDefault();
  e.stopPropagation();
  run(id);
  return true;
}

/// Every bound key and its command id, for the Keyboard shortcuts dialog.
export function bindings(contexts) {
  const out = [];
  for (const c of contexts) for (const [k, v] of SHORTCUTS[c] || []) out.push([k, v, c]);
  return out;
}

// ---- The Keyboard shortcuts panel (UX-04) ----------------------------------------------

/// What each bound command is called in the shortcuts panel: the same words its buttons
/// and the editor use, available whether or not that screen is open.
const LABEL_KEYS = [
  [/^help\.shortcuts$/, "help.shortcuts"],
  [/^palette\.open$/, "palette.label"],
  [/^search\.focus$/, "cmd.search"],
  [/^envelope\.new$/, "nav.new"],
  [/^nav\.(home|agreements|templates|reports|admin)$/, (id) => `cmd.${id}`],
  [/^theme\.toggle$/, "cmd.theme"],
  [/^field\.nudge-[a-z]+-10$/, "cmd.field.nudge-10"],
  [/^field\.nudge-/, "cmd.field.nudge"],
  [/^field\.(grow|shrink)-/, "cmd.field.resize"],
  [/^field\.jump-/, "cmd.field.jump"],
  [/^field\.select-page$/, "cmd.field.select-page"],
  [/^field\.(delete|duplicate|copy|paste|deselect)$/, (id) => `cmd.${id}`],
  [/^edit\.(undo|redo)$/, (id) => `cmd.${id}`],
  [/^envelope\.(save|send)$/, (id) => `cmd.${id}`],
  [/^recipient\.select-\d$/, "cmd.recipient.select"],
];

function labelOf(id, fallback) {
  for (const [re, key] of LABEL_KEYS) if (re.test(id)) return t(typeof key === "function" ? key(id) : key);
  return fallback?.(id) || id;
}

const ARROWS = { ArrowLeft: "←", ArrowRight: "→", ArrowUp: "↑", ArrowDown: "↓" };

/// A table key as the keys to press: `["Ctrl", "Shift", "Z"]`, or `["⌘", "⇧", "Z"]` on
/// a Mac; arrows as arrows, Escape as Esc.
export function keyParts(k, mac = false) {
  // A sequence ("G A") is its keys in turn.
  return k.split(/\+(?!$)| (?=\S)/).map((p) => {
    if (p === "Ctrl") return mac ? "⌘" : "Ctrl";
    if (p === "Alt") return mac ? "⌥" : "Alt";
    if (p === "Shift") return mac ? "⇧" : "Shift";
    if (p === "Escape") return "Esc";
    return ARROWS[p] || p;
  });
}

/// The shortcuts panel's content: one group per context (`contexts` first, then the
/// rest), each a list of `{label, keys: [[part, …], …]}` with one row per action. Keys
/// that do the same thing share a row (Delete or Backspace); four arrows with the same
/// modifiers are one key (`←↑→↓`); the nine recipient digits are `1–9`.
/// `label(id)` names a command no table entry names (a registered command's own label).
export function shortcutGroups(contexts = ["global"], { mac = false, label = null } = {}) {
  const order = [...new Set([...contexts.filter((c) => SHORTCUTS[c]), ...Object.keys(SHORTCUTS)])];
  return [...order.map(tableGroup), toolGroup()];

  function tableGroup(context) {
    const rows = new Map();
    for (const [k, id] of SHORTCUTS[context]) {
      const name = labelOf(id, label);
      const row = rows.get(name) || { label: name, keys: [] };
      rows.set(name, row);
      if (/^recipient\.select-\d$/.test(id)) {
        if (!row.keys.length) row.keys.push(["1–9"]);
        continue;
      }
      row.keys.push(keyParts(k, mac));
    }
    for (const row of rows.values()) {
      const arrows = new Map(); // modifiers → arrow count
      for (const parts of row.keys) {
        const last = parts[parts.length - 1];
        if (Object.values(ARROWS).includes(last)) {
          const mods = parts.slice(0, -1).join("+");
          arrows.set(mods, (arrows.get(mods) || 0) + 1);
        }
      }
      for (const [mods, n] of arrows) {
        if (n !== 4) continue;
        const first = row.keys.findIndex((p) => Object.values(ARROWS).includes(p[p.length - 1]) && p.slice(0, -1).join("+") === mods);
        row.keys = row.keys.filter((p, i) => i === first || !(Object.values(ARROWS).includes(p[p.length - 1]) && p.slice(0, -1).join("+") === mods));
        row.keys[first] = [...(mods ? mods.split("+") : []), "←↑→↓"];
      }
    }
    return { context, rows: [...rows.values()] };
  }
}

/// The editor's single-key tools (WEB-17; preparemodel.js `TOOL_KEYS`), last in the
/// panel. prepare.js dispatches them itself on the fields step (a bare letter, not while
/// typing), so they are listed here rather than bound in `SHORTCUTS`.
function toolGroup() {
  const rows = Object.entries(TOOL_KEYS).map(([tool, key]) => ({
    label: tool === "select" ? t("cmd.tool.select") : t("cmd.tool.place", { type: t(`ftype.${tool}`) }),
    keys: [[key]],
  }));
  return { context: "tools", rows };
}
