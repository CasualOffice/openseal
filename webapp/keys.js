// Keyboard shortcuts (WEB-01; docs/47 §Keyboard): one table from keys to command ids,
// run through the registry, so a key does exactly what its button does.
//
// Adapted from OpenPresent's `webapp/editor.keys.js` at `e61277d` (PROVENANCE.md):
// keys are matched on `KeyboardEvent.code` for punctuation and on `key` for letters;
// Ctrl and Cmd are one. Changed: tables per context (`global`, `editor`), and a key
// with no modifier never fires while the user types in a field.

import { command, run } from "./commands.js";

/// Context → key → command id. The editor's table is checked before the global one.
export const SHORTCUTS = {
  global: new Map([
    ["Shift+?", "help.shortcuts"],
    ["?", "help.shortcuts"],
    ["/", "list.search"],
    ["N", "envelope.new"],
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

/// The command id a key means in `contexts` (most specific first), or null. A key with
/// no Ctrl or Alt is ignored while typing, except Escape and Ctrl/Alt combinations.
export function commandFor(e, contexts, typing = false) {
  const k = combo(e);
  const plain = !(e.ctrlKey || e.metaKey || e.altKey);
  if (typing && plain && k !== "Escape") return null;
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
