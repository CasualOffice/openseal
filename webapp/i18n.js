// Messages (WEB-01). Shaped after OpenCalc's `t(key, fallback)` and `setMessages`
// (`webapp/editor.i18n.js` at `b23c67c`, PROVENANCE.md): one map per locale, looked
// up by key. English only for now; a locale is another `strings.<tag>.js` registered
// with `setMessages`. Placeholders are `{name}`, filled as text, never markup.

import { EN } from "./strings.en.js";

const messages = new Map([["en", EN]]);
let locale = "en";

export function setMessages(tag, map) {
  messages.set(tag, { ...(messages.get(tag) || {}), ...map });
}

export function setLocale(tag) {
  if (messages.has(tag)) locale = tag;
}

export function getLocale() {
  return locale;
}

/// The message for `key` in the current locale, English, or the key itself (so a
/// missing string is visible, and `tests/i18n.test.mjs` fails on it first).
export function t(key, vars) {
  const s = messages.get(locale)?.[key] ?? EN[key] ?? key;
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
}

/// Whether `key` has an English message.
export function has(key) {
  return Object.prototype.hasOwnProperty.call(EN, key);
}

/// Fill `[data-i18n]` (text) and `[data-i18n-attr="attr:key;attr:key"]` under `root`.
export function applyI18n(root) {
  for (const n of root.querySelectorAll("[data-i18n]")) n.textContent = t(n.dataset.i18n);
  for (const n of root.querySelectorAll("[data-i18n-attr]")) {
    for (const pair of n.dataset.i18nAttr.split(";")) {
      const [attr, key] = pair.split(":");
      if (attr && key) n.setAttribute(attr.trim(), t(key.trim()));
    }
  }
}
