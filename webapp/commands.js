// The command registry (WEB-01). Copied from OpenPresent's `webapp/commands.js` at
// `e61277d` (itself OpenCalc's at `b23c67c`; PROVENANCE.md), with `data-op-command`
// renamed `data-os-command`, the ribbon exclusions dropped (this app has no ribbon),
// and `CSS.escape` guarded so the module loads under Node for its tests. Every verb in
// the app is a command here; buttons, menus and shortcuts (`keys.js`) are views of it
// (docs/47 principle 4). OpenPresent's and OpenCalc's notes follow, shortened.
//
// One place that answers "what does command X do, and may it run now?". Two kinds of
// entry, one lookup:
//
//  - **registered** — `register(id, {label, run, ...})`, for commands that have no
//    node of their own.
//  - **owned by a node** — every `[data-os-command]` in the page. Running one clicks
//    that node, so the behaviour is the node's own, never a second copy of it.
//
// A command this build names but cannot run yet is registered with
// `enabled: () => false`, so it shows present and disabled.

const registered = new Map();

/// The app's command rules: `(id) => {hidden, disabled}`.
let policy = () => ({ hidden: false, disabled: false });
export function setPolicy(fn) { policy = fn; }
export function isRegistered(id) { return registered.has(id); }
export function registeredIds() { return [...registered.keys()]; }

/// Register a command that has no DOM node. `spec`: `{ label, run, shortcut?,
/// enabled?: () => boolean, checked?: () => boolean, hidden?: () => boolean }`.
/// Registering an id again replaces it (a screen re-registers its verbs on entry).
export function register(id, spec) {
  registered.set(id, { id, ...spec });
}

/// Remove commands whose id starts with `prefix` (a screen's verbs, on leaving it).
export function unregisterPrefix(prefix) {
  for (const id of [...registered.keys()]) if (id.startsWith(prefix)) registered.delete(id);
}

/// The `Document` or `ShadowRoot` the app's nodes live in.
let root = null;
export function setRoot(r) { root = r; }
const scope = () => root || (typeof document === "undefined" ? null : document);

const escape = (s) => (typeof CSS !== "undefined" && CSS.escape ? CSS.escape(s) : String(s).replace(/["\\]/g, "\\$&"));

function nodeFor(id) {
  const r = scope();
  if (!r) return null;
  return r.querySelector(`[data-os-command="${escape(id)}"]`);
}

/// The command, or `null` if this build has no such verb.
export function command(id) {
  const r = registered.get(id);
  if (r) {
    return {
      ...r,
      hidden: () => policy(id).hidden || (r.hidden ? r.hidden() : false),
      enabled: () => { const p = policy(id); return !p.hidden && !p.disabled && !(r.hidden && r.hidden()) && (r.enabled ? r.enabled() : true); },
    };
  }
  const n = nodeFor(id);
  if (!n) return null;
  return {
    id,
    node: n,
    label: (n.getAttribute("aria-label") || n.textContent || "").trim().split(/\s+[—–-]\s+|\s*\(/)[0].trim(),
    run: () => n.click(),
    hidden: () => n.hidden || n.classList.contains("os-cmd-hidden"),
    enabled: () => !n.disabled && !n.hidden && !n.classList.contains("os-cmd-hidden"),
    checked: () => {
      const p = n.getAttribute("aria-pressed") ?? n.getAttribute("aria-checked");
      return p === "true";
    },
  };
}

export function has(id) { return !!command(id); }

/// Run a command. Returns false when the command is absent or disabled.
export function run(id, ...args) {
  const c = command(id);
  if (!c) return false;
  if (c.enabled && !c.enabled()) return false;
  c.run(...args);
  return true;
}

/// Every command this build can run now, for the shortcut list and search.
export function all() {
  const out = new Map();
  for (const id of registered.keys()) {
    const c = command(id);
    if (!c.hidden()) out.set(id, c);
  }
  const r = scope();
  if (r) {
    for (const n of r.querySelectorAll("[data-os-command]")) {
      const id = n.dataset.osCommand;
      if (out.has(id) || !id.includes(".")) continue;
      const c = command(id);
      if (c && c.label && !c.hidden()) out.set(id, c);
    }
  }
  return [...out.values()];
}
