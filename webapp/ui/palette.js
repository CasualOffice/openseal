// The ⌘K command menu (WEB-17; docs/47 §As built: design foundation; the canvas's
// Main artboard). One dialog for jumping anywhere and running any verb: sections of
// results from providers, streamed as each answers.
//
// Accessibility: the WAI-ARIA combobox pattern with a listbox popup. The input is the
// combobox (`aria-expanded`, `aria-controls`, `aria-activedescendant`); options carry
// `aria-selected` for the active one. Arrow keys move, Home and End jump to the first and
// last option, Enter runs the active one, Escape closes; pointer movement sets the
// active option. It is a modal `<dialog>` (focus stays in it, the page is inert), and
// focus returns to whatever opened it.
//
// Providers: `registerPaletteProvider({id, title, icon, order, search(query, signal)})`.
// `search` answers an array of items or a promise of one; a slow one shows a skeleton row
// in its section until it answers, and a newer query aborts it through `signal`. An item
// is `{id, label, sub?, snippet?: [{text, mark?}], hint?, hintTone?, icon?, kbd?, run()}`
// (all strings shown as text). A provider may set `titleTone: "ml"` and `note` (the
// canvas's "Matches by meaning · finds the clause even when the words differ").

import { h, clear, reducedMotion } from "../dom.js";
import { icon } from "../icons.js";
import { t } from "../i18n.js";

const providers = new Map();

/// Add a section to the command menu. Returns a function that removes it again (a
/// screen calls it on leaving). Registering an id again replaces it.
export function registerPaletteProvider(p) {
  if (!p || typeof p.id !== "string" || typeof p.search !== "function") throw new TypeError("a palette provider needs an id and search()");
  providers.set(p.id, { order: 50, ...p });
  return () => { if (providers.get(p.id)?.search === p.search) providers.delete(p.id); };
}

/// The registered providers, in display order (for tests and the shell).
export function paletteProviders() {
  return [...providers.values()].sort((a, b) => a.order - b.order);
}

/// Split `text` into runs, marking the parts that match `query`'s words (case-insensitive),
/// for highlighting. Pure.
export function markRuns(text, query) {
  const s = String(text ?? "");
  const words = String(query || "").toLowerCase().split(/\s+/).filter((w) => w.length > 0);
  if (!words.length) return [{ text: s }];
  const lower = s.toLowerCase();
  const hit = new Array(s.length).fill(false);
  for (const w of words) {
    for (let i = lower.indexOf(w); i !== -1; i = lower.indexOf(w, i + w.length)) for (let k = i; k < i + w.length; k++) hit[k] = true;
  }
  const out = [];
  for (let i = 0; i < s.length;) {
    let j = i;
    while (j < s.length && hit[j] === hit[i]) j++;
    out.push(hit[i] ? { text: s.slice(i, j), mark: true } : { text: s.slice(i, j) });
    i = j;
  }
  return out.length ? out : [{ text: s }];
}

/// Whether `label` matches every word of `query` (case-insensitive). Pure.
export function matches(label, query) {
  const l = String(label || "").toLowerCase();
  return String(query || "").toLowerCase().split(/\s+/).filter(Boolean).every((w) => l.includes(w));
}

let open = null; // the open palette's close function

/// Whether the command menu is open.
export function paletteOpen() { return !!open; }

/// Close the command menu if it is open.
export function closePalette() { open?.(); }

/// Open the command menu (or close it when it is already open, for ⌘K as a toggle).
export function openPalette({ query = "", debounce = 150 } = {}) {
  if (open) { open(); return; }
  const returnTo = document.activeElement;
  const listId = "os-cmdk-list";
  const input = h("input", {
    class: "os-cmdk__input", type: "text", value: query, autocomplete: "off", spellcheck: false,
    attrs: { role: "combobox", "aria-expanded": "true", "aria-controls": listId, "aria-autocomplete": "list", "aria-label": t("palette.input"), placeholder: t("palette.placeholder") },
  });
  const list = h("div", { class: "os-cmdk__list", id: listId, attrs: { role: "listbox", "aria-label": t("palette.results") } });
  const esc = h("button", { type: "button", class: "os-cmdk__esc", text: "esc", attrs: { "aria-label": t("action.close") } });
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
  const foot = h("div", { class: "os-cmdk__foot", attrs: { "aria-hidden": "true" } },
    h("span", {}, h("kbd", { text: "↑↓" }), t("palette.move")),
    h("span", {}, h("kbd", { text: "↵" }), t("palette.open")),
    h("span", {}, h("kbd", { text: mac ? "⌘K" : "Ctrl K" }), t("palette.toggle")));
  const dlg = h("dialog", { class: "os-cmdk", attrs: { "aria-label": t("palette.label"), "data-testid": "palette" } },
    h("div", { class: "os-cmdk__head" }, icon("os-search", { size: 16, stroke: 1.6 }), input, esc), list, foot);

  // ---- state -------------------------------------------------------------------------
  let sections = []; // [{p, state: "loading"|"done"|"error", items}]
  let activeKey = null;
  let seq = 0;
  let ctrl = null;
  let timer = null;
  let closed = false;
  const keyOf = (sec, it, i) => `${sec.p.id}:${it.id ?? i}`;
  const flat = () => sections.flatMap((sec) => (sec.state === "done" ? sec.items.map((it, i) => ({ sec, it, key: keyOf(sec, it, i) })) : []));

  function run(entry) {
    // The item may move focus itself (a dialog, a new screen); only when it leaves focus
    // nowhere does it go back to the opener.
    close(false);
    try { entry.it.run?.(); } catch { /* an item's own failure is its own to report */ }
    setTimeout(() => {
      const a = document.activeElement;
      if ((!a || a === document.body) && returnTo?.isConnected && !returnTo.closest("[inert]")) returnTo.focus({ preventScroll: true });
    }, reducedMotion() ? 0 : 160);
  }

  function render() {
    const q = input.value.trim();
    const entries = flat();
    if (!entries.some((e) => e.key === activeKey)) activeKey = entries[0]?.key ?? null;
    clear(list);
    let n = 0;
    for (const sec of sections) {
      if (sec.state === "done" && !sec.items.length) continue;
      if (sec.state === "error") continue;
      const titleId = `os-cmdk-g-${sec.p.id}`;
      const title = h("div", { id: titleId, class: `os-cmdk__title${sec.p.titleTone === "ml" ? " os-cmdk__title--ml" : ""}`, attrs: { role: "presentation" } },
        sec.p.icon ? icon(sec.p.icon, { size: 12, stroke: 1.6 }) : null, h("span", { text: sec.p.title }),
        sec.p.note ? h("span", { class: "os-cmdk__note", text: `· ${sec.p.note}` }) : null);
      const group = h("div", { class: "os-cmdk__group", attrs: { role: "group", "aria-labelledby": titleId } }, title);
      if (sec.state === "loading") {
        group.append(h("div", { class: "os-cmdk__skel", attrs: { "aria-hidden": "true" } }, h("span", { class: "os-skel os-skel--circle" }), h("span", { class: "os-skel os-skel--text" })));
        group.setAttribute("aria-busy", "true");
      } else {
        sec.items.forEach((it, i) => {
          const key = keyOf(sec, it, i);
          const id = `os-cmdk-o-${n++}`;
          const rich = !!(it.sub || it.snippet);
          const label = h("span", { class: "os-cmdk__label" });
          for (const r of markRuns(it.label, q)) label.append(r.mark ? h("mark", { text: r.text }) : document.createTextNode(r.text));
          const main = h("span", { class: "os-cmdk__main" }, label);
          if (it.snippet) {
            const sub = h("span", { class: "os-cmdk__sub" });
            for (const r of it.snippet) sub.append(r.mark ? h("mark", { text: String(r.text) }) : document.createTextNode(String(r.text)));
            main.append(sub);
          } else if (it.sub) main.append(h("span", { class: "os-cmdk__sub", text: it.sub }));
          const opt = h("div", {
            id, class: `os-cmdk__item${rich ? " os-cmdk__item--rich" : ""}`,
            attrs: { role: "option", "aria-selected": key === activeKey ? "true" : "false", "data-key": key },
          }, it.icon ? icon(it.icon, { size: 16 }) : null, main,
          it.hint ? h("span", { class: `os-cmdk__hint${it.hintTone === "you" ? " os-cmdk__hint--you" : ""}`, text: it.hint }) : null,
          it.kbd ? h("kbd", { text: it.kbd }) : null);
          opt.addEventListener("pointermove", () => { if (activeKey !== key) setActive(key, false); });
          opt.addEventListener("click", () => run({ sec, it, key }));
          group.append(opt);
        });
      }
      list.append(group);
    }
    const busy = sections.some((s) => s.state === "loading");
    list.setAttribute("aria-busy", busy ? "true" : "false");
    if (!entries.length && !busy) list.append(h("div", { class: "os-cmdk__empty", attrs: { role: "status", "data-testid": "palette-empty" }, text: q ? t("palette.none", { query: q }) : t("palette.nothing") }));
    syncActive(true);
  }

  function syncActive(scroll) {
    const opts = [...list.querySelectorAll('[role="option"]')];
    let cur = null;
    for (const o of opts) {
      const on = o.dataset.key === activeKey;
      o.setAttribute("aria-selected", on ? "true" : "false");
      if (on) cur = o;
    }
    if (cur) {
      input.setAttribute("aria-activedescendant", cur.id);
      if (scroll) cur.scrollIntoView({ block: "nearest" });
    } else input.removeAttribute("aria-activedescendant");
  }
  function setActive(key, scroll = true) { activeKey = key; syncActive(scroll); }
  function move(by) {
    const keys = flat().map((e) => e.key);
    if (!keys.length) return;
    const i = keys.indexOf(activeKey);
    setActive(keys[(i + by + keys.length) % keys.length]);
  }

  function search() {
    const q = input.value.trim();
    const mine = ++seq;
    ctrl?.abort();
    ctrl = typeof AbortController === "function" ? new AbortController() : null;
    const signal = ctrl?.signal;
    sections = paletteProviders().map((p) => ({ p, state: "loading", items: [] }));
    for (const sec of sections) {
      let res;
      try { res = sec.p.search(q, signal); } catch { sec.state = "error"; continue; }
      if (!res || typeof res.then !== "function") { sec.state = "done"; sec.items = Array.isArray(res) ? res : []; continue; }
      res.then((items) => {
        if (mine !== seq || closed) return;
        sec.state = "done";
        sec.items = Array.isArray(items) ? items : [];
        render();
      }, () => {
        if (mine !== seq || closed) return;
        sec.state = "error";
        render();
      });
    }
    render();
  }

  input.addEventListener("input", () => {
    // Synchronous sections answer at once; the slower ones wait for typing to pause.
    clearTimeout(timer);
    timer = setTimeout(search, debounce);
    // Keep showing results while typing: re-filter the synchronous sections now.
    const q = input.value.trim();
    for (const sec of sections) {
      const res = (() => { try { return sec.p.sync ? sec.p.search(q, null) : null; } catch { return null; } })();
      if (Array.isArray(res)) { sec.state = "done"; sec.items = res; }
    }
    render();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Home" && flat().length) { e.preventDefault(); setActive(flat()[0].key); }
    else if (e.key === "End" && flat().length) { e.preventDefault(); setActive(flat().at(-1).key); }
    else if (e.key === "Enter") {
      e.preventDefault();
      clearTimeout(timer);
      const entry = flat().find((x) => x.key === activeKey);
      if (entry) run(entry);
    } else if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) { e.preventDefault(); close(); }
  });
  esc.addEventListener("click", () => close());
  dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(); });
  dlg.addEventListener("click", (e) => { if (e.target === dlg) close(); });

  function close(restore = true) {
    if (closed) return;
    closed = true;
    open = null;
    clearTimeout(timer);
    ctrl?.abort();
    dlg.classList.add("is-leaving");
    const done = () => {
      if (dlg.open) dlg.close();
      dlg.remove();
      if (restore && returnTo?.isConnected) returnTo.focus?.({ preventScroll: true });
    };
    if (reducedMotion()) done(); else setTimeout(done, 120);
  }
  open = close;

  document.body.append(dlg);
  dlg.showModal();
  input.focus();
  input.select();
  search();
  return close;
}
