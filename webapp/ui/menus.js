// Menus, tabs and the drawer of the component library (WEB-02 redesign). The ARIA
// menu-button, tabs and dialog patterns: arrow keys, Home, End, Escape, focus return.

import { h, clear } from "../dom.js";
import { icon } from "../icons.js";
import { t } from "../i18n.js";
import { button } from "./core.js";

const open = new Set();
document.addEventListener("click", (e) => { for (const m of [...open]) if (!m.contains(e.target)) m.close(); });

/// A menu button. `items()` returns entries `{label, icon, run, danger?}` or nodes
/// (shown as they are, e.g. a header). The trigger is `trigger` (an existing button)
/// or a new button from `label`/`buttonOpts`. Returns the wrapper element.
export function menuButton({ label, items, trigger = null, buttonOpts = {}, align = "end", menuLabel = label, menuClass = "" }) {
  const wrap = h("div", { class: "os-menu-wrap" });
  const btn = trigger || button(label, buttonOpts);
  btn.setAttribute("aria-haspopup", "menu");
  btn.setAttribute("aria-expanded", "false");
  const list = h("div", { class: `os-menu os-menu--${align} ${menuClass}`.trim(), attrs: { role: "menu", "aria-label": menuLabel }, hidden: true });
  wrap.append(btn, list);
  wrap.close = (focus = false) => {
    if (list.hidden) return;
    list.hidden = true;
    btn.setAttribute("aria-expanded", "false");
    open.delete(wrap);
    if (focus) btn.focus();
  };
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (!list.hidden) return wrap.close();
    for (const m of [...open]) m.close();
    clear(list);
    for (const it of items()) {
      if (!it) continue;
      if (it instanceof Node) { list.append(it); continue; }
      const b = h("button", { type: "button", class: `os-menu__item${it.danger ? " os-menu__item--danger" : ""}`, attrs: { role: "menuitem", tabindex: "-1" } },
        it.icon ? icon(it.icon, { size: 16 }) : null, h("span", { text: it.label }));
      b.addEventListener("click", (ev) => { ev.stopPropagation(); wrap.close(); it.run(); });
      list.append(b);
    }
    list.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    open.add(wrap);
    const entries = [...list.querySelectorAll('[role="menuitem"]')];
    entries[0]?.focus();
    list.onkeydown = (ev) => {
      const i = entries.indexOf(document.activeElement);
      if (ev.key === "ArrowDown") { ev.preventDefault(); entries[(i + 1) % entries.length].focus(); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); entries[(i - 1 + entries.length) % entries.length].focus(); }
      else if (ev.key === "Home") { ev.preventDefault(); entries[0].focus(); }
      else if (ev.key === "End") { ev.preventDefault(); entries[entries.length - 1].focus(); }
      else if (ev.key === "Escape" || ev.key === "Tab") wrap.close(ev.key === "Escape");
    };
  });
  return wrap;
}

/// Tabs: `tabs` are `{id, label, icon?}`; `render(id, panel)` fills the panel when a
/// tab is chosen. Arrow keys move between tabs (automatic activation).
export function tabs({ label, tabs: list, current, render, onChange = null }) {
  const bar = h("div", { class: "os-tabs", attrs: { role: "tablist", "aria-label": label } });
  const panel = h("div", { class: "os-tabpanel", attrs: { role: "tabpanel", tabindex: "0" } });
  const btns = list.map((tb) => {
    const b = h("button", { type: "button", class: "os-tab", id: `tab-${tb.id}`, attrs: { role: "tab", "aria-controls": "", "data-tab": tb.id } },
      tb.icon ? icon(tb.icon, { size: 16 }) : null, h("span", { text: tb.label }));
    b.addEventListener("click", () => pick(tb.id));
    b.addEventListener("keydown", (e) => {
      const i = list.indexOf(tb);
      const to = e.key === "ArrowRight" ? list[(i + 1) % list.length] : e.key === "ArrowLeft" ? list[(i - 1 + list.length) % list.length] : null;
      if (to) { e.preventDefault(); pick(to.id); bar.querySelector(`[data-tab="${to.id}"]`).focus(); }
    });
    bar.append(b);
    return b;
  });
  panel.id = `panel-${Math.random().toString(36).slice(2)}`;
  for (const b of btns) b.setAttribute("aria-controls", panel.id);
  function pick(id) {
    for (const b of btns) {
      const on = b.dataset.tab === id;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      if (on) panel.setAttribute("aria-labelledby", b.id);
    }
    clear(panel);
    render(id, panel);
    onChange?.(id);
  }
  pick(current || list[0].id);
  return h("div", { class: "os-tabset" }, bar, panel);
}

/// A drawer from the right edge: a modal `<dialog>` (focus trap, Escape, inert
/// background). `build(body, close)` fills it. Resolves when closed.
export function drawer({ title, build }) {
  return new Promise((resolve) => {
    const returnTo = document.activeElement;
    const id = `dr-${Math.random().toString(36).slice(2)}`;
    const dlg = h("dialog", { class: "os-drawer", attrs: { "aria-labelledby": id } });
    const body = h("div", { class: "os-drawer__body" });
    const close = (v = null) => { dlg.close(); dlg.remove(); returnTo?.focus?.({ preventScroll: true }); resolve(v); };
    dlg.append(h("div", { class: "os-drawer__head" }, h("h2", { id, class: "os-dialog__title", text: title }),
      button(t("action.close"), { icon: "x", variant: "ghost", size: "sm", iconOnly: true, onClick: () => close(null) })), body);
    build(body, close);
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
    dlg.addEventListener("click", (e) => { if (e.target === dlg) close(null); });
    document.body.append(dlg);
    dlg.showModal();
  });
}
