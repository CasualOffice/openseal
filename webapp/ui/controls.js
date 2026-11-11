// Form controls and small parts of the component library (WEB-02 redesign; docs/47
// §As built: components). Every screen builds these through `webapp/ui/index.js`;
// none writes its own markup for them. Strings go in as text, never markup.

import { h } from "../dom.js";
import { icon } from "../icons.js";
import { button } from "./core.js";

let seq = 0;
const uid = (p) => `${p}-${++seq}`;

/// An icon-only button with its name as the accessible label and a tooltip.
export function iconButton(label, ic, { onClick = null, size = "md", variant = "ghost", attrs = {} } = {}) {
  const b = button(label, { icon: ic, size, variant, iconOnly: true, onClick, attrs });
  return tooltip(b, label);
}

/// A labelled text field: label above, input, optional help, error below (empty until
/// set). Returns `{el, input, setError(text)}`.
export function field(label, { id = uid("f"), type = "text", value = "", help = null, required = false, placeholder = null, maxLength = null, autocomplete = "off", inputMode = null, multiline = false, rows = 4, attrs = {}, onInput = null } = {}) {
  const helpId = help ? `${id}-help` : null;
  const errId = `${id}-err`;
  const input = h(multiline ? "textarea" : "input", {
    id, class: `os-input${multiline ? " os-textarea" : ""}`, value, autocomplete, inputMode, maxLength,
    ...(multiline ? { rows } : { type }),
    placeholder,
    attrs: { "aria-describedby": [helpId, errId].filter(Boolean).join(" "), ...(required ? { "aria-required": "true" } : {}), ...attrs },
  });
  if (onInput) input.addEventListener("input", () => onInput(input.value));
  const err = h("p", { id: errId, class: "os-field-error", attrs: { "aria-live": "polite" } });
  const el = h("div", { class: "os-fieldrow" },
    h("label", { class: "os-label", attrs: { for: id }, text: label }), input,
    help ? h("p", { id: helpId, class: "os-help", text: help }) : null, err);
  return {
    el, input,
    setError(text) {
      err.textContent = text || "";
      if (text) input.setAttribute("aria-invalid", "true"); else input.removeAttribute("aria-invalid");
    },
  };
}

/// A labelled select: `options` are `[value, label]`. Returns `{el, select}`.
export function selectField(label, options, { id = uid("s"), value = null, help = null, onChange = null, labelHidden = false, size = "md", attrs = {} } = {}) {
  const select = h("select", { id, class: `os-input os-select${size === "sm" ? " os-input--sm" : ""}`, attrs }, ...options.map(([v, l]) => h("option", { value: v, text: l, selected: v === value })));
  if (onChange) select.addEventListener("change", () => onChange(select.value));
  const el = h("div", { class: "os-fieldrow" },
    h("label", { class: labelHidden ? "os-sr-only" : "os-label", attrs: { for: id }, text: label }), select,
    help ? h("p", { class: "os-help", text: help }) : null);
  return { el, select };
}

/// A checkbox with its label. Returns `{el, input}`.
export function checkbox(label, { id = uid("c"), checked = false, onChange = null, large = false, attrs = {} } = {}) {
  const input = h("input", { id, type: "checkbox", class: "os-checkbox", checked, attrs });
  if (onChange) input.addEventListener("change", () => onChange(input.checked));
  return { el: h("label", { class: `os-check${large ? " os-check--lg" : ""}`, attrs: { for: id } }, input, h("span", { text: label })), input };
}

/// Radio buttons in a fieldset with a legend: `options` are `[value, label]`.
export function radioGroup(legend, options, { name = uid("r"), value = null, onChange = null } = {}) {
  const fs = h("fieldset", { class: "os-radios" }, h("legend", { class: "os-label", text: legend }));
  for (const [v, l] of options) {
    const id = `${name}-${v}`;
    const input = h("input", { id, type: "radio", name, value: v, checked: v === value });
    if (onChange) input.addEventListener("change", () => { if (input.checked) onChange(v); });
    fs.append(h("label", { class: "os-radio", attrs: { for: id } }, input, h("span", { text: l })));
  }
  return fs;
}

/// An on/off switch (`role="switch"` on a checkbox). Returns `{el, input}`.
export function toggle(label, { id = uid("t"), checked = false, onChange = null } = {}) {
  const input = h("input", { id, type: "checkbox", class: "os-switch__input", checked, attrs: { role: "switch" } });
  if (onChange) input.addEventListener("change", () => onChange(input.checked));
  return { el: h("label", { class: "os-switch", attrs: { for: id } }, input, h("span", { class: "os-switch__track", attrs: { "aria-hidden": "true" } }), h("span", { text: label })), input };
}

/// A soft-tinted pill with an icon and a word (status is never colour alone).
export function pill(text, { tone = "neutral", ic = null } = {}) {
  return h("span", { class: `os-badge os-badge--${tone}` }, ic ? icon(ic, { size: 16 }) : null, h("span", { text }));
}

/// A card: optional title (h2 by default) and actions in its head, then the body.
export function card({ title = null, level = 2, actions = null, flush = false, labelId = uid("card"), testId = null } = {}, ...body) {
  const head = title || actions ? h("div", { class: "os-card__head" },
    title ? h(`h${level}`, { id: labelId, class: "os-card__title", text: title }) : null, actions) : null;
  return h("section", { class: `os-card${flush ? " os-card--flush" : ""}`, attrs: { ...(title ? { "aria-labelledby": labelId } : {}), "data-testid": testId } }, head, ...body);
}

/// A data table: `columns` are `{label, className?, hidden?}`; `rows` are arrays of
/// cells (node or string) or `{cells, attrs, onOpen}`. Wrapped for horizontal scroll.
export function table({ caption, columns, rows, className = "" }) {
  const t = h("table", { class: `os-table ${className}`.trim() },
    h("caption", { class: "os-sr-only", text: caption }),
    h("thead", {}, h("tr", {}, ...columns.map((c) => h("th", { attrs: { scope: "col" }, class: c.className || null }, c.hidden ? h("span", { class: "os-sr-only", text: c.label }) : c.label)))));
  const tb = h("tbody");
  for (const r of rows) {
    const spec = Array.isArray(r) ? { cells: r } : r;
    const tr = h("tr", { class: spec.onOpen ? "os-row" : null, attrs: spec.attrs || {} }, ...spec.cells.map((c, i) => h("td", { class: columns[i]?.className || null }, c)));
    if (spec.onOpen) tr.addEventListener("click", (e) => { if (!e.target.closest("a, button, input, select, .os-menu")) spec.onOpen(); });
    tb.append(tr);
  }
  t.append(tb);
  return h("div", { class: "os-table-wrap" }, t);
}

/// An avatar: initials in a circle, decorative (the control around it is named).
export function avatar(initials) {
  return h("span", { class: "os-avatar", attrs: { "aria-hidden": "true" }, text: initials || "" });
}

/// A tooltip for `el`: the name shown on hover and keyboard focus, after a short delay.
export function tooltip(el, text) {
  el.classList.add("os-has-tip");
  el.dataset.tip = text;
  el.removeAttribute("title");
  return el;
}

/// A numbered step bar. `steps` are `{id, label}`; `onPick(id)`. Returns `{el, set(id, doneIds)}`.
export function stepper(steps, { label, onPick }) {
  const ol = h("ol", { class: "os-stepper", attrs: { "aria-label": label } });
  const btns = new Map();
  steps.forEach((s, i) => {
    const b = h("button", { type: "button", class: "os-stepper__btn", attrs: { "data-step": s.id } },
      h("span", { class: "os-stepper__n", text: String(i + 1) }), h("span", { class: "os-stepper__label", text: s.label }));
    b.addEventListener("click", () => onPick(s.id));
    btns.set(s.id, b);
    ol.append(h("li", {}, b));
  });
  return {
    el: ol,
    set(current) {
      const idx = steps.findIndex((s) => s.id === current);
      steps.forEach((s, i) => {
        const b = btns.get(s.id);
        if (s.id === current) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
        b.classList.toggle("is-done", i < idx);
      });
    },
  };
}
