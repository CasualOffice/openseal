// Form controls and small parts of the component library (WEB-02 redesign; docs/47
// §As built: components). Every screen builds these through `webapp/ui/index.js`;
// none writes its own markup for them. Strings go in as text, never markup.

import { h, initials as initialsOf } from "../dom.js";
import { icon } from "../icons.js";
import { t } from "../i18n.js";
import { button, busy, toastError } from "./core.js";
import { isLowConfidence, percent } from "../ml.js";

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
export function toggle(label, { id = uid("t"), checked = false, onChange = null, tone = null } = {}) {
  const input = h("input", { id, type: "checkbox", class: "os-switch__input", checked, attrs: { role: "switch" } });
  if (onChange) input.addEventListener("change", () => onChange(input.checked));
  return { el: h("label", { class: `os-switch${tone === "ml" ? " os-switch--ml" : ""}`, attrs: { for: id } }, input, h("span", { class: "os-switch__track", attrs: { "aria-hidden": "true" } }), h("span", { text: label })), input };
}

/// A switch button (canvas Intelligence): `role="switch"` with `aria-checked`, a spring
/// knob, named by `label` (shown elsewhere, e.g. a card's title). `tone: "ml"` is violet.
/// `onChange(on)` may return a promise: the switch is busy until it settles and goes back
/// when it rejects. Returns `{el, set(on), get()}`.
export function switchButton(label, { checked = false, onChange = null, tone = null, disabled = false, attrs = {} } = {}) {
  let on = !!checked;
  const el = h("button", { type: "button", class: `os-switchbtn${tone === "ml" ? " os-switchbtn--ml" : ""}`, disabled, attrs: { role: "switch", "aria-checked": String(on), "aria-label": label, ...attrs } });
  const set = (v) => { on = !!v; el.setAttribute("aria-checked", String(on)); };
  el.addEventListener("click", async () => {
    const was = on;
    set(!on);
    if (!onChange) return;
    try { await busy(el, () => onChange(on)); } catch (err) { set(was); toastError(err); }
  });
  return { el, set, get: () => on };
}

const AVATAR_TONES = 4;

/// Overlapping avatars (canvas rows): initials of each name, at most `max`, then "+n".
/// Decorative; the row carries the names as text.
export function avatarStack(names, { max = 3 } = {}) {
  const list = (names || []).filter(Boolean);
  const wrap = h("span", { class: "os-avatars", attrs: { "aria-hidden": "true" } });
  list.slice(0, max).forEach((n, i) => wrap.append(h("span", { class: `os-avatar os-avatar--c${(i % AVATAR_TONES) + 1}`, text: initialsOf(n) })));
  if (list.length > max) wrap.append(h("span", { class: "os-avatar os-avatars__more", text: `+${list.length - max}` }));
  return wrap;
}

/// A status pill in the canvas's four tones (`you`, `wait`, `done`, `draft`; also
/// `danger`, `warning`, `info`, `ml`), with a dot or an icon; text, never colour alone.
export function statusPill(text, { tone = "draft", dot = false, ic = null } = {}) {
  return h("span", { class: `os-badge os-badge--${tone}${dot ? " os-badge--dot" : ""}` }, ic ? icon(ic, { size: 14 }) : null, h("span", { text }));
}

/// A progress ring (canvas signer guide): `value` of `total`, drawn in SVG, with the
/// count inside. `tone`: accent (default), `ml` or `done`. Returns `{el, set(value, total)}`.
export function progressRing({ value = 0, total = 1, size = 36, stroke = 3, tone = null, label = null } = {}) {
  const NS = "http://www.w3.org/2000/svg";
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const svg = document.createElementNS(NS, "svg");
  for (const [k, v] of Object.entries({ width: size, height: size, viewBox: `0 0 ${size} ${size}`, "aria-hidden": "true", focusable: "false" })) svg.setAttribute(k, String(v));
  const mk = (cls) => {
    const n = document.createElementNS(NS, "circle");
    for (const [k, v] of Object.entries({ cx: size / 2, cy: size / 2, r, "stroke-width": stroke, class: cls })) n.setAttribute(k, String(v));
    return n;
  };
  const bar = mk("os-ring__bar");
  bar.setAttribute("stroke-dasharray", String(c));
  bar.setAttribute("transform", `rotate(-90 ${size / 2} ${size / 2})`);
  svg.append(mk("os-ring__track"), bar);
  const text = h("span", { class: "os-ring__label", attrs: { "aria-hidden": "true" } });
  const el = h("span", { class: `os-ring${tone ? ` os-ring--${tone}` : ""}`, attrs: { role: "progressbar", "aria-valuemin": "0" } }, svg, text);
  el.style.width = `${size / 16}rem`;
  el.style.height = `${size / 16}rem`;
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "100%");
  function set(v, tot = total) {
    total = Math.max(1, tot);
    const n = Math.min(total, Math.max(0, v));
    bar.setAttribute("stroke-dashoffset", String(c * (1 - n / total)));
    text.textContent = `${n}/${total}`;
    el.setAttribute("aria-valuemax", String(total));
    el.setAttribute("aria-valuenow", String(n));
    el.setAttribute("aria-valuetext", t("ml.progress", { done: n, total }));
    if (label) el.setAttribute("aria-label", label);
  }
  set(value, total);
  return { el, set };
}

/// The heading of a model-suggestions area (canvas Insights): a violet sparkle, "Suggested
/// from the document", and where it ran.
export function mlHeading({ title = t("ml.title"), sub = t("ml.sub") } = {}) {
  return h("div", { class: "os-ml-head" },
    h("span", { class: "os-ml-mark", attrs: { "aria-hidden": "true" } }, icon("os-sparkle", { size: 14 })),
    h("span", { class: "os-ml-head__text" }, h("b", { class: "os-ml-head__title", text: title }), sub ? h("span", { class: "os-ml-head__sub", text: sub }) : null));
}

/// A model suggestion card (WEB-18; canvas Insights): its label, its confidence ("check
/// this" under 75 %), its value, the page it came from, and Save / Dismiss. `s` is a
/// suggestion as `GET …/suggestions` answers it. `onAccept()` and `onDismiss()` return
/// promises (ml.js's optimistic store); the card shows the decided state from `s.state`
/// and `update(s)` redraws it. Returns `{el, update(s)}`.
export function suggestion(s, { onAccept = null, onDismiss = null, acceptLabel = t("ml.save"), dismissLabel = t("ml.dismiss"), acceptedText = t("ml.accepted"), testId = null } = {}) {
  const el = h("div", { class: "os-sugg", attrs: { "data-testid": testId || "suggestion", "data-suggestion": s.id } });
  function update(next) {
    s = next;
    const state = s.state || "open";
    const low = isLowConfidence(s);
    el.className = `os-sugg${low ? " is-low" : ""}${state === "accepted" ? " is-accepted" : state === "dismissed" ? " is-dismissed" : ""}`;
    el.replaceChildren(
      h("div", { class: "os-sugg__head" },
        h("span", { class: "os-sugg__label", text: s.label || "" }),
        h("span", { class: "os-sugg__conf", text: low ? t("ml.check", { pct: percent(s) }) : percent(s) })),
      h("span", { class: "os-sugg__value", text: s.value ?? s.normalized ?? "" }));
    if (state === "open") {
      const acts = h("div", { class: "os-sugg__actions" });
      if (onAccept) acts.append(button(acceptLabel, { variant: "strong", size: "sm", onClick: () => onAccept(s), attrs: { "data-testid": "suggestion-accept" } }));
      if (onDismiss) acts.append(button(dismissLabel, { variant: "ghost", size: "sm", onClick: () => onDismiss(s), attrs: { "data-testid": "suggestion-dismiss" } }));
      if (s.page) acts.append(h("span", { class: "os-sugg__page", text: t("ml.page", { n: s.page }) }));
      el.append(acts);
    } else {
      el.append(h("span", { class: "os-sugg__decided", attrs: { role: "status" }, text: state === "accepted" ? acceptedText : t("ml.dismissed") }));
    }
  }
  update(s);
  return { el, update };
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
