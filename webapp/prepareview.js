// The prepare editor's view pieces on the approved canvas (WEB-17 lane B;
// docs/assets/design-canvas/Editor.dc.html, docs/47 §As built: the prepare editor on the
// canvas). Each builder takes what to show and the callbacks to run, and returns DOM;
// none of them holds state or decides a rule (preparemodel.js decides, prepare.js wires).
// Text goes in by `textContent` (h's `text`); styles come from prepare.css classes and,
// for a recipient's colour, the `os-rN` class that sets `--rc`.

import { h } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { TOOL_KEYS } from "./preparemodel.js";

const NS = "http://www.w3.org/2000/svg";

/// An inline SVG from path data (the canvas's sparkle and template marks, which the
/// vendored icon set lacks). Decorative.
export function glyph(paths, { size = "1rem", fill = "none", stroke = "currentColor", width = 1.6, className = "" } = {}) {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("width", size);
  s.setAttribute("height", size);
  s.setAttribute("fill", fill);
  s.setAttribute("aria-hidden", "true");
  s.setAttribute("focusable", "false");
  if (className) s.setAttribute("class", className);
  if (fill === "none") { s.setAttribute("stroke", stroke); s.setAttribute("stroke-width", String(width)); }
  for (const d of paths) {
    const [tag, attrs] = typeof d === "string" ? ["path", { d }] : d;
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    s.append(el);
  }
  return s;
}
/// The canvas's sparkle: model work (Detect fields, suggestions).
export const sparkle = (size = "0.875rem") => glyph(["M12 2l1.8 6.2L20 10l-6.2 1.8L12 18l-1.8-6.2L4 10l6.2-1.8z"], { size, fill: "currentColor" });
/// The canvas's spinner arc.
export const spinner = (size = "0.875rem") => glyph(["M21 12a9 9 0 1 1-6.2-8.56"], { size, width: 2.4, className: "os-spin" });
/// The canvas's template-match mark.
const templateMark = () => glyph([["rect", { x: "4", y: "4", width: "7", height: "7", rx: "1.5" }], ["rect", { x: "13", y: "4", width: "7", height: "7", rx: "1.5" }], ["rect", { x: "4", y: "13", width: "7", height: "7", rx: "1.5" }], "M14 17.5l2 2 4-4"]);

/// A short glyph per field kind, as the canvas's library chips show them (text, so the
/// chip reads in any font; decorative, the button names the kind).
export const KIND_GLYPH = {
  signature: "✍", initials: "AB", date_signed: "◷", name: "Aa", email: "@", company: "▦", title: "Tt",
  text: "T", number: "#", checkbox: "☑", radio_group: "◉", dropdown: "▾", attachment: "⎘", note: "i", select: "↖",
};

/// The segmented step control: one button per step, done ones ticked, the current one
/// raised (`aria-current="step"`). `onPick(step)`.
export function stepControl(steps, labelOf, onPick) {
  const btns = new Map();
  const ol = h("ol", { class: "os-stepper os-segsteps", attrs: { "aria-label": t("wizard.steps") } });
  steps.forEach((s, i) => {
    const b = h("button", { type: "button", class: "os-stepper__btn", attrs: { "data-step": s, title: t(labelOf(s)) } },
      h("span", { class: "os-stepper__n", attrs: { "aria-hidden": "true" } }),
      h("span", { class: "os-stepper__label", text: t(labelOf(s)) }),
      h("span", { class: "os-sr-only os-stepper__state" }));
    b.dataset.n = String(i + 1);
    b.addEventListener("click", () => onPick(s));
    btns.set(s, b);
    ol.append(h("li", {}, b));
  });
  /// Mark from `states` (preparemodel.js stepStates).
  function sync(states) {
    for (const st of states) {
      const b = btns.get(st.step);
      if (st.current) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
      b.classList.toggle("is-done", st.done);
      b.querySelector(".os-stepper__n").textContent = st.done ? "✓" : "";
      b.querySelector(".os-stepper__state").textContent = st.done ? ` ${t("wizard.step-done")}` : "";
    }
  }
  return { el: ol, sync };
}

/// One row of the recipients list: colour chip with the number, name and role line, field
/// count. A radio (the group is "Placing fields for"): its name is the recipient's name.
export function recipientRow({ key, n, colour, name, role, count, on, onPick, onKey }) {
  const descId = `prc-${key}`;
  const b = h("button", { type: "button", class: `os-prc os-r${colour}${on ? " is-on" : ""}`, attrs: { role: "radio", "aria-checked": String(on), tabindex: on ? "0" : "-1", "aria-label": name, "aria-describedby": descId, "data-rkey": key, title: t("prepare.placing-key", { n }) } },
    h("span", { class: "os-prc__chip", attrs: { "aria-hidden": "true" }, text: String(n) }),
    h("span", { class: "os-prc__main" }, h("span", { class: "os-prc__name", text: name }),
      h("span", { id: descId, class: "os-prc__role" }, role, h("span", { class: "os-sr-only", text: `, ${t(count === 1 ? "prepare.fields-one" : "prepare.fields-n", { n: count })}` }))),
    h("span", { class: "os-prc__count", attrs: { "aria-hidden": "true" }, text: String(count) }));
  b.addEventListener("click", onPick);
  b.addEventListener("keydown", onKey);
  return b;
}

/// One library row: the kind's chip in the current recipient's colour, its name and its
/// key. The button is named "Add <kind> field" (the visible name inside it).
export function libraryItem(type, key) {
  return h("button", { type: "button", class: "os-palette__item os-lib", draggable: true, attrs: { "data-field-type": type, "data-os-command": `field.add-${type}`, "aria-pressed": "false", "aria-label": t("prepare.add-field", { type: t(`ftype.${type}`) }), "aria-keyshortcuts": key || null } },
    h("span", { class: "os-lib__chip", attrs: { "aria-hidden": "true" }, text: KIND_GLYPH[type] || "T" }),
    h("span", { class: "os-lib__label", text: t(`ftype.${type}`) }),
    key ? h("kbd", { class: "os-lib__key", attrs: { "aria-hidden": "true" }, text: key }) : null);
}

/// One tool on the floating bar (Select or a kind), named with its key.
export function toolButton(tool, onClick) {
  const name = tool === "select" ? t("prepare.tool-select") : t(`ftype.${tool}`);
  const label = t("prepare.tool-key", { name, key: TOOL_KEYS[tool] });
  const b = h("button", { type: "button", class: "os-tool", attrs: { "aria-label": label, title: label, "aria-pressed": "false", "data-tool": tool, "aria-keyshortcuts": TOOL_KEYS[tool] } },
    h("span", { attrs: { "aria-hidden": "true" }, text: KIND_GLYPH[tool] }));
  b.addEventListener("click", onClick);
  return b;
}

/// The dark hint chip while a kind is armed: "Click on the page to place <kind> for <name> · Esc".
export function armHint({ kind, who, colour, onCancel }) {
  const cancel = h("button", { type: "button", class: "os-chip-btn", text: t("prepare.esc"), attrs: { "aria-label": t("prepare.disarm") } });
  cancel.addEventListener("click", onCancel);
  return h("div", { class: `os-floathint os-r${colour}`, attrs: { "data-testid": "arm-hint" } },
    h("span", { class: "os-floathint__dot", attrs: { "aria-hidden": "true" } }),
    h("span", { class: "os-floathint__text" }, t("prepare.hint-place-a"), h("b", { text: kind }), t("prepare.hint-place-b", { name: who })),
    cancel);
}

/// The floating "N suggested fields for <name> · Accept all · Dismiss all" bar.
export function ghostBar({ n, who, onAccept, onDismiss }) {
  const accept = h("button", { type: "button", class: "os-pillbtn os-pillbtn--ml", text: t("prepare.accept-all"), attrs: { "data-testid": "accept-all" } });
  const dismiss = h("button", { type: "button", class: "os-pillbtn os-pillbtn--ghost", text: t("prepare.dismiss-all"), attrs: { "data-testid": "dismiss-all" } });
  accept.addEventListener("click", onAccept);
  dismiss.addEventListener("click", onDismiss);
  return h("div", { class: "os-ghostbar", attrs: { role: "group", "aria-label": t("prepare.suggested-n", { n }), "data-testid": "suggestions" } },
    h("span", { class: "os-ghostbar__mark" }, sparkle()),
    h("span", { class: "os-ghostbar__text" }, h("b", { text: t(n === 1 ? "prepare.suggested-one" : "prepare.suggested-n", { n }) }), h("span", { class: "os-muted", text: ` ${t("prepare.suggested-for", { name: who })}` })),
    accept, dismiss);
}

/// The template-match banner: "Looks like your “<name>” template · 96% match · apply its N
/// roles and M fields", Apply template and Not now.
export function templateBanner({ name, pct, roles, fields, onApply, onSkip }) {
  const apply = h("button", { type: "button", class: "os-btn os-btn--ml os-btn--md", text: t("prepare.tpl-apply"), attrs: { "data-testid": "tpl-apply" } });
  const skip = h("button", { type: "button", class: "os-btn os-btn--ghost os-btn--md", text: t("prepare.tpl-skip"), attrs: { "data-testid": "tpl-skip" } });
  apply.addEventListener("click", onApply);
  skip.addEventListener("click", onSkip);
  return h("div", { class: "os-tplbanner", attrs: { role: "status", "data-testid": "tpl-banner" } },
    h("span", { class: "os-tplbanner__mark" }, templateMark()),
    h("span", { class: "os-tplbanner__text" },
      h("b", { text: t("prepare.tpl-looks", { name }) }),
      h("span", { text: t("prepare.tpl-detail", { pct, roles, fields }) })),
    apply, skip);
}

/// The dark "Applied “<name>”: N fields placed · Undo" chip.
export function appliedChip({ name, n, onUndo }) {
  const undo = h("button", { type: "button", class: "os-chip-btn", text: t("cmd.edit.undo"), attrs: { "data-testid": "tpl-undo" } });
  undo.addEventListener("click", onUndo);
  return h("div", { class: "os-appliedchip", attrs: { role: "status", "data-testid": "tpl-applied" } },
    h("span", { class: "os-appliedchip__tick", attrs: { "aria-hidden": "true" }, text: "✓" }),
    h("span", { text: t("prepare.tpl-applied", { name, n }) }), undo);
}

/// The page skeleton while the documents render: "Preparing n pages…".
export function loadingPage(n) {
  const lines = [["w8", "s"], ["w60", "l"], ["w100"], ["w94"], ["w82"], ["w100", "gap"], ["w90"], ["w70"]];
  return h("div", { class: "os-prepload", attrs: { "aria-busy": "true", "aria-label": t("prepare.preparing-label"), "data-testid": "prepare-loading" } },
    ...lines.map((c) => h("span", { class: `os-prepload__line os-shimmer ${c.map((x) => `is-${x}`).join(" ")}`, attrs: { "aria-hidden": "true" } })),
    h("div", { class: "os-prepload__chip", attrs: { role: "status" } }, spinner(), h("span", { text: n ? t(n === 1 ? "prepare.preparing-one" : "prepare.preparing-n", { n }) : t("prepare.preparing") })));
}

/// The right panel's "Ready to send?" checks, from preparemodel.js sendChecks.
export function checksList(checks) {
  return h("ul", { class: "os-checks", attrs: { "data-testid": "send-checks" } },
    ...checks.map((c) => h("li", { class: `os-check-item os-rise${c.ok ? " is-ok" : " is-warn"}` },
      h("span", { class: "os-check-item__mark", attrs: { "aria-hidden": "true" }, text: c.ok ? "✓" : "!" }),
      c.ok ? null : h("span", { class: "os-sr-only", text: `${t("prepare.check-warn")} ` }),
      h("span", { text: t(c.key, c.params) }))));
}

/// The amber personal-data card (ML personal_data suggestions; preparemodel.js piiSummary).
/// Reports what the model suggested, by label and count, never the values themselves.
export function piiCard(sum, { onReview = null } = {}) {
  const what = sum.labels.map(([label, n]) => (n > 1 ? `${n} × ${label}` : label)).join(", ");
  const review = onReview ? h("button", { type: "button", class: "os-piicard__btn", text: t("prepare.pii-review"), attrs: { "data-testid": "pii-review" } }) : null;
  review?.addEventListener("click", onReview);
  return h("div", { class: "os-piicard", attrs: { "data-testid": "pii-card" } },
    h("b", { text: sum.page ? t("prepare.pii-title", { page: sum.page }) : t("prepare.pii-title-doc") }),
    h("span", { text: `${what}. ${t("prepare.pii-text")}` }),
    review);
}

/// "Assigned to": one button per recipient who can take the field, the owner ticked.
export function assignList(people, onPick) {
  return h("div", { class: "os-assign", attrs: { role: "radiogroup", "aria-labelledby": "fp-assign-h" } },
    ...people.map((p) => {
      const b = h("button", { type: "button", class: `os-assign__item os-r${p.colour}${p.on ? " is-on" : ""}`, attrs: { role: "radio", "aria-checked": String(p.on), "data-rkey": p.key } },
        h("span", { class: "os-assign__dot", attrs: { "aria-hidden": "true" } }),
        h("span", { class: "os-trunc", text: p.name }),
        h("span", { class: "os-assign__mark", attrs: { "aria-hidden": "true" }, text: p.on ? "✓" : "" }));
      b.addEventListener("click", () => onPick(p.key));
      return b;
    }));
}

/// The page thumbnails' OCR badges (scanned pages, read by OCR), added to docview's
/// thumbnails by index. `pages` are 1-based laid-out page numbers.
export function markOcr(thumbsBox, pages) {
  for (const b of thumbsBox.querySelectorAll(".os-thumb")) {
    const i = Number(b.dataset.index) + 1;
    const on = pages.includes(i);
    let tag = b.querySelector(".os-thumb__ocr");
    if (on && !tag) {
      tag = h("span", { class: "os-thumb__ocr", text: t("prepare.ocr"), attrs: { title: t("prepare.ocr-tip") } });
      b.append(tag);
      b.setAttribute("aria-label", `${b.getAttribute("aria-label") || ""}, ${t("prepare.ocr-tip")}`);
    } else if (!on && tag) tag.remove();
    b.classList.toggle("is-scanned", on);
  }
}

export { icon };
