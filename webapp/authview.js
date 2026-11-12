// The pieces the signed-out pages share (WEB-18 lane E): the warm-canvas layout with the
// seal mark, the receipt-style card, a password field with a reveal toggle, a field error
// tied to its input, an alert, and the restrained side panel shown on wide screens.
// The look is the approved canvas (docs/assets/design-canvas: Main's seal mark and
// buttons, Signer's sealed receipt frame); styles are in auth.css.
//
// Every string arrives through `t()` and goes in as text (dom.js `h`), never as markup.

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";

const SVG = "http://www.w3.org/2000/svg";

/// The seal mark: the red rounded square with a tick, as in the canvas sidebar.
export function sealMark(size = "md") {
  return h("span", { class: `os-auth-mark os-auth-mark--${size}`, attrs: { "aria-hidden": "true" } }, icon("check", { size: 16 }));
}

/// The page: a centred column (brand, framed card, footer) on the warm canvas, with an
/// optional side panel that shows only on wide screens. Returns the card to fill.
export function authLayout(view, { labelledBy, footer = null, aside = false, homeHref = null }) {
  const card = h("section", { class: "os-auth__card", attrs: { "aria-labelledby": labelledBy } });
  const brand = h(homeHref ? "a" : "span", { class: "os-auth__brand", ...(homeHref ? { href: homeHref } : {}) },
    sealMark("md"), h("span", { class: "os-auth__word", text: "OpenSeal" }));
  const column = h("div", { class: "os-auth__col" },
    brand,
    h("div", { class: "os-auth__frame os-auth-rise" }, card),
    footer);
  const grid = h("div", { class: `os-auth__grid${aside ? " has-aside" : ""}` }, column, aside ? sidePanel() : null);
  view.append(h("div", { class: "os-auth" }, grid));
  return card;
}

/// A card's heading block: title and one sentence under it.
export function cardHead(id, title, lede = null) {
  return h("header", { class: "os-auth__head" },
    h("h1", { id, class: "os-auth__title", text: title }),
    lede ? h("p", { class: "os-auth__lede", text: lede }) : null);
}

/// A labelled text field with its error line. Returns `{ block, input, error }`.
export function textField({ id, label, type = "text", autocomplete, value = "", maxLength = null }) {
  const errorId = `${id}-error`;
  const input = h("input", { id, class: "os-input os-auth__input", type, name: id, autocomplete, value, required: true,
    ...(maxLength ? { maxLength } : {}), attrs: { "aria-describedby": errorId, spellcheck: "false" } });
  const error = h("p", { id: errorId, class: "os-field-error os-auth__error" });
  const block = h("div", { class: "os-auth__field" }, h("label", { class: "os-label os-auth__label", attrs: { for: id }, text: label }), input, error);
  return { block, input, error };
}

/// A password field with a reveal toggle inside its right edge. The toggle is named by
/// hidden text ("Show password"), its state in `aria-pressed`, so the field's label
/// "Password" stays the only thing that label finds. Returns `{ block, input, error, toggle }`.
export function passwordField({ id, label, autocomplete, describedBy = [], command = null, revealLabel = null }) {
  const errorId = `${id}-error`;
  const input = h("input", { id, class: "os-input os-auth__input os-auth__input--secret", type: "password", name: id, autocomplete, required: true,
    maxLength: 256, attrs: { "aria-describedby": [...describedBy, errorId].join(" "), spellcheck: "false" } });
  const eye = h("span", { class: "os-auth__eye", attrs: { "aria-hidden": "true" } }, icon("eye", { size: 16 }));
  const toggle = h("button", { type: "button", class: "os-auth__reveal", attrs: { "aria-pressed": "false", "aria-controls": id, ...(command ? { "data-os-command": command } : {}), title: t("signin.show-title") } },
    eye, h("span", { class: "os-sr-only", text: revealLabel || t("signin.show-password") }));
  toggle.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(show));
    toggle.title = t(show ? "signin.hide-title" : "signin.show-title");
    toggle.classList.toggle("is-on", show);
    input.focus();
  });
  const error = h("p", { id: errorId, class: "os-field-error os-auth__error" });
  const block = h("div", { class: "os-auth__field" },
    h("label", { class: "os-label os-auth__label", attrs: { for: id }, text: label }),
    h("div", { class: "os-auth__secret" }, input, toggle), error);
  return { block, input, error, toggle };
}

/// Show `key`'s message under `input` (or clear it with null), with `aria-invalid`.
export function setFieldError(input, node, message) {
  node.textContent = message || "";
  if (message) input.setAttribute("aria-invalid", "true"); else input.removeAttribute("aria-invalid");
}

/// An alert above the fields, hidden until `show(title, text)`. The node carries
/// `role="alert"` only while shown, so a page has at most one alert at a time.
export function alertBox(testId) {
  const node = h("div", { class: "os-auth__alert", hidden: true, attrs: { "data-testid": testId } });
  return {
    node,
    show(title, text) {
      clear(node);
      node.append(h("span", { class: "os-auth__alert-icon" }, icon("circle-alert", { size: 16 })),
        h("div", { class: "os-auth__alert-body" }, h("p", { class: "os-auth__alert-title", text: title }), h("p", { text })));
      node.setAttribute("role", "alert");
      node.hidden = false;
    },
    hide() { node.hidden = true; node.removeAttribute("role"); clear(node); },
  };
}

/// A finished state inside the card: the green seal and one sentence, announced.
export function successBlock(testId, title, text) {
  return h("div", { class: "os-auth__done os-auth-rise", attrs: { role: "status", "data-testid": testId } },
    h("span", { class: "os-auth-seal os-auth-seal--ok", attrs: { "aria-hidden": "true" } }, icon("check", { size: 24 })),
    h("p", { class: "os-auth__done-title", text: title }),
    h("p", { class: "os-auth__lede", text }));
}

/// The footer under the card: plain links.
export function footerLinks(links) {
  return h("footer", { class: "os-auth__foot" }, ...links.map(([href, text]) => h("a", { class: "os-auth__footlink", href, text })));
}

// ---- The side panel (wide screens) --------------------------------------------------------

/// What OpenSeal does, in three plain lines beside a drawn sealed receipt. Says only what
/// the product does (docs/04 rule 25): no legal or compliance claim.
function sidePanel() {
  const points = [["send", "signin.aside.send"], ["pen-line", "signin.aside.sign"], ["shield-check", "signin.aside.verify"]];
  return h("aside", { class: "os-auth__aside", attrs: { "aria-labelledby": "auth-aside-title" } },
    receiptArt(),
    h("h2", { id: "auth-aside-title", class: "os-auth__aside-title", text: t("signin.aside.title") }),
    h("ul", { class: "os-auth__points" }, ...points.map(([ic, key]) => h("li", {}, h("span", { class: "os-auth__point-icon", attrs: { "aria-hidden": "true" } }, icon(ic, { size: 16 })), h("span", { text: t(key) })))));
}

/// A drawn page with signature lines and the seal, floating gently (no text, decorative).
function receiptArt() {
  const svg = document.createElementNS(SVG, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 200 150", class: "os-auth__art os-auth-float", "aria-hidden": "true", focusable: "false" })) svg.setAttribute(k, v);
  const shapes = [
    ["ellipse", { cx: 100, cy: 140, rx: 62, ry: 6, class: "art-shadow" }],
    ["rect", { x: 46, y: 10, width: 108, height: 120, rx: 8, class: "art-page" }],
    ["rect", { x: 62, y: 28, width: 48, height: 6, rx: 3, class: "art-ink" }],
    ["rect", { x: 62, y: 42, width: 76, height: 4, rx: 2, class: "art-line" }],
    ["rect", { x: 62, y: 52, width: 70, height: 4, rx: 2, class: "art-line" }],
    ["rect", { x: 62, y: 62, width: 76, height: 4, rx: 2, class: "art-line" }],
    ["rect", { x: 62, y: 72, width: 54, height: 4, rx: 2, class: "art-line" }],
    ["path", { d: "M62 104c8-4 10-14 16-14s3 10 9 10 8-8 13-8", class: "art-sign" }],
    ["path", { d: "M62 112h52", class: "art-rule" }],
    ["circle", { cx: 138, cy: 104, r: 17, class: "art-seal" }],
    ["path", { d: "m130.5 104 5 5 10-10", class: "art-tick" }],
    ["circle", { cx: 30, cy: 40, r: 3, class: "art-dot-a" }],
    ["circle", { cx: 172, cy: 30, r: 2.5, class: "art-dot-b" }],
  ];
  for (const [tag, attrs] of shapes) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    svg.append(n);
  }
  return svg;
}
