// The Verify page's views (WEB-18 lane E): the drop zone, the scanning screen, the
// sealed-receipt result and the detail cards. Render only: the flow is verify.js, the
// rules verifyreport.js. The look is the approved canvas (Signer.dc.html's secure-open
// loader and sealed receipt; Main.dc.html's empty-state art and scan); styles in auth.css.
//
// Honesty (docs/04 rule 25, brief): every line here names what the verifier reported or
// what this page actually did. The checks are the verifier's own, in its order, with its
// status; nothing is added, and nothing is called valid that the verifier did not pass.

import { h, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t, has } from "./i18n.js";
import { button } from "./ui/index.js";
import { stepStates, verdictTone, checkTone, tally, fileSize, coverage } from "./verifyreport.js";
import { eventLabel } from "./trail.js";

const SVG = "http://www.w3.org/2000/svg";

/// An SVG built node by node (no markup). `shapes`: `[tag, attrs]`.
function art(viewBox, cls, shapes) {
  const svg = document.createElementNS(SVG, "svg");
  for (const [k, v] of Object.entries({ viewBox, class: cls, "aria-hidden": "true", focusable: "false" })) svg.setAttribute(k, v);
  for (const [tag, attrs] of shapes) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    svg.append(n);
  }
  return svg;
}

// ---- Start ---------------------------------------------------------------------------------

/// A drawn PDF with the seal and a magnifier, floating (decorative).
function dropArt() {
  return art("0 0 160 120", "os-vfy__art os-auth-float", [
    ["ellipse", { cx: 80, cy: 112, rx: 46, ry: 5, class: "art-shadow" }],
    ["rect", { x: 44, y: 12, width: 72, height: 92, rx: 8, class: "art-page" }],
    ["rect", { x: 44, y: 12, width: 72, height: 18, rx: 8, class: "art-band" }],
    ["rect", { x: 56, y: 40, width: 40, height: 4, rx: 2, class: "art-line" }],
    ["rect", { x: 56, y: 50, width: 48, height: 4, rx: 2, class: "art-line" }],
    ["rect", { x: 56, y: 60, width: 34, height: 4, rx: 2, class: "art-line" }],
    ["path", { d: "M56 82c6-3 8-10 12-10s2 7 7 7 6-6 10-6", class: "art-sign" }],
    ["circle", { cx: 112, cy: 82, r: 17, class: "art-seal" }],
    ["path", { d: "m104.5 82 5 5 10-10", class: "art-tick" }],
    ["circle", { cx: 28, cy: 38, r: 3, class: "art-dot-a" }],
    ["circle", { cx: 136, cy: 28, r: 2.5, class: "art-dot-b" }],
  ]);
}

/// The drop zone: art, "Drop a PDF here", the Choose button, and what happens to the file.
/// Returns `{ el, choose }`; the caller wires the file input and the drop.
export function dropZone(onChoose) {
  const choose = button(t("verify.choose"), { icon: "file-search", variant: "primary", size: "lg", command: "pdf.verify-choose", onClick: onChoose });
  const el = h("div", { class: "os-vfy__drop", attrs: { "data-testid": "verify-drop" } },
    dropArt(),
    h("p", { class: "os-vfy__drop-title", text: t("verify.drop") }),
    h("p", { class: "os-vfy__drop-or", text: t("verify.drop-or") }),
    choose,
    h("p", { class: "os-vfy__drop-note" }, icon("lock", { size: 12 }), h("span", { text: t("verify.private") })));
  return { el, choose };
}

/// The line under the drop zone that says whether the verifier is here: a skeleton while
/// it loads, then ready or not available. `set(state)`: "loading" | "ready" | "missing".
export function engineLine() {
  const el = h("p", { class: "os-vfy__engine", attrs: { "aria-live": "polite", "data-testid": "verify-engine" } });
  const set = (state) => {
    el.dataset.state = state;
    if (state === "loading") {
      el.replaceChildren(h("span", { class: "os-vfy__skel os-vfy__skel--dot", attrs: { "aria-hidden": "true" } }),
        h("span", { class: "os-vfy__skel os-vfy__skel--line", attrs: { "aria-hidden": "true" } }),
        h("span", { class: "os-sr-only", text: t("verify.engine-loading") }));
      el.setAttribute("aria-busy", "true");
      return;
    }
    el.removeAttribute("aria-busy");
    el.replaceChildren(icon(state === "ready" ? "shield-check" : "triangle-alert", { size: 16 }),
      h("span", { text: t(state === "ready" ? "verify.engine-ready" : "verify.engine-missing") }));
  };
  set("loading");
  return { el, set };
}

// ---- Scanning --------------------------------------------------------------------------------

/// The page being read, with the scanning line (decorative).
function scanArt() {
  return h("div", { class: "os-vfy__scan-page", attrs: { "aria-hidden": "true" } },
    ...Array.from({ length: 7 }, () => h("span", { class: "os-vfy__scan-line" })),
    h("span", { class: "os-vfy__scan-bar" }));
}

/// The scanning screen: the page with its scan line, "Checking <file>", and the real
/// stages ticking off. Returns `{ el, step(id) }`.
export function scanning(name) {
  const list = h("ol", { class: "os-vfy__steps" });
  const status = h("span", { class: "os-sr-only", attrs: { "aria-live": "polite" } });
  const step = (current) => {
    list.replaceChildren(...stepStates(current).map((s) => h("li", { class: `os-vfy__step is-${s.state}` },
      h("span", { class: "os-vfy__step-dot", attrs: { "aria-hidden": "true" } }, s.state === "done" ? icon("check", { size: 12 }) : null),
      h("span", { text: t(`verify.step.${s.id}`) }))));
    const active = stepStates(current).find((s) => s.state === "active");
    status.textContent = active ? t(`verify.step.${active.id}`) : "";
  };
  step("read");
  const el = h("div", { class: "os-vfy__scanning os-auth-fade", attrs: { role: "status", "aria-busy": "true", "data-testid": "verify-scanning" } },
    h("div", { class: "os-vfy__scan-wrap os-vfy-breathe" }, scanArt()),
    h("div", { class: "os-vfy__scan-head" },
      h("p", { class: "os-vfy__scan-title", text: t("verify.checking", { name }) }),
      h("p", { class: "os-vfy__scan-sub", text: t("verify.private") })),
    h("div", { class: "os-vfy__steps-card" }, list), status);
  // Long names truncate with an ellipsis; the full name is in the title.
  el.querySelector(".os-vfy__scan-title").title = name;
  return { el, step };
}

/// A plain busy line (the hand-over from an envelope, before there is a file).
export function opening(text) {
  return h("div", { class: "os-vfy__scanning os-auth-fade", attrs: { role: "status", "aria-busy": "true" } },
    h("div", { class: "os-vfy__scan-wrap os-vfy-breathe" }, scanArt()),
    h("p", { class: "os-vfy__scan-title", text }));
}

// ---- Result: the sealed receipt ----------------------------------------------------------

const SEAL_ICON = { ok: "check", warn: "circle-alert", bad: "x" };

/// The tally line: "2 valid, 1 not confirmed", or "None".
function tallyText(signatures) {
  const n = tally(signatures);
  const parts = ["valid", "invalid", "indeterminate"].filter((k) => n[k]).map((k) => t(`verify.tally.${k}`, { n: n[k] }));
  return parts.length ? parts.join(", ") : t("verify.trust-none");
}

/// The receipt: the seal in the verdict's colour, the verdict and why, the facts of the
/// check, and Check another PDF. `r` is `summarize`'s report.
export function receipt({ file, size, report: r, trusted, checkedAt, onAnother }) {
  const tone = verdictTone(r.state);
  const fs = fileSize(size);
  const rows = [
    ["verify.file", h("span", { class: "os-vfy__ellipsis", title: file, text: file })],
    ["verify.size", h("span", { text: t(fs.key, { n: fs.n }) })],
    ["verify.signatures-label", h("span", { text: tallyText(r.signatures) })],
    r.revisions ? ["verify.revisions", h("span", { text: String(r.revisions) })] : null,
    ["verify.trusted", h("span", { class: "os-vfy__ellipsis", text: trusted.length ? trusted.join(", ") : t("verify.trust-none") })],
    ["verify.checked-at", h("span", { text: fmtDate(new Date(checkedAt).toISOString()) })],
  ].filter(Boolean);
  const another = button(t("verify.another"), { icon: "file-search", variant: "secondary", size: "lg", command: "pdf.verify-another", onClick: onAnother, attrs: { "data-testid": "verify-another" } });
  another.classList.add("os-vfy__dark");
  const text = r.state === "error" ? t("verify.state.error-text", { code: r.code }) : t(`verify.state.${r.state}-text`);
  return h("section", { class: `os-vfy__result is-${tone}`, attrs: { "data-testid": "verdict", "data-state": r.state, role: "status", "aria-labelledby": "verdict-h" } },
    h("div", { class: "os-auth__frame os-auth-rise os-vfy__receipt-frame" },
      h("div", { class: "os-vfy__receipt" },
        h("span", { class: `os-auth-seal os-auth-seal--${tone} os-auth-stamp`, attrs: { "aria-hidden": "true" } }, icon(SEAL_ICON[tone], { size: 24 })),
        h("h2", { id: "verdict-h", class: "os-vfy__verdict", attrs: { tabindex: "-1" }, text: t(`verify.state.${r.state}`) }),
        h("p", { class: "os-vfy__verdict-text", text }),
        r.needsTrust ? h("p", { class: "os-vfy__hint" }, icon("info", { size: 16 }), h("span", { text: t("verify.needs-trust") })) : null,
        h("dl", { class: "os-vfy__facts" }, ...rows.flatMap(([k, v]) => [h("dt", { text: t(k) }), h("dd", {}, v)])),
        h("div", { class: "os-vfy__actions" }, another))));
}

// ---- Detail cards --------------------------------------------------------------------------

/// A card with a heading.
export function detailCard(id, title, ...body) {
  return h("section", { class: "os-vfy__card os-auth-rise", attrs: { "aria-labelledby": id } }, h("h2", { id, class: "os-vfy__card-title", text: title }), ...body);
}

const CHECK_ICON = { ok: "check", bad: "x", none: null };

/// One check as the verifier reported it: its name, its status, and its reason and code
/// when it gave them.
function checkRow(c) {
  const tone = checkTone(c.status);
  const why = c.sub ? `${c.sub}${c.code ? ` · ${c.code}` : ""}` : null;
  return h("li", { class: `os-vfy__check is-${tone}` },
    h("span", { class: "os-vfy__check-dot", attrs: { "aria-hidden": "true" } }, CHECK_ICON[tone] ? icon(CHECK_ICON[tone], { size: 12 }) : null),
    h("span", { class: "os-vfy__check-name", text: t(`verify.check.${c.name}`) }),
    h("span", { class: "os-vfy__check-status", text: t(`verify.status.${c.status}`) }),
    why ? h("code", { class: "os-vfy__check-why", text: why }) : null);
}

const SIG_TONE = { valid: "ok", invalid: "bad", indeterminate: "warn" };

/// One signature: its number and kind, the verifier's verdict, why, when, what it covers,
/// and every check.
export function signatureItem(s) {
  const when = s.time != null
    ? t("verify.time-proven", { when: fmtDate(new Date(s.time * 1000).toISOString()), source: t(`verify.source.${s.timeSource}`) })
    : t("verify.time-none", { when: s.validationTime != null ? fmtDate(new Date(s.validationTime * 1000).toISOString()) : "—" });
  const tone = SIG_TONE[s.verdict];
  return h("li", { class: "os-vfy__sig", attrs: { "data-testid": "signature" } },
    h("div", { class: "os-vfy__sig-head" },
      h("h3", { class: "os-vfy__sig-title", text: t("verify.sig-n", { n: s.n, kind: t(`verify.kind.${s.kind}`) }) }),
      h("span", { class: `os-vfy__pill is-${tone}` }, icon(tone === "ok" ? "circle-check" : tone === "bad" ? "circle-x" : "circle-alert", { size: 12 }), h("span", { text: t(`verify.sig.${s.verdict}`) }))),
    s.sub ? h("p", { class: "os-vfy__why", text: t("verify.why", { sub: s.sub, code: s.code || "—" }) }) : null,
    h("dl", { class: "os-vfy__facts os-vfy__facts--plain" },
      h("dt", { text: t("verify.signer") }), h("dd", { class: "os-vfy__muted", text: t("verify.signer-unknown") }),
      h("dt", { text: t("verify.time") }), h("dd", { text: when }),
      h("dt", { text: t("verify.coverage") }), h("dd", { text: t(`verify.coverage.${coverage(s)}`, { n: s.changesAfter }) }),
      h("dt", { text: t("verify.format") }), h("dd", {}, h("code", { text: s.subFilter || "—" }))),
    h("p", { class: "os-vfy__checks-title", text: t("verify.checks") }),
    h("ul", { class: "os-vfy__checks" }, ...s.checks.map(checkRow)));
}

function classLabel(c) {
  const key = `verify.class.${c.split(":")[0]}`;
  return has(key) ? t(key) : c;
}

/// Changes after the signatures, each allowed or not as the verifier classed it.
export function changesList(changes) {
  return h("ul", { class: "os-vfy__checks" }, ...changes.map((c) => {
    const tone = c.allowed ? "ok" : "bad";
    return h("li", { class: `os-vfy__check is-${tone}` },
      h("span", { class: "os-vfy__check-dot", attrs: { "aria-hidden": "true" } }, icon(c.allowed ? "check" : "x", { size: 12 })),
      h("span", { class: "os-vfy__check-name", text: t(c.allowed ? "verify.change-allowed" : "verify.change-disallowed", { n: c.revision, what: c.classes.map(classLabel).join(", ") }) }));
  }));
}

/// The audit trail the PDF carries: whether its links hold (what trail.js checks), that
/// hashes are not recomputed here, and the events.
export function trailBody(trail) {
  if (!trail) return [h("p", { class: "os-vfy__muted", attrs: { "data-testid": "trail-none" }, text: t("verify.trail-none") })];
  if (!trail.ok) return [h("p", { class: "os-vfy__line is-bad" }, icon("circle-x", { size: 16 }), h("span", { text: t(`verify.trail-bad.${trail.problem}`) }))];
  const out = [
    h("p", { class: `os-vfy__line is-${trail.links.ok ? "ok" : "bad"}`, attrs: { "data-testid": "trail-links" } },
      icon(trail.links.ok ? "circle-check" : "circle-x", { size: 16 }),
      h("span", { text: trail.links.ok ? t("verify.trail-links-ok", { n: trail.events.length }) : t("verify.trail-links-bad", { n: trail.links.problems.length }) })),
    h("p", { class: "os-vfy__muted os-vfy__small", text: t("verify.trail-hashes") }),
  ];
  const ol = h("ol", { class: "os-vfy__trail", attrs: { "data-testid": "trail" } });
  for (const e of trail.events) {
    const key = `event.${e.type}`;
    ol.append(h("li", { class: "os-vfy__event" },
      h("span", { class: "os-vfy__event-dot", attrs: { "aria-hidden": "true" } }),
      h("div", { class: "os-vfy__event-body" },
        h("span", { class: "os-vfy__event-what", text: has(key) ? t(key) : eventLabel(e.type) }),
        h("span", { class: "os-vfy__muted os-vfy__small", text: e.actor.name || e.actor.kind }),
        e.at ? h("time", { class: "os-vfy__muted os-vfy__small os-vfy__event-at", attrs: { datetime: e.at }, text: fmtDate(e.at) }) : null)));
  }
  out.push(ol);
  if (trail.head) out.push(h("p", { class: "os-vfy__muted os-vfy__small os-vfy__head" }, h("span", { text: `${t("audit.head")} ` }), h("code", { text: trail.head })));
  return out;
}
