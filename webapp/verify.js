// Verify a signed PDF (WEB-02; docs/47 §Screens "Verify"; docs/32 §4), at verify.html.
// Everything runs in this browser: the file is never uploaded. The verdict is
// casual-sign-verify's own, compiled to WebAssembly (`crates/casual-sign-wasm`, built
// into vendor/openseal-wasm/ by tools/build-webapp-wasm.sh), the code the server and
// the CLI run. This page only shows its report (verifyreport.js), and the audit trail
// the PDF carries (`audit-trail.json`, read by pdf.js, checked for links by trail.js).
//
// Inputs: the PDF, and optionally trusted certificates (DER or PEM) the person
// supplies; without one, a signature's chain cannot be anchored and the verdict says
// so. The validation time is now, read from the clock here and passed in (the engine
// reads no clock). No account, no server call.

import { h, clear, fmtDate } from "./dom.js";
import { icon } from "./icons.js";
import { t, applyI18n } from "./i18n.js";
import { button, emptyState, toast, pdfPreview } from "./ui/index.js";
import { illustration } from "./illustrations.js";
import { initTheme, getTheme, toggleTheme } from "./theme.js";
import { summarize, coverage, certificatesFrom } from "./verifyreport.js";
import { parseTrail, TRAIL_NAME, MAX_TRAIL_BYTES, eventLabel } from "./trail.js";
import { readAttachment } from "./pdfview.js";
import { has } from "./i18n.js";

const MAX_PDF = 50 * 1024 * 1024; // docs/21: 50 MiB
const main = document.getElementById("main");
const trust = []; // {name, der: [base64]}
let wasm = null;

/// The verifier module, loaded once. Null when it is not installed on this server.
async function verifier() {
  if (wasm) return wasm;
  try {
    const mod = await import("./vendor/openseal-wasm/casual_sign_wasm.js");
    await mod.default();
    wasm = mod;
    return wasm;
  } catch {
    return null;
  }
}

// ---- Start: choose a file ------------------------------------------------------------

function start() {
  clear(main);
  const input = h("input", { type: "file", accept: "application/pdf,.pdf", class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "verify-input" } });
  input.addEventListener("change", () => { if (input.files[0]) check(input.files[0]); input.value = ""; });
  const choose = button(t("verify.choose"), { icon: "file-search", variant: "primary", size: "lg", onClick: () => input.click() });
  const drop = h("div", { class: "os-drop", attrs: { "data-testid": "verify-drop" } },
    illustration("verify"),
    h("p", { class: "os-drop__title", text: t("verify.drop") }),
    choose,
    h("p", { class: "os-muted os-small", text: t("verify.private") }));
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); drop.classList.add("is-dropping"); } });
  drop.addEventListener("dragleave", () => drop.classList.remove("is-dropping"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("is-dropping");
    const f = e.dataTransfer.files?.[0];
    if (f) check(f);
  });

  main.append(
    h("h1", { class: "os-page-title", text: t("verify.title") }),
    h("p", { class: "os-muted os-lede", text: t("verify.lede") }),
    drop, input, trustCard());
  choose.focus({ preventScroll: true });
}

function trustCard() {
  const list = h("ul", { class: "os-chips", attrs: { "aria-live": "polite" } });
  const input = h("input", { type: "file", accept: ".cer,.crt,.der,.pem,application/x-x509-ca-cert,application/pkix-cert", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "trust-input" } });
  const render = () => {
    clear(list);
    if (!trust.length) { list.append(h("li", { class: "os-muted os-small", text: t("verify.trust-none") })); return; }
    trust.forEach((c, i) => {
      list.append(h("li", { class: "os-chip-item" }, icon("shield-check", { size: 16 }), h("span", { text: c.name }),
        button(t("verify.trust-remove", { name: c.name }), { icon: "x", size: "sm", variant: "ghost", iconOnly: true, onClick: () => { trust.splice(i, 1); render(); } })));
    });
  };
  input.addEventListener("change", async () => {
    for (const f of [...input.files]) {
      if (f.size > 1 << 20) { toast(t("verify.trust-bad", { name: f.name }), "error"); continue; }
      const der = certificatesFrom(new Uint8Array(await f.arrayBuffer()));
      if (!der.length) { toast(t("verify.trust-bad", { name: f.name }), "error"); continue; }
      trust.push({ name: f.name.slice(0, 120), der });
    }
    input.value = "";
    render();
  });
  render();
  return h("section", { class: "os-card", attrs: { "aria-labelledby": "trust-h" } },
    h("h2", { id: "trust-h", class: "os-card__title", text: t("verify.trust-title") }),
    h("p", { class: "os-muted os-small", text: t("verify.trust-text") }),
    list, input,
    button(t("verify.trust-add"), { icon: "plus", size: "sm", onClick: () => input.click() }));
}

// ---- Check -----------------------------------------------------------------------------

async function check(file) {
  clear(main);
  const status = h("div", { class: "os-verify__busy", attrs: { role: "status", "aria-busy": "true" } },
    h("span", { class: "os-spinner", attrs: { "aria-hidden": "true" } }), h("p", { text: t("verify.checking", { name: file.name }) }));
  main.append(h("h1", { class: "os-page-title", text: t("verify.title") }), status);
  main.focus({ preventScroll: true });

  if (file.size > MAX_PDF) return problem(t("verify.too-large"));
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length < 5 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") return problem(t("verify.not-pdf"));

  const mod = await verifier();
  if (!mod) {
    clear(main);
    main.append(emptyState({ illus: "error", title: t("verify.missing.title"), text: t("verify.missing.text"), action: button(t("verify.another"), { icon: "file-search", variant: "primary", onClick: start }), testId: "verify-missing" }));
    return;
  }
  // Let the busy state paint before the verifier takes the thread.
  await new Promise((r) => setTimeout(r, 30));
  const trustJson = JSON.stringify({ validation_time: Math.floor(Date.now() / 1000), anchors: trust.flatMap((c) => c.der) });
  let report;
  try { report = summarize(mod.verify(bytes, trustJson)); } catch { report = { state: "error", code: "CS-API-0010", signatures: [], changes: [] }; }
  let trail = null;
  try {
    const raw = await readAttachment(bytes, TRAIL_NAME, MAX_TRAIL_BYTES);
    trail = raw ? parseTrail(raw) : null;
  } catch { trail = null; }
  show(file, bytes.length, report, trail);
  main.append(h("section", { class: "os-card", attrs: { "aria-labelledby": "vpreview-h" } }, h("h2", { id: "vpreview-h", class: "os-card__title", text: t("verify.preview") }), pdfPreview({ load: async () => bytes, name: file.name, height: 560 }).el));
}

function problem(text) {
  clear(main);
  main.append(emptyState({ illus: "error", title: t("verify.cannot.title"), text, action: button(t("verify.another"), { icon: "file-search", variant: "primary", onClick: start }), testId: "verify-problem" }));
}

// ---- Result ----------------------------------------------------------------------------

const STATE_ICON = { valid: "shield-check", invalid: "shield-x", indeterminate: "shield-alert", unsigned: "shield-question", error: "circle-x" };

function show(file, size, r, trail) {
  clear(main);
  const verdict = h("section", { class: `os-verdict os-verdict--${r.state}`, attrs: { role: "status", "data-testid": "verdict", "data-state": r.state, "aria-labelledby": "verdict-h" } },
    h("span", { class: "os-verdict__icon" }, icon(STATE_ICON[r.state], { size: 24 })),
    h("div", {},
      h("h2", { id: "verdict-h", class: "os-verdict__title", text: t(`verify.state.${r.state}`) }),
      h("p", { class: "os-verdict__text", text: r.state === "error" ? t("verify.state.error-text", { code: r.code }) : t(`verify.state.${r.state}-text`) }),
      r.needsTrust ? h("p", { class: "os-verdict__text", text: t("verify.needs-trust") }) : null));
  const meta = h("dl", { class: "os-meta" },
    h("dt", { text: t("verify.file") }), h("dd", { text: `${file.name} · ${Math.max(1, Math.round(size / 1024))} KB` }),
    r.revisions ? [h("dt", { text: t("verify.revisions") }), h("dd", { text: String(r.revisions) })] : null,
    h("dt", { text: t("verify.trusted") }), h("dd", { text: trust.length ? trust.map((c) => c.name).join(", ") : t("verify.trust-none") }));

  main.append(
    h("div", { class: "os-page-head" }, h("h1", { class: "os-page-title", text: t("verify.title") }),
      button(t("verify.another"), { icon: "file-search", onClick: start, attrs: { "data-testid": "verify-another" } })),
    verdict, meta);

  if (r.signatures.length) {
    const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "sigs-h" } }, h("h2", { id: "sigs-h", class: "os-card__title", text: t("verify.signatures", { n: r.signatures.length }) }));
    const ol = h("ol", { class: "os-sigs" });
    for (const s of r.signatures) ol.append(signatureItem(s));
    sec.append(ol);
    main.append(sec);
  }
  if (r.changes.length) {
    const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "changes-h" } }, h("h2", { id: "changes-h", class: "os-card__title", text: t("verify.changes") }));
    const ul = h("ul", { class: "os-checks" });
    for (const c of r.changes) {
      ul.append(h("li", { class: c.allowed ? "is-passed" : "is-failed" }, icon(c.allowed ? "circle-check" : "circle-x", { size: 16 }),
        h("span", { text: t(c.allowed ? "verify.change-allowed" : "verify.change-disallowed", { n: c.revision, what: c.classes.map(classLabel).join(", ") }) })));
    }
    sec.append(ul);
    main.append(sec);
  }
  main.append(trailSection(trail));
  main.focus({ preventScroll: true });
}

function classLabel(c) {
  const key = `verify.class.${c.split(":")[0]}`;
  return has(key) ? t(key) : c;
}

function signatureItem(s) {
  const when = s.time != null
    ? t("verify.time-proven", { when: fmtDate(new Date(s.time * 1000).toISOString()), source: t(`verify.source.${s.timeSource}`) })
    : t("verify.time-none", { when: s.validationTime != null ? fmtDate(new Date(s.validationTime * 1000).toISOString()) : "—" });
  const badge = h("span", { class: `os-badge os-badge--${s.verdict === "valid" ? "completed" : s.verdict === "invalid" ? "declined" : "sent"}` },
    icon(s.verdict === "valid" ? "circle-check" : s.verdict === "invalid" ? "circle-x" : "circle-alert", { size: 16 }), h("span", { text: t(`verify.sig.${s.verdict}`) }));
  const checks = h("ul", { class: "os-checks" });
  for (const c of s.checks) {
    checks.append(h("li", { class: `is-${c.status}` },
      icon(c.status === "passed" ? "circle-check" : c.status === "failed" ? "circle-x" : "clock", { size: 16 }),
      h("span", { text: t(`verify.check.${c.name}`) }),
      h("span", { class: "os-muted os-small", text: ` · ${t(`verify.status.${c.status}`)}${c.sub ? ` (${c.sub}${c.code ? `, ${c.code}` : ""})` : ""}` })));
  }
  return h("li", { class: "os-sig", attrs: { "data-testid": "signature" } },
    h("div", { class: "os-sig__head" },
      h("h3", { class: "os-sig__title", text: t("verify.sig-n", { n: s.n, kind: t(`verify.kind.${s.kind}`) }) }), badge),
    s.sub ? h("p", { class: "os-small", text: t("verify.why", { sub: s.sub, code: s.code || "—" }) }) : null,
    h("dl", { class: "os-meta os-meta--tight" },
      h("dt", { text: t("verify.signer") }), h("dd", { class: "os-muted", text: t("verify.signer-unknown") }),
      h("dt", { text: t("verify.time") }), h("dd", { text: when }),
      h("dt", { text: t("verify.coverage") }), h("dd", { text: t(`verify.coverage.${coverage(s)}`, { n: s.changesAfter }) }),
      h("dt", { text: t("verify.format") }), h("dd", { text: s.subFilter || "—" })),
    h("details", { class: "os-details" }, h("summary", { text: t("verify.checks") }), checks));
}

function trailSection(trail) {
  const sec = h("section", { class: "os-card", attrs: { "aria-labelledby": "trail-h" } }, h("h2", { id: "trail-h", class: "os-card__title", text: t("verify.trail") }));
  if (!trail) { sec.append(h("p", { class: "os-muted", attrs: { "data-testid": "trail-none" }, text: t("verify.trail-none") })); return sec; }
  if (!trail.ok) { sec.append(h("p", { class: "os-field-error", text: t(`verify.trail-bad.${trail.problem}`) })); return sec; }
  sec.append(h("p", { class: trail.links.ok ? "os-small" : "os-field-error", attrs: { "data-testid": "trail-links" } },
    icon(trail.links.ok ? "circle-check" : "circle-x", { size: 16 }),
    h("span", { text: ` ${trail.links.ok ? t("verify.trail-links-ok", { n: trail.events.length }) : t("verify.trail-links-bad", { n: trail.links.problems.length })}` })),
  h("p", { class: "os-muted os-small", text: t("verify.trail-hashes") }));
  const ol = h("ol", { class: "os-trail", attrs: { "data-testid": "trail" } });
  for (const e of trail.events) {
    const key = `event.${e.type}`;
    ol.append(h("li", { class: "os-trail__item" },
      h("span", { class: "os-trail__dot", attrs: { "aria-hidden": "true" } }),
      h("div", {},
        h("strong", { text: has(key) ? t(key) : eventLabel(e.type) }),
        h("span", { class: "os-muted os-small", text: ` · ${e.actor.name || e.actor.kind}` }),
        e.at ? h("time", { class: "os-muted os-small os-block", attrs: { datetime: e.at }, text: fmtDate(e.at) } ) : null)));
  }
  sec.append(ol);
  if (trail.head) sec.append(h("p", { class: "os-muted os-small" }, h("span", { text: `${t("audit.head")} ` }), h("code", { text: trail.head })));
  return sec;
}

// ---- Chrome ------------------------------------------------------------------------------

function syncTheme() {
  const b = document.getElementById("theme-btn");
  const dark = getTheme() === "dark" || (getTheme() === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  b.replaceChildren(icon(dark ? "moon" : "sun"));
  b.setAttribute("aria-label", t(dark ? "theme.to-light" : "theme.to-dark"));
  b.title = b.getAttribute("aria-label");
}

initTheme();
applyI18n(document);
document.getElementById("theme-btn").addEventListener("click", () => { toggleTheme(); syncTheme(); });
syncTheme();
start();
