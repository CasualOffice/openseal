// The website's Verify page (SITE-03): a sealed PDF checked in this browser by
// casual-sign-verify compiled to WebAssembly, the build the web app's own Verify page
// runs. Both come from the web app's demo copy, published at app/ next to this site
// (tools/build-site.py --publish): the module at app/vendor/openseal-wasm/ and the app's
// report rules (app/verifyreport.js, which names the verifier's verdict and never
// upgrades one) and its wording (app/i18n.js). This file only draws the result.
//
// Nothing is uploaded: the file is read with the File API and handed to the verifier in
// memory; the page makes no request with it. Trusted roots the visitor adds stay in the
// tab too. Every string from a file (its name, a reason code) is set as text.
//
// The validation time is now, read here and passed in (the engine reads no clock).

const box = document.querySelector(".vfy");
const APP = box?.dataset.app || "app/";
const SAMPLES = box?.dataset.samples || "samples/";
const MAX_PDF = 50 * 1024 * 1024; // docs/21: 50 MiB
const MAX_CERT = 1 << 20;

const drop = box.querySelector(".vfy-drop");
const input = box.querySelector('[data-testid="vfy-input"]');
const trustInput = box.querySelector('[data-testid="vfy-trust-input"]');
const chips = box.querySelector('[data-testid="vfy-trusted"]');
const engineLine = box.querySelector('[data-testid="vfy-engine"]');
const out = box.querySelector('[data-testid="vfy-result"]');
const trust = []; // {name, der: [base64]}

// ---- Loading the verifier and the app's rules ----------------------------------------------

let loading = null;
/// The verifier and the report rules, loaded once; null when they are not published here.
function engine() {
  loading ||= Promise.all([
    import(`../${APP}vendor/openseal-wasm/casual_sign_wasm.js`).then(async (mod) => { await mod.default(); return mod; }),
    import(`../${APP}verifyreport.js`),
    import(`../${APP}i18n.js`),
  ]).then(([wasm, report, i18n]) => ({ wasm, report, t: i18n.t, has: i18n.has })).catch(() => null);
  return loading;
}

function setEngine(state, text) {
  engineLine.dataset.state = state;
  engineLine.textContent = text;
}

// ---- Small DOM helpers (text only) ---------------------------------------------------------

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === "text") el.textContent = v;
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid);
  return el;
}

const SVG = "http://www.w3.org/2000/svg";
// Lucide (ISC) paths for the few marks drawn here.
const MARKS = {
  ok: [["path", { d: "M20 6 9 17l-5-5" }]],
  bad: [["path", { d: "M18 6 6 18" }], ["path", { d: "m6 6 12 12" }]],
  warn: [["circle", { cx: "12", cy: "12", r: "10" }], ["line", { x1: "12", x2: "12", y1: "8", y2: "12" }], ["line", { x1: "12", x2: "12.01", y1: "16", y2: "16" }]],
  none: [["circle", { cx: "12", cy: "12", r: "4" }]],
};
function mark(tone, size = 16) {
  const s = document.createElementNS(SVG, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", width: String(size), height: String(size), fill: "none", stroke: "currentColor", "stroke-width": "2.25", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" })) s.setAttribute(k, v);
  for (const [tag, attrs] of MARKS[tone] || MARKS.none) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    s.append(n);
  }
  return s;
}

const when = (secs) => new Date(secs * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

// ---- Trusted certificates -------------------------------------------------------------------

function renderTrust() {
  chips.replaceChildren();
  if (!trust.length) { chips.append(h("li", { class: "muted", text: "None" })); return; }
  trust.forEach((c, i) => {
    const remove = h("button", { type: "button", class: "vfy-chip__x", "aria-label": `Remove ${c.name}` }, mark("bad", 12));
    remove.addEventListener("click", () => { trust.splice(i, 1); renderTrust(); });
    chips.append(h("li", { class: "vfy-chip" }, h("span", { class: "vfy-chip__name", text: c.name }), remove));
  });
}

async function addTrust(name, bytes) {
  const eng = await engine();
  if (!eng) return false;
  const der = eng.report.certificatesFrom(bytes);
  if (!der.length) return false;
  if (!trust.some((c) => c.name === name)) trust.push({ name: name.slice(0, 120), der });
  renderTrust();
  return true;
}

trustInput.addEventListener("change", async () => {
  for (const f of [...trustInput.files]) {
    const ok = f.size <= MAX_CERT && (await addTrust(f.name, new Uint8Array(await f.arrayBuffer())));
    if (!ok) problem(`${f.name} is not a certificate (DER or PEM).`);
  }
  trustInput.value = "";
});

// ---- Choosing a file ------------------------------------------------------------------------

input.addEventListener("change", () => { const f = input.files[0]; input.value = ""; if (f) check(f.name, f); });
for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { if (e.dataTransfer?.types.includes("Files")) { e.preventDefault(); drop.classList.add("is-dropping"); } });
drop.addEventListener("dragleave", (e) => { if (!drop.contains(e.relatedTarget)) drop.classList.remove("is-dropping"); });
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("is-dropping");
  const f = e.dataTransfer?.files?.[0];
  if (f) check(f.name, f);
});

// A sample: the PDF and the test roots it was sealed under, from this site (not the
// visitor's file, so fetching them sends nothing of theirs).
for (const b of box.querySelectorAll("[data-sample]")) {
  b.addEventListener("click", async () => {
    try {
      const [pdf, roots] = await Promise.all([fetch(SAMPLES + b.dataset.sample), fetch(`${SAMPLES}test-roots.pem`)]);
      if (!pdf.ok || !roots.ok) throw new Error("sample");
      await addTrust("test-roots.pem (samples only)", new Uint8Array(await roots.arrayBuffer()));
      await check(b.dataset.sample, new Blob([await pdf.arrayBuffer()], { type: "application/pdf" }));
    } catch {
      problem("The sample could not be loaded. Download it with the links below and choose it instead.");
    }
  });
}

function problem(text) {
  out.replaceChildren(h("p", { class: "vfy-problem", role: "alert", "data-testid": "vfy-problem" }, mark("warn"), h("span", { text })));
}

// ---- The check ------------------------------------------------------------------------------

async function check(name, file) {
  out.replaceChildren(h("p", { class: "vfy-busy", role: "status", "aria-busy": "true", text: `Checking ${name}…` }));
  if (file.size > MAX_PDF) return problem("The file is larger than 50 MB.");
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length < 5 || String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") return problem("That file is not a PDF.");
  const eng = await engine();
  if (!eng) return problem("The verifier is not published with this copy of the site. Use the openseal command line, or build it with tools/build-webapp-wasm.sh.");
  const checkedAt = Date.now();
  const trustJson = JSON.stringify({ validation_time: Math.floor(checkedAt / 1000), anchors: trust.flatMap((c) => c.der) });
  let r;
  try { r = eng.report.summarize(eng.wasm.verify(bytes, trustJson)); } catch { r = { state: "error", code: "CS-API-0010", signatures: [], changes: [] }; }
  show(eng, { name, size: bytes.length, r, checkedAt });
}

/// The four answers the page promises, from the verifier's own checks: a row passes only
/// when that check passed for every signature, fails when it failed for any.
function answer(sigs, names) {
  const st = sigs.flatMap((s) => s.checks.filter((c) => names.includes(c.name)).map((c) => c.status));
  if (!st.length) return "none";
  if (st.includes("failed")) return "bad";
  return st.every((x) => x === "passed") ? "ok" : "warn";
}

function row(label, tone, text, testid) {
  return h("li", { class: `vfy-row is-${tone}`, "data-testid": testid, "data-tone": tone },
    h("span", { class: "vfy-row__dot" }, mark(tone, 14)),
    h("span", { class: "vfy-row__label", text: label }),
    h("span", { class: "vfy-row__text", text }));
}

function show({ report, t, has }, { name, size, r, checkedAt }) {
  const tone = report.verdictTone(r.state);
  const sigs = r.signatures;
  const integrity = answer(sigs, ["byte_range", "digest", "signature"]);
  // A chain the verifier could not anchor (no trusted root given) is "not confirmed", as
  // its verdict is (INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND), not broken.
  let chain = answer(sigs, ["chain"]);
  if (chain === "bad" && r.needsTrust && !sigs.some((s) => s.checks.some((c) => c.name === "chain" && c.status === "failed" && c.sub !== "NO_CERTIFICATE_CHAIN_FOUND"))) chain = "warn";
  const stamp = answer(sigs, ["timestamp"]);
  const proven = sigs.map((s) => s.time).filter((x) => x != null);
  const disallowed = r.changes.filter((c) => !c.allowed).length;
  const rows = [
    row("Integrity", integrity, { ok: "The signed bytes are unchanged.", bad: "The document does not match what was signed.", warn: "Not every signature could be checked against the document.", none: "There is no signature to check." }[integrity], "vfy-integrity"),
    row("Certificate trust", chain, { ok: "The sealing certificate chains to a root you trust.", bad: "The sealing certificate's chain is broken.", warn: r.needsTrust ? "No trusted root for the issuer: add it under Trusted certificates." : "The chain could not be confirmed.", none: "Not checked." }[chain], "vfy-trust"),
    row("Timestamp", stamp, stamp === "ok" && proven.length ? `Proven to exist at ${when(Math.min(...proven))}, by an RFC 3161 timestamp.` : { ok: "The timestamp checks out.", bad: "A timestamp does not check out.", warn: "No trusted timestamp; the time rests on the check itself.", none: "No timestamp." }[stamp], "vfy-timestamp"),
    row("Revisions", disallowed ? "bad" : "ok", r.revisions ? `${r.revisions} revision${r.revisions === 1 ? "" : "s"}; ${disallowed ? `${disallowed} change the signed content` : "every later one only adds what the signatures allow"}.` : "No later revisions.", "vfy-revisions"),
  ];
  const text = r.state === "error" ? t("verify.state.error-text", { code: r.code }) : t(`verify.state.${r.state}-text`);
  const again = h("button", { type: "button", class: "btn btn-secondary btn-sm", "data-testid": "vfy-again" }, "Check another PDF");
  again.addEventListener("click", () => { out.replaceChildren(); input.click(); });

  const details = h("details", { class: "vfy-details" }, h("summary", { text: `Every check, signature by signature (${sigs.length})` }));
  for (const s of sigs) {
    details.append(h("section", { class: "vfy-sig", "data-testid": "vfy-signature" },
      h("h3", { text: `${t("verify.sig-n", { n: s.n, kind: t(`verify.kind.${s.kind}`) })}: ${t(`verify.sig.${s.verdict}`)}` }),
      s.sub ? h("p", { class: "muted" }, "Reason: ", h("code", { text: `${s.sub}${s.code ? ` (${s.code})` : ""}` })) : null,
      h("ul", { class: "vfy-checks" }, s.checks.map((c) => h("li", { class: `is-${report.checkTone(c.status)}` },
        mark(report.checkTone(c.status), 12),
        h("span", { text: `${t(`verify.check.${c.name}`)}: ${t(`verify.status.${c.status}`)}` }),
        c.sub ? h("code", { text: c.sub }) : null)))));
  }
  for (const c of r.changes) {
    const what = c.classes.map((x) => { const k = `verify.class.${x.split(":")[0]}`; return has(k) ? t(k) : x; }).join(", ");
    details.append(h("p", { class: `vfy-change is-${c.allowed ? "ok" : "bad"}` }, mark(c.allowed ? "ok" : "bad", 12), h("span", { text: t(c.allowed ? "verify.change-allowed" : "verify.change-disallowed", { n: c.revision, what }) })));
  }

  out.replaceChildren(h("section", { class: `vfy-verdict is-${tone}`, "data-testid": "vfy-verdict", "data-state": r.state, "aria-labelledby": "vfy-verdict-h" },
    h("div", { class: "vfy-verdict__head" },
      h("span", { class: "vfy-seal" }, mark(tone === "ok" ? "ok" : tone === "bad" ? "bad" : "warn", 22)),
      h("div", {},
        h("h2", { id: "vfy-verdict-h", text: t(`verify.state.${r.state}`) }),
        h("p", { text }))),
    h("ul", { class: "vfy-rows" }, rows),
    h("dl", { class: "vfy-facts" },
      h("dt", { text: "File" }), h("dd", { class: "vfy-ellipsis", title: name, text: name }),
      h("dt", { text: "Size" }), h("dd", { text: size < 1048576 ? `${Math.max(1, Math.round(size / 1024))} KB` : `${(size / 1048576).toFixed(1)} MB` }),
      h("dt", { text: "Trusted roots" }), h("dd", { text: trust.length ? trust.map((c) => c.name).join(", ") : "None" }),
      h("dt", { text: "Checked" }), h("dd", { text: `${new Date(checkedAt).toLocaleString()}, in this browser` })),
    sigs.length || r.changes.length ? details : null,
    h("div", { class: "cta-row" }, again)));
  out.focus({ preventScroll: false });
}

// ---- Start ------------------------------------------------------------------------------------

renderTrust();
engine().then((eng) => {
  if (eng) setEngine("ready", "Verifier ready. Checks run in this browser.");
  else setEngine("missing", "The verifier is not published with this copy of the site.");
});
