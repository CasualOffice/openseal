// The verifier's report, for people (WEB-02 Verify). Pure: no DOM, so Node tests it.
//
// Input is the canonical JSON `verify()` returns from the WASM build of
// casual-sign-verify (`crates/casual-sign-wasm/src/api.rs`, `report_json`): `{"ok":
// report}` or `{"error": {code, message}}`. The verdict is the verifier's; this module
// only names it. It never upgrades one: a signature is "valid" only when the verifier
// says TOTAL_PASSED, and the document only when every signature is, and every change
// after the last one is of a kind the verifier allows (a DSS update or a document
// timestamp on a long-term signature).

/// The checks in the order a person reads them, with their message keys.
export const CHECKS = ["byte_range", "digest", "signature", "chain", "revocation", "timestamp", "modifications"];

/// Overall states: "valid", "invalid", "indeterminate", "unsigned", "error".
export function summarize(text) {
  let parsed;
  try { parsed = typeof text === "string" ? JSON.parse(text) : text; } catch { return { state: "error", code: "CS-API-0001", signatures: [], changes: [] }; }
  if (!parsed || typeof parsed !== "object") return { state: "error", code: "CS-API-0001", signatures: [], changes: [] };
  if (parsed.error) return { state: "error", code: String(parsed.error.code || "CS-API-0010"), signatures: [], changes: [] };
  const r = parsed.ok;
  if (!r || typeof r !== "object") return { state: "error", code: "CS-API-0001", signatures: [], changes: [] };
  if (r.error) return { state: "error", code: String(r.error.code || "CS-API-0010"), signatures: [], changes: [] };
  const sigs = Array.isArray(r.signatures) ? r.signatures : [];
  const changes = (Array.isArray(r.revision_changes) ? r.revision_changes : []).map((c) => ({
    revision: Number(c?.revision) || 0,
    allowed: c?.allowed === true,
    classes: (Array.isArray(c?.classes) ? c.classes : []).map(className),
  }));
  const signatures = sigs.map((s, i) => signature(s, i));
  let state;
  if (!signatures.length) state = "unsigned";
  else if (signatures.some((s) => s.verdict === "invalid") || changes.some((c) => !c.allowed)) state = "invalid";
  else if (signatures.every((s) => s.verdict === "valid")) state = "valid";
  else state = "indeterminate";
  return {
    state,
    code: null,
    revisions: Number(r.revisions) || 0,
    coveredByLast: r.covered_by_last_signature === true,
    signatures,
    changes,
    needsTrust: signatures.some((s) => s.sub === "NO_CERTIFICATE_CHAIN_FOUND"),
  };
}

function className(c) {
  if (typeof c === "string") return c;
  if (c && typeof c === "object" && typeof c.disallowed === "string") return `disallowed:${c.disallowed}`;
  return "unknown";
}

function signature(s, i) {
  const ind = s?.indication || {};
  const verdict = ind.indication === "TOTAL_PASSED" ? "valid" : ind.indication === "TOTAL_FAILED" ? "invalid" : "indeterminate";
  const kind = s?.kind?.type === "certification" ? "certification" : s?.kind?.type === "document_timestamp" ? "document_timestamp" : "approval";
  const secs = (d) => (d && Number.isFinite(d.secs) ? d.secs : null);
  const after = Array.isArray(s?.modifications_after) ? s.modifications_after : [];
  return {
    n: i + 1,
    object: Number.isInteger(s?.field) ? s.field : null,
    kind,
    permissions: kind === "certification" ? s.kind.permissions ?? null : null,
    verdict,
    indication: ind.indication || "INDETERMINATE",
    sub: ind.sub_indication || null,
    code: ind.code || null,
    subFilter: typeof s?.sub_filter === "string" ? s.sub_filter : "",
    /// The time the signature is proven to exist: a timestamp's, or none.
    time: secs(s?.timestamp),
    timeSource: s?.time_source || "validation_time",
    validationTime: secs(s?.validation_time),
    coversWhole: s?.covers_whole_document === true,
    signedRevision: Number(s?.signed_revision) || 0,
    changesAfter: after.length,
    changesAfterAllowed: after.every((c) => c?.allowed === true),
    checks: CHECKS.map((name) => ({
      name,
      status: ["passed", "failed", "not_run"].includes(s?.checks?.[name]?.status) ? s.checks[name].status : "not_run",
      sub: s?.checks?.[name]?.sub_indication || null,
      code: s?.checks?.[name]?.code || null,
    })),
  };
}

/// How a signature's coverage reads: "whole" (nothing after it), "allowed" (only
/// changes the verifier allows came after), "changed" (anything else).
export function coverage(sig) {
  if (sig.coversWhole) return "whole";
  return sig.changesAfterAllowed ? "allowed" : "changed";
}

/// A trust file to the base64 DER the verifier takes: DER as is, or every
/// "CERTIFICATE" block of a PEM file. Returns `[]` when there is none.
export function certificatesFrom(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (u8.length && u8[0] === 0x30) return [b64(u8)];
  const text = new TextDecoder("utf-8", { fatal: false }).decode(u8.subarray(0, 1 << 20));
  const out = [];
  for (const m of text.matchAll(/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/g)) {
    const body = m[1].replace(/\s+/g, "");
    if (body) out.push(body);
    if (out.length >= 32) break;
  }
  return out;
}

function b64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

// ---- Presentation rules (WEB-18 lane E) ------------------------------------------------
//
// What the page shows for a report, decided here so the view only renders. None of these
// adds a check or upgrades a verdict: they name what `summarize` already decided.

/// The real stages of a check, in order: the file is read and its header checked, the
/// verifier runs, the attached audit trail is read. The scanning screen lists these.
export const STEPS = ["read", "verify", "trail"];

/// Each stage's state while `current` runs: "done", "active" or "todo". "done" (or any
/// name that is not a stage) marks them all done.
export function stepStates(current) {
  const i = STEPS.indexOf(current);
  const at = i < 0 ? STEPS.length : i;
  return STEPS.map((id, n) => ({ id, state: n < at ? "done" : n === at ? "active" : "todo" }));
}

/// The receipt's colour for an overall state: "ok" (green seal) only for "valid";
/// "bad" (red) for a broken or unreadable file; "warn" (amber) for the rest.
export function verdictTone(state) {
  if (state === "valid") return "ok";
  if (state === "invalid" || state === "error") return "bad";
  return "warn";
}

/// One check's colour: passed → "ok", failed → "bad", anything else (not run) → "none".
export function checkTone(status) {
  return status === "passed" ? "ok" : status === "failed" ? "bad" : "none";
}

/// How many signatures the verifier found valid, invalid and not confirmed.
export function tally(signatures) {
  const out = { valid: 0, invalid: 0, indeterminate: 0 };
  for (const s of Array.isArray(signatures) ? signatures : []) if (s && Object.hasOwn(out, s.verdict)) out[s.verdict] += 1;
  return out;
}

/// A file size for people: `{ key, n }`, whole kilobytes under 1 MB (at least 1), else
/// megabytes to one decimal.
export function fileSize(bytes) {
  const b = Math.max(0, Number(bytes) || 0);
  if (b < 1024 * 1024) return { key: "verify.size-kb", n: Math.max(1, Math.round(b / 1024)) };
  return { key: "verify.size-mb", n: Math.round((b / (1024 * 1024)) * 10) / 10 };
}
