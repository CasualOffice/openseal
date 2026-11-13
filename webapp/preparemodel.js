// The prepare editor's state rules (WEB-17 lane B; docs/47 §As built: the prepare editor
// on the approved canvas). Pure: no DOM, no network, so `tests/editor.test.mjs` runs them
// under Node. prepare.js renders from what these return and never decides these things
// itself:
//
// - the fields library and the floating tool bar (which kinds, in what order, by which
//   single key), as the canvas (docs/assets/design-canvas/Editor.dc.html) lists them;
// - the step control's done marks;
// - whether Continue is blocked on the fields step, and the sentence that says why;
// - the "Ready to send?" checks;
// - the recipients list in the left panel (number, role line, field count);
// - the template-match offer and how a template's roles and fields land on this draft;
// - the scanned pages (OCR) and the personal-data summary from the model's results.
//
// Messages are returned as `{key, params}` for `t()`, never as English.

import { FIELD_TYPES, clampRect } from "./geometry.js";
import { settingsOf } from "./templatesync.js";

/// The library's kinds with their single-key shortcuts, in the canvas's order, then the
/// kinds the canvas leaves under "More" (no key: typed less often).
export const LIBRARY = Object.freeze([
  ["signature", "S"], ["initials", "I"], ["date_signed", "D"], ["name", "N"],
  ["email", "E"], ["company", "O"], ["text", "T"], ["checkbox", "C"],
]);
export const LIBRARY_MORE = Object.freeze(FIELD_TYPES.filter((ty) => !LIBRARY.some(([k]) => k === ty)));

/// The floating tool bar: Select (V), then the six kinds the canvas puts there.
export const TOOLBAR = Object.freeze(["select", "signature", "initials", "date_signed", "name", "email", "checkbox"]);

/// The single key for each tool (Select is V).
export const TOOL_KEYS = Object.freeze(Object.fromEntries([["select", "V"], ...LIBRARY.map(([k, key]) => [k, key])]));

/// The tool a key press means on the fields step (`"select"`, a field type, or null).
/// Only a bare letter: any modifier, or a key that is not a single letter, is not a tool.
export function toolForKey({ key = "", ctrlKey = false, metaKey = false, altKey = false, shiftKey = false } = {}) {
  if (ctrlKey || metaKey || altKey || shiftKey || typeof key !== "string" || key.length !== 1) return null;
  const k = key.toUpperCase();
  for (const [tool, letter] of Object.entries(TOOL_KEYS)) if (letter === k) return tool;
  return null;
}

/// The step control: each step with whether it is the current one and whether it is done
/// (any step before the current one, as the canvas ticks them).
export function stepStates(steps, current) {
  const at = steps.indexOf(current);
  return steps.map((s, i) => ({ step: s, current: s === current, done: at > -1 && i < at }));
}

/// Who fills fields: a signer, and an in-person signer whom staff host.
export const takesFields = (r) => r?.type === "signer" || r?.type === "in_person_signer";

/// Each signer with how many fields and signature fields they have.
export function signerTally(recipients, fields) {
  return (recipients || []).filter(takesFields).map((r) => {
    const mine = (fields || []).filter((f) => f.recipientKey === r.key);
    return { key: r.key, fields: mine.length, signatures: mine.filter((f) => f.type === "signature").length };
  });
}

/// Whether Continue may leave the fields step (the canvas: a signer without a field, or a
/// suggestion still undecided, holds it), and the reason to show. Templates follow the same
/// rule. Other steps are never blocked here (the documents step waits for a document
/// itself, and Send lists its own problems).
export function continueState({ step, recipients = [], fields = [], ghosts = 0, docs = 0 } = {}) {
  if (step === "documents" && !docs) return { blocked: true, reason: { key: "wizard.need-doc", params: {} } };
  if (step !== "fields") return { blocked: false, reason: null };
  if (ghosts > 0) return { blocked: true, reason: { key: ghosts === 1 ? "prepare.why-suggestion-one" : "prepare.why-suggestions", params: { n: ghosts } } };
  const bare = signerTally(recipients, fields).filter((s) => s.fields === 0);
  if (bare.length) return { blocked: true, reason: { key: "prepare.why-signer", params: { n: bare.length } }, keys: bare.map((s) => s.key) };
  return { blocked: false, reason: null };
}

/// The "Ready to send?" checks: one per signer (a signature field; a field but no
/// signature; nothing yet), then undecided suggestions, then each scanned page whose text
/// was read by OCR. `name(r)` names a recipient. Each check is `{ok, key, params}`;
/// `ok: false` is amber.
export function sendChecks({ recipients = [], fields = [], ghosts = 0, ocrPages = [] } = {}, name = (r) => r.name) {
  const out = [];
  const tally = new Map(signerTally(recipients, fields).map((s) => [s.key, s]));
  for (const r of recipients.filter(takesFields)) {
    const s = tally.get(r.key);
    if (s.signatures) out.push({ ok: true, key: "prepare.check-sig", params: { name: name(r) } });
    else if (s.fields) out.push({ ok: false, key: "prepare.check-no-sig", params: { name: name(r) } });
    else out.push({ ok: false, key: "prepare.check-none", params: { name: name(r) } });
  }
  out.push(ghosts ? { ok: false, key: ghosts === 1 ? "prepare.check-ghost-one" : "prepare.check-ghosts", params: { n: ghosts } } : { ok: true, key: "prepare.check-no-ghosts", params: {} });
  for (const p of ocrPages) out.push({ ok: true, key: "prepare.check-ocr", params: { page: p } });
  return out;
}

/// The recipients list on the fields step: every recipient who takes fields, numbered by
/// their place in the list, with a role line and their field count.
export function recipientRows(recipients, fields, { order = (r) => r.order || 1, ordered = true } = {}) {
  return (recipients || []).map((r, i) => ({ r, i })).filter(({ r }) => takesFields(r)).map(({ r, i }) => ({
    key: r.key,
    n: i + 1,
    role: { key: ordered ? "prepare.role-step" : "prepare.role-once", params: { type: r.type, n: order(r) } },
    count: (fields || []).filter((f) => f.recipientKey === r.key).length,
  }));
}

/// The template-match offer: the open `template` suggestion with the highest score and a
/// template to apply, or null.
export function templateOffer(suggestions) {
  const open = (suggestions || []).filter((s) => s?.kind === "template" && (s.state === "open" || s.state == null) && s.template_id);
  open.sort((a, b) => Number(b.score || 0) - Number(a.score || 0));
  return open[0] || null;
}

/// How a template lands on this draft (the template-application path of templates.js,
/// `envelopeFromTemplate`, for a draft that already has its documents): the template's
/// roles become recipients in routing order, taking the draft's recipients' places one
/// for one (the draft's people keep their names and emails), extra roles become new
/// recipients named after the role; each template field goes on the draft's document of
/// the same position, on the same page, clamped to it, with its settings (UX-11). A field whose document or page the
/// draft lacks is dropped and counted. Returns `{recipients, fields, dropped}` where
/// `recipients` is the new list (existing objects updated in a copy) and `fields` the new
/// fields; `newKey(prefix)` makes keys.
export function applyTemplatePlan(template, { docs = [], recipients = [] } = {}, newKey) {
  const roles = [...(template?.roles || [])].sort((a, b) => (a.routing_order ?? 1) - (b.routing_order ?? 1));
  const tdocs = [...(template?.documents || [])].sort((a, b) => (a.ord ?? 0) - (b.ord ?? 0));
  const out = recipients.map((r) => ({ ...r }));
  const roleKey = new Map();
  roles.forEach((role, i) => {
    const type = typeof role.type === "string" ? role.type : "signer";
    const existing = out[i];
    if (existing) {
      Object.assign(existing, { type, order: role.routing_order ?? existing.order ?? i + 1 });
      roleKey.set(role.id, existing.key);
    } else {
      const r = { key: newKey("r"), id: null, name: String(role.name || ""), email: "", type, accessCode: "", order: role.routing_order ?? i + 1 };
      out.push(r);
      roleKey.set(role.id, r.key);
    }
  });
  const fields = [];
  let dropped = 0;
  for (const f of template?.fields || []) {
    const di = tdocs.findIndex((d) => d.id === f.document_id);
    const doc = docs[di];
    const p = f.placement || f;
    const page = Number(p.page);
    const pg = doc?.pages?.[page - 1];
    const rk = roleKey.get(f.role_id);
    if (!doc || !pg || !rk || !FIELD_TYPES.includes(f.type)) { dropped++; continue; }
    const rect = clampRect({ x: Number(p.x), y: Number(p.y), width: Number(p.width), height: Number(p.height) }, pg);
    fields.push({ key: newKey("f"), id: null, docKey: doc.key, recipientKey: rk, type: f.type, page, ...rect, required: !!f.required, label: f.label || "", ...settingsOf(f) });
  }
  return { recipients: out, fields, dropped };
}

/// The pages read by OCR across the draft's documents, numbered as the editor lays them
/// out (`offsets[i]` is the number of pages before document `i`). `analyses[i]` is the
/// analysis answer for document `i`, or null.
export function ocrPagesFrom(analyses, offsets) {
  const out = [];
  (analyses || []).forEach((a, i) => {
    if (!a || a.status !== "done" || !Array.isArray(a.ocr_pages)) return;
    for (const p of a.ocr_pages) if (Number.isInteger(p) && p > 0) out.push((offsets?.[i] || 0) + p);
  });
  return [...new Set(out)].sort((a, b) => a - b);
}

/// The personal-data card: open `personal_data` suggestions grouped by page, the page with
/// the most first: `{page, total, labels: [[label, n]]}` or null when there are none.
export function piiSummary(suggestions) {
  const open = (suggestions || []).filter((s) => s?.kind === "personal_data" && (s.state === "open" || s.state == null));
  if (!open.length) return null;
  const byPage = new Map();
  for (const s of open) {
    const p = Number.isInteger(s.page) ? s.page : 0;
    if (!byPage.has(p)) byPage.set(p, []);
    byPage.get(p).push(s);
  }
  const [page, list] = [...byPage.entries()].sort((a, b) => b[1].length - a[1].length || a[0] - b[0])[0];
  const labels = new Map();
  for (const s of list) labels.set(String(s.label || ""), (labels.get(String(s.label || "")) || 0) + 1);
  return { page, total: list.length, pages: byPage.size, labels: [...labels.entries()] };
}
