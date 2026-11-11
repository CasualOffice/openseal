// Field detection in the editor (WEB-09; DocuSign's and SignNow's auto-place): the
// server's `POST …/documents/{doc}/detect-fields` suggestions turned into ghost fields
// the sender accepts one by one, all at once, or dismisses. Pure (Node tests it).
//
// A suggestion is in the field endpoints' geometry (ADR-019: displayed page space,
// points, origin top-left; decimals as strings). The editor's palette places the
// Release 1 field types; a suggestion of another type (title, company, a form field's
// own type) becomes a text field labelled with its cue, so nothing suggested is lost.

import { FIELD_TYPES, fromWire, clampRect, overlaps } from "./geometry.js";

/// Kinds whose cue would only repeat what the field shows already.
const SELF_EVIDENT = new Set(["signature", "initials", "date_signed", "name", "email", "checkbox"]);

/// Ghosts from the server's suggestions: `items` as the API answers them, `docs` the
/// editor's documents (`{key, id, pages}`), `placed` its fields. A suggestion is left
/// out when its document or page is not there, its geometry is unreadable, or it lies
/// on a field already placed or on an earlier suggestion. Each ghost is
/// `{key, docKey, page, x, y, width, height, type, label, cue, confidence, source}`.
export function suggestionsFrom(items, docs, placed, newKey) {
  const out = [];
  for (const s of Array.isArray(items) ? items : []) {
    const d = docs.find((x) => x.id && x.id === s?.document_id);
    if (!d) continue;
    const p = fromWire(s);
    const pg = p && d.pages[p.page - 1];
    if (!pg) continue;
    const rect = clampRect(p, pg);
    const here = (f) => f.docKey === d.key && f.page === p.page && overlaps(rect, f, 0);
    if (placed.some(here) || out.some(here)) continue;
    const type = FIELD_TYPES.includes(s.type) ? s.type : "text";
    const cue = typeof s.cue === "string" ? s.cue.slice(0, 64) : "";
    out.push({
      key: newKey(), docKey: d.key, page: p.page, ...rect, type,
      label: SELF_EVIDENT.has(type) ? "" : cue, cue,
      confidence: Number.isFinite(s.confidence) ? s.confidence : 0, source: String(s.source || ""),
    });
  }
  return out;
}
