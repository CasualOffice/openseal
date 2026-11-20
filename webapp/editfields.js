// An editor changing fields during their turn (VS-06A, DocuSign's "Allow to edit";
// docs/24 §3): which fields they may move or remove, for whom they may add one, and the
// wire bodies `POST /s/{token}/editor/fields` and `PATCH …/editor/fields/{field}` take.
// The server decides (ceremony.rs `editable_owner`); this only shapes what the page
// offers, from the view's `fields`, `editable_fields` and `later_recipients`.
//
// Pure: no DOM, so `tests/editfields.test.mjs` runs it under Node.

import { placeAt, freeSpot, nudge, resize, toWire, fromWire, formatPoints, requiredByDefault, DEFAULT_SIZE } from "./geometry.js";

/// The field types an editor places on the signing page, in menu order: the common
/// ones (the full palette is the sender's editor).
/// `strikethrough` (FG-080, ADR-044) is a line the seal draws through the middle of
/// its box: the editor strikes out text they do not accept.
export const EDIT_TYPES = ["signature", "initials", "date_signed", "name", "text", "checkbox", "date", "strikethrough"];

/// Whether this view's recipient may change fields now: an editor whose view lists the
/// later recipients' fields (the server adds the member only for an authenticated editor).
export function canEditFields(view) {
  return view?.recipient?.type === "editor" && Array.isArray(view?.editable_fields);
}

/// The fields an editor may move or remove: their own (in `fields`), then the later
/// recipients' (`editable_fields`), each with its placement in numbers as `p`; a field
/// without a readable placement is left out.
export function editableFields(view) {
  const me = view?.recipient?.id;
  const own = (view?.fields || []).filter((f) => f.recipient_id === me);
  return [...own, ...(view?.editable_fields || [])]
    .map((f) => ({ ...f, p: fromWire(f.placement) }))
    .filter((f) => f.p);
}

/// For whom an editor may add a field: themself first, then each later recipient not
/// yet reached, `{id, name, me}`.
export function ownersOf(view) {
  const r = view?.recipient;
  if (!r) return [];
  return [{ id: r.id, name: r.name || "", me: true }, ...(view.later_recipients || []).map((q) => ({ id: q.id, name: q.name || "", me: false }))];
}

/// The name of field owner `id` as `ownersOf` knows it, else "".
export function ownerName(view, id) {
  return ownersOf(view).find((o) => o.id === id)?.name || "";
}

/// The new field's wire body: `type` for recipient `recipientId` on page `page` of
/// document `documentId`, placed at the page's centre (`page` `{width, height}` in
/// points) clear of `existing` rectangles on that page.
export function newField({ type, recipientId, documentId, pageNo, page, existing = [] }) {
  const size = DEFAULT_SIZE[type] || DEFAULT_SIZE.text;
  const start = placeAt(type, page.width / 2, page.height / 3, page);
  const r = freeSpot(existing, size, page, start.x + size.width / 2, start.y + size.height / 2);
  return { recipient_id: recipientId, document_id: documentId, type, required: requiredByDefault(type), ...toWire(pageNo, r) };
}

/// What an arrow key does to a field, in points: `[dx, dy, dw, dh]`. It moves it 1
/// point, or 10 with Shift; with Alt it resizes it instead (Right and Down grow it, so a
/// strike-through can be made as long as the words). Null for any other key.
export function keyStep({ key, shiftKey = false, altKey = false }) {
  const n = shiftKey ? 10 : 1;
  const steps = { ArrowLeft: [-n, 0], ArrowRight: [n, 0], ArrowUp: [0, -n], ArrowDown: [0, n] };
  const s = steps[key];
  if (!s) return null;
  return altKey ? [0, 0, s[0], s[1]] : [s[0], s[1], 0, 0];
}

/// Rectangle `r` moved by (dx, dy) points and resized by (dw, dh), kept on `page`.
export function moved(r, dx, dy, page, dw = 0, dh = 0) {
  const m = { ...r, ...nudge(r, dx, dy, page) };
  return dw || dh ? { ...m, ...resize(m, dw, dh, page) } : m;
}

/// The `PATCH` body for a field now at `r`: where it is and its size.
export function movePatch(r) {
  return { x: formatPoints(r.x), y: formatPoints(r.y), width: formatPoints(r.width), height: formatPoints(r.height) };
}

/// The ways an intermediary or editor may ask a later recipient to prove who they are,
/// in menu order (VS-06A; the sender offers the rest): none beyond the emailed link,
/// an access code, a code by email, a code by text message.
export const LATER_AUTH = ["none", "access_code", "email_otp", "sms_otp"];

/// The menu's choice for a recipient's methods `auth`: the first one it offers, else
/// "none" (a method it does not offer is kept unless another is chosen).
export function laterAuthOf(auth = []) {
  return LATER_AUTH.find((m) => m !== "none" && auth.includes(m)) || "none";
}

/// What `POST /s/{token}/recipients` is sent for one recipient's authentication, from
/// the menu: `{body}` the members to add (none when nothing changed), or `{error}`:
/// `need-code` (an access code chosen, none set before and none typed), `need-phone`
/// (a text message without a number in E.164).
export function laterAuthChange({ had, method, code = "", phone = "", oldPhone = "" }) {
  if (method === "access_code" && !code && had !== "access_code") return { error: "need-code" };
  if (method === "sms_otp" && !/^\+[1-9][0-9 .()-]{7,}$/.test(phone)) return { error: "need-phone" };
  const body = {};
  if (method !== had) body.auth = method === "none" ? [] : [method];
  if (method === "access_code" && code) { body.auth = ["access_code"]; body.access_code = code; }
  if (method === "sms_otp" && phone !== oldPhone) body.phone = phone;
  return { body: Object.keys(body).length ? body : null };
}
