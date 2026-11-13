// Saving a template from the editor (WEB-09, WEB-10): the editor's documents, roles and
// role-bound fields brought onto the server's template with the template endpoints of
// api/openapi.yaml (`/templates/{id}/documents`, `/roles`, `/fields`, each change with
// If-Match). The server is the source of truth: the editor reloads the template after.
//
// `templatePlan` is pure (Node tests it): what to remove, change and add, compared with
// the template as the server last answered. `applyTemplate` runs a plan in the order
// the references need: removals first (fields, then roles and documents, which take
// their fields with them), then role and document changes and additions (new fields
// need their ids), then field changes and additions.
//
// Shapes (server/…/api/templates.rs): a role `{id, name, type, routing_order}`; a
// document `{id, name, ord, pages, page_geometry, sha256}`; a field is the envelope
// field's wire form with `role_id` and `document_id`. Adding a document or a role
// answers the whole template, so the new one is the id that was not there before.
//
// A field carries every setting the editor offers (UX-11): `FIELD_SETTINGS`, sent when
// set, compared for "has it changed", and on a change all named, `null` for a cleared
// one (the server's `PATCH` is a JSON merge).

import { formatPoints, fromWire } from "./geometry.js";

/// A placement as the API takes it, from `{page, x, y, width, height}` in points.
export function wirePlacement(f) {
  return { page: f.page, x: formatPoints(f.x), y: formatPoints(f.y), width: formatPoints(f.width), height: formatPoints(f.height) };
}

/// The settings of a field the editor offers besides its place, owner, `required` and
/// `label` (UX-05, UX-11), by their wire names (api.js `FIELD_MEMBERS`).
export const FIELD_SETTINGS = Object.freeze(["read_only", "value", "tooltip", "placeholder", "validation", "format", "options", "allow_custom"]);

/// Whether a setting's value means "not set" (as the server leaves it out).
export const blankSetting = (v) => v == null || v === false || v === "" || (Array.isArray(v) && !v.length);

/// The settings a field has, in `FIELD_SETTINGS` order.
export function settingsOf(f) {
  return Object.fromEntries(FIELD_SETTINGS.filter((k) => !blankSetting(f?.[k])).map((k) => [k, f[k]]));
}

/// Every setting named, `null` for one not set: a `PATCH` that clears what was cleared.
export function settingsPatch(f) {
  return Object.fromEntries(FIELD_SETTINGS.map((k) => [k, blankSetting(f?.[k]) ? null : f[k]]));
}

/// A value with every object's keys sorted: the server answers a setting's members in
/// its own order (`format` sorted), which is not a change.
const canonical = (v) => (Array.isArray(v) ? v.map(canonical)
  : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])])) : v);

/// What identifies a field's content, for "has it changed": role, placement (to the
/// hundredth of a point), required, label, and its settings (in any member order).
export function fieldSig(roleId, placement, required, label, settings = {}) {
  const p = fromWire(placement) || {};
  return JSON.stringify([roleId || null, p.page, ...["x", "y", "width", "height"].map((k) => formatPoints(p[k] ?? 0)), !!required, label || "", canonical(settingsOf(settings))]);
}

/// The editor state (`st`) against the server's template (`server`):
/// - `st.details`: `{name, email_subject, email_message}`
/// - `st.roles`: `[{key, id|null, name, type, routing_order}]`
/// - `st.docs`: `[{key, id|null, name, bytes}]`
/// - `st.fields`: `[{key, id|null, roleKey, docKey, type, page, x, y, width, height, required, label, …settings}]`
///
/// Returns `{details|null, removeFields, removeRoles, removeDocs, patchRoles, addRoles,
/// addDocs, patchFields, addFields}`; ids for the removals and patches, keys for the
/// additions (resolved to ids as the additions are made).
export function templatePlan(server, st, { takesInput = () => true } = {}) {
  const sRoles = server?.roles || [];
  const sDocs = server?.documents || [];
  const sFields = server?.fields || [];
  const keepF = new Set(st.fields.filter((f) => f.id).map((f) => f.id));
  const keepR = new Set(st.roles.filter((r) => r.id).map((r) => r.id));
  const keepD = new Set(st.docs.filter((d) => d.id).map((d) => d.id));
  const d = st.details || {};
  const norm = (v) => (v == null ? "" : String(v));
  const details = norm(server?.name) !== norm(d.name) || norm(server?.email_subject) !== norm(d.email_subject) || norm(server?.email_message) !== norm(d.email_message)
    ? { name: d.name, email_subject: d.email_subject || null, email_message: d.email_message || null }
    : null;
  // A field on a removed role or document goes with it on the server: do not remove it twice.
  const goneR = new Set(sRoles.filter((r) => !keepR.has(r.id)).map((r) => r.id));
  const goneD = new Set(sDocs.filter((x) => !keepD.has(x.id)).map((x) => x.id));
  const removeFields = sFields.filter((f) => !keepF.has(f.id) && !goneR.has(f.role_id) && !goneD.has(f.document_id)).map((f) => f.id);
  const patchRoles = [];
  for (const r of st.roles.filter((x) => x.id)) {
    const s = sRoles.find((x) => x.id === r.id);
    if (!s) continue;
    const body = {};
    for (const k of ["name", "type", "routing_order"]) if (s[k] !== r[k]) body[k] = r[k];
    if (Object.keys(body).length) patchRoles.push({ id: r.id, body });
  }
  const roleIdOf = (k) => st.roles.find((r) => r.key === k)?.id || null;
  const patchFields = [];
  for (const f of st.fields.filter((x) => x.id)) {
    const s = sFields.find((x) => x.id === f.id);
    if (!s) continue;
    const req = !!f.required && takesInput(f.type);
    const now = fieldSig(roleIdOf(f.roleKey), wirePlacement(f), req, f.label, f);
    if (now === fieldSig(s.role_id, s.placement || s, s.required, s.label, s)) continue;
    patchFields.push({ id: f.id, key: f.key });
  }
  return {
    details,
    removeFields,
    removeRoles: [...goneR],
    removeDocs: [...goneD],
    patchRoles,
    addRoles: st.roles.filter((r) => !r.id).map((r) => r.key),
    addDocs: st.docs.filter((x) => !x.id).map((x) => x.key),
    patchFields,
    addFields: st.fields.filter((f) => !f.id).map((f) => f.key),
  };
}

/// Whether a plan changes nothing.
export function emptyPlan(p) {
  return !p.details && ["removeFields", "removeRoles", "removeDocs", "patchRoles", "addRoles", "addDocs", "patchFields", "addFields"].every((k) => !p[k].length);
}

/// The ids in `after` that are not in `before` (the document or role just added).
export function added(before, after) {
  const had = new Set((before || []).map((x) => x.id));
  return (after || []).filter((x) => !had.has(x.id));
}

/// A field as `POST /templates/{id}/fields` takes it.
export function fieldBody(f, roleId, docId, takesInput = () => true) {
  const body = { role_id: roleId, document_id: docId, type: f.type, placement: wirePlacement(f) };
  if (f.required && takesInput(f.type)) body.required = true;
  if (f.label) body.label = f.label;
  return { ...body, ...settingsOf(f) };
}

/// Run `plan` for template `id` against `api` (api.js's client). Ids of what is added
/// are written back onto `st`'s roles, documents and fields as they are made, so a
/// failure part-way leaves the editor knowing what the server already has. Returns the
/// template as it ends.
export async function applyTemplate(api, id, st, plan, { takesInput = () => true } = {}) {
  const etag = async () => (await api.templates.get(id)).etag;
  if (plan.details) await api.templates.patch(id, await etag(), plan.details);
  for (const f of plan.removeFields) await api.templates.removeField(id, f, await etag());
  for (const r of plan.removeRoles) await api.templates.removeRole(id, r, await etag());
  for (const d of plan.removeDocs) await api.templates.removeDocument(id, d, await etag());
  for (const p of plan.patchRoles) await api.templates.patchRole(id, p.id, await etag(), p.body);
  let tpl = (await api.templates.get(id)).template;
  for (const key of plan.addRoles) {
    const r = st.roles.find((x) => x.key === key);
    const next = await api.templates.addRole(id, { name: r.name, type: r.type, routing_order: r.routing_order });
    r.id = added(tpl.roles, next.roles)[0]?.id || null;
    tpl = next;
  }
  for (const key of plan.addDocs) {
    const d = st.docs.find((x) => x.key === key);
    const next = await api.templates.addDocument(id, d.name, d.bytes);
    d.id = added(tpl.documents, next.documents)[0]?.id || null;
    tpl = next;
  }
  const roleId = (k) => st.roles.find((r) => r.key === k)?.id;
  const docId = (k) => st.docs.find((x) => x.key === k)?.id;
  for (const p of plan.patchFields) {
    const f = st.fields.find((x) => x.key === p.key);
    await api.templates.patchField(id, p.id, await etag(), {
      role_id: roleId(f.roleKey), placement: wirePlacement(f), required: !!f.required && takesInput(f.type), label: f.label || null, ...settingsPatch(f),
    });
  }
  const fresh = plan.addFields.map((k) => st.fields.find((f) => f.key === k)).filter(Boolean);
  if (fresh.length) {
    const out = await api.templates.addFields(id, fresh.map((f) => fieldBody(f, roleId(f.roleKey), docId(f.docKey), takesInput)));
    (out?.items || []).forEach((x, i) => { if (fresh[i]) fresh[i].id = x.id; });
  }
  return (await api.templates.get(id)).template;
}
