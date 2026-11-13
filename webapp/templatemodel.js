// Templates as data (WEB-02): the pure parts of saving a template from the editor and
// starting an envelope from one. No DOM and no network, so Node tests every rule.
//
// A template has **roles** where an envelope has people ("Client", "Witness"): a role
// has a name, a type (signer or cc) and a routing order. Fields name the role they
// belong to. Using a template fills each role with a person and becomes one
// `POST /api/v1/envelopes` body (documents, recipients, fields in one call), so it
// runs on today's envelope API.

import { settingsOf } from "./templatesync.js";

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/// Roles for `POST /api/v1/templates` from the editor's recipients. `routing` is either
/// a function giving each recipient's routing order (the editor's signing groups,
/// WEB-09), or "sequential" (signers 1, 2, 3…, CCs after them) or "parallel" (signers
/// share 1, CCs 2). Empty names become "Role n". Names are trimmed and kept unique (a
/// person filling the template tells roles apart by name), so a repeat gets " (2)".
export function rolesFrom(recipients, routing = "sequential") {
  const signers = recipients.filter((r) => r.type === "signer");
  const seen = new Map();
  return recipients.map((r, i) => {
    let name = (r.name || "").trim() || `Role ${i + 1}`;
    const n = (seen.get(name.toLowerCase()) || 0) + 1;
    seen.set(name.toLowerCase(), n);
    if (n > 1) name = `${name} (${n})`;
    const order = typeof routing === "function" ? routing(r, i)
      : r.type === "signer"
        ? (routing === "parallel" ? 1 : signers.indexOf(r) + 1)
        : (routing === "parallel" ? 2 : signers.length + 1);
    return { name: name.slice(0, 255), type: r.type === "cc" ? "cc" : "signer", routing_order: order };
  });
}

/// The roles of a template as the API returns them, sorted by routing order, each
/// with its id, a usable name and type (an API object with neither is "Role n").
export function rolesOf(template) {
  const list = Array.isArray(template?.roles) ? template.roles : [];
  return list
    .map((r, i) => ({
      id: typeof r?.id === "string" ? r.id : null,
      name: typeof r?.name === "string" && r.name.trim() ? r.name.trim() : `Role ${i + 1}`,
      type: r?.type === "cc" ? "cc" : "signer",
      routing_order: Number.isInteger(r?.routing_order) && r.routing_order > 0 ? r.routing_order : 1,
      index: i,
    }))
    .sort((a, b) => a.routing_order - b.routing_order || a.index - b.index);
}

/// What is missing before a template can be used: one entry per problem, as
/// `{role, problem: "name" | "email"}`. `people` is `{[roleName]: {name, email}}`.
export function peopleProblems(roles, people) {
  const out = [];
  for (const r of roles) {
    const p = people?.[r.name] || {};
    if (!(p.name || "").trim()) out.push({ role: r.name, problem: "name" });
    if (!EMAIL.test((p.email || "").trim())) out.push({ role: r.name, problem: "email" });
  }
  return out;
}

/// What is missing in the people added beyond the roles (UX-08): one entry per
/// problem, `{index, problem: "name" | "email"}`.
export function extraProblems(extra) {
  const out = [];
  (extra || []).forEach((p, index) => {
    if (!String(p?.name || "").trim()) out.push({ index, problem: "name" });
    if (!EMAIL.test(String(p?.email || "").trim())) out.push({ index, problem: "email" });
  });
  return out;
}

/// The `POST /api/v1/envelopes` body for a template filled with `people`.
///
/// - `docs`: `[{id, name, base64}]`, the template's documents with their bytes.
/// - `fields`: the template's fields, `{document_id, role_id, type, placement, required?,
///   label?, …settings}` as the server answers them (a `role` name is taken too).
/// - `status`: "draft" (open it in the editor) or "sent" (send at once).
///
/// A field whose role or document is not in the template is left out (the template
/// changed under it), and counted in the returned `dropped`.
///
/// - `extra` (UX-08): people added beyond the roles, `[{name, email, type: "signer" |
///   "cc"}]`, after every role in routing order (an added signer has no fields; it is
///   placed in the editor before sending).
export function envelopeFromTemplate(template, people, { docs = [], fields = [], subject, message, status = "draft", signingOptions = {}, extra = [] } = {}) {
  const roles = rolesOf(template);
  const ref = new Map(roles.map((r, i) => [r.name, `role${i}`]));
  const refById = new Map(roles.filter((r) => r.id).map((r) => [r.id, `role${roles.indexOf(r)}`]));
  const docIndex = new Map(docs.map((d, i) => [d.id, i]));
  let dropped = 0;
  const body = {
    subject: String(subject ?? template?.email_subject ?? template?.name ?? "").trim().slice(0, 255),
    message: String(message ?? template?.email_message ?? "").slice(0, 10000),
    status,
    signing_options: { ...signingOptions },
    documents: docs.map((d) => ({ name: d.name, content_base64: d.base64 })),
    recipients: roles.map((r, i) => ({
      ref: `role${i}`,
      type: r.type,
      name: (people?.[r.name]?.name || "").trim(),
      email: (people?.[r.name]?.email || "").trim(),
      routing_order: r.routing_order,
    })),
    fields: [],
  };
  const last = Math.max(0, ...roles.map((r) => r.routing_order));
  (extra || []).forEach((p, i) => body.recipients.push({
    ref: `extra${i}`,
    type: p?.type === "signer" ? "signer" : "cc",
    name: String(p?.name || "").trim(),
    email: String(p?.email || "").trim(),
    routing_order: last + 1,
  }));
  for (const f of fields) {
    const rf = f.role_id != null ? refById.get(f.role_id) : ref.get(f.role);
    const di = docIndex.get(f.document_id);
    if (rf === undefined || di === undefined || !f.placement) { dropped++; continue; }
    const field = { recipient: rf, document: di, type: f.type, page: f.placement.page, x: f.placement.x, y: f.placement.y, width: f.placement.width, height: f.placement.height };
    if (f.required) field.required = true;
    if (f.label) field.label = f.label;
    // Every setting the template kept (UX-11): tooltip, value, options, validation, format…
    Object.assign(field, settingsOf(f));
    body.fields.push(field);
  }
  return { body, dropped };
}

/// A counter as people read it: "7", or "200+" when the list went on past the page.
export function countLabel({ n, more }) {
  return more ? `${n}+` : String(n);
}
