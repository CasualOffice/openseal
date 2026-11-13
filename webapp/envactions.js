// What Agreements and the envelope page share (WEB-06; docs/47 §UX audit A-01, A-03,
// E-01, E-02, E-05): a one-line status ("Waiting for Taylor Kim"), who did each audit
// event, the history panel, and the actions on one envelope — copy, save as template,
// delete, download the PDF as it stands, correct. Each screen calls these and refreshes
// itself; nothing here keeps state.

import { h, fmtDate, fmtShortDate, download } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { toBase64, corrections } from "./api.js";
import { added } from "./templatesync.js";
import { recipientCorrection } from "./people.js";
import { DELETABLE, ACTIVE, ENDED } from "./managemodel.js";
import { openPanel, toast, confirmDialog, reasonDialog, emptyState, button } from "./ui/index.js";

const SIGNING = new Set(["signer", "in_person_signer", "approver"]);
const ACTED = new Set(["completed", "declined"]);
// The state sets live in managemodel.js (UX-07, pure); re-exported for the screens.
export { DELETABLE, ACTIVE, ENDED };

/// A short date for lists and status lines (UX-07); `fmtDate` gives the full one for a
/// tooltip.
export const shortDate = (iso, now) => fmtShortDate(iso, { today: t("dates.today"), yesterday: t("dates.yesterday") }, now);

const byOrder = (e) => [...(e?.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);
const who = (r) => r?.name || r?.email || t("actor.unknown");

/// The recipients the envelope is waiting for: signing recipients who have been sent
/// it and not acted, at the lowest routing order still open.
export function waitingFor(e) {
  const open = byOrder(e).filter((r) => SIGNING.has(r.type) && !ACTED.has(r.status));
  if (!open.length) return [];
  const sent = open.filter((r) => r.status === "sent" || r.status === "delivered");
  if (sent.length) return sent;
  const first = Math.min(...open.map((r) => r.routing_order));
  return open.filter((r) => r.routing_order === first);
}

/// One line saying where an envelope stands, in words (A-01): "Waiting for Taylor Kim".
export function statusLine(e) {
  if (!e) return "";
  switch (e.status) {
    case "draft": return "";
    case "sent":
    case "delivered": {
      const names = waitingFor(e).map(who);
      return names.length ? t("agreements.line.waiting", { names: names.join(", ") }) : "";
    }
    case "completed": return t("agreements.line.completed", { date: shortDate(e.ended_at) });
    case "declined": return t("agreements.line.declined", { name: who(byOrder(e).find((r) => r.status === "declined")) });
    case "voided": return t("agreements.line.voided", { date: shortDate(e.ended_at) });
    case "expired": return t("agreements.line.expired", { date: shortDate(e.ended_at || e.expires_at) });
    default: return "";
  }
}

/// Who did an audit event (E-05): the event's `actor` (docs/32 §2: `{kind, id, name}`;
/// the mock writes `"sender"`, `"recipient"` or `"system"`), else its recipient, else
/// the system. `senderName` names the sending user.
export function actorOf(item, env, senderName = "") {
  const ev = item?.event || {};
  const a = ev.actor;
  const kind = a && typeof a === "object" ? a.kind : a;
  // Only an event a recipient made is theirs; the system's invitation to them is not.
  const rid = kind === "recipient" ? (a.id || ev.data?.recipient_id) : null;
  const sender = () => t("actor.sender", { name: (a && typeof a === "object" && a.name) || senderName || t("agreements.you") });
  if (kind === "sender" || kind === "user" || kind === "api_client") return sender();
  if (kind === "recipient") {
    const r = (env?.recipients || []).find((x) => x.id === rid);
    return t("actor.recipient", { name: (a && typeof a === "object" && a.name) || who(r) });
  }
  return t("actor.system");
}

/// The label of an audit event type, or the type itself when there is none.
export function eventLabel(type) {
  const label = t(`event.${type}`);
  return label === `event.${type}` ? type : label;
}

/// The audit events as a table: number, event, by whom, when, hash.
export function auditTable(audit, env, senderName) {
  const table = h("table", { class: "os-table os-table--compact os-table--cards os-audit" },
    h("caption", { class: "os-sr-only", text: t("envelope.audit") }),
    h("thead", {}, h("tr", {},
      h("th", { class: "os-col-num", attrs: { scope: "col" }, text: "#" }),
      h("th", { attrs: { scope: "col" }, text: t("audit.event") }),
      h("th", { attrs: { scope: "col" }, text: t("envelope.by") }),
      h("th", { attrs: { scope: "col" }, text: t("audit.when") }),
      h("th", { attrs: { scope: "col" }, class: "os-col-hash", text: t("audit.hash") }))));
  const tb = h("tbody");
  for (const a of audit.items || []) {
    tb.append(h("tr", {},
      h("td", { class: "os-col-num", text: String(a.seq) }),
      h("td", { class: "os-audit__event", text: eventLabel(a.type) }),
      h("td", { attrs: { "data-label": t("envelope.by") }, text: actorOf(a, env, senderName) }),
      h("td", { attrs: { "data-label": t("audit.when") } }, h("time", { attrs: { datetime: a.at }, text: fmtDate(a.at) })),
      h("td", { class: "os-col-hash" }, h("code", { attrs: { title: a.hash }, text: `${(a.hash || "").slice(0, 12)}…` }))));
  }
  table.append(tb);
  return h("div", { class: "os-table-wrap" }, table);
}

/// The plain verb a person expects for an audit event in the History panel (UX-07):
/// "Signed", "Viewed", "Declined"; the audit trail's own label otherwise.
export function historyVerb(type) {
  const label = t(`history.${type}`);
  return label === `history.${type}` ? eventLabel(type) : label;
}

/// Copy `text` to the clipboard and say so; a browser that refuses says that instead.
export async function copyText(text, done = t("action.copied")) {
  try { await navigator.clipboard.writeText(text); toast(done, "success"); } catch { toast(t("action.copy-failed"), "error"); }
}

/// The audit events as a vertical timeline (UX-07, the History panel): the verb in
/// bold, who and when under it, and the event's hash in a disclosure with a copy button.
export function historyTimeline(audit, env, senderName = "") {
  const ol = h("ol", { class: "os-histline", attrs: { "data-testid": "history-timeline" } });
  for (const a of audit.items || []) {
    const hash = a.hash || "";
    ol.append(h("li", { class: "os-histline__item" },
      h("strong", { class: "os-histline__verb", text: historyVerb(a.type) }),
      h("span", { class: "os-muted os-small" }, h("span", { text: `${actorOf(a, env, senderName)} · ` }), h("time", { attrs: { datetime: a.at, title: fmtDate(a.at) }, text: fmtDate(a.at) })),
      hash ? h("details", { class: "os-histline__details" },
        h("summary", { text: t("history.details") }),
        h("div", { class: "os-histline__hash" },
          h("code", { text: hash }),
          button(t("history.copy-hash"), { icon: "copy", size: "sm", variant: "ghost", iconOnly: true, onClick: () => copyText(hash) }))) : null));
  }
  return ol;
}

/// The history of one envelope in a side panel (A-03 "History"; UX-07 a timeline).
export async function historyPanel(ctx, id, subject) {
  const [{ envelope }, audit] = await Promise.all([ctx.api.getEnvelope(id), ctx.api.audit(id)]);
  await openPanel({
    id: "history",
    title: t("agreements.history-title", { subject }),
    width: 44,
    build(body) {
      if (!(audit.items || []).length) { body.append(emptyState({ illus: "documents", title: t("envelope.audit-empty"), text: "" })); return; }
      body.append(historyTimeline(audit, envelope, ""));
    },
    actions: [{ label: t("action.close"), value: null }],
  });
}

/// Void one or more envelopes with one dialog (UX-07): the count, what voiding does,
/// and the reason recipients see; a filled danger button. Resolves true when voided.
export async function voidEnvelopes(ctx, ids) {
  const many = ids.length > 1;
  const reason = await reasonDialog(
    many ? t("agreements.void-many-title", { n: ids.length }) : t("envelope.void-title"),
    t("envelope.void-label"),
    { confirm: many ? t("agreements.bulk-void", { n: ids.length }) : t("envelope.void"), consequence: t("envelope.void-consequence") },
  );
  if (!reason) return false;
  for (const id of ids) await ctx.api.voidEnvelope(id, reason);
  toast(t(many ? "agreements.voided-n" : "envelope.voided", { n: ids.length }), "success");
  return true;
}

/// Fetch every document of an envelope as `{name, content_base64}`.
async function docsOf(ctx, e, variant = "normalized") {
  const out = [];
  for (const d of e.documents || []) {
    const blob = await ctx.api.documentContent(e.id, d.id, variant);
    out.push({ id: d.id, name: d.name, content_base64: toBase64(new Uint8Array(await blob.arrayBuffer())) });
  }
  return out;
}
const num = (v) => Number.parseFloat(v);

/// Copy (A-03): a new draft with the same documents, recipients, fields, message and
/// options. Access codes are secrets and are not copied; the copy asks for them again.
export async function copyEnvelope(ctx, id) {
  const { envelope: e } = await ctx.api.getEnvelope(id);
  const docs = await docsOf(ctx, e);
  const docIndex = new Map(docs.map((d, i) => [d.id, i]));
  const recs = byOrder(e);
  const body = {
    subject: e.subject ? `${e.subject} (copy)`.slice(0, 255) : "",
    message: e.message || "",
    signing_options: e.signing_options || {},
    documents: docs.map(({ name, content_base64 }) => ({ name, content_base64 })),
    recipients: recs.map((r, i) => ({ ref: `r${i}`, type: r.type, name: r.name, email: r.email || undefined, routing_order: r.routing_order, auth: (r.auth || []).filter((m) => m !== "access_code") })),
    fields: (e.fields || []).filter((f) => docIndex.has(f.document_id) && recs.some((r) => r.id === f.recipient_id)).map((f) => ({
      recipient: `r${recs.findIndex((r) => r.id === f.recipient_id)}`,
      document: docIndex.get(f.document_id),
      type: f.type,
      page: f.placement.page, x: num(f.placement.x), y: num(f.placement.y), width: num(f.placement.width), height: num(f.placement.height),
      ...(f.required ? { required: true } : {}),
      ...(f.label ? { label: f.label } : {}),
    })),
  };
  const created = await ctx.api.createEnvelope(body);
  toast(t("agreements.copied"), "success");
  return created;
}

/// Save as template (A-03): roles "Role 1…n" in routing order, then the documents and
/// the fields bound to the roles' ids (the server answers the template with ids; adding
/// a document answers the whole template, so the new document is the one not there).
export async function saveAsTemplate(ctx, id) {
  const { envelope: e } = await ctx.api.getEnvelope(id);
  const recs = byOrder(e);
  const roleOf = new Map(recs.map((r, i) => [r.id, t("template.role-n", { n: i + 1 })]));
  const name = (e.subject || t("envelope.untitled")).slice(0, 255);
  const tpl = await ctx.api.templates.create({
    name, ...(e.subject ? { email_subject: e.subject } : {}), ...(e.message ? { email_message: e.message } : {}),
    roles: recs.map((r) => ({ name: roleOf.get(r.id), type: r.type, routing_order: r.routing_order })),
  });
  const roleId = new Map(recs.map((r) => [r.id, (tpl.roles || []).find((x) => x.name === roleOf.get(r.id))?.id]));
  const docs = await docsOf(ctx, e);
  const ids = new Map();
  let known = tpl.documents || [];
  for (const d of docs) {
    const bytes = Uint8Array.from(atob(d.content_base64), (c) => c.charCodeAt(0));
    const next = await ctx.api.templates.addDocument(tpl.id, d.name, bytes);
    ids.set(d.id, added(known, next?.documents)[0]?.id);
    known = next?.documents || known;
  }
  const fields = (e.fields || []).filter((f) => ids.get(f.document_id) && roleId.get(f.recipient_id));
  if (fields.length) {
    await ctx.api.templates.addFields(tpl.id, fields.map((f) => ({
      role_id: roleId.get(f.recipient_id), document_id: ids.get(f.document_id), type: f.type, placement: f.placement,
      ...(f.required ? { required: true } : {}), ...(f.label ? { label: f.label } : {}),
    })));
  }
  toast(t("agreements.template-saved", { name }), "success");
  return tpl;
}

/// Delete (A-03; a destructive confirmation, so a modal). Resolves true when deleted.
export async function deleteEnvelope(ctx, id, subject, status) {
  const draft = status === "draft";
  const ok = await confirmDialog(t(draft ? "agreements.delete-draft-title" : "agreements.delete-title"), t("agreements.delete-text", { subject }), { confirm: t(draft ? "agreements.delete-draft" : "agreements.delete"), danger: true });
  if (!ok) return false;
  const { etag } = await ctx.api.getEnvelope(id);
  await ctx.api.deleteEnvelope(id, etag);
  toast(t("agreements.deleted"), "success");
  return true;
}

/// Download each document as it stands (E-02): while the envelope is in progress, or as
/// it ended when declined, voided or expired (UX-07). `version=current` serves any
/// envelope that was sent (docs/40), with a "not signed" banner unless sealed.
export async function downloadCurrent(ctx, id, env = null) {
  const e = env || (await ctx.api.getEnvelope(id)).envelope;
  const suffix = ENDED.has(e.status) ? e.status : "current";
  for (const d of e.documents || []) {
    download(await ctx.api.documentContent(id, d.id, "current"), `${(d.name || "document.pdf").replace(/\.pdf$/i, "")}-${suffix}.pdf`);
  }
}

/// The certificate of an envelope (completed; ended ones once `certificateEnded` is
/// served, UXW-30).
export async function downloadCertificate(ctx, id) {
  download(await ctx.api.certificate(id), `certificate-${id}.pdf`);
}

/// Whether the certificate can be asked for in this state: a completed envelope's
/// always; an ended one's (UXW-30) where the backend serves it.
export function hasCertificate(ctx, status) {
  return status === "completed" || (ENDED.has(status) && !!ctx.api.available?.("certificateEnded"));
}

/// Download the sealed documents of a completed envelope.
export async function downloadSealed(ctx, id, env = null) {
  const e = env || (await ctx.api.getEnvelope(id)).envelope;
  for (const d of e.documents || []) {
    download(await ctx.api.documentContent(id, d.id, "sealed"), `${(d.name || "document.pdf").replace(/\.pdf$/i, "")}-sealed.pdf`);
  }
}

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/// Correct a sent envelope (E-01, DocuSign's Correct) in a side panel. For each
/// recipient who has not acted: name, email, access code and signing order, or remove
/// them; add a recipient; change the expiry and the reminders (UX-07). Recipients who
/// have acted are shown locked. Resolves true when corrected.
///
/// WEB-10: a changed recipient is one `PATCH …/recipients/{r}` (If-Match), which the
/// server applies as a correction of a sent envelope. `POST …/correct`'s
/// `update_recipient` replaces the whole engine `RecipientSpec`, refuses an
/// `access_code` member, and needs members the API does not show (`date_format`), so
/// it would drop settings or fail; the PATCH keeps the rest and stores the code (and
/// the routing order). Adding and removing recipients, the expiry and the reminders go
/// in one `POST …/correct` change list (UX-07; casual-sign-workflow `Change`), all or
/// none, before the PATCHes. A full editor-based Correct (fields, documents) is UXW-19.
export async function correctPanel(ctx, id) {
  const { envelope: e, etag } = await ctx.api.getEnvelope(id);
  const recs = byOrder(e);
  const rows = [];
  const fresh = [];
  let list;
  let expiry;
  let first;
  let every;
  let settingsErr;
  const lastOrder = () => Math.max(1, ...recs.map((r) => r.routing_order || 1), ...fresh.map((x) => Number(x.order.value) || 1));
  const dateOf = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "" : `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  };
  const rem = e.reminders || {};
  const orderInput = (pid, value) => h("input", { id: `${pid}-order`, class: "os-input os-input--sm os-correct__order", type: "number", min: 1, max: 99, step: 1, value: String(value), attrs: { inputmode: "numeric" } });

  function addRow() {
    const n = fresh.length + rows.length + 1;
    const p = `cr-new-${n}-${Math.random().toString(36).slice(2, 6)}`;
    const name = h("input", { id: `${p}-name`, class: "os-input", maxLength: 255, autocomplete: "off", attrs: { "aria-describedby": `${p}-err` } });
    const email = h("input", { id: `${p}-email`, class: "os-input", type: "email", autocomplete: "off", attrs: { "aria-describedby": `${p}-err` } });
    const type = h("select", { id: `${p}-type`, class: "os-input os-select" }, ["signer", "approver", "viewer", "cc"].map((k) => h("option", { value: k, text: t(`rtype.${k}`) })));
    const order = orderInput(p, lastOrder() + (fresh.length ? 0 : 1));
    const err = h("p", { id: `${p}-err`, class: "os-field-error", attrs: { "aria-live": "polite" } });
    const li = h("li", { class: "os-correct__item is-new", attrs: { "data-testid": "correct-new" } });
    const x = { name, email, type, order, err, li };
    const remove = button(t("envelope.correct-remove-new"), { icon: "x", size: "sm", variant: "ghost", onClick: () => { li.remove(); fresh.splice(fresh.indexOf(x), 1); } });
    li.append(
      h("div", { class: "os-correct__head" }, h("strong", { text: t("envelope.correct-new") }), h("span", { class: "os-spacer" }), remove),
      h("label", { class: "os-label", attrs: { for: `${p}-name` }, text: t("prepare.name") }), name,
      h("label", { class: "os-label", attrs: { for: `${p}-email` }, text: t("prepare.email") }), email,
      h("div", { class: "os-correct__pair" },
        h("div", {}, h("label", { class: "os-label", attrs: { for: `${p}-type` }, text: t("envelope.correct-type") }), type),
        h("div", {}, h("label", { class: "os-label", attrs: { for: `${p}-order` }, text: t("envelope.correct-order") }), order)),
      err);
    fresh.push(x);
    list.append(li);
    name.focus();
  }

  const result = await openPanel({
    id: "correct",
    title: t("envelope.correct-title"),
    width: 32,
    build(body) {
      body.append(h("p", { class: "os-muted", text: t("envelope.correct-lede") }));
      body.append(h("h3", { class: "os-correct__section", text: t("envelope.recipients") }));
      list = h("ol", { class: "os-correct" });
      recs.forEach((r, i) => {
        const acted = ACTED.has(r.status);
        const head = h("div", { class: "os-correct__head" },
          h("span", { class: "os-order", text: String(r.routing_order) }),
          h("strong", { text: who(r) }),
          h("span", { class: "os-muted os-small", text: t(`rtype.${r.type}`) }));
        const li = h("li", { class: `os-correct__item os-r${(i % 6) + 1}${acted ? " is-acted" : ""}` }, head);
        if (acted) {
          li.append(h("p", { class: "os-muted os-small", text: t("envelope.correct-acted", { name: who(r) }) }));
          list.append(li);
          return;
        }
        const p = `cr-${i}`;
        const name = h("input", { id: `${p}-name`, class: "os-input", value: r.name || "", maxLength: 255, autocomplete: "off", attrs: { "aria-describedby": `${p}-err` } });
        const email = h("input", { id: `${p}-email`, class: "os-input", type: "email", value: r.email || "", autocomplete: "off", attrs: { "aria-describedby": `${p}-err` } });
        const had = (r.auth || []).includes("access_code");
        const req = h("input", { id: `${p}-req`, type: "checkbox", class: "os-checkbox", checked: had });
        const code = h("input", { id: `${p}-code`, class: "os-input", type: "text", autocomplete: "off", maxLength: 255, attrs: { "aria-describedby": `${p}-code-help ${p}-err` } });
        const codeRow = h("div", { class: "os-correct__code" },
          h("label", { class: "os-label", attrs: { for: `${p}-code` }, text: t("envelope.correct-code") }), code,
          h("p", { id: `${p}-code-help`, class: "os-help", text: t("envelope.correct-code-help") }));
        codeRow.hidden = !had;
        req.addEventListener("change", () => { codeRow.hidden = !req.checked; });
        const order = orderInput(p, r.routing_order || 1);
        const err = h("p", { id: `${p}-err`, class: "os-field-error", attrs: { "aria-live": "polite" } });
        const fieldsBox = h("div", { class: "os-correct__fields" },
          h("label", { class: "os-label", attrs: { for: `${p}-name` }, text: t("prepare.name") }), name,
          h("label", { class: "os-label", attrs: { for: `${p}-email` }, text: t("prepare.email") }), email,
          h("div", { class: "os-correct__pair" },
            h("div", {}, h("label", { class: "os-label", attrs: { for: `${p}-order` }, text: t("envelope.correct-order") }), order)),
          h("label", { class: "os-check", attrs: { for: `${p}-req` } }, req, h("span", { text: t("envelope.require-code") })),
          codeRow);
        const x = { r, name, email, req, code, order, err, had, removed: false };
        const removedNote = h("p", { class: "os-muted os-small", hidden: true, text: t("envelope.correct-removed", { name: who(r) }) });
        const remove = button(t("envelope.correct-remove"), { icon: "trash-2", size: "sm", variant: "ghost", attrs: { "aria-label": t("envelope.correct-remove-named", { name: who(r) }) }, onClick: () => {
          x.removed = !x.removed;
          li.classList.toggle("is-removed", x.removed);
          fieldsBox.hidden = x.removed;
          removedNote.hidden = !x.removed;
          remove.setAttribute("aria-label", t(x.removed ? "envelope.correct-undo-remove-named" : "envelope.correct-remove-named", { name: who(r) }));
          remove.querySelector("span")?.replaceChildren(t(x.removed ? "envelope.correct-undo-remove" : "envelope.correct-remove"));
        } });
        head.append(h("span", { class: "os-spacer" }), remove);
        li.append(fieldsBox, removedNote, err);
        rows.push(x);
        list.append(li);
      });
      body.append(list);
      body.append(h("div", { class: "os-correct__add" }, button(t("envelope.correct-add"), { icon: "user-plus", size: "sm", attrs: { "data-testid": "correct-add" }, onClick: addRow })));
      if (!rows.length) body.append(h("p", { class: "os-muted", attrs: { "data-testid": "correct-none" }, text: t("envelope.correct-none") }));

      // Expiry and reminders (UX-07): `set_expiry` and `set_reminders` in the change list.
      expiry = h("input", { id: "cr-expiry", class: "os-input", type: "date", value: dateOf(e.expires_at), attrs: { "aria-describedby": "cr-expiry-help cr-settings-err" } });
      first = h("input", { id: "cr-first", class: "os-input os-input--sm", type: "number", min: 0, max: 999, step: 1, value: String(rem.first_after_days || 0), attrs: { inputmode: "numeric", "aria-describedby": "cr-rem-help" } });
      every = h("input", { id: "cr-every", class: "os-input os-input--sm", type: "number", min: 0, max: 999, step: 1, value: String(rem.then_every_days || 0), attrs: { inputmode: "numeric", "aria-describedby": "cr-rem-help" } });
      settingsErr = h("p", { id: "cr-settings-err", class: "os-field-error", attrs: { "aria-live": "polite" } });
      body.append(h("h3", { class: "os-correct__section", text: t("envelope.correct-settings") }),
        h("div", { class: "os-correct__settings" },
          h("label", { class: "os-label", attrs: { for: "cr-expiry" }, text: t("envelope.correct-expiry") }), expiry,
          h("p", { id: "cr-expiry-help", class: "os-help", text: t("envelope.correct-expiry-help") }),
          h("div", { class: "os-correct__pair" },
            h("div", {}, h("label", { class: "os-label", attrs: { for: "cr-first" }, text: t("envelope.correct-first") }), first),
            h("div", {}, h("label", { class: "os-label", attrs: { for: "cr-every" }, text: t("envelope.correct-every") }), every)),
          h("p", { id: "cr-rem-help", class: "os-help", text: t("envelope.correct-reminders-help") }),
          settingsErr));
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("envelope.correct-save"), variant: "primary", icon: "send", attrs: { "data-testid": "correct-save" },
        onClick: async () => {
          let bad = null;
          const flag = (el, err, msg) => { err.textContent = msg; el.setAttribute("aria-invalid", "true"); bad ||= el; };
          const orderOk = (el) => /^\d{1,2}$/.test(el.value) && Number(el.value) >= 1;
          for (const x of [...rows, ...fresh]) {
            x.err.textContent = "";
            for (const el of [x.name, x.email, x.code, x.order]) el?.removeAttribute("aria-invalid");
            if (x.removed) continue;
            if (!x.name.value.trim()) flag(x.name, x.err, t("use.need-name"));
            else if (!EMAIL.test(x.email.value.trim())) flag(x.email, x.err, t("use.need-email"));
            else if (!orderOk(x.order)) flag(x.order, x.err, t("envelope.correct-need-order"));
            else if (x.req && x.req.checked && !x.had && !x.code.value) flag(x.code, x.err, t("envelope.correct-need-code"));
          }
          settingsErr.textContent = "";
          for (const el of [expiry, first, every]) el.removeAttribute("aria-invalid");
          const today = dateOf(new Date().toISOString());
          if (expiry.value && expiry.value < today) flag(expiry, settingsErr, t("envelope.correct-expiry-past"));
          for (const el of [first, every]) if (!/^\d{1,3}$/.test(el.value)) flag(el, settingsErr, t("envelope.correct-need-days"));
          const keeps = recs.some((r) => SIGNING.has(r.type) && (ACTED.has(r.status) || !rows.find((x) => x.r === r)?.removed))
            || fresh.some((x) => SIGNING.has(x.type.value));
          if (!bad && !keeps) { const x = rows.find((y) => y.removed); if (x) flag(x.order, x.err, t("envelope.correct-need-signer")); }
          if (bad) { (bad.hidden || bad.closest("[hidden]") ? null : bad)?.focus(); return undefined; }

          const changes = [];
          for (const x of rows) if (x.removed) changes.push(corrections.removeRecipient(x.r.id));
          for (const x of fresh) changes.push(corrections.addRecipient({ type: x.type.value, name: x.name.value.trim(), email: x.email.value.trim(), routing_order: Number(x.order.value) }));
          if (expiry.value !== dateOf(e.expires_at)) changes.push(corrections.setExpiry(expiry.value ? new Date(`${expiry.value}T23:59:59`) : null));
          if (Number(first.value) !== (rem.first_after_days || 0) || Number(every.value) !== (rem.then_every_days || 0)) {
            changes.push(corrections.setReminders({ first_after_days: Number(first.value), then_every_days: Number(every.value) }));
          }
          const patches = [];
          for (const x of rows) {
            if (x.removed) continue;
            const body = recipientCorrection(x.r, { name: x.name.value.trim(), email: x.email.value.trim(), requireCode: x.req.checked, code: x.code.value }) || {};
            if (Number(x.order.value) !== x.r.routing_order) body.routing_order = Number(x.order.value);
            if (Object.keys(body).length) patches.push([x, body]);
          }
          if (!changes.length && !patches.length) return "same";
          let tag = etag;
          if (changes.length) {
            await ctx.api.correctEnvelope(id, tag, changes);
            tag = (await ctx.api.getEnvelope(id)).etag;
          }
          for (const [x, body] of patches) {
            await ctx.api.patchRecipient(id, x.r.id, tag, body);
            tag = (await ctx.api.getEnvelope(id)).etag;
          }
          // A new invitation for those whose name, email or code changed and who are
          // (still, after any reordering) sent it; added recipients are invited by routing.
          const contact = patches.filter(([, body]) => Object.keys(body).some((k) => k !== "routing_order")).map(([x]) => x.r.id);
          const now = contact.length ? (await ctx.api.getEnvelope(id)).envelope : null;
          const notify = contact.filter((rid) => ["sent", "delivered"].includes(now?.recipients?.find((r) => r.id === rid)?.status));
          if (notify.length) await ctx.api.resend(id, notify);
          return "corrected";
        },
      },
    ],
  });
  if (result === "same") toast(t("envelope.corrected-nochange"), "info");
  if (result === "corrected") toast(t("envelope.corrected"), "success");
  return result === "corrected";
}

/// The icon for a status line, for lists.
export function lineIcon(status) {
  return icon({ draft: "file-pen-line", sent: "hourglass", delivered: "hourglass", completed: "circle-check", declined: "circle-x", voided: "ban", expired: "clock" }[status] || "file-text", { size: 16 });
}
