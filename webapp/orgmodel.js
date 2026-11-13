// Organization admin as data (ORG-06, docs/23 §10): the pure rules of the organization
// screens, apart from org.js so Node tests them. No DOM and no network.

/// The organization admin's pages, first cut (docs/23 §10): Overview, Workspaces, Users,
/// Administrators, Audit log. Identity, Security policy, Data and retention, Branding and
/// Plan and usage follow with their server routes (ORG-08, ORG-12, PLAN-*).
export const ORG_NAV = Object.freeze(["overview", "workspaces", "users", "admins", "audit"]);

/// The page a route's `?section=` names; Overview by default. Pure.
export function orgRouteFrom(params) {
  const want = params?.get?.("section") || "";
  return ORG_NAV.includes(want) ? want : "overview";
}

/// The link to a page (Overview is the bare `#/org`). Pure.
export function orgHref(id) {
  return id === "overview" || !ORG_NAV.includes(id) ? "#/org" : `#/org?section=${id}`;
}

/// What a role may do from these screens, as the server's `holds` (api/org.rs; docs/23
/// §2.2): an owner everything; an admin all but managing owners and admins; a delegated
/// admin reads, and changes only what its permission set names (the server decides per
/// workspace; the screen offers it and shows the refusal). Unknown roles hold nothing.
/// The server enforces every one of these on each request: this only decides which
/// buttons to draw.
export function orgCan(role, action) {
  if (role === "owner") return true;
  if (role === "admin") return action !== "admins";
  if (role === "delegated") return action === "read";
  return false;
}

/// The workspaces' counts for the Overview: `{active, archived, total}`. Pure.
export function workspaceCounts(items) {
  const list = Array.isArray(items) ? items : [];
  const archived = list.filter((w) => w?.status === "archived").length;
  return { active: list.length - archived, archived, total: list.length };
}

/// The administrators' counts by role for the Overview: `{owner, admin, delegated}`.
export function adminCounts(items) {
  const out = { owner: 0, admin: 0, delegated: 0 };
  for (const a of Array.isArray(items) ? items : []) if (a && Object.hasOwn(out, a.role)) out[a.role] += 1;
  return out;
}

/// The actions the organization's log knows a sentence for (the store's `AdminChange`
/// names in `org_admin_events`; ORG-05). Others are shown by their name.
export const ORG_ACTIONS = Object.freeze([
  "organization.created", "organization.renamed", "organization.admin_added", "organization.admin_removed",
  "organization.admin_role_changed", "workspace.created", "workspace.archived", "org.workspace_joined",
]);

/// One event of `GET /organizations/me/audit` as a row: `{seq, at, action, known,
/// actor: {kind, id}, targets: [[name, id]], changes: [{key, old, new}]}`. Tolerates a
/// missing or malformed `event` (the row still shows the stored action). Pure.
export function auditRow(item) {
  const e = item?.event && typeof item.event === "object" ? item.event : {};
  const action = typeof item?.action === "string" ? item.action : typeof e.action === "string" ? e.action : "";
  const actor = e.actor && typeof e.actor === "object" ? { kind: String(e.actor.kind || ""), id: e.actor.id ? String(e.actor.id) : null } : { kind: "", id: null };
  const targets = e.target && typeof e.target === "object" ? Object.entries(e.target).map(([k, v]) => [k, String(v)]) : [];
  const changes = Array.isArray(e.changes) ? e.changes.filter((c) => c && typeof c.key === "string") : [];
  return { seq: item?.seq ?? null, at: item?.at || null, action, known: ORG_ACTIONS.includes(action), actor, targets, changes };
}

/// The log's rows that match a filter (`q` in the action, a target id or the actor's
/// name), in the order given. `nameOf(id)` names a user id when the screen knows it.
export function filterAudit(rows, q = "", nameOf = () => "") {
  const s = String(q || "").trim().toLowerCase();
  if (!s) return rows;
  return rows.filter((r) => r.action.toLowerCase().includes(s)
    || r.targets.some(([, id]) => id.toLowerCase().includes(s))
    || (r.actor.id && (nameOf(r.actor.id) || "").toLowerCase().includes(s)));
}

/// A short form of an id for a row the screen cannot name (a user outside this
/// workspace): its first eight characters.
export function shortId(id) {
  const s = String(id || "");
  return s.length > 8 ? `${s.slice(0, 8)}…` : s;
}
