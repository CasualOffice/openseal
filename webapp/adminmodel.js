// Admin as data (UX-08): the pure rules of the Admin screens, apart from admin.js so
// Node tests them. No DOM and no network.

/// The Admin sections, in the rail's order and groups (UX-08, after DocuSign
/// eSignature Admin). `ready`: drawn over endpoints the server has; the others wait for
/// their endpoints and are shown as rows that say so, never hidden (docs/47 §Admin).
export const SECTIONS = Object.freeze([
  { id: "account", group: "account", icon: "settings", ready: true },
  { id: "signing", group: "account", icon: "pen-line", ready: false },
  { id: "ersd", group: "account", icon: "file-text", ready: false },
  { id: "retention", group: "account", icon: "hourglass", ready: false },
  { id: "users", group: "people", icon: "users", ready: true },
  { id: "groups", group: "people", icon: "list", ready: false },
  { id: "profiles", group: "people", icon: "shield-check", ready: false },
  { id: "webhooks", group: "integrations", icon: "bell", ready: true },
  { id: "api", group: "integrations", icon: "key-round", ready: true },
  { id: "sso", group: "security", icon: "lock", ready: false },
  { id: "seal", group: "security", icon: "stamp", ready: false },
  { id: "audit", group: "security", icon: "list-checks", ready: false },
]);
export const GROUPS = Object.freeze(["account", "people", "integrations", "security"]);

/// The section a route's parameters name: `?section=`, or the older `?tab=`; Users by default.
export function sectionFrom(params) {
  const want = params?.get?.("section") || params?.get?.("tab");
  return SECTIONS.some((s) => s.id === want) ? want : "users";
}

/// Every scope of docs/40 §2 (server `auth.rs` `SCOPES`), grouped for the New API
/// client panel; each has a one-line description in the strings (`admin.scope.<name>`).
export const SCOPE_GROUPS = Object.freeze([
  ["envelopes", ["envelopes:read", "envelopes:write", "envelopes:send", "bulk:send"]],
  ["templates", ["templates:read", "templates:write"]],
  ["admin", ["admin:users", "admin:account", "webhooks:manage", "audit:read"]],
]);

/// The webhook event types grouped by what they are about (the part before the dot).
export function eventGroups(types) {
  const out = new Map();
  for (const e of types || []) {
    const g = String(e).split(".")[0];
    if (!out.has(g)) out.set(g, []);
    out.get(g).push(e);
  }
  return [...out.entries()];
}

/// The signing-secret names typed for a webhook (comma or space separated): 1 to 4
/// names of letters, digits, `_` and `-`, at most 64 long each, as the server takes
/// them. `{refs}` or `{error: "none" | "many" | "bad"}`.
export function parseSecretRefs(text) {
  const refs = [...new Set(String(text || "").split(/[\s,]+/).filter(Boolean))];
  if (!refs.length) return { error: "none" };
  if (refs.length > 4) return { error: "many" };
  if (refs.some((r) => !/^[A-Za-z0-9_-]{1,64}$/.test(r))) return { error: "bad" };
  return { refs };
}

/// Where a key's expiry stands at `now` (ms): `none` (never expires), `expired`,
/// `soon` (within `warnDays`), or `ok`; `days` whole days left (rounded up).
export function expiryState(expiresAt, now = Date.now(), warnDays = 30) {
  if (expiresAt == null || expiresAt === "") return { state: "none", days: null };
  const at = Date.parse(expiresAt);
  if (!Number.isFinite(at)) return { state: "none", days: null };
  const days = Math.ceil((at - now) / 86_400_000);
  if (at <= now) return { state: "expired", days: 0 };
  return { state: days <= warnDays ? "soon" : "ok", days };
}

/// A member's state: `disabled`, `pending` (invited, not set up) or `active`.
export function userState(u) {
  if (u?.disabled) return "disabled";
  return ["pending", "sent", "expired"].includes(u?.invitation) ? "pending" : "active";
}

/// The members a search and filters leave: `q` in the name or email (any case),
/// `profile` a profile name or "all", `status` a `userState` or "all". `profileOf(u)`
/// names a member's profile.
export function filterUsers(items, { q = "", profile = "all", status = "all" } = {}, profileOf = () => "") {
  const s = String(q).trim().toLowerCase();
  return (items || []).filter((u) => (!s || [u.name, u.email].some((v) => String(v || "").toLowerCase().includes(s)))
    && (profile === "all" || profileOf(u) === profile)
    && (status === "all" || userState(u) === status));
}

const channel = (c) => {
  const v = c / 255;
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
};
/// WCAG 2.2 relative luminance of `#rrggbb`; null for anything else.
export function luminance(hex) {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(String(hex || ""));
  if (!m) return null;
  const [r, g, b] = m.slice(1).map((x) => channel(Number.parseInt(x, 16)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
/// WCAG contrast ratio of two `#rrggbb` colours, to two decimals; null if either is not one.
export function contrastRatio(a, b) {
  const la = luminance(a);
  const lb = luminance(b);
  if (la == null || lb == null) return null;
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
}
