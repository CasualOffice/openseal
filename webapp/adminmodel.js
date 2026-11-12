// Admin as data (UX-08, WEB-17): the pure rules of the Admin screens, apart from admin.js
// so Node tests them. No DOM and no network.

/// The Admin navigation (WEB-17, canvas Intelligence): one secondary nav inside the
/// content card, in the canvas's order. `ready`: drawn over endpoints the server has;
/// the others are pages that say what they will hold and that this server does not have
/// them yet (`waits`: the parts each one waits for), never dead links. `tabs`: a page
/// holding more than one part, shown as pill tabs.
export const NAV = Object.freeze([
  { id: "organization", ready: true },
  { id: "members", ready: true },
  { id: "security", ready: false, waits: ["sso"] },
  { id: "signing", ready: false, waits: ["signing", "seal", "ersd"] },
  { id: "branding", ready: true },
  { id: "intelligence", ready: true, ml: true },
  { id: "retention", ready: false, waits: ["retention"] },
  { id: "integrations", ready: true, tabs: ["api", "webhooks"] },
  { id: "audit", ready: false, waits: ["audit"] },
]);

/// Section names from before WEB-17 (`?section=` and `?tab=` links in other screens and
/// bookmarks) and the page each now lives on.
const ALIASES = Object.freeze({
  account: "organization", users: "members", groups: "members", profiles: "members",
  sso: "security", seal: "signing", ersd: "signing", api: "integrations", webhooks: "integrations",
});

/// The page and tab a route's parameters name (`?section=`, or the older `?tab=`):
/// `{nav, tab}`; Members by default; `tab` only for a page with tabs (its first by
/// default). Pure.
export function routeFrom(params) {
  const want = params?.get?.("section") || params?.get?.("tab") || "";
  const id = NAV.some((n) => n.id === want) ? want : ALIASES[want] || "members";
  const item = NAV.find((n) => n.id === id);
  const tab = item.tabs ? (item.tabs.includes(want) ? want : item.tabs[0]) : null;
  return { nav: id, tab };
}

/// The link to a page (Members is the bare `#/admin`), or to one of its tabs. Pure.
export function navHref(id, tab = null) {
  if (tab) return `#/admin?section=${tab}`;
  if (id === "members") return "#/admin";
  const item = NAV.find((n) => n.id === id);
  return item?.tabs ? `#/admin?section=${item.tabs[0]}` : `#/admin?section=${id}`;
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
