// Members and recipients as the API shapes them (WEB-10): the pure rules Admin and
// Correct need, apart from their screens so Node tests them.

/// A member's profile as a name ("admin", "sender", "viewer") where the account's
/// built-in profiles say so (`settings.builtin_profiles`: name → id, set by the server),
/// else the id itself (a custom profile).
export function profileName(u, builtin = {}) {
  const id = String(u?.permission_profile_id || "");
  for (const [name, pid] of Object.entries(builtin || {})) if (pid === id) return name;
  return id.replace(/^profile-/, "");
}

/// Whether a member's latest invitation is still to be used, so Resend is offered
/// (`invitation` is on a single read, `GET /users/{id}`, not on the list).
export const invitePending = (u) => ["pending", "sent", "expired"].includes(u?.invitation);

/// The `PATCH …/recipients/{r}` body that corrects `r` to the values typed: only what
/// changed; `auth` with or without `access_code`; a new code when one is typed (the
/// server needs one when the method is newly required, and refuses one without it).
/// Null when nothing changed.
export function recipientCorrection(r, { name, email, requireCode, code }) {
  const body = {};
  if (name !== (r.name || "")) body.name = name;
  if (email !== (r.email || "")) body.email = email;
  const had = (r.auth || []).includes("access_code");
  if (requireCode !== had) body.auth = (r.auth || []).filter((m) => m !== "access_code").concat(requireCode ? ["access_code"] : []);
  if (requireCode && code) body.access_code = code;
  return Object.keys(body).length ? body : null;
}

/// Recipient types that fill fields (UX-05): a signer, and an in-person signer whom
/// staff host. An approver and a viewer act in their turn and fill nothing; a copy only
/// receives the completed envelope.
export const FIELD_TAKERS = new Set(["signer", "in_person_signer"]);
const ACTING = new Set(["signer", "in_person_signer", "approver", "viewer"]);

/// What the send confirmation says (R-02, UX-05), as `[key, params]` for `t`:
/// `people` are `{name, type, order}` (order: the routing step). With one step for
/// everyone who acts, all get it now; with several, only the first step gets it now
/// and the rest in turn ("A → B & C"). Then who reviews without signing, then copies.
export function sendSummary(people, subject) {
  const acting = people.filter((r) => ACTING.has(r.type));
  const signing = acting.filter((r) => FIELD_TAKERS.has(r.type));
  const reviewers = acting.filter((r) => !FIELD_TAKERS.has(r.type));
  const copies = people.filter((r) => !ACTING.has(r.type));
  const names = (list) => list.map((r) => r.name).join(", ");
  const steps = [...new Set(acting.map((r) => r.order))].sort((a, b) => a - b);
  const out = [];
  if (steps.length <= 1) {
    out.push([signing.length === 1 ? "send.confirm-one" : "send.confirm-text", { n: signing.length, subject }]);
    if (signing.length > 1) out.push(["send.confirm-together", {}]);
  } else {
    const at = (o) => acting.filter((r) => r.order === o).map((r) => r.name).join(" & ");
    out.push(["send.confirm-first", { names: at(steps[0]), subject }]);
    out.push(["send.confirm-order", { order: steps.map(at).join(" → ") }]);
  }
  if (reviewers.length) out.push(["send.confirm-reviewers", { names: names(reviewers) }]);
  if (copies.length) out.push(["send.confirm-copies", { names: names(copies) }]);
  return out;
}
