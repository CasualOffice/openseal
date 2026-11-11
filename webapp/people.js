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
