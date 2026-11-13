// Sign-in, password reset and accept-invite rules (WEB-18 lane E). Pure: no DOM, so
// Node tests it (tests/auth.test.mjs). The views (signin.js, acceptinvite.js) ask this
// module what is wrong with a form and render the answer; they hold no rules of their own.
//
// Every answer is a message key, not text, so the view passes it through `t()`.

/// The address shape the client checks before asking the server. Deliberately loose (one
/// `@`, a dot in the domain, no spaces): the server is the judge of what an account is.
export const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/// The shortest password an invitation accepts (the server's rule, docs/40 `AcceptInvite`).
export const MIN_PASSWORD = 12;

/// The longest password a field takes, so a paste cannot send megabytes.
export const MAX_PASSWORD = 256;

/// The sign-in form's field errors: `{ email, password }`, each a message key or null.
export function signInErrors({ email = "", password = "" } = {}) {
  const e = String(email).trim();
  return {
    email: !e ? "signin.email-missing" : EMAIL.test(e) ? null : "signin.email-invalid",
    password: password ? null : "signin.password-missing",
  };
}

/// The first field with an error, in reading order, or null when the form may be sent.
export function firstInvalid(errors, order) {
  return order.find((k) => errors[k]) || null;
}

/// The reset form's error for an address: a message key or null.
export function resetError(email = "") {
  const e = String(email).trim();
  return !e ? "signin.email-missing" : EMAIL.test(e) ? null : "signin.email-invalid";
}

/// The invitation's password rules as a checklist the page shows while the person types:
/// `[{ id, key, met }]`. "match" is met only once something is typed in both fields.
export function inviteChecks(password = "", again = "") {
  return [
    { id: "length", key: "invite.rule-length", met: password.length >= MIN_PASSWORD },
    { id: "match", key: "invite.rule-match", met: again.length > 0 && password === again },
  ];
}

/// What stops the invitation form from being sent: `{ field: "password" | "again", key }`
/// or null. Length first: a short password is the first thing to fix.
export function inviteError(password = "", again = "") {
  if (password.length < MIN_PASSWORD) return { field: "password", key: "invite.password-help" };
  if (password !== again) return { field: "again", key: "invite.mismatch" };
  return null;
}

/// The token in a route's parameters, or "" when there is none or it has a character a
/// token never has (so a crafted link cannot carry markup or a path into a request).
export function inviteToken(params) {
  const v = params?.get("token") || "";
  return /^[A-Za-z0-9._~-]{1,512}$/.test(v) ? v : "";
}

/// The company sign-in providers worth a button: a same-origin path (never another site,
/// never `//host` or `/\host`, which browsers read as another host) and a name, the name cut to 80 characters.
export function usableProviders(items) {
  if (!Array.isArray(items)) return [];
  return items
    .filter((p) => p && typeof p.url === "string" && /^\/[^/\\]/.test(p.url) && typeof p.name === "string" && p.name.trim())
    .map((p) => ({ url: p.url, name: p.name.trim().slice(0, 80) }));
}

/// What a session still owes before the app opens (ASVS-01): `"verify"`, `"enrol"`, or
/// null when it owes nothing (`GET /auth/session`'s `second_factor`).
export function owedFactor(session) {
  const f = session?.second_factor;
  return f === "verify" || f === "enrol" ? f : null;
}

/// The second-factor form's error: a message key or null. A code is six digits (spaces
/// ignored); a recovery code is anything non-empty (the server is the judge).
export function factorError(value = "", recovery = false) {
  const v = String(value).replace(/\s+/g, "");
  if (recovery) return v ? null : "mfa.recovery-missing";
  return /^[0-9]{6}$/.test(v) ? null : "mfa.code-missing";
}

/// The setup key as people type it into an authenticator: base32 in groups of four.
export function groupSecret(secret = "") {
  return String(secret).replace(/[^A-Z2-7]/g, "").replace(/(.{4})(?=.)/g, "$1 ");
}

/// The message key for a refused sign-in: wrong credentials get the plain sentence, any
/// other failure (server down, locked) the API client's own message.
export function signInFailure(err) {
  return err?.code === "CS-AUTH-0007" ? "signin.invalid" : null;
}
