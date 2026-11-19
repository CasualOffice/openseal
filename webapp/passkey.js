// Staff passkeys in the browser (CON-13, docs/40 §2): the WebAuthn ceremonies between
// the server's options (`POST /api/v1/auth/mfa/passkeys/options`) and the browser's
// `navigator.credentials`. The server sends binary members as base64url; the browser
// takes and gives ArrayBuffers. The conversions are pure functions (tested under Node,
// tests/passkey.test.mjs); `createPasskey` and `getPasskey` are the only calls into the
// browser, and the server checks everything that matters (challenge, origin, RP id,
// signature, counter).
//
// Registration sends the key from `response.getPublicKey()` (SubjectPublicKeyInfo DER,
// WebAuthn Level 2 §5.2.1), so neither side decodes CBOR.

/// Base64url (no padding) of bytes.
export function toB64url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i += 1) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/// Bytes of base64url (padding tolerated); throws on anything else.
export function fromB64url(text) {
  const s = String(text).replace(/=+$/, "");
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new TypeError("not base64url");
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i += 1) out[i] = b.charCodeAt(i);
  return out;
}

const descriptor = (d) => ({ type: "public-key", id: fromB64url(d.id), ...(Array.isArray(d.transports) && d.transports.length ? { transports: d.transports } : {}) });

/// `PublicKeyCredentialCreationOptions` from the server's `public_key` options.
export function creationOptions(o) {
  return {
    ...o,
    challenge: fromB64url(o.challenge),
    user: { ...o.user, id: fromB64url(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map(descriptor),
  };
}

/// `PublicKeyCredentialRequestOptions` from the server's `public_key` options.
export function requestOptions(o) {
  return {
    ...o,
    challenge: fromB64url(o.challenge),
    allowCredentials: (o.allowCredentials || []).map(descriptor),
  };
}

/// The body `POST /auth/mfa/passkeys` takes, from a new `PublicKeyCredential`.
export function registrationBody(cred, name) {
  const r = cred.response;
  const key = typeof r.getPublicKey === "function" ? r.getPublicKey() : null;
  if (!key) throw new Error("passkey-unsupported");
  return {
    name: String(name || "").trim() || undefined,
    credential: {
      id: toB64url(cred.rawId),
      client_data_json: toB64url(r.clientDataJSON),
      authenticator_data: toB64url(r.getAuthenticatorData()),
      public_key: toB64url(key),
      public_key_algorithm: r.getPublicKeyAlgorithm(),
      transports: typeof r.getTransports === "function" ? r.getTransports() : [],
    },
  };
}

/// The `passkey` member `POST /auth/mfa/verify` and `/auth/reauthenticate` take, from a
/// `PublicKeyCredential` the browser asserted.
export function assertionBody(cred) {
  const r = cred.response;
  return {
    credential_id: toB64url(cred.rawId),
    client_data_json: toB64url(r.clientDataJSON),
    authenticator_data: toB64url(r.authenticatorData),
    signature: toB64url(r.signature),
    ...(r.userHandle && r.userHandle.byteLength ? { user_handle: toB64url(r.userHandle) } : {}),
  };
}

/// Whether this browser can use passkeys at all.
export function passkeysSupported(win = globalThis) {
  return !!(win?.PublicKeyCredential && win?.navigator?.credentials?.create && win.isSecureContext !== false);
}

/// Whether the session's person has a passkey the server will take (`GET /auth/session`).
export function hasPasskey(session) {
  return Number(session?.factors?.passkeys) > 0;
}

/// Whether passkeys can be added here: the server allows them and the browser has them.
export function canAddPasskey(session, win = globalThis) {
  return session?.factors?.passkeys_available !== false && passkeysSupported(win);
}

/// The message key for a ceremony that failed in the browser (cancelled, timed out, or
/// a credential already registered), or null for a server refusal the caller words.
export function ceremonyError(err) {
  const n = err?.name;
  if (n === "NotAllowedError" || n === "AbortError") return "passkey.cancelled";
  if (n === "InvalidStateError") return "passkey.already";
  if (n === "NotSupportedError" || n === "SecurityError" || err?.message === "passkey-unsupported") return "passkey.unsupported";
  return null;
}

/// Register a passkey: options, the browser's ceremony, the server's check. Resolves to
/// the server's answer (`{passkey, second_factor, recovery_codes?}`).
export async function createPasskey(api, name, nav = globalThis.navigator) {
  const o = await api.passkeyOptions("register");
  const cred = await nav.credentials.create({ publicKey: creationOptions(o.public_key) });
  return api.registerPasskey(registrationBody(cred, name));
}

/// Assert a passkey for `purpose` (`verify` or `reauthenticate`): resolves to the
/// `passkey` member the server's call takes.
export async function getPasskey(api, purpose, nav = globalThis.navigator) {
  const o = await api.passkeyOptions(purpose);
  const cred = await nav.credentials.get({ publicKey: requestOptions(o.public_key) });
  return assertionBody(cred);
}
