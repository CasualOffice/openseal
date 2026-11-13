// The console API client (CON-17): `/console/v1` on the console's own origin.
//
// The session is the `__Host-os_op` cookie (HttpOnly, set by the server). Every
// changing request sends `X-CSRF-Token` with the token sign-in returned; the page keeps
// it in sessionStorage so a reload in the same tab keeps working, and forgets it at
// sign-out. A failed request throws a `Problem` carrying the server's stable code.

const PREFIX = "/console/v1";
const CSRF_KEY = "openseal.console.csrf";

/// A failed request: `status`, `code` (`CS-CON-*`), `field`, `retry_after`, or
/// `network` when nothing answered.
export class Problem extends Error {
  constructor(p) {
    super(p.code || `HTTP ${p.status}`);
    this.status = p.status ?? 0;
    this.code = p.code ?? null;
    this.field = p.field ?? null;
    this.retry_after = p.retry_after ?? null;
    this.network = !!p.network;
  }
}

let csrf = null;
try { csrf = sessionStorage.getItem(CSRF_KEY); } catch { csrf = null; }

/// Remember the CSRF token sign-in returned (or forget it with `null`).
export function setCsrf(token) {
  csrf = token || null;
  try {
    if (csrf) sessionStorage.setItem(CSRF_KEY, csrf);
    else sessionStorage.removeItem(CSRF_KEY);
  } catch { /* storage blocked: the token lives for this page only */ }
}

/// Whether this page holds a CSRF token (it cannot change anything without one).
export function hasCsrf() {
  return !!csrf;
}

/// Call the API. `body` is sent as JSON. Returns the parsed JSON, or `null` for 204.
export async function call(method, path, body) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  let res;
  try {
    res = await fetch(PREFIX + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new Problem({ network: true });
  }
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) throw new Problem({ status: res.status, ...(data && typeof data === "object" ? data : {}) });
  return data;
}

export const get = (path) => call("GET", path);
export const post = (path, body) => call("POST", path, body === undefined ? {} : body);
export const patch = (path, body) => call("PATCH", path, body);
