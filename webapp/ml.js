// The web app's model layer (WEB-18; docs/33 §6, docs/47 §As built: design foundation):
// the one place screens ask whether document intelligence is available and read, accept
// or dismiss its suggestions.
//
// - `mlStatus()` resolves once per session to `{available, features: {ocr,
//   template_matching, extraction, personal_data}, notInPlan, notInstalled}` from
//   `GET /account/settings/ml`. A 404 (the server does not serve docs/33 §6 yet,
//   `WEB-19`), `CS-ML-0011` (off or not in the plan) or a call the client knows is not on
//   the server means **unavailable, and every ML surface hides** (WEB-18 acceptance).
//   The settings are a workspace admin's; for anyone else a refusal that is not an ML
//   code means "not known here": `available` with every feature assumed, and each surface
//   still hides when its own call answers 404 or `CS-ML-0011` (`isUnavailable`).
// - A suggestion store per envelope: `loadSuggestions`, `suggestions`, `openCount`,
//   `acceptSuggestion` and `dismissSuggestion`, which change the state at once
//   (optimistic), roll back when the server refuses, and tell listeners
//   (`onSuggestions`). Suggestions never decide anything: a person accepts each one.
//
// The decisions below that need no network are pure and exported for the tests.

/// The four features of docs/33 §7, in the settings' wire spelling.
export const ML_FEATURES = Object.freeze(["ocr", "template_matching", "extraction", "personal_data"]);
/// Below this score a suggestion says "check this" (canvas Insights: 75 %).
export const LOW_CONFIDENCE = 0.75;

const UNAVAILABLE_CODES = new Set(["CS-ML-0011", "CS-NET-0002", "CS-API-0002", "HTTP-404", "HTTP-501"]);

/// Whether an error from an ML call means "this server has no such feature here": the
/// surface hides rather than showing an error.
export function isUnavailable(err) {
  if (!err) return false;
  return err.status === 404 || err.status === 501 || UNAVAILABLE_CODES.has(err.code);
}

const none = () => Object.fromEntries(ML_FEATURES.map((f) => [f, false]));

/// The status for a settings answer or a refusal. Pure.
export function statusFrom({ settings = null, error = null } = {}) {
  if (error) {
    if (isUnavailable(error)) {
      return { available: false, features: none(), notInPlan: [], notInstalled: error.status === 404 || error.code === "CS-NET-0002" || error.code === "HTTP-404", known: true };
    }
    if (error.status === 403) {
      // Not an admin: the settings are not readable here; each surface asks for itself.
      return { available: true, features: Object.fromEntries(ML_FEATURES.map((f) => [f, true])), notInPlan: [], notInstalled: false, known: false };
    }
    // Anything else (offline, a server error): show nothing ML this session.
    return { available: false, features: none(), notInPlan: [], notInstalled: false, known: false };
  }
  const s = settings && typeof settings === "object" ? settings : {};
  const notInPlan = Array.isArray(s.not_in_plan) ? s.not_in_plan.filter((f) => ML_FEATURES.includes(f)) : [];
  const notInstalled = s.installed === false;
  const features = Object.fromEntries(ML_FEATURES.map((f) => [f, !notInstalled && s[f] === true && !notInPlan.includes(f)]));
  return { available: Object.values(features).some(Boolean), features, notInPlan, notInstalled, known: true };
}

/// Whether `feature` (or any feature, without one) is on in `status`. Pure.
export function featureOn(status, feature = null) {
  if (!status?.available) return false;
  return feature ? status.features?.[feature] === true : true;
}

/// A suggestion's score as a number from 0 to 1 (`score` or `confidence`). Pure.
export function scoreOf(s) {
  const v = typeof s === "number" ? s : Number(s?.score ?? s?.confidence);
  return Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : 0;
}

/// Whether a suggestion should say "check this": a score under 75 %. Pure.
export function isLowConfidence(s) {
  return scoreOf(s) < LOW_CONFIDENCE;
}

/// The score as people read it: "94%". Pure.
export function percent(s) {
  return `${Math.round(scoreOf(s) * 100)}%`;
}

/// The open suggestions in `list`. Pure.
export function openOf(list) {
  return (list || []).filter((s) => s.state === "open" || s.state == null);
}

/// `list` with suggestion `id` in `state` (a new array; the others untouched). Pure.
export function withState(list, id, state) {
  return (list || []).map((s) => (s.id === id ? { ...s, state } : s));
}

// ---- Session state -----------------------------------------------------------------

let api = null;
let status = null; // Promise of the status, once per session
const store = new Map(); // envelope id → suggestions
const loading = new Map(); // envelope id → Promise
const listeners = new Set();

/// Give the layer its API client (app.js, once; tests pass a mock client).
export function initMl(client) {
  api = client;
  status = null;
  store.clear();
  loading.clear();
}

/// Forget the cached status and suggestions (sign-out, or after an admin changes settings).
export function resetMl() {
  status = null;
  store.clear();
  loading.clear();
}

/// The model features' status for this session (see the top of this file).
export function mlStatus({ refresh = false } = {}) {
  if (!api) return Promise.resolve(statusFrom({ error: { status: 404, code: "HTTP-404" } }));
  if (!status || refresh) {
    status = api.getMlSettings().then((settings) => statusFrom({ settings }), (error) => statusFrom({ error }));
  }
  return status;
}

function emit(envId) {
  for (const fn of [...listeners]) {
    try { fn({ envId, items: store.get(envId) || [] }); } catch { /* a listener's own failure */ }
  }
}

/// Listen for changes to any envelope's suggestions: `fn({envId, items})`. Returns the
/// function that stops listening.
export function onSuggestions(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/// The envelope's suggestions as last loaded (all states), or `[]`.
export function suggestions(envId) {
  return store.get(envId) || [];
}

/// How many of the envelope's suggestions are still open (the row badge, the tab count).
export function openCount(envId) {
  return openOf(store.get(envId)).length;
}

/// Load the envelope's suggestions (every page, up to 500), once unless `refresh`.
/// Resolves `[]` when ML is unavailable; never rejects for an unavailable server.
export async function loadSuggestions(envId, { kind = null, refresh = false } = {}) {
  if (!refresh && store.has(envId)) return store.get(envId);
  if (!refresh && loading.has(envId)) return loading.get(envId);
  const p = (async () => {
    const st = await mlStatus();
    if (!st.available) return [];
    const items = [];
    let cursor = null;
    try {
      for (let page = 0; page < 10; page++) {
        const r = await api.listSuggestions(envId, { kind, cursor });
        items.push(...(r?.items || []));
        cursor = r?.next_cursor || null;
        if (!cursor || items.length >= 500) break;
      }
    } catch (err) {
      if (isUnavailable(err)) return [];
      throw err;
    }
    store.set(envId, items);
    emit(envId);
    return items;
  })();
  loading.set(envId, p);
  try { return await p; } finally { loading.delete(envId); }
}

async function decide(envId, sId, state, call) {
  const before = store.get(envId) || [];
  store.set(envId, withState(before, sId, state));
  emit(envId);
  try {
    const r = await call(envId, sId);
    if (r && typeof r === "object" && r.id === sId) store.set(envId, (store.get(envId) || []).map((s) => (s.id === sId ? { ...s, ...r } : s)));
    emit(envId);
    return r;
  } catch (err) {
    // Refused (stale, already decided, offline): put it back as it was, and say so.
    store.set(envId, before);
    emit(envId);
    throw err;
  }
}

/// Accept a suggestion: it shows as accepted at once and goes back to open if refused.
export function acceptSuggestion(envId, sId) {
  return decide(envId, sId, "accepted", (e, s) => api.acceptSuggestion(e, s));
}

/// Dismiss a suggestion, the same way.
export function dismissSuggestion(envId, sId) {
  return decide(envId, sId, "dismissed", (e, s) => api.dismissSuggestion(e, s));
}
