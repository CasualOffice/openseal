// Admin › Document intelligence as data (WEB-18; docs/33 §6–7, canvas Intelligence):
// the pure rules of the page, apart from adminintel.js so Node tests them. No DOM and no
// network.
//
// The page reads `GET /account/settings/ml` and writes `PATCH` of the same. Its five
// cards are the canvas's; four are the settings' features, and "Detect fields on upload"
// has no switch of its own on the server (docs/33 §6: OCR-sourced field suggestions are
// merged into detect-fields when OCR is on), so its switch follows "Read scanned pages"
// and cannot be turned separately. The page never claims a model is installed unless the
// settings answer lists it.

/// The canvas's five cards, in its order. `key`: the settings member that turns it on
/// (`follows`: the card has none and shows that member's state); `model`: the model the
/// card names when the server does not list its models (docs/33 §5 choices); `profile`:
/// the models list's profile that backs it.
export const FEATURES = Object.freeze([
  { id: "ocr", key: "ocr", glyph: "◫", model: "PP-OCRv6", profile: "ocr" },
  { id: "detect", key: null, follows: "ocr", glyph: "✍", model: "rules + OCR", profile: null },
  { id: "templates", key: "template_matching", glyph: "▦", model: "multilingual-e5-small", profile: "templates" },
  { id: "extract", key: "extraction", glyph: "Aa", model: "gliner_multi-v2.1", profile: "extraction" },
  { id: "pii", key: "personal_data", glyph: "◉", model: "gliner-pii-base", profile: "personal_data" },
]);

/// The settings keys the page may PATCH.
export const SETTING_KEYS = Object.freeze(FEATURES.map((f) => f.key).filter(Boolean));

const UNINSTALLED = new Set(["CS-NET-0002", "HTTP-404", "CS-API-0002"]);

/// What the page shows for a settings answer or a refusal (docs/33 §7):
/// - `not-installed`: the server has no models (404, a call it does not serve, or
///   `installed: false`); the page is an illustrated empty state naming the operator.
/// - `no-plan`: `403 CS-ML-0011` for the whole workspace; every card is disabled with
///   "not in your plan".
/// - `forbidden`: another refusal of access (the member is not an admin).
/// - `error`: anything else (offline, a server error); the page offers to try again.
/// - `ready`: the settings, per card.
/// Pure.
export function pageState({ settings = null, error = null } = {}) {
  if (error) {
    if (error.status === 404 || error.status === 501 || UNINSTALLED.has(error.code)) return { kind: "not-installed" };
    if (error.code === "CS-ML-0011") return { kind: "no-plan" };
    if (error.status === 403 || error.status === 401) return { kind: "forbidden", error };
    return { kind: "error", error };
  }
  const s = settings && typeof settings === "object" ? settings : {};
  if (s.installed === false) return { kind: "not-installed" };
  return { kind: "ready", settings: s };
}

/// The features the plan lacks: every one when the whole workspace is refused, else the
/// settings' `not_in_plan` (unknown names dropped). Pure.
export function notInPlan(state) {
  if (state?.kind === "no-plan") return [...SETTING_KEYS];
  const list = state?.settings?.not_in_plan;
  return Array.isArray(list) ? list.filter((k) => SETTING_KEYS.includes(k)) : [];
}

/// Each card's state: `{id, key, on, disabled, reason}` where `reason` is `plan` (the
/// plan lacks it), `follows` (it follows another card) or null. Pure.
export function cards(state) {
  const s = state?.settings || {};
  const lacking = new Set(notInPlan(state));
  return FEATURES.map((f) => {
    const key = f.key || f.follows;
    const plan = lacking.has(key);
    const on = !plan && s[key] === true;
    const reason = plan ? "plan" : f.key ? null : "follows";
    return { id: f.id, key: f.key, glyph: f.glyph, on, disabled: reason != null, reason };
  });
}

/// "n of 5 on": how many cards are on. Pure.
export function onCount(list) {
  return (list || []).filter((c) => c.on).length;
}

/// The settings with `key` set to `value` (a new object; the PATCH body is `{[key]:
/// value}`). Throws for a key the page does not own, so a typo never reaches the server.
/// Pure.
export function withSetting(settings, key, value) {
  if (!SETTING_KEYS.includes(key)) throw new Error(`not a document intelligence setting: ${key}`);
  return { ...(settings || {}), [key]: !!value };
}

/// The bytes as people read them: "30 MB", "0.7 GB", "512 KB"; "" for no number. Pure.
export function sizeText(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return "";
  if (n >= 1e9) return `${Math.round(n / 1e8) / 10} GB`;
  if (n >= 1e6) return `${Math.round(n / 1e6)} MB`;
  return `${Math.max(1, Math.round(n / 1e3))} KB`;
}

/// A SHA-256 shortened to its first and last four hex digits ("9c41…e07a"); null when the
/// value is not 64 hex digits (a model still installing has none). Pure.
export function shortHash(sha) {
  const v = String(sha || "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(v) ? `${v.slice(0, 4)}…${v.slice(-4)}` : null;
}

const MODEL_STATUS = new Set(["ready", "installing", "failed"]);

/// The settings' `models` list (an additive member: `[{id, name?, profile?, status,
/// licence?, bytes?, sha256?}]`) as rows: `{id, name, status, licence, size, profile,
/// hash}`; rows without an id are dropped, an unknown status reads `failed`. `[]` when
/// the server lists none. Pure.
export function modelRows(settings) {
  const list = Array.isArray(settings?.models) ? settings.models : [];
  return list.filter((m) => m && typeof m.id === "string" && m.id).map((m) => ({
    id: m.id,
    name: typeof m.name === "string" && m.name ? m.name : m.id,
    status: MODEL_STATUS.has(m.status) ? m.status : "failed",
    licence: typeof m.licence === "string" ? m.licence : "",
    size: sizeText(m.bytes),
    profile: typeof m.profile === "string" ? m.profile : "",
    hash: shortHash(m.sha256),
  }));
}

/// The model name a card shows: the docs/33 choice in its short form (the canvas's),
/// suffixed "· installing" or "· not working" when the server lists that profile's model
/// and it is not ready, so the card never names a model as working that is not. Pure.
export function cardModel(feature, rows) {
  const f = FEATURES.find((x) => x.id === feature);
  if (!f) return { name: "", status: null };
  const m = f.profile ? (rows || []).find((r) => r.profile === f.profile) : null;
  return { name: f.model, status: m && m.status !== "ready" ? m.status : null };
}

const PACK_STATE = new Set(["installed", "installing", "missing"]);

/// The OCR script packs (an additive member `ocr_packs: [{script, state}]`), grouped as
/// the canvas chips: installed scripts in one chip, then each installing pack, then each
/// pack the operator has not installed. Without the member, the scripts in `ocr_scripts`
/// count as installed. Pure.
export function packChips(settings) {
  const packs = Array.isArray(settings?.ocr_packs)
    ? settings.ocr_packs.filter((p) => p && typeof p.script === "string" && PACK_STATE.has(p.state))
    : (Array.isArray(settings?.ocr_scripts) ? settings.ocr_scripts : []).filter((x) => typeof x === "string").map((script) => ({ script, state: "installed" }));
  const installed = packs.filter((p) => p.state === "installed").map((p) => p.script);
  const out = installed.length ? [{ state: "installed", scripts: installed }] : [];
  for (const state of ["installing", "missing"]) {
    for (const p of packs.filter((x) => x.state === state)) out.push({ state, scripts: [p.script] });
  }
  return out;
}
