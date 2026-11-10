// The audit trail embedded in a sealed PDF (`audit-trail.json`, docs/32 §As built), for
// the Verify page's timeline (WEB-02). Pure: no DOM, so Node tests it.
//
// What this does: reads the file within bounds and checks its *links*: the format
// name, `seq` dense from 0, each `prev` equal to the hash before it, and `head` equal
// to the last hash. What it does not do: recompute the hashes (SHA-256 over RFC 8785
// canonical JSON). That belongs to casual-sign-audit, whose WASM build does not yet
// expose it to the page (row in the WEB-02 report); until then the page says "links
// checked, hashes not recomputed here" and never calls the chain verified.

export const TRAIL_NAME = "audit-trail.json";
export const MAX_TRAIL_BYTES = 16 << 20;
export const MAX_EVENTS = 100_000;

/// Parse a trail file. Returns `{ok: true, envelopeId, head, events, links}` or
/// `{ok: false, problem}`, where `problem` is one of "too_large", "not_json",
/// "not_trail", "too_many". `links` is `{ok, problems: [{seq, problem}]}`.
export function parseTrail(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (u8.length > MAX_TRAIL_BYTES) return { ok: false, problem: "too_large" };
  let v;
  try { v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(u8)); } catch { return { ok: false, problem: "not_json" }; }
  if (!v || typeof v !== "object" || v.format !== "openseal.audit-trail" || !Array.isArray(v.events)) return { ok: false, problem: "not_trail" };
  if (v.events.length > MAX_EVENTS) return { ok: false, problem: "too_many" };
  const str = (x) => (typeof x === "string" ? x : null);
  const events = v.events.map((e) => ({
    seq: Number.isSafeInteger(e?.seq) ? e.seq : null,
    type: str(e?.type) || "unknown",
    at: str(e?.at),
    hash: str(e?.hash),
    prev: e?.prev === null ? null : str(e?.prev),
    actor: actorOf(e?.actor),
  }));
  const problems = [];
  events.forEach((e, i) => {
    if (e.seq !== i) problems.push({ seq: i, problem: "seq" });
    if (!e.hash || !/^[0-9a-f]{64}$/.test(e.hash)) problems.push({ seq: i, problem: "hash" });
    const want = i === 0 ? null : events[i - 1].hash;
    if (e.prev !== want) problems.push({ seq: i, problem: "prev" });
  });
  const head = str(v.head);
  if ((events.length ? events[events.length - 1].hash : null) !== head) problems.push({ seq: events.length, problem: "head" });
  return { ok: true, envelopeId: str(v.envelope_id), head, events, links: { ok: problems.length === 0, problems } };
}

/// Who acted, as the timeline shows it: a name or the kind ("system", "sender"…).
/// Personal data stays in the page; nothing here is sent or logged.
function actorOf(a) {
  if (!a || typeof a !== "object") return { kind: "unknown", name: null };
  return { kind: typeof a.kind === "string" ? a.kind : "unknown", name: typeof a.name === "string" && a.name ? a.name : null };
}

/// A readable event name from a type: "recipient.signature_adopted" →
/// "Recipient signature adopted". The page prefers a message key when there is one.
export function eventLabel(type) {
  const s = String(type || "").replace(/[._]+/g, " ").trim();
  return s ? s[0].toUpperCase() + s.slice(1) : "Event";
}
