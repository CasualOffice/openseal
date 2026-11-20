// Slice 9, embedding (VS-09): the host page's elements (openseal-elements.js) take a
// message only from their own frame and OpenSeal's origin; the framed view
// (embedframe.js) posts only to its host page's origins, never `*`, takes the host's
// commands only from its parent, and returns with `event` and `state`; Admin's list of
// websites is checked as the server checks it; the API client carries an embedded
// view's credentials; and the mock's views open once. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { acceptMessage, viewOrigin, checkTheme, EVENT_MAP, define, OpenSealSigning, OpenSealPrepare } from "../openseal-elements.js";
import { hostChannel, returnTo, targetsOf, fromHost, themeDeclarations, EVENTS } from "../embedframe.js";
import { normalOrigin, parseOrigins, MAX_ORIGINS } from "../embedmodel.js";
import { createClient } from "../api.js";
import { createMockFetch, MOCK, embedOriginFor } from "../mock.js";

const OS = "https://sign.example.com";
const HOST = "https://shop.example";
const msg = (data, source, origin = OS) => ({ data, source, origin });

test("an element takes a message only from its own frame, from OpenSeal's origin, in the protocol's shape", () => {
  const frame = { name: "frame" };
  const other = { name: "another window" };
  const ok = { type: "openseal", v: 1, event: "completed", state: "o-7", envelope_id: "e1", name: "Casey", email: "c@x" };
  assert.deepEqual(acceptMessage(msg(ok, frame), frame, OS), { type: "openseal:complete", detail: { event: "completed", state: "o-7", envelope_id: "e1" } });
  // The page itself, another frame, another origin: ignored.
  assert.equal(acceptMessage(msg(ok, other), frame, OS), null);
  assert.equal(acceptMessage(msg(ok, null), frame, OS), null);
  assert.equal(acceptMessage(msg(ok, frame, "https://evil.example"), frame, OS), null);
  assert.equal(acceptMessage(msg(ok, frame, "null"), frame, OS), null);
  // Not the protocol, or an event it does not know.
  assert.equal(acceptMessage(msg({ ...ok, type: "other" }, frame), frame, OS), null);
  assert.equal(acceptMessage(msg({ ...ok, v: 2 }, frame), frame, OS), null);
  assert.equal(acceptMessage(msg({ ...ok, event: "toString" }, frame), frame, OS), null);
  assert.equal(acceptMessage(msg("completed", frame), frame, OS), null);
  // No frame yet, or no origin: nothing.
  assert.equal(acceptMessage(msg(ok, frame), null, OS), null);
  assert.equal(acceptMessage(msg(ok, frame), frame, null), null);
});

test("each view event raises one of the element's events", () => {
  const raised = (event) => acceptMessage(msg({ type: "openseal", v: 1, event }, 1), 1, OS)?.type;
  assert.equal(raised("ready"), "openseal:ready");
  for (const e of ["completed", "sent", "saved", "corrected"]) assert.equal(raised(e), "openseal:complete", e);
  assert.equal(raised("declined"), "openseal:decline");
  for (const e of ["cancelled", "finish_later"]) assert.equal(raised(e), "openseal:cancel", e);
  for (const e of ["expired", "error"]) assert.equal(raised(e), "openseal:error", e);
  // The framed side sends only events the element knows.
  for (const e of EVENTS) assert.ok(Object.hasOwn(EVENT_MAP, e), e);
});

test("an element's origin is its view URL's, and an origin attribute must agree with it", () => {
  const base = "https://shop.example/checkout";
  assert.equal(viewOrigin(`${OS}/s/tok`, null, base), OS);
  assert.equal(viewOrigin(`${OS}/s/tok`, OS, base), OS);
  assert.equal(viewOrigin(`${OS}/e/tok`, "https://evil.example", base), null);
  assert.equal(viewOrigin(`${OS}/e/tok`, `${OS}/path`, base), null);
  assert.equal(viewOrigin("javascript:alert(1)", null, base), null);
  assert.equal(viewOrigin("data:text/html,x", null, base), null);
});

test("theme tokens are named; a typo throws at the call", () => {
  assert.deepEqual(checkTheme({ accentColor: "#7c3aed" }), { accentColor: "#7c3aed" });
  assert.throws(() => checkTheme({ accentColour: "#7c3aed" }), /unknown OpenSeal theme token/);
  assert.throws(() => checkTheme({ accentColor: 7 }), /takes a string/);
  // The frame applies known names with safe values only.
  const d = themeDeclarations({ accentColor: "#7c3aed", radius: "6px", textColor: "red; background: url(x)", nope: "1" });
  assert.deepEqual(d.set, [["--os-accent", "#7c3aed"], ["--os-radius", "6px"]]);
  assert.deepEqual(d.refused.sort(), ["nope", "textColor"]);
});

test("both elements are defined once, by their names", () => {
  const names = new Map();
  const registry = { get: (n) => names.get(n), define: (n, c) => names.set(n, c) };
  define(registry);
  define(registry);
  assert.equal(names.get("openseal-signing"), OpenSealSigning);
  assert.equal(names.get("openseal-prepare"), OpenSealPrepare);
});

/// A framed window: `parent` records what is posted to it, by target origin.
function framedWindow() {
  const posted = [];
  const listeners = [];
  const parent = { postMessage: (m, o) => posted.push([m, o]) };
  const assigned = [];
  const win = { parent, posted, listeners, assigned, addEventListener: (t, fn) => listeners.push([t, fn]), location: { assign: (u) => assigned.push(u) } };
  return win;
}

test("the framed view posts only to its host page's origins, never everywhere, and nothing about the signer", () => {
  const win = framedWindow();
  const ch = hostChannel({ win, embed: { frame_origin: HOST, frame_origins: [HOST], return_url: null, state: "o-7" }, root: null });
  assert.equal(ch.active, true);
  assert.equal(ch.post("ready", { envelope_id: "e1", name: "Casey Signer", email: "casey@x" }), 1);
  assert.deepEqual(win.posted, [[{ type: "openseal", v: 1, event: "ready", state: "o-7", envelope_id: "e1" }, HOST]]);
  assert.ok(win.posted.every(([, o]) => o !== "*"));
  assert.equal(ch.post("not-an-event"), 0);
  // A list of allowed websites: one message each, each to its own origin.
  const w2 = framedWindow();
  hostChannel({ win: w2, embed: { frame_origin: null, frame_origins: [HOST, "https://b.example", "*", "javascript:x"] }, root: null }).post("ready");
  assert.deepEqual(w2.posted.map(([, o]) => o), [HOST, "https://b.example"]);
  // Not framed (a link opened on its own): nothing is posted.
  const top = framedWindow();
  top.parent = top;
  assert.equal(hostChannel({ win: top, embed: { frame_origins: [HOST] }, root: null }).post("ready"), 0);
  assert.deepEqual(targetsOf(null), []);
});

test("the view ends once, then returns to the host's URL with the event and state", async () => {
  const win = framedWindow();
  const ch = hostChannel({ win, embed: { frame_origins: [HOST], return_url: `${HOST}/back?order=7`, state: "o-7" }, root: null });
  assert.equal(ch.end("completed"), `${HOST}/back?order=7&event=completed&state=o-7`);
  assert.equal(ch.end("declined"), null);
  await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(win.assigned, [`${HOST}/back?order=7&event=completed&state=o-7`]);
  assert.deepEqual(win.posted.map(([m]) => m.event), ["completed"]);
  assert.equal(returnTo("javascript:alert(1)", "completed", null), null);
  assert.equal(returnTo(`${HOST}/x`, "cancelled", ""), `${HOST}/x?event=cancelled`);
});

test("the framed view takes the host's commands only from its parent and the host page's origin", () => {
  const win = framedWindow();
  const root = { style: { set: [], setProperty(p, v) { this.set.push([p, v]); } } };
  hostChannel({ win, embed: { frame_origins: [HOST] }, root });
  const [[type, onMessage]] = win.listeners;
  assert.equal(type, "message");
  const theme = { type: "openseal", v: 1, command: "theme", tokens: { accentColor: "#123456" } };
  onMessage({ source: {}, origin: HOST, data: theme });
  onMessage({ source: win.parent, origin: "https://evil.example", data: theme });
  onMessage({ source: win.parent, origin: HOST, data: { ...theme, type: "x" } });
  assert.deepEqual(root.style.set, []);
  onMessage({ source: win.parent, origin: HOST, data: theme });
  assert.deepEqual(root.style.set, [["--os-accent", "#123456"]]);
  assert.equal(fromHost({ source: win.parent, origin: HOST, data: theme }, win.parent, []), false);
});

test("plain http is taken for intranet hosts only, as the server takes it (owner instruction 81)", () => {
  for (const ok of ["http://10.1.2.3", "http://172.16.0.9:8080", "http://192.168.1.20", "http://169.254.10.10", "http://127.0.0.2", "http://[fd12:3456::1]", "http://[fe80::1]", "http://[::1]", "http://intranet", "http://portal.corp.internal", "http://wiki.local", "http://sign.lan:8443"]) {
    assert.equal(normalOrigin(ok), ok, ok);
  }
  for (const pub of ["http://8.8.8.8", "http://172.32.0.1", "http://192.169.0.1", "http://[2001:db8::1]", "http://example.com", "http://intranet.example.com"]) {
    assert.equal(normalOrigin(pub), null, pub);
  }
  assert.equal(normalOrigin("https://8.8.8.8"), "https://8.8.8.8");
});

test("Admin's websites are origins as the server writes them, at most twenty", () => {
  assert.equal(normalOrigin("https://Shop.Example:443"), "https://shop.example");
  assert.equal(normalOrigin("http://localhost:3000"), "http://localhost:3000");
  assert.equal(normalOrigin("http://embed-host.test"), "http://embed-host.test");
  for (const bad of ["http://shop.example", "https://shop.example/", "https://*.shop.example", "shop.example", "https://u@shop.example", "https://shop.example:0"]) {
    assert.equal(normalOrigin(bad), null, bad);
  }
  assert.deepEqual(parseOrigins(`${HOST}\n\n https://SHOP.example \nhttp://localhost:3000`), { origins: [HOST, "http://localhost:3000"] });
  assert.deepEqual(parseOrigins(`${HOST}\nhttps://shop.example/checkout`), { bad: "https://shop.example/checkout" });
  assert.deepEqual(parseOrigins(Array.from({ length: MAX_ORIGINS + 1 }, (_, i) => `https://h${i}.example`).join("\n")), { tooMany: MAX_ORIGINS });
  assert.deepEqual(parseOrigins(""), { origins: [] });
});

test("the API client sends an embedded view's credentials where the server reads them", async () => {
  const seen = [];
  const fetch = async (url, init) => { seen.push([url, init.headers]); return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }); };
  const api = createClient({ fetch });
  api.setBinding("b1");
  api.setBearer("osv_s1");
  await api.ceremony.view("tok");
  await api.getEnvelope("e1");
  const [[, ceremony], [, staff]] = seen;
  assert.equal(ceremony["X-OpenSeal-Binding"], "b1");
  assert.equal(ceremony.Authorization, undefined);
  assert.equal(staff.Authorization, "Bearer osv_s1");
  assert.equal(staff["X-OpenSeal-Binding"], undefined);
});

test("the mock's embedded views open once, the signing view with its binding and where its events go", async () => {
  const store = new Map();
  const mockFetch = createMockFetch({ store: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) } });
  const api = createClient({ fetch: mockFetch });
  const v = await api.ceremony.open(MOCK.embedSignToken);
  assert.ok(v.binding);
  assert.deepEqual(v.embed.frame_origins, [embedOriginFor()]);
  assert.equal(embedOriginFor(new URL("http://127.0.0.1:8131/x")), "http://localhost:8132");
  assert.equal(embedOriginFor(new URL("http://localhost:8080")), "http://127.0.0.1:8081");
  assert.equal(v.embed.state, MOCK.embedState);
  await assert.rejects(api.ceremony.open(MOCK.embedSignToken), (e) => e.code === "CS-AUTH-0009");
  const s = await api.views.session(MOCK.embedPrepareToken);
  assert.equal(s.kind, "prepare");
  assert.match(s.session, /^osv_/);
  await assert.rejects(api.views.session(MOCK.embedPrepareToken), (e) => e.code === "CS-AUTH-0002");
  const env = await api.getEnvelope(s.envelope_id);
  assert.equal(env.envelope.status, "draft");
  assert.equal((await api.views.session(MOCK.embedCorrectToken)).kind, "correct");
});
