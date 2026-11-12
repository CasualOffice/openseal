// The app shell's pure parts (UX-04): the Keyboard shortcuts panel's grouping, and the
// calls the shell makes ahead of the server (profile, password reset, SSO providers),
// served by the mock and refused at once by a client against a server without them.
// Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { SHORTCUTS, shortcutGroups, keyParts, commandFor } from "../keys.js";
import { createMockFetch, MOCK } from "../mock.js";
import { createClient, NOT_ON_SERVER } from "../api.js";

const row = (group, label) => group.rows.find((r) => r.label === label);

test("the shortcuts panel has one row per action, aliases together, global first", () => {
  const groups = shortcutGroups(["global"]);
  assert.deepEqual(groups.map((g) => g.context), ["global", "editor"]);
  const [global, editor] = groups;
  // "?" once (it was listed twice, as "?" and "Shift+?").
  assert.equal(global.rows.filter((r) => r.label === "Keyboard shortcuts").length, 1);
  assert.deepEqual(row(global, "Keyboard shortcuts").keys, [["?"]]);
  assert.deepEqual(row(editor, "Delete field").keys, [["Delete"], ["Backspace"]]);
  assert.deepEqual(row(editor, "Redo").keys, [["Ctrl", "Shift", "Z"], ["Ctrl", "Y"]]);
  // Four arrows with the same modifiers are one key; nine digits are one.
  assert.deepEqual(row(editor, "Move field 1 point").keys, [["←↑→↓"]]);
  assert.deepEqual(row(editor, "Move field 10 points").keys, [["Shift", "←↑→↓"]]);
  assert.deepEqual(row(editor, "Place fields for recipient 1 to 9").keys, [["1–9"]]);
  // Every bound command is named in words, none by its id.
  for (const g of groups) for (const r of g.rows) assert.doesNotMatch(r.label, /^[a-z]+\.[a-z-]+/, r.label);
  // The editor first when the editor is open.
  assert.equal(shortcutGroups(["editor", "global"])[0].context, "editor");
});

test("on a Mac the panel shows the Mac modifier symbols", () => {
  assert.deepEqual(keyParts("Ctrl+Shift+Z", true), ["⌘", "⇧", "Z"]);
  assert.deepEqual(keyParts("Alt+ArrowUp", true), ["⌥", "↑"]);
  assert.deepEqual(keyParts("Ctrl+Shift+Z", false), ["Ctrl", "Shift", "Z"]);
  assert.deepEqual(keyParts("Escape"), ["Esc"]);
  const redo = shortcutGroups(["global"], { mac: true })[1].rows.find((r) => r.label === "Redo");
  assert.deepEqual(redo.keys[0], ["⌘", "⇧", "Z"]);
});

test("/ searches from every screen with the bar, not only Agreements", () => {
  const key = { key: "/", code: "Slash", ctrlKey: false, metaKey: false, altKey: false, shiftKey: false };
  assert.equal(commandFor(key, ["global"]), "search.focus");
  assert.equal(commandFor(key, ["global"], true), null, "not while typing");
  assert.ok(![...SHORTCUTS.global.keys()].includes("Shift+?"), "no binding combo() can never produce");
});

test("the shell's calls ahead of the server are refused at once against a server", async () => {
  const seen = [];
  const c = createClient({ fetch: async (url) => { seen.push(url); return new Response("{}", { status: 200 }); } });
  for (const name of ["profile", "passwordReset", "authProviders"]) assert.equal(c.available(name), false, name);
  for (const p of [c.me(), c.patchMe({ name: "x" }), c.requestPasswordReset("a@example.com"), c.authProviders()]) {
    await assert.rejects(p, (e) => e.status === 501 && e.code === "CS-NET-0002" && Object.hasOwn(NOT_ON_SERVER, e.detail));
  }
  assert.deepEqual(seen, []);
});

test("the mock serves the profile: name, notifications and marks saved; a password change needs the current one", async () => {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  const me = await c.me();
  assert.equal(me.email, MOCK.email);
  assert.deepEqual(me.notifications, { completed: true, declined: true, viewed: false });
  assert.equal(me.signature, null);
  const saved = await c.patchMe({ name: "Robin Quinn", notifications: { viewed: true }, signature: { image_base64: "iVBORw0KGgo=" } });
  assert.equal(saved.name, "Robin Quinn");
  assert.equal(saved.notifications.viewed, true);
  assert.equal(saved.signature.image_base64, "iVBORw0KGgo=");
  assert.equal((await c.me()).name, "Robin Quinn");
  // The admin list keeps the server's member shape.
  const listed = (await c.users.list()).items.find((u) => u.email === MOCK.email);
  assert.equal(listed.name, "Robin Quinn");
  assert.ok(!("notifications" in listed) && !("signature" in listed));
  await assert.rejects(c.patchMe({ password: "a-long-enough-password", current_password: "wrong" }), (e) => e.code === "CS-AUTH-0007");
  await assert.rejects(c.patchMe({ password: "short", current_password: MOCK.password }), (e) => e.code === "CS-API-0001");
  await assert.rejects(c.patchMe({ email: "x@example.com" }), (e) => e.code === "CS-API-0001", "email is not the user's to change");
});

test("the mock's reset request answers alike for any address; providers are none until configured", async () => {
  const store = new Map();
  const ss = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
  const c = createClient({ fetch: createMockFetch({ store: ss }) });
  assert.deepEqual(await c.requestPasswordReset(MOCK.email), {});
  assert.deepEqual(await c.requestPasswordReset("nobody@example.com"), {});
  await assert.rejects(c.requestPasswordReset("not an email"), (e) => e.code === "CS-API-0001");
  assert.deepEqual((await c.authProviders()).items, []);
  ss.setItem("openseal.mock.idp", "Acme SSO");
  const [idp] = (await c.authProviders()).items;
  assert.equal(idp.name, "Acme SSO");
  assert.match(idp.url, /^\/[^/]/);
});
