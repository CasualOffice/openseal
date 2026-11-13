// ERSD-01, UXW-12: publishing a disclosure through the API client makes it the one the
// signer's view asks consent to, with its `url` and exact text; the Admin card's pure
// rules (adminmodel.js) refuse what the server refuses. Run: npm test (in webapp/).
import test from "node:test";
import assert from "node:assert/strict";

import { createMockFetch, MOCK } from "../mock.js";
import { createClient } from "../api.js";
import { NAV, ersdProblem, ersdPreview, nextErsdVersion, shortHash, ERSD_MAX_BYTES } from "../adminmodel.js";

async function signedIn() {
  const c = createClient({ fetch: createMockFetch() });
  await c.login(MOCK.email, MOCK.password);
  return c;
}
async function sha256hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

test("a published disclosure is the one the signer's view carries, with its url and text", async () => {
  const c = await signedIn();
  const before = await c.ersd.get();
  assert.equal(before.current.label, MOCK.ersd);
  assert.deepEqual(before.items, []);

  const text = "Our disclosure, version one.\nPaper copies on request.";
  const p = await c.ersd.publish({ text });
  assert.equal(p.version, 1);
  assert.equal(p.label, "1");
  assert.equal(p.language, "en");
  assert.equal(p.sha256, `sha256:${await sha256hex(text)}`);
  assert.equal("text" in p, false);

  const v = await c.ceremony.open(MOCK.ceremonyToken);
  assert.deepEqual(v.consent_required, { version: "1", sha256: p.sha256, url: `/s/${MOCK.ceremonyToken}/disclosure` });
  await c.ceremony.authenticate(MOCK.ceremonyToken, "access_code", MOCK.accessCode);
  assert.deepEqual(await c.ceremony.disclosure(MOCK.ceremonyToken), { version: "1", sha256: p.sha256, text });
  // Consent binds the version now required; the old demo version is refused.
  await assert.rejects(c.ceremony.consent(MOCK.ceremonyToken, MOCK.ersd), (e) => e.code === "CS-API-0001");
  await c.ceremony.consent(MOCK.ceremonyToken, "1");

  const p2 = await c.ersd.publish({ text: "Version two.", language: "en" });
  assert.equal(p2.version, 2);
  const after = await c.ersd.get();
  assert.equal(after.current.label, "2");
  assert.equal(after.current.text, "Version two.");
  assert.deepEqual(after.items.map((d) => d.version), [2, 1]);
  assert.ok(after.items.every((d) => !("text" in d)));
});

test("the mock refuses what the server refuses", async () => {
  const c = await signedIn();
  for (const [body, code] of [
    [{ text: "" }, "CS-API-0001"], [{ text: "  \n" }, "CS-API-0001"], [{ text: "a\0b" }, "CS-API-0001"],
    [{ text: "ok", language: "e" }, "CS-API-0001"], [{ text: "ok", language: "en_GB" }, "CS-API-0001"],
    [{ text: "x".repeat(ERSD_MAX_BYTES + 1) }, "CS-API-0006"],
  ]) await assert.rejects(c.ersd.publish(body), (e) => e.code === code, JSON.stringify(body).slice(0, 40));
  assert.deepEqual((await c.ersd.get()).items, []);
});

test("the Admin card's rules: what blocks publishing, the preview, the next version, the short hash", () => {
  assert.equal(ersdProblem(""), "admin.ersd.need-text");
  assert.equal(ersdProblem(" \t\n"), "admin.ersd.need-text");
  assert.equal(ersdProblem("a\0b"), "admin.ersd.bad-text");
  assert.equal(ersdProblem("é".repeat(ERSD_MAX_BYTES / 2 + 1)), "admin.ersd.too-long");
  assert.equal(ersdProblem("ok", "e"), "admin.ersd.bad-language");
  assert.equal(ersdProblem("ok", "fr-CA"), null);
  assert.equal(ersdPreview("a  b\n c"), "a b c");
  const long = "word ".repeat(100);
  const pv = ersdPreview(long, 50);
  assert.ok(pv.endsWith("…") && pv.length <= 51 && !pv.includes("wor…"), pv);
  assert.equal(nextErsdVersion([], "en"), 1);
  assert.equal(nextErsdVersion([{ version: 3, language: "en" }, { version: 7, language: "fr" }], "en"), 4);
  assert.equal(shortHash("sha256:0123456789abcdef"), "0123456789ab…");
  // The Signing and seals page draws the disclosure; the rest of it still waits.
  const signing = NAV.find((n) => n.id === "signing");
  assert.deepEqual(signing.live, ["ersd"]);
  assert.ok(!signing.waits.includes("ersd"));
});
