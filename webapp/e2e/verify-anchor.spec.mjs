// Public anchoring on the Verify page (FG-158, docs/32 §5): an envelope's anchor proof
// checked in the browser by casual-sign-wasm's `verify_anchor`, beside the PDF that
// carries the envelope's audit trail. A valid proof reads "History anchored on <day> by
// <TSA>" and is matched to the PDF's trail; a tampered one is refused with the check that
// caught it; without the TSA's root it is not confirmed; a file that is not a proof says
// so. Fixtures: fixtures/anchor (casual-sign-sdk's gen_anchor example). verify.html makes
// no server call with the files, so these run against the real stack as well; the
// hand-over from an envelope (which asks the server for the proof) runs in demo mode.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";
import { REAL, signIn, expectAccessible, snap } from "./helpers.mjs";
import { pdfWithAttachments } from "./pdfattach.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixture = (p) => path.join(ROOT, "fixtures", "anchor", p);
const WASM = REAL || fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));
const page0 = REAL ? "/verify.html" : "/verify.html?mock=1";

const proof = fs.readFileSync(fixture("anchor-proof.json"), "utf8");
const trail = fs.readFileSync(fixture("audit-trail.json"), "utf8");
const withTrail = () => ({ name: "agreement.pdf", mimeType: "application/pdf", buffer: pdfWithAttachments({ "audit-trail.json": trail }) });
const proofFile = (text, name = "anchor-proof.json") => ({ name, mimeType: "application/json", buffer: Buffer.from(text) });

/// The proof with its anchored head changed in its last hex digit.
function tampered() {
  const head = JSON.parse(proof).head;
  const last = head.at(-1) === "0" ? "1" : "0";
  return proof.replace(head, head.slice(0, -1) + last);
}

async function check(page, { root = true, anchor = proofFile(proof), pdf = withTrail() } = {}) {
  await page.goto(page0);
  await expect(page.getByTestId("verify-engine")).toHaveAttribute("data-state", "ready");
  if (root) {
    await page.getByTestId("trust-input").setInputFiles(fixture("trust-root.pem"));
    await expect(page.getByText("trust-root.pem")).toBeVisible();
  }
  await page.getByTestId("anchor-input").setInputFiles(anchor);
  await expect(page.getByTestId("anchor-chosen")).toContainText(anchor.name);
  await page.getByTestId("verify-input").setInputFiles(pdf);
  await expect(page.getByTestId("verdict")).toBeVisible();
  return page.getByTestId("anchor-verdict");
}

test.describe("anchor proof", () => {
  test.beforeEach(() => test.skip(!WASM, "the WASM verifier is built locally by tools/build-webapp-wasm.sh"));

  test("a valid proof shows the history anchored on its day by its TSA, matched to the PDF's trail", async ({ page }, testInfo) => {
    const v = await check(page);
    await expect(v).toHaveAttribute("data-state", "anchored");
    await expect(v).toContainText(/^History anchored on .*2026 by T-1G Test TSA$/);
    const checks = page.getByTestId("anchor-checks").locator("li");
    await expect(checks).toHaveCount(4);
    for (let i = 0; i < 4; i += 1) await expect(checks.nth(i)).toHaveClass(/is-ok/);
    await expect(page.getByTestId("anchor-trail")).toHaveText("Checked against the audit trail in this PDF.");
    await expect(page.getByTestId("trail-links")).toContainText("3 events, each linked to the one before.");
    await expectAccessible(page, "verify anchored");
    await snap(page, testInfo, "verify-anchor-valid");
  });

  test("a tampered proof is refused, naming the check that caught it", async ({ page }, testInfo) => {
    const v = await check(page, { anchor: proofFile(tampered(), "tampered-proof.json") });
    await expect(v).toHaveAttribute("data-state", "failed");
    await expect(v).toHaveText("The anchor proof does not hold");
    const checks = page.getByTestId("anchor-checks");
    await expect(checks.locator("li").filter({ hasText: "History is in the anchored tree" })).toContainText("CS-AUD-0009");
    await expect(checks.locator("li").filter({ hasText: "Matches this PDF's audit trail" })).toContainText("CS-AUD-0012");
    await expect(page.locator("body")).not.toContainText("History anchored on");
    await expectAccessible(page, "verify anchor refused");
    await snap(page, testInfo, "verify-anchor-tampered");
  });

  test("without the TSA's root the proof is not confirmed, and a non-proof says so", async ({ page }) => {
    let v = await check(page, { root: false });
    await expect(v).toHaveAttribute("data-state", "unconfirmed");
    await expect(v).toContainText("by T-1G Test TSA, not confirmed");
    await expect(page.getByTestId("anchor-checks").locator("li").filter({ hasText: "Time-stamping authority is trusted" })).toContainText("CS-VER-0004");
    await expectAccessible(page, "verify anchor unconfirmed");

    v = await check(page, { anchor: proofFile(trail, "audit-trail.json") });
    await expect(v).toHaveAttribute("data-state", "error");
    await expect(v).toHaveText("Not an anchor proof");
  });

  test("a hostile proof file name is shown as text", async ({ page }) => {
    const dialogs = [];
    page.on("dialog", (d) => { dialogs.push(d.message()); d.dismiss(); });
    const name = "<img src=x onerror=alert(1)>.json";
    await check(page, { anchor: proofFile(proof, name) });
    await expect(page.getByTestId("anchor-verdict")).toHaveAttribute("data-state", "anchored");
    await expect(page.locator("main img[src=x]")).toHaveCount(0);
    expect(dialogs).toEqual([]);
  });

  test("a PDF without the trail is checked without it, and the page says so", async ({ page }) => {
    const plain = { name: "plain.pdf", mimeType: "application/pdf", buffer: pdfWithAttachments({}) };
    const v = await check(page, { pdf: plain });
    await expect(v).toHaveAttribute("data-state", "anchored");
    await expect(page.getByTestId("anchor-trail")).toHaveText("This PDF carries no audit trail, so the proof was not matched to it.");
    await expect(page.getByTestId("anchor-checks").locator("li").filter({ hasText: "Matches this PDF's audit trail" })).toContainText("not run");
  });

  test("opened from an envelope with nothing anchored yet, the page says so", async ({ page }) => {
    test.skip(REAL, "demo mode: the stack anchors only after a day closes");
    await signIn(page, "home");
    const ref = await page.evaluate(() => {
      const db = JSON.parse(sessionStorage.getItem("openseal.mock.v1"));
      const env = db.envelopes.find((e) => e.status === "completed" && e.documents?.length);
      return env ? { envelope: env.id, document: env.documents[0].id } : null;
    });
    expect(ref).not.toBeNull();
    await page.goto(`/verify.html?mock=1&envelope=${ref.envelope}&document=${ref.document}`);
    await expect(page.getByTestId("verdict")).toBeVisible();
    const v = page.getByTestId("anchor-verdict");
    await expect(v).toHaveAttribute("data-state", "not-yet");
    await expect(v).toHaveText("Not anchored yet: the envelope's history is anchored once a day, after the day ends.");
    await expectAccessible(page, "verify anchor not yet");
  });
});
