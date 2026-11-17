// VS-02 (slice 2, routing and recipient types), in a browser: a sender sends one envelope
// to an approver, a viewer, an agent and a signer, in that order; each acts through their
// own link in their turn (the approver approves, the viewer views every page, the agent
// names the signer), the named signer signs, and the sender downloads the sealed PDF and
// the certificate of completion.
//
// Both modes. On the Compose deployment (compose-e2e) each link is the one the worker
// emailed, read from Mailpit, and each recipient acts in a browser context of their own;
// the downloads are written to target/e2e-sealed/ for pyHanko (tools/verify-sealed.py)
// and every screen is recorded as the slice 2 demo (RTE-04, target/e2e-demo/vs02-*,
// uploaded by compose-e2e as `slice-2-demo`). In mock mode the link is the mock's token
// for that address, once routing has reached it, and the recipients act in the sender's
// tab (the mock lives in the tab's storage).
//
// Every run has its own recipients (the run id in each address), and the spec changes no
// account setting: the shared account's disclosure, if any, is accepted, never published.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "@playwright/test";
import { signIn, pdfFile, REAL, app, signPage } from "./helpers.mjs";

const MAIL = (process.env.OPENSEAL_E2E_MAIL_URL || "http://127.0.0.1:8025").replace(/\/$/, "");
const OUT = path.resolve(fileURLToPath(new URL("../../target/e2e-sealed", import.meta.url)));
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));
const SIZE = { width: 1280, height: 800 };

// The sender's screens are recorded on the real stack only (the demo); Playwright takes
// video settings per file, not inside a test.
test.use({ video: REAL ? { mode: "on", size: SIZE } : "off" });

/// Real stack: the signing link in the newest email to `to` sent after `after`.
async function emailedLink(to, after) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const res = await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`);
    if (res.ok) {
      const { messages = [] } = await res.json();
      for (const m of messages) {
        if (after && Date.parse(m.Created) < after) continue;
        const full = await (await fetch(`${MAIL}/api/v1/message/${encodeURIComponent(m.ID)}`)).json();
        const link = `${full.Text || ""}\n${full.HTML || ""}`.match(/https?:\/\/[^\s"'<>]+\/s\/[A-Za-z0-9._~%-]+/);
        if (link) return link[0];
      }
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no signing link emailed to ${to} within 90 s`);
}

/// Mock: the signing token the mock gave `email` on envelope `id` (null until routing
/// reaches them), read through api.js against the tab's own mock.
function mockToken(page, id, email) {
  return page.evaluate(async ({ id, email }) => {
    const { createClient } = await import("/api.js");
    const { createMockFetch } = await import("/mock.js");
    const api = createClient({ fetch: createMockFetch({ store: sessionStorage }), store: sessionStorage });
    const { envelope: env } = await api.getEnvelope(id);
    return env.recipients.find((r) => r.email === email)?.mock_token || null;
  }, { id, email });
}

async function addRecipient(page, n, { name, email, type }) {
  await page.getByRole("button", { name: "Add recipient" }).first().click();
  const row = page.locator(".os-rcpt").nth(n);
  await row.getByTestId("recipient-name").fill(name);
  await row.getByTestId("recipient-email").fill(email);
  await row.getByTestId("recipient-email").blur();
  if (type !== "signer") await row.getByTestId("recipient-type").selectOption(type);
}

/// Consent when the account asks for it, then the documents step; answers its Finish.
async function openDocuments(p) {
  const consent = p.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = p.locator("#guide-progress");
  await expect(consent.or(progress).first()).toBeVisible();
  if (await consent.isVisible()) {
    await p.getByLabel("I agree to use electronic records and signatures.").check();
    await p.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toBeVisible();
  await expect(p.locator(".os-page.is-loading")).toHaveCount(0);
}

/// From the documents step (nothing to fill) to the review step.
async function toReview(p) {
  await p.locator("#guide-finish").click();
  await expect(p.getByTestId("review-finish")).toBeVisible();
}

test("slice 2 (VS-02): an approver, a viewer and an agent act in order through their links, the named signer signs; the sealed PDF and certificate download", async ({ page, browser }, testInfo) => {
  test.setTimeout(REAL ? 420_000 : 120_000);
  const run = `${Date.now()}-${testInfo.project.name}-${Math.random().toString(36).slice(2, 8)}`;
  const approver = { name: "Ann Approver", email: `approver-${run}@example.com`, type: "approver" };
  const viewer = { name: "Vic Viewer", email: `viewer-${run}@example.com`, type: "viewer" };
  const agent = { name: "Abe Agent", email: `agent-${run}@example.com`, type: "agent" };
  const later = { name: "To be named", email: `later-${run}@example.com`, type: "signer" };
  const named = { name: "Bea Buyer", email: `buyer-${run}@example.com` };
  const started = Date.now() - 5_000;
  if (REAL) fs.mkdirSync(DEMO, { recursive: true });
  const demo = (step) => path.join(DEMO, `vs02-${testInfo.project.name}-${step}.webm`);

  // The sender: four recipients in order, one signature field for the signer.
  await signIn(page);
  await page.locator("#start-btn").click();
  await page.getByRole("menuitem", { name: "Send an envelope" }).click();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("routing.pdf", "Routing agreement"));
  await expect(page.getByTestId("doc-card")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  for (const [i, r] of [approver, viewer, agent, later].entries()) await addRecipient(page, i, r);
  expect(await page.getByTestId("recipient-order").evaluateAll((els) => els.map((e) => e.value))).toEqual(["1", "2", "3", "4"]);
  expect(await page.getByTestId("recipient-type").evaluateAll((els) => els.map((e) => e.value))).toEqual(["approver", "viewer", "agent", "signer"]);
  await page.getByTestId("wizard-next").click();
  await expect(page.locator(".os-page")).toHaveCount(2);
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);
  // Only the signer takes fields (UX-05), so the field is theirs.
  await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
  await expect(page.locator(".os-field")).toHaveCount(1);
  await page.getByTestId("wizard-next").click();
  await page.getByLabel("Subject").fill(`Routing ${run}`);
  await page.getByRole("button", { name: "Send", exact: true }).first().click();
  await page.getByRole("dialog", { name: "Send this envelope?" }).getByRole("button", { name: "Send" }).click();
  await expect(page).toHaveURL(/#\/envelopes\/[^/]+$/, { timeout: 20_000 });
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");
  const detail = page.url();
  const id = decodeURIComponent(detail.match(/#\/envelopes\/([^/]+)$/)[1]);

  // The link routing has sent `who`: emailed on the real stack, the mock's token in mock
  // mode. Before their turn there is none: checked for the next in line each time.
  const linkFor = async (who) => {
    if (REAL) return emailedLink(who.email, started);
    await expect.poll(() => mockToken(page, id, who.email), { message: `a link for ${who.name}` }).not.toBeNull();
    return signPage(await mockToken(page, id, who.email));
  };
  const notYet = async (who) => {
    if (!REAL) expect(await mockToken(page, id, who.email), `${who.name} is not invited yet`).toBeNull();
  };

  /// One recipient's turn: their own context on the real stack (recorded as `step`),
  /// the sender's tab in mock mode.
  const turn = async (who, step, act) => {
    const link = await linkFor(who);
    if (!REAL) {
      await page.goto(link);
      await act(page);
      return;
    }
    const context = await browser.newContext({ viewport: SIZE, recordVideo: { dir: testInfo.outputPath(`video-${step}`), size: SIZE } });
    const p = await context.newPage();
    // The pages the server took as seen (`POST …/documents/{d}/viewed`), recorded from
    // the first request: the page reports them on its own as they come into view.
    const seen = new Set();
    p.on("requestfinished", async (req) => {
      if (req.method() !== "POST" || !/\/documents\/[^/]+\/viewed$/.test(req.url())) return;
      if ((await req.response())?.ok()) for (const n of req.postDataJSON()?.pages_seen || []) seen.add(n);
    });
    await p.goto(link, { waitUntil: "domcontentloaded" });
    await act(p, seen);
    await context.close();
    await p.video()?.saveAs(demo(step));
  };

  await notYet(viewer);
  // 1. The approver approves: the button says Approve, and nobody signs here.
  await turn(approver, "2-approver-approves", async (p) => {
    await openDocuments(p);
    await toReview(p);
    await expect(p.getByTestId("review-finish")).toHaveText("Approve");
    await expect(p.getByText("By selecting Approve, you approve these documents")).toHaveCount(1);
    await p.getByTestId("review-finish").click();
    const done = p.getByTestId("sign-done");
    await expect(done).toContainText("Approved. Thank you, Ann.");
    await expect(done).not.toContainText("Signed");
  });

  await notYet(agent);
  // 2. The viewer views every page; viewing the last one completes them.
  await turn(viewer, "3-viewer-views", async (p, seen) => {
    await openDocuments(p);
    const pages = p.locator(".os-sign__pages .os-page");
    await expect(pages).toHaveCount(2);
    await pages.first().scrollIntoViewIfNeeded();
    await pages.last().scrollIntoViewIfNeeded();
    // Viewing the last page completes the viewer: on the real server once the page has
    // reported it (batched), or Finish is refused as not viewed; in the mock, routing
    // has moved on to the agent.
    if (REAL) await expect.poll(() => seen.has(2), { message: "the server took the last page as seen", timeout: 30_000 }).toBe(true);
    else await expect.poll(() => mockToken(page, id, agent.email), { message: "routing moves on once every page is viewed" }).not.toBeNull();
    await toReview(p);
    await p.getByTestId("review-finish").click();
    const done = p.getByTestId("sign-done");
    await expect(done).toContainText("Viewed. Thank you, Vic.");
    await expect(done).not.toContainText("Signed");
  });

  await notYet(later);
  // 3. The agent names the signer (the later recipient), then finishes.
  await turn(agent, "4-agent-names-the-signer", async (p) => {
    await openDocuments(p);
    await toReview(p);
    const form = p.getByTestId("later-recipients");
    await expect(form).toBeVisible();
    await expect(form.getByTestId("later-name")).toHaveValue(later.name);
    await form.getByTestId("later-name").fill(named.name);
    await form.getByTestId("later-email").fill(named.email);
    await p.getByTestId("review-finish").click();
    const done = p.getByTestId("sign-done");
    await expect(done).toContainText("Your part is finished. Thank you, Abe.");
    await expect(done).not.toContainText("Signed");
  });

  // 4. The signer the agent named gets the link at the address the agent gave, and signs.
  await turn(named, "5-named-signer-signs", async (p) => {
    await openDocuments(p);
    await expect(p.locator("#guide-progress")).toHaveText("0 of 1 required");
    await p.getByRole("button", { name: /Signature, required/ }).click();
    const dlg = p.getByRole("dialog", { name: "Adopt your signature" });
    await expect(dlg.getByLabel("Your full name")).toHaveValue(named.name);
    await dlg.getByTestId("adopt-confirm").click();
    await expect(dlg).toBeHidden();
    await p.getByRole("button", { name: "Finish" }).click();
    await expect(p.getByRole("heading", { name: "Review and finish" })).toBeVisible();
    await p.getByTestId("review-finish").click();
    await expect(p.getByTestId("sign-done")).toContainText("Everyone has signed");
  });

  // The worker seals; the sender sees it completed, every recipient done, and downloads.
  if (!REAL) await page.goto(app(`#/envelopes/${encodeURIComponent(id)}`));
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".os-page-head .os-badge")).toHaveText("Completed", { timeout: 2_000 });
  }).toPass({ timeout: 120_000, intervals: [2_000] });
  const rows = page.getByTestId("recipient-row");
  await expect(rows.filter({ hasText: named.email })).toContainText(named.name);
  await expect(rows.filter({ hasText: later.email })).toHaveCount(0);

  const dir = REAL ? OUT : testInfo.outputPath("downloads");
  fs.mkdirSync(dir, { recursive: true });
  const keep = async (label, file) => {
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: label }).click()]);
    const to = path.join(dir, `${testInfo.project.name}-${file}`);
    await dl.saveAs(to);
    expect(fs.readFileSync(to).subarray(0, 5).toString("latin1"), `${label} is a PDF`).toBe("%PDF-");
    return path.basename(to);
  };
  const sealed = await keep("Download signed PDF", "vs02-sealed.pdf");
  const certificate = await keep("Certificate", "vs02-certificate.pdf");
  if (!REAL) return;
  await page.close();
  await page.video()?.saveAs(demo("1-6-sender-sends-and-downloads"));
  // The manifest tools/verify-sealed.py reads (rows appended per browser project).
  const manifest = path.join(OUT, "manifest.tsv");
  if (!fs.existsSync(manifest)) fs.writeFileSync(manifest, "file\texpect\twhy\tlevel\n");
  fs.appendFileSync(manifest, `${sealed}\tintact\tVS-02 routed agreement, ${testInfo.project.name}\tB-T\n`);
  fs.appendFileSync(manifest, `${certificate}\tintact\tVS-02 certificate of completion, ${testInfo.project.name}\tB-T\n`);
});
