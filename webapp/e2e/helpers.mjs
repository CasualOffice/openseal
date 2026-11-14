// Shared steps for the e2e specs (WEB-01). Every spec runs in mock mode by default and
// against a real server when OPENSEAL_E2E_BASE_URL is set (playwright.config.mjs).

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import { MOCK } from "../mock.js";
import { makePdf } from "../mockpdf.js";

export const REAL = !!process.env.OPENSEAL_E2E_BASE_URL;
const q = REAL ? "" : "?mock=1";

/// Where screenshots for people go (not baselines): target/e2e-screens/.
export const SCREENS = path.resolve(fileURLToPath(new URL("../../target/e2e-screens", import.meta.url)));

export const creds = REAL
  ? { email: process.env.OPENSEAL_E2E_EMAIL || "", password: process.env.OPENSEAL_E2E_PASSWORD || "" }
  : { email: MOCK.email, password: MOCK.password };

/// The signing tokens: the mock's seeded ones, or what a real run provides.
export const tokens = REAL
  ? { sign: process.env.OPENSEAL_E2E_SIGN_TOKEN || "", decline: process.env.OPENSEAL_E2E_DECLINE_TOKEN || "", accessCode: process.env.OPENSEAL_E2E_ACCESS_CODE || "" }
  : { sign: MOCK.ceremonyToken, decline: MOCK.declineToken, accessCode: MOCK.accessCode };

export const app = (hash = "#/agreements") => `/app.html${q}${hash}`;
export const signPage = (token) => `/s/${encodeURIComponent(token)}${q}`;

/// Against a real server: the session the first sign-in made, reused by later ones.
/// The server allows ten sign-ins a minute per account and per address (docs/40 §2),
/// and a run signs in more often than that; the form itself is still used by the first
/// sign-in of each worker and by the specs about signing in.
let realSession = null;

/// Choose who the next fields are for in the editor (WEB-06: recipient chips, a radio
/// group of the signers). `who`: a signer's index, or a name ("1. Ana Signer" also works).
export async function placingFor(page, who) {
  const group = page.getByRole("radiogroup", { name: "Placing fields for" });
  const radio = typeof who === "number"
    ? group.getByRole("radio").nth(who)
    : group.getByRole("radio", { name: String(who).replace(/^\d+\.\s*/, ""), exact: true });
  await radio.click();
  await expect(radio).toHaveAttribute("aria-checked", "true");
}

/// Sign in and land on Agreements (most specs), or on Home with `land = "home"`.
/// Sign-in itself lands on Home (WEB-02).
export async function signIn(page, land = "agreements") {
  if (REAL && !creds.email) throw new Error("OPENSEAL_E2E_EMAIL and OPENSEAL_E2E_PASSWORD are needed against a real server");
  const agreements = page.getByRole("heading", { name: "Agreements" });
  const home = page.getByRole("heading", { name: "Home", exact: true });
  const goLand = async () => {
    // "domcontentloaded": the heading below is what matters; WebKit on the shared stack
    // has waited past the test timeout for a full "load" (compose-e2e, run 43121391179).
    if (land === "home") { await page.goto(app("#/home"), { waitUntil: "domcontentloaded" }); await expect(home).toBeVisible(); return; }
    await page.goto(app("#/agreements"), { waitUntil: "domcontentloaded" });
    await expect(agreements).toBeVisible();
  };
  if (REAL && realSession) {
    await page.context().addCookies(realSession.cookies);
    // Still signed in? (A spec may have signed this session out.) Asked of the API, not
    // the page, which shows its sign-in form for a moment while it checks.
    const alive = await page.request.get("/api/v1/auth/session");
    if (alive.ok()) {
      await page.addInitScript((csrf) => sessionStorage.setItem("openseal.csrf", csrf), realSession.csrf);
      await goLand();
      return;
    }
    realSession = null;
    await page.context().clearCookies();
  }
  await page.goto(app("#/signin"));
  await page.getByLabel("Email").fill(creds.email);
  await page.getByLabel("Password").fill(creds.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  if (REAL) await passFactor(page, home);
  await expect(home).toBeVisible();
  if (REAL) {
    realSession = {
      cookies: await page.context().cookies(),
      csrf: await page.evaluate(() => sessionStorage.getItem("openseal.csrf")),
    };
    await seedReal(page);
  }
  if (land !== "home" || REAL) await goLand();
}

/// Against a real server, the run's administrator owes a second factor (ASVS-31: the
/// default for administrators). The first sign-in enrols through the sign-in card, as a
/// person would with an authenticator app; later ones answer the code step with a code
/// for a time step not used yet, else a recovery code (each code is accepted once).
/// Kept in a file beside the run's results, not in memory: Playwright restarts its worker
/// after any failure, and a factor held in memory would be lost with it (compose-e2e on
/// PR #7). One worker runs the real-stack suite, so the file has one writer.
const factorFile = path.join(os.tmpdir(), `openseal-e2e-factor-${Buffer.from(String(creds.email)).toString("hex").slice(0, 32)}.json`);
function loadFactor() {
  try {
    const f = JSON.parse(fs.readFileSync(factorFile, "utf8"));
    return { seed: f.seed ? Buffer.from(f.seed, "hex") : null, lastStep: f.lastStep ?? -1, recovery: f.recovery ?? [] };
  } catch {
    return { seed: null, lastStep: -1, recovery: [] };
  }
}
function saveFactor(f) {
  fs.writeFileSync(factorFile, JSON.stringify({ seed: f.seed?.toString("hex") ?? null, lastStep: f.lastStep, recovery: f.recovery }), { mode: 0o600 });
}

function unbase32(s) {
  const out = [];
  let buf = 0, bits = 0;
  for (const c of s.replace(/[\s=]/g, "").toUpperCase()) {
    const v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);
    if (v < 0) throw new Error("the setup key is not base32");
    buf = ((buf << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return Buffer.from(out);
}

/// RFC 6238: six digits, 30-second steps, HMAC-SHA1.
function totp(seed, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = crypto.createHmac("sha1", seed).update(msg).digest();
  const off = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/// Pass the second-factor step a sign-in may show (ASVS-01, ASVS-31); a spec that signs in
/// by hand calls it after submitting the form.
export async function passFactor(page, home = page.getByRole("heading", { name: "Home", exact: true })) {
  const factor = loadFactor();
  const enrol = page.getByRole("heading", { name: "Set up two-step verification" });
  const verify = page.getByRole("heading", { name: "Two-step verification", exact: true });
  await expect(home.or(enrol).or(verify)).toBeVisible();
  const now = Math.floor(Date.now() / 1000 / 30);
  if (await enrol.isVisible()) {
    const text = await page.getByTestId("mfa-secret").textContent();
    factor.seed = unbase32(text.split(":").pop());
    factor.lastStep = now;
    await page.getByLabel("Verification code").fill(totp(factor.seed, now));
    await page.getByRole("button", { name: "Turn on two-step verification" }).click();
    const codes = page.getByTestId("mfa-recovery-codes").locator("code");
    await expect(codes.first()).toBeVisible();
    factor.recovery = await codes.allTextContents();
    saveFactor(factor);
    await page.getByRole("button", { name: "I saved them, continue" }).click();
  } else if (await verify.isVisible()) {
    if (!factor.seed) throw new Error("the e2e administrator enrolled a second factor outside this run");
    // A step's code is accepted once (ASVS 2.8.5): when this step's is spent, wait for
    // the next step rather than spend the few recovery codes.
    let step = Math.floor(Date.now() / 1000 / 30);
    if (step <= factor.lastStep) {
      await page.waitForTimeout((factor.lastStep + 1) * 30_000 - Date.now() + 250);
      step = factor.lastStep + 1;
    }
    factor.lastStep = step;
    saveFactor(factor);
    await page.getByLabel("Verification code").fill(totp(factor.seed, step));
    await page.getByRole("button", { name: "Verify" }).click();
  }
}

/// A real account needs something to list: a draft and a sent envelope, made through
/// the API once (the mock seeds its own). Answers whether it made any.
async function seedReal(page) {
  const headers = { "X-CSRF-Token": realSession.csrf };
  const list = await page.request.get("/api/v1/envelopes?limit=200", { headers });
  expect(list.ok(), `list envelopes: ${list.status()}`).toBeTruthy();
  const have = new Set((await list.json()).items.map((e) => e.status));
  const pdf = Buffer.from(makePdf([{ title: "Seeded agreement", lines: ["Made by the e2e suite."] }])).toString("base64");
  let made = false;
  for (const status of ["draft", "sent"]) {
    if (have.has(status)) continue;
    const res = await page.request.post("/api/v1/envelopes", {
      headers: { ...headers, "Idempotency-Key": `seed-${status}-${Date.now()}` },
      data: {
        subject: `Seeded ${status} envelope`,
        status,
        documents: [{ name: "seeded.pdf", content_base64: pdf }],
        recipients: [{ ref: "s", type: "signer", name: "Sam Seed", email: "sam.seed@example.com" }],
        fields: [{ recipient: "s", document: 0, type: "signature", page: 1, x: 72, y: 600, width: 180, height: 40, required: true }],
      },
    });
    expect(res.ok(), `seed a ${status} envelope: ${res.status()} ${await res.text()}`).toBeTruthy();
    made = true;
  }
  return made;
}

/// A small PDF made on the spot (two pages), as a file for `setInputFiles`.
export function pdfFile(name = "contract.pdf", title = "Services contract") {
  const bytes = makePdf([
    { title, lines: ["This contract is between the parties below.", "1. Services. 2. Fees. 3. Term."] },
    { title: `${title} (signatures)`, lines: ["Signed by the parties on the dates shown."] },
  ]);
  return { name, mimeType: "application/pdf", buffer: Buffer.from(bytes) };
}

/// Zero serious or critical axe violations (WCAG 2.2 A and AA rules).
export async function expectAccessible(page, what) {
  // Let entrance transitions finish: axe measures colours as painted, and a view
  // fading in is a view at partial opacity. Endless ones (shimmer, spinner) excepted.
  // E2E-02: on CI's WebKit a view's fade was still at its first frames when axe ran,
  // although this wait had just seen nothing running (text measured at about 2 %
  // opacity). So the scan is taken again, after the animations settle, until it is
  // clean or the timeout (15 s: one axe pass on a slow CI WebKit can take seconds,
  // and the deadline covers the scan itself): a violation of the settled page fails.
  const scan = async () => {
    await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity));
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
    const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    return bad.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} × ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(", ")} — ${(v.nodes[0]?.any?.[0]?.message || v.nodes[0]?.failureSummary || "").slice(0, 160)}`);
  };
  await expect.poll(scan, { message: `axe on ${what}`, intervals: [250, 500, 1000], timeout: 15_000 }).toEqual([]);
}

/// Save a screenshot for people to look at (the visual check), and attach it.
export async function snap(target, testInfo, name) {
  fs.mkdirSync(SCREENS, { recursive: true });
  const file = path.join(SCREENS, `${testInfo.project.name}-${name}.png`);
  await target.screenshot({ path: file, animations: "disabled" });
  await testInfo.attach(name, { path: file, contentType: "image/png" });
  return file;
}

/// Press Tab until `locator` has focus (keyboard-only tests), at most `max` times.
/// WebKit follows macOS: Tab alone skips buttons unless "Keyboard navigation" is on,
/// and Option+Tab reaches every control, as a Safari keyboard user presses it.
export async function tabTo(page, locator, max = 80, shift = false) {
  const webkit = page.context().browser()?.browserType().name() === "webkit";
  // macOS WebKit moves focus to buttons and links only with Option+Tab (its system
  // setting); WebKit on Linux, as on the CI runners, uses plain Tab like everyone else.
  const key = `${shift ? "Shift+" : ""}${webkit && process.platform === "darwin" ? "Alt+" : ""}Tab`;
  for (let i = 0; i < max; i++) {
    if (await locator.evaluate((el) => el === document.activeElement).catch(() => false)) return;
    await page.keyboard.press(key);
  }
  throw new Error(`could not reach ${locator} with Tab`);
}
