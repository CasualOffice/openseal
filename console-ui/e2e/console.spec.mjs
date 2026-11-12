// The platform console UI against a real console and PostgreSQL (CON-17): enrolment,
// sign-in with TOTP, health, organizations, the two-person suspend flow across two
// operators (with a stale second factor re-entered), operators and the operator log.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { test, expect } from "@playwright/test";

const SHOTS = process.env.SHOTS || "";
const PASSWORD = "correct horse battery staple";

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s), from the base32 secret the UI shows.
function base32(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/[\s=]/g, "").toUpperCase()) bits += A.indexOf(c).toString(2).padStart(5, "0");
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = crypto.createHmac("sha1", base32(secret)).update(msg).digest();
  const o = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
const last = new Map();
/// A code the server has not seen for this operator: it accepts steps −1..+1 and each
/// step once, so wait when the next unused step is beyond +1.
async function nextCode(secret) {
  const now = () => Math.floor(Date.now() / 30_000);
  const want = Math.max(now(), (last.get(secret) ?? -1) + 1);
  while (want > now() + 1) await new Promise((r) => setTimeout(r, 1000));
  last.set(secret, want);
  return totp(secret, want);
}

async function shoot(page, name) {
  if (!SHOTS) return;
  fs.mkdirSync(SHOTS, { recursive: true });
  const size = page.viewportSize();
  for (const [w, hgt] of [[1440, 900], [390, 844]]) {
    await page.setViewportSize({ width: w, height: hgt });
    await page.waitForTimeout(150);
    await page.screenshot({ path: path.join(SHOTS, `${name}-${w}.png`), fullPage: true });
  }
  await page.setViewportSize(size);
}

function watchErrors(page) {
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  return errors;
}

/// Enrol from a token and return the operator's TOTP secret.
async function enrol(page, token, shots) {
  await page.goto(`/#/enrol/${token}`);
  await expect(page.getByRole("heading", { name: "Set up your operator account" })).toBeVisible();
  if (shots) await shoot(page, "enrol-token");
  await page.getByRole("button", { name: "Continue" }).click();
  const secretBox = page.locator(".secret");
  await expect(secretBox).toBeVisible();
  const secret = (await secretBox.textContent()).replace(/\s/g, "");
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  if (shots) await shoot(page, "enrol-secret");
  await page.getByLabel("New password").fill(PASSWORD);
  await page.getByLabel("Repeat password").fill(PASSWORD);
  await page.getByLabel("Code from your authenticator app").fill(await nextCode(secret));
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByRole("heading", { name: "You're set up" })).toBeVisible();
  return secret;
}

async function signIn(page, email, secret, shots) {
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("E-mail").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  if (shots) await shoot(page, "signin");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Enter your code" })).toBeVisible();
  if (shots) await shoot(page, "totp");
  await page.getByLabel("Authenticator code").fill(await nextCode(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Health" })).toBeVisible();
}

test("the console UI drives the real console API end to end", async ({ browser }) => {
  const token = fs.readFileSync(path.join(process.env.STATE_DIR, "token"), "utf8").trim();
  const ownerCtx = await browser.newContext({ reducedMotion: "reduce" });
  const owner = await ownerCtx.newPage();
  const ownerErrors = watchErrors(owner);

  // A wrong password is refused without saying which part was wrong.
  await owner.goto("/");
  await expect(owner.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await owner.getByLabel("E-mail").fill("owner@console.example");
  // An error box is hidden until there is an error.
  await expect(owner.locator(".alert-box.bad:visible")).toHaveCount(0);
  await owner.getByLabel("Password").fill("not the password at all");
  await owner.getByRole("button", { name: "Continue" }).click();
  await expect(owner.getByRole("alert")).toContainText("do not match an operator");

  const ownerSecret = await enrol(owner, token, true);
  await signIn(owner, "owner@console.example", ownerSecret, true);

  // Health: only what the API returned.
  const tiles = owner.locator(".tile");
  await expect(tiles).toHaveCount(5);
  await expect(owner.getByRole("group", { name: "Dead letters" })).toContainText("1");
  await expect(owner.getByRole("group", { name: "Services" })).toContainText("1 of 2");
  await expect(owner.getByRole("group", { name: "Operator log" })).toContainText("Verified");
  await expect(owner.getByText("No open alerts")).toBeVisible();
  await expect(owner.locator(".nav", { hasText: "Operators" })).toBeVisible();
  await shoot(owner, "health");
  await expect(owner.locator("main")).not.toContainText(/\bnull\b|undefined|NaN/);

  // Loading skeleton while health is slow.
  await owner.route("**/console/v1/health", async (r) => { await new Promise((x) => setTimeout(x, 2500)); await r.continue().catch(() => {}); });
  await owner.reload();
  await expect(owner.locator(".tiles[aria-busy=true]")).toBeVisible();
  await shoot(owner, "health-loading");
  await owner.unroute("**/console/v1/health");
  await expect(tiles).toHaveCount(5);

  // Error state with retry when the API fails.
  await owner.route("**/console/v1/organizations?*", (r) => r.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({ type: "x", title: "Database unavailable", status: 503, code: "CS-CON-0015" }) }));
  await owner.locator(".nav", { hasText: "Organizations" }).click();
  await expect(owner.getByText("The database is not answering")).toBeVisible();
  await shoot(owner, "organizations-error");
  await owner.unroute("**/console/v1/organizations?*");
  await owner.getByRole("button", { name: "Try again" }).click();

  // Organizations.
  await expect(owner.getByRole("link", { name: "Acme Holdings" })).toBeVisible();
  await expect(owner.locator("tbody tr")).toHaveCount(3);
  await shoot(owner, "organizations");
  await expect(owner.locator("main")).not.toContainText(/\bnull\b|undefined|NaN/);
  await owner.getByRole("link", { name: "Globex Field Services" }).click();
  await owner.getByRole("button", { name: "Rename" }).click();
  await owner.getByLabel("Name", { exact: true }).fill("Globex Services");
  await owner.getByRole("button", { name: "Save" }).click();
  await expect(owner.getByRole("heading", { name: "Globex Services" })).toBeVisible();
  await owner.getByRole("button", { name: "Edit labels" }).click();
  await owner.getByLabel("Labels", { exact: true }).fill("us-east, BAD_label");
  await owner.getByRole("button", { name: "Save labels" }).click();
  await expect(owner.getByRole("alert")).toContainText("Not a label: bad_label");
  await owner.getByLabel("Labels", { exact: true }).fill("us-east");
  await owner.getByRole("button", { name: "Save labels" }).click();
  await expect(owner.locator(".chip.region", { hasText: "us-east" })).toBeVisible();

  await owner.goto("/#/organizations/0190c8e2-0000-7000-8000-000000000001");
  await expect(owner.getByRole("heading", { name: "Acme Holdings" })).toBeVisible();
  await expect(owner.getByRole("cell", { name: "Contracts", exact: true })).toBeVisible();
  await shoot(owner, "organization");
  await owner.getByRole("button", { name: "Request suspension" }).click();
  await expect(owner.getByText(/Waiting for a second operator/)).toBeVisible();
  await shoot(owner, "organization-waiting");

  // Operators: add a second operator; the token is shown once.
  await owner.locator(".nav", { hasText: "Operators" }).click();
  await owner.getByRole("button", { name: "Add operator" }).click();
  await owner.getByLabel("E-mail").fill("second@console.example");
  await owner.getByRole("button", { name: "Create and get enrolment link" }).click();
  await expect(owner.getByRole("heading", { name: "Enrolment link" })).toBeVisible();
  await shoot(owner, "operators-token");
  const secondToken = (await owner.locator(".panel .secret").nth(1).textContent()).trim();
  await owner.getByRole("button", { name: "Close" }).click();
  await expect(owner.getByRole("cell", { name: "second@console.example", exact: true })).toBeVisible();
  await shoot(owner, "operators");

  // The second operator grants, re-entering a second factor the server calls stale.
  const secondCtx = await browser.newContext({ reducedMotion: "reduce" });
  const second = await secondCtx.newPage();
  const secondErrors = watchErrors(second);
  const secondSecret = await enrol(second, secondToken, false);
  await signIn(second, "second@console.example", secondSecret, false);
  await expect(second.locator(".nav", { hasText: "Operators" })).toHaveCount(0);
  await expect(second.locator(".nav .count")).toHaveText("1");
  await second.locator(".nav", { hasText: "Approvals" }).click();
  await expect(second.getByText("Suspend organization:")).toBeVisible();
  await shoot(second, "approvals");
  await expect(second.locator("main")).not.toContainText(/\bnull\b|undefined|NaN/);
  let staled = false;
  await second.route("**/console/v1/approvals/*/grant", async (r) => {
    if (staled) return r.continue();
    staled = true;
    return r.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ type: "x", title: "Second factor required", status: 401, code: "CS-CON-0002" }) });
  });
  await second.getByRole("button", { name: /^Approve/ }).click();
  await expect(second.getByRole("heading", { name: "Confirm it's you" })).toBeVisible();
  await shoot(second, "factor-panel");
  await second.getByLabel("Authenticator code").fill(await nextCode(secondSecret));
  await second.getByRole("button", { name: "Confirm" }).click();
  await expect(second.getByText("Approved, waiting for the requester")).toBeVisible();
  expect(staled).toBe(true);

  // The requester applies; the organization is suspended.
  await owner.goto("/#/organizations/0190c8e2-0000-7000-8000-000000000001");
  await owner.getByRole("button", { name: "Apply suspension" }).click();
  await expect(owner.locator(".head .chip", { hasText: "Suspended" })).toBeVisible();
  await expect(owner.getByRole("button", { name: "Request resumption" })).toBeVisible();
  await shoot(owner, "organization-suspended");

  // The operator log verifies and shows every action.
  await owner.locator(".nav", { hasText: "Operator log" }).click();
  await expect(owner.getByText("Organization suspended")).toBeVisible();
  await owner.getByRole("button", { name: "Verify chain" }).click();
  await expect(owner.getByText(/^Verified: \d+ events/)).toBeVisible();
  await shoot(owner, "log");
  await expect(owner.locator("main")).not.toContainText(/\bnull\b|undefined|NaN/);

  await owner.locator(".nav", { hasText: "Approvals" }).click();
  await expect(owner.getByText("Applied")).toBeVisible();

  // Sign-out ends the session.
  await owner.getByRole("button", { name: "Sign out" }).click();
  await expect(owner.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await owner.goto("/#/organizations");
  await expect(owner.getByRole("heading", { name: "Sign in" })).toBeVisible();

  // No script errors and no CSP violations on any screen, apart from the failures the
  // test itself provoked (wrong password, the forced 503 and 401, signed-out reads).
  const unexpected = [...ownerErrors, ...secondErrors].filter((e) => !/status of (401|503)|Content Security Policy/.test(e) || /Content Security Policy/.test(e));
  expect(unexpected.filter((e) => /Content Security Policy|Uncaught|TypeError|ReferenceError/.test(e))).toEqual([]);
});
