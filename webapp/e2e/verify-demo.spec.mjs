// The slice 7 demo (VS-07): the Verify page recorded as a video, as the slice 1 demo is
// (real-stack.spec.mjs, S1-02). A visitor opens verify.html, the verifier (casual-sign-
// verify in WebAssembly) loads, they add the issuer's certificate, check a sealed B-LT
// PDF (valid, every check listed), then a tampered one (invalid, the failing check
// marked). The recording is written to target/e2e-demo/vs07-<browser>-verify.webm and
// uploaded by CI's e2e job as the `slice-7-demo` artifact.
//
// Mock mode only: verify.html makes no server call, so the page is the same on any
// server; the Compose run records slice 1 instead.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";
import { REAL } from "./helpers.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixture = (p) => path.join(ROOT, "fixtures", p);
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));
const DEMO = path.resolve(fileURLToPath(new URL("../../target/e2e-demo", import.meta.url)));

// Playwright refuses video inside a describe group, so it is set for this file.
test.use({ video: { mode: "on", size: { width: 1280, height: 800 } }, viewport: { width: 1280, height: 800 } });

test("verify a sealed PDF and a tampered one, recorded (VS-07 demo)", async ({ page }, testInfo) => {
  test.skip(REAL, "recorded in mock mode by the e2e job; verify.html calls no server");
  test.skip(!WASM, "the WASM verifier is built locally by tools/build-webapp-wasm.sh");
  // A pause between steps so a person watching can follow; the assertions do the checking.
  const beat = () => page.waitForTimeout(800);

  await page.goto("/verify.html?mock=1");
  await expect(page.getByRole("heading", { name: "Verify a signed PDF" })).toBeVisible();
  await expect(page.getByTestId("verify-engine")).toHaveAttribute("data-state", "ready");
  await beat();

  await page.getByTestId("trust-input").setInputFiles(fixture("sealed/trust-root.pem"));
  await expect(page.getByText("trust-root.pem")).toBeVisible();
  await beat();
  await page.getByTestId("verify-input").setInputFiles(fixture("sealed/p256-approval-blt.pdf"));
  const verdict = page.getByTestId("verdict");
  await expect(verdict).toHaveAttribute("data-state", "valid");
  await expect(page.getByRole("heading", { name: "Signed and unchanged" })).toBeVisible();
  await expect(page.getByTestId("signature")).toContainText("Valid");
  await beat();
  await page.getByTestId("signature").scrollIntoViewIfNeeded();
  await beat();

  await page.getByTestId("verify-another").click();
  await page.getByTestId("trust-input").setInputFiles(fixture("signed/trust-root.der"));
  await page.getByTestId("verify-input").setInputFiles(fixture("signed/flip-range1.pdf"));
  await expect(verdict).toHaveAttribute("data-state", "invalid");
  await expect(page.locator(".os-vfy__check.is-bad").first()).toBeVisible();
  await page.locator(".os-vfy__check.is-bad").first().scrollIntoViewIfNeeded();
  await beat();

  await page.close();
  fs.mkdirSync(DEMO, { recursive: true });
  const out = path.join(DEMO, `vs07-${testInfo.project.name}-verify.webm`);
  await page.video()?.saveAs(out);
  expect(fs.statSync(out).size, "the recording was written").toBeGreaterThan(10_000);
});
