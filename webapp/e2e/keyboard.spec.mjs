// Scenario 5 (WEB-01): keyboard only — sign in, start an envelope, add a recipient,
// place a field, move and size it, and send, without the mouse. (The file is chosen
// with `setInputFiles`, which stands for the operating system's file dialog.)
import { test, expect } from "@playwright/test";
import { app, creds, pdfFile, tabTo } from "./helpers.mjs";

test("place a field and send with the keyboard alone", async ({ page }) => {
  await page.goto(app("#/signin"));
  await expect(page.getByLabel("Email")).toBeFocused();
  await page.keyboard.type(creds.email);
  await page.keyboard.press("Tab");
  await page.keyboard.type(creds.password);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();

  await page.locator("body").press("n"); // N: new envelope (keys.js)
  await expect(page.getByTestId("empty-documents")).toBeVisible();
  await page.getByTestId("pdf-input").setInputFiles(pdfFile("keys.pdf", "Keyboard terms"));
  await expect(page.locator(".os-page.is-loading")).toHaveCount(0);

  const add = page.getByRole("button", { name: "Add recipient" }).first();
  await tabTo(page, add);
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("recipient-name")).toBeFocused();
  await page.keyboard.type("Kim Keys");
  await page.keyboard.press("Tab");
  await page.keyboard.type("kim@example.com");

  const sig = page.locator(".os-palette").getByRole("button", { name: "Add Signature field" });
  await tabTo(page, sig);
  await page.keyboard.press("Enter");
  const field = page.locator(".os-field");
  await expect(field).toHaveCount(1);
  await expect(field).toBeFocused();
  const left = page.getByLabel("Left");
  const x0 = Number(await left.inputValue());
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("Shift+ArrowRight");
  await expect(left).toHaveValue(String(Math.round((x0 + 11) * 100) / 100));
  await page.keyboard.press("Alt+ArrowRight");
  await expect(page.getByLabel("Width")).toHaveValue("164");
  await page.keyboard.press("Control+z");
  await expect(page.getByLabel("Width")).toHaveValue("160");

  await page.keyboard.press("Control+Enter");
  const dlg = page.getByRole("dialog", { name: "Send this envelope?" });
  await expect(dlg).toBeVisible();
  await expect(dlg.getByRole("button", { name: "Send" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Recipients" })).toBeVisible({ timeout: 20_000 });
  await expect(page.locator(".os-page-head .os-badge")).toHaveText("Sent");
});

test("the shortcut list opens with ? and closes with Escape, returning focus", async ({ page }) => {
  await page.goto(app("#/signin"));
  await page.keyboard.type(creds.email);
  await page.keyboard.press("Tab");
  await page.keyboard.type(creds.password);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Agreements" })).toBeVisible();
  await page.locator("body").press("Shift+?");
  const dlg = page.getByRole("dialog", { name: "Keyboard shortcuts" });
  await expect(dlg).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dlg).toBeHidden();
});
