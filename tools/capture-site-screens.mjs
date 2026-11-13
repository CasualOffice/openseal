// Product screenshots for the website (SITE-01): the real web app in demo mode and the
// real platform console UI, driven by Playwright, in light and dark, at device scale 2
// so they stay sharp on high-density screens. Raw PNGs go to an output directory; then
// tools/build-site.py --screens turns them into site/assets/screens/*.webp and .png.
//
//   python3 -I tools/serve-webapp.py 8150 &                     # the web app, demo mode
//   tools/build-webapp-wasm.sh                                  # the Verify shot needs the verifier
//   node tools/capture-site-screens.mjs [--only a,b] [OUT] [BASE]
//   python3 tools/build-site.py --screens OUT && python3 tools/build-site.py
//
// OUT defaults to target/site-screens, BASE to http://127.0.0.1:8150. Re-runnable: each
// scene is captured on its own, `--only` picks scenes, and build-site.py --screens
// converts whatever raw files OUT holds, so one screen can be refreshed without the rest.
//
// Scenes (the name is the file the site uses, site/assets/screens/NAME-{light,dark}.*):
//   ready now   signin, home, palette, verify, sign (sign-desktop, adopt-desktop,
//               sign-done), phone (sign-phone, adopt-phone), console, certificate
//   after the web-app rebuild merges (Agreements, Prepare and Admin lanes): agreements,
//               editor, admin (writes admin-api and admin-intelligence), templates, envelope
// A scene that fails is named and the run exits non-zero; the others are still written.
//
// The console is the real console-ui/ served by this script, with its API answered by a
// fixed demo fixture (no database, no operator), as the web app's own demo mode does.
// Uses the e2e harness's Playwright (`cd webapp/e2e && npm ci`). Headless only. The
// demo-mode banner is hidden by a style injected here, never by the app.

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const argv = process.argv.slice(2);
let only = null;
const pos = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--only") only = new Set((argv[++i] || "").split(",").map((s) => s.trim()).filter(Boolean));
  else pos.push(argv[i]);
}
const OUT = path.resolve(pos[0] || path.join(ROOT, "target/site-screens"));
const BASE = pos[1] || "http://127.0.0.1:8150";
const PW = path.join(ROOT, "webapp/e2e/node_modules/playwright/index.mjs");
if (!fs.existsSync(PW)) {
  console.error("capture-site-screens: Playwright is not installed; run `npm ci` in webapp/e2e");
  process.exit(1);
}
const { chromium } = await import(pathToFileURL(PW).href);
const { makePdf } = await import(pathToFileURL(path.join(ROOT, "webapp/mockpdf.js")).href);
const CERT = process.env.OPENSEAL_SITE_CERT_PDF || "";

const SCENES = ["signin", "home", "palette", "verify", "sign", "phone", "console", "certificate",
  "agreements", "editor", "admin", "templates", "envelope"];
if (only) {
  const unknown = [...only].filter((s) => !SCENES.includes(s));
  if (unknown.length) { console.error(`capture-site-screens: unknown scene(s) ${unknown.join(", ")}; known: ${SCENES.join(", ")}`); process.exit(2); }
}
const want = (s) => !only || only.has(s);

fs.mkdirSync(OUT, { recursive: true });
const HIDE = "#mock-banner{display:none!important}";
const DESK = { width: 1440, height: 900 };
const PHONE = { width: 390, height: 844 };

function contractPdf() {
  const bytes = makePdf([
    { title: "Master services agreement", lines: ["Between Halden Logistics and Ferro Analytics.", "1. Services. 2. Fees. 3. Term and termination.", "4. Confidentiality. 5. Liability."] },
    { title: "Signatures", lines: ["Signed by the parties on the dates shown."] },
  ]);
  return { name: "services-agreement.pdf", mimeType: "application/pdf", buffer: Buffer.from(bytes) };
}

async function settle(page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity), null, { timeout: 15_000 });
  await page.waitForTimeout(300);
}

async function painted(page, selector) {
  await page.locator(`${selector} canvas`).first().waitFor({ state: "visible", timeout: 20_000 });
  await page.waitForFunction((sel) => [...document.querySelectorAll(`${sel} .os-page`)].every((p) => !p.classList.contains("is-loading")), selector, { timeout: 20_000 });
  await page.waitForTimeout(400);
}

// ---- The console UI, served here with a demo API ------------------------------------------

const CONSOLE_DIR = path.join(ROOT, "console-ui");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".svg": "image/svg+xml" };

function consoleServer() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const url = new URL(req.url, "http://x");
      let rel = decodeURIComponent(url.pathname);
      if (rel === "/") rel = "/index.html";
      const file = path.join(CONSOLE_DIR, path.normalize(rel));
      if (!file.startsWith(CONSOLE_DIR + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream", "cache-control": "no-store" });
      fs.createReadStream(file).pipe(res);
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

/// The console API's answers for the screenshot: a healthy platform with one open
/// alert, one dead letter and a little queue. Demo data, like the web app's mock.
function consoleApi(nowMs) {
  const ago = (s) => new Date(nowMs - s * 1000).toISOString();
  const me = "0190c8e2-0000-7000-8000-00000000f001";
  return {
    "/me": { operator: me, roles: ["platform_owner"] },
    "/operators": { operators: [{ id: me, email: "owner@console.example", roles: ["platform_owner"], disabled: false }] },
    "/approvals": { approvals: [] },
    "/health": {
      jobs: [
        { kind: "deliver_webhook", status: "queued", jobs: 3, oldest_seconds: 12 },
        { kind: "send_invitation", status: "queued", jobs: 5, oldest_seconds: 40 },
        { kind: "send_invitation", status: "running", jobs: 2 },
        { kind: "seal_envelope", status: "running", jobs: 1 },
        { kind: "send_invitation", status: "dead", jobs: 1 },
      ],
      dead_letters: 1,
      connections: [{ state: "active", connections: 4 }, { state: "idle", connections: 11 }],
      database: { status: "up" },
      operator_log: { verified: true, events: 214 },
      services: [
        { name: "server", role: "api", probe: "http", status: "up", latency_ms: 4, http_status: 200 },
        { name: "worker", role: "worker", probe: "http", status: "up", latency_ms: 6, http_status: 200 },
        { name: "keyd", role: "keyd", probe: "tcp", status: "up", latency_ms: 2 },
        { name: "modeld", role: "modeld", probe: "http", status: "up", latency_ms: 9, http_status: 200 },
      ],
    },
    "/alerts": { alerts: [
      { id: "a1", at: ago(540), source: "worker", code: "CS-TSA-0001" },
      { id: "a2", at: ago(7200), source: "worker", code: "CS-MAIL-0001" },
      { id: "a3", at: ago(3600), source: "worker", code: "CS-MAIL-0001", resolves: "a2" },
    ] },
    "/dead-letters": { dead_letters: [
      { id: "0190c8e2-0000-7000-8000-0000000000d1", kind: "send_invitation", error_code: "CS-MAIL-0001", attempts: 15, workspace_id: "0190c8e2-0000-7000-8000-0000000000a1", finished_at: ago(1200) },
    ] },
  };
}

// ---- Capture --------------------------------------------------------------------------------

const failures = [];

async function run(scheme, consoleBase) {
  const browser = await chromium.launch({ headless: true });
  const shot = async (page, name) => {
    await page.addStyleTag({ content: HIDE }).catch(() => {});
    // Park the pointer on an empty margin, so no row shows its hover state.
    const vp = page.viewportSize();
    await page.mouse.move(vp.width - 2, Math.round(vp.height * 0.6));
    await settle(page);
    await page.screenshot({ path: path.join(OUT, `${scheme}-${name}.png`), animations: "disabled" });
    console.log(`  ${scheme}-${name}`);
  };
  const ctxFor = async (viewport, extra = {}) => {
    // bypassCSP: only so the banner-hiding style applies.
    const ctx = await browser.newContext({ viewport, deviceScaleFactor: 2, colorScheme: scheme, locale: "en-US", timezoneId: "Europe/Amsterdam", bypassCSP: true, ...extra });
    await ctx.addInitScript(([s, css]) => {
      try { localStorage.setItem("openseal.theme", s); } catch { /* storage off */ }
      document.addEventListener("DOMContentLoaded", () => { const st = document.createElement("style"); st.textContent = css; document.head.append(st); });
    }, [scheme, HIDE]);
    return ctx;
  };
  /// Run one scene in its own context; a failure is recorded, never fatal to the others.
  const scene = async (name, viewport, fn, extra) => {
    if (!want(name)) return;
    const ctx = await ctxFor(viewport, extra);
    try {
      await fn(await ctx.newPage(), ctx);
    } catch (err) {
      failures.push(`${scheme} ${name}: ${String(err.message || err).split("\n")[0]}`);
      console.error(`  ${scheme}-${name}: FAILED`);
    } finally {
      await ctx.close();
    }
  };
  const signIn = async (page) => {
    await page.goto(`${BASE}/app.html?mock=1#/signin`);
    await page.getByLabel("Email").fill("demo@openseal.test");
    await page.getByLabel("Password").fill("openseal-demo-1");
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.getByRole("heading", { name: "Home", exact: true }).waitFor();
  };
  const home = async (page) => {
    await signIn(page);
    await page.locator(".os-counters:not([aria-busy])").waitFor();
    await page.locator(".os-recent__item").first().waitFor();
  };

  // ---- Ready now ---------------------------------------------------------------------------
  await scene("signin", DESK, async (page) => {
    await page.goto(`${BASE}/app.html?mock=1#/signin`);
    await page.getByLabel("Email").waitFor();
    await page.getByLabel("Email").fill("ada@halden.example");
    await page.locator("main").click({ position: { x: 4, y: 4 } }).catch(() => {});
    await page.evaluate(() => document.activeElement?.blur());
    await shot(page, "signin");
  });

  await scene("home", DESK, async (page) => {
    await home(page);
    await shot(page, "home");
  });

  await scene("palette", DESK, async (page) => {
    await home(page);
    await page.locator("#palette-btn").click();
    const menu = page.getByRole("dialog", { name: "Command menu" });
    await menu.waitFor();
    await menu.getByRole("combobox").fill("nda");
    await menu.getByRole("option").first().waitFor();
    await shot(page, "palette");
  });

  await scene("verify", DESK, async (page) => {
    await page.goto(`${BASE}/verify.html`);
    await page.getByTestId("trust-input").setInputFiles(path.join(ROOT, "fixtures/sealed/trust-root.pem")).catch(() => {});
    await page.getByTestId("verify-input").setInputFiles(path.join(ROOT, "fixtures/sealed/p256-approval-blt.pdf"));
    await page.locator('[data-testid="verdict"]').first().waitFor({ timeout: 30_000 });
    await page.locator(".os-preview__pages canvas, .os-page canvas").first().waitFor({ timeout: 20_000 }).catch(() => {});
    await page.waitForTimeout(600);
    await shot(page, "verify");
  });

  const ceremony = async (sp) => {
    await sp.goto(`${BASE}/s/demo-sign?mock=1`);
    await sp.getByLabel("Access code").fill("2468");
    await sp.getByRole("button", { name: "Continue" }).click();
    await sp.getByRole("button", { name: "Share my location" }).click();
    await sp.getByLabel("I agree to use electronic records and signatures.").check();
    await sp.getByRole("button", { name: "Continue" }).click();
    await painted(sp, ".os-sign__pages");
  };
  const geo = { geolocation: { latitude: 52.37, longitude: 4.89, accuracy: 25 }, permissions: ["geolocation"] };

  await scene("sign", DESK, async (sp) => {
    await ceremony(sp);
    // The guide's first step done (Job title), the signature next; the page from its top.
    await sp.getByRole("button", { name: "Start" }).click();
    const title = sp.getByRole("textbox", { name: /Job title/ });
    await title.fill("Head of People");
    await title.press("Enter");
    await title.blur();
    await sp.getByRole("button", { name: "Next" }).click();
    await sp.locator('[data-testid="signer-doc"]').evaluate((el) => el.scrollTo(0, 0));
    await sp.waitForTimeout(400);
    await shot(sp, "sign-desktop");
    await sp.getByRole("button", { name: /Signature, required/ }).first().click();
    const dlg = sp.getByRole("dialog", { name: "Adopt your signature" });
    await dlg.waitFor();
    const typed = dlg.getByRole("textbox").first();
    if (await typed.isVisible().catch(() => false)) await typed.fill("Jordan Rivera");
    await shot(sp, "adopt-desktop");
    await dlg.getByTestId("adopt-confirm").click();
    await dlg.waitFor({ state: "hidden" });
    await sp.getByRole("button", { name: "Finish" }).click();
    await sp.getByRole("heading", { name: "Review and finish" }).waitFor();
    await painted(sp, ".os-review__pages");
    await sp.getByTestId("review-finish").click();
    await sp.getByTestId("sign-done").waitFor();
    await shot(sp, "sign-done");
  }, geo);

  await scene("phone", PHONE, async (sp) => {
    await ceremony(sp);
    await sp.locator('[data-testid="signer-doc"]').evaluate((el) => el.scrollTo(0, 0)).catch(() => {});
    await shot(sp, "sign-phone");
    await sp.getByRole("button", { name: /Signature, required/ }).first().click();
    const dlg = sp.getByRole("dialog", { name: "Adopt your signature" });
    await dlg.waitFor();
    const typed = dlg.getByRole("textbox").first();
    if (await typed.isVisible().catch(() => false)) await typed.fill("Jordan Rivera");
    await shot(sp, "adopt-phone");
  }, geo);

  await scene("console", DESK, async (page) => {
    const api = consoleApi(Date.now());
    await page.addInitScript(() => { try { sessionStorage.setItem("openseal.console.csrf", "demo"); } catch { /* storage off */ } });
    await page.route("**/console/v1/**", (route) => {
      const p = new URL(route.request().url()).pathname.replace("/console/v1", "");
      const body = api[p];
      return body ? route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) }) : route.fulfill({ status: 404, contentType: "application/json", body: "{}" });
    });
    await page.goto(`${consoleBase}/#/health`);
    await page.locator(".tiles:not([aria-busy]) .tile").first().waitFor({ timeout: 15_000 });
    await shot(page, "console");
  });

  // ---- Certificate of completion: page 1 drawn by the app's own pdf.js ---------------------
  if (want("certificate") && CERT && scheme === "light") {
    const ctx = await ctxFor(DESK);
    const page = await ctx.newPage();
    await page.goto(`${BASE}/verify.html`);
    const b64 = fs.readFileSync(CERT).toString("base64");
    const png = await page.evaluate(async (data) => {
      const pdfjs = await import("./vendor/pdfjs/pdf.min.mjs");
      pdfjs.GlobalWorkerOptions.workerSrc = "./vendor/pdfjs/pdf.worker.min.mjs";
      const bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
      const doc = await pdfjs.getDocument({ data: bytes, isEvalSupported: false, enableScripting: false, standardFontDataUrl: "./vendor/pdfjs/standard_fonts/", cMapUrl: "./vendor/pdfjs/cmaps/" }).promise;
      const p = await doc.getPage(1);
      const vp = p.getViewport({ scale: 2 });
      const c = document.createElement("canvas");
      c.width = vp.width; c.height = vp.height;
      await p.render({ canvasContext: c.getContext("2d"), viewport: vp }).promise;
      return c.toDataURL("image/png").split(",")[1];
    }, b64);
    fs.writeFileSync(path.join(OUT, `${scheme}-certificate.png`), Buffer.from(png, "base64"));
    console.log(`  ${scheme}-certificate`);
    await ctx.close();
  }

  // ---- After the web-app rebuild merges ------------------------------------------------------
  // Selectors follow the approved canvas (docs/assets/design-canvas) and the current e2e
  // specs; if a rebuilt screen names things differently, adjust the step here and rerun
  // with --only.
  await scene("agreements", DESK, async (page) => {
    await signIn(page);
    await page.goto(`${BASE}/app.html?mock=1#/agreements`);
    await page.locator(".os-row__sub, [data-testid='agreement-row']").first().waitFor();
    await shot(page, "agreements");
  });

  await scene("envelope", DESK, async (page) => {
    await signIn(page);
    await page.goto(`${BASE}/app.html?mock=1#/agreements`);
    await page.getByRole("link", { name: /Mutual NDA/ }).first().click();
    await page.getByRole("heading", { name: /Audit trail|Activity/ }).first().waitFor();
    await shot(page, "envelope");
  });

  await scene("editor", DESK, async (page) => {
    await signIn(page);
    await page.goto(`${BASE}/app.html?mock=1#/prepare`);
    await page.getByTestId("pdf-input").setInputFiles(contractPdf());
    await page.getByTestId("doc-card").first().waitFor();
    await page.getByTestId("wizard-next").click();
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    await page.getByTestId("recipient-name").fill("Ilse Marten");
    await page.getByTestId("recipient-email").fill("ilse@halden.example");
    await page.getByRole("button", { name: "Add recipient" }).first().click();
    await page.getByTestId("recipient-name").nth(1).fill("Tomas Okafor");
    await page.getByTestId("recipient-email").nth(1).fill("tomas@ferro.example");
    await page.getByTestId("wizard-next").click();
    await painted(page, ".os-stage");
    const placing = (i) => page.getByRole("radiogroup", { name: "Placing fields for" }).getByRole("radio").nth(i).click();
    const add = (name) => page.locator(".os-palette").getByRole("button", { name: `Add ${name} field` }).click();
    await placing(0);
    await add("Signature"); await add("Date signed"); await add("Text");
    await placing(1);
    await add("Signature"); await add("Date signed");
    await page.mouse.click(5, 5);
    await shot(page, "editor");
  });

  await scene("templates", DESK, async (page) => {
    await signIn(page);
    await page.goto(`${BASE}/app.html?mock=1#/templates`);
    await page.getByRole("link", { name: /Mutual NDA/ }).first().waitFor();
    await shot(page, "templates");
  });

  await scene("admin", DESK, async (page) => {
    await signIn(page);
    await page.goto(`${BASE}/app.html?mock=1#/admin`);
    const api = page.getByRole("tab", { name: /API clients/ }).or(page.getByRole("link", { name: /API clients/ }));
    await api.first().click();
    await page.getByText("CRM integration").first().waitFor();
    await shot(page, "admin-api");
    const tab = page.getByRole("tab", { name: /Document intelligence/ }).or(page.getByRole("link", { name: /Document intelligence/ }));
    await tab.first().click();
    await page.getByRole("switch").first().waitFor();
    await shot(page, "admin-intelligence");
  });

  await browser.close();
}

const srv = want("console") ? await consoleServer() : null;
const consoleBase = srv ? `http://127.0.0.1:${srv.address().port}` : "";
for (const scheme of ["light", "dark"]) {
  console.log(`capturing ${scheme}`);
  await run(scheme, consoleBase);
}
srv?.close();
if (failures.length) {
  console.error(`capture-site-screens: ${failures.length} scene(s) failed\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log(`capture-site-screens: done; raw PNGs in ${OUT}`);
