// Visual QA (WEB-02 redesign, owner's rule 4): every screen at 1440×900 and 390×844,
// full-page screenshots under target/e2e-screens/visual-*, and on each screen:
//  - nothing overflows the viewport horizontally;
//  - no two visible interactive elements overlap;
//  - no visible control is an unstyled browser default (each has an os-* class);
//  - every PDF page canvas that should be painted is painted (pixels sampled).
// Mock mode: the screens need the mock's seeded data.
import { test, expect } from "@playwright/test";
import { signIn, app, signPage, tokens, pdfFile, REAL, placingFor } from "./helpers.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SHOTS = path.resolve(fileURLToPath(new URL("../../target/e2e-screens", import.meta.url)));
const ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const WASM = fs.existsSync(path.join(ROOT, "webapp/vendor/openseal-wasm/casual_sign_wasm_bg.wasm"));

/// The layout rules, measured in the page.
async function checkLayout(page, what) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity));
  const problems = await page.evaluate(() => {
    const out = [];
    const vw = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth > vw + 1) out.push(`horizontal overflow: ${document.documentElement.scrollWidth} > ${vw}`);
    // `hidden` means hidden (UX-02): no component's display rule may override it.
    for (const el of document.querySelectorAll("body [hidden]")) {
      if (getComputedStyle(el).display !== "none") out.push(`hidden but shown: ${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}.${[...el.classList].join(".")}`);
    }
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return null;
      const cs = getComputedStyle(el);
      if (cs.visibility === "hidden" || cs.display === "none" || Number(cs.opacity) === 0) return null;
      if (el.closest("[hidden], [aria-hidden='true'], .os-sr-only")) return null;
      // Clip by every scrolling or clipping ancestor: what is scrolled out of view is not shown.
      let box = { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        const ps = getComputedStyle(p);
        if (ps.overflowX !== "visible" || ps.overflowY !== "visible") {
          const q = p.getBoundingClientRect();
          box = { left: Math.max(box.left, q.left), top: Math.max(box.top, q.top), right: Math.min(box.right, q.right), bottom: Math.min(box.bottom, q.bottom) };
          if (box.right - box.left < 1 || box.bottom - box.top < 1) return null;
        }
      }
      if (box.right <= 0 || box.left >= innerWidth) return null; // off-canvas (a closed drawer)
      return box;
    };
    const controls = [...document.querySelectorAll("button, a[href], input:not([type=hidden]):not([type=file]), select, textarea")]
      .map((el) => ({ el, r: visible(el) })).filter((x) => x.r);
    // Unstyled defaults: a control with no class of ours (checkboxes and radios inside our labels count as styled).
    for (const { el } of controls) {
      const styled = [...el.classList].some((c) => c.startsWith("os-")) || el.closest(".os-check, .os-radio, .os-switch, .os-adopt__font, .os-segmented, .os-sfield");
      if (!styled) out.push(`unstyled ${el.tagName.toLowerCase()}: ${(el.getAttribute("aria-label") || el.textContent || el.name || "").trim().slice(0, 40)}`);
    }
    // Overlaps between interactive elements that are not nested in each other.
    const skip = (el) => el.closest(".os-page__overlay, .os-menu, dialog:not([open])");
    const live = controls.filter((x) => !skip(x.el));
    for (let i = 0; i < live.length; i++) {
      for (let j = i + 1; j < live.length; j++) {
        const a = live[i]; const b = live[j];
        if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
        if (a.el.closest("label") && a.el.closest("label") === b.el.closest("label")) continue;
        const w = Math.min(a.r.right, b.r.right) - Math.max(a.r.left, b.r.left);
        const hgt = Math.min(a.r.bottom, b.r.bottom) - Math.max(a.r.top, b.r.top);
        if (w > 2 && hgt > 2) out.push(`overlap: ${a.el.tagName}(${(a.el.getAttribute("aria-label") || a.el.textContent).trim().slice(0, 30)}) × ${b.el.tagName}(${(b.el.getAttribute("aria-label") || b.el.textContent).trim().slice(0, 30)})`);
      }
    }
    return out;
  });
  expect(problems, `layout on ${what}`).toEqual([]);
}

/// The document-first rules (WEB-06, docs/47 §Layout spec) on the editor and the signer:
/// the pages take at least 65 % of a desktop viewport's width; the pages have exactly one
/// scrolling ancestor (the document view), nothing inside it scrolls, and the page itself
/// never scrolls; and no visible text is smaller than 12 px (PDF field overlays aside,
/// which are points × zoom).
async function documentRules(page, vp, testId) {
  const r = await page.evaluate((id) => {
    const doc = document.querySelector(`[data-testid="${id}"]`);
    const box = doc.getBoundingClientRect();
    const scrolls = (el) => {
      const cs = getComputedStyle(el);
      return /(auto|scroll)/.test(`${cs.overflowY} ${cs.overflowX}`) && (el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1);
    };
    const first = doc.querySelector(".os-page");
    const chain = [];
    for (let p = first?.parentElement; p; p = p.parentElement) if (scrolls(p)) chain.push(p === doc ? "document" : p.className || p.tagName);
    const se = document.scrollingElement;
    const root = se.scrollHeight > se.clientHeight + 1 || se.scrollWidth > se.clientWidth + 1;
    const nested = [...doc.querySelectorAll("*")].filter(scrolls).map((e) => e.className);
    const small = [...document.querySelectorAll("body *")].filter((el) => {
      if (el.closest(".os-page__overlay, .os-sr-only, [hidden], [aria-hidden='true']")) return false;
      if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) return false;
      const b = el.getBoundingClientRect();
      if (!b.width || !b.height) return false;
      return Number.parseFloat(getComputedStyle(el).fontSize) < 12;
    }).map((e) => `${e.tagName}.${e.className}`);
    return { share: box.width / innerWidth, chain, root, nested, small };
  }, testId);
  if (vp === "desktop") expect(r.share, `${testId}: document share of the width`).toBeGreaterThanOrEqual(0.65);
  expect(r.chain, `${testId}: scrolling ancestors of the pages`).toEqual(["document"]);
  expect(r.root, `${testId}: the page itself scrolls`).toBe(false);
  expect(r.nested, `${testId}: scrolling inside the document`).toEqual([]);
  expect(r.small, `${testId}: text under 12 px`).toEqual([]);
}
const editorRules = (page, vp) => documentRules(page, vp, "editor-doc");

/// Every canvas under `scope` has drawn something other than white: PDF previews work.
async function expectPainted(page, selector, what) {
  await expect(page.locator(`${selector} canvas`).first()).toBeVisible();
  await page.waitForFunction((sel) => [...document.querySelectorAll(`${sel}`)].every((p) => !p.classList.contains("is-loading")), selector.split(" ")[0] + " .os-page");
  const blank = () => page.evaluate((sel) => [...document.querySelectorAll(`${sel} canvas`)].map((c) => {
    const ctx = c.getContext("2d");
    if (!c.width || !c.height) return true;
    const d = ctx.getImageData(0, 0, c.width, c.height).data;
    // Every pixel, any visible ink: a 140 px thumbnail holds a few hundred antialiased
    // text pixels, which Linux renders lighter than macOS, so a sparse sample with a dark
    // threshold found none on CI although the card was painted.
    let ink = 0;
    for (let i = 0; i < d.length; i += 4) if (d[i + 3] > 0 && (d[i] < 230 || d[i + 1] < 230 || d[i + 2] < 230)) ink++;
    return ink < 3;
  }).filter(Boolean).length, selector);
  await expect.poll(blank, { message: `blank canvases on ${what}`, timeout: 10_000 }).toBe(0);
}

async function shot(page, name, viewport, fullPage = true) {
  fs.mkdirSync(SHOTS, { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(SHOTS, `visual-${viewport}-${name}.png`), fullPage, animations: "disabled" });
}

for (const [vp, size] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]]) {
  test.describe(`visual ${vp}`, () => {
    test.use({ viewport: size });

    test("sender screens", async ({ page }, testInfo) => {
      test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
      test.setTimeout(180_000);
      const check = async (name) => { await checkLayout(page, `${vp} ${name}`); await shot(page, name, vp); };
      await page.goto(app("#/signin"));
      await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
      await check("01-signin");
      await signIn(page, "home");
      await expect(page.locator(".os-counters:not([aria-busy])")).toBeVisible();
      await expect(page.locator(".os-recent__item").first()).toBeVisible();
      await check("02-home");
      await page.goto(app("#/agreements"));
      await expect(page.locator(".os-row__sub").first()).not.toBeEmpty();
      await check("03-agreements");
      await page.getByRole("link", { name: "Mutual NDA — Acme and Globex" }).click();
      await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();
      await check("04-envelope-summary");
      await page.getByRole("tab", { name: "Documents" }).click();
      await expectPainted(page, ".os-preview__pages", "envelope documents");
      await check("05-envelope-documents");

      await page.goto(app("#/prepare"));
      await expect(page.getByTestId("empty-documents")).toBeVisible();
      await check("06-prepare-empty");
      await page.getByTestId("pdf-input").setInputFiles(pdfFile());
      await expectPainted(page, ".os-doccard__frame", "document card");
      await check("07-prepare-documents");
      await page.getByTestId("wizard-next").click();
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      await page.getByTestId("recipient-name").fill("Avery Chen");
      await page.getByTestId("recipient-email").fill("avery@example.com");
      await page.getByRole("button", { name: "Add recipient" }).first().click();
      await page.getByTestId("recipient-name").nth(1).fill("Sam Patel");
      await page.getByTestId("recipient-email").nth(1).fill("sam@example.com");
      await check("08-prepare-recipients");
      await page.getByTestId("wizard-next").click();
      await expectPainted(page, ".os-stage", "editor pages");
      // On phones the palette is a bottom sheet behind "Add field" (WEB-06).
      const palette = async () => { if (vp === "phone") await page.getByTestId("add-field-sheet").click(); };
      await palette();
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
      await palette();
      await placingFor(page, 1);
      await page.locator(".os-palette").getByRole("button", { name: "Add Signature field" }).press("Enter");
      await check("09-prepare-fields");
      await editorRules(page, vp, "editor");
      await page.getByTestId("wizard-next").click();
      await check("10-prepare-review");

      // Unsaved work: leaving asks first (A12).
      await page.goto(app("#/templates"));
      await page.getByRole("button", { name: "Leave without saving" }).click();
      await expect(page.getByRole("link", { name: "Mutual NDA" })).toBeVisible();
      await check("11-templates");
      await page.getByRole("button", { name: "Use Mutual NDA" }).click();
      await expectPainted(page, ".os-preview__pages", "template preview");
      await check("12-template-use");
      await page.goto(app("#/reports"));
      await expect(page.locator(".os-bars")).toBeVisible();
      await check("13-reports");
      await page.goto(app("#/admin"));
      await expect(page.getByRole("cell", { name: "Robin Sender", exact: true })).toBeVisible();
      await check("14-admin-users");
      await page.getByRole("tab", { name: "API clients" }).click();
      await expect(page.getByText("CRM integration")).toBeVisible();
      await check("15-admin-api");
    });

    test("verify", async ({ page }, testInfo) => {
      test.skip(!WASM || REAL || testInfo.project.name !== "chromium", "needs the locally built WASM verifier (not in the server image yet); one browser");
      await page.goto("/verify.html");
      await checkLayout(page, `${vp} verify start`);
      await shot(page, "16-verify-start", vp);
      await page.getByTestId("trust-input").setInputFiles(path.join(ROOT, "fixtures/sealed/trust-root.pem"));
      await page.getByTestId("verify-input").setInputFiles(path.join(ROOT, "fixtures/sealed/p256-approval-blt.pdf"));
      await expect(page.getByTestId("verdict")).toHaveAttribute("data-state", "valid");
      await expectPainted(page, ".os-preview__pages", "verify preview");
      await checkLayout(page, `${vp} verify result`);
      await shot(page, "17-verify-result", vp);
    });

    test("signer screens", async ({ page, context }, testInfo) => {
      test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
      await context.grantPermissions(["geolocation"]);
      await context.setGeolocation({ latitude: 52.37, longitude: 4.89, accuracy: 25 });
      // The signing page has fixed bars: the shots show the viewport, as a signer sees it.
      const check = async (name) => { await checkLayout(page, `${vp} ${name}`); await shot(page, name, vp, false); };
      await page.goto(signPage(tokens.sign));
      await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
      await check("20-sign-code");
      await page.getByLabel("Access code").fill(tokens.accessCode);
      await page.getByRole("button", { name: "Continue" }).click();
      await page.getByRole("button", { name: "Share my location" }).click();
      await expect(page.getByRole("heading", { name: "Electronic records and signatures" })).toBeVisible();
      await check("21-sign-consent");
      await page.getByLabel("I agree to use electronic records and signatures.").check();
      await page.getByRole("button", { name: "Continue" }).click();
      await expectPainted(page, ".os-sign__pages", "signer pages");
      await check("22-sign-document");
      await documentRules(page, vp, "signer-doc");
      await page.getByRole("textbox", { name: /Job title/ }).fill("Engineer");
      await page.getByRole("textbox", { name: /Job title/ }).blur();
      await page.getByRole("button", { name: /Signature, required/ }).click();
      const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
      await expect(dlg).toBeVisible();
      await checkLayout(page, `${vp} adopt`);
      await page.screenshot({ path: path.join(SHOTS, `visual-${vp}-23-sign-adopt.png`), animations: "disabled" });
      await dlg.getByTestId("adopt-confirm").click();
      await expect(dlg).toBeHidden();
      await page.getByRole("button", { name: "Finish" }).click();
      await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
      await expectPainted(page, ".os-review__pages", "review pages");
      await check("24-sign-review");
      await page.getByTestId("review-finish").click();
      await expect(page.getByTestId("sign-done")).toBeVisible();
      await check("25-sign-done");
    });
  });
}

// Menus open in the top layer, inside the viewport (UX-02): a row menu is never clipped
// by its table's scroll box or its card, and the Start menu never runs off a phone.
/// Every item of the open menu is inside the viewport and is what the page shows at
/// its centre (nothing clips or covers it).
async function menuInView(page, what) {
  const menu = page.locator('[role="menu"]:visible').last();
  await expect(menu, `${what}: a menu is open`).toBeVisible();
  const bad = await menu.evaluate((m) => {
    const out = [];
    const vw = document.documentElement.clientWidth; const vh = document.documentElement.clientHeight;
    for (const it of m.querySelectorAll('[role="menuitem"]')) {
      // Scroll the menu itself only (a long menu scrolls inside), never the page or the
      // table around it: a menu clipped by its table is what this catches.
      if (m.scrollHeight > m.clientHeight) m.scrollTop = it.offsetTop - m.clientHeight / 2;
      const r = it.getBoundingClientRect();
      const name = it.textContent.trim();
      if (r.left < 0 || r.top < 0 || r.right > vw || r.bottom > vh) { out.push(`${name}: outside the viewport (${Math.round(r.left)},${Math.round(r.top)})-(${Math.round(r.right)},${Math.round(r.bottom)})`); continue; }
      const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      if (!at || !it.contains(at)) out.push(`${name}: covered or clipped (${at?.className || at?.tagName})`);
    }
    return out;
  });
  expect(bad, what).toEqual([]);
}

for (const [vp, size] of [["1440", { width: 1440, height: 900 }], ["1366", { width: 1366, height: 768 }], ["390", { width: 390, height: 844 }]]) {
  test.describe(`menus at ${vp}`, () => {
    test.use({ viewport: size });
    test("row menus, the Start menu and the account menu stay inside the viewport", async ({ page }, testInfo) => {
      test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
      await signIn(page, "agreements");
      await expect(page.locator(".os-row__sub").first()).not.toBeEmpty();
      const rowMenus = page.getByRole("button", { name: /^Actions for / });
      await rowMenus.last().click();
      await menuInView(page, `${vp} agreements: last row's menu`);
      await page.keyboard.press("Escape");
      await rowMenus.first().click();
      await menuInView(page, `${vp} agreements: first row's menu`);
      await page.keyboard.press("Escape");
      await page.locator("#start-btn").click();
      await menuInView(page, `${vp} Start menu`);
      await page.keyboard.press("Escape");
      await page.locator("#account-btn").click();
      await menuInView(page, `${vp} account menu`);
      await page.keyboard.press("Escape");
      await page.goto(app("#/templates"));
      const tplMenus = page.getByRole("button", { name: /^Actions for / });
      await tplMenus.last().click();
      await menuInView(page, `${vp} templates: last row's menu`);
    });
  });
}

// Status badges (UX-02): Declined alone takes the danger colour; Voided is neutral with
// a ban icon; Expired is amber; neutral badges keep an outline in dark.
for (const scheme of ["light", "dark"]) {
  test.describe(`badges (${scheme})`, () => {
    test.use({ colorScheme: scheme });
    test("Declined, Voided and Expired read as three different states", async ({ page }, testInfo) => {
      test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
      await page.addInitScript((th) => localStorage.setItem("openseal.theme", th), scheme);
      await signIn(page, "agreements");
      await expect(page.locator(".os-badge--voided").first()).toBeVisible();
      const look = (sel) => page.locator(sel).first().evaluate((el) => {
        const cs = getComputedStyle(el);
        const probe = document.createElement("span");
        document.body.append(probe);
        const paint = (v) => { probe.style.color = `var(${v})`; return getComputedStyle(probe).color; };
        const out = { color: cs.color, bg: cs.backgroundColor, shadow: cs.boxShadow, danger: paint("--os-danger"), text: paint("--os-text"), warning: paint("--os-warning"), icon: el.querySelector("svg path, svg circle, svg line") ? el.querySelector("svg").outerHTML.length : 0 };
        probe.remove();
        return out;
      });
      const declined = await look(".os-badge--declined");
      const voided = await look(".os-badge--voided");
      expect(declined.color, "Declined is in the danger colour").toBe(declined.danger);
      expect(voided.color, "Voided is neutral, not the danger colour").toBe(voided.text);
      expect(voided.bg).not.toBe(declined.bg);
      await expect(page.locator(".os-badge--voided").first().locator("svg")).toHaveCount(1);
      // Neutral badges keep an edge in dark, where the grey pill all but disappeared.
      if (scheme === "dark") expect(voided.shadow, "neutral badge outline in dark").not.toBe("none");
      const expired = page.locator(".os-badge--expired");
      if (await expired.count()) expect((await look(".os-badge--expired")).color).toBe(declined.warning);
    });
  });
}

// The UI font and the root size (UX-02): the bundled Inter draws the app and the signing
// page, and the root size is the same in every window.
test("the bundled UI font draws the app and the signing page, at one root size", async ({ page }, testInfo) => {
  test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
  const sizes = [];
  for (const width of [1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(app("#/signin"));
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    const r = await page.evaluate(async () => {
      await document.fonts.ready;
      return { root: getComputedStyle(document.documentElement).fontSize, loaded: document.fonts.check('14px "OpenSeal Inter"', "Agreement"), family: getComputedStyle(document.body).fontFamily };
    });
    expect(r.family.startsWith('"OpenSeal Inter"'), `body font at ${width}: ${r.family}`).toBe(true);
    expect(r.loaded, `Inter loaded at ${width}`).toBe(true);
    sizes.push(r.root);
  }
  expect(new Set(sizes).size, `root size by window: ${sizes.join(", ")}`).toBe(1);
  await page.goto(signPage(tokens.sign));
  await expect(page.getByRole("heading", { name: "Enter your access code" })).toBeVisible();
  expect(await page.evaluate(async () => { await document.fonts.ready; return document.fonts.check('16px "OpenSeal Inter"', "Sign"); })).toBe(true);
});

// Small component defects (UX-02).
test.describe("components at 390", () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test("the envelope's details stack in one column on a phone", async ({ page }, testInfo) => {
    test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
    await signIn(page, "agreements");
    await page.getByRole("link", { name: "Mutual NDA — Acme and Globex" }).click();
    const meta = page.locator(".os-meta").first();
    await expect(meta).toBeVisible();
    const cols = await meta.evaluate((dl) => getComputedStyle(dl).gridTemplateColumns.split(" ").length);
    expect(cols, "one column of label, then value").toBe(1);
  });
});

test("row checkboxes have a 44 px target (SC 2.5.8 and the touch size)", async ({ page }, testInfo) => {
  test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "agreements");
  const box = page.locator("tbody .os-checkbox").first();
  await expect(box).toBeVisible();
  const r = await box.evaluate((el) => {
    const b = el.getBoundingClientRect();
    const cx = b.left + b.width / 2; const cy = b.top + b.height / 2;
    const hits = [[-19, 0], [19, 0], [0, -19], [0, 19]].map(([dx, dy]) => document.elementFromPoint(cx + dx, cy + dy) === el);
    return { w: b.width, h: b.height, hits };
  });
  expect(Math.min(r.w, r.h), "target size").toBeGreaterThanOrEqual(44);
  expect(r.hits, "the box answers 19 px from its centre").toEqual([true, true, true, true]);
});

test("openPanel can refuse dismissal, and view toasts clear on navigation", async ({ page }, testInfo) => {
  test.skip(REAL || testInfo.project.name !== "chromium", "mock data, one browser");
  await signIn(page, "agreements");
  // A one-time secret: no close button, Escape does nothing, only the action closes it.
  await page.evaluate(() => import("/ui/index.js").then((ui) => {
    window.__panel = ui.openPanel({ id: "secret", title: "Secret", dismissible: false, build: (b) => b.append(document.createTextNode("shown once")), actions: [{ label: "I have copied it", variant: "primary", value: "done" }] });
  }));
  const sheet = page.getByTestId("sheet-secret");
  await expect(sheet).toBeVisible();
  await expect(sheet.getByRole("button", { name: "Close" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(sheet).toBeVisible();
  await page.evaluate(() => import("/ui/index.js").then((ui) => ui.closePanel()));
  await expect(sheet).toBeVisible();
  await sheet.getByRole("button", { name: "I have copied it" }).click();
  await expect(sheet).toHaveCount(0);
  expect(await page.evaluate(() => window.__panel)).toBe("done");
  // Toasts: a view-scoped one goes when the view does; a global one stays.
  await page.evaluate(() => import("/ui/index.js").then((ui) => { ui.toast("about this list", "info", { scope: "view" }); ui.toast("saved everywhere", "success"); ui.clearViewToasts(); }));
  await expect(page.locator(".os-toast", { hasText: "about this list" })).toHaveCount(0);
  await expect(page.locator(".os-toast", { hasText: "saved everywhere" })).toBeVisible();
});
