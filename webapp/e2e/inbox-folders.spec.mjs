// UXW-42, the exit test of UXW-01/02/03/30 against the Compose deployment: the calls
// api.js makes for the Inbox, folders, the Deleted views, the server filters and the
// certificate of an envelope that ended without completing, answered by the real
// server; and the Inbox envelope signed in the browser through the member's own link.
// Skipped in mock mode (the mock's shapes are checked by tests/contract.test.mjs).
import { test, expect } from "@playwright/test";
import { signIn, creds, REAL } from "./helpers.mjs";
import { makePdf } from "../mockpdf.js";

test.skip(!REAL, "runs against a real server only (OPENSEAL_E2E_BASE_URL)");

/// Run `fn(api, arg)` in the signed-in app page with api.js's client (the page's CSP
/// allows no eval, so the client is put on `window` first and `fn` reads it).
async function inApp(page, fn, arg) {
  await page.evaluate(async () => {
    const { createClient } = await import(new URL("api.js", location.href).href);
    window.__uxw42 = createClient({ store: sessionStorage });
  });
  return page.evaluate(fn, arg);
}

const pdf64 = (title) => Buffer.from(makePdf([{ title }])).toString("base64");

test("Inbox, folders, Deleted, server filters and the ended certificate on the server (UXW-01/02/03/30)", async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  await signIn(page, "home");
  const stamp = `${Date.now()}-${testInfo.project.name}`;
  const arg = { stamp, me: creds.email, mine: pdf64(`Inbox ${stamp}`), other: pdf64(`Voided ${stamp}`) };

  const out = await inApp(page, async ({ stamp, me, mine, other }) => {
    const api = window.__uxw42;
    const r = {};
    const field = { recipient: "a", document: 0, type: "signature", page: 1, x: "72", y: "600", width: "160", height: "44" };
    // UXW-01: an envelope sent to the signed-in member waits in their Inbox.
    const inbox = await api.createEnvelope({
      subject: `UXW-42 inbox ${stamp}`, status: "sent",
      documents: [{ name: "inbox.pdf", content_base64: mine }],
      recipients: [{ ref: "a", type: "signer", name: "E2E Admin", email: me, routing_order: 1 }],
      fields: [field],
    });
    const waiting = (await api.inbox({ limit: 100 })).items.find((x) => x.id === inbox.id);
    r.inInbox = !!waiting;
    r.myRecipient = !!waiting && inbox.recipients.some((x) => x.id === waiting.my_recipient_id);
    r.signUrl = (await api.signLink(inbox.id)).url;

    // UXW-03: the recipient filter and the date-field range find it, and only it.
    const other_email = `uxw42-${stamp}@example.com`;
    const ended = await api.createEnvelope({
      subject: `UXW-42 voided ${stamp}`, status: "sent",
      documents: [{ name: "voided.pdf", content_base64: other }],
      recipients: [{ ref: "a", type: "signer", name: "Vic Voided", email: other_email, routing_order: 1 }],
      fields: [field],
    });
    r.byRecipient = (await api.listEnvelopes({ recipient: `uxw42-${stamp}`, limit: 100 })).items.map((x) => x.id);
    const sinceHour = new Date(Date.now() - 3600_000);
    r.bySent = (await api.listEnvelopes({ recipient: `uxw42-${stamp}`, date_field: "sent_at", from: sinceHour, limit: 100 })).items.length;
    r.bySentLater = (await api.listEnvelopes({ recipient: `uxw42-${stamp}`, date_field: "sent_at", from: new Date(Date.now() + 3600_000), limit: 100 })).items.length;
    r.notInboxOther = !(await api.inbox({ limit: 100 })).items.some((x) => x.id === ended.id);

    // UXW-02: a folder of the member's own; Move in and out.
    const f = await api.createFolder(`UXW-42 ${stamp}`);
    r.moved = (await api.moveEnvelopes(f.id, [inbox.id])).moved;
    r.inFolder = (await api.listEnvelopes({ folder: f.id, limit: 100 })).items.map((x) => x.id);
    r.count = (await api.listFolders()).items.find((x) => x.id === f.id)?.count;
    await api.renameFolder(f.id, `UXW-42 renamed ${stamp}`);
    r.renamed = (await api.listFolders()).items.find((x) => x.id === f.id)?.name;
    await api.moveEnvelopes(null, [inbox.id]);
    r.afterUnfile = (await api.listEnvelopes({ folder: f.id, limit: 100 })).items.length;
    await api.deleteFolder(f.id);
    r.folderGone = !(await api.listFolders()).items.some((x) => x.id === f.id);

    // UXW-30: a voided envelope's certificate (made by the worker; 409 until it is).
    await api.voidEnvelope(ended.id, "UXW-42 probe");
    r.ended = ended.id;

    // UXW-02: a template deleted, listed in Deleted, restored.
    const tp = await api.templates.create({ name: `UXW-42 ${stamp}`, roles: [{ name: "Client", type: "signer", routing_order: 1 }] });
    await api.templates.remove(tp.id, (await api.templates.get(tp.id)).etag);
    r.tplDeleted = (await api.templates.listDeleted()).items.some((x) => x.id === tp.id);
    r.tplHidden = !(await api.templates.list()).items.some((x) => x.id === tp.id);
    await api.templates.restore(tp.id);
    r.tplBack = (await api.templates.list()).items.some((x) => x.id === tp.id);
    await api.templates.remove(tp.id, (await api.templates.get(tp.id)).etag);
    r.inbox = inbox.id;
    return r;
  }, arg);

  expect(out).toMatchObject({
    inInbox: true, myRecipient: true,
    byRecipient: [out.ended], bySent: 1, bySentLater: 0, notInboxOther: true,
    moved: 1, inFolder: [out.inbox], count: 1, renamed: `UXW-42 renamed ${stamp}`, afterUnfile: 0, folderGone: true,
    tplDeleted: true, tplHidden: true, tplBack: true,
  });
  expect(typeof out.signUrl).toBe("string");

  // UXW-30: the ended envelope's certificate, once the worker has made it: a PDF.
  let cert = null;
  const deadline = Date.now() + 90_000;
  while (!cert && Date.now() < deadline) {
    cert = await inApp(page, async (id) => {
      try {
        const blob = await window.__uxw42.certificate(id);
        const head = new TextDecoder().decode(new Uint8Array(await blob.slice(0, 5).arrayBuffer()));
        return { head, size: blob.size };
      } catch (e) {
        if (e.status === 409) return null;
        return { error: e.code };
      }
    }, out.ended);
    if (!cert) await page.waitForTimeout(2000);
  }
  expect(cert).toMatchObject({ head: "%PDF-" });

  // UXW-02: the voided envelope deleted is in the Deleted view only, still readable.
  const deleted = await inApp(page, async (id) => {
    const api = window.__uxw42;
    await api.deleteEnvelope(id, (await api.getEnvelope(id)).etag);
    return {
      inDeleted: (await api.listEnvelopes({ deleted: true, limit: 100 })).items.some((x) => x.id === id),
      inList: (await api.listEnvelopes({ limit: 100 })).items.some((x) => x.id === id),
      readable: (await api.getEnvelope(id)).envelope.id === id,
    };
  }, out.ended);
  expect(deleted).toEqual({ inDeleted: true, inList: false, readable: true });

  // UXW-01: the member signs the Inbox envelope through their own link, in the app's
  // session; afterwards it no longer waits for them.
  await page.goto(new URL(out.signUrl, page.url()).href);
  const consent = page.getByRole("heading", { name: "Electronic records and signatures" });
  const progress = page.locator("#guide-progress");
  await expect(consent.or(progress)).toBeVisible();
  if (await consent.isVisible()) {
    await page.getByLabel("I agree to use electronic records and signatures.").check();
    await page.getByRole("button", { name: "Continue" }).click();
  }
  await expect(progress).toHaveText("0 of 1 required");
  await page.getByRole("button", { name: /Signature, required/ }).click();
  const dlg = page.getByRole("dialog", { name: "Adopt your signature" });
  await dlg.getByTestId("adopt-confirm").click();
  await expect(dlg).toBeHidden();
  await expect(progress).toHaveText("1 of 1 required");
  await page.getByRole("button", { name: "Finish" }).click();
  await expect(page.getByRole("heading", { name: "Review and finish" })).toBeVisible();
  await page.getByTestId("review-finish").click();
  await expect(page.getByTestId("sign-done")).toContainText("Everyone has signed");

  await signIn(page, "home");
  const after = await inApp(page, async (id) => !(await window.__uxw42.inbox({ limit: 100 })).items.some((x) => x.id === id), out.inbox);
  expect(after).toBe(true);
});
