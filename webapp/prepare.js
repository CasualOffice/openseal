// Prepare (WEB-01; docs/47 §Screens "Prepare", document-first): upload PDFs, add
// recipients, place fields on the pages, save a draft, send.
//
// SignNow's speed: the editor opens on the upload, fields go on with one drag (or
// one key), recipients are coloured, and nothing asks a question before it has to.
// Every verb is a command (`field.*`, `envelope.*`, `edit.*`, `recipient.*`), so the
// keyboard table in keys.js and the buttons run the same code. Field placement is
// keyboard-operable: a palette button places its field on the page in view, arrows
// move it, Alt+arrows size it (WCAG 2.1.1, 2.5.7).
//
// Geometry is ADR-019's: points in the page's displayed space, top-left origin
// (geometry.js). The server is the source of truth: after each save the editor
// reloads the envelope and rebuilds its state from it.
//
// Template mode (WEB-02, `#/templates/new`, `opts.template`): the same editor with
// roles ("Client", "Witness") where an envelope has people: no emails or access codes,
// a template name instead of a subject, "Save template" instead of Send. Saving is
// `POST /api/v1/templates` (name, email subject and message, roles), then the
// documents and fields on docs/40's slice-3 template endpoints (api-extra.js); a
// server without those keeps the roles and the editor says so.

import { h, clear, reducedMotion } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix, run } from "./commands.js";
import { button, busy, emptyState, toast, toastError, openDialog, confirmDialog, selectField } from "./ui/index.js";
import { openPdf, fitScale } from "./pdfview.js";
import { FIELD_TYPES, DEFAULT_SIZE, clampRect, nudge, resize, placeAt, freeSpot, snap, toWire, fromWire, takesInput } from "./geometry.js";
import { errorMessage } from "./api.js";
import { templateDocsUnsupported } from "./api-extra.js";
import { rolesFrom } from "./templatemodel.js";
import { takeFiles } from "./handoff.js";

const FIELD_ICON = { signature: "signature", initials: "pen-line", date_signed: "calendar", name: "user", email: "at-sign", text: "text-cursor-input", checkbox: "square-check" };
const MAX_UPLOAD = 50 * 1024 * 1024; // docs/21: 50 MiB decoded
const COLOURS = 6;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

let keySeq = 0;
const newKey = (p) => `${p}${++keySeq}`;

export async function mount(view, ctx, [rawId] = [], _params = null, opts = {}) {
  const TPL = !!opts.template;
  const S = {
    id: rawId && !TPL ? decodeURIComponent(rawId) : null,
    subject: "",
    message: "",
    emailSubject: "",
    captureLocation: false,
    reminderFirst: null,
    reminderEvery: null,
    expiresDays: null,
    serverOptions: "",
    routing: "sequential",
    docs: [],
    recipients: [],
    fields: [],
    active: null,
    selected: null,
    clipboard: null,
    dirty: false,
    undo: [],
    redo: [],
  };
  ctx.contexts = ["editor", "global"];
  const pdfs = new Map(); // doc key → pdf.js handle
  let scale = 1;

  // ---- Layout ----------------------------------------------------------------------
  // A stepped flow (WEB-02 redesign, DocuSign's send flow): 1 documents, 2 recipients
  // (roles in a template), 3 fields, 4 review and send. Every step's panels stay in the
  // page and are shown one step at a time, so state and commands never depend on which
  // step is open; the step bar and the Back and Next buttons move between them.
  const STEPS = ["documents", "recipients", "fields", "review"];
  let step = "documents";
  const subject = h("input", { id: "env-subject", class: "os-input", placeholder: t(TPL ? "template.name-placeholder" : "prepare.subject-placeholder"), maxLength: 255 });
  subject.addEventListener("input", () => { S.subject = subject.value; S.dirty = true; title.textContent = S.subject.trim() || t(TPL ? "template.new-title" : "prepare.title"); });
  const saveBtn = TPL
    ? button(t("template.save"), { icon: "save", variant: "primary", command: "template.save", onClick: () => run("template.save") })
    : button(t("prepare.save"), { icon: "save", command: "envelope.save", onClick: () => run("envelope.save") });
  const sendBtn = TPL ? null : button(t("prepare.send"), { icon: "send", variant: "primary", command: "envelope.send", onClick: () => run("envelope.send") });
  const title = h("h1", { class: "os-prepare__title", text: t(TPL ? "template.new-title" : "prepare.title") });
  const stepper = h("ol", { class: "os-stepper", attrs: { "aria-label": t("wizard.steps") } });
  const stepBtns = new Map();
  STEPS.forEach((s, i) => {
    const b = h("button", { type: "button", class: "os-stepper__btn", attrs: { "data-step": s } },
      h("span", { class: "os-stepper__n", text: String(i + 1) }), h("span", { class: "os-stepper__label", text: t(stepLabel(s)) }));
    b.addEventListener("click", () => go(s));
    stepBtns.set(s, b);
    stepper.append(h("li", {}, b));
  });
  const bar = h("div", { class: "os-prepare__bar" },
    h("a", { href: TPL ? "#/templates" : "#/agreements", class: "os-btn os-btn--ghost os-btn--md os-btn--icon", attrs: { "aria-label": t(TPL ? "template.back" : "prepare.back"), title: t(TPL ? "template.back" : "prepare.back") } }, icon("chevron-left")),
    h("div", { class: "os-prepare__head" },
      TPL ? h("span", { class: "os-badge os-badge--template" }, icon("layout-template", { size: 16 }), h("span", { text: t("template.badge") })) : null,
      title),
    stepper,
    h("span", { class: "os-spacer" }),
    h("span", { class: "os-prepare__status os-muted", attrs: { "aria-live": "polite", id: "save-status" } }),
    TPL ? null : saveBtn);

  const docsPanel = h("section", { class: "os-panel os-panel--docs", attrs: { "aria-labelledby": "docs-h" } });
  const rcptPanel = h("section", { class: "os-panel os-panel--rcpt", attrs: { "aria-labelledby": "rcpt-h" } });
  const palettePanel = h("section", { class: "os-panel", attrs: { "aria-labelledby": "pal-h" } });
  const thumbs = h("nav", { class: "os-thumbs", attrs: { "aria-label": t("prepare.thumbs") } });
  const left = h("aside", { class: "os-prepare__left", attrs: { "aria-label": t("prepare.setup") } }, palettePanel, thumbs);
  const stage = h("div", { class: "os-stage", attrs: { "aria-label": t("prepare.pages"), role: "region", tabindex: "0", id: "stage" } });
  const zoomLabel = h("span", { class: "os-zoom__label", attrs: { "aria-live": "polite" } });
  let zoom = 1;
  const setZoom = (z) => { zoom = Math.max(0.5, Math.min(2.5, Math.round(z * 100) / 100)); renderStage(); };
  const zoomBar = h("div", { class: "os-zoom", attrs: { role: "toolbar", "aria-label": t("prepare.zoom") } },
    button(t("prepare.zoom-out"), { icon: "zoom-out", size: "sm", variant: "ghost", iconOnly: true, onClick: () => setZoom(zoom / 1.25) }),
    zoomLabel,
    button(t("prepare.zoom-in"), { icon: "zoom-in", size: "sm", variant: "ghost", iconOnly: true, onClick: () => setZoom(zoom * 1.25) }),
    button(t("prepare.zoom-fit"), { size: "sm", variant: "ghost", onClick: () => setZoom(1) }));
  const centre = h("div", { class: "os-prepare__centre" }, zoomBar, stage);
  const props = h("aside", { class: "os-prepare__right", attrs: { "aria-label": t("prepare.properties") } });
  const reviewPanel = h("section", { class: "os-panel os-panel--review", attrs: { "aria-labelledby": "review-h" } });
  const live = h("div", { class: "os-sr-only", attrs: { "aria-live": "polite" } });
  const fileInput = h("input", { type: "file", accept: "application/pdf,.pdf", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "pdf-input" } });
  fileInput.addEventListener("change", () => { addFiles([...fileInput.files]); fileInput.value = ""; });
  const panes = {
    documents: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, docsPanel),
    recipients: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, rcptPanel),
    fields: h("div", { class: "os-prepare__body" }, left, centre, props),
    review: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, reviewPanel),
  };
  const backBtn = button(t("action.back"), { icon: "chevron-left", onClick: () => go(STEPS[STEPS.indexOf(step) - 1]) });
  const nextBtn = button(t("wizard.next"), { icon: "arrow-right", variant: "primary", attrs: { "data-testid": "wizard-next" }, onClick: () => go(STEPS[STEPS.indexOf(step) + 1]) });
  const where = h("span", { class: "os-wizard__where os-muted" });
  const foot = h("div", { class: "os-wizard__foot" }, backBtn, where, h("span", { class: "os-spacer" }), TPL ? saveBtn : null, sendBtn, nextBtn);
  view.append(h("div", { class: "os-prepare" }, bar, h("div", { class: "os-wizard" }, ...Object.values(panes)), foot, live, fileInput));

  function stepLabel(s) {
    return s === "recipients" && TPL ? "wizard.step.roles" : `wizard.step.${s}`;
  }
  /// Open step `s`: show its pane, mark the step bar, set the footer's buttons.
  async function go(s) {
    if (!STEPS.includes(s)) return;
    step = s;
    const i = STEPS.indexOf(s);
    for (const [k, pane] of Object.entries(panes)) pane.hidden = k !== s;
    for (const [k, b] of stepBtns) {
      if (k === s) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
      b.classList.toggle("is-done", STEPS.indexOf(k) < i);
    }
    backBtn.hidden = i === 0;
    nextBtn.hidden = i === STEPS.length - 1;
    if (sendBtn) sendBtn.hidden = s !== "review";
    if (TPL) saveBtn.hidden = s !== "review";
    where.textContent = t("wizard.where", { n: i + 1, total: STEPS.length, label: t(stepLabel(s)) });
    if (s === "fields") await renderStage();
    if (s === "review") renderReview();
  }

  const say = (msg) => { live.textContent = ""; setTimeout(() => { live.textContent = msg; }, 30); };

  // ---- History -----------------------------------------------------------------------
  const snapshot = () => JSON.stringify({ recipients: S.recipients, fields: S.fields, routing: S.routing });
  function change(fn) {
    S.undo.push(snapshot());
    if (S.undo.length > 200) S.undo.shift();
    S.redo = [];
    fn();
    S.dirty = true;
    renderAll();
  }
  function restore(snap) {
    const v = JSON.parse(snap);
    S.recipients = v.recipients;
    S.fields = v.fields;
    S.routing = v.routing;
    if (S.selected && !S.fields.some((f) => f.key === S.selected)) S.selected = null;
    if (!S.recipients.some((r) => r.key === S.active)) S.active = S.recipients[0]?.key || null;
    S.dirty = true;
    renderAll();
  }

  // ---- Recipients ----------------------------------------------------------------------
  const colourOf = (rk) => (S.recipients.findIndex((r) => r.key === rk) % COLOURS) + 1;
  const recipient = (rk) => S.recipients.find((r) => r.key === rk);
  const signers = () => S.recipients.filter((r) => r.type === "signer");
  const displayName = (r, i) => r?.name?.trim() || t(TPL ? "template.role-n" : "prepare.recipient-n", { n: i + 1 });
  function orderOf(r) {
    const sg = signers();
    if (r.type !== "signer") return S.routing === "parallel" ? 2 : sg.length + 1;
    return S.routing === "parallel" ? 1 : sg.indexOf(r) + 1;
  }
  function addRecipient(focus = true) {
    const r = { key: newKey("r"), id: null, name: "", email: "", type: "signer", accessCode: "" };
    change(() => { S.recipients.push(r); S.active = r.key; });
    if (focus) setTimeout(() => rcptPanel.querySelector(`[data-rkey="${r.key}"] input`)?.focus(), 0);
    return r;
  }

  function renderRecipients() {
    clear(rcptPanel);
    const addLabel = t(TPL ? "template.add-role" : "prepare.add-recipient");
    rcptPanel.append(h("div", { class: "os-step-head" },
      h("div", {},
        h("h2", { id: "rcpt-h", class: "os-step-head__title", text: t(TPL ? "template.roles" : "prepare.recipients") }),
        h("p", { class: "os-muted", text: t(TPL ? "wizard.roles-lede" : "wizard.recipients-lede") })),
      S.recipients.length ? button(addLabel, { icon: "user-plus", command: "recipient.add", onClick: () => addRecipient() }) : null));
    if (!S.recipients.length) {
      rcptPanel.append(TPL
        ? emptyState({ illus: "recipients", title: t("empty.roles.title"), text: t("empty.roles.text"), action: button(addLabel, { icon: "user-plus", variant: "primary", onClick: () => addRecipient() }), testId: "empty-roles" })
        : emptyState({ illus: "recipients", title: t("empty.recipients.title"), text: t("empty.prepare-recipients.text"), action: button(addLabel, { icon: "user-plus", variant: "primary", onClick: () => addRecipient() }), testId: "empty-recipients" }));
      return;
    }
    // DocuSign's "Set signing order": on, signers go one after another; off, all at once.
    const orderBox = h("input", { id: "routing-order", type: "checkbox", class: "os-switch__input", checked: S.routing === "sequential", attrs: { role: "switch" } });
    orderBox.addEventListener("change", () => change(() => { S.routing = orderBox.checked ? "sequential" : "parallel"; }));
    rcptPanel.append(h("div", { class: "os-switchrow" },
      h("label", { class: "os-switch", attrs: { for: "routing-order" } }, orderBox, h("span", { class: "os-switch__track", attrs: { "aria-hidden": "true" } }), h("span", { text: t("prepare.set-order") })),
      h("span", { class: "os-muted os-small", text: t(S.routing === "sequential" ? "prepare.routing-sequential-help" : "prepare.routing-parallel-help") })));
    const list = h("ol", { class: "os-rcpt-list" });
    S.recipients.forEach((r, i) => {
      const c = colourOf(r.key);
      const nameId = `rn-${r.key}`;
      const mailId = `re-${r.key}`;
      const typeId = `rt-${r.key}`;
      const name = h("input", { id: nameId, class: "os-input os-input--sm", value: r.name, autocomplete: "off", placeholder: t(TPL ? "template.role-placeholder" : "prepare.name"), maxLength: 255, attrs: { "data-testid": TPL ? "role-name" : "recipient-name" } });
      const email = h("input", { id: mailId, class: "os-input os-input--sm", type: "email", value: r.email, autocomplete: "off", placeholder: t("prepare.email"), attrs: { "data-testid": "recipient-email" } });
      const typeField = selectField(t("prepare.role-for", { name: displayName(r, i) }), [["signer", t("rtype.signer")], ["cc", t("rtype.cc")]], { id: typeId, value: r.type, labelHidden: true, size: "sm", attrs: { "data-testid": "recipient-type" } });
      const type = typeField.select;
      const commit = (k, v) => {
        if (r[k] === v) return;
        S.undo.push(snapshot()); S.redo = [];
        r[k] = v; S.dirty = true;
        renderPalette(); renderFieldsOnly(); renderProps();
        if (k === "type") renderRecipients();
      };
      // Typed values are kept as they are typed, so a re-render (a role change, a field
      // placed) never loses them; the label refresh waits for the change event.
      name.addEventListener("input", () => { r.name = name.value.trim(); S.dirty = true; });
      email.addEventListener("input", () => { r.email = email.value.trim(); S.dirty = true; });
      name.addEventListener("change", () => { renderPalette(); renderFieldsOnly(); renderProps(); });
      email.addEventListener("change", () => { renderPalette(); });
      type.addEventListener("change", () => commit("type", type.value));
      const up = button(t("prepare.move-up"), { icon: "chevron-left", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveRecipient(i, -1) });
      up.querySelector("svg").classList.add("os-rot90");
      up.disabled = i === 0;
      const del = button(t("prepare.remove-recipient", { name: displayName(r, i) }), { icon: "trash-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => removeRecipient(r) });
      // The access code is set when the recipient is created; the API has no way to
      // change it afterwards (RecipientPatch), so a saved recipient shows it read-only.
      const access = h("input", { id: `ra-${r.key}`, class: "os-input os-input--sm", value: r.id ? "" : r.accessCode, disabled: !!r.id, autocomplete: "off", inputMode: "numeric", placeholder: r.id ? t(r.hasAccessCode ? "prepare.access-code-set" : "prepare.access-code-none") : t("prepare.access-code"), maxLength: 64, attrs: { "aria-label": t("prepare.access-code-for", { name: displayName(r, i) }), "data-testid": "recipient-access-code" } });
      access.addEventListener("input", () => { r.accessCode = access.value.trim(); S.dirty = true; });
      const li = h("li", { class: `os-rcpt os-r${c}${S.active === r.key ? " is-active" : ""}`, attrs: { "data-rkey": r.key } },
        h("div", { class: "os-rcpt__head" },
          h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
          h("span", { class: "os-order", attrs: { title: t("prepare.routing-order") }, text: String(orderOf(r)) }),
          typeField.el,
          h("span", { class: "os-spacer" }), up, del),
        h("label", { class: "os-sr-only", attrs: { for: nameId }, text: t(TPL ? "template.role-name-of" : "prepare.name-of", { n: i + 1 }) }), name,
        TPL ? null : [h("label", { class: "os-sr-only", attrs: { for: mailId }, text: t("prepare.email-of", { n: i + 1 }) }), email],
        r.type === "signer" && !TPL ? access : null);
      li.addEventListener("focusin", () => { if (S.active !== r.key) { S.active = r.key; markActive(); renderPalette(); } });
      list.append(li);
    });
    rcptPanel.append(list);
  }
  function markActive() {
    for (const li of rcptPanel.querySelectorAll(".os-rcpt")) li.classList.toggle("is-active", li.dataset.rkey === S.active);
  }
  function moveRecipient(i, d) {
    const j = i + d;
    if (j < 0 || j >= S.recipients.length) return;
    change(() => { const [r] = S.recipients.splice(i, 1); S.recipients.splice(j, 0, r); });
  }
  async function removeRecipient(r) {
    const n = S.fields.filter((f) => f.recipientKey === r.key).length;
    if (n && !(await confirmDialog(t("prepare.remove-recipient-title"), t("prepare.remove-recipient-text", { n }), { confirm: t("action.remove"), danger: true }))) return;
    change(() => {
      S.recipients = S.recipients.filter((x) => x !== r);
      S.fields = S.fields.filter((f) => f.recipientKey !== r.key);
      if (S.active === r.key) S.active = S.recipients[0]?.key || null;
    });
  }

  // ---- Palette --------------------------------------------------------------------------
  // The buttons are built once and never replaced: a re-render between a button's
  // mousedown and its click (a name committed on blur) would swallow the click.
  const palFor = h("div", { class: "os-palette__for" });
  const palGrid = h("div", { class: "os-palette os-r1" });
  for (const type of FIELD_TYPES) {
    const b = h("button", { type: "button", class: "os-palette__item", draggable: true, attrs: { "data-field-type": type, "data-os-command": `field.add-${type}`, "aria-label": t("prepare.add-field", { type: t(`ftype.${type}`) }) } },
      icon(FIELD_ICON[type], { size: 20 }), h("span", { text: t(`ftype.${type}`) }));
    b.addEventListener("click", () => addFieldInView(type));
    b.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("application/x-openseal-field", type);
      e.dataTransfer.effectAllowed = "copy";
      stage.classList.add("is-dropping");
    });
    b.addEventListener("dragend", () => stage.classList.remove("is-dropping"));
    palGrid.append(b);
  }
  palettePanel.append(
    h("div", { class: "os-panel__head" }, h("h2", { id: "pal-h", class: "os-panel__title", text: t("prepare.fields") })),
    palFor, palGrid, h("p", { class: "os-muted os-small", text: t("prepare.palette-hint") }));

  function renderPalette() {
    const active = recipient(S.active);
    const idx = S.recipients.indexOf(active);
    const focused = document.activeElement?.id === "pal-for";
    clear(palFor);
    if (S.recipients.length > 1) {
      const pf = selectField(t("prepare.placing-for"), S.recipients.map((r, i) => [r.key, `${i + 1}. ${displayName(r, i)}`]), { id: "pal-for", value: S.active, onChange: (v) => { S.active = v; markActive(); renderPalette(); } });
      const sel = pf.select;
      palFor.append(pf.el);
      if (focused) sel.focus();
    } else if (active) {
      palFor.append(h("p", { class: "os-muted os-small", text: t("prepare.placing-for-name", { name: displayName(active, idx) }) }));
    }
    palGrid.className = `os-palette os-r${active ? colourOf(active.key) : 1}`;
  }

  // ---- Documents ---------------------------------------------------------------------------
  /// Step 1: each document as a card with its first page, page count, order and remove.
  /// Saved documents keep their order (the API has no reorder) and stay.
  function renderDocs() {
    clear(docsPanel);
    docsPanel.append(h("div", { class: "os-step-head" },
      h("div", {},
        h("h2", { id: "docs-h", class: "os-step-head__title", text: t("prepare.documents") }),
        h("p", { class: "os-muted", text: t("wizard.documents-lede") })),
      S.docs.length ? button(t("prepare.add-pdf"), { icon: "file-up", command: "document.add", onClick: () => fileInput.click() }) : null));
    if (!S.docs.length) {
      const empty = emptyState({
        illus: "documents", title: t("empty.documents.title"), text: t("empty.documents.text"),
        action: button(t("prepare.add-pdf"), { icon: "file-up", variant: "primary", size: "lg", onClick: () => fileInput.click() }),
        testId: "empty-documents",
      });
      empty.classList.add("os-dropzone--big");
      docsPanel.append(empty);
      return;
    }
    const ul = h("ul", { class: "os-doccards" });
    S.docs.forEach((d, i) => {
      const thumb = h("canvas", { class: "os-doccard__thumb", attrs: { "aria-hidden": "true" } });
      const pdf = pdfs.get(d.key);
      const p1 = d.pages[0] || { width: 612, height: 792 };
      pdf?.render(1, thumb, 140 / p1.width).catch(() => {});
      const up = button(t("prepare.move-doc-up", { name: d.name }), { icon: "chevron-left", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveDoc(i, -1) });
      const down = button(t("prepare.move-doc-down", { name: d.name }), { icon: "chevron-right", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveDoc(i, 1) });
      up.disabled = i === 0 || !!d.id || !!S.docs[i - 1]?.id;
      down.disabled = i === S.docs.length - 1 || !!d.id || !!S.docs[i + 1]?.id;
      ul.append(h("li", { class: "os-doccard", attrs: { "data-testid": "doc-card" } },
        h("div", { class: "os-doccard__frame" }, thumb),
        h("div", { class: "os-doccard__meta" },
          h("strong", { class: "os-doccard__name", text: d.name }),
          h("span", { class: "os-muted os-small", text: (d.pages.length === 1 ? t("prepare.page-one") : t("prepare.pages-long", { n: d.pages.length })) })),
        h("div", { class: "os-doccard__actions" }, up, down,
          d.id ? null : button(t("prepare.remove-doc", { name: d.name }), { icon: "trash-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => removeDoc(d) }))));
    });
    const add = h("li", {}, h("button", { type: "button", class: "os-doccard os-doccard--add", on: { click: () => fileInput.click() } },
      icon("plus", { size: 24 }), h("span", { text: t("prepare.add-pdf") })));
    ul.append(add);
    docsPanel.append(ul);
  }
  function moveDoc(i, dlt) {
    const j = i + dlt;
    if (j < 0 || j >= S.docs.length) return;
    const [d] = S.docs.splice(i, 1);
    S.docs.splice(j, 0, d);
    S.dirty = true;
    renderDocs();
  }
  async function removeDoc(d) {
    const n = S.fields.filter((f) => f.docKey === d.key).length;
    if (n && !(await confirmDialog(t("prepare.remove-doc-title"), t("prepare.remove-doc-text", { n }), { confirm: t("action.remove"), danger: true }))) return;
    change(() => {
      S.docs = S.docs.filter((x) => x !== d);
      S.fields = S.fields.filter((f) => f.docKey !== d.key);
    });
    pdfs.get(d.key)?.destroy();
    pdfs.delete(d.key);
    if (step === "fields") renderStage();
  }

  async function addFiles(files) {
    for (const file of files) {
      if (file.size > MAX_UPLOAD) { toast(t("prepare.too-large", { name: file.name }), "error"); continue; }
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (String.fromCharCode(...bytes.subarray(0, 5)) !== "%PDF-") { toast(t("prepare.not-pdf", { name: file.name }), "error"); continue; }
      try {
        const pdf = await openPdf(bytes.slice());
        const d = { key: newKey("d"), id: null, name: file.name.slice(0, 255), bytes, pages: pdf.pages };
        pdfs.set(d.key, pdf);
        S.docs.push(d);
        S.dirty = true;
        const base = file.name.replace(/\.pdf$/i, "");
        if (!S.subject) { S.subject = (TPL ? base : t("prepare.default-subject", { name: base })).slice(0, 255); subject.value = S.subject; }
        if (TPL && !S.emailSubject) S.emailSubject = t("prepare.default-subject", { name: base }).slice(0, 255);
        say(t("prepare.doc-added", { name: d.name, n: d.pages.length }));
      } catch {
        toast(t("prepare.unreadable", { name: file.name }), "error");
      }
    }
    renderDocs();
    if (step === "fields") await renderStage();
    renderProps();
  }

  // ---- Stage: pages and fields ---------------------------------------------------------
  async function renderStage() {
    clear(stage);
    clear(thumbs);
    zoomLabel.textContent = `${Math.round(zoom * 100)}%`;
    if (!S.docs.length) {
      stage.append(emptyState({
        illus: "documents", title: t("empty.documents.title"), text: t("empty.documents.text"),
        action: button(t("prepare.add-pdf"), { icon: "file-up", variant: "primary", size: "lg", onClick: () => fileInput.click() }),
        testId: "empty-stage",
      }));
      return;
    }
    const width = stage.clientWidth || 800;
    const widest = Math.max(...S.docs.flatMap((d) => d.pages.map((p) => p.width)));
    scale = Math.min(fitScale(widest, width - 48), 1.5) * zoom;
    renderThumbs();
    for (const d of S.docs) {
      const pdf = pdfs.get(d.key);
      d.pages.forEach((p, i) => {
        const canvas = h("canvas", { class: "os-page__canvas", attrs: { "aria-hidden": "true" } });
        const overlay = h("div", { class: "os-page__overlay", attrs: { "data-doc": d.key, "data-page": String(i + 1) } });
        const pageEl = h("div", { class: "os-page is-loading", attrs: { role: "group", "aria-label": t("prepare.page-of", { n: i + 1, total: d.pages.length, name: d.name }) } }, canvas, overlay);
        pageEl.style.width = `${p.width * scale}px`;
        pageEl.style.height = `${p.height * scale}px`;
        overlay.addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("application/x-openseal-field")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } });
        overlay.addEventListener("drop", (e) => {
          const type = e.dataTransfer.getData("application/x-openseal-field");
          if (!type) return;
          e.preventDefault();
          stage.classList.remove("is-dropping");
          const box = overlay.getBoundingClientRect();
          addField(type, d, i + 1, (e.clientX - box.left) / scale, (e.clientY - box.top) / scale);
        });
        overlay.addEventListener("pointerdown", (e) => { if (e.target === overlay) select(null); });
        stage.append(pageEl);
        pdf?.render(i + 1, canvas, scale).then(() => pageEl.classList.remove("is-loading")).catch(() => pageEl.classList.add("is-error"));
      });
    }
    renderFieldsOnly();
  }

  /// The page strip: a small picture of every page; choosing one scrolls the stage to it.
  function renderThumbs() {
    const ol = h("ol", { class: "os-thumbs__list" });
    for (const d of S.docs) {
      const pdf = pdfs.get(d.key);
      d.pages.forEach((p, i) => {
        const c = h("canvas", { attrs: { "aria-hidden": "true" } });
        pdf?.render(i + 1, c, 72 / p.width).catch(() => {});
        const b = h("button", { type: "button", class: "os-thumb", attrs: { "aria-label": t("prepare.page-of", { n: i + 1, total: d.pages.length, name: d.name }) } }, c, h("span", { class: "os-thumb__n", text: String(i + 1) }));
        b.addEventListener("click", () => stage.querySelector(`.os-page__overlay[data-doc="${d.key}"][data-page="${i + 1}"]`)?.parentElement.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" }));
        ol.append(h("li", {}, b));
      });
    }
    thumbs.append(h("h2", { class: "os-panel__title", text: t("prepare.pages") }), ol);
  }

  function overlayFor(f) {
    return stage.querySelector(`.os-page__overlay[data-doc="${f.docKey}"][data-page="${f.page}"]`);
  }
  function fieldLabel(f) {
    const r = recipient(f.recipientKey);
    const i = S.recipients.indexOf(r);
    return t("prepare.field-aria", { type: t(`ftype.${f.type}`), name: displayName(r, i), page: f.page, req: f.required ? t("prepare.required-suffix") : "" });
  }
  function renderFieldsOnly() {
    for (const n of stage.querySelectorAll(".os-field")) n.remove();
    for (const f of S.fields) {
      const ov = overlayFor(f);
      if (!ov) continue;
      const el = h("button", { type: "button", class: `os-field os-r${colourOf(f.recipientKey)}${f.required ? " is-required" : ""}${S.selected === f.key ? " is-selected" : ""}`, attrs: { "data-fkey": f.key, "data-field": f.type, "aria-label": fieldLabel(f), "aria-pressed": String(S.selected === f.key) } },
        icon(FIELD_ICON[f.type], { size: 16 }),
        h("span", { class: "os-field__label", text: f.label || t(`ftype.${f.type}`) }),
        h("span", { class: "os-field__handle", attrs: { "aria-hidden": "true" } }));
      place(el, f);
      el.addEventListener("focus", () => { if (S.selected !== f.key) select(f.key, false); });
      el.addEventListener("pointerdown", (e) => startDrag(e, f, e.target.classList.contains("os-field__handle") ? "resize" : "move"));
      ov.append(el);
    }
  }
  function place(el, f) {
    el.style.left = `${f.x * scale}px`;
    el.style.top = `${f.y * scale}px`;
    el.style.width = `${f.width * scale}px`;
    el.style.height = `${f.height * scale}px`;
  }
  function pageOf(f) {
    const d = S.docs.find((x) => x.key === f.docKey);
    return d?.pages[f.page - 1] || { width: 612, height: 792 };
  }

  function startDrag(e, f, mode) {
    if (e.button !== 0) return;
    e.preventDefault();
    const el = e.currentTarget;
    select(f.key, false);
    el.focus({ preventScroll: true });
    try { el.setPointerCapture(e.pointerId); } catch { /* listeners are on window anyway */ }
    const start = { x: e.clientX, y: e.clientY, r: { x: f.x, y: f.y, width: f.width, height: f.height } };
    const before = snapshot();
    let moved = false;
    el.classList.add("is-dragging");
    const move = (ev) => {
      const dx = (ev.clientX - start.x) / scale;
      const dy = (ev.clientY - start.y) / scale;
      if (!moved && Math.abs(dx) + Math.abs(dy) < 1) return;
      moved = true;
      const pg = pageOf(f);
      const r = mode === "move"
        ? clampRect({ ...start.r, x: snap(start.r.x + dx), y: snap(start.r.y + dy) }, pg)
        : clampRect({ ...start.r, width: snap(start.r.width + dx), height: snap(start.r.height + dy) }, pg);
      Object.assign(f, r);
      place(el, f);
      el.classList.toggle("is-snapped", r.x % 4 === 0 && r.y % 4 === 0);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", up);
      el.classList.remove("is-dragging", "is-snapped");
      if (moved) {
        S.undo.push(before); S.redo = []; S.dirty = true;
        el.classList.add("is-dropped");
        setTimeout(() => el.classList.remove("is-dropped"), 250);
        renderProps();
      }
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", up);
  }

  function select(key, focus = true) {
    S.selected = key;
    for (const n of stage.querySelectorAll(".os-field")) {
      const on = n.dataset.fkey === key;
      n.classList.toggle("is-selected", on);
      n.setAttribute("aria-pressed", String(on));
    }
    if (key && focus) stage.querySelector(`.os-field[data-fkey="${key}"]`)?.focus({ preventScroll: false });
    renderProps();
  }

  function addField(type, doc, page, cx, cy) {
    let r = recipient(S.active);
    if (!r) r = addRecipient(false);
    const pg = doc.pages[page - 1];
    const rect = placeAt(type, cx, cy, pg);
    const f = { key: newKey("f"), id: null, docKey: doc.key, recipientKey: r.key, type, page, ...rect, required: type === "signature" || type === "initials", label: "" };
    change(() => { S.fields.push(f); S.selected = f.key; });
    const el = stage.querySelector(`.os-field[data-fkey="${f.key}"]`);
    if (el) {
      el.classList.add("is-new");
      setTimeout(() => el.classList.remove("is-new"), 250);
      el.focus({ preventScroll: false });
    }
    say(t("prepare.field-added", { label: fieldLabel(f) }));
    return f;
  }

  /// Place a field without a pointer: on the page nearest the middle of the view,
  /// at its centre, stepping down for each field already there.
  function addFieldInView(type) {
    if (!S.docs.length) { toast(t("prepare.add-pdf-first"), "info"); fileInput.click(); return; }
    const pages = [...stage.querySelectorAll(".os-page__overlay")];
    const mid = stage.getBoundingClientRect().top + stage.clientHeight / 2;
    let best = pages[0];
    let bestD = Infinity;
    for (const p of pages) {
      const b = p.getBoundingClientRect();
      const d = b.top <= mid && b.bottom >= mid ? 0 : Math.min(Math.abs(b.top - mid), Math.abs(b.bottom - mid));
      if (d < bestD) { bestD = d; best = p; }
    }
    const doc = S.docs.find((d) => d.key === best.dataset.doc);
    const page = Number(best.dataset.page);
    const pg = doc.pages[page - 1];
    const here = S.fields.filter((f) => f.docKey === doc.key && f.page === page);
    const size = DEFAULT_SIZE[type];
    // A margin below each field keeps keyboard-placed fields apart, not touching.
    const spot = freeSpot(here.map((f) => ({ ...f, height: f.height + 16 })), size, pg, pg.width / 2, pg.height / 3);
    addField(type, doc, page, spot.x + size.width / 2, spot.y + size.height / 2);
  }

  // ---- Properties ------------------------------------------------------------------------
  function renderProps() {
    clear(props);
    const f = S.fields.find((x) => x.key === S.selected);
    if (!f) {
      props.append(h("h2", { class: "os-panel__title", text: t("prepare.properties") }),
        h("p", { class: "os-muted os-small", text: t("prepare.props-none") }));
      if (S.docs.length && !S.fields.length) {
        props.append(emptyState({ illus: "fields", title: t("empty.fields.title"), text: t("empty.fields.text"), action: button(t("prepare.add-field", { type: t("ftype.signature") }), { icon: "signature", variant: "primary", onClick: () => addFieldInView("signature") }), testId: "empty-fields" }));
      } else if (S.fields.length) {
        props.append(h("p", { class: "os-muted os-small", text: t("prepare.fields-count", { n: S.fields.length }) }));
      }
      return;
    }
    const pg = pageOf(f);
    const set = (k, v) => {
      S.undo.push(snapshot()); S.redo = [];
      f[k] = v; S.dirty = true;
      renderFieldsOnly();
    };
    props.append(h("h2", { class: "os-panel__title", text: t("prepare.field-props", { type: t(`ftype.${f.type}`) }) }));
    props.append(selectField(t(TPL ? "template.assigned-to" : "prepare.assigned-to"), S.recipients.map((r, i) => [r.key, `${i + 1}. ${displayName(r, i)}`]), { id: "fp-recipient", value: f.recipientKey, onChange: (v) => set("recipientKey", v) }).el);
    if (takesInput(f.type)) {
      const req = h("input", { id: "fp-required", type: "checkbox", checked: !!f.required });
      req.addEventListener("change", () => set("required", req.checked));
      props.append(h("label", { class: "os-check", attrs: { for: "fp-required" } }, req, h("span", { text: t("prepare.required") })));
    } else {
      props.append(h("p", { class: "os-muted os-small", text: t(`prepare.auto-${f.type}`) }));
    }
    const label = h("input", { id: "fp-label", class: "os-input", value: f.label || "", maxLength: 255 });
    label.addEventListener("change", () => set("label", label.value.trim()));
    props.append(h("label", { class: "os-label", attrs: { for: "fp-label" }, text: t("prepare.label") }), label);
    const geo = h("div", { class: "os-geo" });
    for (const k of ["x", "y", "width", "height"]) {
      const id = `fp-${k}`;
      const inp = h("input", { id, class: "os-input os-input--sm", type: "number", step: "1", min: "0", value: String(Math.round(f[k] * 100) / 100) });
      inp.addEventListener("change", () => {
        const v = Number.parseFloat(inp.value);
        if (!Number.isFinite(v)) { inp.value = String(f[k]); return; }
        S.undo.push(snapshot()); S.redo = [];
        Object.assign(f, clampRect({ ...f, [k]: v }, pg));
        S.dirty = true;
        renderFieldsOnly(); renderProps();
      });
      geo.append(h("label", { class: "os-geo__item", attrs: { for: id } }, h("span", { text: t(`prepare.geo-${k}`) }), inp));
    }
    props.append(h("p", { class: "os-label", text: t("prepare.position") }), geo, h("p", { class: "os-muted os-small", text: t("prepare.position-help", { page: f.page }) }));
    props.append(h("div", { class: "os-actions" },
      button(t("prepare.duplicate"), { icon: "copy", size: "sm", onClick: () => run("field.duplicate") }),
      button(t("prepare.delete-field"), { icon: "trash-2", size: "sm", variant: "danger", onClick: () => run("field.delete") })));
  }

  function renderAll() {
    renderDocs();
    renderRecipients();
    renderPalette();
    renderFieldsOnly();
    renderProps();
    if (step === "review") renderReview();
  }

  /// Step 4: the email (subject, message), reminders and expiry, signer location, and a
  /// summary of who gets what. In a template: its name, email subject and message.
  function renderReview() {
    clear(reviewPanel);
    reviewPanel.append(h("div", { class: "os-step-head" }, h("div", {},
      h("h2", { id: "review-h", class: "os-step-head__title", text: t(TPL ? "wizard.review-template" : "wizard.step.review") }),
      h("p", { class: "os-muted", text: t(TPL ? "wizard.review-template-lede" : "wizard.review-lede") }))));
    const msg = h("textarea", { id: "env-message", class: "os-input os-textarea", rows: 4, maxLength: 10000, value: S.message, placeholder: t("prepare.message-placeholder") });
    msg.addEventListener("input", () => { S.message = msg.value; S.dirty = true; });
    const email = h("section", { class: "os-card", attrs: { "aria-labelledby": "rv-email-h" } },
      h("h3", { id: "rv-email-h", class: "os-card__title", text: t(TPL ? "wizard.template-details" : "wizard.email") }),
      h("label", { class: "os-label", attrs: { for: "env-subject" }, text: t(TPL ? "template.name" : "prepare.subject") }), subject);
    if (TPL) {
      const es = h("input", { id: "tpl-email-subject", class: "os-input", maxLength: 255, value: S.emailSubject });
      es.addEventListener("input", () => { S.emailSubject = es.value; S.dirty = true; });
      email.append(h("label", { class: "os-label", attrs: { for: "tpl-email-subject" }, text: t("template.email-subject") }), es);
    }
    email.append(h("label", { class: "os-label", attrs: { for: "env-message" }, text: t("prepare.message") }), msg);
    reviewPanel.append(email);
    if (!TPL) {
      const num = (id, value, set) => {
        const i = h("input", { id, class: "os-input os-input--num", type: "number", min: "0", max: "999", step: "1", value: value == null ? "" : String(value), inputMode: "numeric" });
        i.addEventListener("change", () => { const v = Number.parseInt(i.value, 10); set(Number.isInteger(v) && v > 0 ? Math.min(v, 999) : null); S.dirty = true; });
        return i;
      };
      const loc = h("input", { id: "env-location", type: "checkbox", checked: S.captureLocation });
      loc.addEventListener("change", () => { S.captureLocation = loc.checked; S.dirty = true; });
      reviewPanel.append(h("section", { class: "os-card", attrs: { "aria-labelledby": "rv-opt-h" } },
        h("h3", { id: "rv-opt-h", class: "os-card__title", text: t("wizard.options") }),
        h("div", { class: "os-optgrid" },
          h("div", {}, h("label", { class: "os-label", attrs: { for: "rem-first" }, text: t("prepare.reminder-first") }), num("rem-first", S.reminderFirst, (v) => { S.reminderFirst = v; })),
          h("div", {}, h("label", { class: "os-label", attrs: { for: "rem-every" }, text: t("prepare.reminder-every") }), num("rem-every", S.reminderEvery, (v) => { S.reminderEvery = v; })),
          h("div", {}, h("label", { class: "os-label", attrs: { for: "expires" }, text: t("prepare.expires") }), num("expires", S.expiresDays, (v) => { S.expiresDays = v; }))),
        h("p", { class: "os-muted os-small", text: t("prepare.reminders-help") }),
        h("label", { class: "os-check", attrs: { for: "env-location" } }, loc, h("span", { text: t("prepare.capture-location") })),
        h("p", { class: "os-muted os-small", text: t("prepare.capture-location-help") })));
    } else {
      reviewPanel.append(h("p", { class: "os-muted os-small", text: t("template.roles-help") }));
    }
    // Summary: documents, then each recipient with the fields they fill.
    const sum = h("section", { class: "os-card", attrs: { "aria-labelledby": "rv-sum-h" } }, h("h3", { id: "rv-sum-h", class: "os-card__title", text: t("wizard.summary") }));
    sum.append(h("p", { class: "os-summary__docs" }, icon("file-text", { size: 16 }),
      h("span", { text: S.docs.length ? S.docs.map((d) => t("wizard.doc-pages", { name: d.name, n: d.pages.length })).join(", ") : t("prepare.no-docs") })));
    const ul = h("ul", { class: "os-summary" });
    S.recipients.forEach((r, i) => {
      const n = S.fields.filter((f) => f.recipientKey === r.key).length;
      ul.append(h("li", { class: `os-summary__item os-r${colourOf(r.key)}` },
        h("span", { class: "os-order", text: String(orderOf(r)) }),
        h("span", { class: "os-summary__who" }, h("strong", { text: displayName(r, i) }), TPL ? null : h("span", { class: "os-muted os-small", text: r.email || t("wizard.no-email") })),
        h("span", { class: "os-muted os-small", text: t(`rtype.${r.type}`) }),
        h("span", { class: "os-small", text: r.type === "signer" ? t("wizard.fields-n", { n }) : "" })));
    });
    if (!S.recipients.length) ul.append(h("li", { class: "os-muted", text: t(TPL ? "empty.roles.title" : "empty.recipients.title") }));
    sum.append(ul);
    reviewPanel.append(sum);
  }

  // ---- Loading a draft ------------------------------------------------------------------
  async function loadFromServer(env) {
    S.id = env.id;
    S.subject = env.subject || "";
    S.message = env.message || "";
    S.captureLocation = !!env.signing_options?.capture_location;
    S.reminderFirst = Number.isInteger(env.reminders?.first_after_days) ? env.reminders.first_after_days : null;
    S.reminderEvery = Number.isInteger(env.reminders?.then_every_days) ? env.reminders.then_every_days : null;
    S.expiresDays = env.expires_at ? Math.max(1, Math.ceil((Date.parse(env.expires_at) - Date.now()) / 86_400_000)) : null;
    S.serverOptions = JSON.stringify(sendOptions());
    subject.value = S.subject;
    title.textContent = S.subject.trim() || t("prepare.title");
    const prevDocs = new Map(S.docs.filter((d) => d.id).map((d) => [d.id, d]));
    const docs = [];
    for (const d of env.documents || []) {
      let doc = prevDocs.get(d.id);
      if (!doc) {
        const bytes = new Uint8Array(await (await ctx.api.documentContent(env.id, d.id, "normalized")).arrayBuffer());
        const pdf = await openPdf(bytes.slice());
        doc = { key: newKey("d"), id: d.id, name: d.name, bytes, pages: pdf.pages };
        pdfs.set(doc.key, pdf);
      }
      docs.push(doc);
    }
    for (const d of S.docs) if (!docs.includes(d)) { pdfs.get(d.key)?.destroy(); pdfs.delete(d.key); }
    S.docs = docs;
    const recs = [...(env.recipients || [])].sort((a, b) => a.routing_order - b.routing_order);
    const signerOrders = new Set(recs.filter((r) => r.type === "signer").map((r) => r.routing_order));
    S.routing = recs.filter((r) => r.type === "signer").length > 1 && signerOrders.size === 1 ? "parallel" : "sequential";
    const prevAccess = new Map(S.recipients.map((r) => [r.id, r.accessCode]));
    S.recipients = recs.map((r) => ({ key: newKey("r"), id: r.id, name: r.name || "", email: r.email || "", type: r.type === "cc" ? "cc" : "signer", accessCode: prevAccess.get(r.id) || "", hasAccessCode: (r.auth || []).includes("access_code"), serverOrder: r.routing_order }));
    const rkey = new Map(S.recipients.map((r) => [r.id, r.key]));
    const dkey = new Map(S.docs.map((d) => [d.id, d.key]));
    S.fields = (env.fields || []).map((f) => {
      const p = fromWire(f.placement);
      if (!p || !dkey.has(f.document_id)) return null;
      return { key: newKey("f"), id: f.id, docKey: dkey.get(f.document_id), recipientKey: rkey.get(f.recipient_id), type: f.type, page: p.page, x: p.x, y: p.y, width: p.width, height: p.height, required: !!f.required, label: f.label || "", server: JSON.stringify({ r: f.recipient_id, p: f.placement, q: !!f.required, l: f.label || "" }) };
    }).filter(Boolean);
    S.active = S.recipients[0]?.key || null;
    S.selected = null;
    S.undo = []; S.redo = [];
    S.dirty = false;
  }

  // ---- Saving ------------------------------------------------------------------------------
  function recipientBody(r) {
    const body = { type: r.type, name: r.name || t("prepare.recipient-n", { n: S.recipients.indexOf(r) + 1 }), email: r.email, routing_order: orderOf(r) };
    if (r.type === "signer" && r.accessCode) { body.auth = ["access_code"]; body.access_code = r.accessCode; }
    return body;
  }
  function fieldBody(f, recipientRef, documentRef) {
    const body = { recipient: recipientRef, document: documentRef, type: f.type, ...toWire(f.page, f) };
    if (f.required && takesInput(f.type)) body.required = true;
    if (f.label) body.label = f.label;
    return body;
  }
  const options = () => ({ ...(S.captureLocation ? { capture_location: true } : {}) });
  /// Reminders and expiry as the API takes them; absent members mean "account default".
  const sendOptions = () => ({
    reminders: { ...(S.reminderFirst ? { first_after_days: S.reminderFirst } : {}), ...(S.reminderEvery ? { then_every_days: S.reminderEvery } : {}) },
    expires_in_days: S.expiresDays || null,
  });
  const etagNow = async () => (await ctx.api.getEnvelope(S.id)).etag;

  async function save() {
    const status = document.getElementById("save-status");
    status.textContent = t("prepare.saving");
    if (!S.id) {
      const body = {
        subject: S.subject.trim(),
        message: S.message,
        signing_options: options(),
        ...(Object.keys(sendOptions().reminders).length ? { reminders: sendOptions().reminders } : {}),
        ...(S.expiresDays ? { expires_in_days: S.expiresDays } : {}),
        documents: S.docs.map((d) => ({ name: d.name, content_base64: toB64(d.bytes) })),
        recipients: S.recipients.map((r, i) => ({ ref: `r${i}`, ...recipientBody(r) })),
        fields: S.fields.map((f) => fieldBody(f, `r${S.recipients.findIndex((r) => r.key === f.recipientKey)}`, S.docs.findIndex((d) => d.key === f.docKey))),
      };
      const env = await ctx.api.createEnvelope(body);
      S.recipients.forEach((r, i) => { r.id = env.recipients?.[i]?.id || null; });
      history.replaceState(null, "", `${location.pathname}${location.search}#/prepare/${encodeURIComponent(env.id)}`);
      await loadFromServer(env);
    } else {
      // Documents first: new fields need their ids.
      for (const d of S.docs.filter((x) => !x.id)) {
        const created = await ctx.api.addDocument(S.id, d.name, d.bytes);
        d.id = created.id;
      }
      const { envelope: server } = await ctx.api.getEnvelope(S.id);
      const keepFields = new Set(S.fields.filter((f) => f.id).map((f) => f.id));
      for (const f of server.fields || []) if (!keepFields.has(f.id)) await ctx.api.deleteField(S.id, f.id, await etagNow());
      const keepRecs = new Set(S.recipients.filter((r) => r.id).map((r) => r.id));
      for (const r of server.recipients || []) if (!keepRecs.has(r.id)) await ctx.api.deleteRecipient(S.id, r.id, await etagNow());
      const serverRecs = new Map((server.recipients || []).map((r) => [r.id, r]));
      for (const r of S.recipients.filter((x) => x.id)) {
        const s = serverRecs.get(r.id);
        const want = recipientBody(r);
        const patch = {};
        for (const k of ["name", "email", "routing_order"]) if (s && s[k] !== want[k]) patch[k] = want[k];
        if (Object.keys(patch).length) await ctx.api.patchRecipient(S.id, r.id, await etagNow(), patch);
      }
      const fresh = S.recipients.filter((x) => !x.id);
      if (fresh.length) {
        const out = await ctx.api.addRecipients(S.id, fresh.map(recipientBody));
        (out?.items || []).forEach((r, i) => { if (fresh[i]) fresh[i].id = r.id; });
      }
      const rid = (k) => S.recipients.find((r) => r.key === k)?.id;
      const did = (k) => S.docs.find((d) => d.key === k)?.id;
      for (const f of S.fields.filter((x) => x.id)) {
        const now = JSON.stringify({ r: rid(f.recipientKey), p: toWire(f.page, f), q: !!f.required, l: f.label || "" });
        if (now === f.server) continue;
        const body = fieldBody(f, rid(f.recipientKey), did(f.docKey));
        await ctx.api.patchField(S.id, f.id, await etagNow(), { recipient_id: body.recipient, placement: toWire(f.page, f), required: !!body.required, label: f.label || null });
      }
      const newFields = S.fields.filter((x) => !x.id);
      if (newFields.length) await ctx.api.addFields(S.id, newFields.map((f) => fieldBody(f, rid(f.recipientKey), did(f.docKey))));
      const { envelope: e2, etag } = await ctx.api.getEnvelope(S.id);
      const optsChanged = JSON.stringify(sendOptions()) !== S.serverOptions;
      if (optsChanged || (e2.subject || "") !== S.subject.trim() || (e2.message || "") !== S.message || !!e2.signing_options?.capture_location !== S.captureLocation) {
        await ctx.api.patchEnvelope(S.id, etag, { subject: S.subject.trim(), message: S.message, signing_options: { ...(e2.signing_options || {}), capture_location: S.captureLocation }, ...(optsChanged ? sendOptions() : {}) });
      }
      const { envelope: final } = await ctx.api.getEnvelope(S.id);
      await loadFromServer(final);
    }
    status.textContent = t("prepare.saved");
    renderAll();
    await renderStage();
  }

  function problems() {
    const out = [];
    if (!S.docs.length) out.push(t("send.need-doc"));
    if (!signers().length) out.push(t("send.need-signer"));
    S.recipients.forEach((r, i) => {
      if (!r.name.trim()) out.push(t("send.need-name", { n: i + 1 }));
      if (!EMAIL.test(r.email)) out.push(t("send.need-email", { name: displayName(r, i) }));
      if (r.type === "signer" && !S.fields.some((f) => f.recipientKey === r.key)) out.push(t("send.need-field", { name: displayName(r, i) }));
    });
    return out;
  }

  async function send() {
    const list = problems();
    if (list.length) {
      await openDialog({
        title: t("send.problems-title"),
        description: t("send.problems-text"),
        build(body) { body.append(h("ul", { class: "os-problems" }, ...list.map((p) => h("li", {}, icon("triangle-alert", { size: 16 }), h("span", { text: p }))))); },
        actions: [{ label: t("action.ok"), variant: "primary", value: null }],
      });
      return;
    }
    const sum = S.recipients.filter((r) => r.type === "signer").length;
    if (!(await confirmDialog(t("send.confirm-title"), t("send.confirm-text", { n: sum, subject: S.subject.trim() || t("envelope.untitled") }), { confirm: t("prepare.send") }))) return;
    await busy(sendBtn, async () => {
      try {
        await save();
        await ctx.api.sendEnvelope(S.id);
        S.dirty = false;
        await celebrate();
        ctx.navigate(`#/envelopes/${encodeURIComponent(S.id)}`);
      } catch (err) {
        if (!ctx.failed(err)) showSaveError(err);
      }
    });
  }

  function showSaveError(err) {
    document.getElementById("save-status").textContent = t("prepare.not-saved");
    const extra = (err.errors || []).map((e) => `${e.pointer || ""} ${e.code || ""}`.trim()).filter(Boolean);
    toast(extra.length ? `${errorMessage(err)} — ${extra.slice(0, 3).join("; ")}` : errorMessage(err), "error");
  }

  // ---- Template mode: save ---------------------------------------------------------------
  function templateProblems() {
    const out = [];
    if (!S.subject.trim()) out.push(t("template.need-name"));
    if (!S.recipients.length) out.push(t("template.need-role"));
    else if (!signers().length) out.push(t("send.need-signer"));
    return out;
  }

  async function saveTemplate() {
    const list = templateProblems();
    if (list.length) {
      await openDialog({
        title: t("template.problems-title"),
        description: t("send.problems-text"),
        build(body) { body.append(h("ul", { class: "os-problems" }, ...list.map((p) => h("li", {}, icon("triangle-alert", { size: 16 }), h("span", { text: p }))))); },
        actions: [{ label: t("action.ok"), variant: "primary", value: null }],
      });
      return;
    }
    await busy(saveBtn, async () => {
      const status = document.getElementById("save-status");
      status.textContent = t("prepare.saving");
      const roles = rolesFrom(S.recipients, S.routing);
      let tpl;
      try {
        tpl = await ctx.api.templates.create({
          name: S.subject.trim(),
          ...(S.emailSubject.trim() ? { email_subject: S.emailSubject.trim() } : {}),
          ...(S.message ? { email_message: S.message } : {}),
          roles,
        });
      } catch (err) {
        if (!ctx.failed(err)) showSaveError(err);
        return;
      }
      // Documents and fields: docs/40 slice 3. A server without them keeps the roles.
      let partial = false;
      try {
        const docIds = new Map();
        for (const d of S.docs) docIds.set(d.key, (await ctx.api.templates.addDocument(tpl.id, d.name, d.bytes)).id);
        const roleOf = new Map(S.recipients.map((r, i) => [r.key, roles[i].name]));
        if (S.fields.length) {
          await ctx.api.templates.addFields(tpl.id, S.fields.map((f) => {
            const body = { document_id: docIds.get(f.docKey), role: roleOf.get(f.recipientKey), type: f.type, placement: toWire(f.page, f) };
            if (f.required && takesInput(f.type)) body.required = true;
            if (f.label) body.label = f.label;
            return body;
          }));
        }
      } catch (err) {
        if (!templateDocsUnsupported(err)) {
          if (!ctx.failed(err)) showSaveError(err);
          return;
        }
        partial = S.docs.length > 0;
      }
      S.dirty = false;
      status.textContent = t("prepare.saved");
      toast(partial ? t("template.saved-roles-only") : t("template.saved"), partial ? "info" : "success");
      ctx.navigate("#/templates");
    });
  }

  async function celebrate() {
    const node = h("div", { class: "os-celebrate", attrs: { role: "status", "data-testid": "sent-celebration" } },
      h("img", { class: "os-celebrate__seal", src: "assets/mark.svg", alt: "", width: 96, height: 96 }),
      h("p", { class: "os-celebrate__text", text: t("send.sent") }));
    document.body.append(node);
    await new Promise((r) => setTimeout(r, reducedMotion() ? 400 : 1100));
    node.remove();
    toast(t("send.sent"), "success");
  }

  // ---- Commands -----------------------------------------------------------------------------
  const sel = () => S.fields.find((f) => f.key === S.selected);
  const withSel = (fn) => () => {
    const f = sel();
    if (!f) return;
    const before = snapshot();
    fn(f);
    S.undo.push(before); S.redo = []; S.dirty = true;
    const el = stage.querySelector(`.os-field[data-fkey="${f.key}"]`);
    if (el) { place(el, f); el.setAttribute("aria-label", fieldLabel(f)); }
    renderProps();
    say(t("prepare.field-at", { x: Math.round(f.x), y: Math.round(f.y), w: Math.round(f.width), h: Math.round(f.height) }));
  };
  const hasSel = () => !!sel();
  const nudgeBy = (dx, dy) => withSel((f) => Object.assign(f, nudge(f, dx, dy, pageOf(f))));
  const sizeBy = (dw, dh) => withSel((f) => Object.assign(f, resize(f, dw, dh, pageOf(f))));
  const reg = (id, label, runFn, enabled = hasSel) => register(id, { label, run: runFn, enabled });
  reg("field.nudge-left", t("cmd.field.nudge"), nudgeBy(-1, 0));
  reg("field.nudge-right", t("cmd.field.nudge"), nudgeBy(1, 0));
  reg("field.nudge-up", t("cmd.field.nudge"), nudgeBy(0, -1));
  reg("field.nudge-down", t("cmd.field.nudge"), nudgeBy(0, 1));
  reg("field.nudge-left-10", t("cmd.field.nudge-10"), nudgeBy(-10, 0));
  reg("field.nudge-right-10", t("cmd.field.nudge-10"), nudgeBy(10, 0));
  reg("field.nudge-up-10", t("cmd.field.nudge-10"), nudgeBy(0, -10));
  reg("field.nudge-down-10", t("cmd.field.nudge-10"), nudgeBy(0, 10));
  reg("field.grow-width", t("cmd.field.resize"), sizeBy(4, 0));
  reg("field.shrink-width", t("cmd.field.resize"), sizeBy(-4, 0));
  reg("field.grow-height", t("cmd.field.resize"), sizeBy(0, 4));
  reg("field.shrink-height", t("cmd.field.resize"), sizeBy(0, -4));
  reg("field.delete", t("cmd.field.delete"), () => {
    const f = sel();
    if (!f) return;
    const order = S.fields.filter((x) => x.docKey === f.docKey && x.page === f.page);
    const next = order[order.indexOf(f) + 1] || order[order.indexOf(f) - 1];
    change(() => { S.fields = S.fields.filter((x) => x !== f); S.selected = null; });
    say(t("prepare.field-deleted"));
    if (next) select(next.key); else stage.focus();
  });
  reg("field.duplicate", t("cmd.field.duplicate"), () => {
    const f = sel();
    if (!f) return;
    const copy = { ...f, key: newKey("f"), id: null, server: undefined, ...nudge(f, 12, 12, pageOf(f)) };
    change(() => { S.fields.push(copy); S.selected = copy.key; });
    select(copy.key);
  });
  reg("field.copy", t("cmd.field.copy"), () => { S.clipboard = { ...sel() }; say(t("prepare.copied")); });
  reg("field.paste", t("cmd.field.paste"), () => {
    const c = S.clipboard;
    if (!c || !S.docs.some((d) => d.key === c.docKey)) return;
    const copy = { ...c, key: newKey("f"), id: null, server: undefined, ...nudge(c, 12, 12, pageOf(c)) };
    S.clipboard = copy;
    change(() => { S.fields.push(copy); S.selected = copy.key; });
    select(copy.key);
  }, () => !!S.clipboard);
  reg("field.deselect", t("cmd.field.deselect"), () => { const f = sel(); select(null); if (f) stage.focus(); });
  reg("edit.undo", t("cmd.edit.undo"), () => { const s = S.undo.pop(); if (!s) return; S.redo.push(snapshot()); restore(s); }, () => S.undo.length > 0);
  reg("edit.redo", t("cmd.edit.redo"), () => { const s = S.redo.pop(); if (!s) return; S.undo.push(snapshot()); restore(s); }, () => S.redo.length > 0);
  if (TPL) {
    // Ctrl/Cmd+S (bound to envelope.save in the editor table) saves the template here.
    reg("template.save", t("template.save"), () => saveTemplate(), () => true);
    reg("envelope.save", t("template.save"), () => saveTemplate(), () => true);
  } else {
    reg("envelope.save", t("prepare.save"), () => busy(saveBtn, async () => {
      try { await save(); toast(t("prepare.saved"), "success"); } catch (err) { if (!ctx.failed(err)) showSaveError(err); }
    }), () => true);
    reg("envelope.send", t("prepare.send"), send, () => true);
  }
  reg("recipient.add", t(TPL ? "template.add-role" : "prepare.add-recipient"), () => addRecipient(), () => true);
  reg("document.add", t("prepare.add-pdf"), () => fileInput.click(), () => true);
  for (const type of FIELD_TYPES) reg(`field.add-${type}`, t("prepare.add-field", { type: t(`ftype.${type}`) }), () => addFieldInView(type), () => true);
  for (let n = 1; n <= 9; n++) {
    reg(`recipient.select-${n}`, t("cmd.recipient.select"), () => {
      S.active = S.recipients[n - 1].key;
      markActive(); renderPalette();
      say(t("prepare.placing-for-name", { name: displayName(S.recipients[n - 1], n - 1) }));
    }, () => S.recipients.length >= n);
  }

  // Files dropped from the desktop onto the stage.
  stage.addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); stage.classList.add("is-dropping"); } });
  stage.addEventListener("dragleave", (e) => { if (e.target === stage) stage.classList.remove("is-dropping"); });
  stage.addEventListener("drop", (e) => {
    if (!e.dataTransfer.files?.length) return;
    e.preventDefault();
    stage.classList.remove("is-dropping");
    addFiles([...e.dataTransfer.files].filter((f) => f.type === "application/pdf" || /\.pdf$/i.test(f.name)));
  });

  let resizeTimer = null;
  const onResize = () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (S.docs.length && step === "fields") renderStage(); }, 200); };
  window.addEventListener("resize", onResize);
  const beforeUnload = (e) => { if (S.dirty) { e.preventDefault(); e.returnValue = ""; } };
  window.addEventListener("beforeunload", beforeUnload);

  // ---- Start ---------------------------------------------------------------------------------
  renderAll();
  stage.append(h("div", { class: "os-page os-skeleton-page", attrs: { "aria-hidden": "true" } }));
  if (S.id) {
    try {
      const { envelope } = await ctx.api.getEnvelope(S.id);
      if (envelope.status !== "draft") { ctx.navigate(`#/envelopes/${encodeURIComponent(S.id)}`); return () => {}; }
      await loadFromServer(envelope);
      renderAll();
    } catch (err) {
      if (!ctx.failed(err)) toastError(err);
    }
  }
  const handed = !TPL && !S.id ? takeFiles() : null;
  if (handed) await addFiles(handed);
  // A saved draft with documents and people opens on its fields; anything else starts
  // at the documents, or at the people when the documents are already there.
  await go(S.docs.length && S.recipients.length ? "fields" : S.docs.length ? "recipients" : "documents");
  if (step === "documents") docsPanel.querySelector(".os-btn--primary")?.focus();

  return () => {
    window.removeEventListener("resize", onResize);
    window.removeEventListener("beforeunload", beforeUnload);
    unregisterPrefix("field.");
    unregisterPrefix("edit.");
    unregisterPrefix("envelope.save");
    unregisterPrefix("envelope.send");
    unregisterPrefix("template.");
    unregisterPrefix("recipient.");
    unregisterPrefix("document.");
    for (const p of pdfs.values()) p.destroy();
  };
}

function toB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
