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
// documents and the fields bound to the roles' ids (templatesync.js, WEB-10).
// `#/templates/{id}/edit` (`opts.templateId`, WEB-09) reopens a saved template's
// documents, roles and fields; saving brings the server's template into line with
// the editor (removals, changes and additions, each with If-Match).

import { h, append, clear, reducedMotion, skipTo } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix, run } from "./commands.js";
import { button, busy, emptyState, toast, toastError, confirmDialog, selectField, switchButton, dockPanel, openPanel, closePanel } from "./ui/index.js";
import { openPdf } from "./pdfview.js";
import { docView, zoomControls, thumbnails } from "./docview.js";
import { FIELD_TYPES, TYPED, CHOICE, DEFAULT_SIZE, clampRect, nudge, resize, placeAt, freeSpot, toWire, fromWire, takesInput, requiredByDefault, validationFrom, optionsFrom } from "./geometry.js";
import { errorMessage, RECIPIENT_TYPES } from "./api.js";
import { rolesFrom } from "./templatemodel.js";
import { templatePlan, applyTemplate } from "./templatesync.js";
import { suggestionsFrom } from "./detect.js";
import { snapRect, touching, nextStop, bounds, intersects, fromCorners } from "./guides.js";
import { compact, fromServer, groups, stepMove, canStep, moveGroup, joinGroup, newStepBefore, setOrder, byOrder, isAllAtOnce } from "./routing.js";
import { takeFiles } from "./handoff.js";
import { sendSummary } from "./people.js";
import { LIBRARY, LIBRARY_MORE, TOOLBAR, toolForKey, stepStates, continueState, sendChecks, recipientRows, templateOffer, applyTemplatePlan, ocrPagesFrom, piiSummary } from "./preparemodel.js";
import { stepControl, recipientRow, libraryItem, toolButton, armHint, ghostBar, templateBanner, appliedChip, loadingPage, checksList, piiCard, assignList, markOcr, sparkle, spinner, KIND_GLYPH } from "./prepareview.js";
import { mlStatus, featureOn, loadSuggestions, acceptSuggestion, dismissSuggestion, suggestions as mlSuggestions, percent, isUnavailable } from "./ml.js";

const FIELD_ICON = {
  signature: "signature", initials: "pen-line", date_signed: "calendar", name: "user", email: "at-sign", company: "layers", title: "type",
  text: "text-cursor-input", number: "list-ordered", checkbox: "square-check", radio_group: "circle-dashed", dropdown: "chevron-down", attachment: "paperclip", note: "info",
};
/// The members of a field the editor sets besides its place, owner, `required` and `label`
/// (UX-05), by their wire names (api.js `FIELD_MEMBERS`); kept on the editor's field as is.
const MEMBERS = ["read_only", "value", "tooltip", "placeholder", "validation", "format", "options", "allow_custom"];
const blankMember = (v) => v == null || v === false || v === "" || (Array.isArray(v) && !v.length);
/// The members a field has, for the wire and for comparing with the server's copy.
const membersOf = (f) => Object.fromEntries(MEMBERS.filter((k) => !blankMember(f[k])).map((k) => [k, f[k]]));
/// What a new field of `type` starts with: a radio group or dropdown has two options to
/// rename, since one with none cannot be answered.
const newMembers = (type) => (CHOICE.has(type) ? { options: [t("prepare.option-n", { n: 1 }), t("prepare.option-n", { n: 2 })] } : {});
const MAX_UPLOAD = 50 * 1024 * 1024; // docs/21: 50 MiB decoded
const COLOURS = 6;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

let keySeq = 0;
const newKey = (p) => `${p}${++keySeq}`;

export async function mount(view, ctx, [rawId] = [], _params = null, opts = {}) {
  const TPL = !!opts.template;
  const TPL_ID = TPL && opts.templateId ? decodeURIComponent(opts.templateId) : null;
  const S = {
    tplId: TPL_ID,
    tplServer: null,
    id: rawId && !TPL ? decodeURIComponent(rawId) : null,
    subject: "",
    message: "",
    emailSubject: "",
    captureLocation: false,
    reminderFirst: null,
    reminderEvery: null,
    expiresDays: null,
    serverOptions: "",
    ordered: true, // "Set signing order"; each recipient's step is `r.order` (WEB-09)
    docs: [],
    recipients: [],
    fields: [],
    active: null,
    selected: null,
    clipboard: null,
    ghosts: [], // suggested fields from detection, not yet accepted (WEB-09)
    undo: [],
    redo: [],
  };
  // Whether there is unsaved work: the status in the toolbar follows it (A13).
  let dirty = false;
  let savedAt = null;
  let saving = false;
  Object.defineProperty(S, "dirty", { get: () => dirty, set: (v) => { dirty = !!v; syncStatus(); if (dirty) scheduleAutosave(); } });
  ctx.contexts = ["editor", "global"];
  const pdfs = new Map(); // doc key → pdf.js handle

  // ---- Layout ----------------------------------------------------------------------
  // A stepped flow (WEB-02 redesign, DocuSign's send flow): 1 documents, 2 recipients
  // (roles in a template), 3 fields, 4 review and send. Every step's panels stay in the
  // page and are shown one step at a time, so state and commands never depend on which
  // step is open. WEB-06 (docs/47 §Layout spec): a full-height frame with one toolbar —
  // steps, the document's zoom and page, undo and redo, the save state, and Back, Next
  // or Send — and on the fields step the document between two docked panels.
  const STEPS = ["documents", "recipients", "fields", "review"];
  let step = "documents";
  const subject = h("input", { id: "env-subject", class: "os-input", placeholder: t(TPL ? "template.name-placeholder" : "prepare.subject-placeholder"), maxLength: 255 });
  subject.addEventListener("input", () => { S.subject = subject.value; S.dirty = true; title.textContent = S.subject.trim() || newTitle(); title.title = title.textContent; });
  // The top bar (canvas): back, breadcrumb, title and the save state on the left; the
  // segmented step control in the middle; Preview as signer and the one primary action
  // (Continue, then Send or Save template) on the right. Saving is automatic for a draft;
  // the save button beside the state saves now (Ctrl/Cmd+S).
  const saveBtn = TPL
    ? button(t("template.save"), { icon: "save", variant: "primary", command: "template.save", onClick: () => run("template.save") })
    : button(t("prepare.save"), { icon: "save", size: "sm", variant: "ghost", iconOnly: true, command: "envelope.save", onClick: () => run("envelope.save"), attrs: { "data-testid": "save-draft", title: t("prepare.save-tip") } });
  const sendBtn = TPL ? null : button(t("prepare.send"), { icon: "send", variant: "primary", command: "envelope.send", onClick: () => run("envelope.send") });
  const newTitle = () => t(TPL_ID ? "templates.edit-title" : TPL ? "template.new-title" : "prepare.title");
  const title = h("h1", { class: "os-prepare__title", text: newTitle() });
  // The canvas names the last step "Review"; its full name ("Review and send") stays for
  // assistive technology, so the visible word is part of the accessible name.
  const steps = stepControl(STEPS, stepLabel, (s) => go(s), (s) => (s === "review" && !TPL ? "wizard.step.review-short" : null));
  const status = h("span", { class: "os-savestate", attrs: { "aria-live": "polite", id: "save-status", "data-testid": "save-status" } });

  // The document: one scroll container (docview.js) on a dotted canvas, the floating
  // tool bar, and the thumbnails in the left panel.
  const live = h("div", { class: "os-sr-only", attrs: { "aria-live": "polite" } });
  const dv = docView({
    label: t("prepare.pages"),
    testId: "editor-doc",
    // Phones open at a readable size (UX-05: 1 CSS px a point, 11 pt body text at 11 px;
    // fit width was about 5 px) and pan; two fingers zoom, as on any page.
    mode: matchMedia("(max-width: 47.999em)").matches ? 1 : "fit-width",
    onLayout: () => { zoom.sync(); syncZoomPct(); },
    onZoom: () => { zoom.sync(); syncZoomPct(); },
    onPage: (i) => { zoom.sync(); thumbs.mark(i); },
  });
  const stage = dv.scroller;
  stage.classList.add("os-stage");
  const zoom = zoomControls(dv);
  // The tool bar shows the zoom as the canvas does ("100%"); the select under it stays
  // the control (fit width, fit page, presets), transparent over the number.
  const zoomPct = h("span", { class: "os-zoompct", attrs: { "aria-hidden": "true" } });
  const zoomSel = zoom.el.querySelector("select");
  zoomSel?.before(h("span", { class: "os-zoomwrap" }, zoomPct));
  zoomPct.parentElement?.append(zoomSel);
  const syncZoomPct = () => { zoomPct.textContent = dv.pages.length ? `${dv.percent()}%` : "—"; };
  const undoBtn = button(t("cmd.edit.undo"), { icon: "undo-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => run("edit.undo"), attrs: { "aria-keyshortcuts": "Control+Z", "data-testid": "undo" } });
  const redoBtn = button(t("cmd.edit.redo"), { icon: "redo-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => run("edit.redo"), attrs: { "aria-keyshortcuts": "Control+Shift+Z", "data-testid": "redo" } });

  // Continue: the next step, held on the fields step while a signer has no field or a
  // suggestion is undecided (preparemodel.js continueState); held, it stays focusable and
  // a press says why beside it.
  const whyId = "prepare-why";
  const why = h("div", { id: whyId, class: "os-why", attrs: { role: "status", "data-testid": "continue-why" } });
  why.hidden = true;
  const nextBtn = button(t("wizard.continue"), { icon: "arrow-right", variant: "primary", attrs: { "data-testid": "wizard-next" }, onClick: () => continueNow() });
  nextBtn.classList.add("os-btn--trail");
  const previewBtn = TPL ? null : button(t("prepare.preview-signer"), { variant: "ghost", command: "editor.preview", onClick: () => run("editor.preview"), attrs: { "data-testid": "preview-signer" } });
  const bar = h("header", { class: "os-prepare__bar", attrs: { "aria-label": t(TPL ? "template.new-title" : "prepare.title") } },
    h("div", { class: "os-prepare__lead" },
      h("a", { href: TPL ? "#/templates" : "#/agreements", class: "os-btn os-btn--ghost os-btn--md os-btn--icon", attrs: { "aria-label": t(TPL ? "template.back" : "prepare.back"), title: t(TPL ? "template.back" : "prepare.back") } }, icon("chevron-left")),
      h("span", { class: "os-crumb", attrs: { "aria-hidden": "true" } }, h("span", { text: t(TPL ? "nav.templates" : "nav.agreements") }), h("span", { class: "os-crumb__sep", text: "/" })),
      TPL ? h("span", { class: "os-badge os-badge--template" }, icon("layout-template", { size: 16 }), h("span", { text: t("template.badge") })) : null,
      title, status, TPL ? null : saveBtn),
    h("nav", { class: "os-prepare__steps", attrs: { "aria-label": t("wizard.steps") } }, steps.el),
    h("div", { class: "os-prepare__actions" }, previewBtn, h("div", { class: "os-why-anchor" }, nextBtn, why), sendBtn, TPL ? saveBtn : null));

  // Left panel: recipients, Detect fields, the fields library, the pages.
  const docsPanel = h("section", { class: "os-panel os-panel--docs", attrs: { "aria-labelledby": "docs-h" } });
  const rcptPanel = h("section", { class: "os-panel os-panel--rcpt", attrs: { "aria-labelledby": "rcpt-h" } });
  const palettePanel = h("section", { class: "os-panel os-panel--palette", attrs: { "aria-labelledby": "pal-h" } });
  const thumbsBox = h("nav", { class: "os-thumbs", attrs: { "aria-label": t("prepare.thumbs") } });
  const thumbs = thumbnails(dv, thumbsBox, { width: 56, byDocument: true });
  const leftDock = dockPanel({ id: "editor-fields", side: "left", title: t("prepare.fields"), icon: "signature", width: 16.5, min: 13, max: 24, testId: "panel-fields" });
  leftDock.el.classList.add("os-prepdock");
  leftDock.body.append(palettePanel);
  leftDock.body.classList.add("os-dock__body--split");
  const rail = h("section", { class: "os-prepare__rail os-panel--thumbs", attrs: { "aria-labelledby": "thumbs-h", "data-testid": "thumbs-rail" } },
    h("h3", { id: "thumbs-h", class: "os-prep-h", text: t("prepare.pages-short") }), thumbsBox);
  leftDock.body.append(rail);
  const props = h("div", { class: "os-props" });
  const rightDock = dockPanel({ id: "editor-props", side: "right", title: t("prepare.properties"), icon: "settings", width: 17.5, min: 14, max: 30, testId: "panel-props", collapsed: matchMedia("(max-width: 74.999em)").matches });
  rightDock.el.classList.add("os-prepdock");
  rightDock.body.append(props);
  // Phones: the palette and the properties are bottom sheets; this opens the palette.
  const addFab = button(t("prepare.add-field-short"), { icon: "plus", variant: "primary", size: "lg", onClick: () => leftDock.openSheet(), attrs: { "data-testid": "add-field-sheet" } });
  const propsFab = button(t("prepare.field-settings"), { icon: "settings", size: "lg", onClick: () => rightDock.openSheet(), attrs: { "data-testid": "props-sheet", title: t("prepare.field-settings") } });
  propsFab.hidden = true;
  // The floating tool bar (canvas): Select and six kinds, Detect fields, zoom, undo and
  // redo. Phones: the same bar holds the page indicator, Field settings and Add field.
  const toolBtns = new Map(TOOLBAR.map((k) => [k, toolButton(k, () => (k === "select" ? run("field.disarm-select") : toggleArm(k)))]));
  const toolDetect = TPL ? null : h("button", { type: "button", class: "os-tool os-tool--ml", attrs: { "aria-label": t("prepare.detect"), title: t("prepare.detect"), "data-testid": "tool-detect" } }, sparkle("1rem"));
  toolDetect?.addEventListener("click", () => run("field.detect"));
  const toolbar = h("div", { class: "os-docbar os-toolbar", attrs: { role: "toolbar", "aria-label": t("prepare.tools") } },
    h("div", { class: "os-toolbar__tools" }, ...toolBtns.values()),
    h("span", { class: "os-toolbar__sep", attrs: { "aria-hidden": "true" } }),
    toolDetect, zoom.el,
    h("span", { class: "os-toolbar__sep os-toolbar__sep--hist", attrs: { "aria-hidden": "true" } }),
    h("div", { class: "os-toolbar__hist" }, undoBtn, redoBtn),
    h("div", { class: "os-docbar__actions" }, propsFab, addFab));
  const previewBar = h("div", { class: "os-previewbar", attrs: { role: "status", "data-testid": "preview-as" } });
  previewBar.hidden = true;
  // Floating layers over the page: the template banner (top), the hint or the suggestion
  // bar (bottom, above the tool bar).
  const topLayer = h("div", { class: "os-floattop" });
  const bottomLayer = h("div", { class: "os-floatbottom", attrs: { "aria-live": "polite" } });
  const centre = h("div", { class: "os-prepare__centre" }, stage, previewBar, topLayer, bottomLayer, toolbar);
  /// Preview as a recipient (UX-05, DocuSign's "Preview"): on the fields step, their
  /// fields stand out and everyone else's fade, with a bar saying whose view it is.
  let previewKey = null;
  function previewAs(key) {
    previewKey = key;
    const r = recipient(key);
    previewBar.hidden = !r;
    previewBar.replaceChildren();
    if (r) {
      previewBar.append(icon("eye", { size: 16 }), h("span", { text: t("prepare.previewing", { name: displayName(r, S.recipients.indexOf(r)) }) }),
        button(t("prepare.preview-end"), { size: "sm", onClick: () => { previewAs(null); stage.focus(); } }));
    }
    previewBtn?.setAttribute("aria-pressed", String(!!r));
    renderFieldsOnly();
  }
  const reviewPanel = h("section", { class: "os-panel os-panel--review", attrs: { "aria-labelledby": "review-h" } });
  const fileInput = h("input", { type: "file", accept: "application/pdf,.pdf", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "pdf-input" } });
  fileInput.addEventListener("change", () => { addFiles([...fileInput.files]); fileInput.value = ""; });
  const panes = {
    documents: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, docsPanel),
    recipients: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, rcptPanel),
    fields: h("div", { class: "os-prepare__body" }, leftDock.el, centre, rightDock.el),
    review: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, reviewPanel),
  };
  // Contacts autocomplete (UX-05; GET /contacts): one list of names and one of addresses
  // for every recipient row, filled as the user types; choosing one fills the other box.
  const contactNames = h("datalist", { id: "rc-names" });
  const contactMails = h("datalist", { id: "rc-mails" });
  const contacts = new Map(); // lower-cased name or email → {name, email}
  let contactTimer = null;
  let contactSeq = 0;
  function lookContacts(q) {
    clearTimeout(contactTimer);
    if (TPL || q.trim().length < 2 || !ctx.api.listContacts) return;
    contactTimer = setTimeout(async () => {
      const seq = ++contactSeq;
      try {
        const out = await ctx.api.listContacts({ q: q.trim(), limit: 8 });
        if (seq !== contactSeq) return;
        const items = (out?.items || []).filter((c) => c && typeof c.email === "string");
        contactNames.replaceChildren(...items.filter((c) => c.name).map((c) => h("option", { value: c.name, label: c.email })));
        contactMails.replaceChildren(...items.map((c) => h("option", { value: c.email, label: c.name || "" })));
        for (const c of items) { contacts.set(c.email.toLowerCase(), c); if (c.name) contacts.set(c.name.toLowerCase(), c); }
      } catch { /* suggestions only: typing goes on without them */ }
    }, 200);
  }
  const frame = h("div", { class: "os-prepare", attrs: { "data-step": step } }, bar, h("div", { class: "os-wizard" },...Object.values(panes)), live, dv.live, fileInput, contactNames, contactMails);
  view.append(frame);


  function stepLabel(s) {
    // A template is saved, not sent (UX-05): its last step is "Review and save".
    if (TPL && s === "review") return "wizard.review-template";
    return s === "recipients" && TPL ? "wizard.step.roles" : `wizard.step.${s}`;
  }
  /// Open step `s`: show its pane, mark the step control, set the bar's buttons.
  async function go(s) {
    if (!STEPS.includes(s)) return;
    const prevStep = step;
    step = s;
    frame.dataset.step = s;
    const i = STEPS.indexOf(s);
    for (const [k, pane] of Object.entries(panes)) pane.hidden = k !== s;
    steps.sync(stepStates(STEPS, s));
    skipTo(s === "fields" ? "#document" : "#main", t(s === "fields" ? "a11y.skip-doc" : "a11y.skip"));
    if (s !== "fields") { leftDock.closeSheet(); rightDock.closeSheet(); disarm(); if (previewKey) previewAs(null); }
    if (s !== "fields") renderFloats(); // the hint and the suggestion bar belong to the fields step
    nextBtn.hidden = i === STEPS.length - 1;
    if (previewBtn) previewBtn.hidden = s !== "fields" && s !== "review";
    if (sendBtn) sendBtn.hidden = s !== "review";
    if (TPL) saveBtn.hidden = s !== "review";
    hideWhy();
    syncNext();
    say(t("wizard.where", { n: i + 1, total: STEPS.length, label: t(stepLabel(s)) }));
    if (s === "fields") {
      // Fields start with the first signer (P-01), whoever was edited last on step 2.
      if (prevStep !== "fields") { S.active = signers()[0]?.key || null; renderPalette(); }
      if (stageKey !== S.docs.map((d) => d.key).join()) await renderStage();
      else { dv.relayout(); renderFieldsOnly(); }
      renderFloats();
    }
    if (s === "review") renderReview();
  }

  /// Continue's state (preparemodel.js continueState): on the documents step it waits for
  /// a document (disabled, as before); on the fields step it is held while a signer has no
  /// field or a suggestion is undecided, and says why when pressed.
  let held = { blocked: false, reason: null };
  function syncNext() {
    held = continueState({ step, recipients: S.recipients, fields: S.fields, ghosts: S.ghosts.length, docs: S.docs.length });
    const need = step === "documents" && held.blocked;
    nextBtn.disabled = need;
    const soft = step !== "documents" && held.blocked;
    nextBtn.classList.toggle("is-held", soft);
    if (soft) { nextBtn.setAttribute("aria-disabled", "true"); nextBtn.setAttribute("aria-describedby", whyId); } else { nextBtn.removeAttribute("aria-disabled"); nextBtn.removeAttribute("aria-describedby"); }
    const reason = held.reason ? t(held.reason.key, held.reason.params) : "";
    if (reason) nextBtn.title = reason; else nextBtn.removeAttribute("title");
    why.textContent = reason;
    if (!soft) hideWhy();
  }
  function hideWhy() { why.hidden = true; }
  /// Continue pressed: the next step, or, held, the reason beside it and the recipient who
  /// still needs a field picked, so the next tool places for them.
  function continueNow() {
    syncNext();
    if (held.blocked) {
      if (step === "documents") return;
      why.hidden = false;
      say(why.textContent);
      if (held.keys?.length) pick(held.keys[0]);
      return;
    }
    go(STEPS[STEPS.indexOf(step) + 1]);
  }
  const onDocDown = (e) => { if (!why.hidden && !e.target.closest?.(".os-why-anchor")) hideWhy(); };
  document.addEventListener("pointerdown", onDocDown, true);

  const say = (msg) => { live.textContent = ""; setTimeout(() => { live.textContent = msg; }, 30); };

  /// The save state in the bar (A13: canvas "Saved" with its dot) and undo and redo (A14).
  function syncStatus() {
    status.replaceChildren();
    if (saving) status.append(spinner("0.75rem"), h("span", { text: t("prepare.saving") }));
    else if (dirty) status.append(h("span", { class: "os-savestate__dot", attrs: { "aria-hidden": "true" } }), h("span", { text: t("prepare.unsaved") }));
    else if (savedAt) status.append(h("span", { class: "os-savestate__dot", attrs: { "aria-hidden": "true" } }), h("span", { text: t("prepare.saved-state") }));
    status.classList.toggle("is-dirty", dirty && !saving);
    status.classList.toggle("is-saved", !dirty && !saving && !!savedAt);
    status.title = savedAt && !dirty && !saving ? t("prepare.saved-at", { time: savedAt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) }) : status.textContent;
    syncHistory();
  }
  function syncHistory() {
    undoBtn.disabled = !S.undo?.length;
    redoBtn.disabled = !S.redo?.length;
  }

  // ---- History -----------------------------------------------------------------------
  const snapshot = () => JSON.stringify({ recipients: S.recipients, fields: S.fields, ordered: S.ordered, ghosts: S.ghosts });
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
    S.ordered = v.ordered;
    S.ghosts = v.ghosts || [];
    if (S.selected && !S.fields.some((f) => f.key === S.selected)) S.selected = null;
    if (!S.recipients.some((r) => r.key === S.active)) S.active = S.recipients[0]?.key || null;
    S.dirty = true;
    renderAll();
  }

  // ---- Recipients ----------------------------------------------------------------------
  // WEB-09 signing groups (routing.js; DocuSign's "Set signing order"): with the order on,
  // each recipient has a step (`r.order`), recipients who share a step get the envelope
  // at the same time, and the list is drawn as one box per step. The list is kept in
  // step order. With the order off, signers are all step 1 and copies step 2.
  const colourOf = (rk) => (S.recipients.findIndex((r) => r.key === rk) % COLOURS) + 1;
  const recipient = (rk) => S.recipients.find((r) => r.key === rk);
  /// Who fills fields (UX-05): a signer, and an in-person signer whom staff host. An
  /// approver, a viewer and a copy take none.
  const takesFields = (r) => r?.type === "signer" || r?.type === "in_person_signer";
  const signers = () => S.recipients.filter(takesFields);
  /// The types a recipient may be given (UX-05): the engine's ready ones (api.js
  /// RECIPIENT_TYPES_READY), and an in-person signer only where staff can host one
  /// (NOT_ON_SERVER.hostInPerson); a type already set stays offered.
  const recipientTypes = (current) => {
    const out = ["signer", ...(ctx.api.available?.("hostInPerson") ? ["in_person_signer"] : []), "approver", "viewer", "cc"];
    return out.includes(current) || !current ? out : [...out, current];
  };
  const displayName = (r, i) => r?.name?.trim() || t(TPL ? "template.role-n" : "prepare.recipient-n", { n: i + 1 });
  function orderOf(r) {
    if (S.ordered) return r.order || 1;
    // All at once: everyone who acts at step 1, copies after them.
    return r.type === "cc" ? 2 : 1;
  }
  const orders = () => S.recipients.map((r) => r.order || 1);
  /// Set every recipient's step from `next` (aligned with S.recipients), then keep the
  /// list in step order.
  function setOrders(next) {
    S.recipients.forEach((r, i) => { r.order = next[i]; });
    S.recipients = byOrder(next).map((i) => S.recipients[i]);
  }
  const nextStep = () => (S.recipients.length ? Math.max(...orders()) + 1 : 1);
  function addRecipient(focus = true) {
    const r = { key: newKey("r"), id: null, name: "", email: "", type: "signer", accessCode: "", order: nextStep() };
    change(() => { S.recipients.push(r); S.active = r.key; });
    // To the new name box, unless the user has already gone on to type somewhere.
    if (focus) setTimeout(() => { if (!document.activeElement?.matches?.("input, select, textarea")) document.getElementById(`rn-${r.key}`)?.focus(); }, 0);
    return r;
  }
  function addMe() {
    const r = { key: newKey("r"), id: null, name: ctx.who?.name || "", email: ctx.who?.email || "", type: "signer", accessCode: "", order: nextStep() };
    change(() => { S.recipients.push(r); });
    say(t("prepare.added-me", { name: r.name || r.email }));
  }
  /// Where a recipient now signs, for the live region: "step 2", and with whom.
  function sayStep(r) {
    const i = S.recipients.indexOf(r);
    const with_ = S.recipients.filter((x) => x !== r && orderOf(x) === orderOf(r)).map((x) => displayName(x, S.recipients.indexOf(x)));
    say(with_.length ? t("prepare.step-with", { name: displayName(r, i), n: orderOf(r), names: with_.join(", ") }) : t("prepare.step-now", { name: displayName(r, i), n: orderOf(r) }));
  }

  function renderRecipients() {
    clear(rcptPanel);
    const addLabel = t(TPL ? "template.add-role" : "prepare.add-recipient");
    rcptPanel.append(h("div", { class: "os-step-head" },
      h("div", {},
        h("h2", { id: "rcpt-h", class: "os-step-head__title", text: t(TPL ? "template.roles" : "prepare.recipients") }),
        h("p", { class: "os-muted", text: t(TPL ? "wizard.roles-lede" : "wizard.recipients-lede") })),
      h("div", { class: "os-actions" },
        // "Add me" (S-03): the sender as a signer, in one click, when the app knows who they are.
        !TPL && ctx.who?.email && !S.recipients.some((x) => x.email === ctx.who.email) ? button(t("prepare.add-me"), { icon: "user", onClick: addMe, attrs: { "data-testid": "add-me" } }) : null,
        S.recipients.length ? button(addLabel, { icon: "user-plus", command: "recipient.add", onClick: () => addRecipient() }) : null)));
    if (!S.recipients.length) {
      rcptPanel.append(TPL
        ? emptyState({ illus: "recipients", title: t("empty.roles.title"), text: t("empty.roles.text"), action: button(addLabel, { icon: "user-plus", variant: "primary", onClick: () => addRecipient() }), testId: "empty-roles" })
        : emptyState({ illus: "recipients", title: t("empty.recipients.title"), text: t("empty.prepare-recipients.text"), action: button(addLabel, { icon: "user-plus", variant: "primary", onClick: () => addRecipient() }), testId: "empty-recipients" }));
      return;
    }
    // DocuSign's "Set signing order": on, recipients go step by step (a step may hold
    // several, who sign at the same time); off, all signers at once.
    const orderBox = h("input", { id: "routing-order", type: "checkbox", class: "os-switch__input", checked: S.ordered, attrs: { role: "switch" } });
    orderBox.addEventListener("change", () => change(() => {
      S.ordered = orderBox.checked;
      // Turned on: one step each, in the order shown.
      if (S.ordered) S.recipients.forEach((r, i) => { r.order = i + 1; });
    }));
    rcptPanel.append(h("div", { class: "os-switchrow" },
      h("label", { class: "os-switch", attrs: { for: "routing-order" } }, orderBox, h("span", { class: "os-switch__track", attrs: { "aria-hidden": "true" } }), h("span", { text: t("prepare.set-order") })),
      h("span", { class: "os-muted os-small", text: t(S.ordered ? "prepare.routing-groups-help" : "prepare.routing-parallel-help") })));
    if (!S.ordered) {
      rcptPanel.append(h("ol", { class: "os-rcpt-list" }, ...S.recipients.map((r, i) => card(r, i))));
      return;
    }
    const list = h("ol", { class: "os-rgroups", attrs: { "data-testid": "signing-steps" } });
    const all = groups(orders());
    all.forEach((g, gi) => {
      list.append(gap(g.order));
      const headId = `rg-${g.order}`;
      const together = g.members.length > 1;
      const earlier = button(t("prepare.step-earlier", { n: g.order }), { icon: "chevron-left", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveStep(g.order, -1) });
      earlier.querySelector("svg").classList.add("os-rot90");
      earlier.disabled = gi === 0;
      const later = button(t("prepare.step-later", { n: g.order }), { icon: "chevron-right", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveStep(g.order, 1) });
      later.querySelector("svg").classList.add("os-rot90");
      later.disabled = gi === all.length - 1;
      const box = h("div", { class: `os-rgroup${together ? " is-together" : ""}`, attrs: { role: "group", "aria-labelledby": headId, "data-step": String(g.order), "data-testid": "signing-step" } },
        h("div", { class: "os-rgroup__head" },
          h("span", { id: headId, class: "os-rgroup__title" },
            h("span", { class: "os-rgroup__n", attrs: { "aria-hidden": "true" }, text: String(g.order) }),
            h("span", { text: t("prepare.step-n", { n: g.order }) }),
            together ? h("span", { class: "os-rgroup__together" }, icon("users", { size: 16 }), h("span", { text: t("prepare.step-together", { n: g.members.length }) })) : null),
          h("span", { class: "os-spacer" }),
          all.length > 1 ? earlier : null, all.length > 1 ? later : null),
        h("ol", { class: "os-rcpt-list" }, ...g.members.map((i) => card(S.recipients[i], i))));
      // A card dropped on the box joins its step.
      // Drop targets cancel dragenter as well as dragover (HTML drag and drop): WebKit
      // sends a drag that entered an uncancelled target to the body, so it never drops.
      for (const ev of ["dragenter", "dragover"]) box.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("application/x-openseal-recipient")) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; box.classList.add("is-drop-target"); } });
      box.addEventListener("dragleave", (e) => { if (!box.contains(e.relatedTarget)) box.classList.remove("is-drop-target"); });
      box.addEventListener("drop", (e) => {
        box.classList.remove("is-drop-target");
        const from = Number(e.dataTransfer.getData("application/x-openseal-recipient"));
        if (!Number.isInteger(from) || !S.recipients[from]) return;
        e.preventDefault();
        e.stopPropagation();
        const r = S.recipients[from];
        change(() => setOrders(joinGroup(orders(), from, g.order)));
        sayStep(r);
      });
      list.append(h("li", { class: "os-rgroup-item" }, box));
    });
    list.append(gap(Math.max(...orders()) + 1));
    rcptPanel.append(list, h("p", { class: "os-muted os-small", text: t("prepare.steps-help") }));
  }
  /// A drop zone between steps: a card dropped here gets a step of its own there.
  function gap(order) {
    const z = h("li", { class: "os-rgroup__gap", attrs: { "aria-hidden": "true", "data-before": String(order), "data-testid": "step-gap" } });
    for (const ev of ["dragenter", "dragover"]) z.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("application/x-openseal-recipient")) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; z.classList.add("is-drop-target"); } });
    z.addEventListener("dragleave", () => z.classList.remove("is-drop-target"));
    z.addEventListener("drop", (e) => {
      z.classList.remove("is-drop-target");
      const from = Number(e.dataTransfer.getData("application/x-openseal-recipient"));
      if (!Number.isInteger(from) || !S.recipients[from]) return;
      e.preventDefault();
      const r = S.recipients[from];
      change(() => setOrders(newStepBefore(orders(), from, order)));
      sayStep(r);
    });
    return z;
  }
  function moveStep(order, d) {
    change(() => setOrders(moveGroup(orders(), order, d)));
    say(t("prepare.step-moved", { n: order + d }));
    setTimeout(() => rcptPanel.querySelector(`[data-step="${order + d}"] .os-rgroup__head button:not([disabled])`)?.focus(), 0);
  }

  /// One recipient's card: type, step (when ordered), name, email, access code, and
  /// the controls that move it.
  function card(r, i) {
    const c = colourOf(r.key);
    const nameId = `rn-${r.key}`;
    const mailId = `re-${r.key}`;
    const typeId = `rt-${r.key}`;
    const name = h("input", { id: nameId, class: "os-input os-input--sm", value: r.name, autocomplete: "off", placeholder: t(TPL ? "template.role-placeholder" : "prepare.name"), maxLength: 255, attrs: { "data-testid": TPL ? "role-name" : "recipient-name" } });
    const emailErr = h("p", { id: `${mailId}-err`, class: "os-field-error os-rcpt__err", attrs: { "aria-live": "polite" } });
    const email = h("input", { id: mailId, class: "os-input os-input--sm", type: "email", value: r.email, autocomplete: "email", placeholder: t("prepare.email"), attrs: { "data-testid": "recipient-email", "aria-describedby": `${mailId}-err` } });
    const typeField = selectField(t("prepare.role-for", { name: displayName(r, i) }), recipientTypes(r.type).map((ty) => [ty, t(`rtype.${ty}`)]), { id: typeId, value: r.type, labelHidden: true, size: "sm", attrs: { "data-testid": "recipient-type" } });
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
    email.addEventListener("input", () => { r.email = email.value.trim(); S.dirty = true; lookContacts(email.value); });
    name.addEventListener("input", () => lookContacts(name.value));
    if (!TPL) { name.setAttribute("list", "rc-names"); email.setAttribute("list", "rc-mails"); }
    // A contact chosen from either list fills both boxes (the other only when empty).
    const fillFrom = (v) => {
      const c = contacts.get(String(v).trim().toLowerCase());
      if (!c) return;
      if (!name.value.trim() && c.name) { name.value = c.name; r.name = c.name; }
      if (!email.value.trim()) { email.value = c.email; r.email = c.email; }
    };
    name.addEventListener("change", () => fillFrom(name.value));
    email.addEventListener("change", () => fillFrom(email.value));
    name.addEventListener("change", () => { renderPalette(); renderFieldsOnly(); renderProps(); });
    // A bad address is said beside the field when the user leaves it (S-02), not only at send.
    const checkEmail = () => {
      const bad = !!r.email && !EMAIL.test(r.email);
      emailErr.textContent = bad ? t("prepare.email-invalid") : "";
      if (bad) email.setAttribute("aria-invalid", "true"); else email.removeAttribute("aria-invalid");
    };
    email.addEventListener("change", () => { checkEmail(); renderPalette(); });
    type.addEventListener("change", () => commit("type", type.value));
    // Up and down, and a drag handle (S-04): by keyboard or pointer. With the order on,
    // they move the recipient a step (routing.js stepMove): out of a shared step first,
    // then past the next one.
    const canUp = S.ordered ? canStep(orders(), i, -1) : i > 0;
    const canDown = S.ordered ? canStep(orders(), i, 1) : i < S.recipients.length - 1;
    const up = button(t("prepare.move-up"), { icon: "chevron-left", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveRecipient(i, -1) });
    up.querySelector("svg").classList.add("os-rot90");
    up.disabled = !canUp;
    const down = button(t("prepare.move-down"), { icon: "chevron-right", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveRecipient(i, 1) });
    down.querySelector("svg").classList.add("os-rot90");
    down.disabled = !canDown;
    const grip = h("span", { class: "os-rcpt__grip", attrs: { "aria-hidden": "true", title: t("prepare.drag-reorder") } }, icon("grip-vertical", { size: 16 }));
    const del = button(t("prepare.remove-recipient", { name: displayName(r, i) }), { icon: "trash-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => removeRecipient(r) });
    // The step as a number (DocuSign's box): the same number as someone else signs with them.
    let order = h("span", { class: "os-order", attrs: { title: t("prepare.routing-order") }, text: String(orderOf(r)) });
    if (S.ordered) {
      order = h("input", { id: `ro-${r.key}`, class: "os-input os-input--sm os-order-input", type: "number", min: "1", max: "999", step: "1", inputMode: "numeric", value: String(orderOf(r)), attrs: { "aria-label": t("prepare.order-for", { name: displayName(r, i) }), "data-testid": "recipient-order" } });
      order.addEventListener("change", () => {
        const n = Number.parseInt(order.value, 10);
        if (!Number.isInteger(n) || n < 1) { order.value = String(orderOf(r)); return; }
        change(() => setOrders(setOrder(orders(), i, n)));
        sayStep(r);
        setTimeout(() => document.getElementById(`ro-${r.key}`)?.focus(), 0);
      });
    }
    // The access code is set when the recipient is created; the API has no way to
    // change it afterwards (RecipientPatch), so a saved recipient shows it read-only.
    const access = h("input", { id: `ra-${r.key}`, class: "os-input os-input--sm", value: r.id ? "" : r.accessCode, disabled: !!r.id, autocomplete: "off", inputMode: "numeric", placeholder: r.id ? t(r.hasAccessCode ? "prepare.access-code-set" : "prepare.access-code-none") : t("prepare.access-code-optional"), maxLength: 64, attrs: { "data-testid": "recipient-access-code", "aria-describedby": `ra-${r.key}-help` } });
    access.addEventListener("input", () => { r.accessCode = access.value.trim(); S.dirty = true; });
    // An emailed one-time code (SEC-A02): set when the recipient is created, like the
    // access code, so a saved recipient shows it read-only.
    const otpBox = h("input", { id: `rotp-${r.key}`, type: "checkbox", checked: !!r.emailOtp, disabled: !!r.id, attrs: { "data-testid": "recipient-email-otp" } });
    otpBox.addEventListener("change", () => { r.emailOtp = otpBox.checked; S.dirty = true; });
    const otp = h("label", { class: "os-check os-rcpt__otp", attrs: { for: `rotp-${r.key}` } }, otpBox, h("span", { text: t("prepare.email-otp") }));
    // Per-recipient options (UX-05, DocuSign's "More" on each row): how they prove who
    // they are. Set when the recipient is created (the API has no later change).
    const acting = r.type !== "cc";
    const more = TPL || !acting ? null : h("details", { class: "os-details os-rcpt__more", open: !!(r.accessCode || r.emailOtp) && !r.id, attrs: { "data-testid": "recipient-more" } },
      h("summary", {}, h("span", { text: t("prepare.more-options") }), h("span", { class: "os-sr-only", text: t(TPL ? "template.of-role" : "prepare.of-recipient", { n: i + 1 }) })),
      h("div", { class: "os-rcpt__opts" },
        h("div", { class: "os-rcpt__cell" },
          h("label", { class: "os-label os-rcpt__label", attrs: { for: `ra-${r.key}` } }, t("prepare.access-code-label"), h("span", { class: "os-sr-only", text: t("prepare.of-recipient", { n: i + 1 }) })),
          access, h("p", { id: `ra-${r.key}-help`, class: "os-help", text: t("prepare.access-code-help") })),
        otp));
    // One dense row (UX-05): type, step, name, email, options, then the row's tools.
    const tools = h("div", { class: "os-rcpt__tools" }, up, down, del);
    const li = h("li", { class: `os-rcpt os-rcpt--row${TPL ? " os-rcpt--role" : ""} os-r${c}${S.active === r.key ? " is-active" : ""}`, attrs: { "data-rkey": r.key, "data-type": r.type } },
      h("div", { class: "os-rcpt__head" },
        grip, h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
        order,
        typeField.el),
      // Visible labels, not placeholders alone (S-03); "of recipient 2" for screen readers.
      h("div", { class: "os-rcpt__cell" },
        h("label", { class: "os-label os-rcpt__label", attrs: { for: nameId } }, t("prepare.name"), h("span", { class: "os-sr-only", text: t(TPL ? "template.of-role" : "prepare.of-recipient", { n: i + 1 }) })), name),
      TPL ? null : h("div", { class: "os-rcpt__cell" },
        h("label", { class: "os-label os-rcpt__label", attrs: { for: mailId } }, t("prepare.email"), h("span", { class: "os-sr-only", text: t("prepare.of-recipient", { n: i + 1 }) })), email, emailErr),
      tools,
      more);
    // The card's controls are named after the recipient: renamed, they follow.
    name.addEventListener("change", () => {
      const who = displayName(r, S.recipients.indexOf(r));
      if (S.ordered) order.setAttribute("aria-label", t("prepare.order-for", { name: who }));
      del.setAttribute("aria-label", t("prepare.remove-recipient", { name: who }));
      del.title = t("prepare.remove-recipient", { name: who });
      typeField.el.querySelector("label")?.replaceChildren(t("prepare.role-for", { name: who }));
    });
    li.addEventListener("focusin", () => { if (S.active !== r.key) { S.active = r.key; markActive(); renderPalette(); } });
    // Drag a card by its head: onto another card or step box to sign with them (order
    // on), or to take that place (order off); onto a gap for a step of its own.
    li.draggable = true;
    li.addEventListener("dragstart", (e) => { if (e.target.closest("input, select, button")) { e.preventDefault(); return; } e.dataTransfer.setData("application/x-openseal-recipient", String(i)); e.dataTransfer.effectAllowed = "move"; li.classList.add("is-dragging"); });
    li.addEventListener("dragend", () => li.classList.remove("is-dragging"));
    if (!S.ordered) {
      for (const ev of ["dragenter", "dragover"]) li.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("application/x-openseal-recipient")) { e.preventDefault(); e.dataTransfer.dropEffect = "move"; li.classList.add("is-drop-target"); } });
      li.addEventListener("dragleave", () => li.classList.remove("is-drop-target"));
      li.addEventListener("drop", (e) => {
        const from = Number(e.dataTransfer.getData("application/x-openseal-recipient"));
        li.classList.remove("is-drop-target");
        if (!Number.isInteger(from) || from === i) return;
        e.preventDefault();
        moveRecipient(from, i - from);
        say(t("prepare.moved-to", { name: displayName(S.recipients[i], i), n: i + 1 }));
      });
    }
    return li;
  }
  function markActive() {
    for (const li of rcptPanel.querySelectorAll(".os-rcpt")) li.classList.toggle("is-active", li.dataset.rkey === S.active);
  }
  function moveRecipient(i, d) {
    const r = S.recipients[i];
    if (S.ordered) {
      if (Math.abs(d) !== 1) return;
      change(() => setOrders(stepMove(orders(), i, d)));
      sayStep(r);
    } else {
      const j = i + d;
      if (j < 0 || j >= S.recipients.length) return;
      change(() => { S.recipients.splice(i, 1); S.recipients.splice(j, 0, r); });
    }
    // Keep focus on the same control of the card that moved.
    setTimeout(() => rcptPanel.querySelector(`[data-rkey="${r.key}"] .os-rcpt__tools button[aria-label="${t(d < 0 ? "prepare.move-up" : "prepare.move-down")}"]:not([disabled])`)?.focus(), 0);
  }
  async function removeRecipient(r) {
    const n = S.fields.filter((f) => f.recipientKey === r.key).length;
    if (n && !(await confirmDialog(t("prepare.remove-recipient-title"), t("prepare.remove-recipient-text", { n }), { confirm: t("action.remove"), danger: true }))) return;
    change(() => {
      S.recipients = S.recipients.filter((x) => x !== r);
      S.fields = S.fields.filter((f) => f.recipientKey !== r.key);
      if (S.active === r.key) S.active = S.recipients[0]?.key || null;
      if (S.recipients.length) setOrders(compact(orders()));
    });
  }

  // ---- Left panel: recipients, Detect fields, the fields library -------------------------
  let detecting = false; // Detect fields is reading the pages
  // The canvas's left panel. The library's buttons are built once and never replaced: a
  // re-render between a button's mousedown and its click (a name committed on blur) would
  // swallow the click. The recipients list is rebuilt on change; it is the radio group
  // "Placing fields for" (A21): arrows move, the choice follows focus, keys 1–9 pick.
  const palFor = h("div", { class: "os-prc-list", attrs: { role: "radiogroup", "aria-label": t("prepare.placing-for") } });
  const addPerson = h("button", { type: "button", class: "os-prep-add", attrs: { "aria-label": t(TPL ? "template.add-role" : "prepare.add-recipient"), title: t(TPL ? "template.add-role" : "prepare.add-recipient") } }, icon("plus", { size: 16 }));
  addPerson.addEventListener("click", async () => { await go("recipients"); addRecipient(); });
  const palGrid = h("div", { class: "os-palette os-r1" });
  const libItems = [...LIBRARY, ...LIBRARY_MORE.map((k) => [k, null])];
  const moreAt = LIBRARY.length;
  const palForName = h("span", { class: "os-prep-h__aside" });
  libItems.forEach(([type, key], n) => {
    const b = libraryItem(type, key);
    // A pointer click arms the type (UX-05, DocuSign's and SignNow's click-to-place): the
    // next click on a page places it there. A double click keeps it armed for several.
    // Enter or Space (a click with no pointer, `detail` 0) places it on the page in view,
    // so the keyboard keeps its one-key placement.
    b.addEventListener("click", (e) => {
      if (e.detail === 0) { disarm(); addFieldInView(type); leftDock.closeSheet(); return; }
      if (e.detail > 1) return;
      toggleArm(type);
      leftDock.closeSheet();
    });
    b.addEventListener("dblclick", () => arm(type, true));
    b.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("application/x-openseal-field", type);
      e.dataTransfer.effectAllowed = "copy";
      stage.classList.add("is-dropping");
    });
    b.addEventListener("dragend", () => stage.classList.remove("is-dropping"));
    if (n === moreAt) palGrid.append(h("p", { class: "os-lib__more", text: t("prepare.more-fields") }));
    palGrid.append(b);
  });
  // Detect fields (WEB-09): the server's suggestions as ghost fields, in violet (model
  // work). Envelopes only: the API detects on an envelope's documents.
  const detectBtn = TPL ? null : h("button", { type: "button", class: "os-detectbtn", attrs: { "data-testid": "detect-fields", "aria-describedby": "detect-help", "data-os-command": "field.detect" } });
  detectBtn?.addEventListener("click", () => run("field.detect"));
  function syncDetect() {
    if (!detectBtn) return;
    detectBtn.replaceChildren(detecting ? spinner() : sparkle(), h("span", { text: t(detecting ? "prepare.detecting" : "prepare.detect") }));
    detectBtn.setAttribute("aria-busy", String(detecting));
    toolDetect?.classList.toggle("is-busy", detecting);
  }
  syncDetect();
  append(palettePanel, [
    h("div", { class: "os-prep-h" }, h("h3", { id: "rcpt-list-h", text: t(TPL ? "template.roles" : "prepare.recipients") }), addPerson),
    palFor,
    detectBtn ? h("div", { class: "os-detect" }, detectBtn, h("p", { id: "detect-help", class: "os-sr-only", text: t("prepare.detect-help") })) : null,
    h("div", { class: "os-prep-sep", attrs: { "aria-hidden": "true" } }),
    h("div", { class: "os-prep-h" }, h("h3", { id: "pal-h", text: t("prepare.fields") }), palForName),
    palGrid,
    // Touch screens get touch words (UX-05): no Enter, arrows or Shift there. Phones only;
    // a desktop has the hint chip over the page.
    h("p", { class: "os-muted os-small os-palette__hint", attrs: { "data-testid": "palette-hint" }, text: t(matchMedia("(pointer: coarse)").matches ? "prepare.palette-hint-touch" : "prepare.palette-hint") })]);

  /// The recipients list (canvas): each signer's colour chip with their number, name, role
  /// line and field count; the one fields are being placed for is tinted. Only signers take
  /// fields (P-01): the choice falls back to the first signer whenever it is not one.
  function renderPalette() {
    const sg = signers();
    if (!sg.some((r) => r.key === S.active)) S.active = sg[0]?.key || null;
    const active = recipient(S.active);
    const focused = palFor.contains(document.activeElement);
    const rows = recipientRows(S.recipients, S.fields, { order: orderOf, ordered: S.ordered });
    palFor.replaceChildren(...rows.map((row, j) => {
      const r = recipient(row.key);
      return recipientRow({
        key: row.key, n: row.n, colour: colourOf(row.key), name: displayName(r, row.n - 1),
        role: t(row.role.key, { type: t(`rtype.${r.type}`), n: row.role.params.n }), count: row.count, on: row.key === S.active,
        onPick: () => pick(row.key),
        onKey: (e) => {
          const d = e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : e.key === "ArrowUp" || e.key === "ArrowLeft" ? -1 : 0;
          if (!d) return;
          e.preventDefault();
          pick(rows[(j + d + rows.length) % rows.length].key, true);
        },
      });
    }));
    if (!rows.length) palFor.append(h("p", { class: "os-muted os-small", text: t(TPL ? "empty.roles.title" : "empty.recipients.title") }));
    if (focused) palFor.querySelector('[aria-checked="true"]')?.focus();
    palForName.textContent = active ? t("prepare.for-name", { name: firstName(displayName(active, S.recipients.indexOf(active))) }) : "";
    palGrid.className = `os-palette os-r${active ? colourOf(active.key) : 1}`;
    for (const b of toolBtns.values()) b.className = `os-tool os-r${active ? colourOf(active.key) : 1}`;
    markArmed();
  }
  function pick(key, focus = false) {
    S.active = key;
    markActive();
    renderPalette();
    if (S.ghosts.length) { renderGhosts(); renderFloats(); }
    if (armed) renderFloats();
    if (focus) palFor.querySelector('[aria-checked="true"]')?.focus();
    const i = S.recipients.findIndex((r) => r.key === key);
    say(t("prepare.placing-for-name", { name: displayName(S.recipients[i], i) }));
  }
  /// The name the canvas uses in its short lines ("for Jordan"): the first word.
  const firstName = (name) => String(name).trim().split(/\s+/)[0] || name;

  // ---- Documents ---------------------------------------------------------------------------
  /// Step 1: each document as a card with its first page, page count, order and remove.
  /// Saved documents keep their order (the API has no reorder) and stay.
  function renderDocs() {
    clear(docsPanel);
    docsPanel.append(h("div", { class: "os-step-head" },
      h("div", {},
        h("h2", { id: "docs-h", class: "os-step-head__title", text: t("prepare.documents") }),
        h("p", { class: "os-muted", text: t(TPL ? "template.documents-lede" : "wizard.documents-lede") })),
      S.docs.length ? button(t("prepare.add-pdf"), { icon: "file-up", command: "document.add", onClick: () => fileInput.click() }) : null));
    syncNext();
    if (TPL) {
      // A template is named where it starts (UX-05); the same name as on Review and save.
      const name = h("input", { id: "tpl-name", class: "os-input", value: S.subject, maxLength: 255, autocomplete: "off", placeholder: t("template.name-example"), attrs: { "data-testid": "template-name-start" } });
      name.addEventListener("input", () => { subject.value = name.value; subject.dispatchEvent(new Event("input")); });
      docsPanel.append(h("div", { class: "os-fieldrow os-tplname" }, h("label", { class: "os-label", attrs: { for: "tpl-name" }, text: t("template.name-start") }), name));
    }
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
          d.id && !TPL ? null : button(t("prepare.remove-doc", { name: d.name }), { icon: "trash-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => removeDoc(d) }))));
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
  /// Lay the documents' pages out in the one scroll container (docview.js: fit width,
  /// painted near the view only) and put the fields on them.
  let stageKey = null;
  async function renderStage() {
    stageKey = S.docs.map((d) => d.key).join();
    stage.querySelector(":scope > .os-empty")?.remove();
    if (!S.docs.length) {
      dv.setPages([]);
      thumbs.build();
      stage.append(emptyState({
        illus: "documents", title: t("empty.documents.title"), text: t("empty.documents.text"),
        action: button(t("prepare.add-pdf"), { icon: "file-up", variant: "primary", size: "lg", onClick: () => fileInput.click() }),
        testId: "empty-stage",
      }));
      zoom.sync();
      return;
    }
    dv.setPages(S.docs.flatMap((d) => d.pages.map((p, i) => ({ key: d.key, n: i + 1, total: d.pages.length, name: d.name, width: p.width, height: p.height, pdf: pdfs.get(d.key) }))));
    // Each document's name above its first page (UX-05), so a page says whose document it is.
    if (S.docs.length > 1) dv.pages.forEach((p, i) => { if (p.n === 1) dv.els[i].el.before(h("div", { class: "os-docband", attrs: { "aria-hidden": "true", "data-testid": "doc-band" } }, icon("file-text", { size: 16 }), h("span", { class: "os-trunc", text: p.name }), h("span", { class: "os-muted", text: p.total === 1 ? t("prepare.page-one") : t("prepare.pages-long", { n: p.total }) }))); });
    dv.els.forEach(({ overlay }, i) => {
      const p = dv.pages[i];
      const d = S.docs.find((x) => x.key === p.key);
      for (const ev of ["dragenter", "dragover"]) overlay.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("application/x-openseal-field")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } });
      overlay.addEventListener("drop", (e) => {
        const type = e.dataTransfer.getData("application/x-openseal-field");
        if (!type) return;
        e.preventDefault();
        stage.classList.remove("is-dropping");
        const box = overlay.getBoundingClientRect();
        addField(type, d, p.n, (e.clientX - box.left) / dv.scale, (e.clientY - box.top) / dv.scale);
      });
      // Armed (UX-05): the click places; a press neither draws a marquee nor selects text.
      // A click, not the press, so a finger that scrolls the page places nothing.
      overlay.addEventListener("pointerdown", (e) => {
        if (armed) { if (e.pointerType !== "touch") e.preventDefault(); return; }
        if (e.target === overlay) startMarquee(e, overlay, p.key, p.n);
      });
      overlay.addEventListener("click", (e) => {
        if (armed && (e.target === overlay || e.target === armGhost || armGhost.contains(e.target))) placeArmed(e, overlay, p.key, p.n);
      });
    });
    thumbs.build();
    rail.classList.toggle("is-single", S.docs.length === 1);
    markOcr(thumbsBox, ocrPages);
    renderFieldsOnly();
    renderProps();
    zoom.sync();
    showPreparing(dv.pages.length);
  }
  /// The canvas's loading page: a skeleton with "Preparing n pages…" over the stage until
  /// the first page has painted (docview drops `is-loading` from it), so the stage is
  /// never blank and nothing shifts when the page arrives.
  let preparing = null;
  let preparingWatch = null;
  function showPreparing(n) {
    preparingWatch?.disconnect();
    preparing?.remove();
    const first = dv.els[0]?.el;
    if (n && first && !first.classList.contains("is-loading")) { preparing = null; return; }
    preparing = h("div", { class: "os-prepload-wrap" }, loadingPage(n));
    centre.append(preparing);
    if (!first) return;
    preparingWatch = new MutationObserver(() => {
      if (first.classList.contains("is-loading") && first.isConnected) return;
      preparingWatch.disconnect();
      preparing?.remove();
      preparing = null;
    });
    preparingWatch.observe(first, { attributes: true, attributeFilter: ["class"] });
  }
  const pageIndex = (docKey, page) => dv.pages.findIndex((p) => p.key === docKey && p.n === page);

  function overlayFor(f) {
    return stage.querySelector(`.os-page__overlay[data-doc="${f.docKey}"][data-page="${f.page}"]`);
  }
  function fieldLabel(f) {
    const r = recipient(f.recipientKey);
    const i = S.recipients.indexOf(r);
    const base = t("prepare.field-aria", { type: t(`ftype.${f.type}`), name: displayName(r, i), page: f.page, req: f.required ? t("prepare.required-suffix") : "" });
    // The name starts with the label the box shows, when it shows one (SC 2.5.3).
    return f.label ? `${f.label}, ${base}` : base;
  }
  function renderFieldsOnly() {
    for (const n of stage.querySelectorAll(".os-field")) n.remove();
    for (const f of S.fields) {
      const ov = overlayFor(f);
      if (!ov) continue;
      const el = h("button", { type: "button", class: `os-field os-r${colourOf(f.recipientKey)}${f.required ? " is-required" : ""}${previewKey && f.recipientKey !== previewKey ? " is-other" : ""}${S.selected === f.key ? " is-selected" : ""}`, attrs: { "data-fkey": f.key, "data-field": f.type, "aria-label": fieldLabel(f), "aria-pressed": String(S.selected === f.key) } },
        icon(FIELD_ICON[f.type] || "text-cursor-input", { size: 16 }),
        h("span", { class: "os-field__label", text: f.label || t(`ftype.${f.type}`) }),
        // Whose field it is, beside its colour (F-02): the recipient's first name, drawn by CSS
        // from data-who so the visible text stays the field's label (SC 2.5.3).
        h("span", { class: "os-field__who", attrs: { "aria-hidden": "true", "data-who": firstName(displayName(recipient(f.recipientKey), S.recipients.findIndex((r) => r.key === f.recipientKey))) } }),
        h("span", { class: "os-field__handle", attrs: { "aria-hidden": "true" } }));
      place(el, f);
      el.addEventListener("focus", () => { if (S.selected !== f.key && !multi.has(f.key)) select(f.key, false); });
      el.addEventListener("mousedown", (e) => { if (e.shiftKey) e.preventDefault(); });
      el.addEventListener("pointerdown", (e) => {
        if (e.shiftKey && e.button === 0) { e.preventDefault(); toggleInSelection(f.key); return; }
        startDrag(e, f, e.target.classList.contains("os-field__handle") ? "resize" : "move");
      });
      el.addEventListener("keydown", (e) => { if (e.shiftKey && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleInSelection(f.key); } });
      ov.append(el);
    }
    renderGhosts();
    if (multi.size) markSelection();
    thumbs.badges((i) => S.fields.filter((f) => pageIndex(f.docKey, f.page) === i).length, (n) => t(n === 1 ? "prepare.thumb-one" : "prepare.thumb-n", { n }));
  }
  /// A field box in percentages of its page: PDF points × the view's scale at any zoom,
  /// without a relayout per zoom step.
  function place(el, f) {
    const pg = pageOf(f);
    el.style.left = `${(f.x / pg.width) * 100}%`;
    el.style.top = `${(f.y / pg.height) * 100}%`;
    el.style.width = `${(f.width / pg.width) * 100}%`;
    el.style.height = `${(f.height / pg.height) * 100}%`;
  }
  function pageOf(f) {
    const d = S.docs.find((x) => x.key === f.docKey);
    return d?.pages[f.page - 1] || { width: 612, height: 792 };
  }

  // ---- Moving, resizing, snapping guides and marquee (WEB-09) ----------------------------
  // A field (or the selected group, as one box) snaps its edges and centre to the page's
  // and to other fields' on its page while it moves or resizes, and a line shows what it
  // lined up with (guides.js); Alt held turns snapping off. Tolerance is 6 screen pixels
  // at any zoom. Dragging on an empty part of a page draws a marquee that selects the
  // fields it touches (Shift adds to the selection). The keyboard has the same:
  // Ctrl/Cmd+A selects the page's fields, Alt+Shift+arrows jump to the next guide, and
  // a nudge shows the guides it lands on.
  const SNAP_PX = 6;
  let guideTimer = null;
  /// Draw `guides` (`[{axis, at}]`, points) on `ov`, the page `pg`; none clears them.
  function drawGuides(ov, pg, guides = []) {
    clearTimeout(guideTimer);
    for (const g of stage.querySelectorAll(".os-guide")) g.remove();
    if (!ov) return;
    for (const g of guides) {
      const line = h("div", { class: `os-guide os-guide--${g.axis}`, attrs: { "aria-hidden": "true", "data-testid": "snap-guide" } });
      if (g.axis === "x") line.style.left = `${(g.at / pg.width) * 100}%`;
      else line.style.top = `${(g.at / pg.height) * 100}%`;
      ov.append(line);
    }
  }
  /// Show the guides a field now lies on for a moment (after a keyboard move).
  function flashGuides(moved) {
    const f = moved[0];
    if (!f) return;
    const pg = pageOf(f);
    const keys = new Set(moved.map((x) => x.key));
    const others = S.fields.filter((x) => x.docKey === f.docKey && x.page === f.page && !keys.has(x.key));
    drawGuides(overlayFor(f), pg, touching(moved.length > 1 ? bounds(moved) : f, others, pg));
    guideTimer = setTimeout(() => drawGuides(null), 900);
  }
  const elOf = (f) => stage.querySelector(`.os-field[data-fkey="${f.key}"]`);

  function startDrag(e, f, mode) {
    if (e.button !== 0) return;
    e.preventDefault();
    const el = e.currentTarget;
    // A field of the selected group moves the group, as one box.
    const group = mode === "move" && multi.size > 1 && multi.has(f.key)
      ? S.fields.filter((x) => multi.has(x.key) && x.docKey === f.docKey && x.page === f.page) : null;
    if (!group) select(f.key, false);
    el.focus({ preventScroll: true });
    try { el.setPointerCapture(e.pointerId); } catch { /* listeners are on window anyway */ }
    const moving = group || [f];
    const starts = new Map(moving.map((x) => [x.key, { x: x.x, y: x.y, width: x.width, height: x.height }]));
    const box0 = bounds([...starts.values()]);
    const others = S.fields.filter((x) => x.docKey === f.docKey && x.page === f.page && !starts.has(x.key));
    const ov = overlayFor(f);
    const start = { x: e.clientX, y: e.clientY };
    const before = snapshot();
    let moved = false;
    for (const x of moving) elOf(x)?.classList.add("is-dragging");
    const move = (ev) => {
      const dx = (ev.clientX - start.x) / dv.scale;
      const dy = (ev.clientY - start.y) / dv.scale;
      if (!moved && Math.abs(dx) + Math.abs(dy) < 1) return;
      moved = true;
      const pg = pageOf(f);
      const tol = SNAP_PX / dv.scale;
      let guides = [];
      if (mode === "move") {
        let b = clampRect({ ...box0, x: box0.x + dx, y: box0.y + dy }, pg);
        if (!ev.altKey) { const s = snapRect(b, others, pg, tol); b = clampRect(s.rect, pg); guides = s.guides; }
        for (const x of moving) {
          const s0 = starts.get(x.key);
          Object.assign(x, clampRect({ ...s0, x: s0.x + (b.x - box0.x), y: s0.y + (b.y - box0.y) }, pg));
          const n = elOf(x);
          if (n) place(n, x);
        }
      } else {
        const s0 = starts.get(f.key);
        let r = { ...s0, width: s0.width + dx, height: s0.height + dy };
        if (!ev.altKey) { const s = snapRect(r, others, pg, tol, "resize"); r = s.rect; guides = s.guides; }
        Object.assign(f, clampRect(r, pg));
        place(el, f);
      }
      drawGuides(ov, pg, guides);
      el.classList.toggle("is-snapped", guides.length > 0);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", up);
      for (const x of moving) elOf(x)?.classList.remove("is-dragging", "is-snapped");
      drawGuides(null);
      // A click (no move) on one field of a group selects just that field.
      if (!moved && group) select(f.key, false);
      if (moved) {
        S.undo.push(before); S.redo = []; S.dirty = true;
        el.classList.add("is-dropped");
        setTimeout(() => el.classList.remove("is-dropped"), 250);
        renderProps();
        if (group) say(t("prepare.multi-moved", { n: group.length }));
      }
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", up);
  }

  /// Marquee selection on an empty part of a page (mouse and pen; a finger scrolls).
  function startMarquee(e, ov, docKey, pageN) {
    if (e.button !== 0 || e.pointerType === "touch") { if (e.button === 0) select(null); return; }
    e.preventDefault();
    stage.focus({ preventScroll: true });
    const pg = S.docs.find((d) => d.key === docKey)?.pages[pageN - 1];
    if (!pg) return;
    const at = (ev) => {
      const b = ov.getBoundingClientRect();
      return [Math.min(Math.max((ev.clientX - b.left) / dv.scale, 0), pg.width), Math.min(Math.max((ev.clientY - b.top) / dv.scale, 0), pg.height)];
    };
    const [sx, sy] = at(e);
    const kept = e.shiftKey ? selection().map((f) => f.key) : [];
    let band = null;
    const move = (ev) => {
      const [ex, ey] = at(ev);
      const r = fromCorners(sx, sy, ex, ey);
      if (!band && r.width * dv.scale + r.height * dv.scale < 4) return;
      if (!band) { band = h("div", { class: "os-marquee", attrs: { "aria-hidden": "true", "data-testid": "marquee" } }); ov.append(band); }
      band.style.left = `${(r.x / pg.width) * 100}%`;
      band.style.top = `${(r.y / pg.height) * 100}%`;
      band.style.width = `${(r.width / pg.width) * 100}%`;
      band.style.height = `${(r.height / pg.height) * 100}%`;
      const hits = S.fields.filter((f) => f.docKey === docKey && f.page === pageN && intersects(r, f)).map((f) => f.key);
      setSelection([...new Set([...kept, ...hits])], false);
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", up);
      if (!band) { if (!kept.length) select(null); return; }
      band.remove();
      const n = selection().length;
      say(n > 1 ? t("prepare.multi-n", { n }) : n === 1 ? t("prepare.selected", { label: fieldLabel(selection()[0]) }) : t("prepare.none-selected"));
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", up);
  }

  /// Shift+click (or Shift+Enter/Space) adds a field to the selection or takes it out
  /// (F-03); the group then moves with the arrows and lines up from the panel.
  const multi = new Set();
  function markSelection() {
    for (const n of stage.querySelectorAll(".os-field")) {
      const on = n.dataset.fkey === S.selected || multi.has(n.dataset.fkey);
      n.classList.toggle("is-selected", on);
      n.setAttribute("aria-pressed", String(on));
    }
  }
  function toggleInSelection(key) {
    if (!multi.size && S.selected) multi.add(S.selected);
    if (multi.has(key)) multi.delete(key); else multi.add(key);
    if (multi.size === 1) { const [only] = multi; multi.clear(); S.selected = only; } else S.selected = multi.has(key) ? key : [...multi][0] || null;
    markSelection();
    renderProps();
    say(multi.size > 1 ? t("prepare.multi-n", { n: multi.size }) : "");
  }
  const selection = () => (multi.size > 1 ? S.fields.filter((f) => multi.has(f.key)) : S.fields.filter((f) => f.key === S.selected));
  /// Select exactly `keys` (a marquee, Ctrl/Cmd+A): one is a plain selection, several a group.
  function setSelection(keys, announce = true) {
    multi.clear();
    if (keys.length > 1) for (const k of keys) multi.add(k);
    S.selected = keys.length ? keys[keys.length - 1] : null;
    markSelection();
    renderProps();
    propsFab.hidden = !S.selected;
    if (announce) say(keys.length > 1 ? t("prepare.multi-n", { n: keys.length }) : "");
  }
  function select(key, focus = true) {
    const changed = S.selected !== key;
    S.selected = key;
    multi.clear();
    markSelection();
    const f = S.fields.find((x) => x.key === key);
    if (f && focus) {
      // Smooth scroll-to-field when it is out of view; focus without the browser's jump.
      const el = stage.querySelector(`.os-field[data-fkey="${key}"]`);
      const r = el?.getBoundingClientRect();
      const s = stage.getBoundingClientRect();
      if (r && (r.top < s.top || r.bottom > s.bottom || r.left < s.left || r.right > s.right)) dv.scrollToBox(pageIndex(f.docKey, f.page), f);
      el?.focus({ preventScroll: true });
    }
    renderProps();
    if (f && changed) say(t("prepare.selected", { label: fieldLabel(f) }));
    // Phones: the properties are a bottom sheet, opened from the "Field settings" button.
    propsFab.hidden = !f;
    if (!f) rightDock.closeSheet();
  }

  // ---- Click-to-place (UX-05; canvas: pick a tool, then click the page) -------------------
  // An armed type follows the pointer as a ghost of its default size, the page takes a
  // crosshair, and a dark chip says what the next click does; a click on a page places
  // the field centred there. Escape (field.deselect), Select (V) or a second click on the
  // type disarms; a double-clicked type stays armed until then.
  let armed = null; // {type, sticky}
  const armGhost = h("div", { class: "os-armghost", attrs: { "aria-hidden": "true", "data-testid": "arm-ghost" } });
  function markArmed() {
    for (const b of palGrid.querySelectorAll(".os-palette__item")) {
      const on = armed?.type === b.dataset.fieldType;
      b.classList.toggle("is-armed", on);
      b.setAttribute("aria-pressed", String(on));
    }
    for (const [k, b] of toolBtns) {
      const on = k === "select" ? !armed : armed?.type === k;
      b.classList.toggle("is-on", on);
      b.setAttribute("aria-pressed", String(on));
    }
    stage.classList.toggle("is-armed", !!armed);
    if (!armed) armGhost.remove();
  }
  function arm(type, sticky) {
    if (!S.docs.length) { toast(t("prepare.add-pdf-first"), "info"); fileInput.click(); return; }
    armed = { type, sticky };
    markArmed();
    armGhost.replaceChildren(icon(FIELD_ICON[type] || "text-cursor-input", { size: 16 }), h("span", { text: t(`ftype.${type}`) }));
    say(t(sticky ? "prepare.armed-sticky" : "prepare.armed", { type: t(`ftype.${type}`) }));
    renderFloats();
  }
  /// A tool or library row pressed: arms its kind, or disarms it when it is armed already.
  function toggleArm(type) {
    if (armed?.type === type && !armed.sticky) disarm(true); else arm(type, false);
  }
  function disarm(announce = false) {
    if (!armed) return;
    armed = null;
    markArmed();
    if (announce) say(t("prepare.disarmed"));
    renderFloats();
  }

  // ---- Floating layers (canvas): template banner on top; hint or suggestions at the foot --
  let tplState = "none"; // none | offer | applied | done
  let tplOffer = null; // {suggestion, template, roles, fields}
  let tplApplied = null; // {name, n}
  let tplTimer = null;
  function renderFloats() {
    const onFields = step === "fields";
    const top = [];
    if (onFields && tplState === "offer" && tplOffer) {
      top.push(templateBanner({
        name: tplOffer.suggestion.label || tplOffer.template.name || "", pct: percent(tplOffer.suggestion),
        roles: tplOffer.roles, fields: tplOffer.fields, onApply: () => run("editor.apply-template"), onSkip: () => run("editor.skip-template"),
      }));
    } else if (onFields && tplState === "applied" && tplApplied) {
      top.push(appliedChip({ name: tplApplied.name, n: tplApplied.n, onUndo: () => undoTemplate() }));
    }
    topLayer.replaceChildren(...top);
    const who = signerFor();
    const whoName = who ? firstName(displayName(who, S.recipients.indexOf(who))) : t("prepare.recipient-n", { n: S.recipients.length + 1 });
    const bottom = [];
    if (onFields && armed) bottom.push(armHint({ kind: t(`ftype.${armed.type}`), who: whoName, colour: who ? colourOf(who.key) : 1, onCancel: () => disarm(true) }));
    else if (onFields && S.ghosts.length) bottom.push(ghostBar({ n: S.ghosts.length, who: whoName, onAccept: () => run("field.accept-suggestions"), onDismiss: () => run("field.dismiss-suggestions") }));
    bottomLayer.replaceChildren(...bottom);
  }
  /// The ghost under the pointer, on the page it is over (points → % of that page).
  function moveGhost(e) {
    if (!armed || e.pointerType === "touch") return;
    const ov = e.target.closest?.(".os-page__overlay");
    if (!ov) { armGhost.remove(); return; }
    const p = dv.pages.find((x) => x.key === ov.dataset.doc && String(x.n) === ov.dataset.page);
    if (!p) return;
    const box = ov.getBoundingClientRect();
    const r = placeAt(armed.type, (e.clientX - box.left) / dv.scale, (e.clientY - box.top) / dv.scale, p);
    if (armGhost.parentElement !== ov) ov.append(armGhost);
    place(armGhost, { ...r, docKey: p.key, page: p.n });
    armGhost.className = `os-armghost os-r${S.active ? colourOf(S.active) : 1}`;
  }
  stage.addEventListener("pointermove", moveGhost);
  stage.addEventListener("pointerleave", () => armGhost.remove());
  /// A click on an empty part of a page with a type armed: the field, centred there.
  function placeArmed(e, ov, docKey, pageN) {
    if (!armed || e.button !== 0) return false;
    const doc = S.docs.find((d) => d.key === docKey);
    if (!doc) return false;
    const box = ov.getBoundingClientRect();
    const type = armed.type;
    if (!armed.sticky) disarm();
    addField(type, doc, pageN, (e.clientX - box.left) / dv.scale, (e.clientY - box.top) / dv.scale);
    return true;
  }

  let lastPlaced = null;
  function addField(type, doc, page, cx, cy) {
    let r = recipient(S.active);
    if (!takesFields(r)) r = signers()[0];
    if (!r) r = addRecipient(false);
    const pg = doc.pages[page - 1];
    const rect = placeAt(type, cx, cy, pg);
    const f = { key: newKey("f"), id: null, docKey: doc.key, recipientKey: r.key, type, page, ...rect, required: requiredByDefault(type), label: "", ...newMembers(type) };
    change(() => { S.fields.push(f); S.selected = f.key; });
    lastPlaced = f.key;
    propsFab.hidden = false;
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
  function inView() {
    const p = dv.pages[dv.current] || dv.pages[0];
    return p ? { doc: S.docs.find((d) => d.key === p.key), page: p.n } : null;
  }
  function addFieldInView(type) {
    if (!S.docs.length) { toast(t("prepare.add-pdf-first"), "info"); fileInput.click(); return; }
    const where = inView();
    if (!where?.doc) return;
    const { doc, page } = where;
    const pg = doc.pages[page - 1];
    const here = S.fields.filter((f) => f.docKey === doc.key && f.page === page);
    const size = DEFAULT_SIZE[type];
    // Where the user is looking (F-01): just below the field placed last on this page,
    // lined up with it; else the top third of the part of the page that is on screen.
    const last = lastPlaced && here.find((f) => f.key === lastPlaced);
    let cx = pg.width / 2;
    let cy = pg.height / 3;
    if (last) {
      cx = last.x + size.width / 2;
      cy = last.y + last.height + 12 + size.height / 2;
    } else {
      const el = dv.els[pageIndex(doc.key, page)]?.el;
      const r = el?.getBoundingClientRect();
      const s = stage.getBoundingClientRect();
      if (r && r.height) {
        const top = Math.max(r.top, s.top);
        const bottom = Math.min(r.bottom, s.bottom);
        if (bottom > top) cy = ((top - r.top) + (bottom - top) / 3) / dv.scale;
        // Across too (UX-05): a page wider than the view (phones, zoomed in) gets the
        // field in the middle of the part on screen, not of the page.
        const left = Math.max(r.left, s.left);
        const right = Math.min(r.right, s.right);
        if (right > left && r.width > s.width) cx = ((left - r.left) + (right - left) / 2) / dv.scale;
      }
    }
    // A margin below each field keeps keyboard-placed fields apart, not touching.
    const spot = freeSpot(here.map((f) => ({ ...f, height: f.height + 12 })), size, pg, cx, cy);
    addField(type, doc, page, spot.x + size.width / 2, spot.y + size.height / 2);
  }

  // ---- Detected fields (WEB-09; canvas: dashed ghosts with ✓ and ×) ------------------------
  // The server's suggestions (`POST …/documents/{doc}/detect-fields`, detect.js) are drawn
  // as dashed ghosts in the colour of the signer fields are being placed for, each with its
  // kind, its cue and an accept (✓) and a dismiss (×) button; a floating bar accepts or
  // dismisses them all. Each of these is one undo step. While detection runs, a violet
  // sweep crosses the pages and the button says "Reading the page…". A draft is saved
  // first, since detection reads the stored documents. A suggestion whose source is a
  // scan's text (`source: "ocr"`) says so; the server's detector has no such source today.
  /// Who accepted suggestions are for: the signer being placed for, else the first.
  const signerFor = () => { const r = recipient(S.active); return takesFields(r) ? r : signers()[0] || null; };
  const ghostLabel = (g) => (g.label || t(`ftype.${g.type}`));
  function renderGhosts() {
    for (const n of stage.querySelectorAll(".os-ghost")) n.remove();
    const who = signerFor();
    const colour = who ? colourOf(who.key) : 1;
    for (const g of S.ghosts) {
      const ov = overlayFor(g);
      if (!ov) continue;
      const where = { type: ghostLabel(g), page: pageIndex(g.docKey, g.page) + 1 };
      const accept = h("button", { type: "button", class: "os-ghost__accept", attrs: { "aria-label": t("prepare.ghost-accept", where), title: t("prepare.accept"), "data-testid": "ghost" } }, "✓");
      const dismiss = h("button", { type: "button", class: "os-ghost__dismiss", attrs: { "aria-label": t("prepare.ghost-dismiss", where), title: t("prepare.dismiss") } }, "×");
      accept.addEventListener("click", (e) => { e.stopPropagation(); acceptGhosts([g]); });
      dismiss.addEventListener("click", (e) => { e.stopPropagation(); dismissGhosts([g]); });
      for (const b of [accept, dismiss]) {
        b.addEventListener("keydown", (e) => {
          if (e.key !== "Delete" && e.key !== "Backspace") return;
          e.preventDefault();
          e.stopPropagation();
          dismissGhosts([g]);
        });
      }
      const cue = g.source === "ocr" ? t("prepare.from-scan") : g.cue && g.cue !== ghostLabel(g) ? g.cue : "";
      const el = h("div", { class: `os-ghost os-r${colour}`, attrs: { "data-gkey": g.key, "data-field": g.type } },
        h("span", { class: "os-ghost__text", attrs: { "aria-hidden": "true" } }, h("span", { class: "os-ghost__label", text: ghostLabel(g) }), cue ? h("span", { class: "os-ghost__cue", text: cue }) : null),
        h("span", { class: "os-ghost__btns" }, accept, dismiss));
      place(el, g);
      ov.append(el);
    }
  }
  /// After a ghost goes, focus the next one (or the document), so the keyboard keeps its place.
  function focusNextGhost(i) {
    const keys = S.ghosts.map((x) => x.key);
    const next = keys[Math.min(i, keys.length - 1)];
    setTimeout(() => (next ? stage.querySelector(`.os-ghost[data-gkey="${next}"] .os-ghost__accept`) : stage)?.focus({ preventScroll: false }), 0);
  }
  function acceptGhosts(list) {
    if (!list.length) return;
    const i = S.ghosts.indexOf(list[0]);
    let r = signerFor();
    if (!r) r = addRecipient(false);
    const made = list.map((g) => ({ key: newKey("f"), id: null, docKey: g.docKey, recipientKey: r.key, type: g.type, page: g.page, x: g.x, y: g.y, width: g.width, height: g.height, required: requiredByDefault(g.type), label: g.label || "", ...newMembers(g.type) }));
    const gone = new Set(list);
    change(() => { S.ghosts = S.ghosts.filter((g) => !gone.has(g)); S.fields.push(...made); });
    say(made.length === 1 ? t("prepare.field-added", { label: fieldLabel(made[0]) }) : t("prepare.ghosts-accepted", { n: made.length, name: displayName(r, S.recipients.indexOf(r)) }));
    if (list.length === 1) focusNextGhost(i);
  }
  function dismissGhosts(list) {
    if (!list.length) return;
    const i = S.ghosts.indexOf(list[0]);
    const gone = new Set(list);
    change(() => { S.ghosts = S.ghosts.filter((g) => !gone.has(g)); });
    say(t(list.length === 1 ? "prepare.ghost-dismissed" : "prepare.ghosts-dismissed", { n: list.length }));
    if (list.length === 1) focusNextGhost(i);
  }
  /// The sweep over every laid-out page while detection runs (decorative; reduced motion
  /// keeps a still tint).
  function setDetecting(on) {
    detecting = on;
    syncDetect();
    stage.classList.toggle("is-detecting", on);
    for (const n of stage.querySelectorAll(".os-sweepbox")) n.remove();
    if (on) for (const { overlay } of dv.els) overlay.append(h("div", { class: "os-sweepbox", attrs: { "aria-hidden": "true" } }, h("div", { class: "os-sweepbox__bar os-sweep" })));
  }
  async function detect() {
    if (!S.docs.length) { toast(t("prepare.add-pdf-first"), "info"); fileInput.click(); return; }
    if (detecting) return;
    disarm();
    setDetecting(true);
    say(t("prepare.detecting"));
    try {
      // Detection reads the stored documents: save the draft first when any is new.
      if (!S.id || S.docs.some((d) => !d.id)) await save();
      setDetecting(true); // a save re-lays the pages
      const items = [];
      let truncated = false;
      for (const d of S.docs.filter((x) => x.id)) {
        const out = await ctx.api.detectFields(S.id, d.id);
        items.push(...(out?.items || []));
        truncated ||= !!out?.truncated;
      }
      const ghosts = suggestionsFrom(items, S.docs, S.fields, () => newKey("g"));
      if (!ghosts.length) { toast(t("prepare.detect-none"), "info"); say(t("prepare.detect-none")); return; }
      change(() => { S.ghosts = ghosts; S.selected = null; });
      const who = signerFor();
      const msg = t("prepare.detect-found", { n: ghosts.length, name: who ? displayName(who, S.recipients.indexOf(who)) : t("prepare.recipient-n", { n: S.recipients.length + 1 }) });
      say(truncated ? `${msg} ${t("prepare.detect-truncated")}` : msg);
      if (truncated) toast(t("prepare.detect-truncated"), "info");
      const first = ghosts[0];
      dv.scrollToBox(pageIndex(first.docKey, first.page), first);
    } catch (err) {
      if (!ctx.failed(err)) showSaveError(err);
    } finally {
      setDetecting(false);
    }
  }

  // ---- Properties ------------------------------------------------------------------------
  let advancedOpen = true;
  const propOpen = {}; // section → open, while the editor is open (UX-05)
  // A validation preset chosen whose settings are not typed yet (a pattern, a length):
  // field key → kind, so the panel shows its inputs before there is a rule to store.
  const kindChosen = new Map();
  function renderProps() {
    clear(props);
    if (multi.size > 1) {
      // A Shift-selected group (F-03): line it up, size it alike, space it, or delete it.
      const b = (label, ic, how) => button(label, { icon: ic, size: "sm", onClick: () => arrange(how), attrs: { "data-testid": `arrange-${how}` } });
      props.append(
        h("div", { class: "os-props__head" }, h("h3", { class: "os-props__title", text: t("prepare.multi-n", { n: multi.size }) })),
        h("p", { class: "os-muted os-small", text: t("prepare.multi-help") }),
        h("p", { class: "os-label", text: t("prepare.align") }),
        h("div", { class: "os-actions" }, b(t("prepare.align-left"), "arrow-right", "left"), b(t("prepare.align-top"), "chevron-down", "top"), b(t("prepare.align-right"), "chevron-left", "right"), b(t("prepare.align-bottom"), "chevron-down", "bottom")),
        h("p", { class: "os-label", text: t("prepare.arrange") }),
        h("div", { class: "os-actions" }, b(t("prepare.same-size"), "copy", "size"), b(t("prepare.space-evenly"), "list", "vspace")),
        h("div", { class: "os-actions os-props__danger" }, button(t("prepare.delete-n", { n: multi.size }), { icon: "trash-2", size: "sm", variant: "danger", onClick: () => run("field.delete") })));
      return;
    }
    const f = S.fields.find((x) => x.key === S.selected);
    if (!f) { renderOverview(); return; }
    const pg = pageOf(f);
    const set = (k, v) => {
      S.undo.push(snapshot()); S.redo = [];
      f[k] = v; S.dirty = true;
      renderFieldsOnly();
      syncNext();
    };
    // The canvas's head: the kind's chip in its recipient's colour, its name, Delete.
    const del = h("button", { type: "button", class: "os-props__delete", text: t("prepare.delete-field"), attrs: { "aria-label": t("prepare.delete-this-field") } });
    del.addEventListener("click", () => run("field.delete"));
    props.append(h("div", { class: `os-props__head os-r${colourOf(f.recipientKey)}` },
      h("span", { class: "os-props__chip", attrs: { "aria-hidden": "true" }, text: KIND_GLYPH[f.type] || "T" }),
      h("h3", { class: "os-props__title" }, t(`ftype.${f.type}`), h("span", { class: "os-sr-only", text: t("prepare.field-props", { type: t(`ftype.${f.type}`) }).slice(t(`ftype.${f.type}`).length) })), del));
    // A member set or cleared (blank removes it, as the server stores it), one undo step.
    const setM = (k, v) => {
      const blank = v == null || v === false || v === "" || (Array.isArray(v) && !v.length);
      if (blank ? !(k in f) : JSON.stringify(f[k]) === JSON.stringify(v)) return;
      S.undo.push(snapshot()); S.redo = [];
      if (blank) delete f[k]; else f[k] = v;
      S.dirty = true;
      renderFieldsOnly();
    };
    const textIn = (id, labelKey, value, onSet, { help = null, max = 255, type = "text", area = false } = {}) => {
      const i = h(area ? "textarea" : "input", { id, class: `os-input${area ? " os-textarea" : ""}`, value: value ?? "", maxLength: max, ...(area ? { rows: 3 } : { type }), attrs: help ? { "aria-describedby": `${id}-help` } : {} });
      i.addEventListener("change", () => onSet(i.value));
      return h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: id }, text: t(labelKey) }), i, help ? h("p", { id: `${id}-help`, class: "os-help", text: t(help) }) : null);
    };
    const check = (id, labelKey, on, onSet) => {
      const i = h("input", { id, type: "checkbox", checked: !!on });
      i.addEventListener("change", () => onSet(i.checked));
      return h("label", { class: "os-check", attrs: { for: id } }, i, h("span", { text: t(labelKey) }));
    };
    /// A section of the panel (UX-05: General, Formatting, Validation, Options), open by
    /// default, remembered while the editor is open.
    const section = (key, ...body) => {
      const d = h("details", { class: "os-details os-props__sec", open: propOpen[key] !== false, attrs: { "data-testid": `props-${key}` } },
        h("summary", { text: t(`prepare.props-${key}`) }), ...body);
      d.addEventListener("toggle", () => { propOpen[key] = d.open; });
      return d;
    };
    // Assigned to (canvas): one row per recipient who can take the field, the owner ticked.
    const owners = S.recipients.map((r, i) => [r, i]).filter(([r]) => takesFields(r) || r.key === f.recipientKey)
      .map(([r, i]) => ({ key: r.key, name: displayName(r, i), colour: colourOf(r.key), on: r.key === f.recipientKey }));
    props.append(h("div", { class: "os-props__group" },
      h("span", { id: "fp-assign-h", class: "os-props__cap", text: t(TPL ? "template.assigned-to" : "prepare.assigned-to") }),
      assignList(owners, (key) => { if (key !== f.recipientKey) { set("recipientKey", key); renderProps(); renderPalette(); } })));
    // Behaviour: Required (a switch) and the tooltip.
    const behaviour = [h("span", { class: "os-props__cap", text: t("prepare.behaviour") })];
    if (takesInput(f.type)) {
      const sw = switchButton(t("prepare.required"), { checked: f.required, onChange: (v) => { set("required", v); } , attrs: { id: "fp-required" } });
      behaviour.push(h("div", { class: "os-props__switch" }, h("span", { attrs: { "aria-hidden": "true" }, text: t("prepare.required") }), sw.el));
    } else behaviour.push(h("p", { class: "os-muted os-small", text: t(`prepare.auto-${f.type}`) }));
    if (!TPL) behaviour.push(textIn("fp-tooltip", "prepare.tooltip", f.tooltip, (v) => setM("tooltip", v.trim()), { max: 1000 }));
    props.append(h("div", { class: "os-props__group" }, ...behaviour));
    const general = [];
    if (!TPL && f.type === "note") {
      // A note is the sender's text, shown to the recipient as written.
      general.push(textIn("fp-note", "prepare.note-text", f.value?.text, (v) => setM("value", v.trim() ? { text: v.trim() } : null), { max: 2000, area: true }));
    }
    if (!TPL && (TYPED.has(f.type) || f.type === "checkbox")) {
      // DocuSign's "Read only" with a sender's value: the recipient sees it, cannot change it.
      general.push(check("fp-readonly", "prepare.read-only", f.read_only, (v) => { setM("read_only", v); renderProps(); }));
      if (f.type === "checkbox") general.push(check("fp-checked", "prepare.checked-value", f.value?.checked, (v) => setM("value", v ? { checked: true } : null)));
      else general.push(textIn("fp-value", f.read_only ? "prepare.value-fixed" : "prepare.value-start", f.value?.text, (v) => setM("value", v ? { text: v } : null), { help: "prepare.value-help", max: 4000 }));
    }
    general.push(textIn("fp-label", "prepare.label", f.label, (v) => set("label", v.trim()), { help: "prepare.label-help" }));
    // A template keeps only Required and Label until templatesync.js sends the rest (UX-11); the
    // panel offers nothing that would vanish on save (UX-05 review).
    if (TPL) general.push(h("p", { class: "os-muted os-small", text: t("prepare.template-settings-later"), attrs: { "data-testid": "props-template-note" } }));
    if (!TPL && TYPED.has(f.type)) general.push(textIn("fp-placeholder", "prepare.placeholder", f.placeholder, (v) => setM("placeholder", v.trim())));
    props.append(section("general", ...general));
    if (!TPL && CHOICE.has(f.type)) {
      const opts = textIn("fp-options", "prepare.options", (f.options || []).join("\n"), (v) => { setM("options", optionsFrom(v)); renderProps(); }, { help: "prepare.options-help", max: 50000, area: true });
      const body = [opts];
      if (f.type === "dropdown") body.push(check("fp-custom", "prepare.allow-custom", f.allow_custom, (v) => setM("allow_custom", v)));
      if (!(f.options || []).length) body.push(h("p", { class: "os-field-error", text: t("prepare.options-none") }));
      props.append(section("options", ...body));
    }
    if (!TPL && (TYPED.has(f.type) || ["name", "email", "date_signed"].includes(f.type))) {
      const fmt = f.format || {};
      const setF = (k, v) => { const next = { ...(f.format || {}) }; if (v === "" || v == null || v === false) delete next[k]; else next[k] = v; setM("format", Object.keys(next).length ? next : null); };
      const size = h("input", { id: "fp-font-size", class: "os-input os-input--sm", type: "number", min: "6", max: "72", step: "1", inputMode: "numeric", value: fmt.font_size ?? "", placeholder: t("prepare.fmt-auto") });
      size.addEventListener("change", () => { const n = Number.parseInt(size.value, 10); setF("font_size", Number.isInteger(n) && n >= 6 && n <= 72 ? String(n) : null); });
      const body = [
        selectField(t("prepare.font"), [["", t("prepare.fmt-default")], ["helvetica", "Helvetica"], ["times", "Times"], ["courier", "Courier"]], { id: "fp-font", value: fmt.font_family || "", size: "sm", onChange: (v) => setF("font_family", v) }).el,
        h("div", { class: "os-fieldrow" }, h("label", { class: "os-label", attrs: { for: "fp-font-size" }, text: t("prepare.font-size") }), size),
        selectField(t("prepare.text-align"), [["", t("prepare.fmt-default")], ["left", t("prepare.align-left-text")], ["center", t("prepare.align-center-text")], ["right", t("prepare.align-right-text")]], { id: "fp-align", value: fmt.align || "", size: "sm", onChange: (v) => setF("align", v) }).el,
      ];
      if (TYPED.has(f.type)) body.push(check("fp-mask", "prepare.mask", fmt.mask, (v) => setF("mask", v)));
      props.append(section("format", ...body));
    }
    if (!TPL && (f.type === "text" || f.type === "number")) {
      // Validation (DocuSign's and SignNow's presets): what the recipient's value must be.
      const v = f.validation || {};
      const kind = f.type === "number" ? "number" : (v.kind || kindChosen.get(f.key) || "");
      const opts = { min: v.min, max: v.max, pattern: v.pattern, maxLength: v.kind === "length" ? v.max : "", message: v.message };
      const apply = (k, val) => { opts[k] = val; const next = validationFrom(kindNow, opts); setM("validation", next); };
      let kindNow = kind;
      const body = [];
      if (f.type === "text") {
        body.push(selectField(t("prepare.validate"), [["", t("prepare.validate-none")], ["email", t("prepare.validate-email")], ["phone", t("prepare.validate-phone")], ["zip", t("prepare.validate-zip")], ["ssn", t("prepare.validate-ssn")], ["number", t("prepare.validate-number")], ["length", t("prepare.validate-length")], ["regex", t("prepare.validate-regex")]],
          { id: "fp-validate", value: kind, size: "sm", onChange: (k) => { kindNow = k; kindChosen.set(f.key, k); setM("validation", validationFrom(k, opts)); renderProps(); props.querySelector("#fp-validate")?.focus(); } }).el);
      }
      if (kindNow === "number") {
        body.push(h("div", { class: "os-geo" },
          textIn("fp-min", "prepare.min", opts.min, (x) => apply("min", x), { type: "text" }),
          textIn("fp-max", "prepare.max", opts.max, (x) => apply("max", x), { type: "text" })));
      }
      if (kindNow === "length") body.push(textIn("fp-maxlen", "prepare.max-length", opts.maxLength, (x) => apply("maxLength", x), { type: "number" }));
      if (kindNow === "regex") body.push(textIn("fp-pattern", "prepare.pattern", opts.pattern, (x) => apply("pattern", x), { help: "prepare.pattern-help", max: 1000 }));
      if (kindNow) body.push(textIn("fp-vmsg", "prepare.validate-message", opts.message, (x) => apply("message", x.trim()), { max: 500 }));
      props.append(section("validation", ...body));
    }
    // Position (canvas: X and Y in points), with the size, open by default (UX-05's
    // Advanced): typed coordinates are clamped to the page.
    const geo = h("div", { class: "os-geo" });
    for (const k of ["x", "y", "width", "height"]) {
      const id = `fp-${k}`;
      const inp = h("input", { id, class: "os-geo__input", type: "number", step: "1", min: "0", value: String(Math.round(f[k] * 100) / 100), attrs: { "aria-label": t(`prepare.geo-${k}`) } });
      inp.addEventListener("change", () => {
        const v = Number.parseFloat(inp.value);
        if (!Number.isFinite(v)) { inp.value = String(f[k]); return; }
        S.undo.push(snapshot()); S.redo = [];
        Object.assign(f, clampRect({ ...f, [k]: v }, pg));
        S.dirty = true;
        renderFieldsOnly(); renderProps();
      });
      geo.append(h("label", { class: "os-geo__item", attrs: { for: id } }, h("span", { class: "os-geo__k", text: t(`prepare.geo-${k}-short`) }), inp, h("span", { class: "os-geo__unit", attrs: { "aria-hidden": "true" }, text: "pt" })));
    }
    const adv = h("details", { class: "os-details os-advanced os-props__sec", open: advancedOpen },
      h("summary", { text: t("prepare.position") }), geo, h("p", { class: "os-muted os-small", text: t("prepare.position-help", { page: pageIndex(f.docKey, f.page) + 1 }) }));
    adv.addEventListener("toggle", () => { advancedOpen = adv.open; });
    props.append(adv);
    props.append(h("div", { class: "os-actions os-props__foot" },
      button(t("prepare.duplicate"), { icon: "copy", size: "sm", onClick: () => run("field.duplicate") })));
  }

  /// The right panel with no field selected (canvas): "No fields yet" with Detect fields
  /// and Place a signature; otherwise "Ready to send?" with the checks (preparemodel.js
  /// sendChecks) and, when the model found personal data, the amber card.
  function renderOverview() {
    if (!S.docs.length) { props.append(h("p", { class: "os-muted os-small", text: t("prepare.props-none") })); return; }
    if (!S.fields.length && !S.ghosts.length) {
      const detectNow = TPL ? null : h("button", { type: "button", class: "os-btn os-btn--ml os-btn--md os-btn--block", text: t("prepare.detect"), attrs: { "data-testid": "empty-detect" } });
      detectNow?.addEventListener("click", () => run("field.detect"));
      const sig = h("button", { type: "button", class: "os-btn os-btn--subtle os-btn--md os-btn--block", text: t("prepare.place-signature"), attrs: { "data-testid": "empty-place-signature" } });
      sig.addEventListener("click", () => { arm("signature", false); stage.focus({ preventScroll: true }); });
      const empty = emptyState({ illus: "fields", title: t("prepare.no-fields"), text: t(tplState === "offer" ? "prepare.empty-fields-tpl" : TPL ? "prepare.empty-fields-template" : "prepare.empty-fields"), action: h("div", { class: "os-empty__actions" }, detectNow, sig), testId: "empty-fields" });
      empty.classList.add("os-rise");
      props.append(empty);
      return;
    }
    const checks = sendChecks({ recipients: S.recipients, fields: S.fields, ghosts: S.ghosts.length, ocrPages }, (r) => displayName(r, S.recipients.indexOf(r)));
    props.append(h("div", { class: "os-props__headrow" }, h("h3", { class: "os-props__title", text: t(TPL ? "prepare.ready-save" : "prepare.ready-send") })),
      h("div", { class: "os-props__body" }, checksList(checks),
        pii ? piiCard(pii) : null,
        mlOn ? h("p", { class: "os-props__fine", text: t("prepare.ml-fine") }) : null));
  }

  function renderAll() {
    renderDocs();
    renderRecipients();
    renderPalette();
    renderFieldsOnly();
    renderProps();
    syncNext();
    renderFloats();
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
        // Empty means the account's default, and says so (R-03).
        const i = h("input", { id, class: "os-input os-input--num", type: "number", min: "0", max: "999", step: "1", value: value == null ? "" : String(value), inputMode: "numeric", placeholder: t("prepare.default") });
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
    // Summary first (R-01): documents, then who does what, in order, with the fields
    // each one fills by kind, so a missing signature shows before Send.
    const sum = h("section", { class: "os-card", attrs: { "aria-labelledby": "rv-sum-h" } }, h("h3", { id: "rv-sum-h", class: "os-card__title", text: t("wizard.summary") }));
    sum.append(h("p", { class: "os-summary__docs" }, icon("file-text", { size: 16 }),
      h("span", { text: S.docs.length ? S.docs.map((d) => t(d.pages.length === 1 ? "wizard.doc-page-one" : "wizard.doc-pages", { name: d.name, n: d.pages.length })).join(", ") : t("prepare.no-docs") })));
    const ul = h("ul", { class: "os-summary" });
    S.recipients.forEach((r, i) => {
      const mine = S.fields.filter((f) => f.recipientKey === r.key);
      const kinds = FIELD_TYPES.map((ty) => [ty, mine.filter((f) => f.type === ty).length]).filter(([, c]) => c)
        .map(([ty, c]) => (c > 1 ? `${t(`ftype.${ty}`)} ×${c}` : t(`ftype.${ty}`))).join(", ");
      ul.append(h("li", { class: `os-summary__item os-r${colourOf(r.key)}`, attrs: { "data-testid": "summary-recipient" } },
        h("span", { class: "os-order", text: String(orderOf(r)) }),
        h("span", { class: "os-summary__who" }, h("strong", { text: displayName(r, i) }), TPL ? null : h("span", { class: "os-muted os-small", text: r.email || t("wizard.no-email") })),
        h("span", { class: "os-muted os-small", text: t(`rtype.${r.type}`) }),
        // A signer with no fields is a warning here, with its fix, not only at Send (UX-05).
        takesFields(r) && !mine.length
          ? h("span", { class: "os-small os-summary__fields os-summary__warn", attrs: { "data-testid": "summary-no-fields" } },
            icon("triangle-alert", { size: 16 }), h("span", { text: t("wizard.no-fields") }),
            button(t("wizard.place-fields"), { size: "sm", icon: "arrow-right", attrs: { "aria-label": t("wizard.place-fields-for", { name: displayName(r, i) }) }, onClick: async () => { await go("fields"); pick(r.key); } }))
          : h("span", { class: "os-small os-summary__fields", text: takesFields(r) ? `${fieldsN(mine.length)}: ${kinds}` : t(r.type === "cc" ? "wizard.gets-copy" : "wizard.reviews") })));
    });
    if (!S.recipients.length) ul.append(h("li", { class: "os-muted", text: t(TPL ? "empty.roles.title" : "empty.recipients.title") }));
    sum.append(ul);
    // Preview as each recipient who fills fields (UX-05): the document with their fields.
    const sg = signers();
    if (sg.length && S.docs.length) {
      sum.append(h("div", { class: "os-previewstrip", attrs: { role: "group", "aria-labelledby": "rv-prev-h", "data-testid": "preview-strip" } },
        h("span", { id: "rv-prev-h", class: "os-label", text: t("wizard.preview-as") }),
        ...sg.map((r) => {
          const i = S.recipients.indexOf(r);
          const b = button(displayName(r, i), { size: "sm", icon: "eye", attrs: { "aria-label": t("wizard.preview-as-name", { name: displayName(r, i) }) }, onClick: async () => { await go("fields"); previewAs(r.key); } });
          b.classList.add(`os-r${colourOf(r.key)}`, "os-previewstrip__btn");
          return b;
        })));
    }
    reviewPanel.querySelector(".os-step-head").after(sum);
  }
  /// "1 field" / "3 fields" (T-02).
  const fieldsN = (n) => t(n === 1 ? "wizard.fields-one" : "wizard.fields-n", { n });

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
    const prevActive = Math.max(0, S.recipients.findIndex((r) => r.key === S.active));
    const prevAccess = new Map(S.recipients.map((r) => [r.id, r.accessCode]));
    const steps = fromServer(recs.map((r) => r.routing_order));
    S.recipients = recs.map((r, i) => ({ key: newKey("r"), id: r.id, name: r.name || "", email: r.email || "", type: RECIPIENT_TYPES.includes(r.type) ? r.type : "signer", accessCode: prevAccess.get(r.id) || "", hasAccessCode: (r.auth || []).includes("access_code"), emailOtp: (r.auth || []).includes("email_otp"), order: steps[i] }));
    // Signers all at one step with copies after them is the switch off; anything else is steps.
    S.ordered = !isAllAtOnce(steps, (i) => S.recipients[i].type !== "cc");
    const rkey = new Map(S.recipients.map((r) => [r.id, r.key]));
    const dkey = new Map(S.docs.map((d) => [d.id, d.key]));
    S.fields = (env.fields || []).map((f) => {
      const p = fromWire(f.placement);
      if (!p || !dkey.has(f.document_id)) return null;
      return { key: newKey("f"), id: f.id, docKey: dkey.get(f.document_id), recipientKey: rkey.get(f.recipient_id), type: f.type, page: p.page, x: p.x, y: p.y, width: p.width, height: p.height, required: !!f.required, label: f.label || "", ...membersOf(f), server: JSON.stringify({ r: f.recipient_id, p: f.placement, q: !!f.required, l: f.label || "", m: membersOf(f) }) };
    }).filter(Boolean);
    // Keep whom fields are being placed for across a save (the list keeps its order).
    S.active = S.recipients[prevActive]?.key || S.recipients[0]?.key || null;
    S.selected = null;
    S.undo = []; S.redo = [];
    S.dirty = false;
  }

  // ---- Loading a template (WEB-09) ----------------------------------------------------------
  /// A saved template into the editor: its documents (fetched and opened), its roles in
  /// routing order as the people, and its fields bound to them by `role_id`.
  async function loadTemplate(tp) {
    S.tplServer = tp;
    S.subject = tp.name || "";
    S.emailSubject = tp.email_subject || "";
    S.message = tp.email_message || "";
    subject.value = S.subject;
    title.textContent = S.subject.trim() || newTitle();
    title.title = title.textContent;
    const docs = [];
    for (const d of [...(tp.documents || [])].sort((a, b) => (a.ord ?? 0) - (b.ord ?? 0))) {
      const bytes = new Uint8Array(await (await ctx.api.templates.documentContent(tp.id, d.id)).arrayBuffer());
      const pdf = await openPdf(bytes.slice());
      const doc = { key: newKey("d"), id: d.id, name: d.name, bytes, pages: pdf.pages };
      pdfs.set(doc.key, pdf);
      docs.push(doc);
    }
    S.docs = docs;
    const roles = [...(tp.roles || [])].sort((a, b) => (a.routing_order ?? 1) - (b.routing_order ?? 1));
    const steps = fromServer(roles.map((r) => r.routing_order));
    S.recipients = roles.map((r, i) => ({ key: newKey("r"), id: r.id, name: r.name || "", email: "", type: RECIPIENT_TYPES.includes(r.type) ? r.type : "signer", accessCode: "", order: steps[i] }));
    S.ordered = !isAllAtOnce(steps, (i) => S.recipients[i].type !== "cc");
    const rkey = new Map(S.recipients.map((r) => [r.id, r.key]));
    const dkey = new Map(S.docs.map((d) => [d.id, d.key]));
    S.fields = (tp.fields || []).map((f) => {
      const p = fromWire(f.placement || f);
      if (!p || !dkey.has(f.document_id) || !rkey.has(f.role_id)) return null;
      return { key: newKey("f"), id: f.id, docKey: dkey.get(f.document_id), recipientKey: rkey.get(f.role_id), type: f.type, page: p.page, x: p.x, y: p.y, width: p.width, height: p.height, required: !!f.required, label: f.label || "" };
    }).filter(Boolean);
    S.active = S.recipients[0]?.key || null;
    S.selected = null;
    S.undo = []; S.redo = [];
    S.dirty = false;
  }

  // ---- Saving ------------------------------------------------------------------------------
  function recipientBody(r) {
    const body = { type: r.type, name: r.name || t("prepare.recipient-n", { n: S.recipients.indexOf(r) + 1 }), email: r.email, routing_order: orderOf(r) };
    if (r.type !== "cc" && r.accessCode) { body.auth = ["access_code"]; body.access_code = r.accessCode; }
    if (r.type !== "cc" && r.emailOtp && r.email) body.auth = (body.auth || []).concat(["email_otp"]);
    return body;
  }
  function fieldBody(f, recipientRef, documentRef) {
    const body = { recipient: recipientRef, document: documentRef, type: f.type, ...toWire(f.page, f) };
    if (f.required && takesInput(f.type)) body.required = true;
    if (f.label) body.label = f.label;
    Object.assign(body, membersOf(f));
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
    saving = true;
    syncStatus();
    const had = !!S.id;
    try { await saveNow(); savedAt = new Date(); } finally { saving = false; syncStatus(); }
    renderAll();
    await renderStage();
    // A new draft now has an id: the model's results for it can be read.
    if (!had && S.id) loadIntelligence();
  }

  // ---- Autosave (P-04) -----------------------------------------------------------------
  // A draft saves itself 4 s after the last change, as DocuSign's and SignNow's do, when
  // what is there can be saved (every recipient named with a valid email, at least one
  // document) and the user is not typing or dragging. It is quiet: no toast; the status
  // says "Saving…" then "Saved at …", and a failure leaves "Unsaved changes" for the
  // explicit Save, which reports errors. Templates save only on request.
  let autosaveTimer = null;
  const AUTOSAVE_MS = 4000;
  function scheduleAutosave() {
    if (TPL) return;
    clearTimeout(autosaveTimer);
    autosaveTimer = setTimeout(autosave, AUTOSAVE_MS);
  }
  const savable = () => S.docs.length > 0 && S.recipients.every((r) => r.name.trim() && EMAIL.test(r.email));
  async function autosave() {
    if (!dirty || saving || !frame.isConnected) return;
    const a = document.activeElement;
    const typing = a && (a.matches?.("input, textarea, select") || a.isContentEditable);
    // Not while suggestions wait for a decision (WEB-17): a save reloads the draft and
    // empties undo, which would take back the undo of an accept or a dismiss.
    if (typing || S.ghosts.length || document.querySelector(".os-field.is-dragging, dialog[open]") || !savable()) { scheduleAutosave(); return; }
    // Keep the selection and focus across the reload of state that a save does.
    const sel = S.fields.find((f) => f.key === S.selected);
    const hadFocus = sel && a?.dataset?.fkey === sel.key;
    const same = sel && { type: sel.type, page: sel.page, x: sel.x, y: sel.y, doc: S.docs.findIndex((d) => d.key === sel.docKey) };
    try {
      await save();
    } catch { saving = false; syncStatus(); return; }
    if (same) {
      const docKey = S.docs[same.doc]?.key;
      const f = S.fields.find((x) => x.type === same.type && x.page === same.page && x.docKey === docKey && Math.abs(x.x - same.x) < 0.01 && Math.abs(x.y - same.y) < 0.01);
      if (f) select(f.key, hadFocus);
    }
  }
  async function saveNow() {
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
        const now = JSON.stringify({ r: rid(f.recipientKey), p: toWire(f.page, f), q: !!f.required, l: f.label || "", m: membersOf(f) });
        if (now === f.server) continue;
        const body = fieldBody(f, rid(f.recipientKey), did(f.docKey));
        // Every member named: null removes one the sender cleared (a JSON merge, UX-05).
        const members = Object.fromEntries(MEMBERS.map((k) => [k, blankMember(f[k]) ? null : f[k]]));
        await ctx.api.patchField(S.id, f.id, await etagNow(), { recipient_id: body.recipient, placement: toWire(f.page, f), required: !!body.required, label: f.label || null, ...members });
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
  }

  /// What stops sending, each with the step that fixes it (A16).
  function problems() {
    const out = [];
    if (!S.docs.length) out.push({ text: t("send.need-doc"), step: "documents" });
    if (!signers().length) out.push({ text: t("send.need-signer"), step: "recipients" });
    // Suggestions neither accepted nor dismissed would be lost on send (UX-05).
    if (S.ghosts.length) out.push({ text: t(S.ghosts.length === 1 ? "send.need-suggestion-one" : "send.need-suggestions", { n: S.ghosts.length }), step: "fields" });
    S.recipients.forEach((r, i) => {
      if (!r.name.trim()) out.push({ text: t("send.need-name", { n: i + 1 }), step: "recipients", focus: `#rn-${r.key}` });
      if (!EMAIL.test(r.email)) out.push({ text: t("send.need-email", { name: displayName(r, i) }), step: "recipients", focus: `#re-${r.key}` });
      if (takesFields(r) && !S.fields.some((f) => f.recipientKey === r.key)) out.push({ text: t("send.need-field", { name: displayName(r, i) }), step: "fields", recipient: r.key });
      // A copy recipient signs nothing: fields left on one would be dropped (P-02).
      const cc = !takesFields(r) ? S.fields.filter((f) => f.recipientKey === r.key).length : 0;
      if (cc) out.push({ text: t("send.cc-fields", { name: displayName(r, i), n: cc }), step: "fields" });
    });
    // A radio group or dropdown with no options cannot be answered (UX-05).
    for (const f of S.fields.filter((x) => CHOICE.has(x.type) && !(x.options || []).length)) {
      const r = recipient(f.recipientKey);
      out.push({ text: t("send.need-options", { type: t(`ftype.${f.type}`), name: displayName(r, S.recipients.indexOf(r)) }), step: "fields", field: f.key });
    }
    return out;
  }

  /// The problems in a side panel: each one a button that opens the step and the place to fix it.
  function showProblems(list, title) {
    return openPanel({
      id: "problems",
      title,
      description: t("send.problems-text"),
      build(body, close) {
        body.append(h("ul", { class: "os-problems" }, ...list.map((p) => {
          const fix = button(t("send.fix"), { size: "sm", icon: "arrow-right", onClick: async () => {
            close(null);
            await go(p.step);
            if (p.recipient) pick(p.recipient);
            if (p.field) select(p.field);
            if (p.focus) setTimeout(() => document.querySelector(p.focus)?.focus(), 0);
          } });
          return h("li", {}, icon("triangle-alert", { size: 16 }), h("span", { class: "os-problems__text", text: p.text }), fix);
        })));
      },
      actions: [{ label: t("action.ok"), variant: "primary", value: null }],
    });
  }

  async function send() {
    const list = problems();
    if (list.length) { await showProblems(list, t("send.problems-title")); return; }
    // Who gets it now, who in turn, who reviews and who only gets a copy (R-02; UX-05:
    // with signing steps only the first step is emailed at once).
    const subj = S.subject.trim() || t("envelope.untitled");
    const text = sendSummary(S.recipients.map((r, i) => ({ name: displayName(r, i), type: r.type, order: orderOf(r) })), subj).map(([k, p]) => t(k, p)).join(" ");
    if (!(await confirmDialog(t("send.confirm-title"), text, { confirm: t("prepare.send") }))) return;
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
    saving = false;
    syncStatus();
    status.replaceChildren(icon("circle-alert", { size: 16 }), h("span", { text: t("prepare.not-saved") }));
    const extra = (err.errors || []).map((e) => `${e.pointer || ""} ${e.code || ""}`.trim()).filter(Boolean);
    toast(extra.length ? `${errorMessage(err)} — ${extra.slice(0, 3).join("; ")}` : errorMessage(err), "error");
  }

  // ---- Template mode: save ---------------------------------------------------------------
  function templateProblems() {
    const out = [];
    if (!S.subject.trim()) out.push({ text: t("template.need-name"), step: "review", focus: "#env-subject" });
    if (!S.recipients.length) out.push({ text: t("template.need-role"), step: "recipients" });
    else if (!signers().length) out.push({ text: t("send.need-signer"), step: "recipients" });
    return out;
  }

  /// The editor's template as templatesync.js takes it; `roles` from `rolesFrom`.
  function templateState(roles) {
    return {
      details: { name: S.subject.trim(), email_subject: S.emailSubject.trim(), email_message: S.message },
      roles: S.recipients.map((r, i) => ({ key: r.key, id: r.id, ...roles[i] })),
      docs: S.docs,
      // A field whose document is gone (an undo after removing it) is not sent.
      fields: S.fields.filter((f) => S.docs.some((d) => d.key === f.docKey)).map((f) => ({ ...f, roleKey: f.recipientKey })),
    };
  }

  async function saveTemplate() {
    const list = templateProblems();
    if (list.length) { await showProblems(list, t("template.problems-title")); return; }
    await busy(saveBtn, async () => {
      saving = true; syncStatus();
      const roles = rolesFrom(S.recipients, (r) => orderOf(r));
      try {
        if (!S.tplId) {
          const tpl = await ctx.api.templates.create({
            name: S.subject.trim(),
            ...(S.emailSubject.trim() ? { email_subject: S.emailSubject.trim() } : {}),
            ...(S.message ? { email_message: S.message } : {}),
            roles,
          });
          // The roles come back with ids; their names are unique (rolesFrom).
          S.tplId = tpl.id;
          S.tplServer = tpl;
          S.recipients.forEach((r, i) => { r.id = (tpl.roles || []).find((x) => x.name === roles[i].name)?.id || null; });
        }
        const st = templateState(roles);
        const plan = templatePlan(S.tplServer, st, { takesInput });
        try {
          S.tplServer = await applyTemplate(ctx.api, S.tplId, st, plan, { takesInput });
        } finally {
          // What was made has its id now, even after a failure part-way.
          for (const r of st.roles) { const x = S.recipients.find((y) => y.key === r.key); if (x) x.id = r.id; }
          for (const f of st.fields) { const x = S.fields.find((y) => y.key === f.key); if (x) x.id = f.id; }
        }
      } catch (err) {
        saving = false;
        if (!ctx.failed(err)) showSaveError(err);
        return;
      }
      saving = false;
      savedAt = new Date();
      S.dirty = false;
      toast(t("template.saved"), "success");
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

  // ---- Document intelligence on the editor (WEB-18; ml.js) ------------------------------
  // Read when a draft is saved and opened: the template match (the banner), scanned pages
  // read by OCR (thumbnail badges and a check) and personal data (the amber card). When
  // the server has no model service (404, CS-ML-0011) nothing here shows. A suggestion is
  // only ever applied by a person's click.
  let mlOn = false;
  let ocrPages = [];
  let pii = null;
  let mlSeq = 0;
  async function loadIntelligence() {
    if (TPL || !S.id) return;
    const seq = ++mlSeq;
    const st = await mlStatus();
    if (seq !== mlSeq) return;
    mlOn = st.available;
    if (!mlOn) return;
    let items = [];
    try { items = await loadSuggestions(S.id, { refresh: true }); } catch (err) { if (!isUnavailable(err)) items = []; }
    if (seq !== mlSeq) return;
    pii = featureOn(st, "personal_data") ? piiSummary(items) : null;
    const offer = featureOn(st, "template_matching") && tplState === "none" ? templateOffer(items) : null;
    if (offer) await prepareOffer(offer);
    if (featureOn(st, "ocr")) ocrPages = await readOcrPages();
    if (seq !== mlSeq) return;
    markOcr(thumbsBox, ocrPages);
    renderProps();
    renderFloats();
  }
  /// The offer is shown only when the template can place something on this draft.
  async function prepareOffer(offer) {
    try {
      const { template } = await ctx.api.templates.get(offer.template_id);
      const plan = applyTemplatePlan(template, { docs: S.docs, recipients: S.recipients }, newKey);
      if (!plan.fields.length) return;
      tplOffer = { suggestion: offer, template, roles: (template.roles || []).length, fields: plan.fields.length, accepted: false };
      tplState = "offer";
    } catch { /* no template to apply: no offer */ }
  }
  async function readOcrPages() {
    const offsets = [];
    let before = 0;
    for (const d of S.docs) { offsets.push(before); before += d.pages.length; }
    const analyses = await Promise.all(S.docs.map((d) => (d.id ? ctx.api.getAnalysis(S.id, d.id).catch(() => null) : null)));
    return ocrPagesFrom(analyses, offsets);
  }
  /// Apply the matched template (the person's click): its roles and fields land on this
  /// draft as one undo step; the suggestion is recorded as accepted.
  function applyMatchedTemplate() {
    const o = tplOffer;
    if (!o || tplState !== "offer") return;
    const plan = applyTemplatePlan(o.template, { docs: S.docs, recipients: S.recipients }, newKey);
    change(() => {
      S.recipients = plan.recipients;
      setOrders(compact(orders()));
      S.fields.push(...plan.fields);
      S.selected = null;
      if (!S.recipients.some((r) => r.key === S.active)) S.active = signers()[0]?.key || null;
    });
    tplApplied = { name: o.suggestion.label || o.template.name || "", n: plan.fields.length };
    tplState = "applied";
    say(t("prepare.tpl-applied", tplApplied));
    renderAll();
    clearTimeout(tplTimer);
    tplTimer = setTimeout(() => { if (tplState === "applied") { tplState = "done"; renderFloats(); } }, 6000);
    if (!o.accepted) {
      o.accepted = true;
      acceptSuggestion(S.id, o.suggestion.id).catch((err) => { o.accepted = false; if (!isUnavailable(err)) toastError(err); });
    }
  }
  /// Undo on the applied chip: the edit before the template, and the offer again.
  function undoTemplate() {
    run("edit.undo");
    tplState = "offer";
    clearTimeout(tplTimer);
    renderAll();
  }

  /// Single-key tools on the fields step (canvas: V, S, I, D, N, E, O, T, C): a bare letter
  /// while nothing is being typed and no dialog is open. Runs before the global table so
  /// N picks Full name here rather than a new envelope.
  function onToolKey(e) {
    if (step !== "fields" || !frame.isConnected || e.defaultPrevented) return;
    if (document.querySelector("dialog[open]") || document.body.classList.contains("has-sheet")) return;
    const a = document.activeElement;
    if (a && (a.matches?.("input, textarea, select") || a.isContentEditable)) return;
    const tool = toolForKey(e);
    if (!tool) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    run(tool === "select" ? "field.disarm-select" : `field.arm-${tool}`);
  }
  window.addEventListener("keydown", onToolKey, true);
  // ---- Commands -----------------------------------------------------------------------------
  const sel = () => S.fields.find((f) => f.key === S.selected);
  /// Run `fn` on every selected field (one, or the Shift-selected group), as one undo step.
  const withSel = (fn) => () => {
    const all = selection();
    const f = sel() || all[0];
    if (!f) return;
    const before = snapshot();
    for (const x of all) fn(x);
    S.undo.push(before); S.redo = []; S.dirty = true;
    for (const x of all) {
      const el = stage.querySelector(`.os-field[data-fkey="${x.key}"]`);
      if (el) { place(el, x); el.setAttribute("aria-label", fieldLabel(x)); }
    }
    flashGuides(all);
    renderProps();
    say(all.length > 1 ? t("prepare.multi-moved", { n: all.length }) : t("prepare.field-at", { x: Math.round(f.x), y: Math.round(f.y), w: Math.round(f.width), h: Math.round(f.height) }));
  };
  /// Line the selected group up (F-03): edges, centres, sizes, or even spacing.
  function arrange(how) {
    const all = selection();
    if (all.length < 2) return;
    const before = snapshot();
    const minX = Math.min(...all.map((f) => f.x));
    const minY = Math.min(...all.map((f) => f.y));
    const maxR = Math.max(...all.map((f) => f.x + f.width));
    const maxB = Math.max(...all.map((f) => f.y + f.height));
    const first = sel() || all[0];
    if (how === "left") for (const f of all) f.x = minX;
    if (how === "top") for (const f of all) f.y = minY;
    if (how === "right") for (const f of all) f.x = maxR - f.width;
    if (how === "bottom") for (const f of all) f.y = maxB - f.height;
    if (how === "size") for (const f of all) { f.width = first.width; f.height = first.height; }
    if (how === "vspace") {
      const byY = [...all].sort((a, b) => a.y - b.y);
      const total = byY.reduce((s, f) => s + f.height, 0);
      const gap = (maxB - minY - total) / (byY.length - 1);
      let y = minY;
      for (const f of byY) { f.y = y; y += f.height + gap; }
    }
    for (const f of all) Object.assign(f, clampRect(f, pageOf(f)));
    S.undo.push(before); S.redo = []; S.dirty = true;
    for (const f of all) { const el = stage.querySelector(`.os-field[data-fkey="${f.key}"]`); if (el) place(el, f); }
    say(t("prepare.arranged", { n: all.length }));
  }
  const hasSel = () => !!sel();
  /// Alt+Shift+arrow: the selection (as one box) to the next guide on that side
  /// (guides.js nextStop): another field's edge or centre, or the page's.
  const jump = (axis, dir) => () => {
    const all = selection();
    const f = all[0];
    if (!f) return;
    const pg = pageOf(f);
    const keys = new Set(all.map((x) => x.key));
    const box = all.length > 1 ? bounds(all) : f;
    const pos = nextStop(box, S.fields.filter((x) => x.docKey === f.docKey && x.page === f.page && !keys.has(x.key)), pg, axis, dir);
    if (pos === null) { say(t("prepare.no-guide")); return; }
    const d = pos - box[axis];
    withSel((x) => Object.assign(x, clampRect({ ...x, [axis]: x[axis] + d }, pageOf(x))))();
  };
  /// Ctrl/Cmd+A on the fields step: every field on the page in view (the marquee's
  /// keyboard equivalent); not while typing, where it selects the text.
  const typingNow = () => { const a = document.activeElement; return !!a && (a.matches?.("input, textarea, select") || a.isContentEditable); };
  const pageFields = () => { const w = inView(); return w ? S.fields.filter((f) => f.docKey === w.doc.key && f.page === w.page) : []; };
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
  reg("field.jump-left", t("cmd.field.jump"), jump("x", -1));
  reg("field.jump-right", t("cmd.field.jump"), jump("x", 1));
  reg("field.jump-up", t("cmd.field.jump"), jump("y", -1));
  reg("field.jump-down", t("cmd.field.jump"), jump("y", 1));
  if (!TPL) {
    reg("field.detect", t("prepare.detect"), () => detect(), () => S.docs.length > 0);
    reg("field.accept-suggestions", t("prepare.accept-all"), () => acceptGhosts([...S.ghosts]), () => S.ghosts.length > 0);
    reg("field.dismiss-suggestions", t("prepare.dismiss-all"), () => dismissGhosts([...S.ghosts]), () => S.ghosts.length > 0);
  }
  reg("field.select-page", t("cmd.field.select-page"), () => {
    const keys = pageFields().map((f) => f.key);
    setSelection(keys);
    if (keys.length === 1) say(t("prepare.selected", { label: fieldLabel(sel()) }));
    stage.querySelector(`.os-field[data-fkey="${S.selected}"]`)?.focus({ preventScroll: true });
  }, () => step === "fields" && !typingNow() && pageFields().length > 0);
  reg("field.grow-width", t("cmd.field.resize"), sizeBy(4, 0));
  reg("field.shrink-width", t("cmd.field.resize"), sizeBy(-4, 0));
  reg("field.grow-height", t("cmd.field.resize"), sizeBy(0, 4));
  reg("field.shrink-height", t("cmd.field.resize"), sizeBy(0, -4));
  reg("field.delete", t("cmd.field.delete"), () => {
    const f = sel();
    if (!f) return;
    const gone = new Set(selection());
    const order = S.fields.filter((x) => x.docKey === f.docKey && x.page === f.page && (x === f || !gone.has(x)));
    const next = order[order.indexOf(f) + 1] || order[order.indexOf(f) - 1];
    multi.clear();
    change(() => { S.fields = S.fields.filter((x) => !gone.has(x)); S.selected = null; });
    toast(gone.size > 1 ? t("prepare.fields-deleted", { n: gone.size }) : t("prepare.field-deleted"), "info", { action: { label: t("cmd.edit.undo"), onClick: () => run("edit.undo") } });
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
    // Paste lands on the page in view (A23): the same spot there, or nudged on the same page.
    const where = inView();
    const samePage = !where || (where.doc.key === c.docKey && where.page === c.page);
    const target = samePage ? { docKey: c.docKey, page: c.page } : { docKey: where.doc.key, page: where.page };
    const pg = where && !samePage ? where.doc.pages[where.page - 1] : pageOf(c);
    const pos = samePage ? nudge(c, 12, 12, pg) : clampRect({ x: c.x, y: c.y, width: c.width, height: c.height }, pg);
    const copy = { ...c, ...target, key: newKey("f"), id: null, server: undefined, ...pos };
    S.clipboard = copy;
    change(() => { S.fields.push(copy); S.selected = copy.key; });
    select(copy.key);
  }, () => !!S.clipboard);
  // Escape: an armed type first (UX-05), then the selection.
  reg("field.deselect", t("cmd.field.deselect"), () => { if (armed) { disarm(true); return; } const f = sel(); select(null); if (f) stage.focus(); }, () => !!armed || hasSel());
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
  for (const type of FIELD_TYPES) {
    reg(`field.add-${type}`, t("prepare.add-field", { type: t(`ftype.${type}`) }), () => addFieldInView(type), () => true);
    reg(`field.arm-${type}`, t("prepare.arm-field", { type: t(`ftype.${type}`) }), () => arm(type, false), () => S.docs.length > 0);
  }
  reg("field.disarm", t("prepare.disarm"), () => disarm(true), () => !!armed);
  // Select (V) on the tool bar: always available on the fields step; disarms if armed.
  reg("field.disarm-select", t("prepare.tool-select"), () => disarm(true), () => step === "fields");
  if (!TPL) {
    reg("editor.preview", t("prepare.preview-signer"), async () => {
      if (previewKey) { previewAs(null); return; }
      const first = signerFor();
      if (!first) return;
      if (step !== "fields") await go("fields");
      previewAs(first.key);
    }, () => signers().length > 0 && S.docs.length > 0);
    reg("editor.apply-template", t("prepare.tpl-apply"), () => applyMatchedTemplate(), () => tplState === "offer" && !!tplOffer);
    reg("editor.skip-template", t("prepare.tpl-skip"), () => { tplState = "dismissed"; renderFloats(); renderProps(); }, () => tplState === "offer");
  }
  for (let n = 1; n <= 9; n++) {
    reg(`recipient.select-${n}`, t("cmd.recipient.select"), () => pick(signers()[n - 1].key), () => signers().length >= n);
  }

  // Files dropped from the desktop onto the stage.
  for (const ev of ["dragenter", "dragover"]) stage.addEventListener(ev, (e) => { if (e.dataTransfer.types.includes("Files")) { e.preventDefault(); stage.classList.add("is-dropping"); } });
  stage.addEventListener("dragleave", (e) => { if (e.target === stage) stage.classList.remove("is-dropping"); });
  stage.addEventListener("drop", (e) => {
    if (!e.dataTransfer.files?.length) return;
    e.preventDefault();
    stage.classList.remove("is-dropping");
    addFiles([...e.dataTransfer.files].filter((f) => f.type === "application/pdf" || /\.pdf$/i.test(f.name)));
  });

  const beforeUnload = (e) => { if (S.dirty) { e.preventDefault(); e.returnValue = ""; } };
  window.addEventListener("beforeunload", beforeUnload);
  // Leaving by a link asks first when there is unsaved work (A12).
  ctx.leaveGuard = async () => !S.dirty || confirmDialog(t("prepare.leave-title"), t("prepare.leave-text"), { confirm: t("prepare.leave"), danger: true });

  // ---- Start ---------------------------------------------------------------------------------
  renderAll();
  syncStatus();
  // A saved draft or template opens on the canvas's loading page (the fields pane, a page
  // skeleton and "Preparing pages…") while its documents are fetched, never a blank screen.
  const opening = !!(S.id || TPL_ID);
  if (opening) {
    for (const [k, pane] of Object.entries(panes)) pane.hidden = k !== "fields";
    frame.dataset.step = "fields";
    for (const b of [nextBtn, sendBtn, previewBtn, TPL ? saveBtn : null]) if (b) b.hidden = true;
    showPreparing(0);
  } else {
    dv.inner.append(h("div", { class: "os-page os-skeleton-page", attrs: { "aria-hidden": "true" } }));
  }
  if (TPL_ID) {
    try {
      const { template } = await ctx.api.templates.get(TPL_ID);
      await loadTemplate(template);
      renderAll();
    } catch (err) {
      if (!ctx.failed(err)) toastError(err);
    }
  }
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
  if (opening && !S.docs.length) { preparing?.remove(); preparing = null; }
  // A saved draft with documents and people opens on its fields; anything else starts
  // at the documents, or at the people when the documents are already there.
  await go(S.docs.length && S.recipients.length ? "fields" : S.docs.length ? "recipients" : "documents");
  if (step === "documents") docsPanel.querySelector(".os-btn--primary")?.focus();
  loadIntelligence();

  return () => {
    window.removeEventListener("beforeunload", beforeUnload);
    window.removeEventListener("keydown", onToolKey, true);
    document.removeEventListener("pointerdown", onDocDown, true);
    ctx.leaveGuard = null;
    clearTimeout(autosaveTimer);
    clearTimeout(tplTimer);
    preparingWatch?.disconnect();
    mlSeq++;
    dv.destroy();
    thumbs.destroy();
    closePanel();
    document.body.classList.remove("has-sheet");
    skipTo("#main", t("a11y.skip"));
    unregisterPrefix("field.");
    unregisterPrefix("edit.");
    unregisterPrefix("editor.");
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
