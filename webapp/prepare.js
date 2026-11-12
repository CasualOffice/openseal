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

import { h, clear, reducedMotion, skipTo, initials } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix, run } from "./commands.js";
import { button, busy, emptyState, toast, toastError, confirmDialog, selectField, dockPanel, openPanel, closePanel } from "./ui/index.js";
import { openPdf } from "./pdfview.js";
import { docView, zoomControls, thumbnails } from "./docview.js";
import { FIELD_TYPES, DEFAULT_SIZE, clampRect, nudge, resize, placeAt, freeSpot, toWire, fromWire, takesInput } from "./geometry.js";
import { errorMessage } from "./api.js";
import { rolesFrom } from "./templatemodel.js";
import { templatePlan, applyTemplate } from "./templatesync.js";
import { suggestionsFrom } from "./detect.js";
import { snapRect, touching, nextStop, bounds, intersects, fromCorners } from "./guides.js";
import { compact, fromServer, groups, stepMove, canStep, moveGroup, joinGroup, newStepBefore, setOrder, byOrder, isAllAtOnce } from "./routing.js";
import { takeFiles } from "./handoff.js";

const FIELD_ICON = { signature: "signature", initials: "pen-line", date_signed: "calendar", name: "user", email: "at-sign", text: "text-cursor-input", checkbox: "square-check" };
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
  const saveBtn = TPL
    ? button(t("template.save"), { icon: "save", variant: "primary", command: "template.save", onClick: () => run("template.save") })
    : button(t("prepare.save"), { icon: "save", command: "envelope.save", onClick: () => run("envelope.save"), attrs: { "data-testid": "save-draft", title: t("prepare.save-tip") } });
  const sendBtn = TPL ? null : button(t("prepare.send"), { icon: "send", variant: "primary", command: "envelope.send", onClick: () => run("envelope.send") });
  const newTitle = () => t(TPL_ID ? "templates.edit-title" : TPL ? "template.new-title" : "prepare.title");
  const title = h("h1", { class: "os-prepare__title", text: newTitle() });
  const stepper = h("ol", { class: "os-stepper", attrs: { "aria-label": t("wizard.steps") } });
  const stepBtns = new Map();
  STEPS.forEach((s, i) => {
    const b = h("button", { type: "button", class: "os-stepper__btn", attrs: { "data-step": s, title: t(stepLabel(s)) } },
      h("span", { class: "os-stepper__n", text: String(i + 1) }), h("span", { class: "os-stepper__label", text: t(stepLabel(s)) }));
    b.addEventListener("click", () => go(s));
    stepBtns.set(s, b);
    stepper.append(h("li", {}, b));
  });
  const status = h("span", { class: "os-savestate", attrs: { "aria-live": "polite", id: "save-status", "data-testid": "save-status" } });

  // The document: one scroll container (docview.js), the zoom and page controls, and
  // the thumbnails, all on the fields step.
  const live = h("div", { class: "os-sr-only", attrs: { "aria-live": "polite" } });
  const dv = docView({
    label: t("prepare.pages"),
    testId: "editor-doc",
    onLayout: () => { zoom.sync(); },
    onZoom: () => zoom.sync(),
    onPage: (i) => { zoom.sync(); thumbs.mark(i); },
  });
  const stage = dv.scroller;
  stage.classList.add("os-stage");
  const zoom = zoomControls(dv);
  const undoBtn = button(t("cmd.edit.undo"), { icon: "undo-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => run("edit.undo"), attrs: { "aria-keyshortcuts": "Control+Z", "data-testid": "undo" } });
  const redoBtn = button(t("cmd.edit.redo"), { icon: "redo-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => run("edit.redo"), attrs: { "aria-keyshortcuts": "Control+Shift+Z", "data-testid": "redo" } });
  const keysBtn = button(t("help.shortcuts"), { icon: "keyboard", size: "sm", variant: "ghost", iconOnly: true, onClick: () => run("help.shortcuts") });
  const docTools = h("div", { class: "os-prepare__doctools", attrs: { role: "group", "aria-label": t("prepare.doc-tools") } }, undoBtn, redoBtn, keysBtn);

  const backBtn = button(t("action.back"), { icon: "chevron-left", size: "md", onClick: () => go(STEPS[STEPS.indexOf(step) - 1]), attrs: { "data-testid": "wizard-back", title: t("action.back") } });
  const nextBtn = button(t("wizard.next"), { icon: "arrow-right", variant: "primary", attrs: { "data-testid": "wizard-next" }, onClick: () => go(STEPS[STEPS.indexOf(step) + 1]) });
  const bar = h("header", { class: "os-prepare__bar", attrs: { "aria-label": t(TPL ? "template.new-title" : "prepare.title") } },
    h("a", { href: TPL ? "#/templates" : "#/agreements", class: "os-btn os-btn--ghost os-btn--md os-btn--icon", attrs: { "aria-label": t(TPL ? "template.back" : "prepare.back"), title: t(TPL ? "template.back" : "prepare.back") } }, icon("chevron-left")),
    h("div", { class: "os-prepare__head" },
      TPL ? h("span", { class: "os-badge os-badge--template" }, icon("layout-template", { size: 16 }), h("span", { text: t("template.badge") })) : null,
      title),
    h("nav", { class: "os-prepare__steps", attrs: { "aria-label": t("wizard.steps") } }, stepper),
    docTools,
    // The step's actions keep their place at the bar's end on every step (UX-05): the
    // title and the step labels give way first, never Back, Next or Send.
    h("div", { class: "os-prepare__actions" },
      status,
      TPL ? null : saveBtn,
      backBtn, nextBtn, sendBtn, TPL ? saveBtn : null));

  const docsPanel = h("section", { class: "os-panel os-panel--docs", attrs: { "aria-labelledby": "docs-h" } });
  const rcptPanel = h("section", { class: "os-panel os-panel--rcpt", attrs: { "aria-labelledby": "rcpt-h" } });
  const palettePanel = h("section", { class: "os-panel os-panel--palette", attrs: { "aria-labelledby": "pal-h" } });
  const thumbsBox = h("nav", { class: "os-thumbs", attrs: { "aria-label": t("prepare.thumbs") } });
  const thumbs = thumbnails(dv, thumbsBox, { width: 88 });
  const leftDock = dockPanel({ id: "editor-fields", side: "left", title: t("prepare.fields"), icon: "signature", width: 13.5, min: 11, max: 24, testId: "panel-fields" });
  leftDock.body.append(palettePanel, h("section", { class: "os-panel os-panel--thumbs", attrs: { "aria-labelledby": "thumbs-h" } },
    h("h3", { id: "thumbs-h", class: "os-panel__title", text: t("prepare.pages") }), thumbsBox));
  const props = h("div", { class: "os-props" });
  const rightDock = dockPanel({ id: "editor-props", side: "right", title: t("prepare.properties"), icon: "settings", width: 15, min: 13, max: 30, testId: "panel-props", collapsed: matchMedia("(max-width: 74.999em)").matches });
  rightDock.body.append(props);
  // Phones: the palette and the properties are bottom sheets; this opens the palette.
  const addFab = button(t("prepare.add-field-short"), { icon: "plus", variant: "primary", size: "lg", onClick: () => leftDock.openSheet(), attrs: { "data-testid": "add-field-sheet" } });
  const propsFab = button(t("prepare.field-settings"), { icon: "settings", size: "lg", onClick: () => rightDock.openSheet(), attrs: { "data-testid": "props-sheet" } });
  propsFab.hidden = true;
  // The document's own bar floats at the bottom of the pages: zoom and "Page n of N".
  const centre = h("div", { class: "os-prepare__centre" }, stage,
    h("div", { class: "os-docbar", attrs: { role: "toolbar", "aria-label": t("doc.toolbar") } }, zoom.el),
    h("div", { class: "os-fabs" }, propsFab, addFab));
  const reviewPanel = h("section", { class: "os-panel os-panel--review", attrs: { "aria-labelledby": "review-h" } });
  const fileInput = h("input", { type: "file", accept: "application/pdf,.pdf", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "pdf-input" } });
  fileInput.addEventListener("change", () => { addFiles([...fileInput.files]); fileInput.value = ""; });
  const panes = {
    documents: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, docsPanel),
    recipients: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, rcptPanel),
    fields: h("div", { class: "os-prepare__body" }, leftDock.el, centre, rightDock.el),
    review: h("div", { class: "os-wizard__pane os-wizard__pane--narrow" }, reviewPanel),
  };
  const frame = h("div", { class: "os-prepare", attrs: { "data-step": step } }, bar, h("div", { class: "os-wizard" },...Object.values(panes)), live, dv.live, fileInput);
  view.append(frame);


  function stepLabel(s) {
    return s === "recipients" && TPL ? "wizard.step.roles" : `wizard.step.${s}`;
  }
  /// Open step `s`: show its pane, mark the step bar, set the toolbar's buttons.
  async function go(s) {
    if (!STEPS.includes(s)) return;
    const prevStep = step;
    step = s;
    frame.dataset.step = s;
    const i = STEPS.indexOf(s);
    for (const [k, pane] of Object.entries(panes)) pane.hidden = k !== s;
    for (const [k, b] of stepBtns) {
      if (k === s) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
      const doneStep = STEPS.indexOf(k) < i;
      b.classList.toggle("is-done", doneStep);
      // Steps behind are ticked (R-04); the number stays for the screen reader.
      const n = b.querySelector(".os-stepper__n");
      n.replaceChildren(doneStep ? icon("check", { size: 16 }) : String(STEPS.indexOf(k) + 1), doneStep ? h("span", { class: "os-sr-only", text: `${STEPS.indexOf(k) + 1} ${t("wizard.step-done")}` }) : "");
    }
    docTools.hidden = s !== "fields";
    skipTo(s === "fields" ? "#document" : "#main", t(s === "fields" ? "a11y.skip-doc" : "a11y.skip"));
    if (s !== "fields") { leftDock.closeSheet(); rightDock.closeSheet(); }
    backBtn.hidden = i === 0;
    nextBtn.hidden = i === STEPS.length - 1;
    if (sendBtn) sendBtn.hidden = s !== "review";
    if (TPL) saveBtn.hidden = s !== "review";
    say(t("wizard.where", { n: i + 1, total: STEPS.length, label: t(stepLabel(s)) }));
    if (s === "fields") {
      // Fields start with the first signer (P-01), whoever was edited last on step 2.
      if (prevStep !== "fields") { S.active = signers()[0]?.key || null; renderPalette(); }
      if (stageKey !== S.docs.map((d) => d.key).join()) await renderStage();
      else { dv.relayout(); renderFieldsOnly(); }
    }
    if (s === "review") renderReview();
  }

  const say = (msg) => { live.textContent = ""; setTimeout(() => { live.textContent = msg; }, 30); };

  /// The save state beside Save (A13) and the undo and redo buttons (A14).
  function syncStatus() {
    status.replaceChildren();
    if (saving) status.append(h("span", { text: t("prepare.saving") }));
    else if (dirty) status.append(h("span", { class: "os-savestate__dot", attrs: { "aria-hidden": "true" } }), h("span", { text: t("prepare.unsaved") }));
    else if (savedAt) status.append(icon("circle-check", { size: 16 }), h("span", { text: t("prepare.saved-at", { time: savedAt.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) }) }));
    status.classList.toggle("is-dirty", dirty && !saving);
    status.title = status.textContent;
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
  const signers = () => S.recipients.filter((r) => r.type === "signer");
  const displayName = (r, i) => r?.name?.trim() || t(TPL ? "template.role-n" : "prepare.recipient-n", { n: i + 1 });
  function orderOf(r) {
    if (S.ordered) return r.order || 1;
    return r.type === "signer" ? 1 : 2;
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
    const access = h("input", { id: `ra-${r.key}`, class: "os-input os-input--sm", value: r.id ? "" : r.accessCode, disabled: !!r.id, autocomplete: "off", inputMode: "numeric", placeholder: r.id ? t(r.hasAccessCode ? "prepare.access-code-set" : "prepare.access-code-none") : t("prepare.access-code"), maxLength: 64, attrs: { "aria-label": t("prepare.access-code-for", { name: displayName(r, i) }), "data-testid": "recipient-access-code" } });
    access.addEventListener("input", () => { r.accessCode = access.value.trim(); S.dirty = true; });
    // An emailed one-time code (SEC-A02): set when the recipient is created, like the
    // access code, so a saved recipient shows it read-only.
    const otpBox = h("input", { id: `rotp-${r.key}`, type: "checkbox", checked: !!r.emailOtp, disabled: !!r.id, attrs: { "data-testid": "recipient-email-otp" } });
    otpBox.addEventListener("change", () => { r.emailOtp = otpBox.checked; S.dirty = true; });
    const otp = h("label", { class: "os-check os-rcpt__otp", attrs: { for: `rotp-${r.key}` } }, otpBox, h("span", { text: t("prepare.email-otp") }));
    const li = h("li", { class: `os-rcpt os-r${c}${S.active === r.key ? " is-active" : ""}`, attrs: { "data-rkey": r.key } },
      h("div", { class: "os-rcpt__head" },
        grip, h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
        order,
        typeField.el,
        h("span", { class: "os-spacer" }), up, down, del),
      // Visible labels, not placeholders alone (S-03); "of recipient 2" for screen readers.
      h("div", { class: "os-rcpt__cell" },
        h("label", { class: "os-label os-rcpt__label", attrs: { for: nameId } }, t("prepare.name"), h("span", { class: "os-sr-only", text: t(TPL ? "template.of-role" : "prepare.of-recipient", { n: i + 1 }) })), name),
      TPL ? null : h("div", { class: "os-rcpt__cell" },
        h("label", { class: "os-label os-rcpt__label", attrs: { for: mailId } }, t("prepare.email"), h("span", { class: "os-sr-only", text: t("prepare.of-recipient", { n: i + 1 }) })), email, emailErr),
      r.type === "signer" && !TPL ? access : null,
      r.type === "signer" && !TPL ? otp : null);
    // The card's controls are named after the recipient: renamed, they follow.
    name.addEventListener("change", () => {
      const who = displayName(r, S.recipients.indexOf(r));
      if (S.ordered) order.setAttribute("aria-label", t("prepare.order-for", { name: who }));
      del.setAttribute("aria-label", t("prepare.remove-recipient", { name: who }));
      del.title = t("prepare.remove-recipient", { name: who });
      access.setAttribute("aria-label", t("prepare.access-code-for", { name: who }));
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
    setTimeout(() => rcptPanel.querySelector(`[data-rkey="${r.key}"] .os-rcpt__head button[aria-label="${t(d < 0 ? "prepare.move-up" : "prepare.move-down")}"]:not([disabled])`)?.focus(), 0);
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

  // ---- Palette --------------------------------------------------------------------------
  // The buttons are built once and never replaced: a re-render between a button's
  // mousedown and its click (a name committed on blur) would swallow the click.
  const palFor = h("div", { class: "os-palette__for" });
  const palGrid = h("div", { class: "os-palette os-r1" });
  for (const type of FIELD_TYPES) {
    const b = h("button", { type: "button", class: "os-palette__item", draggable: true, attrs: { "data-field-type": type, "data-os-command": `field.add-${type}`, "aria-label": t("prepare.add-field", { type: t(`ftype.${type}`) }) } },
      icon(FIELD_ICON[type], { size: 20 }), h("span", { text: t(`ftype.${type}`) }));
    b.addEventListener("click", () => { addFieldInView(type); leftDock.closeSheet(); });
    b.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("application/x-openseal-field", type);
      e.dataTransfer.effectAllowed = "copy";
      stage.classList.add("is-dropping");
    });
    b.addEventListener("dragend", () => stage.classList.remove("is-dropping"));
    palGrid.append(b);
  }
  palettePanel.append(
    palFor,
    h("h3", { id: "pal-h", class: "os-panel__title", text: t("prepare.field-types") }),
    palGrid, h("p", { class: "os-muted os-small", text: t("prepare.palette-hint") }));
  // Detect fields (WEB-09): the server's suggestions as ghost fields. Envelopes only:
  // the API detects on an envelope's documents.
  const detectBtn = TPL ? null : button(t("prepare.detect"), { icon: "scan", command: "field.detect", onClick: () => run("field.detect"), attrs: { "data-testid": "detect-fields", "aria-describedby": "detect-help" } });
  if (detectBtn) palettePanel.append(h("div", { class: "os-detect" }, detectBtn, h("p", { id: "detect-help", class: "os-muted os-small", text: t("prepare.detect-help") })));

  /// The recipient chips (A21): who the next field is for, by colour, number and key 1–9.
  /// A radio group with roving focus; arrows move, the choice follows focus.
  /// Only signers take fields (P-01): copies are never offered, and the choice falls
  /// back to the first signer whenever it is not one.
  function renderPalette() {
    const sg = signers();
    if (!sg.some((r) => r.key === S.active)) S.active = sg[0]?.key || null;
    const active = recipient(S.active);
    const idx = S.recipients.indexOf(active);
    const focused = palFor.contains(document.activeElement);
    clear(palFor);
    if (sg.length > 1) {
      const group = h("div", { class: "os-chips-rcpt", attrs: { role: "radiogroup", "aria-labelledby": "pal-for-h" } });
      const chips = sg.map((r, j) => {
        const i = S.recipients.indexOf(r);
        const on = r.key === S.active;
        const chip = h("button", { type: "button", class: `os-rchip os-r${colourOf(r.key)}`, attrs: { role: "radio", "aria-checked": String(on), tabindex: on ? "0" : "-1", "data-rkey": r.key, title: t("prepare.placing-key", { n: j + 1 }) } },
          h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
          h("span", { class: "os-rchip__name", text: displayName(r, i) }),
          j < 9 ? h("kbd", { class: "os-rchip__key", attrs: { "aria-hidden": "true" }, text: String(j + 1) }) : null);
        chip.addEventListener("click", () => pick(r.key));
        chip.addEventListener("keydown", (e) => {
          const d = e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : e.key === "ArrowUp" || e.key === "ArrowLeft" ? -1 : 0;
          if (!d) return;
          e.preventDefault();
          pick(sg[(j + d + sg.length) % sg.length].key, true);
        });
        return chip;
      });
      group.append(...chips);
      palFor.append(h("p", { id: "pal-for-h", class: "os-panel__title", text: t("prepare.placing-for") }), group);
      if (focused) palFor.querySelector('[aria-checked="true"]')?.focus();
    } else if (active) {
      palFor.append(h("p", { class: "os-muted os-small", text: t("prepare.placing-for-name", { name: displayName(active, idx) }) }));
    }
    palGrid.className = `os-palette os-r${active ? colourOf(active.key) : 1}`;
  }
  function pick(key, focus = false) {
    S.active = key;
    markActive();
    renderPalette();
    if (S.ghosts.length) { renderGhosts(); renderProps(); }
    if (focus) palFor.querySelector('[aria-checked="true"]')?.focus();
    const i = S.recipients.findIndex((r) => r.key === key);
    say(t("prepare.placing-for-name", { name: displayName(S.recipients[i], i) }));
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
      overlay.addEventListener("pointerdown", (e) => { if (e.target === overlay) startMarquee(e, overlay, p.key, p.n); });
    });
    thumbs.build();
    renderFieldsOnly();
    // The placed-fields list numbers pages by the laid-out view, so it follows the stage.
    renderProps();
    zoom.sync();
  }
  const pageIndex = (docKey, page) => dv.pages.findIndex((p) => p.key === docKey && p.n === page);

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
        icon(FIELD_ICON[f.type] || "text-cursor-input", { size: 16 }),
        h("span", { class: "os-field__label", text: f.label || t(`ftype.${f.type}`) }),
        // Whose field it is, beside its colour (F-02): the recipient's initials, drawn by CSS
        // from data-who so the visible text stays the field's label (SC 2.5.3).
        h("span", { class: "os-field__who", attrs: { "aria-hidden": "true", "data-who": initials(displayName(recipient(f.recipientKey), S.recipients.findIndex((r) => r.key === f.recipientKey))) } }),
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

  let lastPlaced = null;
  function addField(type, doc, page, cx, cy) {
    let r = recipient(S.active);
    if (r?.type !== "signer") r = signers()[0];
    if (!r) r = addRecipient(false);
    const pg = doc.pages[page - 1];
    const rect = placeAt(type, cx, cy, pg);
    const f = { key: newKey("f"), id: null, docKey: doc.key, recipientKey: r.key, type, page, ...rect, required: type === "signature" || type === "initials", label: "" };
    change(() => { S.fields.push(f); S.selected = f.key; });
    lastPlaced = f.key;
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
      }
    }
    // A margin below each field keeps keyboard-placed fields apart, not touching.
    const spot = freeSpot(here.map((f) => ({ ...f, height: f.height + 12 })), size, pg, cx, cy);
    addField(type, doc, page, spot.x + size.width / 2, spot.y + size.height / 2);
  }

  // ---- Detected fields (WEB-09) -----------------------------------------------------------
  // The server's suggestions (`POST …/documents/{doc}/detect-fields`, detect.js) are drawn
  // as ghost fields in the colour of the signer fields are being placed for. Each can be
  // accepted (click, Enter) or dismissed (its ×, Delete); the properties panel accepts or
  // dismisses them all. Each of these is one undo step. A draft is saved first, since
  // detection reads the stored documents.
  /// Who accepted suggestions are for: the signer being placed for, else the first.
  const signerFor = () => { const r = recipient(S.active); return r?.type === "signer" ? r : signers()[0] || null; };
  const ghostLabel = (g) => (g.label || t(`ftype.${g.type}`));
  function renderGhosts() {
    for (const n of stage.querySelectorAll(".os-ghost")) n.remove();
    const who = signerFor();
    const colour = who ? colourOf(who.key) : 1;
    for (const g of S.ghosts) {
      const ov = overlayFor(g);
      if (!ov) continue;
      const accept = h("button", { type: "button", class: "os-ghost__accept", attrs: { "aria-label": t("prepare.ghost-accept", { type: ghostLabel(g), page: pageIndex(g.docKey, g.page) + 1 }), "data-testid": "ghost" } },
        icon(FIELD_ICON[g.type] || "text-cursor-input", { size: 16 }), h("span", { class: "os-field__label", text: ghostLabel(g) }));
      const dismiss = h("button", { type: "button", class: "os-ghost__dismiss", attrs: { "aria-label": t("prepare.ghost-dismiss", { type: ghostLabel(g), page: pageIndex(g.docKey, g.page) + 1 }), title: t("prepare.dismiss") } }, icon("x", { size: 16 }));
      accept.addEventListener("click", () => acceptGhosts([g]));
      dismiss.addEventListener("click", () => dismissGhosts([g]));
      for (const b of [accept, dismiss]) {
        b.addEventListener("keydown", (e) => {
          if (e.key !== "Delete" && e.key !== "Backspace") return;
          e.preventDefault();
          e.stopPropagation();
          dismissGhosts([g]);
        });
      }
      const el = h("div", { class: `os-ghost os-r${colour}`, attrs: { "data-gkey": g.key, "data-field": g.type } }, accept, dismiss);
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
    const made = list.map((g) => ({ key: newKey("f"), id: null, docKey: g.docKey, recipientKey: r.key, type: g.type, page: g.page, x: g.x, y: g.y, width: g.width, height: g.height, required: g.type === "signature" || g.type === "initials", label: g.label || "" }));
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
  async function detect() {
    if (!S.docs.length) { toast(t("prepare.add-pdf-first"), "info"); fileInput.click(); return; }
    await busy(detectBtn, async () => {
      try {
        // Detection reads the stored documents: save the draft first when any is new.
        if (!S.id || S.docs.some((d) => !d.id)) await save();
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
        toast(truncated ? `${msg} ${t("prepare.detect-truncated")}` : msg, "info");
        say(msg);
        const first = ghosts[0];
        dv.scrollToBox(pageIndex(first.docKey, first.page), first);
      } catch (err) {
        if (!ctx.failed(err)) showSaveError(err);
      }
    });
  }

  // ---- Properties ------------------------------------------------------------------------
  let advancedOpen = false;
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
    if (!f) {
      props.append(h("p", { class: "os-muted os-small", text: t("prepare.props-none") }));
      if (S.ghosts.length) {
        const who = signerFor();
        props.append(h("section", { class: "os-suggest", attrs: { "aria-labelledby": "suggest-h", "data-testid": "suggestions" } },
          h("h3", { id: "suggest-h", class: "os-panel__title", text: t(S.ghosts.length === 1 ? "prepare.suggestions-one" : "prepare.suggestions", { n: S.ghosts.length }) }),
          h("p", { class: "os-muted os-small", text: who ? t("prepare.suggestions-for", { name: displayName(who, S.recipients.indexOf(who)) }) : t("prepare.suggestions-new") }),
          h("div", { class: "os-actions" },
            button(t("prepare.accept-all"), { icon: "check", size: "sm", variant: "primary", command: "field.accept-suggestions", onClick: () => run("field.accept-suggestions"), attrs: { "data-testid": "accept-all" } }),
            button(t("prepare.dismiss-all"), { icon: "x", size: "sm", command: "field.dismiss-suggestions", onClick: () => run("field.dismiss-suggestions"), attrs: { "data-testid": "dismiss-all" } }))));
      }
      if (S.docs.length && !S.fields.length && !S.ghosts.length) {
        props.append(emptyState({ illus: "fields", title: t("empty.fields.title"), text: t("empty.fields.text"), action: button(t("prepare.add-field", { type: t("ftype.signature") }), { icon: "signature", variant: "primary", onClick: () => addFieldInView("signature") }), testId: "empty-fields" }));
      } else if (S.fields.length) {
        // Every placed field, in page order: choosing one selects it and scrolls to it.
        props.append(h("h3", { class: "os-panel__title", text: t(S.fields.length === 1 ? "prepare.fields-count-one" : "prepare.fields-count", { n: S.fields.length }) }));
        const order = [...S.fields].sort((a, b) => pageIndex(a.docKey, a.page) - pageIndex(b.docKey, b.page) || a.y - b.y || a.x - b.x);
        const ul = h("ul", { class: "os-placed" });
        for (const x of order) {
          const r = recipient(x.recipientKey);
          const i = S.recipients.indexOf(r);
          const b = h("button", { type: "button", class: `os-placed__item os-r${colourOf(x.recipientKey)}`, attrs: { "data-testid": "placed-field" } },
            icon(FIELD_ICON[x.type] || "text-cursor-input", { size: 16 }),
            h("span", { class: "os-placed__main" }, h("span", { class: "os-placed__name", text: x.label || t(`ftype.${x.type}`) }), h("span", { class: "os-muted os-small os-trunc", text: t("prepare.placed-meta", { name: displayName(r, i), page: pageIndex(x.docKey, x.page) + 1 }) })),
            x.required ? h("span", { class: "os-placed__req", text: t("prepare.required") }) : null);
          b.addEventListener("click", () => select(x.key));
          ul.append(h("li", {}, b));
        }
        props.append(ul);
      }
      return;
    }
    const pg = pageOf(f);
    const set = (k, v) => {
      S.undo.push(snapshot()); S.redo = [];
      f[k] = v; S.dirty = true;
      renderFieldsOnly();
    };
    props.append(h("div", { class: "os-props__head" },
      h("h3", { class: "os-props__title", text: t("prepare.field-props", { type: t(`ftype.${f.type}`) }) }),
      button(t("prepare.back-to-list"), { icon: "list", size: "sm", variant: "ghost", iconOnly: true, onClick: () => { select(null); props.querySelector("button")?.focus({ preventScroll: true }); } })));
    props.append(selectField(t(TPL ? "template.assigned-to" : "prepare.assigned-to"), S.recipients.map((r, i) => [r, i]).filter(([r]) => r.type === "signer" || r.key === f.recipientKey).map(([r, i]) => [r.key, `${i + 1}. ${displayName(r, i)}`]), { id: "fp-recipient", value: f.recipientKey, onChange: (v) => set("recipientKey", v) }).el);
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
    // Coordinates are for the few who need them (F-07): under Advanced, closed by default.
    const adv = h("details", { class: "os-details os-advanced", open: advancedOpen },
      h("summary", { text: t("prepare.advanced") }),
      h("p", { class: "os-label", text: t("prepare.position") }), geo, h("p", { class: "os-muted os-small", text: t("prepare.position-help", { page: f.page }) }));
    adv.addEventListener("toggle", () => { advancedOpen = adv.open; });
    props.append(adv);
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
        h("span", { class: "os-small os-summary__fields", text: r.type === "signer" ? (mine.length ? `${fieldsN(mine.length)}: ${kinds}` : t("wizard.no-fields")) : t("wizard.gets-copy") })));
    });
    if (!S.recipients.length) ul.append(h("li", { class: "os-muted", text: t(TPL ? "empty.roles.title" : "empty.recipients.title") }));
    sum.append(ul);
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
    S.recipients = recs.map((r, i) => ({ key: newKey("r"), id: r.id, name: r.name || "", email: r.email || "", type: r.type === "cc" ? "cc" : "signer", accessCode: prevAccess.get(r.id) || "", hasAccessCode: (r.auth || []).includes("access_code"), emailOtp: (r.auth || []).includes("email_otp"), order: steps[i] }));
    // Signers all at one step with copies after them is the switch off; anything else is steps.
    S.ordered = !isAllAtOnce(steps, (i) => S.recipients[i].type === "signer");
    const rkey = new Map(S.recipients.map((r) => [r.id, r.key]));
    const dkey = new Map(S.docs.map((d) => [d.id, d.key]));
    S.fields = (env.fields || []).map((f) => {
      const p = fromWire(f.placement);
      if (!p || !dkey.has(f.document_id)) return null;
      return { key: newKey("f"), id: f.id, docKey: dkey.get(f.document_id), recipientKey: rkey.get(f.recipient_id), type: f.type, page: p.page, x: p.x, y: p.y, width: p.width, height: p.height, required: !!f.required, label: f.label || "", server: JSON.stringify({ r: f.recipient_id, p: f.placement, q: !!f.required, l: f.label || "" }) };
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
    S.recipients = roles.map((r, i) => ({ key: newKey("r"), id: r.id, name: r.name || "", email: "", type: r.type === "cc" ? "cc" : "signer", accessCode: "", order: steps[i] }));
    S.ordered = !isAllAtOnce(steps, (i) => S.recipients[i].type === "signer");
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
    if (r.type === "signer" && r.accessCode) { body.auth = ["access_code"]; body.access_code = r.accessCode; }
    if (r.type === "signer" && r.emailOtp && r.email) body.auth = (body.auth || []).concat(["email_otp"]);
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
    saving = true;
    syncStatus();
    try { await saveNow(); savedAt = new Date(); } finally { saving = false; syncStatus(); }
    renderAll();
    await renderStage();
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
    if (typing || document.querySelector(".os-field.is-dragging, dialog[open]") || !savable()) { scheduleAutosave(); return; }
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
  }

  /// What stops sending, each with the step that fixes it (A16).
  function problems() {
    const out = [];
    if (!S.docs.length) out.push({ text: t("send.need-doc"), step: "documents" });
    if (!signers().length) out.push({ text: t("send.need-signer"), step: "recipients" });
    S.recipients.forEach((r, i) => {
      if (!r.name.trim()) out.push({ text: t("send.need-name", { n: i + 1 }), step: "recipients", focus: `#rn-${r.key}` });
      if (!EMAIL.test(r.email)) out.push({ text: t("send.need-email", { name: displayName(r, i) }), step: "recipients", focus: `#re-${r.key}` });
      if (r.type === "signer" && !S.fields.some((f) => f.recipientKey === r.key)) out.push({ text: t("send.need-field", { name: displayName(r, i) }), step: "fields", recipient: r.key });
      // A copy recipient signs nothing: fields left on one would be dropped (P-02).
      const cc = r.type !== "signer" ? S.fields.filter((f) => f.recipientKey === r.key).length : 0;
      if (cc) out.push({ text: t("send.cc-fields", { name: displayName(r, i), n: cc }), step: "fields" });
    });
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
    const sum = S.recipients.filter((r) => r.type === "signer").length;
    // Says who signs when and who only gets a copy (R-02).
    const subj = S.subject.trim() || t("envelope.untitled");
    const sg = signers();
    const copies = S.recipients.filter((r) => r.type !== "signer");
    const nameOf = (r) => displayName(r, S.recipients.indexOf(r));
    const text = [
      t(sum === 1 ? "send.confirm-one" : "send.confirm-text", { n: sum, subject: subj }),
      sg.length > 1 ? (new Set(sg.map(orderOf)).size > 1
        // Steps in order; a step of several is "A & B" (they sign at the same time).
        ? t("send.confirm-order", { order: groups(sg.map(orderOf)).map((g) => g.members.map((i) => nameOf(sg[i])).join(" & ")).join(" → ") })
        : t("send.confirm-together")) : "",
      copies.length ? t("send.confirm-copies", { names: copies.map(nameOf).join(", ") }) : "",
    ].filter(Boolean).join(" ");
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
  dv.inner.append(h("div", { class: "os-page os-skeleton-page", attrs: { "aria-hidden": "true" } }));
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
  // A saved draft with documents and people opens on its fields; anything else starts
  // at the documents, or at the people when the documents are already there.
  await go(S.docs.length && S.recipients.length ? "fields" : S.docs.length ? "recipients" : "documents");
  if (step === "documents") docsPanel.querySelector(".os-btn--primary")?.focus();

  return () => {
    window.removeEventListener("beforeunload", beforeUnload);
    ctx.leaveGuard = null;
    clearTimeout(autosaveTimer);
    dv.destroy();
    thumbs.destroy();
    closePanel();
    document.body.classList.remove("has-sheet");
    skipTo("#main", t("a11y.skip"));
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
