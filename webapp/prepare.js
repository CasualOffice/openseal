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

import { h, clear, reducedMotion } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { register, unregisterPrefix, run } from "./commands.js";
import { button, busy, emptyState, toast, toastError, openDialog, confirmDialog } from "./ui.js";
import { openPdf, fitScale } from "./pdfview.js";
import { FIELD_TYPES, DEFAULT_SIZE, clampRect, nudge, resize, placeAt, snap, toWire, fromWire, takesInput } from "./geometry.js";
import { errorMessage } from "./api.js";

const FIELD_ICON = { signature: "signature", initials: "pen-line", date_signed: "calendar", name: "user", email: "at-sign", text: "text-cursor-input", checkbox: "square-check" };
const MAX_UPLOAD = 50 * 1024 * 1024; // docs/21: 50 MiB decoded
const COLOURS = 6;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

let keySeq = 0;
const newKey = (p) => `${p}${++keySeq}`;

export async function mount(view, ctx, [rawId]) {
  const S = {
    id: rawId ? decodeURIComponent(rawId) : null,
    subject: "",
    message: "",
    captureLocation: false,
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
  const subject = h("input", { id: "env-subject", class: "os-input os-input--title", placeholder: t("prepare.subject-placeholder"), maxLength: 255, attrs: { "aria-label": t("prepare.subject") } });
  subject.addEventListener("input", () => { S.subject = subject.value; S.dirty = true; });
  const saveBtn = button(t("prepare.save"), { icon: "save", command: "envelope.save", onClick: () => run("envelope.save") });
  const sendBtn = button(t("prepare.send"), { icon: "send", variant: "primary", command: "envelope.send", onClick: () => run("envelope.send") });
  const bar = h("div", { class: "os-prepare__bar" },
    h("a", { href: "#/agreements", class: "os-btn os-btn--ghost os-btn--md os-btn--icon", attrs: { "aria-label": t("prepare.back"), title: t("prepare.back") } }, icon("chevron-left")),
    h("h1", { class: "os-sr-only", text: t("prepare.title") }),
    subject, h("span", { class: "os-prepare__status os-muted", attrs: { "aria-live": "polite", id: "save-status" } }), saveBtn, sendBtn);

  const docsPanel = h("section", { class: "os-panel", attrs: { "aria-labelledby": "docs-h" } });
  const rcptPanel = h("section", { class: "os-panel", attrs: { "aria-labelledby": "rcpt-h" } });
  const palettePanel = h("section", { class: "os-panel", attrs: { "aria-labelledby": "pal-h" } });
  const left = h("aside", { class: "os-prepare__left", attrs: { "aria-label": t("prepare.setup") } }, docsPanel, rcptPanel, palettePanel);
  const stage = h("div", { class: "os-stage", attrs: { "aria-label": t("prepare.pages"), role: "region", tabindex: "-1", id: "stage" } });
  const props = h("aside", { class: "os-prepare__right", attrs: { "aria-label": t("prepare.properties") } });
  const live = h("div", { class: "os-sr-only", attrs: { "aria-live": "polite" } });
  const fileInput = h("input", { type: "file", accept: "application/pdf,.pdf", multiple: true, class: "os-sr-only", attrs: { "aria-hidden": "true", tabindex: "-1", "data-testid": "pdf-input" } });
  fileInput.addEventListener("change", () => { addFiles([...fileInput.files]); fileInput.value = ""; });
  view.append(h("div", { class: "os-prepare" }, bar, h("div", { class: "os-prepare__body" }, left, stage, props), live, fileInput));

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
  const displayName = (r, i) => r?.name?.trim() || t("prepare.recipient-n", { n: i + 1 });
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
    rcptPanel.append(h("div", { class: "os-panel__head" },
      h("h2", { id: "rcpt-h", class: "os-panel__title", text: t("prepare.recipients") }),
      button(t("prepare.add-recipient"), { icon: "user-plus", size: "sm", command: "recipient.add", onClick: () => addRecipient() })));
    if (!S.recipients.length) {
      rcptPanel.append(emptyState({ illus: "recipients", title: t("empty.recipients.title"), text: t("empty.prepare-recipients.text"), action: button(t("prepare.add-recipient"), { icon: "user-plus", variant: "primary", onClick: () => addRecipient() }), testId: "empty-recipients" }));
      return;
    }
    const routing = h("fieldset", { class: "os-segmented" },
      h("legend", { class: "os-label", text: t("prepare.routing") }),
      ...["sequential", "parallel"].map((m) => {
        const id = `routing-${m}`;
        const input = h("input", { type: "radio", name: "routing", id, value: m, checked: S.routing === m });
        input.addEventListener("change", () => change(() => { S.routing = m; }));
        return h("label", { attrs: { for: id } }, input, icon(m === "sequential" ? "list-ordered" : "layers", { size: 16 }), h("span", { text: t(`prepare.routing-${m}`) }));
      }));
    rcptPanel.append(routing);
    const list = h("ol", { class: "os-rcpt-list" });
    S.recipients.forEach((r, i) => {
      const c = colourOf(r.key);
      const nameId = `rn-${r.key}`;
      const mailId = `re-${r.key}`;
      const typeId = `rt-${r.key}`;
      const name = h("input", { id: nameId, class: "os-input os-input--sm", value: r.name, autocomplete: "off", placeholder: t("prepare.name"), maxLength: 255, attrs: { "data-testid": "recipient-name" } });
      const email = h("input", { id: mailId, class: "os-input os-input--sm", type: "email", value: r.email, autocomplete: "off", placeholder: t("prepare.email"), attrs: { "data-testid": "recipient-email" } });
      const type = h("select", { id: typeId, class: "os-input os-input--sm", attrs: { "data-testid": "recipient-type" } },
        h("option", { value: "signer", text: t("rtype.signer"), selected: r.type === "signer" }),
        h("option", { value: "cc", text: t("rtype.cc"), selected: r.type === "cc" }));
      const commit = (k, v) => {
        if (r[k] === v) return;
        S.undo.push(snapshot()); S.redo = [];
        r[k] = v; S.dirty = true;
        renderPalette(); renderFieldsOnly(); renderProps();
        if (k === "type") renderRecipients();
      };
      name.addEventListener("change", () => commit("name", name.value.trim()));
      email.addEventListener("change", () => commit("email", email.value.trim()));
      type.addEventListener("change", () => commit("type", type.value));
      const up = button(t("prepare.move-up"), { icon: "chevron-left", size: "sm", variant: "ghost", iconOnly: true, onClick: () => moveRecipient(i, -1) });
      up.querySelector("svg").classList.add("os-rot90");
      up.disabled = i === 0;
      const del = button(t("prepare.remove-recipient", { name: displayName(r, i) }), { icon: "trash-2", size: "sm", variant: "ghost", iconOnly: true, onClick: () => removeRecipient(r) });
      // The access code is set when the recipient is created; the API has no way to
      // change it afterwards (RecipientPatch), so a saved recipient shows it read-only.
      const access = h("input", { id: `ra-${r.key}`, class: "os-input os-input--sm", value: r.id ? "" : r.accessCode, disabled: !!r.id, autocomplete: "off", inputMode: "numeric", placeholder: r.id ? t(r.hasAccessCode ? "prepare.access-code-set" : "prepare.access-code-none") : t("prepare.access-code"), maxLength: 64, attrs: { "aria-label": t("prepare.access-code-for", { name: displayName(r, i) }), "data-testid": "recipient-access-code" } });
      access.addEventListener("change", () => commit("accessCode", access.value.trim()));
      const li = h("li", { class: `os-rcpt os-r${c}${S.active === r.key ? " is-active" : ""}`, attrs: { "data-rkey": r.key } },
        h("div", { class: "os-rcpt__head" },
          h("span", { class: "os-rcpt__dot", attrs: { "aria-hidden": "true" } }),
          h("span", { class: "os-order", attrs: { title: t("prepare.routing-order") }, text: String(orderOf(r)) }),
          h("label", { class: "os-sr-only", attrs: { for: typeId }, text: t("prepare.role-for", { name: displayName(r, i) }) }), type,
          h("span", { class: "os-spacer" }), up, del),
        h("label", { class: "os-sr-only", attrs: { for: nameId }, text: t("prepare.name-of", { n: i + 1 }) }), name,
        h("label", { class: "os-sr-only", attrs: { for: mailId }, text: t("prepare.email-of", { n: i + 1 }) }), email,
        r.type === "signer" ? access : null);
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
  function renderPalette() {
    clear(palettePanel);
    const active = recipient(S.active);
    const idx = S.recipients.indexOf(active);
    palettePanel.append(h("div", { class: "os-panel__head" }, h("h2", { id: "pal-h", class: "os-panel__title", text: t("prepare.fields") })));
    if (S.recipients.length > 1) {
      const sel = h("select", { id: "pal-for", class: "os-input os-input--sm" },
        ...S.recipients.map((r, i) => h("option", { value: r.key, selected: r.key === S.active, text: `${i + 1}. ${displayName(r, i)}` })));
      sel.addEventListener("change", () => { S.active = sel.value; markActive(); renderPalette(); });
      palettePanel.append(h("label", { class: "os-label", attrs: { for: "pal-for" }, text: t("prepare.placing-for") }), sel);
    } else if (active) {
      palettePanel.append(h("p", { class: "os-muted os-small", text: t("prepare.placing-for-name", { name: displayName(active, idx) }) }));
    }
    const grid = h("div", { class: `os-palette os-r${active ? colourOf(active.key) : 1}` });
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
      grid.append(b);
    }
    palettePanel.append(grid, h("p", { class: "os-muted os-small", text: t("prepare.palette-hint") }));
  }

  // ---- Documents ---------------------------------------------------------------------------
  function renderDocs() {
    clear(docsPanel);
    docsPanel.append(h("div", { class: "os-panel__head" },
      h("h2", { id: "docs-h", class: "os-panel__title", text: t("prepare.documents") }),
      button(t("prepare.add-pdf"), { icon: "file-up", size: "sm", command: "document.add", onClick: () => fileInput.click() })));
    if (!S.docs.length) { docsPanel.append(h("p", { class: "os-muted os-small", text: t("prepare.no-docs") })); return; }
    const ul = h("ul", { class: "os-doc-list" });
    for (const d of S.docs) {
      ul.append(h("li", {}, icon("file-text", { size: 16 }), h("span", { class: "os-doc-list__name", text: d.name }),
        h("span", { class: "os-muted os-small", text: t("prepare.pages-n", { n: d.pages.length }) }),
        d.id ? null : button(t("prepare.remove-doc", { name: d.name }), { icon: "x", size: "sm", variant: "ghost", iconOnly: true, onClick: () => removeDoc(d) })));
    }
    docsPanel.append(ul);
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
    renderStage();
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
        if (!S.subject) { S.subject = t("prepare.default-subject", { name: file.name.replace(/\.pdf$/i, "") }).slice(0, 255); subject.value = S.subject; }
        say(t("prepare.doc-added", { name: d.name, n: d.pages.length }));
      } catch {
        toast(t("prepare.unreadable", { name: file.name }), "error");
      }
    }
    renderDocs();
    await renderStage();
    renderProps();
  }

  // ---- Stage: pages and fields ---------------------------------------------------------
  async function renderStage() {
    clear(stage);
    if (!S.docs.length) {
      stage.append(emptyState({
        illus: "documents", title: t("empty.documents.title"), text: t("empty.documents.text"),
        action: button(t("prepare.add-pdf"), { icon: "file-up", variant: "primary", size: "lg", onClick: () => fileInput.click() }),
        testId: "empty-documents",
      }));
      return;
    }
    const width = stage.clientWidth || 800;
    const widest = Math.max(...S.docs.flatMap((d) => d.pages.map((p) => p.width)));
    scale = Math.min(fitScale(widest, width - 48), 1.5);
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
    el.setPointerCapture(e.pointerId);
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
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", up);
      el.removeEventListener("pointercancel", up);
      el.classList.remove("is-dragging", "is-snapped");
      if (moved) {
        S.undo.push(before); S.redo = []; S.dirty = true;
        el.classList.add("is-dropped");
        setTimeout(() => el.classList.remove("is-dropped"), 250);
        renderProps();
      }
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", up);
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
    const here = S.fields.filter((f) => f.docKey === doc.key && f.page === page).length;
    const size = DEFAULT_SIZE[type];
    addField(type, doc, page, pg.width / 2, Math.min(pg.height / 3 + here * (size.height + 12), pg.height - size.height));
  }

  // ---- Properties ------------------------------------------------------------------------
  function renderProps() {
    clear(props);
    const f = S.fields.find((x) => x.key === S.selected);
    if (!f) {
      props.append(h("h2", { class: "os-panel__title", text: t("prepare.settings") }));
      const msg = h("textarea", { id: "env-message", class: "os-input os-textarea", rows: 4, maxLength: 10000, value: S.message, placeholder: t("prepare.message-placeholder") });
      msg.addEventListener("change", () => { S.message = msg.value; S.dirty = true; });
      const loc = h("input", { id: "env-location", type: "checkbox", checked: S.captureLocation });
      loc.addEventListener("change", () => { S.captureLocation = loc.checked; S.dirty = true; });
      props.append(
        h("label", { class: "os-label", attrs: { for: "env-message" }, text: t("prepare.message") }), msg,
        h("label", { class: "os-check", attrs: { for: "env-location" } }, loc, h("span", { text: t("prepare.capture-location") })),
        h("p", { class: "os-muted os-small", text: t("prepare.capture-location-help") }));
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
    const rsel = h("select", { id: "fp-recipient", class: "os-input" }, ...S.recipients.map((r, i) => h("option", { value: r.key, selected: r.key === f.recipientKey, text: `${i + 1}. ${displayName(r, i)}` })));
    rsel.addEventListener("change", () => set("recipientKey", rsel.value));
    props.append(h("label", { class: "os-label", attrs: { for: "fp-recipient" }, text: t("prepare.assigned-to") }), rsel);
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
  }

  // ---- Loading a draft ------------------------------------------------------------------
  async function loadFromServer(env) {
    S.id = env.id;
    S.subject = env.subject || "";
    S.message = env.message || "";
    S.captureLocation = !!env.signing_options?.capture_location;
    subject.value = S.subject;
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
  const etagNow = async () => (await ctx.api.getEnvelope(S.id)).etag;

  async function save() {
    const status = document.getElementById("save-status");
    status.textContent = t("prepare.saving");
    if (!S.id) {
      const body = {
        subject: S.subject.trim(),
        message: S.message,
        signing_options: options(),
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
      if ((e2.subject || "") !== S.subject.trim() || (e2.message || "") !== S.message || !!e2.signing_options?.capture_location !== S.captureLocation) {
        await ctx.api.patchEnvelope(S.id, etag, { subject: S.subject.trim(), message: S.message, signing_options: { ...(e2.signing_options || {}), capture_location: S.captureLocation } });
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
  reg("envelope.save", t("prepare.save"), () => busy(saveBtn, async () => {
    try { await save(); toast(t("prepare.saved"), "success"); } catch (err) { if (!ctx.failed(err)) showSaveError(err); }
  }), () => true);
  reg("envelope.send", t("prepare.send"), send, () => true);
  reg("recipient.add", t("prepare.add-recipient"), () => addRecipient(), () => true);
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
  const onResize = () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (S.docs.length) renderStage(); }, 200); };
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
  await renderStage();
  if (!S.id) subject.focus();

  return () => {
    window.removeEventListener("resize", onResize);
    window.removeEventListener("beforeunload", beforeUnload);
    unregisterPrefix("field.");
    unregisterPrefix("edit.");
    unregisterPrefix("envelope.save");
    unregisterPrefix("envelope.send");
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
