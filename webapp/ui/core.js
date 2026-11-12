// Shared components (WEB-01; docs/47 §As built: design system): buttons, toasts,
// dialogs, empty states, skeletons, status badges.
//
// Dialogs follow OpenPresent's one-modal pattern (`webapp/editor.dialogs.js` at
// `e61277d`, PROVENANCE.md: body built from nodes with `textContent`, focus returned
// on close), on the native `<dialog>` element, which gives the focus trap, Escape and
// the inert background for free. Toasts announce through one polite live region.

import { h, clear, reducedMotion } from "../dom.js";
import { icon } from "../icons.js";
import { illustration } from "../illustrations.js";
import { t } from "../i18n.js";
import { errorMessage } from "../api.js";

/// A button. `variant`: primary | secondary | ghost | danger | danger-fill; `size`: sm | md | lg.
/// `command` adds `data-os-command`, so the registry can find and run it.
export function button(label, { icon: ic = null, variant = "secondary", size = "md", command = null, onClick = null, type = "button", iconOnly = false, attrs = {} } = {}) {
  const b = h("button", {
    type,
    class: `os-btn os-btn--${variant} os-btn--${size}${iconOnly ? " os-btn--icon" : ""}`,
    attrs: { ...(command ? { "data-os-command": command } : {}), ...(iconOnly ? { "aria-label": label, title: label } : {}), ...attrs },
    on: onClick ? { click: onClick } : {},
  });
  if (ic) b.append(icon(ic, { size: size === "sm" ? 16 : 20 }));
  if (!iconOnly) b.append(h("span", { text: label }));
  return b;
}

/// Mark a button busy while `work` runs (disabled, spinner, aria-busy), then restore.
export async function busy(btn, work) {
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.classList.add("is-busy");
  try { return await work(); } finally {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.classList.remove("is-busy");
  }
}

// ---- Toasts ----------------------------------------------------------------------

const viewToasts = new Set(); // close functions of the toasts about the current view

/// Show a short message. `kind`: info | success | error. Errors stay until dismissed.
/// `action`: `{label, onClick}` adds one button (Undo after a delete, A24); a toast
/// with an action stays 8 s so it can be reached. `scope: "view"` ties the toast to
/// the screen it is about: `clearViewToasts()` (the router, on navigation) removes it;
/// the default, `"app"`, outlives navigation (a send confirmed, a session ended).
export function toast(message, kind = "info", { action = null, scope = "app" } = {}) {
  let region = document.getElementById("os-toasts");
  if (!region) {
    region = h("div", { id: "os-toasts", class: "os-toasts", attrs: { role: "status", "aria-live": "polite" } });
    document.body.append(region);
  }
  const node = h("div", { class: `os-toast os-toast--${kind}` },
    icon(kind === "error" ? "circle-x" : kind === "success" ? "circle-check" : "info", { size: 20 }),
    h("span", { class: "os-toast__text", text: message }),
  );
  const close = () => {
    viewToasts.delete(close);
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), reducedMotion() ? 0 : 200);
  };
  if (scope === "view") {
    node.dataset.scope = "view";
    viewToasts.add(close);
  }
  if (action) node.append(button(action.label, { variant: "ghost", size: "sm", onClick: () => { close(); action.onClick(); }, attrs: { "data-testid": "toast-action" } }));
  node.append(button(t("action.dismiss"), { icon: "x", variant: "ghost", size: "sm", iconOnly: true, onClick: close }));
  region.append(node);
  if (kind !== "error") setTimeout(close, action ? 8000 : 5000);
  return close;
}

/// Remove every toast shown with `scope: "view"` (the view it was about has gone).
export function clearViewToasts() {
  for (const close of [...viewToasts]) close();
}

/// Toast an API error by its code (docs/20), with the request id when there is one.
export function toastError(err) {
  return toast(errorMessage(err), "error");
}

// ---- Dialogs ---------------------------------------------------------------------

/// Open a modal dialog. `build(body, close)` fills it; `actions` are
/// `{label, variant, onClick(close) → value|Promise}`. Resolves with the value given
/// to `close(value)`, or `null` when dismissed.
export function openDialog({ title, description = null, build = null, actions = [], className = "", size = "md" }) {
  return new Promise((resolve) => {
    const returnTo = document.activeElement;
    const titleId = `dlg-${Math.random().toString(36).slice(2)}`;
    const dlg = h("dialog", { class: `os-dialog os-dialog--${size} ${className}`, attrs: { "aria-labelledby": titleId } });
    const body = h("div", { class: "os-dialog__body" });
    let done = false;
    const close = (value = null) => {
      if (done) return;
      done = true;
      dlg.classList.add("is-leaving");
      setTimeout(() => {
        dlg.close();
        dlg.remove();
        returnTo?.focus?.({ preventScroll: true });
        resolve(value);
      }, reducedMotion() ? 0 : 150);
    };
    const head = h("div", { class: "os-dialog__head" },
      h("h2", { id: titleId, class: "os-dialog__title", text: title }),
      button(t("action.close"), { icon: "x", variant: "ghost", size: "sm", iconOnly: true, onClick: () => close(null) }),
    );
    dlg.append(head);
    if (description) body.append(h("p", { class: "os-muted", text: description }));
    if (build) build(body, close);
    dlg.append(body);
    if (actions.length) {
      const foot = h("div", { class: "os-dialog__foot" });
      for (const a of actions) {
        const b = button(a.label, { variant: a.variant || "secondary", icon: a.icon, attrs: a.attrs || {} });
        b.addEventListener("click", async () => {
          if (!a.onClick) return close(a.value ?? null);
          try {
            const v = await busy(b, () => a.onClick(close));
            if (v !== undefined) close(v);
          } catch (e) {
            toastError(e);
          }
        });
        foot.append(b);
      }
      dlg.append(foot);
    }
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); close(null); });
    dlg.addEventListener("click", (e) => { if (e.target === dlg) close(null); });
    document.body.append(dlg);
    dlg.showModal();
    const first = body.querySelector("[autofocus], input, textarea, select") || dlg.querySelector(".os-dialog__foot .os-btn--primary, .os-dialog__foot .os-btn--danger, .os-dialog__foot .os-btn--danger-fill");
    first?.focus();
  });
}

/// The consequence of a destructive action, as a callout with a warning icon (UX-02).
function consequenceLine(text) {
  return h("div", { class: "os-callout os-callout--danger", attrs: { "data-testid": "dialog-consequence" } },
    icon("triangle-alert", { size: 20 }), h("p", { text }));
}

/// Ask a yes/no question. Resolves true or false. With `danger`, the text is shown as
/// the consequence (a warning callout) and the confirming button is the filled danger
/// button with an icon (`icon`, default a warning sign), never the seal-red primary.
export async function confirmDialog(title, text, { confirm = t("action.confirm"), danger = false, icon: ic = "triangle-alert" } = {}) {
  const v = await openDialog({
    title,
    description: danger ? null : text,
    build: danger && text ? (body) => body.append(consequenceLine(text)) : null,
    actions: [
      { label: t("action.cancel"), value: false },
      { label: confirm, variant: danger ? "danger-fill" : "primary", icon: danger ? ic : undefined, onClick: () => true },
    ],
  });
  return v === true;
}

/// Ask for a reason (void, decline). Resolves the trimmed text, or null. A `danger`
/// one (the default) confirms with the filled danger button and its `icon`, and shows
/// `consequence`, when given, as a warning callout above the reason.
export async function reasonDialog(title, label, { confirm, danger = true, required = true, maxLength = 10000, consequence = null, icon: ic = "ban" } = {}) {
  let area;
  let err;
  return openDialog({
    title,
    build(body) {
      const id = `r-${Math.random().toString(36).slice(2)}`;
      if (consequence) body.append(consequenceLine(consequence));
      body.append(
        h("label", { class: "os-label", attrs: { for: id }, text: label }),
        (area = h("textarea", { id, class: "os-input os-textarea", rows: 4, maxLength, attrs: { autofocus: true, "aria-describedby": `${id}-err`, ...(required ? { required: true } : {}) } })),
        (err = h("p", { id: `${id}-err`, class: "os-field-error", attrs: { "aria-live": "polite" } })),
      );
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: confirm,
        variant: danger ? "danger-fill" : "primary",
        icon: danger ? ic : undefined,
        onClick: () => {
          const v = area.value.trim();
          if (required && !v) {
            err.textContent = t("form.required");
            area.setAttribute("aria-invalid", "true");
            area.focus();
            return undefined;
          }
          return v;
        },
      },
    ],
  });
}

// ---- Empty states and loading ----------------------------------------------------

/// An empty state: illustration, one-line title, one sentence, the primary action.
export function emptyState({ illus = "inbox", title, text, action = null, testId = null }) {
  return h("div", { class: "os-empty", attrs: { "data-testid": testId } },
    illustration(illus),
    h("h2", { class: "os-empty__title", text: title }),
    h("p", { class: "os-empty__text", text }),
    action,
  );
}

/// Skeleton rows for a list while it loads (hidden from assistive technology; the
/// container carries `aria-busy`).
export function skeletonRows(n = 5) {
  const wrap = h("div", { class: "os-skeleton-list", attrs: { "aria-hidden": "true" } });
  for (let i = 0; i < n; i++) {
    wrap.append(h("div", { class: "os-skeleton-row" },
      h("span", { class: "os-skel os-skel--text" }),
      h("span", { class: "os-skel os-skel--pill" }),
      h("span", { class: "os-skel os-skel--short" })));
  }
  return wrap;
}

const STATUS_ICON = { draft: "file-pen-line", sent: "send", delivered: "eye", completing: "loader-circle", completed: "circle-check", declined: "circle-x", voided: "ban", expired: "clock", created: "clock" };

/// A status badge with icon and text (never colour alone, SC 1.4.1).
export function statusBadge(status) {
  return h("span", { class: `os-badge os-badge--${status}` }, icon(STATUS_ICON[status] || "info", { size: 16 }), h("span", { text: t(`status.${status}`) }));
}

/// Replace `container`'s content with "no OpenSeal server here" (loopback only, no
/// mock): a retry, and a link to the same page in demo mode.
export function noServerState(container, retry = null) {
  clear(container);
  const q = new URLSearchParams(location.search);
  q.set("mock", "1");
  const demo = h("a", { class: "os-btn os-btn--secondary os-btn--md", href: `${location.pathname}?${q}${location.hash}`, attrs: { "data-testid": "open-demo" } }, icon("eye", { size: 20 }), h("span", { text: t("empty.no-server.demo") }));
  container.append(emptyState({
    illus: "offline",
    title: t("empty.no-server.title"),
    text: t("empty.no-server.text"),
    action: h("div", { class: "os-actions" }, retry ? button(t("action.retry"), { icon: "refresh-cw", variant: "primary", onClick: retry }) : null, demo),
    testId: "empty-no-server",
  }));
}

/// Replace `container`'s content with an error state for `err` and a retry button.
export function errorState(container, err, retry) {
  clear(container);
  const offline = err?.code === "CS-NET-0001";
  container.append(emptyState({
    illus: offline ? "offline" : "error",
    title: offline ? t("empty.offline.title") : t("empty.error.title"),
    text: errorMessage(err),
    action: retry ? button(t("action.retry"), { icon: "refresh-cw", variant: "primary", onClick: retry }) : null,
    testId: offline ? "empty-offline" : "empty-error",
  }));
}
