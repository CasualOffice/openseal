// Shared components (WEB-01; docs/47 §As built: design system): buttons, toasts,
// dialogs, empty states, skeletons, status badges.
//
// Dialogs follow OpenPresent's one-modal pattern (`webapp/editor.dialogs.js` at
// `e61277d`, PROVENANCE.md: body built from nodes with `textContent`, focus returned
// on close), on the native `<dialog>` element, which gives the focus trap, Escape and
// the inert background for free. Toasts announce through one polite live region.

import { h, clear, reducedMotion } from "./dom.js";
import { icon } from "./icons.js";
import { illustration } from "./illustrations.js";
import { t } from "./i18n.js";
import { errorMessage } from "./api.js";

/// A button. `variant`: primary | secondary | ghost | danger; `size`: sm | md | lg.
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

/// Show a short message. `kind`: info | success | error. Errors stay until dismissed.
export function toast(message, kind = "info") {
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
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), reducedMotion() ? 0 : 200);
  };
  node.append(button(t("action.dismiss"), { icon: "x", variant: "ghost", size: "sm", iconOnly: true, onClick: close }));
  region.append(node);
  if (kind !== "error") setTimeout(close, 5000);
  return close;
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
    const first = body.querySelector("[autofocus], input, textarea, select") || dlg.querySelector(".os-dialog__foot .os-btn--primary, .os-dialog__foot .os-btn--danger");
    first?.focus();
  });
}

/// Ask a yes/no question. Resolves true or false.
export async function confirmDialog(title, text, { confirm = t("action.confirm"), danger = false } = {}) {
  const v = await openDialog({
    title,
    description: text,
    actions: [
      { label: t("action.cancel"), value: false },
      { label: confirm, variant: danger ? "danger" : "primary", onClick: () => true },
    ],
  });
  return v === true;
}

/// Ask for a reason (void, decline). Resolves the trimmed text, or null.
export async function reasonDialog(title, label, { confirm, danger = true, required = true, maxLength = 10000 } = {}) {
  let area;
  let err;
  return openDialog({
    title,
    build(body) {
      const id = `r-${Math.random().toString(36).slice(2)}`;
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
        variant: danger ? "danger" : "primary",
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
