// Profile and signature (UX-04): the account menu's side panel for the signed-in user's
// own name, saved signature and initials, email notifications and password. DocuSign's
// "My preferences" and "Signatures", in one panel (owner instruction 22: side panels).
//
// The calls are `NOT_ON_SERVER.profile` (`GET/PATCH /api/v1/users/me`, row UXW-37): the
// mock serves them; against a server without them the panel shows who is signed in and
// says that changing it is not available yet, never a form that cannot save.

import { h, initials } from "./dom.js";
import { t } from "./i18n.js";
import { openPanel, field, toggle, button, toast, toastError } from "./ui/index.js";
import { errorMessage } from "./api.js";

const NOTIFY = ["completed", "declined", "viewed"];
const MIN_PASSWORD = 12;

/// Open the panel. `focus: "notifications"` starts at the notification choices;
/// `onSaved(me)` hears the saved profile (the avatar's initials follow the name).
export async function openProfile(ctx, { focus = null, onSaved = null } = {}) {
  if (!ctx.api.available("profile")) {
    openPanel({
      id: "profile",
      title: t("profile.title"),
      build(body) {
        body.append(
          h("dl", { class: "os-meta" },
            h("dt", { text: t("profile.name") }), h("dd", { text: ctx.who?.name || "—" }),
            h("dt", { text: t("profile.email") }), h("dd", { text: ctx.who?.email || "—" })),
          h("p", { class: "os-muted", attrs: { "data-testid": "profile-unavailable" }, text: t("profile.unavailable") }));
      },
    });
    return;
  }
  let me;
  try { me = await ctx.api.me(); } catch (err) { if (!ctx.failed?.(err)) toastError(err); return; }

  const name = field(t("profile.name"), { id: "profile-name", value: me.name || "", required: true, maxLength: 200, autocomplete: "name" });
  const checks = Object.fromEntries(NOTIFY.map((k) => [k, toggle(t(`profile.notify.${k}`), { id: `profile-notify-${k}`, checked: !!me.notifications?.[k] })]));
  const current = field(t("profile.password-current"), { id: "profile-pw-current", type: "password", autocomplete: "current-password", maxLength: 256 });
  const next = field(t("profile.password-new"), { id: "profile-pw-new", type: "password", autocomplete: "new-password", maxLength: 256, help: t("profile.password-help", { n: MIN_PASSWORD }) });

  const markRow = (mark) => {
    const saved = me[mark]?.image_base64;
    const label = t(`profile.${mark}`);
    return h("div", { class: "os-profile__mark", attrs: { "data-testid": `profile-${mark}` } },
      h("div", { class: "os-profile__mark-head" },
        h("span", { class: "os-label", text: label }),
        button(saved ? t("profile.change") : t("profile.set"), {
          variant: "secondary", size: "sm",
          attrs: { "aria-label": `${saved ? t("profile.change") : t("profile.set")} ${label.toLowerCase()}` },
          onClick: () => adopt(mark),
        })),
      saved
        ? h("img", { class: "os-profile__img", src: `data:image/png;base64,${saved}`, alt: t("profile.mark-alt", { what: label.toLowerCase() }) })
        : h("p", { class: "os-muted os-small", text: t("profile.no-mark") }));
  };

  /// Adopt a new mark with the signer's own component, save it, and come back here.
  async function adopt(mark) {
    await loadStyle("sign.css");
    const { adoptDialog } = await import("./signature.js");
    const got = await adoptDialog({ mark, name: name.input.value.trim() || me.name || "" });
    if (got?.base64) {
      try {
        me = await ctx.api.patchMe({ [mark]: { image_base64: got.base64 } });
        toast(t("profile.mark-saved", { what: t(`profile.${mark}`) }), "success");
      } catch (err) { if (!ctx.failed?.(err)) toastError(err); }
    }
    openProfile(ctx, { onSaved });
  }

  openPanel({
    id: "profile",
    title: t("profile.title"),
    width: 28,
    build(body) {
      const notif = h("fieldset", { class: "os-fieldset os-prof__switches", attrs: { "data-testid": "profile-notifications" } },
        h("legend", { class: "os-label", text: t("profile.notify") }),
        ...NOTIFY.map((k) => checks[k].el));
      body.classList.add("os-prof");
      body.append(
        // WEB-17: who this is, as the canvas's account row draws a person.
        h("div", { class: "os-prof__who", attrs: { "aria-hidden": "true" } },
          h("span", { class: "os-avatar os-avatar--c1 os-prof__avatar", text: initials(me.name || me.email || "") }),
          h("span", { class: "os-prof__who-text" }, h("b", { text: me.name || "—" }), h("span", { text: me.email || "" }))),
        h("section", { class: "os-profile__section", attrs: { "aria-labelledby": "profile-h-you" } },
          h("h3", { id: "profile-h-you", class: "os-profile__h", text: t("profile.you") }),
          name.el,
          h("p", { class: "os-label", text: t("profile.email") }),
          h("p", { class: "os-profile__email", text: me.email || "—" }),
          h("p", { class: "os-help", text: t("profile.email-help") })),
        h("section", { class: "os-profile__section", attrs: { "aria-labelledby": "profile-h-marks" } },
          h("h3", { id: "profile-h-marks", class: "os-profile__h", text: t("profile.marks") }),
          h("p", { class: "os-muted os-small", text: t("profile.marks-text") }),
          markRow("signature"), markRow("initials")),
        h("section", { class: "os-profile__section", attrs: { "aria-labelledby": "profile-h-notify" } },
          h("h3", { id: "profile-h-notify", class: "os-profile__h", text: t("account.notifications") }),
          notif),
        h("section", { class: "os-profile__section", attrs: { "aria-labelledby": "profile-h-pw" } },
          h("h3", { id: "profile-h-pw", class: "os-profile__h", text: t("profile.password") }),
          current.el, next.el));
      if (focus === "notifications") queueMicrotask(() => { checks.completed.input.focus(); notif.scrollIntoView?.({ block: "nearest" }); });
    },
    actions: [
      { label: t("action.cancel"), value: null },
      {
        label: t("profile.save"), variant: "primary", attrs: { "data-testid": "profile-save" },
        onClick: async () => {
          name.setError("");
          current.setError("");
          next.setError("");
          const body = {};
          const n = name.input.value.trim();
          if (!n) { name.setError(t("profile.name-missing")); name.input.focus(); return undefined; }
          if (n !== me.name) body.name = n;
          const notifications = Object.fromEntries(NOTIFY.map((k) => [k, checks[k].input.checked]));
          if (NOTIFY.some((k) => notifications[k] !== !!me.notifications?.[k])) body.notifications = notifications;
          if (next.input.value || current.input.value) {
            if (next.input.value.length < MIN_PASSWORD) { next.setError(t("profile.password-help", { n: MIN_PASSWORD })); next.input.focus(); return undefined; }
            if (!current.input.value) { current.setError(t("profile.password-current-missing")); current.input.focus(); return undefined; }
            body.password = next.input.value;
            body.current_password = current.input.value;
          }
          if (!Object.keys(body).length) return true;
          try {
            me = await ctx.api.patchMe(body);
          } catch (err) {
            if (err?.code === "CS-AUTH-0007") { current.setError(t("profile.password-wrong")); current.input.value = ""; current.input.focus(); return undefined; }
            if (ctx.failed?.(err)) return true;
            toast(errorMessage(err), "error");
            return undefined;
          }
          toast(t("profile.saved"), "success");
          onSaved?.(me);
          return true;
        },
      },
    ],
  });
}

/// Add a stylesheet of this app once (the adopt panel's styles live in sign.css).
function loadStyle(href) {
  if (document.querySelector(`link[rel="stylesheet"][href="${href}"]`)) return Promise.resolve();
  return new Promise((resolve) => {
    const link = h("link", { rel: "stylesheet", href });
    link.addEventListener("load", () => resolve(), { once: true });
    link.addEventListener("error", () => resolve(), { once: true });
    document.head.append(link);
  });
}

