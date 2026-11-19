// Profile and signature (UX-04): the account menu's side panel for the signed-in user's
// own name, saved signature and initials, email notifications and password. DocuSign's
// "My preferences" and "Signatures", in one panel (owner instruction 22: side panels).
//
// The calls are `GET/PATCH /api/v1/users/me` (UXW-37, served). A backend that lists
// `profile` as unavailable gets a panel that shows who is signed in and says changing
// it is not available yet, never a form that cannot save.

import { h, clear, initials, fmtDate } from "./dom.js";
import { t } from "./i18n.js";
import { openPanel, field, checkbox, button, toast, toastError, confirmDialog, closePanel } from "./ui/index.js";
import { errorMessage } from "./api.js";
import { sessionRows } from "./authmodel.js";
import { strengthMeter } from "./pwmeter.js";

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
  const checks = Object.fromEntries(NOTIFY.map((k) => [k, checkbox(t(`profile.notify.${k}`), { id: `profile-notify-${k}`, checked: !!me.notifications?.[k] })]));
  const current = field(t("profile.password-current"), { id: "profile-pw-current", type: "password", autocomplete: "current-password", maxLength: 256 });
  const next = field(t("profile.password-new"), { id: "profile-pw-new", type: "password", autocomplete: "new-password", maxLength: 256, help: t("profile.password-help", { n: MIN_PASSWORD }) });
  // How strong the new password looks, for this person (ASVS-03); advice only.
  const meter = strengthMeter("profile-pw-strength");
  next.el.insertBefore(meter.el, next.el.querySelector(".os-field-error"));
  next.input.setAttribute("aria-describedby", `${next.input.getAttribute("aria-describedby")} profile-pw-strength`);
  next.input.addEventListener("input", () => meter.update(next.input.value, [me.name, me.email]));

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
      const notif = h("fieldset", { class: "os-fieldset", attrs: { "data-testid": "profile-notifications" } },
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
          current.el, next.el),
        sessionsSection(ctx),
        dataSection(ctx));
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

/// The person's sessions (ASVS-06): every browser they are signed in from, in every
/// workspace, this one marked; any other can be signed out, or all of them at once. Ending
/// one is a sensitive action: the API client asks for the password first when the last
/// one was more than five minutes ago (ASVS-07, stepup.js).
export function sessionsSection(ctx) {
  const list = h("ul", { class: "os-sessions", attrs: { "data-testid": "sessions-list", "aria-labelledby": "profile-h-sessions" } });
  const note = h("p", { class: "os-muted os-small", attrs: { "aria-live": "polite", "data-testid": "sessions-note" } });
  const quiet = (err) => ctx.failed?.(err) || err?.code === "CS-AUTH-0013";
  const others = button(t("sessions.end-others"), {
    variant: "secondary", size: "sm", attrs: { "data-testid": "sessions-end-others" },
    onClick: async () => {
      try {
        const r = await ctx.api.endOtherSessions();
        toast(t("sessions.ended-others", { n: r?.ended ?? 0 }), "success");
      } catch (err) { if (!quiet(err)) toastError(err); }
      await load();
    },
  });
  const section = h("section", { class: "os-profile__section", attrs: { "aria-labelledby": "profile-h-sessions", "data-testid": "profile-sessions" } },
    h("h3", { id: "profile-h-sessions", class: "os-profile__h", text: t("sessions.title") }),
    h("p", { class: "os-muted os-small", text: t("sessions.text") }),
    list, note, others);

  async function end(row) {
    try {
      await ctx.api.endSession(row.id);
      toast(t("sessions.ended"), "success");
    } catch (err) { if (!quiet(err)) toastError(err); }
    await load();
  }

  async function load() {
    let rows;
    try {
      rows = sessionRows((await ctx.api.sessions())?.items);
    } catch (err) {
      if (ctx.failed?.(err)) return;
      clear(list);
      note.textContent = t("sessions.failed");
      others.hidden = true;
      return;
    }
    clear(list);
    for (const r of rows) {
      const client = r.client || t("sessions.unknown-client");
      const when = fmtDate(r.lastSeen);
      list.append(h("li", { class: "os-sessions__row", attrs: { "data-testid": "session-row", "data-current": String(r.current) } },
        h("div", { class: "os-sessions__who" },
          h("b", { text: client }),
          r.current ? h("span", { class: "os-sessions__this", attrs: { "data-testid": "session-current" }, text: t("sessions.this") }) : null,
          h("span", { class: "os-muted os-small", text: t("sessions.where", { workspace: r.workspace, when }) })),
        r.current ? null : button(t("sessions.end"), {
          variant: "subtle", size: "sm",
          attrs: { "aria-label": t("sessions.end-label", { client, when }), "data-testid": "session-end" },
          onClick: () => end(r),
        })));
    }
    const alone = rows.every((r) => r.current);
    note.textContent = alone ? t("sessions.none-other") : "";
    others.hidden = alone;
  }

  load();
  return section;
}

/// The person's own data (ASVS-16): download what this workspace holds about them as a
/// JSON file (`GET /users/me/export`), or delete their account (`DELETE /users/me`; the
/// step-up prompt asks for the password when needed). Evidence stays: the text says so.
export function dataSection(ctx) {
  const download = button(t("privacy.export"), {
    variant: "secondary", size: "sm", attrs: { "data-testid": "privacy-export" },
    onClick: async () => {
      let doc;
      try { doc = await ctx.api.exportMe(); } catch (err) { if (!ctx.failed?.(err)) toastError(err); return; }
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, attrs: { download: "openseal-personal-data.json" } });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(t("privacy.exported"), "success");
    },
  });
  const erase = button(t("privacy.erase"), {
    variant: "danger", size: "sm", attrs: { "data-testid": "privacy-erase" },
    onClick: async () => {
      const ok = await confirmDialog(t("privacy.erase-title"), t("privacy.erase-text"), { confirm: t("privacy.erase-confirm"), danger: true });
      if (!ok) return;
      try {
        await ctx.api.eraseMe();
      } catch (err) {
        if (!(ctx.failed?.(err) || err?.code === "CS-AUTH-0013")) toastError(err);
        return;
      }
      closePanel();
      ctx.session = null;
      toast(t("privacy.erased"), "success");
      ctx.navigate("#/signin");
    },
  });
  return h("section", { class: "os-profile__section", attrs: { "aria-labelledby": "profile-h-data", "data-testid": "profile-data" } },
    h("h3", { id: "profile-h-data", class: "os-profile__h", text: t("privacy.title") }),
    h("p", { class: "os-muted os-small", text: t("privacy.text") }),
    h("div", { class: "os-actions" }, download, erase));
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

