// Accept an invitation (WEB-06 AD-01): the page the invitation email links to,
// `app.html#/accept-invite?token=…`. The token stays in the URL fragment, so it never
// reaches a server log or a Referer; the page sends it once in the body of
// `POST /api/v1/auth/accept-invite` with the new password (and a name, optionally),
// then clears it from the address bar. No session is needed or created.

import { h } from "./dom.js";
import { t } from "./i18n.js";
import { button, busy } from "./ui/index.js";
import { errorMessage } from "./api.js";

const MIN = 12;

/// The token in a route's parameters, or "".
export function inviteToken(params) {
  const v = params?.get("token") || "";
  return /^[A-Za-z0-9._~-]{1,512}$/.test(v) ? v : "";
}

export function mount(view, ctx, _match, params) {
  const token = inviteToken(params);
  // Out of the address bar and the history at once.
  history.replaceState(null, "", `${location.pathname}${location.search}#/accept-invite`);
  const card = h("section", { class: "os-signin", attrs: { "aria-labelledby": "inv-title" } },
    h("img", { class: "os-signin__logo os-logo--light", src: "assets/logo.svg", alt: "OpenSeal", width: 184, height: 36 }),
    h("img", { class: "os-signin__logo os-logo--dark", src: "assets/logo-dark.svg", alt: "OpenSeal", width: 184, height: 36 }),
    h("h1", { id: "inv-title", class: "os-signin__title", text: t("invite.title") }));
  view.append(h("div", { class: "os-signin-wrap" }, card));

  const toSignIn = h("a", { class: "os-btn os-btn--secondary os-btn--lg", href: "#/signin" }, h("span", { text: t("invite.to-signin") }));
  if (!token) {
    card.append(h("p", { class: "os-field-error", attrs: { role: "alert", "data-testid": "invite-missing" }, text: t("invite.missing") }), toSignIn);
    return;
  }
  const errId = "inv-error";
  const name = h("input", { id: "inv-name", class: "os-input", autocomplete: "name", maxLength: 255 });
  const pw = h("input", { id: "inv-pw", class: "os-input", type: "password", autocomplete: "new-password", maxLength: 256, attrs: { "aria-describedby": `inv-pw-help ${errId}`, autofocus: true } });
  const pw2 = h("input", { id: "inv-pw2", class: "os-input", type: "password", autocomplete: "new-password", maxLength: 256, attrs: { "aria-describedby": errId } });
  const error = h("p", { id: errId, class: "os-field-error", attrs: { role: "alert" } });
  const submit = button(t("invite.submit"), { variant: "primary", size: "lg", type: "submit" });
  const form = h("form", { class: "os-signin__form", attrs: { novalidate: true, "aria-labelledby": "inv-title" } },
    h("label", { class: "os-label", attrs: { for: "inv-name" }, text: t("invite.name") }), name,
    h("label", { class: "os-label", attrs: { for: "inv-pw" }, text: t("invite.password") }), pw,
    h("p", { id: "inv-pw-help", class: "os-help", text: t("invite.password-help", { n: MIN }) }),
    h("label", { class: "os-label", attrs: { for: "inv-pw2" }, text: t("invite.password-again") }), pw2,
    error, submit);
  card.append(h("p", { class: "os-muted", text: t("invite.lede") }), form);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.textContent = "";
    for (const i of [pw, pw2]) i.removeAttribute("aria-invalid");
    const bad = pw.value.length < MIN ? [pw, t("invite.password-help", { n: MIN })] : pw.value !== pw2.value ? [pw2, t("invite.mismatch")] : null;
    if (bad) { error.textContent = bad[1]; bad[0].setAttribute("aria-invalid", "true"); bad[0].focus(); return; }
    try {
      await busy(submit, () => ctx.api.acceptInvite({ token, password: pw.value, ...(name.value.trim() ? { name: name.value.trim() } : {}) }));
      form.replaceWith(h("p", { attrs: { role: "status", "data-testid": "invite-done" }, text: t("invite.done") }), toSignIn);
      toSignIn.focus();
    } catch (err) {
      error.textContent = err.code === "CS-AUTH-0002" ? t("invite.invalid") : errorMessage(err);
      pw.value = ""; pw2.value = "";
      pw.focus();
    }
  });
  pw.focus();
}
