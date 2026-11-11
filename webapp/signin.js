// Sign-in (WEB-01): local email and password, `POST /api/v1/auth/login` (docs/40).
// SSO arrives with slice 3 (docs/06 §Release 1: after Release 1).

import { h } from "./dom.js";
import { t } from "./i18n.js";
import { button, busy } from "./ui/index.js";
import { errorMessage } from "./api.js";

export async function mount(view, ctx) {
  const hint = ctx.mock ? (await import("./mock.js")).MOCK : null;
  const errId = "signin-error";
  const email = h("input", { id: "signin-email", class: "os-input", type: "email", name: "email", autocomplete: "username", required: true, attrs: { "aria-describedby": errId } });
  const password = h("input", { id: "signin-password", class: "os-input", type: "password", name: "password", autocomplete: "current-password", required: true, attrs: { "aria-describedby": errId } });
  const error = h("p", { id: errId, class: "os-field-error", attrs: { role: "alert" } });
  const submit = button(t("signin.submit"), { variant: "primary", size: "lg", type: "submit" });
  const form = h("form", { class: "os-signin__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } },
    h("label", { class: "os-label", attrs: { for: "signin-email" }, text: t("signin.email") }), email,
    h("label", { class: "os-label", attrs: { for: "signin-password" }, text: t("signin.password") }), password,
    error, submit);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.textContent = "";
    for (const i of [email, password]) i.removeAttribute("aria-invalid");
    if (!email.value.trim() || !password.value) {
      error.textContent = t("signin.missing");
      (email.value.trim() ? password : email).setAttribute("aria-invalid", "true");
      (email.value.trim() ? password : email).focus();
      return;
    }
    try {
      await busy(submit, () => ctx.api.login(email.value.trim(), password.value));
      ctx.session = await ctx.api.session();
      ctx.navigate("#/home");
    } catch (err) {
      error.textContent = err.code === "CS-AUTH-0007" ? t("signin.invalid") : errorMessage(err);
      password.value = "";
      password.setAttribute("aria-invalid", "true");
      password.focus();
    }
  });
  const card = h("section", { class: "os-signin" },
    h("img", { class: "os-signin__logo os-logo--light", src: "assets/logo.svg", alt: "OpenSeal", width: 184, height: 36 }),
    h("img", { class: "os-signin__logo os-logo--dark", src: "assets/logo-dark.svg", alt: "OpenSeal", width: 184, height: 36 }),
    h("h1", { id: "signin-title", class: "os-signin__title", text: t("signin.title") }),
    h("p", { class: "os-muted", text: t("signin.lede") }),
    form,
    hint ? h("p", { class: "os-signin__hint", text: t("signin.mock-hint", hint) }) : null,
  );
  view.append(h("div", { class: "os-signin-wrap" }, card));
  // Focused here, not by an `autofocus` attribute: WebKit runs a page's autofocus at a
  // later rendering update, which on a slow machine lands after typing has begun and
  // pulls the caret back into this field mid-password (WEB-06, the CI e2e on Linux).
  email.focus();
}
