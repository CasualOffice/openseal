// Sign-in (WEB-01; UX-04): local email and password, `POST /api/v1/auth/login` (docs/40).
//
// UX-04 brings it to what a DocuSign user expects: a message under each field that is
// missing (each in its field's `aria-describedby`), an alert above the fields when the
// server refuses the sign-in, a show/hide password button, "Forgot password?" (the reset
// request, `NOT_ON_SERVER.passwordReset`: said to be unavailable on a server without
// it), a company sign-in button only when the server names an identity provider
// (`NOT_ON_SERVER.authProviders`; SSO itself is slice 3, FG-173), and a footer.

import { h, clear } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, busy } from "./ui/index.js";
import { errorMessage } from "./api.js";

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export async function mount(view, ctx) {
  const hint = ctx.mock ? (await import("./mock.js")).MOCK : null;
  const card = h("section", { class: "os-signin", attrs: { "aria-labelledby": "signin-title" } });
  const mockQ = ctx.mock ? "?mock=1" : "";
  const foot = h("footer", { class: "os-signin__foot" },
    h("a", { href: `verify.html${mockQ}`, text: t("signin.verify") }),
    h("a", { href: `index.html${mockQ}`, text: t("signin.about") }));
  view.append(h("div", { class: "os-signin-wrap" }, card, foot));

  const logo = () => [
    h("img", { class: "os-signin__logo os-logo--light", src: "assets/logo.svg", alt: "OpenSeal", width: 184, height: 36 }),
    h("img", { class: "os-signin__logo os-logo--dark", src: "assets/logo-dark.svg", alt: "OpenSeal", width: 184, height: 36 }),
  ];

  // ---- Sign in ---------------------------------------------------------------------------
  function signIn(prefill = "") {
    clear(card);
    const email = h("input", { id: "signin-email", class: "os-input", type: "email", name: "email", autocomplete: "username", required: true, value: prefill, attrs: { "aria-describedby": "signin-email-error" } });
    const emailErr = h("p", { id: "signin-email-error", class: "os-field-error" });
    const password = h("input", { id: "signin-password", class: "os-input", type: "password", name: "password", autocomplete: "current-password", required: true, attrs: { "aria-describedby": "signin-password-error" } });
    const passwordErr = h("p", { id: "signin-password-error", class: "os-field-error" });
    // Show/hide: a toggle button inside the field, its state in aria-pressed.
    // Named by its content ("Show" and a hidden "password"), not aria-label, so the visible word starts the name (SC 2.5.3)
    // and the field labelled "Password" stays the only thing that label finds.
    const show = h("button", { type: "button", class: "os-btn os-btn--ghost os-btn--sm os-password__toggle", attrs: { "aria-pressed": "false", "aria-controls": "signin-password" } },
      h("span", { text: t("signin.show") }), h("span", { class: "os-sr-only", text: ` ${t("signin.show-what")}` }));
    show.addEventListener("click", () => {
      const on = password.type === "password";
      password.type = on ? "text" : "password";
      show.setAttribute("aria-pressed", String(on));
      password.focus();
    });
    const alert = h("div", { class: "os-callout os-callout--danger os-signin__alert", attrs: { role: "alert", "data-testid": "signin-alert" }, hidden: true });
    const forgot = h("button", { type: "button", class: "os-signin__link os-signin__forgot", text: t("signin.forgot") });
    forgot.addEventListener("click", () => reset(email.value.trim()));
    const submit = button(t("signin.submit"), { variant: "primary", size: "lg", type: "submit" });
    const form = h("form", { class: "os-signin__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } },
      alert,
      h("label", { class: "os-label", attrs: { for: "signin-email" }, text: t("signin.email") }), email, emailErr,
      h("div", { class: "os-signin__labelrow" },
        h("label", { class: "os-label", attrs: { for: "signin-password" }, text: t("signin.password") }), forgot),
      h("div", { class: "os-password" }, password, show), passwordErr,
      submit);
    const fieldError = (input, node, text) => {
      node.textContent = text;
      if (text) input.setAttribute("aria-invalid", "true"); else input.removeAttribute("aria-invalid");
    };
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      alert.hidden = true;
      clear(alert);
      fieldError(email, emailErr, email.value.trim() ? "" : t("signin.email-missing"));
      fieldError(password, passwordErr, password.value ? "" : t("signin.password-missing"));
      const first = [email, password].find((i) => i.getAttribute("aria-invalid") === "true");
      if (first) { first.focus(); return; }
      try {
        await busy(submit, () => ctx.api.login(email.value.trim(), password.value));
        ctx.session = await ctx.api.session();
        ctx.navigate("#/home");
      } catch (err) {
        const bad = err.code === "CS-AUTH-0007";
        alert.append(icon("circle-alert", { size: 20 }),
          h("div", {}, h("p", { class: "os-callout__title", text: t("signin.invalid-title") }), h("p", { text: bad ? t("signin.invalid") : errorMessage(err) })));
        alert.hidden = false;
        password.value = "";
        password.focus();
      }
    });
    const sso = h("div", { class: "os-signin__sso", attrs: { "data-testid": "signin-sso" }, hidden: true });
    card.append(
      ...logo(),
      h("h1", { id: "signin-title", class: "os-signin__title", text: t("signin.title") }),
      h("p", { class: "os-muted", text: t("signin.lede") }),
      form,
      sso,
      hint ? h("p", { class: "os-signin__hint", text: t("signin.mock-hint", hint) }) : null,
    );
    providers(sso);
    // Focused here, not by an `autofocus` attribute: WebKit runs a page's autofocus at a
    // later rendering update, which on a slow machine lands after typing has begun and
    // pulls the caret back into this field mid-password (WEB-06, the CI e2e on Linux).
    (prefill ? password : email).focus();
  }

  /// The company sign-in buttons: shown only when the server names an identity
  /// provider. A server without the call (or with none configured) shows nothing.
  async function providers(sso) {
    if (!ctx.api.available("authProviders")) return;
    let items = [];
    try { items = (await ctx.api.authProviders())?.items || []; } catch { items = []; }
    const usable = items.filter((p) => p && typeof p.url === "string" && /^\/[^/]/.test(p.url) && typeof p.name === "string");
    if (!usable.length || !sso.isConnected) return;
    sso.append(h("p", { class: "os-signin__or", text: t("signin.or") }));
    for (const p of usable) {
      sso.append(h("a", { class: "os-btn os-btn--secondary os-btn--lg", href: p.url }, icon("key-round", { size: 20 }), h("span", { text: t("signin.sso", { name: p.name.slice(0, 80) }) })));
    }
    sso.hidden = false;
  }

  // ---- Forgot password ---------------------------------------------------------------------
  function reset(prefill) {
    clear(card);
    let email = null;
    const back = button(t("reset.back"), { icon: "chevron-left", variant: "ghost", onClick: () => signIn(email?.value.trim() || prefill) });
    back.classList.add("os-signin__back");
    const head = [...logo(), h("h1", { id: "signin-title", class: "os-signin__title", text: t("reset.title") })];
    if (!ctx.api.available("passwordReset")) {
      card.append(...head,
        h("p", { attrs: { "data-testid": "reset-unavailable" }, text: t("reset.unavailable") }), back);
      back.focus();
      return;
    }
    email = h("input", { id: "reset-email", class: "os-input", type: "email", autocomplete: "username", required: true, value: prefill, attrs: { "aria-describedby": "reset-email-error" } });
    const err = h("p", { id: "reset-email-error", class: "os-field-error" });
    const submit = button(t("reset.submit"), { variant: "primary", size: "lg", type: "submit" });
    const form = h("form", { class: "os-signin__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } },
      h("label", { class: "os-label", attrs: { for: "reset-email" }, text: t("signin.email") }), email, err, submit);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const v = email.value.trim();
      err.textContent = EMAIL.test(v) ? "" : t("signin.email-missing");
      if (err.textContent) { email.setAttribute("aria-invalid", "true"); email.focus(); return; }
      email.removeAttribute("aria-invalid");
      try {
        await busy(submit, () => ctx.api.requestPasswordReset(v));
      } catch (x) {
        err.textContent = errorMessage(x);
        return;
      }
      // The same answer whether or not the address has an account (no enumeration).
      form.replaceWith(h("p", { attrs: { role: "status", "data-testid": "reset-sent" }, text: t("reset.sent", { email: v }) }));
      back.focus();
    });
    card.append(...head, h("p", { class: "os-muted", text: t("reset.lede") }), form, back);
    email.focus();
  }

  signIn();
}
