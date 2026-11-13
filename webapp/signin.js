// Sign-in (WEB-01, UX-04; rebuilt on the approved canvas in WEB-18 lane E):
// `POST /api/v1/auth/login` (docs/40).
//
// A centred card on the warm canvas with the seal mark (authview.js); the rules are
// authmodel.js. What a DocuSign user expects: a message under each field that is wrong
// (in its `aria-describedby`), checked again as the person fixes it; an alert above the
// fields when the server refuses; a reveal toggle in the password field; a busy submit;
// "Forgot password?" (`POST /auth/password-reset`, UXW-38); a company sign-in button only
// when the server names an identity provider (`GET /auth/providers`, UXW-39, empty until
// SSO, slice 3, FG-173); a footer. A session that owes a second factor (ASVS-01, `GET
// /auth/session` → `second_factor`) goes on to the code step, or to setting one up when
// the workspace's policy asks for it, before the app opens; both use the same card,
// fields and buttons as sign-in.

import { h } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, busy } from "./ui/index.js";
import { errorMessage, isDemoBuild } from "./api.js";
import { signInErrors, firstInvalid, resetError, usableProviders, signInFailure, owedFactor, factorError, groupSecret } from "./authmodel.js";
import { authLayout, cardHead, textField, passwordField, setFieldError, alertBox, footerLinks } from "./authview.js";

export async function mount(view, ctx) {
  const hint = ctx.mock ? (await import("./mock.js")).MOCK : null;
  const mockQ = ctx.mock ? "?mock=1" : "";
  const card = authLayout(view, {
    labelledBy: "signin-title",
    aside: true,
    footer: footerLinks([[`verify.html${mockQ}`, t("signin.verify")], [`index.html${mockQ}`, t("signin.about")]]),
  });
  const screens = {
    signIn: (prefill) => signIn(card, ctx, hint, prefill, screens),
    reset: (prefill) => reset(card, ctx, prefill, screens),
    verify: () => verifyFactor(card, ctx, screens),
    enrol: () => enrolFactor(card, ctx, screens),
  };
  // A session that signed in with its password but still owes the second factor (a
  // reload mid-sign-in) resumes at that step.
  // Asked only when this tab opened a session (it holds a CSRF token), so a plain visit
  // to sign-in makes no call that is bound to fail.
  let owed = null;
  if (ctx.api.hasCsrf()) {
    try { owed = owedFactor(await ctx.api.session()); } catch { owed = null; }
  }
  // The website's demo copy (SITE-04) starts with the demo account filled in.
  if (owed) screens[owed](); else screens.signIn(hint && isDemoBuild() ? hint.email : "");
}

/// Into the app, or on to the second factor the session still owes.
async function afterPassword(ctx, screens) {
  ctx.session = await ctx.api.session();
  const owed = owedFactor(ctx.session);
  if (owed) { ctx.session = null; screens[owed](); return; }
  ctx.navigate("#/home");
}

// ---- Sign in ---------------------------------------------------------------------------

function signIn(card, ctx, hint, prefill, screens) {
  card.replaceChildren();
  const email = textField({ id: "signin-email", label: t("signin.email"), type: "email", autocomplete: "username", value: prefill });
  const password = passwordField({ id: "signin-password", label: t("signin.password"), autocomplete: "current-password", command: "auth.toggle-password" });
  if (hint && isDemoBuild() && prefill === hint.email) password.input.value = hint.password;
  const alert = alertBox("signin-alert");
  const forgot = h("button", { type: "button", class: "os-auth__link", attrs: { "data-os-command": "auth.forgot-password" }, text: t("signin.forgot") });
  forgot.addEventListener("click", () => screens.reset(email.input.value.trim()));
  // The label row carries "Forgot password?" on the right, as in the products people know;
  // it follows the password field in the tab order, so Tab goes email → password → submit.
  const submit = button(t("signin.submit"), { variant: "primary", size: "lg", type: "submit", command: "auth.sign-in" });
  submit.classList.add("os-auth__submit");
  const form = h("form", { class: "os-auth__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } },
    alert.node, email.block, password.block, h("div", { class: "os-auth__row" }, forgot), submit);

  const fields = { email, password };
  const showErrors = (errors) => { for (const [k, f] of Object.entries(fields)) setFieldError(f.input, f.error, errors[k] ? t(errors[k]) : ""); };
  const values = () => ({ email: email.input.value, password: password.input.value });
  // Inline validation: once a field has shown an error, it is checked again as it changes,
  // so the message goes the moment it is fixed (and never appears before a first submit).
  for (const [k, f] of Object.entries(fields)) {
    f.input.addEventListener("input", () => {
      if (f.input.getAttribute("aria-invalid") !== "true") return;
      const msg = signInErrors(values())[k];
      setFieldError(f.input, f.error, msg ? t(msg) : "");
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    alert.hide();
    const errors = signInErrors(values());
    showErrors(errors);
    const first = firstInvalid(errors, ["email", "password"]);
    if (first) { fields[first].input.focus(); return; }
    try {
      await busy(submit, () => ctx.api.login(email.input.value.trim(), password.input.value));
      await afterPassword(ctx, screens);
    } catch (err) {
      alert.show(t("signin.invalid-title"), signInFailure(err) ? t(signInFailure(err)) : errorMessage(err));
      password.input.value = "";
      password.input.focus();
    }
  });

  const sso = h("div", { class: "os-auth__sso", attrs: { "data-testid": "signin-sso" }, hidden: true });
  card.append(
    cardHead("signin-title", t("signin.title"), t("signin.lede")),
    form,
    sso,
    // Sign-in has no sidebar, so its demo tag is not shown: the hint says demo mode itself.
    hint ? h("p", { class: "os-auth__hint", attrs: { role: "note" } }, icon("info", { size: 16 }),
      h("span", {}, h("strong", { text: `${t("mock.tag")}. ` }), document.createTextNode(t("signin.mock-hint", hint)))) : null,
  );
  providers(ctx, sso);
  // Focused here, not by an `autofocus` attribute: WebKit runs a page's autofocus at a
  // later rendering update, which on a slow machine lands after typing has begun and
  // pulls the caret back into this field mid-password (WEB-06, the CI e2e on Linux).
  (prefill ? password.input : email.input).focus();
}

/// The company sign-in buttons: shown only when the server names an identity provider.
/// A server without the call (or with none configured) shows nothing.
async function providers(ctx, sso) {
  if (!ctx.api.available("authProviders")) return;
  let items = [];
  try { items = (await ctx.api.authProviders())?.items || []; } catch { items = []; }
  const usable = usableProviders(items);
  if (!usable.length || !sso.isConnected) return;
  sso.append(h("p", { class: "os-auth__or", text: t("signin.or") }));
  for (const p of usable) {
    sso.append(h("a", { class: "os-btn os-btn--secondary os-btn--lg os-auth__sso-btn", href: p.url }, icon("key-round", { size: 20 }), h("span", { text: t("signin.sso", { name: p.name }) })));
  }
  sso.hidden = false;
}

// ---- Second factor (ASVS-01) -------------------------------------------------------------

/// "Sign in as someone else": end the half-signed-in session and start again.
function otherAccount(ctx, screens) {
  const b = button(t("mfa.other"), { icon: "chevron-left", variant: "ghost", command: "auth.mfa-other-account", onClick: async () => {
    try { await ctx.api.logout(); } catch { /* the session may already be gone */ }
    screens.signIn("");
  } });
  b.classList.add("os-auth__back");
  return b;
}

/// The code field: six digits, or a recovery code once the person asks for that.
function codeField(id, recovery) {
  const f = textField({ id, label: t(recovery ? "mfa.recovery" : "mfa.code"), autocomplete: "one-time-code", maxLength: recovery ? 64 : 8 });
  if (!recovery) f.input.setAttribute("inputmode", "numeric");
  return f;
}

function verifyFactor(card, ctx, screens, recovery = false) {
  card.replaceChildren();
  const code = codeField("mfa-code", recovery);
  const alert = alertBox("mfa-alert");
  const swap = h("button", { type: "button", class: "os-auth__link", attrs: { "data-os-command": "auth.mfa-switch-method" }, text: t(recovery ? "mfa.use-code" : "mfa.use-recovery") });
  swap.addEventListener("click", () => verifyFactor(card, ctx, screens, !recovery));
  const submit = button(t("mfa.submit"), { variant: "primary", size: "lg", type: "submit", command: "auth.mfa-verify" });
  submit.classList.add("os-auth__submit");
  const form = h("form", { class: "os-auth__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } },
    alert.node, code.block, h("div", { class: "os-auth__row" }, swap), submit);
  code.input.addEventListener("input", () => {
    if (code.input.getAttribute("aria-invalid") === "true") { const k = factorError(code.input.value, recovery); setFieldError(code.input, code.error, k ? t(k) : ""); }
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    alert.hide();
    const k = factorError(code.input.value, recovery);
    setFieldError(code.input, code.error, k ? t(k) : "");
    if (k) { code.input.focus(); return; }
    const v = code.input.value.trim();
    try {
      await busy(submit, () => ctx.api.verifySecondFactor(recovery ? { recovery_code: v } : { code: v.replace(/\s+/g, "") }));
      await afterPassword(ctx, screens);
    } catch (err) {
      alert.show(t("signin.invalid-title"), err?.code === "CS-AUTH-0012" ? t("mfa.invalid") : errorMessage(err));
      code.input.value = "";
      code.input.focus();
    }
  });
  card.append(cardHead("signin-title", t("mfa.title"), t(recovery ? "mfa.recovery-lede" : "mfa.lede")), form, otherAccount(ctx, screens));
  code.input.focus();
}

async function enrolFactor(card, ctx, screens) {
  card.replaceChildren();
  let seed = null;
  try { seed = await ctx.api.enrolTotp(); } catch (err) {
    card.append(cardHead("signin-title", t("mfa.enrol-title")),
      h("p", { class: "os-auth__note", attrs: { "data-testid": "mfa-unavailable" } }, icon("info", { size: 16 }), h("span", { text: err?.code === "CS-API-0009" ? t("mfa.unavailable") : errorMessage(err) })),
      otherAccount(ctx, screens));
    return;
  }
  if (!card.isConnected) return;
  const code = codeField("mfa-code", false);
  const alert = alertBox("mfa-alert");
  const submit = button(t("mfa.enrol-submit"), { variant: "primary", size: "lg", type: "submit", command: "auth.mfa-enrol" });
  submit.classList.add("os-auth__submit");
  // The setup key as text (typed into the app), and the `otpauth:` link that opens an
  // authenticator on the same device. Only an `otpauth:` URI from the server is linked.
  const uri = typeof seed?.otpauth_uri === "string" && seed.otpauth_uri.startsWith("otpauth://totp/") ? seed.otpauth_uri : null;
  const key = h("p", { class: "os-auth__note", attrs: { "data-testid": "mfa-secret" } }, icon("key-round", { size: 16 }),
    h("span", { text: t("mfa.secret", { secret: groupSecret(seed?.secret) }) }));
  const open = uri ? h("a", { class: "os-auth__link", href: uri, attrs: { "data-os-command": "auth.mfa-open-app" }, text: t("mfa.open-app") }) : null;
  const form = h("form", { class: "os-auth__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } },
    alert.node, key, open ? h("div", { class: "os-auth__row" }, open) : null, code.block, submit);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    alert.hide();
    const k = factorError(code.input.value, false);
    setFieldError(code.input, code.error, k ? t(k) : "");
    if (k) { code.input.focus(); return; }
    let done = null;
    try {
      done = await busy(submit, () => ctx.api.confirmTotp(code.input.value.replace(/\s+/g, "")));
    } catch (err) {
      alert.show(t("signin.invalid-title"), err?.code === "CS-AUTH-0012" ? t("mfa.invalid") : errorMessage(err));
      code.input.value = "";
      code.input.focus();
      return;
    }
    recoveryCodes(card, ctx, screens, Array.isArray(done?.recovery_codes) ? done.recovery_codes : []);
  });
  card.append(cardHead("signin-title", t("mfa.enrol-title"), t("mfa.enrol-lede")), form, otherAccount(ctx, screens));
  code.input.focus();
}

/// The ten recovery codes, shown once after enrolment, then into the app.
function recoveryCodes(card, ctx, screens, codes) {
  card.replaceChildren();
  const list = h("div", { class: "os-auth__form", attrs: { "data-testid": "mfa-recovery-codes" } },
    ...codes.map((c) => h("p", { class: "os-auth__note" }, h("code", { text: String(c) }))));
  const go = button(t("mfa.continue"), { variant: "primary", size: "lg", command: "auth.mfa-continue", onClick: () => afterPassword(ctx, screens) });
  go.classList.add("os-auth__submit");
  card.append(cardHead("signin-title", t("mfa.codes-title"), t("mfa.codes-lede")), list, go);
  go.focus();
}

// ---- Forgot password ---------------------------------------------------------------------

function reset(card, ctx, prefill, screens) {
  card.replaceChildren();
  let email = null;
  const back = button(t("reset.back"), { icon: "chevron-left", variant: "ghost", command: "auth.back-to-sign-in", onClick: () => screens.signIn(email?.input.value.trim() || prefill) });
  back.classList.add("os-auth__back");
  if (!ctx.api.available("passwordReset")) {
    card.append(cardHead("signin-title", t("reset.title")),
      h("p", { class: "os-auth__note", attrs: { "data-testid": "reset-unavailable" } }, icon("info", { size: 16 }), h("span", { text: t("reset.unavailable") })), back);
    back.focus();
    return;
  }
  email = textField({ id: "reset-email", label: t("signin.email"), type: "email", autocomplete: "username", value: prefill });
  const submit = button(t("reset.submit"), { variant: "primary", size: "lg", type: "submit", command: "auth.send-reset" });
  submit.classList.add("os-auth__submit");
  const form = h("form", { class: "os-auth__form", attrs: { novalidate: true, "aria-labelledby": "signin-title" } }, email.block, submit);
  email.input.addEventListener("input", () => {
    if (email.input.getAttribute("aria-invalid") === "true") { const k = resetError(email.input.value); setFieldError(email.input, email.error, k ? t(k) : ""); }
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = email.input.value.trim();
    const k = resetError(v);
    setFieldError(email.input, email.error, k ? t(k) : "");
    if (k) { email.input.focus(); return; }
    try {
      await busy(submit, () => ctx.api.requestPasswordReset(v));
    } catch (x) {
      setFieldError(email.input, email.error, errorMessage(x));
      return;
    }
    // The same answer whether or not the address has an account (no enumeration).
    form.replaceWith(h("p", { class: "os-auth__note os-auth__note--ok", attrs: { role: "status", "data-testid": "reset-sent" } },
      icon("mail", { size: 16 }), h("span", { text: t("reset.sent", { email: v }) })));
    back.focus();
  });
  card.append(cardHead("signin-title", t("reset.title"), t("reset.lede")), form, back);
  email.input.focus();
}
