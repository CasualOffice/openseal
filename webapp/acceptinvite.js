// Accept an invitation (WEB-06 AD-01; rebuilt on the approved canvas in WEB-18 lane E):
// the page the invitation email links to, `app.html#/accept-invite?token=…`. The token
// stays in the URL fragment, so it never reaches a server log or a Referer; the page
// sends it once in the body of `POST /api/v1/auth/accept-invite` with the new password
// (`AcceptInvite`: token and password only; the name is the admin's), then clears it
// from the address bar. No session is needed or created.
//
// The rules (length, match) are authmodel.js; they show as a checklist that ticks while
// the person types, and the one alert names what still stops the form.

import { h } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, busy } from "./ui/index.js";
import { errorMessage } from "./api.js";
import { MIN_PASSWORD, inviteChecks, inviteError, inviteToken } from "./authmodel.js";
import { authLayout, cardHead, passwordField, setFieldError, successBlock } from "./authview.js";

export { inviteToken };

export function mount(view, ctx, _match, params) {
  const token = inviteToken(params);
  // Out of the address bar and the history at once.
  history.replaceState(null, "", `${location.pathname}${location.search}#/accept-invite`);
  const card = authLayout(view, { labelledBy: "inv-title", aside: true });
  card.append(cardHead("inv-title", t("invite.title"), token ? t("invite.lede") : null));
  if (!token) { missing(card); return; }
  form(card, ctx, token);
}

function toSignIn() {
  return h("a", { class: "os-btn os-btn--secondary os-btn--lg os-auth__submit", href: "#/signin", attrs: { "data-os-command": "auth.go-to-sign-in" } }, h("span", { text: t("invite.to-signin") }));
}

function missing(card) {
  const link = toSignIn();
  card.append(h("div", { class: "os-auth__alert", attrs: { role: "alert", "data-testid": "invite-missing" } },
    h("span", { class: "os-auth__alert-icon" }, icon("circle-alert", { size: 16 })),
    h("div", { class: "os-auth__alert-body" }, h("p", { text: t("invite.missing") }))), link);
}

/// The checklist under the first field: one row per rule, ticked when met. Polite, not
/// an alert: it changes on every key and must not interrupt.
function checklist() {
  const list = h("ul", { id: "inv-rules", class: "os-auth__rules" });
  const update = (pw, again) => {
    list.replaceChildren(...inviteChecks(pw, again).map((r) => h("li", { class: r.met ? "is-met" : "", attrs: { "data-rule": r.id } },
      h("span", { class: "os-auth__rule-dot", attrs: { "aria-hidden": "true" } }, icon(r.met ? "check" : "circle-dashed", { size: 12 })),
      h("span", { text: t(r.key, { n: MIN_PASSWORD }) }),
      h("span", { class: "os-sr-only", text: ` ${t(r.met ? "invite.rule-met" : "invite.rule-unmet")}` }))));
  };
  return { list, update };
}

function form(card, ctx, token) {
  const pw = passwordField({ id: "inv-pw", label: t("invite.password"), autocomplete: "new-password", describedBy: ["inv-rules"], command: "auth.toggle-password" });
  const pw2 = passwordField({ id: "inv-pw2", label: t("invite.password-again"), autocomplete: "new-password", command: "auth.toggle-password-again", revealLabel: t("invite.show-again") });
  const rules = checklist();
  rules.update("", "");
  // The one alert on the page: what stops the form, or the server's refusal.
  const error = h("p", { id: "inv-error", class: "os-auth__formerror", attrs: { role: "alert" } });
  const submit = button(t("invite.submit"), { variant: "primary", size: "lg", type: "submit", command: "auth.set-password" });
  submit.classList.add("os-auth__submit");
  pw.block.insertBefore(rules.list, pw.error);
  const f = h("form", { class: "os-auth__form", attrs: { novalidate: true, "aria-labelledby": "inv-title" } }, pw.block, pw2.block, error, submit);
  for (const input of [pw.input, pw2.input]) input.addEventListener("input", () => {
    rules.update(pw.input.value, pw2.input.value);
    if (input.getAttribute("aria-invalid") === "true" && !inviteError(pw.input.value, pw2.input.value)) clearErrors();
  });
  const clearErrors = () => { error.textContent = ""; setFieldError(pw.input, pw.error, ""); setFieldError(pw2.input, pw2.error, ""); };
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearErrors();
    const bad = inviteError(pw.input.value, pw2.input.value);
    if (bad) {
      const field = bad.field === "password" ? pw : pw2;
      error.textContent = t(bad.key, { n: MIN_PASSWORD });
      field.input.setAttribute("aria-invalid", "true");
      field.input.focus();
      return;
    }
    try {
      await busy(submit, () => ctx.api.acceptInvite(token, pw.input.value));
      const link = toSignIn();
      link.classList.replace("os-btn--secondary", "os-btn--primary");
      f.replaceWith(successBlock("invite-done", t("invite.done-title"), t("invite.done")), link);
      link.focus();
    } catch (err) {
      error.textContent = err.code === "CS-AUTH-0002" ? t("invite.invalid") : errorMessage(err);
      pw.input.value = ""; pw2.input.value = "";
      rules.update("", "");
      pw.input.focus();
    }
  });
  card.append(f);
  pw.input.focus();
}
