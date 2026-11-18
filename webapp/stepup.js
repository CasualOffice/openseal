// Step-up re-authentication (ASVS-07, docs/40 §2). A sensitive call (a new API key,
// a role change, a webhook's address, the workspace's security settings, ending other
// sessions) answers `403 CS-AUTH-0013` when the session has not proved its password in
// the last five minutes. The API client then asks this dialog (`setStepUp`): the person
// enters their password, and their authenticator's code when they have a second factor;
// on success the client repeats the call once. Cancel leaves the refusal standing.
//
// The rules (which field, which message) are in authmodel.js; this file only draws.

import { h } from "./dom.js";
import { t } from "./i18n.js";
import { openDialog, field } from "./ui/index.js";
import { errorMessage } from "./api.js";
import { stepUpNeedsCode, stepUpFailure, factorError } from "./authmodel.js";

/// Ask the person to re-authenticate. Resolves true once the server took it, false when
/// they cancelled.
export async function stepUpDialog(api) {
  let needsCode = false;
  try { needsCode = stepUpNeedsCode(await api.session()); } catch { needsCode = false; }
  const password = field(t("stepup.password"), { id: "stepup-password", type: "password", autocomplete: "current-password", maxLength: 256, required: true });
  const code = needsCode
    ? field(t("stepup.code"), { id: "stepup-code", autocomplete: "one-time-code", maxLength: 64, help: t("stepup.code-help") })
    : null;
  const problem = h("p", { class: "os-field-error", attrs: { "aria-live": "polite", "data-testid": "stepup-problem" } });
  const v = await openDialog({
    title: t("stepup.title"),
    description: t("stepup.text"),
    className: "os-stepup",
    build(body) {
      body.append(password.el);
      if (code) {
        code.input.setAttribute("inputmode", "numeric");
        body.append(code.el);
      }
      body.append(problem);
    },
    actions: [
      { label: t("action.cancel"), value: false },
      {
        label: t("stepup.confirm"), variant: "primary", attrs: { "data-testid": "stepup-confirm" },
        onClick: async () => {
          password.setError("");
          code?.setError("");
          problem.textContent = "";
          if (!password.input.value) { password.setError(t("stepup.password-missing")); password.input.focus(); return undefined; }
          const body = { password: password.input.value };
          if (code) {
            const missing = factorError(code.input.value);
            if (missing) { code.setError(t(missing)); code.input.focus(); return undefined; }
            body.code = code.input.value.replace(/\s+/g, "");
          }
          try {
            await api.reauthenticate(body);
          } catch (err) {
            const f = stepUpFailure(err);
            if (f?.field === "password") { password.setError(t(f.key)); password.input.value = ""; password.input.focus(); return undefined; }
            if (f?.field === "code" && code) { code.setError(t(f.key)); code.input.value = ""; code.input.focus(); return undefined; }
            problem.textContent = errorMessage(err);
            return undefined;
          }
          return true;
        },
      },
    ],
  });
  return v === true;
}
