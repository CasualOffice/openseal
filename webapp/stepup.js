// Step-up re-authentication (ASVS-07, docs/40 §2). A sensitive call (a new API key,
// a role change, a webhook's address, the workspace's security settings, ending other
// sessions, managing passkeys) answers `403 CS-AUTH-0013` when the session has not proved
// its password in the last five minutes. The API client then asks this dialog
// (`setStepUp`): the person enters their password, and proves their second factor when
// they have one: the authenticator's code, or their passkey (CON-13) through the
// browser's own prompt. On success the client repeats the call once. Cancel leaves the
// refusal standing.
//
// The rules (which field, which message) are in authmodel.js; this file only draws.

import { h } from "./dom.js";
import { t } from "./i18n.js";
import { openDialog, field } from "./ui/index.js";
import { errorMessage } from "./api.js";
import { stepUpNeedsCode, stepUpFailure, factorError } from "./authmodel.js";
import { getPasskey, hasPasskey, passkeysSupported, ceremonyError } from "./passkey.js";

/// Ask the person to re-authenticate. Resolves true once the server took it, false when
/// they cancelled.
export async function stepUpDialog(api) {
  let session = null;
  try { session = await api.session(); } catch { session = null; }
  const factor = stepUpNeedsCode(session);
  const passkey = factor && hasPasskey(session) && passkeysSupported();
  // The code field for someone with the authenticator app (or when the server did not
  // say which factors they have).
  const needsCode = factor && (session?.factors ? !!session.factors.totp : true);
  const password = field(t("stepup.password"), { id: "stepup-password", type: "password", autocomplete: "current-password", maxLength: 256, required: true });
  const code = needsCode
    ? field(t("stepup.code"), { id: "stepup-code", autocomplete: "one-time-code", maxLength: 64, help: t("stepup.code-help") })
    : null;
  const problem = h("p", { class: "os-field-error", attrs: { "aria-live": "polite", "data-testid": "stepup-problem" } });

  /// Send `extra` with the password; true when the server took it, undefined (the
  /// dialog stays open, the problem said) when not.
  async function attempt(extra, factorField) {
    try {
      await api.reauthenticate({ password: password.input.value, ...extra });
    } catch (err) {
      const f = stepUpFailure(err);
      if (f?.field === "password") { password.setError(t(f.key)); password.input.value = ""; password.input.focus(); return undefined; }
      if (f?.field === "code" && factorField) { factorField.setError(t(f.key)); factorField.input.value = ""; factorField.input.focus(); return undefined; }
      problem.textContent = f?.field === "code" ? t("passkey.refused") : errorMessage(err);
      return undefined;
    }
    return true;
  }

  const reset = () => { password.setError(""); code?.setError(""); problem.textContent = ""; };
  const passwordGiven = () => {
    if (password.input.value) return true;
    password.setError(t("stepup.password-missing"));
    password.input.focus();
    return false;
  };

  const actions = [{ label: t("action.cancel"), value: false }];
  if (passkey) {
    actions.push({
      label: t("stepup.passkey"), variant: code ? "secondary" : "primary", icon: "key-round",
      attrs: { "data-testid": "stepup-passkey", "data-os-command": "auth.stepup-passkey" },
      onClick: async () => {
        reset();
        if (!passwordGiven()) return undefined;
        let assertion;
        try {
          assertion = await getPasskey(api, "reauthenticate");
        } catch (err) {
          const k = ceremonyError(err);
          problem.textContent = k ? t(k) : errorMessage(err);
          return undefined;
        }
        return attempt({ passkey: assertion }, null);
      },
    });
  }
  if (code || !passkey) {
    actions.push({
      label: t("stepup.confirm"), variant: "primary", attrs: { "data-testid": "stepup-confirm" },
      onClick: async () => {
        reset();
        if (!passwordGiven()) return undefined;
        const extra = {};
        if (code) {
          const missing = factorError(code.input.value);
          if (missing) { code.setError(t(missing)); code.input.focus(); return undefined; }
          extra.code = code.input.value.replace(/\s+/g, "");
        }
        return attempt(extra, code);
      },
    });
  }
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
    actions,
  });
  return v === true;
}
