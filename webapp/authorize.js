// The OAuth consent screen (VS-08A, docs/40 §2): `app.html#/authorize?…`, where the
// server's authorization endpoint (`GET /api/v1/oauth/authorize`) hands an app's request.
// It shows which app asks to act as the signed-in member and with which permissions, and
// sends their answer (`POST /api/v1/oauth/authorize`); the server answers where the
// browser goes next: the app's registered redirect URI with a one-time code, or with
// `access_denied`. A request the server refuses (an unknown app, an unregistered
// redirect URI, a permission beyond the app's or the member's) is said here and never
// followed back to the app. Signing in first returns here (app.js keeps the address).

import { h } from "./dom.js";
import { icon } from "./icons.js";
import { t } from "./i18n.js";
import { button, busy } from "./ui/index.js";
import { errorMessage } from "./api.js";
import { authorizeParams } from "./adminmodel.js";
import { authLayout, cardHead } from "./authview.js";

export function mount(view, ctx, _match, params) {
  const req = authorizeParams(params);
  const card = authLayout(view, { labelledBy: "oa-title" });
  card.append(cardHead("oa-title", t("oauth.title"), null));
  if (!req) { refused(card, null); return; }
  const status = h("p", { class: "os-muted", attrs: { role: "status", "data-testid": "oauth-loading" }, text: t("oauth.loading") });
  card.append(status);
  (async () => {
    let checked;
    try {
      checked = await ctx.api.oauth.request(req);
    } catch (err) {
      status.remove();
      if (ctx.failed(err)) return;
      refused(card, err);
      return;
    }
    status.remove();
    ask(card, ctx, req, checked);
  })();
}

/// The request cannot be completed: say so, with the server's reason, and offer Home.
function refused(card, err) {
  card.append(h("div", { class: "os-auth__alert", attrs: { role: "alert", "data-testid": "oauth-refused" } },
    h("span", { class: "os-auth__alert-icon" }, icon("circle-alert", { size: 16 })),
    h("div", { class: "os-auth__alert-body" },
      h("p", { text: t("oauth.refused") }),
      err ? h("p", { class: "os-muted os-small", text: errorMessage(err) }) : null)),
  h("a", { class: "os-btn os-btn--secondary os-btn--lg os-auth__submit", href: "#/home", attrs: { "data-os-command": "oauth.home" } }, h("span", { text: t("oauth.home") })));
}

function ask(card, ctx, req, checked) {
  const name = checked?.client?.name || "";
  const lede = h("p", { class: "os-auth__lede", attrs: { "data-testid": "oauth-app" }, text: t("oauth.lede", { app: name }) });
  const list = h("ul", { class: "os-auth__rules", attrs: { "aria-label": t("oauth.scopes"), "data-testid": "oauth-scopes" } },
    ...(checked?.scopes || []).map((s) => h("li", { attrs: { "data-scope": s } },
      h("span", { class: "os-auth__rule-dot", attrs: { "aria-hidden": "true" } }, icon("check", { size: 12 })),
      h("span", {}, h("code", { text: s }), h("span", { class: "os-muted os-small os-block", text: t(`admin.scope.${s}`) })))));
  const back = h("p", { class: "os-muted os-small", text: t("oauth.back", { uri: checked?.redirect_uri || "" }) });
  const error = h("p", { class: "os-auth__formerror", attrs: { role: "alert" } });
  const allow = button(t("oauth.allow"), { variant: "primary", size: "lg", command: "oauth.allow", attrs: { "data-testid": "oauth-allow" } });
  const deny = button(t("oauth.deny"), { variant: "secondary", size: "lg", command: "oauth.deny", attrs: { "data-testid": "oauth-deny" } });
  allow.classList.add("os-auth__submit");
  deny.classList.add("os-auth__submit");
  const answer = async (decision, b) => {
    error.textContent = "";
    try {
      const r = await busy(b, () => ctx.api.oauth.answer(req, decision));
      // The server built this address from the app's registered redirect URI.
      if (r?.redirect_to) location.assign(r.redirect_to);
    } catch (err) {
      if (ctx.failed(err)) return;
      error.textContent = errorMessage(err);
    }
  };
  allow.addEventListener("click", () => answer("allow", allow));
  deny.addEventListener("click", () => answer("deny", deny));
  card.append(lede, list, back, error, h("div", { class: "os-auth__actions" }, allow, deny));
  allow.focus();
}
