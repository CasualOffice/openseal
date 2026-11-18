// The password strength meter (ASVS 2.1.8, ASVS-03) under every field that sets a staff
// password: accept-invite (acceptinvite.js), the profile's new password (profile.js) and
// an administrator setting a member's password (admin.js). Four bars and one line, "Password
// strength: Weak", with up to two pieces of advice; read politely by screen readers, never
// an alert. Advisory: it never blocks a password the server's own policy takes.
//
// The score is pwstrength.js; every string comes through `t()` and goes in as text.

import { h } from "./dom.js";
import { t } from "./i18n.js";
import { passwordStrength } from "./pwstrength.js";

/// A meter with the id `id`, empty until something is typed. `update(password, inputs)`
/// scores `password` for the person whose name and email are `inputs`. Returns
/// `{ el, update }`; `el.id` is for the field's `aria-describedby`.
export function strengthMeter(id) {
  const bars = h("span", { class: "os-pwmeter__bars", attrs: { "aria-hidden": "true" } },
    ...[0, 1, 2, 3].map(() => h("span", { class: "os-pwmeter__bar" })));
  const level = h("span", { class: "os-pwmeter__level", attrs: { "data-testid": "pw-strength-level" } });
  const advice = h("span", { class: "os-pwmeter__advice", attrs: { "data-testid": "pw-strength-advice" } });
  const el = h("div", { id, class: "os-pwmeter", hidden: true, attrs: { "data-testid": "pw-strength", "aria-live": "polite" } },
    bars, h("p", { class: "os-pwmeter__text" }, level, advice));
  const update = (password, inputs = []) => {
    const s = passwordStrength(password, inputs);
    el.hidden = s.score === null;
    if (s.score === null) { el.removeAttribute("data-score"); level.textContent = ""; advice.textContent = ""; return s; }
    el.setAttribute("data-score", String(s.score));
    level.textContent = t("pwstrength.label", { level: t(s.label) });
    advice.textContent = s.hints.length ? ` ${s.hints.map((k) => t(k)).join(" ")}` : "";
    return s;
  };
  return { el, update };
}
