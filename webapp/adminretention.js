// Admin › Retention (ASVS-18; docs/40 §3 `/retention`, docs/32 §7): the account's
// retention rules per data class, each days or empty (kept for ever, the default), and
// the retention job's dry run. Saving a rule is a sensitive action: the API client asks
// for the password when the last proof is older than five minutes (stepup.js).
//
// The rules are retentionmodel.js's (pure, tested); this file draws them.

import { h, clear } from "./dom.js";
import { t } from "./i18n.js";
import { button, field, toast, toastError, errorState } from "./ui/index.js";
import { CLASSES, daysText, rulesPatch, previewLines } from "./retentionmodel.js";

const CLASS = {
  draft: () => t("retention.class.draft"), ended: () => t("retention.class.ended"),
  completed: () => t("retention.class.completed"), sessions: () => t("retention.class.sessions"),
};

/// Draw the page into `body`; `head({buttons})` puts the actions in the page head.
export function retentionPage(body, ctx, head = () => {}) {
  const box = h("div", { class: "os-retention", attrs: { "data-testid": "retention" } });
  const report = h("div", { class: "os-retention__preview", attrs: { "aria-live": "polite", "data-testid": "retention-preview" } });
  body.append(box, report);
  let stored = null;
  let max = 36500;
  const fields = {};

  async function load() {
    try {
      const r = await ctx.api.retention();
      stored = r.keep_days || {};
      max = r.max_keep_days || max;
    } catch (err) {
      if (ctx.failed?.(err)) return;
      errorState(box, err, load);
      return;
    }
    render();
  }

  function render() {
    clear(box);
    for (const c of CLASSES) {
      fields[c] = field(CLASS[c](), {
        id: `retention-${c}`, value: daysText(stored[c]), inputMode: "numeric", maxLength: 6,
        help: t("retention.days-help", { max }), attrs: { "data-testid": `retention-${c}` },
      });
      box.append(fields[c].el);
    }
    head({ buttons: [
      button(t("retention.preview"), { variant: "secondary", attrs: { "data-testid": "retention-preview-btn" }, onClick: preview }),
      button(t("retention.save"), { variant: "primary", attrs: { "data-testid": "retention-save" }, onClick: save }),
    ] });
  }

  async function save() {
    for (const c of CLASSES) fields[c].setError("");
    const typed = Object.fromEntries(CLASSES.map((c) => [c, fields[c].input.value]));
    const r = rulesPatch(stored, typed, max);
    if (r.bad) {
      for (const c of r.bad) fields[c].setError(t("retention.days-bad", { max }));
      fields[r.bad[0]].input.focus();
      return;
    }
    if (!Object.keys(r.patch).length) { toast(t("retention.saved"), "success"); return; }
    try {
      const out = await ctx.api.setRetention(r.patch);
      stored = out.keep_days || stored;
    } catch (err) {
      if (!(ctx.failed?.(err) || err?.code === "CS-AUTH-0013")) toastError(err);
      return;
    }
    toast(t("retention.saved"), "success");
  }

  async function preview() {
    let p;
    try { p = await ctx.api.retentionPreview(); } catch (err) { if (!ctx.failed?.(err)) toastError(err); return; }
    clear(report).append(
      h("h2", { class: "os-card__title", text: t("retention.preview-title") }),
      h("ul", { class: "os-retention__lines" }, ...previewLines(p).map((l) => h("li", {
        attrs: { "data-testid": `retention-preview-${l.key}` },
        text: l.key === "held" ? t("retention.preview-held", { n: l.n })
          : l.key === "sessions" ? t("retention.preview-sessions", { n: l.n })
            : t("retention.preview-line", { class: CLASS[l.key](), n: l.n }),
      }))));
  }

  load();
}
