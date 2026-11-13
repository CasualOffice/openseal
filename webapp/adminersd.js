// Admin › Signing and seals › Electronic disclosure (ERSD-01, UXW-12; docs/47 §As
// built: electronic disclosure). The account's electronic record and signature
// disclosure: the version every recipient must accept before signing, a preview of its
// text, and the versions published before. "Publish new version" opens a side panel
// with the text (the current one to start from) and its language; publishing is one
// request (`POST /ersd-versions`) that writes the next version and requires it, so
// envelopes already sent then ask for consent to it. Published versions are never
// edited: a change is a new version, and the panel says so.
//
// Built from existing components only (docs/47: the account card, the side panel, the
// definition list); the pure rules are adminmodel.js's (`ersdProblem`, `ersdPreview`,
// `nextErsdVersion`, `shortHash`), tested in Node. A member without `admin:account`
// gets the server's refusal in place.

import { h, clear, fmtDate } from "./dom.js";
import { t } from "./i18n.js";
import { button, errorState, skeletonBlock, openPanel, toast } from "./ui/index.js";
import { ersdProblem, ersdPreview, nextErsdVersion, shortHash, ERSD_MAX_BYTES } from "./adminmodel.js";

/// The Electronic disclosure card, loading itself; answers the element.
export function ersdCard(ctx) {
  const box = h("section", { class: "os-card os-adm__card", attrs: { "aria-labelledby": "ersd-h", "data-testid": "ersd-card", "aria-busy": "true" } },
    h("h2", { id: "ersd-h", class: "os-card__title", text: t("admin.sec.ersd") }), skeletonBlock({ height: 7 }));
  let state = null;

  async function load() {
    try {
      state = await ctx.api.ersd.get();
      box.removeAttribute("aria-busy");
      render();
    } catch (err) {
      box.removeAttribute("aria-busy");
      if (ctx.failed?.(err)) return;
      clear(box).append(h("h2", { id: "ersd-h", class: "os-card__title", text: t("admin.sec.ersd") }));
      errorState(box, err, load);
    }
  }

  function render() {
    const cur = state?.current || null;
    const items = state?.items || [];
    const row = (label, value, id) => [h("dt", { text: label }), h("dd", { text: value || t("admin.not-set"), attrs: id ? { "data-testid": id } : {} })];
    clear(box).append(
      h("div", { class: "os-card__head" },
        h("h2", { id: "ersd-h", class: "os-card__title", text: t("admin.sec.ersd") }),
        button(t("admin.ersd.publish-new"), { icon: "pencil", size: "sm", command: "admin.ersd.publish", onClick: publish })),
      h("p", { class: "os-muted os-small os-card__lede", text: t("admin.ersd.lede") }));
    if (!cur) {
      box.append(h("p", { class: "os-adm__card-text", attrs: { "data-testid": "ersd-none" }, text: t("admin.ersd.none") }));
    } else {
      box.append(
        h("dl", { class: "os-meta os-adm__meta" },
          row(t("admin.ersd.version"), cur.label, "ersd-version"),
          row(t("admin.ersd.language"), cur.language),
          row(t("admin.ersd.published"), fmtDate(cur.published_at)),
          row(t("admin.ersd.hash"), shortHash(cur.sha256))),
        h("p", { class: "os-adm__card-text", attrs: { "data-testid": "ersd-preview" }, text: cur.text == null ? t("admin.ersd.no-text") : ersdPreview(cur.text) }));
    }
    if (items.length) {
      box.append(h("h3", { class: "os-label", text: t("admin.ersd.history") }),
        h("ul", { class: "os-muted os-small", attrs: { "data-testid": "ersd-history" } },
          ...items.map((d) => h("li", { text: t("admin.ersd.history-item", { version: d.label, language: d.language, date: fmtDate(d.published_at) }) }))));
    }
  }

  async function publish() {
    const f = {};
    const cur = state?.current || null;
    const ok = await openPanel({
      id: "ersd-publish",
      title: t("admin.ersd.publish-title"),
      description: t("admin.ersd.publish-lede"),
      width: 32,
      build(body) {
        f.text = h("textarea", { id: "ersd-text", class: "os-input os-textarea", rows: 14, value: cur?.text || "", attrs: { autofocus: true, "aria-describedby": "ersd-text-help ersd-err" } });
        f.lang = h("input", { id: "ersd-lang", class: "os-input", value: cur?.language || "en", maxLength: 35, attrs: { "aria-describedby": "ersd-lang-help" } });
        f.err = h("p", { id: "ersd-err", class: "os-field-error", attrs: { role: "alert" } });
        body.append(
          h("label", { class: "os-label", attrs: { for: "ersd-text" }, text: t("admin.ersd.text") }), f.text,
          h("p", { id: "ersd-text-help", class: "os-help", text: t("admin.ersd.text-help", { max: ERSD_MAX_BYTES.toLocaleString() }) }),
          h("label", { class: "os-label", attrs: { for: "ersd-lang" }, text: t("admin.ersd.language") }), f.lang,
          h("p", { id: "ersd-lang-help", class: "os-help", text: t("admin.ersd.language-help") }), f.err);
      },
      actions: [
        { label: t("action.cancel"), value: null },
        {
          label: t("admin.ersd.publish"), variant: "primary",
          onClick: async () => {
            const text = f.text.value;
            const language = f.lang.value.trim() || "en";
            const why = ersdProblem(text, language);
            if (why) { f.err.textContent = t(why, { max: ERSD_MAX_BYTES.toLocaleString() }); (why === "admin.ersd.bad-language" ? f.lang : f.text).focus(); return undefined; }
            return ctx.api.ersd.publish({ text, language });
          },
        },
      ],
    });
    if (ok) {
      toast(t("admin.ersd.published-toast", { version: ok.label ?? String(nextErsdVersion(state?.items, ok.language)) }), "success");
      await load();
    }
  }

  load();
  return box;
}
