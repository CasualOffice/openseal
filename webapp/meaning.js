// "Matches by meaning" in the ⌘K command menu (WEB-18; canvas Main, the command menu;
// docs/33 §6 search by meaning, planned server side as WEB-19): the agreements whose
// text means what was typed, with the page and the matching passage. Registered only
// when ml.js says extraction is available; a server without the call (404) or with ML
// off answers nothing and the section never shows.
//
// The passage is the server's `snippet` runs ({text, mark?}); ui/palette.js draws them
// as text nodes and <mark> elements, never as markup.

import { t } from "./i18n.js";
import { mlStatus, featureOn, isUnavailable } from "./ml.js";

/// Turn the search answer into command-menu items. Pure, for the tests.
export function meaningItems(answer, navigate) {
  return (answer?.items || []).filter((x) => x && x.envelope_id).map((x) => ({
    id: `meaning:${x.envelope_id}:${x.page ?? ""}`,
    label: x.subject || t("envelope.untitled"),
    hint: Number.isInteger(x.page) ? t("ml.page", { n: x.page }) : null,
    snippet: Array.isArray(x.snippet) ? x.snippet.map((r) => ({ text: String(r?.text ?? ""), mark: !!r?.mark })) : null,
    icon: "file-search",
    run: () => navigate(x.status === "draft" ? `#/prepare/${encodeURIComponent(x.envelope_id)}` : `#/envelopes/${encodeURIComponent(x.envelope_id)}`),
  }));
}

/// Register the section while a screen is shown; returns the function that removes it.
/// The status check is asynchronous, so a screen that leaves first registers nothing.
export function registerMeaningSearch(ctx) {
  let off = null;
  let gone = false;
  mlStatus().then((st) => {
    if (gone || !featureOn(st, "extraction") || !ctx.registerPaletteProvider) return;
    off = ctx.registerPaletteProvider({
      id: "meaning",
      title: t("palette.meaning"),
      titleTone: "ml",
      note: t("palette.meaning-note"),
      icon: "os-sparkle",
      order: 15,
      async search(q, signal) {
        if (!q || q.trim().length < 3) return [];
        try {
          return meaningItems(await ctx.api.searchByMeaning(q, { signal, limit: 5 }), ctx.navigate);
        } catch (err) {
          if (isUnavailable(err) || err?.name === "AbortError") return [];
          throw err;
        }
      },
    });
  }, () => {});
  return () => { gone = true; off?.(); };
}
