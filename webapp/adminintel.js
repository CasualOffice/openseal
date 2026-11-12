// Admin › Document intelligence (WEB-18; docs/33 §6–7, canvas Intelligence): the
// workspace admin turns each model feature on or off, sees which OCR scripts this server
// reads and which models its operator installed.
//
// State is intelmodel.js's (pure, tested); this file only draws it and wires the
// switches. A switch changes at once and is sent as `PATCH /account/settings/ml`; if the
// server refuses, the card goes back and the refusal is said (switchButton's toast). The
// session's ML status (ml.js) is refreshed after a change so other screens follow.
//
// Three page states besides the settings (docs/33 §7): "not installed on this server"
// (the server has no models, or does not serve the settings yet: the real server answers
// 404 until WEB-19) is an illustrated empty state naming the operator; "not in your
// plan" (`403 CS-ML-0011`) shows every card off and disabled with the reason; any other
// refusal is the usual error in place.

import { h, clear } from "./dom.js";
import { t } from "./i18n.js";
import { register } from "./commands.js";
import { mlStatus } from "./ml.js";
import { emptyState, errorState, skeletonBlock, switchButton, statusPill } from "./ui/index.js";
import { FEATURES, pageState, cards, onCount, withSetting, modelRows, cardModel, packChips } from "./intelmodel.js";

const NAME = {
  ocr: () => t("intel.f.ocr"), detect: () => t("intel.f.detect"), templates: () => t("intel.f.templates"),
  extract: () => t("intel.f.extract"), pii: () => t("intel.f.pii"),
};
const DESC = {
  ocr: () => t("intel.f.ocr-text"), detect: () => t("intel.f.detect-text"), templates: () => t("intel.f.templates-text"),
  extract: () => t("intel.f.extract-text"), pii: () => t("intel.f.pii-text"),
};
const SCRIPT = {
  latin: () => t("intel.script.latin"), cyrillic: () => t("intel.script.cyrillic"), greek: () => t("intel.script.greek"),
  cjk: () => t("intel.script.cjk"), arabic: () => t("intel.script.arabic"), devanagari: () => t("intel.script.devanagari"),
};
const PURPOSE = {
  ocr: () => t("intel.purpose.ocr"), "ocr-pack": () => t("intel.purpose.ocr"), templates: () => t("intel.purpose.templates"),
  extraction: () => t("intel.purpose.extraction"), personal_data: () => t("intel.purpose.personal_data"),
};
const MODEL_STATUS = { ready: () => t("intel.model.ready"), installing: () => t("intel.model.installing"), failed: () => t("intel.model.failed") };
const MODEL_TONE = { ready: "done", installing: "ml", failed: "danger" };
const scriptName = (s) => SCRIPT[s]?.() || s;

/// Draw the page into `body`; `head({badge})` puts the "n of 5 on" chip in the page head.
export function intelligence(body, ctx, head = () => {}) {
  const live = h("p", { class: "os-sr-only", attrs: { "aria-live": "polite", "data-testid": "intel-live" } });
  const box = h("div", { class: "os-intel", attrs: { "aria-busy": "true" } }, loadingSkeleton());
  body.append(box, live);
  let settings = null;
  let state = null;

  async function load() {
    clear(box).append(loadingSkeleton());
    box.setAttribute("aria-busy", "true");
    try {
      state = pageState({ settings: await ctx.api.getMlSettings() });
    } catch (error) {
      state = pageState({ error });
    }
    box.removeAttribute("aria-busy");
    settings = state.settings || null;
    if (state.kind === "forbidden" || state.kind === "error") {
      head({});
      if (ctx.failed(state.error)) return;
      errorState(box, state.error, load);
      return;
    }
    if (state.kind === "not-installed") { head({}); clear(box).append(notInstalled()); return; }
    render();
  }

  /// The settings page: the count, three promises, the cards, the models.
  function render() {
    const countChip = h("span", { class: "os-intel__count", attrs: { "data-testid": "intel-count" } });
    head({ badge: countChip });
    const list = cards(state);
    const rows = modelRows(settings);
    const ui = list.map((c) => featureCard(c, rows));
    const sync = () => {
      const now = cards(state);
      for (const [i, c] of now.entries()) ui[i].sync(c);
      const n = onCount(now);
      countChip.textContent = t("intel.count", { n });
      countChip.classList.toggle("is-on", n > 0);
    };
    controller.sync = sync;
    const features = h("div", { class: "os-intel__features" },
      state.kind === "no-plan" ? planNotice() : null,
      ...ui.map((u) => u.el),
      h("p", { class: "os-intel__footer", attrs: { "data-testid": "intel-footer" }, text: t("intel.footer") }));
    const grid = h("div", { class: `os-intel__grid${rows.length ? "" : " os-intel__grid--one"}` }, features, rows.length ? modelsCard(rows) : null);
    clear(box).append(promises(), grid);
    sync();
  }

  const controller = { sync: () => {} };

  /// Turn a feature on or off: at once on screen, then on the server; back if refused.
  async function change(card, on) {
    const before = settings;
    settings = withSetting(settings, card.key, on);
    state = { ...state, settings };
    controller.sync();
    try {
      const out = await ctx.api.patchMlSettings({ [card.key]: on });
      if (out && typeof out === "object") { settings = { ...settings, ...out }; state = { ...state, settings }; }
      controller.sync();
      live.textContent = t(on ? "intel.saved-on" : "intel.saved-off", { name: NAME[card.id]() });
      mlStatus({ refresh: true }).catch(() => {});
    } catch (err) {
      settings = before;
      state = { ...state, settings };
      controller.sync();
      throw err; // switchButton puts its knob back and says why
    }
  }

  /// One feature's card: glyph, name and model, description, its extras, its switch.
  function featureCard(c, rows) {
    const id = `intel-${c.id}`;
    const note = c.reason && state.kind !== "no-plan" ? h("p", { id: `${id}-why`, class: `os-intel__why os-intel__why--${c.reason}`, attrs: { "data-testid": `${id}-why` }, text: c.reason === "plan" ? t("intel.not-in-plan-text") : t("intel.follows") }) : null;
    const extras = c.id === "ocr" ? scriptChips(settings) : c.id === "pii" ? h("p", { class: "os-intel__pii", text: t("intel.pii-languages") }) : null;
    const sw = switchButton(NAME[c.id](), {
      checked: c.on, tone: "ml", disabled: c.disabled,
      attrs: { "aria-describedby": [`${id}-desc`, note ? `${id}-why` : null, state.kind === "no-plan" ? "intel-no-plan" : null].filter(Boolean).join(" "), "data-testid": `${id}-switch` },
      onChange: c.key ? (on) => change(c, on) : null,
    });
    const el = h("section", { class: "os-intel__card", attrs: { "aria-labelledby": `${id}-name`, "data-feature": c.id, "data-testid": id } },
      h("span", { class: "os-intel__glyph", attrs: { "aria-hidden": "true" }, text: c.glyph }),
      h("div", { class: "os-intel__text" },
        h("div", { class: "os-intel__row" },
          h("h2", { id: `${id}-name`, class: "os-intel__name", text: NAME[c.id]() }),
          modelLabel(cardModel(c.id, rows)),
          c.reason === "plan" ? statusPill(t("intel.not-in-plan"), { tone: "draft" }) : null),
        h("p", { id: `${id}-desc`, class: "os-intel__desc", text: DESC[c.id]() }),
        note, extras),
      sw.el);
    if (c.key && !c.disabled) {
      register(`intel.toggle.${c.id}`, { label: t("intel.toggle", { name: NAME[c.id]() }), run: () => sw.el.click() });
    }
    return {
      el,
      sync(now) {
        el.classList.toggle("is-on", now.on);
        sw.set(now.on);
        if (extras) extras.hidden = !now.on;
      },
    };
  }

  load();
}

/// The card's model name, with its state when the server says it is not ready.
function modelLabel({ name, status }) {
  return h("span", { class: "os-intel__model", text: status ? `${name} · ${MODEL_STATUS[status]().toLowerCase()}` : name });
}

/// While the settings load: the promises row and five cards, shaped like the page.
function loadingSkeleton() {
  return h("div", { class: "os-intel__skeleton", attrs: { "aria-hidden": "true" } },
    h("div", { class: "os-intel__promises" }, skeletonBlock({ height: 4.5 }), skeletonBlock({ height: 4.5 }), skeletonBlock({ height: 4.5 })),
    h("div", { class: "os-intel__grid" },
      h("div", { class: "os-intel__features" }, ...FEATURES.map(() => skeletonBlock({ height: 5.25 }))),
      skeletonBlock({ height: 20 })));
}

/// The three promises (canvas): runs on your servers, never learns, a person decides.
function promises() {
  const one = (ic, title, text) => h("div", { class: "os-intel__promise" }, promiseIcon(ic),
    h("span", { class: "os-intel__promise-text" }, h("b", { text: title }), h("span", { text })));
  return h("div", { class: "os-intel__promises os-rise", attrs: { "data-testid": "intel-promises" } },
    one("server", t("intel.promise.local"), t("intel.promise.local-text")),
    one("shield", t("intel.promise.learn"), t("intel.promise.learn-text")),
    one("person", t("intel.promise.person"), t("intel.promise.person-text")));
}

/// The canvas's three promise glyphs, drawn as it draws them (violet, 1.6 stroke).
function promiseIcon(kind) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "aria-hidden": "true", class: "os-intel__promise-icon" })) svg.setAttribute(k, v);
  const shapes = {
    server: [["rect", { x: "3", y: "4", width: "18", height: "12", rx: "2" }], ["path", { d: "M8 20h8M12 16v4" }]],
    shield: [["path", { d: "M12 3 4 6v6c0 4.5 3.3 8 8 9 4.7-1 8-4.5 8-9V6z" }], ["path", { d: "M9 12h6" }]],
    person: [["circle", { cx: "12", cy: "8", r: "3.5" }], ["path", { d: "M5 20c1-3.6 3.8-5.5 7-5.5s6 1.9 7 5.5" }]],
  }[kind];
  for (const [tag, attrs] of shapes) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.append(n);
  }
  return svg;
}

/// The OCR card's script chips: installed, installing (animated stripes), ask your operator.
function scriptChips(settings) {
  const chips = packChips(settings);
  if (!chips.length) return null;
  return h("ul", { class: "os-intel__chips", attrs: { "aria-label": t("intel.scripts"), "data-testid": "intel-scripts" } }, ...chips.map((c) => {
    const names = c.scripts.map(scriptName);
    if (c.state === "installed") return h("li", { class: "os-intel__chip os-intel__chip--installed", text: t("intel.pack.installed", { scripts: names.join(", ") }) });
    if (c.state === "installing") {
      return h("li", { class: "os-intel__chip os-intel__chip--installing" }, h("span", { text: t("intel.pack.installing", { script: names[0] }) }),
        h("span", { class: "os-intel__stripes", attrs: { "aria-hidden": "true" } }, h("span", { class: "os-intel__stripes-fill" })));
    }
    return h("li", { class: "os-intel__chip os-intel__chip--missing", text: t("intel.pack.missing", { script: names[0] }) });
  }));
}

/// "Models on this server": name, status, licence and size, a short SHA-256.
function modelsCard(rows) {
  return h("section", { class: "os-intel__models os-rise", attrs: { "aria-labelledby": "intel-models-h", "data-testid": "intel-models" } },
    h("div", { class: "os-intel__models-head" }, h("h2", { id: "intel-models-h", class: "os-intel__models-title", text: t("intel.models") }),
      h("span", { class: "os-intel__models-by", text: t("intel.models-by") })),
    h("ul", { class: "os-intel__model-list" }, ...rows.map((m) => h("li", { class: "os-intel__model-row", attrs: { "data-model": m.id } },
      h("div", { class: "os-intel__model-top" }, h("span", { class: "os-intel__model-name", attrs: { title: m.name }, text: m.name }),
        statusPill(MODEL_STATUS[m.status](), { tone: MODEL_TONE[m.status] })),
      h("span", { class: "os-intel__model-meta", text: [m.licence, m.size, PURPOSE[m.profile]?.()].filter(Boolean).join(" · ") }),
      h("code", { class: "os-intel__model-hash", text: m.hash ? t("intel.model.sha", { hash: m.hash }) : t("intel.model.sha-pending") })))));
}

/// The plan lacks every feature: said once above the (disabled) cards.
function planNotice() {
  return h("div", { id: "intel-no-plan", class: "os-intel__plan", attrs: { role: "note", "data-testid": "intel-no-plan" } },
    h("b", { text: t("intel.plan.title") }), h("span", { text: t("intel.plan.text") }));
}

/// No models on this server: say so, name who can change it, promise nothing else.
function notInstalled() {
  return h("div", { class: "os-intel__none", attrs: { "data-testid": "intel-not-installed" } },
    emptyState({ illus: "scanning", title: t("intel.none.title"), text: t("intel.none.text"), action: h("p", { class: "os-intel__none-who", text: t("intel.none.who") }) }));
}
