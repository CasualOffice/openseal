// The embedded prepare and correct page (VS-09, docs/40 §5), at `/e/{token}`: a page on
// another origin frames it (`<openseal-prepare>`, openseal-elements.js) with a link its
// server got from `POST /envelopes/{id}/views/prepare` or `/views/correct`.
//
// The page spends the link once (`POST /e/{token}/session`) for a view session that
// acts on that envelope only (the server keeps it there), holds the session in memory
// only, and opens the same editor the app uses: prepare.js for a draft, envactions.js's
// correct panel for a sent envelope. What happens is posted to the host page
// (embedframe.js): `ready`, then `sent`, `corrected` or `cancelled`; a link that no
// longer opens is `expired`. No app shell, no navigation: the editor's own way out
// ends the view.

import { h, clear, isTyping } from "./dom.js";
import { t, applyI18n } from "./i18n.js";
import { createClient, isMockMode, ApiError, errorMessage } from "./api.js";
import { emptyState } from "./ui/index.js";
import { handle } from "./keys.js";
import { initTheme } from "./theme.js";
import { hostChannel } from "./embedframe.js";

/// The link's token, from `/e/{token}`.
export function embedToken(loc) {
  const m = /^\/e\/([^/?#]+)\/?$/.exec(loc.pathname);
  return m ? decodeURIComponent(m[1]) : null;
}

const mock = isMockMode();
let api;
if (mock) {
  const { createMockFetch } = await import("./mock.js");
  let store = null;
  try { store = sessionStorage; } catch { store = null; }
  api = createClient({ fetch: createMockFetch({ store }), store });
} else {
  api = createClient({ baseUrl: document.querySelector('meta[name="openseal-api-base"]')?.content || "" });
}

const main = document.getElementById("main");
let channel = hostChannel({ embed: null });
let ended = false;

/// End the view: tell the host, then show where things stand.
function finish(event, titleKey, textKey) {
  if (ended) return;
  ended = true;
  document.body.classList.remove("is-frame");
  clear(main);
  main.append(emptyState({ illus: event === "cancelled" ? "documents" : "inbox", title: t(titleKey), text: t(textKey), testId: `embed-${event}` }));
  channel.end(event, {});
}

function failed(err) {
  if (err instanceof ApiError && (err.code === "CS-AUTH-0001" || err.code === "CS-AUTH-0002")) {
    finish("expired", "embed.expired.title", "embed.expired.text");
    return true;
  }
  return false;
}

async function start() {
  initTheme();
  applyI18n(document);
  const token = embedToken(location);
  let s;
  try {
    if (!token) throw new ApiError({ status: 401, code: "CS-AUTH-0002" });
    s = await api.views.session(token);
  } catch (err) {
    if (!failed(err)) {
      clear(main);
      main.append(emptyState({ illus: "error", title: t("empty.error.title"), text: errorMessage(err), testId: "embed-error" }));
    }
    return;
  }
  api.setBearer(s.session);
  channel = hostChannel({ embed: s.embed });
  const id = s.envelope_id;
  const ctx = {
    api,
    mock,
    session: null,
    who: null,
    contexts: ["global"],
    leaveGuard: null,
    registerPaletteProvider: () => () => {},
    /// The editor's way out: to the envelope once sent (prepare.js), anywhere else is
    /// leaving without sending.
    navigate(hash) {
      if (String(hash).startsWith(`#/envelopes/${encodeURIComponent(id)}`)) finish("sent", "embed.sent.title", "embed.sent.text");
      else finish("cancelled", "embed.cancelled.title", "embed.cancelled.text");
    },
    replaceHash: () => true,
    failed,
  };
  document.addEventListener("keydown", (e) => { if (!ended) handle(e, ctx.contexts, isTyping(e)); });
  channel.post("ready", { envelope_id: id });
  if (s.kind === "correct") {
    const { correctPanel } = await import("./envactions.js");
    main.append(h("div", { class: "os-embed__backdrop", attrs: { "data-testid": "embed-correct" } }));
    let done = false;
    try { done = await correctPanel(ctx, id); } catch (err) { if (!failed(err)) throw err; return; }
    if (done) finish("corrected", "embed.corrected.title", "embed.corrected.text");
    else finish("cancelled", "embed.cancelled.title", "embed.cancelled.text");
    return;
  }
  document.body.classList.add("is-chromeless", "is-wide", "is-frame");
  const view = h("div", { class: "os-view" });
  main.append(view);
  const prepare = await import("./prepare.js");
  try { await prepare.mount(view, ctx, [encodeURIComponent(id)]); } catch (err) { if (!failed(err)) throw err; }
}

start();
