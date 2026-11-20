// The framed side of embedding (VS-09, docs/40 §5): an embedded view (the signing page
// at `/s/{token}`, the prepare or correct page at `/e/{token}`) tells the page that
// frames it what happened, and takes theme tokens from it.
//
// - Events go only to the origins the server named for this view (`embed.frame_origins`:
//   the view's own frame origin, or the workspace's allowed list), each by name, never
//   `*`: `postMessage` delivers a message only when its target origin is the frame
//   parent's, so a page that is not allowed hears nothing. The page that frames us
//   is already one of them: the server's `frame-ancestors` let no other page frame it.
// - A message from the host is taken only from the window that frames us, from one of
//   those origins, in the protocol's shape; theme tokens are applied by name from a
//   closed list, values checked, as OpenCalc's `<opencalc-sheet>` takes its `--oc-*`
//   tokens (`webapp/embed.js` at `b23c67c`, PROVENANCE.md).
// - When the view ends it goes to the host's return URL, if it gave one, with `event`
//   and the host's `state` in the query (docs/40 §5).
//
// No DOM is touched here but the root element's style, so tests run it under Node.

/// The protocol's name and version on every message, both ways.
export const PROTOCOL = "openseal";
export const VERSION = 1;

/// Every event an embedded view sends (docs/40 §5). The signing view: `ready`,
/// `completed`, `declined`, `finish_later`, `cancelled`, `expired`, `error`. The prepare
/// and correct views: `ready`, `sent`, `saved`, `corrected`, `cancelled`, `expired`, `error`.
export const EVENTS = Object.freeze(["ready", "completed", "declined", "finish_later", "cancelled", "sent", "saved", "corrected", "expired", "error"]);

/// The theme tokens a host may set, without prefix, and the custom property each sets
/// (tokens.css). Named, so a typo is refused rather than quietly ignored (OpenCalc's
/// rule); typed by suffix (`Color` takes a colour).
export const THEME_TOKENS = Object.freeze({
  accentColor: "--os-accent",
  accentHoverColor: "--os-accent-hover",
  backgroundColor: "--os-bg",
  surfaceColor: "--os-surface",
  textColor: "--os-text",
  mutedTextColor: "--os-muted",
  borderColor: "--os-border",
  radius: "--os-radius",
  fontFamily: "--os-font",
});

/// A token value: a colour, a length or a font list; nothing that could end the
/// declaration, open a URL or a comment.
const SAFE_VALUE = /^[#a-zA-Z0-9 ,.%()'"-]{1,80}$/;
const UNSAFE = /url\(|expression|\/\*|;|[{}<>\\]/i;

/// Whether `v` may be a theme token's value.
export function safeTokenValue(v) {
  return typeof v === "string" && SAFE_VALUE.test(v) && !UNSAFE.test(v);
}

/// The custom properties to set for `tokens` (`{accentColor: "#7c3aed"}`): only known
/// names with safe values; anything else is skipped and named in `refused`.
export function themeDeclarations(tokens) {
  const set = [];
  const refused = [];
  if (!tokens || typeof tokens !== "object") return { set, refused };
  for (const [name, value] of Object.entries(tokens)) {
    const prop = Object.hasOwn(THEME_TOKENS, name) ? THEME_TOKENS[name] : null;
    if (prop && safeTokenValue(value)) set.push([prop, value]);
    else refused.push(name);
  }
  return { set, refused };
}

/// The return URL with `event` and `state` added to its query (the host's own query
/// kept), or null when there is none or it is not an `http(s)` URL.
export function returnTo(url, event, state) {
  if (typeof url !== "string" || !url) return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  u.searchParams.set("event", event);
  if (state != null && state !== "") u.searchParams.set("state", String(state));
  return u.toString();
}

/// The origins this view posts to: the server's list for it, each an `http(s)` origin.
export function targetsOf(embed) {
  const list = Array.isArray(embed?.frame_origins) ? embed.frame_origins : (embed?.frame_origin ? [embed.frame_origin] : []);
  return list.filter((o) => typeof o === "string" && /^https?:\/\/[^/?#\s*]+$/.test(o));
}

/// Whether `e` is a message this view takes: from the window that frames it (`parent`),
/// from one of `origins`, in the protocol's shape.
export function fromHost(e, parent, origins) {
  if (!e || !parent || e.source !== parent) return false;
  if (!origins.includes(e.origin)) return false;
  const d = e.data;
  return !!d && typeof d === "object" && d.type === PROTOCOL && d.v === VERSION && typeof d.command === "string";
}

/// The channel between this view and the page that frames it. `win` is the page's
/// window; `embed` the server's `embed` member (`frame_origins`, `return_url`, `state`);
/// `root` the element theme tokens are set on. With no frame and no return URL every
/// call does nothing, so a page opened on its own behaves as before.
export function hostChannel({ win = globalThis.window, embed = null, root = globalThis.document?.documentElement } = {}) {
  const framed = !!win && win.parent && win.parent !== win;
  const targets = embed ? targetsOf(embed) : [];
  const state = embed?.state ?? null;
  let ended = false;
  const listeners = [];

  function post(event, detail = {}) {
    if (!framed || !EVENTS.includes(event)) return 0;
    const msg = { type: PROTOCOL, v: VERSION, event, state, ...pick(detail) };
    let sent = 0;
    for (const o of targets) {
      try { win.parent.postMessage(msg, o); sent += 1; } catch { /* a closed or navigated parent */ }
    }
    return sent;
  }

  function onMessage(e) {
    if (!fromHost(e, win.parent, targets)) return;
    if (e.data.command === "theme" && root?.style) {
      for (const [prop, value] of themeDeclarations(e.data.tokens).set) root.style.setProperty(prop, value);
    }
    for (const fn of listeners) fn(e.data);
  }
  if (framed && targets.length && typeof win.addEventListener === "function") win.addEventListener("message", onMessage);

  return {
    /// Whether events reach a host page.
    get active() { return framed && targets.length > 0; },
    post,
    /// Post the view's last event, then go to the return URL, once.
    end(event, detail = {}) {
      if (ended) return null;
      ended = true;
      post(event, detail);
      const to = returnTo(embed?.return_url, event, state);
      if (to && win?.location) setTimeout(() => { try { win.location.assign(to); } catch { /* stays */ } }, 0);
      return to;
    },
    /// Listen to the host's commands (after the checks above).
    listen(fn) { listeners.push(fn); },
  };
}

/// Only these members of a detail travel with an event; never a value, a name or an
/// email (the host already knows whom it asked to sign).
function pick(detail) {
  const out = {};
  for (const k of ["envelope_id", "recipient_id", "code"]) if (typeof detail?.[k] === "string") out[k] = detail[k];
  return out;
}
