// OpenSeal's embedding elements (VS-09, docs/40 §5): `<openseal-signing>` and
// `<openseal-prepare>`, for a page on another origin to embed a signing, prepare or
// correct view. One ES module, no framework, served by OpenSeal at
// `/openseal-elements.js` (the one file it lets another origin load):
//
//   <script type="module" src="https://sign.example.com/openseal-elements.js"></script>
//   <openseal-signing src="https://sign.example.com/s/…" origin="https://sign.example.com"></openseal-signing>
//
//   el.addEventListener("openseal:complete", (e) => e.detail.event);   // "completed"
//
// `src` is the view URL your server got from `POST /envelopes/{id}/views/signing`
// (`/views/prepare`, `/views/correct` for `<openseal-prepare>`); it opens once and
// lives five minutes. `origin` is OpenSeal's origin, the only one whose messages the
// element takes (default: `src`'s own). Events, each a `CustomEvent` whose `detail` is
// `{event, state, envelope_id?, recipient_id?}`:
//
//   openseal:ready     the view is open
//   openseal:complete  completed (signing); sent, saved or corrected (prepare, correct)
//   openseal:decline   the signer declined
//   openseal:cancel    finish later, or left without finishing
//   openseal:error     expired, an error in the view, or no answer in `timeout` seconds
//                      (a view this page may not frame never answers: its server
//                      refuses the frame, `frame-ancestors`)
//
// An iframe, not a shadow root as OpenCalc's `<opencalc-sheet>` (`webapp/embed.js` at
// `b23c67c`, PROVENANCE.md, whose element shape and named theme tokens this copies):
// the ceremony must run on OpenSeal's origin, so the signer's session and evidence
// are out of the host page's reach. A message counts only when it comes from this
// element's own frame, from `origin`, in the protocol's shape, naming a known event;
// anything else is ignored. Commands to the frame (`theme`) are posted to `origin`
// only, never `*`.

export const PROTOCOL = "openseal";
export const VERSION = 1;

/// Each view event, and the element event it raises.
export const EVENT_MAP = Object.freeze({
  ready: "openseal:ready",
  completed: "openseal:complete",
  sent: "openseal:complete",
  saved: "openseal:complete",
  corrected: "openseal:complete",
  declined: "openseal:decline",
  finish_later: "openseal:cancel",
  cancelled: "openseal:cancel",
  expired: "openseal:error",
  error: "openseal:error",
});

/// The theme tokens the frame takes (embedframe.js `THEME_TOKENS`).
export const THEME_TOKENS = Object.freeze(["accentColor", "accentHoverColor", "backgroundColor", "surfaceColor", "textColor", "mutedTextColor", "borderColor", "radius", "fontFamily"]);

/// The origin of an `http(s)` URL, or null.
export function originOf(url, base = globalThis.location?.href) {
  try {
    const u = new URL(url, base);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch { return null; }
}

/// The origin an element takes messages from: its `origin` attribute when that is an
/// origin and `src` is on it, else `src`'s own; null when `src` is not an `http(s)` URL
/// or names another origin than `origin` (the element then loads nothing).
export function viewOrigin(src, origin = null, base = globalThis.location?.href) {
  const fromSrc = originOf(src, base);
  if (!fromSrc) return null;
  if (origin == null || origin === "") return fromSrc;
  const want = originOf(origin, base);
  return want && want === fromSrc && new URL(origin, base).pathname === "/" ? want : null;
}

/// The element event for a message `e`, or null when it is not one to take: from the
/// element's own frame window (`frame`), from `origin`, `{type: "openseal", v: 1,
/// event}` naming a known event. The detail carries only the protocol's members.
export function acceptMessage(e, frame, origin) {
  if (!e || !frame || e.source !== frame || !origin || e.origin !== origin) return null;
  const d = e.data;
  if (!d || typeof d !== "object" || d.type !== PROTOCOL || d.v !== VERSION) return null;
  if (typeof d.event !== "string" || !Object.hasOwn(EVENT_MAP, d.event)) return null;
  const detail = { event: d.event, state: typeof d.state === "string" ? d.state : null };
  for (const k of ["envelope_id", "recipient_id", "code"]) if (typeof d[k] === "string") detail[k] = d[k];
  return { type: EVENT_MAP[d.event], detail };
}

/// Theme tokens to send: known names with string values; an unknown name throws, so a
/// typo is found at the call (OpenCalc's rule).
export function checkTheme(tokens) {
  const out = {};
  for (const [k, v] of Object.entries(tokens || {})) {
    if (!THEME_TOKENS.includes(k)) throw new Error(`unknown OpenSeal theme token "${k}": one of ${THEME_TOKENS.join(", ")}`);
    if (typeof v !== "string") throw new Error(`OpenSeal theme token "${k}" takes a string`);
    out[k] = v;
  }
  return out;
}

const Base = globalThis.HTMLElement ?? class {};

class OpenSealView extends Base {
  static get observedAttributes() { return ["src", "origin"]; }

  #frame = null;
  #origin = null;
  #timer = null;
  #ready = false;
  #theme = null;
  #onMessage = (e) => this.#message(e);

  /// The frame's accessible name when the page gives none (`title` attribute).
  get defaultTitle() { return "OpenSeal"; }

  connectedCallback() {
    if (!this.style.display) this.style.display = "block";
    globalThis.addEventListener("message", this.#onMessage);
    this.#load();
  }

  disconnectedCallback() {
    globalThis.removeEventListener("message", this.#onMessage);
    clearTimeout(this.#timer);
  }

  attributeChangedCallback(_name, before, after) {
    if (before !== after && this.isConnected) this.#load();
  }

  /// Set theme tokens (`{accentColor: "#7c3aed"}`), sent to the view now or once it is
  /// open. Unknown names throw.
  theme(tokens) {
    this.#theme = { ...(this.#theme || {}), ...checkTheme(tokens) };
    if (this.#ready) this.#send({ command: "theme", tokens: this.#theme });
    return this;
  }

  #load() {
    const src = this.getAttribute("src");
    clearTimeout(this.#timer);
    this.#ready = false;
    this.#frame?.remove();
    this.#frame = null;
    if (!src) return;
    this.#origin = viewOrigin(src, this.getAttribute("origin"));
    if (!this.#origin) {
      this.#raise("openseal:error", { event: "error", state: null, code: "origin" });
      return;
    }
    const f = document.createElement("iframe");
    f.src = new URL(src, location.href).toString();
    f.title = this.getAttribute("title") || this.defaultTitle;
    f.referrerPolicy = "no-referrer";
    // The signing page may ask for the device's location (GEO-01) and download a copy.
    f.allow = "geolocation";
    f.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads");
    f.style.cssText = "display:block;width:100%;height:100%;min-height:inherit;border:0";
    this.#frame = f;
    this.append(f);
    const secs = Number(this.getAttribute("timeout") || 30);
    this.#timer = setTimeout(() => {
      if (!this.#ready) this.#raise("openseal:error", { event: "error", state: null, code: "timeout" });
    }, (Number.isFinite(secs) && secs > 0 ? secs : 30) * 1000);
  }

  #message(e) {
    const got = acceptMessage(e, this.#frame?.contentWindow, this.#origin);
    if (!got) return;
    if (got.detail.event === "ready") {
      this.#ready = true;
      clearTimeout(this.#timer);
      if (this.#theme) this.#send({ command: "theme", tokens: this.#theme });
    }
    this.#raise(got.type, got.detail);
  }

  #send(msg) {
    try { this.#frame?.contentWindow?.postMessage({ type: PROTOCOL, v: VERSION, ...msg }, this.#origin); } catch { /* navigated away */ }
  }

  #raise(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
  }
}

/// `<openseal-signing>`: a signing view.
export class OpenSealSigning extends OpenSealView {
  get defaultTitle() { return "Sign with OpenSeal"; }
}

/// `<openseal-prepare>`: a prepare (sender) or correct view.
export class OpenSealPrepare extends OpenSealView {
  get defaultTitle() { return "Prepare with OpenSeal"; }
}

/// Register both elements (done on import in a browser); a name already taken is left.
export function define(registry = globalThis.customElements) {
  if (!registry) return;
  if (!registry.get("openseal-signing")) registry.define("openseal-signing", OpenSealSigning);
  if (!registry.get("openseal-prepare")) registry.define("openseal-prepare", OpenSealPrepare);
}

define();
