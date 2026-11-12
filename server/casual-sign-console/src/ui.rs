//! The console's own web UI (`console-ui/`, CON-17), embedded at compile time so the
//! binary is self-contained and no request path ever reaches the file system.
//!
//! The UI is a handful of plain ES modules, a stylesheet and the Geist faces. It is
//! served only by this binary, on the console's private listener, never by the public
//! server (docs/23 §5.2): `webapp/` is served wholesale by the public server, so the
//! console's files live in their own folder at the repository root.
//!
//! Headers: every UI file carries [`PAGE_CSP`] (scripts, styles, fonts and requests
//! from the console's own origin only; no inline script or style, no framing, no form
//! posts elsewhere). Fonts, whose file names carry their version, are cached for a year;
//! the page, scripts and stylesheet are revalidated each time, so an upgraded binary is
//! picked up at once. The API keeps the request middleware's `no-store` and its policy
//! that loads nothing.

use axum::http::{HeaderValue, Method, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::error::ConsoleError;

/// The UI's Content Security Policy.
pub const PAGE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; \
base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Cache policy of files whose name carries their version.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Cache policy of everything else: keep, but ask the binary each time.
const REVALIDATE: &str = "no-cache";

/// One embedded file: its path as requested, its content type and its bytes.
struct Asset {
    path: &'static str,
    content_type: &'static str,
    bytes: &'static [u8],
    immutable: bool,
}

macro_rules! asset {
    ($path:literal, $ct:literal, $file:literal, $immutable:literal) => {
        Asset {
            path: $path,
            content_type: $ct,
            bytes: include_bytes!(concat!("../../../console-ui/", $file)),
            immutable: $immutable,
        }
    };
}

/// Every file the UI is made of. Anything else is `404 CS-CON-0011`.
static ASSETS: &[Asset] = &[
    asset!("/", "text/html; charset=utf-8", "index.html", false),
    asset!("/console.css", "text/css; charset=utf-8", "console.css", false),
    asset!("/app.js", "text/javascript; charset=utf-8", "app.js", false),
    asset!("/api.js", "text/javascript; charset=utf-8", "api.js", false),
    asset!("/dom.js", "text/javascript; charset=utf-8", "dom.js", false),
    asset!("/model.js", "text/javascript; charset=utf-8", "model.js", false),
    asset!("/art.js", "text/javascript; charset=utf-8", "art.js", false),
    asset!(
        "/fonts/geist-1.3.1-variable.woff2",
        "font/woff2",
        "fonts/geist-1.3.1-variable.woff2",
        true
    ),
    asset!(
        "/fonts/geist-mono-1.3.1-variable.woff2",
        "font/woff2",
        "fonts/geist-mono-1.3.1-variable.woff2",
        true
    ),
    asset!(
        "/fonts/OFL-1.1-Geist.txt",
        "text/plain; charset=utf-8",
        "fonts/OFL-1.1-Geist.txt",
        false
    ),
];

fn find(path: &str) -> Option<&'static Asset> {
    let path = if path == "/index.html" { "/" } else { path };
    ASSETS.iter().find(|a| a.path == path)
}

/// Whether `path` names a UI file (for tests and the router).
#[must_use]
pub fn is_asset(path: &str) -> bool {
    find(path).is_some()
}

/// Every route the router does not know: a UI file for `GET` or `HEAD` of one of its
/// paths, otherwise the API's `404` problem.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    let asset = match method {
        Method::GET | Method::HEAD => find(uri.path()),
        _ => None,
    };
    let Some(a) = asset else {
        return ConsoleError::NotFound.into_response();
    };
    let body = if method == Method::HEAD { &[][..] } else { a.bytes };
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(a.content_type));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if a.immutable { IMMUTABLE } else { REVALIDATE }),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PAGE_CSP),
    );
    resp
}
