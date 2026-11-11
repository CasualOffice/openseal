//! The web app's static files (row WEB-04): `webapp/` served at `/`, and `sign.html`
//! for a browser opening a signing link `/s/{token}` (docs/47 §As built).
//!
//! The folder is read once, at start, into memory (about 6 MiB): a request can only
//! name a file that was there then, so no path from a request ever reaches the file
//! system (no traversal, no symlink to follow, no file added later). Only the web
//! app's own kinds of file are kept, by extension; the test folders and Node's
//! manifests are skipped.
//!
//! Headers: each page carries the web app's Content Security Policy (docs/47 §Content
//! Security Policy, with `frame-ancestors 'none'`) and a permissions policy that lets
//! it ask for the device's location (GEO-01); every other file keeps the API's strict
//! policy. Vendored libraries and fonts are cached for a year (their folder names their
//! version, and an upgrade renames them); everything else is revalidated each time.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

/// The web app's Content Security Policy (docs/47), as a header.
pub const PAGE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; \
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// A page may ask for the device's location (GEO-01), nothing else.
const PAGE_PERMISSIONS: &str = "geolocation=(self), camera=(), microphone=()";

/// At most this many files and bytes are read (the web app is about 300 files, 6 MiB).
const MAX_FILES: usize = 4096;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Folders deeper than this are not read.
const MAX_DEPTH: usize = 8;

/// Folders of `webapp/` that are not the web app.
const SKIP_DIRS: &[&str] = &["e2e", "tests", "node_modules"];
/// Files of `webapp/` that are not the web app.
const SKIP_FILES: &[&str] = &["package.json", "package-lock.json"];
/// Folders whose files never change under one name (cached for a year).
const IMMUTABLE: &[&str] = &["vendor/", "fonts/"];

/// Why the web app could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebAppError {
    /// The folder, or a file in it, cannot be read.
    Unreadable,
    /// More than the files or bytes this reads.
    TooLarge,
    /// No `index.html`, `app.html` or `sign.html`: not the web app's folder.
    NotTheWebApp,
}

impl fmt::Display for WebAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "a file or folder cannot be read",
            Self::TooLarge => "more files or bytes than a web app has",
            Self::NotTheWebApp => "no index.html, app.html and sign.html: not the webapp folder",
        })
    }
}

impl std::error::Error for WebAppError {}

#[derive(Debug)]
struct File {
    bytes: Bytes,
    content_type: &'static str,
}

/// The web app's files, in memory.
#[derive(Debug)]
pub struct WebApp {
    files: BTreeMap<String, File>,
}

fn content_type(name: &str) -> Option<&'static str> {
    let ext = name.rsplit_once('.').map(|(_, e)| e)?;
    Some(match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "ttf" => "font/ttf",
        "woff2" => "font/woff2",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        // pdf.js's CMaps and standard fonts, fetched as bytes.
        "pfb" | "bcmap" => "application/octet-stream",
        _ => return None,
    })
}

impl WebApp {
    /// Read the web app from `dir` (the repository's `webapp/`).
    ///
    /// # Errors
    ///
    /// [`WebAppError`] when the folder cannot be read, is larger than a web app, or
    /// is not the web app's.
    pub fn load(dir: &Path) -> Result<Self, WebAppError> {
        let mut app = Self {
            files: BTreeMap::new(),
        };
        let mut total = 0u64;
        app.read_dir(dir, "", 0, &mut total)?;
        for page in ["index.html", "app.html", "sign.html"] {
            if !app.files.contains_key(page) {
                return Err(WebAppError::NotTheWebApp);
            }
        }
        Ok(app)
    }

    fn read_dir(
        &mut self,
        dir: &Path,
        prefix: &str,
        depth: usize,
        total: &mut u64,
    ) -> Result<(), WebAppError> {
        if depth > MAX_DEPTH {
            return Ok(());
        }
        let entries = std::fs::read_dir(dir).map_err(|_| WebAppError::Unreadable)?;
        for entry in entries {
            let entry = entry.map_err(|_| WebAppError::Unreadable)?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            // Never followed: a symlink is skipped, whatever it points at.
            let kind = entry.file_type().map_err(|_| WebAppError::Unreadable)?;
            let path = entry.path();
            if kind.is_dir() {
                if depth == 0 && SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                self.read_dir(
                    &path,
                    &format!("{prefix}{name}/"),
                    depth.saturating_add(1),
                    total,
                )?;
            } else if kind.is_file() {
                if depth == 0 && SKIP_FILES.contains(&name.as_str()) {
                    continue;
                }
                let Some(ct) = content_type(&name) else {
                    continue;
                };
                let len = entry.metadata().map_err(|_| WebAppError::Unreadable)?.len();
                *total = total.saturating_add(len);
                if *total > MAX_BYTES || self.files.len() >= MAX_FILES {
                    return Err(WebAppError::TooLarge);
                }
                let bytes = std::fs::read(&path).map_err(|_| WebAppError::Unreadable)?;
                self.files.insert(
                    format!("{prefix}{name}"),
                    File {
                        bytes: Bytes::from(bytes),
                        content_type: ct,
                    },
                );
            }
        }
        Ok(())
    }

    /// How many files were read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether no file was read (never, for a loaded web app).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The response for the file at `name` (a path relative to the web app, no
    /// leading `/`), or `None` when there is none.
    pub(crate) fn file(&self, name: &str) -> Option<Response> {
        let f = self.files.get(name)?;
        let mut r = Response::new(Body::from(f.bytes.clone()));
        let h = r.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(f.content_type),
        );
        let cache = if IMMUTABLE.iter().any(|p| name.starts_with(p)) {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        if name.ends_with(".html") {
            h.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(PAGE_CSP),
            );
            h.insert(
                header::HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static(PAGE_PERMISSIONS),
            );
            // A signing page's URL holds the link's token: never cached anywhere.
            if name == "sign.html" {
                h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
        }
        Some(r)
    }
}

/// Whether a request asks for a page rather than JSON: its `Accept` names
/// `text/html` and not `application/json` (a browser navigating, not the web app's
/// own `fetch`, which asks for JSON).
pub(crate) fn wants_page(headers: &HeaderMap) -> bool {
    let accept = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let has = |m: &str| {
        accept.split(',').any(|part| {
            part.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case(m))
        })
    };
    has("text/html") && !has("application/json")
}

/// Anything no route matched: a web app file for `GET` or `HEAD`, else `404`.
pub(crate) async fn fallback(
    axum::extract::State(st): axum::extract::State<crate::state::AppState>,
    method: Method,
    uri: axum::http::Uri,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return ApiError::not_found().into_response();
    }
    let Some(app) = st.webapp() else {
        return ApiError::not_found().into_response();
    };
    let path = uri.path();
    let name = if path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };
    app.file(name)
        .unwrap_or_else(|| ApiError::not_found().into_response())
}

/// `sign.html`, for a browser opening a signing link.
pub(crate) fn sign_page(app: &Arc<WebApp>) -> Response {
    app.file("sign.html")
        .unwrap_or_else(|| ApiError::not_found().into_response())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn accept(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn a_browser_navigation_wants_the_page_and_fetch_wants_json() {
        assert!(wants_page(&accept(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )));
        assert!(!wants_page(&accept("application/json")));
        assert!(!wants_page(&accept("*/*")));
        assert!(!wants_page(&HeaderMap::new()));
        assert!(!wants_page(&accept("text/html, application/json")));
    }

    #[test]
    fn only_the_web_apps_kinds_of_file_are_served() {
        assert_eq!(
            content_type("app.js"),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(
            content_type("pdf.worker.min.mjs"),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(content_type("build.py"), None);
        assert_eq!(content_type("LICENSE"), None);
    }
}
