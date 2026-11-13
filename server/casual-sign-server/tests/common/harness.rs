//! The real router on a fresh database, driven in-process (tower `oneshot`), with a
//! clock the test moves, a connection peer address the test chooses, and a record of
//! every route template called (so a test can show every operation of
//! `api/openapi.yaml` was exercised).

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use casual_sign_server::{
    AppState, Blobs, Bootstrapped, Config, JwtKeys, ManualClock, app, bootstrap,
    bootstrap_workspace, table,
};
use casual_sign_store::blob::FsBlobStore;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;

use super::{Rls, TestDb, fresh};

/// 2026-11-11T10:00:00Z.
pub fn start() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_794_391_200).unwrap()
}

/// The password every bootstrapped administrator has.
pub const PASSWORD: &str = "correct horse battery staple";

/// A credential.
#[derive(Debug, Clone)]
pub enum Auth {
    /// None.
    None,
    /// `Authorization: Bearer`.
    Bearer(String),
    /// A staff session.
    Session { cookie: String, csrf: String },
}

/// A response.
#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or("").to_owned()
    }

    pub fn etag(&self) -> String {
        self.headers["etag"].to_str().unwrap().to_owned()
    }
}

/// One test's server.
pub struct Api {
    pub app: Router,
    pub st: AppState,
    pub clock: Arc<ManualClock>,
    pub db: TestDb,
    pub peer: Mutex<SocketAddr>,
    pub called: Mutex<BTreeSet<(String, String)>>,
    /// The blob directory the server stores into.
    pub blob_dir: std::path::PathBuf,
}

/// An account with an administrator's API key holding every scope.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub boot: Bootstrapped,
    pub email: String,
    pub key: String,
    pub auth: Auth,
}

fn template_of(path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    let segs: Vec<&str> = path.split('/').collect();
    let mut best: Option<(usize, &'static str)> = None;
    for r in table() {
        let t: Vec<&str> = r.path.split('/').collect();
        if t.len() != segs.len() {
            continue;
        }
        let mut statics = 0;
        let ok = t.iter().zip(&segs).all(|(a, b)| {
            if a.starts_with('{') {
                true
            } else {
                statics += 1;
                a == b
            }
        });
        if ok && best.is_none_or(|(s, _)| statics > s) {
            best = Some((statics, r.path));
        }
    }
    best.map(|(_, p)| p.to_owned())
}

impl Api {
    pub async fn new(test: &str, rls: Rls) -> Option<Self> {
        Self::with(test, rls, |_| {}).await
    }

    pub async fn with(test: &str, rls: Rls, tweak: impl FnOnce(&mut Config)) -> Option<Self> {
        let db = fresh(test, rls).await?;
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("blobs-{}", uuid::Uuid::now_v7()));
        let blobs = Blobs::Fs(Arc::new(FsBlobStore::new(dir.clone()).unwrap()));
        let clock = Arc::new(ManualClock::at(start()));
        let mut config = Config {
            public_url: "https://sign.example.test".into(),
            ..Config::default()
        };
        tweak(&mut config);
        let st = AppState::new(
            db.store.clone(),
            blobs,
            JwtKeys::generate().unwrap(),
            clock.clone(),
            config,
        )
        .unwrap();
        Some(Self {
            app: app(st.clone()),
            st,
            clock,
            db,
            peer: Mutex::new("198.51.100.7:50000".parse().unwrap()),
            called: Mutex::new(BTreeSet::new()),
            blob_dir: dir,
        })
    }

    pub fn set_peer(&self, peer: &str) {
        *self.peer.lock().unwrap() = peer.parse().unwrap();
    }

    pub async fn send(
        &self,
        method: &str,
        path: &str,
        auth: &Auth,
        body: Body,
        headers: &[(&str, &str)],
    ) -> Resp {
        let mut req = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(path);
        match auth {
            Auth::None => {}
            Auth::Bearer(t) => req = req.header("authorization", format!("Bearer {t}")),
            Auth::Session { cookie, csrf } => {
                req = req
                    .header("cookie", format!("os_session={cookie}"))
                    .header("x-csrf-token", csrf);
            }
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut req = req.body(body).unwrap();
        let peer = *self.peer.lock().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        if let Some(t) = template_of(path) {
            self.called.lock().unwrap().insert((method.to_owned(), t));
        }
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        Resp {
            status,
            headers,
            body,
        }
    }

    pub async fn call(
        &self,
        method: &str,
        path: &str,
        auth: &Auth,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> Resp {
        let mut h: Vec<(&str, &str)> = headers.to_vec();
        let body = match body {
            Some(v) => {
                h.push(("content-type", "application/json"));
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        self.send(method, path, auth, body, &h).await
    }

    /// A new account: bootstrap, log in, and make an administrator's API key.
    pub async fn tenant(&self, name: &str) -> Tenant {
        let email = format!("admin@{name}.example.test");
        // The install's first organization comes from `bootstrap`; later ones as the
        // platform console makes them (the owner role), each with a workspace made
        // through the application's organization scope.
        let any: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organizations)")
            .fetch_one(&self.db.admin)
            .await
            .unwrap();
        let boot = if any {
            let org = casual_sign_store::OrganizationId(uuid::Uuid::now_v7());
            sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, $2)")
                .bind(org.0)
                .bind(name)
                .execute(&self.db.admin)
                .await
                .unwrap();
            bootstrap_workspace(self.st_store(), org, name, &email, "Admin", PASSWORD)
                .await
                .unwrap()
        } else {
            bootstrap(self.st_store(), name, &email, "Admin", PASSWORD)
                .await
                .unwrap()
        };
        let login = self
            .call(
                "POST",
                "/api/v1/auth/login",
                &Auth::None,
                Some(json!({"email": email, "password": PASSWORD})),
                &[],
            )
            .await;
        assert_eq!(login.status, StatusCode::OK, "{:?}", login.json());
        let session = session_of(&login);
        let key = self
            .call(
                "POST",
                "/api/v1/api-clients",
                &session,
                Some(json!({"name": "admin key", "kind": "api_key",
                    "scopes": casual_sign_server::SCOPES})),
                &[],
            )
            .await;
        assert_eq!(key.status, StatusCode::CREATED, "{:?}", key.json());
        let key = key.json()["key"].as_str().unwrap().to_owned();
        Tenant {
            boot,
            email,
            auth: Auth::Bearer(key.clone()),
            key,
        }
    }

    fn st_store(&self) -> &casual_sign_store::Store {
        &self.db.store
    }

    pub fn called(&self) -> BTreeSet<(String, String)> {
        self.called.lock().unwrap().clone()
    }
}

/// The session a login response set.
pub fn session_of(login: &Resp) -> Auth {
    let set = login.headers["set-cookie"].to_str().unwrap();
    let cookie = set
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("os_session=")
        .unwrap()
        .to_owned();
    Auth::Session {
        cookie,
        csrf: login.json()["csrf_token"].as_str().unwrap().to_owned(),
    }
}

/// A small valid PDF of `pages` pages, with correct cross-reference offsets.
pub fn pdf(pages: usize) -> Vec<u8> {
    let mut objs: Vec<String> = Vec::new();
    let kids: Vec<String> = (0..pages).map(|i| format!("{} 0 R", 3 + 2 * i)).collect();
    objs.push("<< /Type /Catalog /Pages 2 0 R >>".into());
    objs.push(format!(
        "<< /Type /Pages /Kids [{}] /Count {} >>",
        kids.join(" "),
        pages
    ));
    for i in 0..pages {
        objs.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << >> >>",
            4 + 2 * i
        ));
        let content = format!("BT /F1 12 Tf 72 720 Td (Page {}) Tj ET", i + 1);
        objs.push(format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content.len(),
            content
        ));
    }
    let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, o).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            objs.len() + 1,
            xref
        )
        .as_bytes(),
    );
    out
}

/// A one-page US Letter PDF whose page shows `content` (a content stream) with Courier
/// as `/F1`, with correct cross-reference offsets.
pub fn text_pdf(content: &str) -> Vec<u8> {
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 5 0 R >> >> >>"
            .to_owned(),
        format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content.len(),
            content
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_owned(),
    ];
    let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, o).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            objs.len() + 1,
            xref
        )
        .as_bytes(),
    );
    out
}

/// A 1×1 PNG.
pub fn png() -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
        .unwrap()
}

/// The `/s/<token>` path of a ceremony URL.
pub fn ceremony_path(url: &str) -> String {
    let i = url.find("/s/").unwrap();
    url[i..].to_owned()
}

/// The ceremony cookie a session response set.
pub fn ceremony_cookie(resp: &Resp) -> String {
    let set = resp.headers["set-cookie"].to_str().unwrap();
    set.split(';').next().unwrap().to_owned()
}

pub const OPENAPI: &str = include_str!("../../../../api/openapi.yaml");

/// `(METHOD, path) -> x-permission` from the OpenAPI document.
pub fn openapi_operations() -> BTreeMap<(String, String), String> {
    let doc: Value = serde_norway::from_str(OPENAPI).unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    let mut out = BTreeMap::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            if method == "parameters" {
                continue;
            }
            let perm = op["x-permission"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} has no x-permission"))
                .to_owned();
            out.insert((method.to_uppercase(), path.clone()), perm);
        }
    }
    out
}
