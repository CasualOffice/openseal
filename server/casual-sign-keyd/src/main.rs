//! `casual-sign-keyd`: the key daemon (docs/31 §5). Configured by environment, one key
//! per process under one alias:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_KEYD_LISTEN` | Address to bind (default `127.0.0.1:7443`) |
//! | `OPENSEAL_KEYD_TLS_CERT`, `OPENSEAL_KEYD_TLS_KEY` | Server certificate chain and key (PEM paths) |
//! | `OPENSEAL_KEYD_CLIENT_CA` | CA a client certificate must chain to (PEM path) |
//! | `OPENSEAL_KEYD_ALLOW_LIST` | Allowed callers: `sha256-fingerprint [name]` per line |
//! | `OPENSEAL_KEYD_ADMIN_ALLOW_LIST` | Optional: admin callers (the console), same format; answered only `list-keys`, `oplog-head`, `oplog-range` and `health`, never a signature (`CON-06`) |
//! | `OPENSEAL_KEYD_OPLOG` | The operation log (append-only, hash-chained) |
//! | `OPENSEAL_KEYD_ALIAS` | The key's alias (default `platform`) |
//! | `OPENSEAL_KEYD_CHAIN` | Signer certificate chain (PEM path); with PKCS#11, optional: the signer certificate is then read from the token |
//! | `OPENSEAL_KEYD_INTERMEDIATES` | With the chain from the token: intermediates (PEM path) |
//! | `OPENSEAL_KEYD_RSA_ALGORITHM` | `pkcs1-sha256` (default), `pkcs1-sha384`, `pkcs1-sha512`, `pss-sha256`, `pss-sha384`, `pss-sha512` |
//! | `OPENSEAL_KEYD_PKCS11_MODULE` | PKCS#11 library path |
//! | `OPENSEAL_KEYD_PKCS11_TOKEN` | Token label |
//! | `OPENSEAL_KEYD_PKCS11_KEY_LABEL`, `OPENSEAL_KEYD_PKCS11_KEY_ID` | Key label and/or id (hex) |
//! | `OPENSEAL_KEYD_PKCS11_PIN` or `OPENSEAL_KEYD_PKCS11_PIN_FILE` | User PIN (the file form is the private one) |
//! | `OPENSEAL_KEYD_FILE_KEY` | A PEM key file instead of PKCS#11: development only, needs `OPENSEAL_DEV_INSECURE_KEY=1` |
//! | `OPENSEAL_KEYD_SIGNATURES_PER_MINUTE` | Per-caller rate (default 600) |
//! | `OPENSEAL_LOG_PSEUDONYM_KEY` or `OPENSEAL_LOG_PSEUDONYM_KEY_FILE` | 32 bytes as base64: keys the pseudonyms in security events (ASVS-08, docs/65 §Logs); none: a key per process; malformed: keyd does not start (`CS-LOG-0001`) |
//!
//! `casual-sign-keyd verify-oplog <path>` verifies an operation log's chain without
//! starting the daemon (a backup's copy before it is restored, ASVS-14) and prints its
//! line count and head; it exits non-zero naming the first line that fails.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use casual_sign_crypto::SignatureAlgorithm;
use casual_sign_keyd::{
    AllowList, ChainSource, DevKeyConsent, DigestSigner, FileKey, KeyService, Keyd, KeydError,
    KeydLimits, OpLog, Pkcs11KeyConfig, Pkcs11Module, certificates, server_tls,
};
use casual_sign_secrets::{env_secret, unknown_secret_files};

const KNOWN_SECRET_FILES: &[&str] = &[
    "OPENSEAL_KEYD_PKCS11_PIN_FILE",
    // Read by the security log's pseudonym key (`casual-sign-seclog`, ASVS-08).
    "OPENSEAL_LOG_PSEUDONYM_KEY_FILE",
];

/// One JSON log line (`casual-sign-seclog`, ASVS-08) with string fields.
fn log_line(level: casual_sign_seclog::Level, event: &str, fields: &[(&str, String)]) {
    let mut m = serde_json::Map::new();
    for (k, v) in fields {
        m.insert((*k).to_owned(), serde_json::Value::String(v.clone()));
    }
    casual_sign_seclog::write(casual_sign_seclog::Service::Keyd, level, event, m);
}

fn var(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn need(name: &'static str) -> Result<String, KeydError> {
    var(name).ok_or(KeydError::Setting(name))
}

fn read(name: &'static str, path: &str) -> Result<Vec<u8>, KeydError> {
    std::fs::read(Path::new(path)).map_err(|_| KeydError::Setting(name))
}

fn rsa_algorithm(s: &str) -> Option<SignatureAlgorithm> {
    Some(match s {
        "pkcs1-sha256" => SignatureAlgorithm::RsaPkcs1Sha256,
        "pkcs1-sha384" => SignatureAlgorithm::RsaPkcs1Sha384,
        "pkcs1-sha512" => SignatureAlgorithm::RsaPkcs1Sha512,
        "pss-sha256" => SignatureAlgorithm::RsaPssSha256,
        "pss-sha384" => SignatureAlgorithm::RsaPssSha384,
        "pss-sha512" => SignatureAlgorithm::RsaPssSha512,
        _ => return None,
    })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i.saturating_add(2))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect()
}

fn key() -> Result<Arc<dyn DigestSigner>, KeydError> {
    let rsa = match var("OPENSEAL_KEYD_RSA_ALGORITHM") {
        Some(s) => {
            Some(rsa_algorithm(&s).ok_or(KeydError::Setting("OPENSEAL_KEYD_RSA_ALGORITHM"))?)
        }
        None => None,
    };
    let chain = |name: &'static str| -> Result<Option<Vec<_>>, KeydError> {
        var(name)
            .map(|p| read(name, &p).and_then(|b| certificates(&b)))
            .transpose()
    };
    match (
        var("OPENSEAL_KEYD_PKCS11_MODULE"),
        var("OPENSEAL_KEYD_FILE_KEY"),
    ) {
        (Some(_), Some(_)) => Err(KeydError::Setting(
            "OPENSEAL_KEYD_PKCS11_MODULE and OPENSEAL_KEYD_FILE_KEY (set one)",
        )),
        (None, None) => Err(KeydError::Setting("OPENSEAL_KEYD_PKCS11_MODULE")),
        (None, Some(path)) => {
            // Consent first: without it the key file is not even read.
            let consent = DevKeyConsent::from_env()?;
            let key_pem = read("OPENSEAL_KEYD_FILE_KEY", &path)?;
            let chain =
                chain("OPENSEAL_KEYD_CHAIN")?.ok_or(KeydError::Setting("OPENSEAL_KEYD_CHAIN"))?;
            let key = FileKey::load(consent, &key_pem, chain, rsa)?;
            casual_sign_keyd::probe(&key)?;
            log_line(
                casual_sign_seclog::Level::Warn,
                "development_file_key",
                &[("note", "not for production".into())],
            );
            Ok(Arc::new(key))
        }
        (Some(module), None) => {
            let pin = env_secret("OPENSEAL_KEYD_PKCS11_PIN")?
                .ok_or(KeydError::Setting("OPENSEAL_KEYD_PKCS11_PIN"))?;
            let key_id = match var("OPENSEAL_KEYD_PKCS11_KEY_ID") {
                Some(h) => {
                    Some(hex_decode(&h).ok_or(KeydError::Setting("OPENSEAL_KEYD_PKCS11_KEY_ID"))?)
                }
                None => None,
            };
            let chain = match chain("OPENSEAL_KEYD_CHAIN")? {
                Some(c) => ChainSource::Supplied(c),
                None => ChainSource::Token {
                    rest: chain("OPENSEAL_KEYD_INTERMEDIATES")?.unwrap_or_default(),
                },
            };
            let module = Pkcs11Module::open(&PathBuf::from(module))?;
            let key = module.key(Pkcs11KeyConfig {
                token_label: need("OPENSEAL_KEYD_PKCS11_TOKEN")?,
                key_label: var("OPENSEAL_KEYD_PKCS11_KEY_LABEL"),
                key_id,
                pin,
                chain,
                rsa_algorithm: rsa,
            })?;
            Ok(Arc::new(key))
        }
    }
}

fn run() -> Result<(), KeydError> {
    for name in unknown_secret_files(std::env::vars().map(|(k, _)| k), KNOWN_SECRET_FILES) {
        log_line(
            casual_sign_seclog::Level::Warn,
            "secret_file_unread",
            &[("variable", name.clone())],
        );
    }
    let tls = server_tls(
        &read("OPENSEAL_KEYD_TLS_CERT", &need("OPENSEAL_KEYD_TLS_CERT")?)?,
        &read("OPENSEAL_KEYD_TLS_KEY", &need("OPENSEAL_KEYD_TLS_KEY")?)?,
        &read("OPENSEAL_KEYD_CLIENT_CA", &need("OPENSEAL_KEYD_CLIENT_CA")?)?,
    )?;
    let allow_text = read(
        "OPENSEAL_KEYD_ALLOW_LIST",
        &need("OPENSEAL_KEYD_ALLOW_LIST")?,
    )?;
    let allow = AllowList::parse(
        core::str::from_utf8(&allow_text)
            .map_err(|_| KeydError::Setting("OPENSEAL_KEYD_ALLOW_LIST"))?,
    )?;
    if allow.is_empty() {
        return Err(KeydError::Setting("OPENSEAL_KEYD_ALLOW_LIST (empty)"));
    }
    let log = OpLog::open(Path::new(&need("OPENSEAL_KEYD_OPLOG")?))?;
    let mut limits = KeydLimits::default();
    if let Some(n) = var("OPENSEAL_KEYD_SIGNATURES_PER_MINUTE") {
        limits.signatures_per_minute = n
            .parse()
            .map_err(|_| KeydError::Setting("OPENSEAL_KEYD_SIGNATURES_PER_MINUTE"))?;
    }
    let alias = var("OPENSEAL_KEYD_ALIAS").unwrap_or_else(|| "platform".into());
    let mut service = KeyService::new(allow, log, limits);
    if let Some(path) = var("OPENSEAL_KEYD_ADMIN_ALLOW_LIST") {
        let text = read("OPENSEAL_KEYD_ADMIN_ALLOW_LIST", &path)?;
        let admin = AllowList::parse(
            core::str::from_utf8(&text)
                .map_err(|_| KeydError::Setting("OPENSEAL_KEYD_ADMIN_ALLOW_LIST"))?,
        )?;
        service = service.with_admin(admin)?;
    }
    service.add_key(&alias, key()?)?;
    let listen = var("OPENSEAL_KEYD_LISTEN").unwrap_or_else(|| "127.0.0.1:7443".into());
    let keyd = Keyd::bind(&listen, tls, service)?;
    log_line(
        casual_sign_seclog::Level::Info,
        "serving",
        &[("alias", alias), ("listen", keyd.local_addr()?.to_string())],
    );
    keyd.serve();
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("verify-oplog") {
        let Some(path) = args.next() else {
            eprintln!("keyd: usage: verify-oplog <path>");
            return ExitCode::FAILURE;
        };
        return match casual_sign_keyd::oplog::verify(Path::new(&path)) {
            Ok((lines, head)) => {
                println!("oplog verified: lines={lines} head={head}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("keyd: {e}");
                ExitCode::FAILURE
            }
        };
    }
    // A malformed pseudonym key stops keyd, as it stops the server and the console.
    if let Err(e) = casual_sign_seclog::Pseudonymizer::from_env() {
        log_line(
            casual_sign_seclog::Level::Error,
            "start_failed",
            &[("code", e.code().into()), ("error", e.to_string())],
        );
        return ExitCode::FAILURE;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log_line(
                casual_sign_seclog::Level::Error,
                "start_failed",
                &[("code", e.code().into()), ("error", e.to_string())],
            );
            ExitCode::FAILURE
        }
    }
}
