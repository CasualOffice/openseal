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
//! | `OPENSEAL_KEYD_NEXT_ALIAS` | Optional, during a seal key rotation (`CON-10`): a second key served beside the first, on the same token: `OPENSEAL_KEYD_NEXT_PKCS11_KEY_LABEL` and/or `_KEY_ID` (one is required), `OPENSEAL_KEYD_NEXT_CHAIN` or `_INTERMEDIATES`; development: `OPENSEAL_KEYD_NEXT_FILE_KEY` with `OPENSEAL_KEYD_NEXT_CHAIN` |
//! | `OPENSEAL_CONFIG_MANIFEST` | Optional (required by the production profile): the manifest of the security settings below; keyd refuses to start when they differ (`CS-KEY-0014`, ASVS-24) |
//!
//! **Security configuration** (ASVS 14.1.5): every setting above except the PIN is read
//! once, at start, so a change takes effect only on a restart. At start keyd logs the
//! SHA-256 of each security setting (the files' contents and the values; never the PIN)
//! and one digest over them all, and, with `OPENSEAL_CONFIG_MANIFEST`, refuses to start
//! unless they are exactly the manifest's. `casual-sign-keyd config-manifest` prints the
//! manifest of the current environment, for the operator to record after an approved
//! change (docs/65 §Configuration integrity).
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
use casual_sign_secrets::integrity::ConfigDigest;
use casual_sign_secrets::{env_secret, unknown_secret_files};

const KNOWN_SECRET_FILES: &[&str] = &["OPENSEAL_KEYD_PKCS11_PIN_FILE"];

/// Security settings that name a file: the file's bytes are hashed (ASVS-24). The
/// PKCS#11 module is the HSM vendor's library, so it is hashed too.
const CONFIG_FILES: &[&str] = &[
    "OPENSEAL_KEYD_TLS_CERT",
    "OPENSEAL_KEYD_CLIENT_CA",
    "OPENSEAL_KEYD_ALLOW_LIST",
    "OPENSEAL_KEYD_ADMIN_ALLOW_LIST",
    "OPENSEAL_KEYD_CHAIN",
    "OPENSEAL_KEYD_INTERMEDIATES",
    "OPENSEAL_KEYD_PKCS11_MODULE",
    "OPENSEAL_KEYD_NEXT_CHAIN",
    "OPENSEAL_KEYD_NEXT_INTERMEDIATES",
];

/// Security settings hashed as values.
const CONFIG_VALUES: &[&str] = &[
    "OPENSEAL_KEYD_LISTEN",
    "OPENSEAL_KEYD_ALIAS",
    "OPENSEAL_KEYD_RSA_ALGORITHM",
    "OPENSEAL_KEYD_PKCS11_TOKEN",
    "OPENSEAL_KEYD_PKCS11_KEY_LABEL",
    "OPENSEAL_KEYD_PKCS11_KEY_ID",
    "OPENSEAL_KEYD_FILE_KEY",
    "OPENSEAL_KEYD_SIGNATURES_PER_MINUTE",
    // A path, not a file: the log grows with every signature.
    "OPENSEAL_KEYD_OPLOG",
    "OPENSEAL_DEV_INSECURE_KEY",
    "OPENSEAL_KEYD_NEXT_ALIAS",
    "OPENSEAL_KEYD_NEXT_PKCS11_KEY_LABEL",
    "OPENSEAL_KEYD_NEXT_PKCS11_KEY_ID",
    "OPENSEAL_KEYD_NEXT_FILE_KEY",
];

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

/// The settings naming one key: the current one, or the one a seal key rotation adds
/// beside it (`CON-10`, docs/65 §Rotation).
struct Slot {
    next: bool,
    alias: String,
    file_key: &'static str,
    chain: &'static str,
    intermediates: &'static str,
    key_label: &'static str,
    key_id: &'static str,
}

/// The current key's settings, and the next key's when `OPENSEAL_KEYD_NEXT_ALIAS` is set.
fn slots() -> Result<Vec<Slot>, KeydError> {
    let mut out = vec![Slot {
        next: false,
        alias: var("OPENSEAL_KEYD_ALIAS").unwrap_or_else(|| "platform".into()),
        file_key: "OPENSEAL_KEYD_FILE_KEY",
        chain: "OPENSEAL_KEYD_CHAIN",
        intermediates: "OPENSEAL_KEYD_INTERMEDIATES",
        key_label: "OPENSEAL_KEYD_PKCS11_KEY_LABEL",
        key_id: "OPENSEAL_KEYD_PKCS11_KEY_ID",
    }];
    if let Some(alias) = var("OPENSEAL_KEYD_NEXT_ALIAS") {
        if out.iter().any(|s| s.alias == alias) {
            return Err(KeydError::Setting(
                "OPENSEAL_KEYD_NEXT_ALIAS (the same as OPENSEAL_KEYD_ALIAS)",
            ));
        }
        out.push(Slot {
            next: true,
            alias,
            file_key: "OPENSEAL_KEYD_NEXT_FILE_KEY",
            chain: "OPENSEAL_KEYD_NEXT_CHAIN",
            intermediates: "OPENSEAL_KEYD_NEXT_INTERMEDIATES",
            key_label: "OPENSEAL_KEYD_NEXT_PKCS11_KEY_LABEL",
            key_id: "OPENSEAL_KEYD_NEXT_PKCS11_KEY_ID",
        });
    }
    Ok(out)
}

/// A key keyd serves, with its alias.
type AliasedKey = (String, Arc<dyn DigestSigner>);

/// Every key keyd serves, by alias: one PKCS#11 module (initialised once) or development
/// file keys, never both.
fn keys() -> Result<Vec<AliasedKey>, KeydError> {
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
    let slots = slots()?;
    match (
        var("OPENSEAL_KEYD_PKCS11_MODULE"),
        var("OPENSEAL_KEYD_FILE_KEY"),
    ) {
        (Some(_), Some(_)) => Err(KeydError::Setting(
            "OPENSEAL_KEYD_PKCS11_MODULE and OPENSEAL_KEYD_FILE_KEY (set one)",
        )),
        (None, None) => Err(KeydError::Setting("OPENSEAL_KEYD_PKCS11_MODULE")),
        (None, Some(_)) => {
            // Consent first: without it no key file is even read.
            let consent = DevKeyConsent::from_env()?;
            let mut out: Vec<AliasedKey> = Vec::new();
            for slot in slots {
                let path = need(slot.file_key)?;
                let key_pem = read(slot.file_key, &path)?;
                let chain = chain(slot.chain)?.ok_or(KeydError::Setting(slot.chain))?;
                let key = FileKey::load(consent, &key_pem, chain, rsa)?;
                casual_sign_keyd::probe(&key)?;
                eprintln!(
                    "keyd: DEVELOPMENT FILE KEY in use for {}; not for production",
                    slot.alias
                );
                out.push((slot.alias, Arc::new(key)));
            }
            Ok(out)
        }
        (Some(module), None) => {
            let module = Pkcs11Module::open(&PathBuf::from(module))?;
            let token_label = need("OPENSEAL_KEYD_PKCS11_TOKEN")?;
            let mut out: Vec<AliasedKey> = Vec::new();
            for slot in slots {
                let pin = env_secret("OPENSEAL_KEYD_PKCS11_PIN")?
                    .ok_or(KeydError::Setting("OPENSEAL_KEYD_PKCS11_PIN"))?;
                let key_id = match var(slot.key_id) {
                    Some(h) => Some(hex_decode(&h).ok_or(KeydError::Setting(slot.key_id))?),
                    None => None,
                };
                let label = var(slot.key_label);
                // The next key must name itself: the token's only key is the current one.
                if slot.next && label.is_none() && key_id.is_none() {
                    return Err(KeydError::Setting(slot.key_label));
                }
                let chain = match chain(slot.chain)? {
                    Some(c) => ChainSource::Supplied(c),
                    None => ChainSource::Token {
                        rest: chain(slot.intermediates)?.unwrap_or_default(),
                    },
                };
                let key = module.key(Pkcs11KeyConfig {
                    token_label: token_label.clone(),
                    key_label: label,
                    key_id,
                    pin,
                    chain,
                    rsa_algorithm: rsa,
                })?;
                out.push((slot.alias, Arc::new(key)));
            }
            Ok(out)
        }
    }
}

fn run() -> Result<(), KeydError> {
    for name in unknown_secret_files(std::env::vars().map(|(k, _)| k), KNOWN_SECRET_FILES) {
        eprintln!("keyd: {name} is set but read by nothing (misspelled?)");
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
    let mut service = KeyService::new(allow, log, limits);
    if let Some(path) = var("OPENSEAL_KEYD_ADMIN_ALLOW_LIST") {
        let text = read("OPENSEAL_KEYD_ADMIN_ALLOW_LIST", &path)?;
        let admin = AllowList::parse(
            core::str::from_utf8(&text)
                .map_err(|_| KeydError::Setting("OPENSEAL_KEYD_ADMIN_ALLOW_LIST"))?,
        )?;
        service = service.with_admin(admin)?;
    }
    let mut aliases = Vec::new();
    for (alias, key) in keys()? {
        service.add_key(&alias, key)?;
        aliases.push(alias);
    }
    let listen = var("OPENSEAL_KEYD_LISTEN").unwrap_or_else(|| "127.0.0.1:7443".into());
    let keyd = Keyd::bind(&listen, tls, service)?;
    eprintln!(
        "keyd: serving alias {} on {}",
        aliases.join(" and "),
        keyd.local_addr()?
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
    let config = match ConfigDigest::from_env(CONFIG_FILES, CONFIG_VALUES) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("keyd: {e}");
            return ExitCode::FAILURE;
        }
    };
    if std::env::args().nth(1).as_deref() == Some("config-manifest") {
        print!("{}", config.manifest());
        return ExitCode::SUCCESS;
    }
    // Before anything else is read: a configuration that is not the approved one never
    // reaches the HSM or the network.
    if let Err(e) = config.log_and_check("keyd") {
        eprintln!("keyd: {e}");
        return ExitCode::FAILURE;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keyd: {e}");
            ExitCode::FAILURE
        }
    }
}
