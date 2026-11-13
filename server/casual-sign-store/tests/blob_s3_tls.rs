//! The hop to a self-hosted object store is TLS with the deployment's private CA
//! (`HRD-06`): a store whose certificate chains only to that CA is refused with the
//! platform's roots alone and reached once `ca_pem` names the CA. A local TLS server
//! stands in for the store; nothing leaves the machine.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use casual_sign_store::blob::{S3BlobStore, S3Config};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A private CA and a `localhost` server certificate it issued.
fn pki() -> (String, CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(p, ca_key).unwrap();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    p.is_ca = IsCa::ExplicitNoCa;
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = p.signed_by(&key, &ca).unwrap();
    (
        ca.pem(),
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// Serve `n` TLS connections, answering every request `200` with no body.
fn serve(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>, n: usize) -> u16 {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let Ok(mut tcp) = stream else { continue };
            let mut conn = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut buf = [0u8; 4096];
            // A failed handshake (the client refused the certificate) ends this one.
            if tls.read(&mut buf).is_ok() {
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                let _ = tls.flush();
            }
        }
    });
    port
}

fn config(port: u16, ca_pem: Option<Vec<u8>>) -> S3Config {
    S3Config {
        endpoint: format!("https://localhost:{port}"),
        bucket: "openseal".into(),
        region: "us-east-1".into(),
        access_key: "openseal".into(),
        secret_key: "not-a-real-secret".into(),
        path_style: true,
        ca_pem,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_behind_the_private_ca_is_reached_only_with_that_ca() {
    let (ca, cert, key) = pki();
    let port = serve(cert, key, 2);

    let without = S3BlobStore::new(&config(port, None)).unwrap();
    assert_eq!(
        without.create_bucket().await.unwrap_err().code(),
        "CS-BLOB-0001",
        "a certificate from an unknown CA was accepted"
    );

    let with = S3BlobStore::new(&config(port, Some(ca.into_bytes()))).unwrap();
    with.create_bucket().await.unwrap();
}

#[test]
fn a_ca_file_with_no_certificate_is_refused() {
    let err = S3BlobStore::new(&config(1, Some(b"not a pem".to_vec()))).unwrap_err();
    assert_eq!(err.code(), "CS-BLOB-0001");
}
