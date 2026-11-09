//! Object identifiers this crate reads and writes, named after their RFC.

use der::asn1::ObjectIdentifier as Oid;

/// `id-data` (RFC 5652).
pub const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
/// `id-signedData` (RFC 5652).
pub const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
/// `id-contentType` (RFC 5652).
pub const ID_CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
/// `id-messageDigest` (RFC 5652).
pub const ID_MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
/// `id-aa-signingCertificateV2` (RFC 5035).
pub const ID_SIGNING_CERTIFICATE_V2: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// `id-aa-signatureTimeStampToken` (RFC 3161 appendix A).
pub const ID_SIGNATURE_TIME_STAMP_TOKEN: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// `id-ct-TSTInfo` (RFC 3161).
pub const ID_CT_TST_INFO: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `id-sha256`.
pub const ID_SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `id-sha384`.
pub const ID_SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
/// `id-sha512`.
pub const ID_SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

/// `id-ecPublicKey`.
pub const ID_EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1`.
pub const SECP256R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1`.
pub const SECP384R1: Oid = Oid::new_unwrap("1.3.132.0.34");
/// `ecdsa-with-SHA256`.
pub const ECDSA_WITH_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384`.
pub const ECDSA_WITH_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
/// `ecdsa-with-SHA512`.
pub const ECDSA_WITH_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");

/// `rsaEncryption` (also seen as a CMS signature algorithm, meaning PKCS#1 v1.5).
pub const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
/// `sha256WithRSAEncryption`.
pub const SHA256_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
/// `sha384WithRSAEncryption`.
pub const SHA384_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
/// `sha512WithRSAEncryption`.
pub const SHA512_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");
/// `id-RSASSA-PSS`.
pub const RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
/// `id-mgf1`.
pub const MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");

/// `id-kp-timeStamping`.
pub const KP_TIME_STAMPING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.8");
/// `id-kp-OCSPSigning`.
pub const KP_OCSP_SIGNING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.9");
/// `id-pkix-ocsp-basic`.
pub const OCSP_BASIC: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// `id-ce-cRLNumber`.
pub const CE_CRL_NUMBER: Oid = Oid::new_unwrap("2.5.29.20");
/// `id-ce-authorityKeyIdentifier`.
pub const CE_AUTHORITY_KEY_IDENTIFIER: Oid = Oid::new_unwrap("2.5.29.35");
/// `id-ce-cRLReasons` (entry extension).
pub const CE_CRL_REASONS: Oid = Oid::new_unwrap("2.5.29.21");
