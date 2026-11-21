//! Remote-provider signatures for OpenSeal (`RSP-01`, ADR-046): the operator's provider
//! catalogue ([`catalogue`]), provider secrets sealed with AES-256-GCM
//! ([`sealing`]), and the Cloud Signature Consortium API v2 client the worker uses to
//! reach a signer's provider.
//!
//! A host crate: it performs network I/O and reads secrets, so it never enters the
//! engine and compiles natively only. Nothing here signs: a provider signs, and the
//! engine (`casual-sign-seal` `prepare`/`complete`) embeds what it returns after checking
//! it.

pub mod catalogue;
pub mod client;
mod error;
pub mod sealing;

pub use catalogue::{Catalogue, Kind, Provider};
pub use client::{Client, CredentialInfo, Scope, Transport};
pub use error::CscError;
pub use sealing::ProviderSecretsKey;
