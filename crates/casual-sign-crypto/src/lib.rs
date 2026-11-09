//! Cryptographic structures for OpenSeal (docs/31, ADR-006): CMS SignedData, X.509,
//! RFC 3161 timestamps, OCSP and CRLs, and the `KeyProvider` seam through which a host
//! signs. No primitive is implemented here; they come from the libraries ADR-006 names.
//! This crate holds no key and performs no I/O.
//!
//! **Skeleton.** Built in stage 1F (`T-1F`).
