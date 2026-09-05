// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-transport-key — the transport-key unit
//!
//! `Transport::listen` / `dial` / `upgrade` each need key material exactly once, resolved through
//! the secret plugin, journaled as an `Access` entry, and handed back as an opaque
//! [`TransportKeyHandle`] (`busbar-contract`, re-exported by `busbar-caps`) rather than as bytes — nothing downstream of this unit can
//! turn a handle back into key material. This crate is that resolution step, standing alone from
//! the transport it serves: given a [`SecretSource`] (the abstract "read this named secret" seam a
//! real deployment's secret plugin sits behind) and an [`AccessJournal`] (the "record that this
//! secret was read, and why" seam the audit trail sits behind), it resolves TLS key material and
//! builds the `rustls::ServerConfig` a listener actually needs.
//!
//! ## What is in here
//!
//! - [`SecretSource`] / [`AccessJournal`] — the two seams a real deployment wires to the secret
//!   plugin and the journal; this crate depends on neither directly.
//! - [`resolve_tls_material`] — reads cert / key / optional client-CA bytes through a
//!   [`SecretSource`], journaling one `Access` entry per secret read.
//! - [`build_server_config`] — parses the resolved PEM material into a `rustls::ServerConfig`
//!   (mTLS when a client CA was resolved, server-only TLS otherwise), ported from
//!   `busbar-core`'s `tls::build_server_config`.
//! - [`issue_handle`] — the thin wrapper over `TransportKeyHandle::issue` this unit is the one
//!   caller of.
//!
//! ## What is deliberately absent
//!
//! The listener accept loop, the hyper/axum connection-serving machinery, and the end-to-end
//! TLS/mTLS wire tests that drive them with a real TCP client are a LISTENER concern, not a
//! key-resolution concern — porting them here would have pulled `axum`, `hyper-util`, and a running
//! `tokio` runtime into a crate whose whole point is standing alone. See the crate's test module
//! doc for the exact list of `busbar-core::tls` tests this leaves unported and why.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use busbar_caps::{TransportKeyHandle, TransportKeyToken};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::sync::Arc;

/// Install a process-wide `ring` crypto provider. rustls 0.23 requires exactly one; idempotent —
/// a "provider already installed" error is expected and ignored. Must run before
/// [`build_server_config`].
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Where a piece of key material comes from — the abstract secret-plugin seam. A real deployment's
/// secret plugin (file, KMS reference, inline literal) sits behind this; this crate names no
/// concrete backend. `location` is caller-defined and opaque to this crate (a file path, a secret
/// reference string, ...); only the caller and its `SecretSource` need to agree on its grammar.
pub trait SecretSource {
    /// Resolve `location` to its raw bytes (PEM, for the callers in this crate). The error string
    /// names the source, never the bytes it failed to produce.
    fn resolve(&self, location: &str) -> Result<Vec<u8>, String>;
}

/// One purpose a resolved secret was read for, named so the journal records WHY, not just WHAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPurpose {
    /// The TLS server certificate chain.
    Cert,
    /// The TLS server private key.
    Key,
    /// The mTLS client-CA bundle used to verify a presented client certificate.
    ClientCa,
}

impl AccessPurpose {
    /// The purpose as a stable string, for a journal entry that outlives this crate's enum.
    pub fn as_str(self) -> &'static str {
        match self {
            AccessPurpose::Cert => "cert",
            AccessPurpose::Key => "key",
            AccessPurpose::ClientCa => "client_ca",
        }
    }
}

/// The "record that a secret was read" seam — the `Access` journal entry this unit is required to
/// write every time it resolves key material. A real deployment journals this into the one
/// audit ledger every other unit posts to; this crate names no concrete journal.
pub trait AccessJournal {
    /// Record one resolution: `location` is the same opaque string passed to [`SecretSource::resolve`],
    /// `purpose` is why it was read.
    fn record_access(&self, location: &str, purpose: AccessPurpose);
}

/// The resolved TLS key material for one listener, before parsing. Bytes only — nothing here is an
/// opaque handle yet; [`build_server_config`] is what turns this into the thing a listener can
/// actually use, and [`issue_handle`] is what a caller mints to stand in for it downstream.
pub struct TlsMaterial {
    /// PEM certificate chain, leaf first.
    pub cert_pem: Vec<u8>,
    /// PEM private key (PKCS#8, PKCS#1, or SEC1).
    pub key_pem: Vec<u8>,
    /// PEM CA bundle for verifying a presented client certificate; `None` means server-only TLS
    /// (no mTLS).
    pub client_ca_pem: Option<Vec<u8>>,
}

/// Resolve one listener's TLS key material through `source`, journaling one [`AccessJournal`] entry
/// per secret actually read (cert, key, and client CA when configured). This is the ONLY place in
/// this crate that reads a `SecretSource`; everything downstream operates on the bytes already
/// returned here.
pub fn resolve_tls_material(
    source: &dyn SecretSource,
    journal: &dyn AccessJournal,
    cert_location: &str,
    key_location: &str,
    client_ca_location: Option<&str>,
) -> Result<TlsMaterial, String> {
    let cert_pem = source
        .resolve(cert_location)
        .map_err(|e| format!("cannot resolve TLS cert ({cert_location}): {e}"))?;
    journal.record_access(cert_location, AccessPurpose::Cert);

    let key_pem = source
        .resolve(key_location)
        .map_err(|e| format!("cannot resolve TLS key ({key_location}): {e}"))?;
    journal.record_access(key_location, AccessPurpose::Key);

    let client_ca_pem = match client_ca_location {
        Some(loc) => {
            let bytes = source
                .resolve(loc)
                .map_err(|e| format!("cannot resolve TLS client_ca ({loc}): {e}"))?;
            journal.record_access(loc, AccessPurpose::ClientCa);
            Some(bytes)
        }
        None => None,
    };

    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        client_ca_pem,
    })
}

/// Parse the PEM certificate chain (leaf first). Cert bytes are public, but errors still avoid
/// echoing them — only the byte length is safe to name and even that is omitted here, matching the
/// ported original's stance of naming only the secret SOURCE.
fn load_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS cert: {e}"))?;
    if certs.is_empty() {
        return Err(
            "TLS cert contains no certificates (expected a PEM chain, leaf first)".to_string(),
        );
    }
    Ok(certs)
}

/// Parse the PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encodings. Never logs
/// key material.
fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    use rustls::pki_types::pem::Error as PemError;
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| match e {
        PemError::NoItemsFound => {
            "TLS key contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)".to_string()
        }
        other => format!("cannot parse TLS key: {other}"),
    })
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).
fn load_client_roots(pem: &[u8]) -> Result<RootCertStore, String> {
    let cas = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS client_ca: {e}"))?;
    if cas.is_empty() {
        return Err("TLS client_ca contains no CA certificates".to_string());
    }
    let mut roots = RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| format!("invalid CA certificate in TLS client_ca: {e}"))?;
    }
    Ok(roots)
}

/// Construct the rustls [`ServerConfig`] from resolved [`TlsMaterial`], ported unchanged from
/// `busbar-core::tls::build_server_config`:
///
/// * `client_ca_pem` present => a `WebPkiClientVerifier` is installed: the client MUST present a
///   certificate chaining to that CA or the handshake fails (mTLS required).
/// * `client_ca_pem` absent => `with_no_client_auth()` (server-only TLS).
///
/// ALPN advertises only `http/1.1` — busbar's server speaks http/1.1, so this must not advertise
/// h2.
pub fn build_server_config(material: &TlsMaterial) -> Result<ServerConfig, String> {
    let certs = load_cert_chain(&material.cert_pem)?;
    let key = load_private_key(&material.key_pem)?;

    let builder = ServerConfig::builder();
    let builder = match &material.client_ca_pem {
        Some(ca_pem) => {
            let roots = load_client_roots(ca_pem)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    format!("cannot build client-cert verifier from TLS client_ca: {e}")
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS cert/key are not a valid pair: {e}"))?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Hand out an opaque handle for resolved key material. The transport-key unit is the only caller —
/// `TransportKeyHandle::issue` demands a [`TransportKeyToken`], which only the kernel lends to this
/// unit. `slot` is whatever local slot the caller keeps the actual material under, and
/// `fingerprint` is what the journal's access entry records; nothing about the material itself is
/// recoverable from the handle. The handle is the contract's own, which is what the transports and
/// the egress unit consume, so the unit that resolves a key and the code that dials with it now
/// name one type.
pub fn issue_handle(
    token: &TransportKeyToken,
    slot: u64,
    fingerprint: &'static str,
) -> TransportKeyHandle {
    TransportKeyHandle::issue(token, slot, fingerprint)
}

#[cfg(test)]
mod tests;
