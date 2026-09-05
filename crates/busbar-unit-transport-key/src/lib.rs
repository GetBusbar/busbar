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
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use std::collections::HashMap;
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

/// Where one listener's material is kept, and what the journal records it as.
///
/// The two travel together because they name one thing from two sides: the slot is what a transport
/// looks a config up by, and the fingerprint is what the access entry says was read. Neither is the
/// material, and neither can be turned back into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// The node-local slot the config is registered under.
    pub index: u64,
    /// What the journal's access entry records.
    pub fingerprint: &'static str,
}

/// Where one listener's TLS material is resolved from, as the secret source spells it.
///
/// `client_ca` present means mTLS: the client MUST present a certificate chaining to that CA or the
/// handshake fails. Absent means server-only TLS. The grammar of each location is the caller's and
/// its own secret source's; this unit never interprets one.
#[derive(Debug, Clone, Copy)]
pub struct TlsLocations<'a> {
    /// The certificate chain, leaf first.
    pub cert: &'a str,
    /// The private key.
    pub key: &'a str,
    /// The CA bundle a presented client certificate is verified against, where mTLS is configured.
    pub client_ca: Option<&'a str>,
}

/// What a transport that speaks TLS offers this unit: somewhere to put the material it resolved.
///
/// A transport is handed an opaque handle and looks a config up by its slot. Something has to have
/// put the config there, and it cannot be the transport — a transport may not read a secret. This
/// is that seam, and the whole of it: the unit resolves, journals and registers, and the transport
/// only ever sees a slot number.
pub trait TlsConfigSink {
    /// Take the server-side config for a slot.
    fn register_server_config(&self, slot: u64, cfg: Arc<ServerConfig>);
    /// Take the client-side config for a slot.
    fn register_client_config(&self, slot: u64, cfg: Arc<rustls::ClientConfig>);
}

/// Resolve a listener's TLS material, journal the access, register the config, and hand back the
/// handle the transport will present at `listen`, `accept` and every adoption over it.
///
/// This is the one call a composition root makes, and it is the whole path the design draws: the
/// secret plugin is read here and nowhere else, the `Access` entry is written for every secret
/// actually read, the config lands in the transport's slot, and what leaves this function carries
/// no material at all. Before it existed the only thing that ever registered a config was the
/// transport's own tests, which meant a production listener had no key.
///
/// # Errors
///
/// The material could not be resolved through the secret source, or it did not parse into a usable
/// certificate and key. The message names the secret's SOURCE, never its bytes.
pub fn provision_server(
    source: &dyn SecretSource,
    journal: &dyn AccessJournal,
    sink: &dyn TlsConfigSink,
    token: &TransportKeyToken,
    slot: Slot,
    at: &TlsLocations<'_>,
) -> Result<TransportKeyHandle, String> {
    let material = resolve_tls_material(source, journal, at.cert, at.key, at.client_ca)?;
    sink.register_server_config(slot.index, Arc::new(build_server_config(&material)?));
    Ok(issue_handle(token, slot.index, slot.fingerprint))
}

/// The dial-side half: register the client config a transport presents when it dials, and hand back
/// the handle naming its slot.
///
/// The trust roots are the caller's, because which authorities a node will accept upstream is a
/// deployment's statement and not this unit's. Nothing is read through the secret source here —
/// a public root store is not a secret — so nothing is journaled either.
pub fn provision_client(
    sink: &dyn TlsConfigSink,
    token: &TransportKeyToken,
    slot: Slot,
    cfg: Arc<rustls::ClientConfig>,
) -> TransportKeyHandle {
    sink.register_client_config(slot.index, cfg);
    issue_handle(token, slot.index, slot.fingerprint)
}

/// One SNI name and the secret locations its certificate and key resolve from, for
/// [`provision_server_named`].
///
/// A named entry never carries a client CA of its own: rustls' [`ResolvesServerCert`] only ever
/// swaps the leaf certificate and key per `ClientHello`, never the client-cert verifier, so mTLS —
/// where a deployment wants it — is a listener-wide setting configured once on `default_at` and
/// applies uniformly regardless of which name a client offered.
#[derive(Debug, Clone, Copy)]
pub struct NamedTlsLocations<'a> {
    /// The SNI name a `ClientHello` must present exactly to select this entry.
    pub sni: &'a str,
    /// The certificate chain, leaf first.
    pub cert: &'a str,
    /// The private key.
    pub key: &'a str,
}

/// Parse resolved material into a [`CertifiedKey`] — the unit of what a [`ResolvesServerCert`]
/// hands back per `ClientHello`. Kept separate from [`build_server_config`] because a named-SNI
/// listener builds several of these and installs them behind one resolver rather than baking a
/// single one straight into a `ServerConfig`.
fn certified_key(material: &TlsMaterial) -> Result<Arc<CertifiedKey>, String> {
    let certs = load_cert_chain(&material.cert_pem)?;
    let key = load_private_key(&material.key_pem)?;
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(certs, key, &provider)
        .map(Arc::new)
        .map_err(|e| format!("TLS cert/key are not a valid pair: {e}"))
}

/// Build the client-cert verifier for a named-SNI listener's shared mTLS setting. Kept apart from
/// [`build_server_config`]'s inline equivalent so that function is untouched by this addition.
fn client_verifier(client_ca_pem: &[u8]) -> Result<Arc<dyn ClientCertVerifier>, String> {
    let roots = load_client_roots(client_ca_pem)?;
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("cannot build client-cert verifier from TLS client_ca: {e}"))
}

/// Picks a [`CertifiedKey`] by the `ClientHello`'s SNI name, falling back to the listener's
/// default when the name is absent (no SNI offered) or present but unrecognised (an unknown name).
/// 1.5.5 served exactly one certificate per listener regardless of SNI (`v1.5.5` `tls.rs` never
/// reads `ClientHello::server_name` at all) — falling through to the default for an unrecognised
/// name, rather than refusing the handshake, is the parity choice: a client that would have gotten
/// 1.5.5's one cert unconditionally still gets *a* cert here, on any name.
#[derive(Debug)]
struct SniCertResolver {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(match client_hello.server_name() {
            Some(name) => self.by_name.get(name).unwrap_or(&self.default).clone(),
            None => self.default.clone(),
        })
    }
}

/// Resolve several named listener certificates plus a default, journal one `Access` entry per
/// secret actually read (each name's cert and key, in order, then the default's cert, key and
/// optional client CA), build one `ServerConfig` whose [`ResolvesServerCert`] picks among them by
/// `ClientHello` SNI, register it under `slot`, and hand back the handle a listener presents at
/// `listen`, `accept` and every adoption over it — the same single handle a single-cert listener
/// gets from [`provision_server`], because the routing this adds lives entirely inside the one
/// registered config's resolver, not in a second registry the transport has to know about.
///
/// # Errors
///
/// A name's or the default's material could not be resolved through the secret source, or it did
/// not parse into a usable certificate and key.
#[allow(clippy::missing_panics_doc)]
pub fn provision_server_named(
    source: &dyn SecretSource,
    journal: &dyn AccessJournal,
    sink: &dyn TlsConfigSink,
    token: &TransportKeyToken,
    slot: Slot,
    names: &[NamedTlsLocations<'_>],
    default_at: &TlsLocations<'_>,
) -> Result<TransportKeyHandle, String> {
    let mut by_name = HashMap::with_capacity(names.len());
    for n in names {
        let material = resolve_tls_material(source, journal, n.cert, n.key, None)?;
        by_name.insert(n.sni.to_string(), certified_key(&material)?);
    }

    let default_material = resolve_tls_material(
        source,
        journal,
        default_at.cert,
        default_at.key,
        default_at.client_ca,
    )?;
    let default = certified_key(&default_material)?;

    let builder = ServerConfig::builder();
    let builder = match &default_material.client_ca_pem {
        Some(ca_pem) => builder.with_client_cert_verifier(client_verifier(ca_pem)?),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(Arc::new(SniCertResolver { by_name, default }));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    sink.register_server_config(slot.index, Arc::new(config));
    Ok(issue_handle(token, slot.index, slot.fingerprint))
}

#[cfg(test)]
mod tests;
