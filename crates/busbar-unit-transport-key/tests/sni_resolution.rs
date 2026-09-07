// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The named-SNI listener, driven the only way the certificate it picks is observable: a real
//! rustls handshake, over a pair of in-memory buffers, reading back the certificate the server
//! actually presented.
//!
//! The unit tests beside `provision_server_named` reach into `SniCertResolver` and compare `Arc`
//! identity out of `pick`. That proves the TABLE is keyed and looked up the way it should be, and
//! proves nothing about whether the table is ever consulted: the `ResolvesServerCert` impl that
//! stands between a `ClientHello` and `pick` can hand back `None` for every name and every one of
//! those assertions still holds. A server that resolves no certificate does not serve the wrong
//! one — it refuses the handshake outright, so every client of a listener an operator provisioned
//! is turned away. Nothing short of completing a handshake sees that, which is what this file does.

use busbar_unit_transport_key::{
    install_crypto_provider, provision_server_named, AccessJournal, AccessPurpose,
    NamedTlsLocations, SecretSource, Slot, TlsConfigSink, TlsLocations, DEFAULT_ALPN,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One CA, and a leaf under it for each SAN list asked for. Every leaf chains to the same CA, so a
/// client that trusts that one CA can complete a handshake against whichever leaf the server picks
/// and the difference that comes back is about the NAME, never about trust.
fn ca_and_leaves(leaf_sans: &[Vec<String>]) -> (String, Vec<(String, String)>) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);

    let leaves = leaf_sans
        .iter()
        .map(|sans| {
            let kp = KeyPair::generate().unwrap();
            let params = CertificateParams::new(sans.clone()).unwrap();
            let cert = params.signed_by(&kp, &issuer).unwrap();
            (cert.pem(), kp.serialize_pem())
        })
        .collect();
    (ca_cert.pem(), leaves)
}

struct MapSource(HashMap<String, Vec<u8>>);
impl SecretSource for MapSource {
    fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
        self.0
            .get(location)
            .cloned()
            .ok_or_else(|| format!("no secret at {location}"))
    }
}

#[derive(Default)]
struct RecordingJournal(Mutex<Vec<(String, AccessPurpose)>>);
impl AccessJournal for RecordingJournal {
    fn record_access(&self, location: &str, purpose: AccessPurpose) {
        self.0.lock().unwrap().push((location.to_string(), purpose));
    }
}

#[derive(Default)]
struct RecordingSink(Mutex<Option<Arc<ServerConfig>>>);
impl TlsConfigSink for RecordingSink {
    fn register_server_config(&self, _slot: u64, cfg: Arc<ServerConfig>) {
        *self.0.lock().unwrap() = Some(cfg);
    }
    fn register_client_config(&self, _slot: u64, _cfg: Arc<rustls::ClientConfig>) {}
}

/// Complete a handshake against `config` offering `sni`, and hand back the DER of the leaf
/// certificate the server presented. The two connections are pumped by hand because the only thing
/// a listener's accept loop contributes here is moving bytes between them, and what is under test
/// is decided before any application data exists.
fn leaf_presented_for(
    config: Arc<ServerConfig>,
    ca_pem: &str,
    sni: &str,
) -> Result<CertificateDer<'static>, rustls::Error> {
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(ca.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), sni.to_string().try_into().unwrap())
            .unwrap();
    let mut server = rustls::ServerConnection::new(config).unwrap();

    for _ in 0..16 {
        let mut to_server = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut to_server).unwrap();
        }
        let mut from_client = to_server.as_slice();
        while !from_client.is_empty() {
            server.read_tls(&mut from_client).unwrap();
            server.process_new_packets()?;
        }

        let mut to_client = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut to_client).unwrap();
        }
        let mut from_server = to_client.as_slice();
        while !from_server.is_empty() {
            client.read_tls(&mut from_server).unwrap();
            client.process_new_packets()?;
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            let chain = client
                .peer_certificates()
                .expect("a completed handshake presented a certificate chain");
            return Ok(chain[0].clone().into_owned());
        }
    }
    panic!("the handshake neither completed nor failed");
}

fn der_of(pem: &str) -> CertificateDer<'static> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .into_owned()
}

/// A listener provisioned with per-name certificates presents the NAMED one to a client that
/// offered that name, and the default to a client that offered a name it has no entry for.
///
/// Both halves are asserted from outside the crate, against the config a composition root actually
/// registers, so they hold regardless of how the resolver is wired internally. Either half failing
/// is a listener serving a certificate an operator did not configure for that name.
#[test]
fn a_provisioned_listener_presents_the_certificate_configured_for_the_offered_name() {
    install_crypto_provider();
    let (ca_pem, leaves) = ca_and_leaves(&[
        vec!["a.example".to_string()],
        vec!["b.example".to_string()],
        vec!["default.example".to_string(), "unknown.example".to_string()],
    ]);
    let [(a_cert, a_key), (b_cert, b_key), (d_cert, d_key)] =
        <[(String, String); 3]>::try_from(leaves)
            .unwrap_or_else(|_| panic!("three leaves were asked for"));

    let source = MapSource(
        [
            ("a.cert".to_string(), a_cert.clone().into_bytes()),
            ("a.key".to_string(), a_key.into_bytes()),
            ("b.cert".to_string(), b_cert.clone().into_bytes()),
            ("b.key".to_string(), b_key.into_bytes()),
            ("d.cert".to_string(), d_cert.clone().into_bytes()),
            ("d.key".to_string(), d_key.into_bytes()),
        ]
        .into_iter()
        .collect(),
    );
    let journal = RecordingJournal::default();
    let sink = RecordingSink::default();

    provision_server_named(
        &source,
        &journal,
        &sink,
        &busbar_caps::TransportKeyToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel()),
        Slot {
            index: 0,
            fingerprint: "fixture",
        },
        &[
            NamedTlsLocations {
                sni: "a.example",
                cert: "a.cert",
                key: "a.key",
            },
            NamedTlsLocations {
                sni: "b.example",
                cert: "b.cert",
                key: "b.key",
            },
        ],
        &TlsLocations {
            cert: "d.cert",
            key: "d.key",
            client_ca: None,
        },
        DEFAULT_ALPN,
    )
    .unwrap();

    let config = sink.0.lock().unwrap().clone().unwrap();

    for (offered, expected_pem, which) in [
        (
            "a.example",
            &a_cert,
            "the certificate provisioned for a.example",
        ),
        (
            "b.example",
            &b_cert,
            "the certificate provisioned for b.example",
        ),
        (
            "unknown.example",
            &d_cert,
            "the listener default, for a name with no entry",
        ),
    ] {
        let presented = leaf_presented_for(Arc::clone(&config), &ca_pem, offered)
            .unwrap_or_else(|e| panic!("the handshake for {offered} did not complete: {e:?}"));
        assert_eq!(presented, der_of(expected_pem), "{offered} got {which}");
    }
}

/// Every secret a named provisioning reads is journaled, in the order it was read: each name's
/// cert and key in the order the names were given, then the default's. An `Access` entry that is
/// not written is a secret read that the audit trail has no record of.
#[test]
fn every_secret_a_named_provisioning_reads_is_journaled_in_order() {
    install_crypto_provider();
    let (_ca_pem, leaves) = ca_and_leaves(&[
        vec!["a.example".to_string()],
        vec!["default.example".to_string()],
    ]);
    let [(a_cert, a_key), (d_cert, d_key)] =
        <[(String, String); 2]>::try_from(leaves).unwrap_or_else(|_| panic!("two leaves"));

    let source = MapSource(
        [
            ("a.cert".to_string(), a_cert.into_bytes()),
            ("a.key".to_string(), a_key.into_bytes()),
            ("d.cert".to_string(), d_cert.into_bytes()),
            ("d.key".to_string(), d_key.into_bytes()),
        ]
        .into_iter()
        .collect(),
    );
    let journal = RecordingJournal::default();
    let sink = RecordingSink::default();

    provision_server_named(
        &source,
        &journal,
        &sink,
        &busbar_caps::TransportKeyToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel()),
        Slot {
            index: 4,
            fingerprint: "fixture",
        },
        &[NamedTlsLocations {
            sni: "a.example",
            cert: "a.cert",
            key: "a.key",
        }],
        &TlsLocations {
            cert: "d.cert",
            key: "d.key",
            client_ca: None,
        },
        DEFAULT_ALPN,
    )
    .unwrap();

    assert_eq!(
        *journal.0.lock().unwrap(),
        vec![
            ("a.cert".to_string(), AccessPurpose::Cert),
            ("a.key".to_string(), AccessPurpose::Key),
            ("d.cert".to_string(), AccessPurpose::Cert),
            ("d.key".to_string(), AccessPurpose::Key),
        ]
    );
}
