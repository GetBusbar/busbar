// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests ported from `busbar-core::tls`'s test module, restricted to what this crate actually does
//! (resolve key material, journal the access, build a `ServerConfig`).
//!
//! NOT PORTED, and why: `busbar-core::tests::tls_tests` is mostly END-TO-END wire tests —
//! `tls_happy_path_trusted_client_gets_200`, `mtls_valid_client_cert_gets_200`, and their sibling
//! rejection cases — each of which boots a real `tokio::net::TcpListener`, drives
//! `busbar_core::tls::serve` (the hyper/axum accept-and-serve loop), and completes an actual HTTPS
//! round trip with a `reqwest` client. That loop, and the `AcceptBackoff` policy its
//! `accept_backoff_spins_only_on_per_connection_transients` test covers, are LISTENER concerns this
//! crate does not implement (see the crate doc): this crate resolves key material and builds the
//! `ServerConfig` a listener consumes, and stops there. Porting the wire tests here would have
//! required pulling `axum`, `hyper-util`, and a running multi-threaded `tokio` runtime into a crate
//! whose whole point is standing alone with `rustls` as its one real dependency.
//!
//! What IS ported: the cert/key/client-CA parsing and `ServerConfig` construction those wire tests
//! exercise indirectly, tested here directly and synchronously — the same assertions
//! (`with_single_cert`/`with_client_cert_verifier` succeed on a valid pair, ALPN is pinned to
//! `http/1.1`), reached without a socket.

use super::*;

fn gen_self_signed() -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    (cert.pem(), signing_key.serialize_pem())
}

fn gen_ca_and_leaf(cn_sans: Vec<String>) -> (String, String, String) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(cn_sans).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
    (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
}

/// A `SecretSource` over an in-memory map, standing in for a real secret plugin.
struct MapSource(std::collections::HashMap<&'static str, Vec<u8>>);
impl SecretSource for MapSource {
    fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
        self.0
            .get(location)
            .cloned()
            .ok_or_else(|| format!("no secret at {location}"))
    }
}

/// An `AccessJournal` that just records what it was told, for assertions.
#[derive(Default)]
struct RecordingJournal(std::sync::Mutex<Vec<(String, AccessPurpose)>>);
impl AccessJournal for RecordingJournal {
    fn record_access(&self, location: &str, purpose: AccessPurpose) {
        self.0.lock().unwrap().push((location.to_string(), purpose));
    }
}

/// A valid self-signed cert/key pair resolves and builds a server-only `ServerConfig`, with ALPN
/// pinned to `http/1.1` — the same construction `tls_happy_path_trusted_client_gets_200` drives end
/// to end, checked here at the `ServerConfig` boundary instead of over a socket.
#[test]
fn resolves_and_builds_server_only_config_for_valid_pair() {
    install_crypto_provider();
    let (cert_pem, key_pem) = gen_self_signed();
    let source = MapSource(
        [
            ("cert", cert_pem.into_bytes()),
            ("key", key_pem.into_bytes()),
        ]
        .into_iter()
        .collect(),
    );
    let journal = RecordingJournal::default();

    let material = resolve_tls_material(&source, &journal, "cert", "key", None).unwrap();
    let config = build_server_config(&material).unwrap();
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);

    let recorded = journal.0.lock().unwrap();
    assert_eq!(
        *recorded,
        vec![
            ("cert".to_string(), AccessPurpose::Cert),
            ("key".to_string(), AccessPurpose::Key),
        ]
    );
}

/// With a client CA configured, resolution journals a third `Access` entry and the resulting
/// config installs a client-cert verifier — the construction
/// `mtls_valid_client_cert_gets_200`/`mtls_missing_client_cert_gets_...` drive end to end.
#[test]
fn resolves_and_builds_mtls_config_when_client_ca_present() {
    install_crypto_provider();
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, _leaf_pem, _leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);
    let source = MapSource(
        [
            ("cert", srv_cert_pem.into_bytes()),
            ("key", srv_key_pem.into_bytes()),
            ("ca", ca_pem.into_bytes()),
        ]
        .into_iter()
        .collect(),
    );
    let journal = RecordingJournal::default();

    let material = resolve_tls_material(&source, &journal, "cert", "key", Some("ca")).unwrap();
    assert!(material.client_ca_pem.is_some());
    let config = build_server_config(&material).unwrap();
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);

    let recorded = journal.0.lock().unwrap();
    assert_eq!(
        *recorded,
        vec![
            ("cert".to_string(), AccessPurpose::Cert),
            ("key".to_string(), AccessPurpose::Key),
            ("ca".to_string(), AccessPurpose::ClientCa),
        ]
    );
}

/// A cert/key pair that do not belong together is refused at `with_single_cert`, never silently
/// paired.
#[test]
fn mismatched_cert_and_key_pair_is_refused() {
    install_crypto_provider();
    let (cert_pem, _key_pem) = gen_self_signed();
    let (_other_cert_pem, other_key_pem) = gen_self_signed();
    let material = TlsMaterial {
        cert_pem: cert_pem.into_bytes(),
        key_pem: other_key_pem.into_bytes(),
        client_ca_pem: None,
    };
    assert!(build_server_config(&material).is_err());
}

/// An empty cert chain is refused with a clear message rather than an empty, silently-accepted
/// chain.
#[test]
fn empty_cert_chain_is_refused() {
    let material = TlsMaterial {
        cert_pem: b"not a pem cert".to_vec(),
        key_pem: b"not a pem key".to_vec(),
        client_ca_pem: None,
    };
    let err = build_server_config(&material).unwrap_err();
    assert!(err.contains("cert"), "{err}");
}

/// A `SecretSource` miss is surfaced with the location named, and the journal records nothing for
/// the secret that was never actually read.
#[test]
fn missing_secret_is_refused_and_not_journaled() {
    let source = MapSource(std::collections::HashMap::new());
    let journal = RecordingJournal::default();
    let err = match resolve_tls_material(&source, &journal, "cert", "key", None) {
        Err(e) => e,
        Ok(_) => panic!("expected a missing-secret refusal"),
    };
    assert!(err.contains("cert"), "{err}");
    assert!(journal.0.lock().unwrap().is_empty());
}

/// The opaque handle: `issue_handle` returns a handle whose `Debug` never shows key material (there
/// is none to show — it carries only the slot and the fingerprint), and equal slots compare equal.
#[test]
fn issue_handle_is_opaque_and_slot_addressed() {
    use busbar_caps::{KernelSeal, TransportKeyToken};
    let seal = KernelSeal::acquire_for_kernel();
    let a = issue_handle(&TransportKeyToken::mint(&seal), 7, "fp");
    let b = issue_handle(&TransportKeyToken::mint(&seal), 7, "fp");
    let c = issue_handle(&TransportKeyToken::mint(&seal), 8, "fp");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.slot(), 7);
    assert_eq!(a.fingerprint(), "fp");
    let debug = format!("{a:?}");
    assert!(debug.contains('7'));
    assert!(!debug.to_lowercase().contains("pem"));
    assert!(!debug.to_lowercase().contains("key-----"));
}

/// The handle a transport receives is the same type the unit issued. This is the whole of CG-19:
/// before it, the unit produced one `TransportKeyHandle` and every transport consumed a different
/// one, with nothing in the tree bridging them.
#[test]
fn the_handle_the_unit_issues_is_the_one_a_transport_consumes() {
    use busbar_caps::{KernelSeal, TransportKeyToken};
    let seal = KernelSeal::acquire_for_kernel();
    let issued = issue_handle(&TransportKeyToken::mint(&seal), 3, "fp");
    let consumed: &busbar_contract::TransportKeyHandle = &issued;
    assert_eq!(consumed.slot(), 3);
}
