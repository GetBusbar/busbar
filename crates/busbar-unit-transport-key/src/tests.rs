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
//!
//! One thing the wire tests proved cannot be left out with them, though: whether a config built for
//! mTLS actually REFUSES an anonymous client. That is decided inside rustls during the handshake and
//! is invisible to any assertion about the config itself, so it is checked here by driving a real
//! `ClientConnection` against a real `ServerConnection` over a pair of in-memory buffers — the whole
//! of the handshake, none of the socket, and no async runtime.

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

/// A `TlsConfigSink` that just keeps whatever it was handed, for reading a provisioned config back
/// out in a test — the same role `TlsTransport` plays in production, without pulling a transport
/// crate into this one's dependency graph.
#[derive(Default)]
struct RecordingSink {
    server: std::sync::Mutex<Option<Arc<ServerConfig>>>,
}
impl TlsConfigSink for RecordingSink {
    fn register_server_config(&self, _slot: u64, cfg: Arc<ServerConfig>) {
        *self.server.lock().unwrap() = Some(cfg);
    }
    fn register_client_config(&self, _slot: u64, _cfg: Arc<rustls::ClientConfig>) {}
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

/// With a client CA configured, resolution journals a third `Access` entry and the config builds —
/// the construction `mtls_valid_client_cert_gets_200`/`mtls_missing_client_cert_gets_...` drive end
/// to end.
///
/// This asserts the RESOLUTION half only: three access entries for three secrets read, in order.
/// What the verifier those bytes built then does to a client is
/// [`only_the_mtls_config_refuses_a_client_that_offers_no_certificate`]'s, because nothing readable
/// off a `ServerConfig` distinguishes a listener that demands a client certificate from one that
/// does not.
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

/// Drive a real rustls handshake against `config` with a client that offers NO certificate, over a
/// pair of in-memory buffers rather than a socket, and hand back what the server made of it.
///
/// The two connections are pumped by hand because that is the whole of what a listener's accept loop
/// contributes here — bytes from one side to the other — and the difference under test is decided
/// inside rustls before a single byte of application data exists. `server_ca_pem` is what the client
/// trusts the server's certificate under, so a failure that comes back is about the CLIENT's
/// certificate and not about the server's.
fn handshake_offering_no_client_certificate(
    config: ServerConfig,
    server_ca_pem: &str,
) -> Result<(), rustls::Error> {
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(server_ca_pem.as_bytes()) {
        roots.add(ca.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();

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
            return Ok(());
        }
    }
    panic!("the handshake neither completed nor failed");
}

/// The client-cert verifier is the DIFFERENCE a client CA makes, and the only way to see it is to
/// make a client try: the same certificate and key, offered to a client that presents nothing,
/// complete the handshake without a client CA configured and are refused with one.
///
/// Asserting the resolved material and the journal entries — which is all the test beside this one
/// does — asserts the setup this test supplied to itself. Replacing the verifier arm in
/// `build_server_config` with `with_no_client_auth()` leaves every one of those assertions true and
/// turns a listener an operator configured for mTLS into one that takes anonymous clients.
#[test]
fn only_the_mtls_config_refuses_a_client_that_offers_no_certificate() {
    install_crypto_provider();
    let (server_ca_pem, server_cert_pem, server_key_pem) =
        gen_ca_and_leaf(vec!["localhost".into()]);
    let (client_ca_pem, _client_leaf_pem, _client_key_pem) =
        gen_ca_and_leaf(vec!["busbar-client".into()]);
    let source = MapSource(
        [
            ("cert", server_cert_pem.into_bytes()),
            ("key", server_key_pem.into_bytes()),
            ("ca", client_ca_pem.into_bytes()),
        ]
        .into_iter()
        .collect(),
    );
    let journal = RecordingJournal::default();

    let server_only =
        build_server_config(&resolve_tls_material(&source, &journal, "cert", "key", None).unwrap())
            .unwrap();
    handshake_offering_no_client_certificate(server_only, &server_ca_pem)
        .expect("server-only TLS asks a client for nothing and completes");

    let mtls = build_server_config(
        &resolve_tls_material(&source, &journal, "cert", "key", Some("ca")).unwrap(),
    )
    .unwrap();
    let err = handshake_offering_no_client_certificate(mtls, &server_ca_pem)
        .expect_err("mTLS means the client MUST present a certificate");
    assert!(
        matches!(err, rustls::Error::NoCertificatesPresented),
        "the handshake failed for the wrong reason: {err:?}"
    );
}

/// A client CA that resolves to bytes with no certificate in it — an operator who pointed the
/// setting at the wrong file — is refused, not quietly turned into an empty root store.
///
/// An empty store would build a verifier that no client certificate can ever chain to, so the
/// listener would come up and then refuse every client, which reads as a client problem for as long
/// as it takes somebody to look at the CA bundle.
#[test]
fn a_client_ca_with_no_certificates_in_it_is_refused() {
    install_crypto_provider();
    let (cert_pem, key_pem) = gen_self_signed();
    let material = TlsMaterial {
        cert_pem: cert_pem.into_bytes(),
        key_pem: key_pem.clone().into_bytes(),
        // A PEM, and a real one — just not one with a certificate anywhere in it.
        client_ca_pem: Some(key_pem.into_bytes()),
    };
    let err = build_server_config(&material).unwrap_err();
    assert!(err.contains("client_ca"), "{err}");
    assert!(err.contains("no CA certificates"), "{err}");
}

/// `provision_server`'s advertised protocol list is the composition root's, not a literal buried
/// in this unit: a listener that declares `h2` gets exactly `[b"h2"]`, and one that declares
/// nothing — the default every existing caller still passes — gets exactly `[b"http/1.1"]`, byte
/// for byte the same as [`resolves_and_builds_server_only_config_for_valid_pair`] pins at
/// `build_server_config` directly.
#[test]
fn provisioning_carries_the_caller_declared_alpn_list() {
    install_crypto_provider();
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let token = TransportKeyToken::mint(&seal);

    for (alpn, want) in [
        (DEFAULT_ALPN, vec![b"http/1.1".to_vec()]),
        (&[b"h2".as_slice()][..], vec![b"h2".to_vec()]),
    ] {
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
        let sink = RecordingSink::default();

        provision_server(
            &source,
            &journal,
            &sink,
            &token,
            Slot {
                index: 0,
                fingerprint: "fixture",
            },
            &TlsLocations {
                cert: "cert",
                key: "key",
                client_ca: None,
            },
            alpn,
        )
        .unwrap();

        let cfg = sink.server.lock().unwrap().clone().unwrap();
        assert_eq!(cfg.alpn_protocols, want);
    }
}

/// DNS names are case-insensitive, and the two sides of this lookup do not agree on a spelling by
/// themselves: rustls lower-cases the name a `ClientHello` carried before a resolver ever sees it,
/// while an operator writes the name in the config however they please. An entry provisioned as
/// `Example.COM` that no client can ever select is a listener quietly serving the default
/// certificate on a name it was explicitly given one for.
#[test]
fn a_named_entry_is_selected_whatever_case_either_side_spelled_it() {
    install_crypto_provider();
    let named = a_certified_key();
    let default = a_certified_key();
    let resolver = SniCertResolver::build(
        vec![("Example.COM", Arc::clone(&named))],
        Arc::clone(&default),
    )
    .unwrap();

    for offered in ["example.com", "EXAMPLE.com", "Example.COM"] {
        assert!(
            Arc::ptr_eq(&resolver.pick(Some(offered)), &named),
            "the name's own certificate, not the default, for {offered}"
        );
    }
    // An unrelated name and an absent one both still fall through to the default.
    assert!(Arc::ptr_eq(&resolver.pick(Some("other.test")), &default));
    assert!(Arc::ptr_eq(&resolver.pick(None), &default));
}

/// Two entries that differ only in case are one name, and the deployment has said two different
/// things about which certificate it carries. Silently keeping whichever was inserted last picks
/// one of them at random from the operator's point of view.
#[test]
fn two_names_that_differ_only_in_case_are_refused() {
    install_crypto_provider();
    let err = SniCertResolver::build(
        vec![
            ("example.com", a_certified_key()),
            ("EXAMPLE.com", a_certified_key()),
        ],
        a_certified_key(),
    )
    .unwrap_err();
    assert!(err.to_lowercase().contains("example.com"), "{err}");
}

/// A parsed certificate and key, for the resolver cells — which care only about which `Arc` comes
/// back, never what is in it.
fn a_certified_key() -> Arc<CertifiedKey> {
    let (cert_pem, key_pem) = gen_self_signed();
    certified_key(&TlsMaterial {
        cert_pem: cert_pem.into_bytes(),
        key_pem: key_pem.into_bytes(),
        client_ca_pem: None,
    })
    .unwrap()
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

/// The handle a transport receives is the same type the unit issued. That is the whole rule:
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
