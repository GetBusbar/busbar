// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND MUTUAL-TLS LEG, AGAINST A PEER THAT ACTUALLY DEMANDS A CERTIFICATE.
//!
//! `pin.mechanism: mtls` has been spellable since the grammar was written and it could not work:
//! nothing in `agents:` named a client certificate, so busbar had nothing to present, and a peer
//! configured for mutual TLS refused every card fetch at the handshake. A mechanism that cannot
//! complete a connection is a claim, not a control.
//!
//! Every test here runs a REAL rustls handshake against a server built with a
//! [`rustls::server::WebPkiClientVerifier`] — the same verifier `crate::tls` installs on busbar's own
//! inbound listener when an operator sets `tls.client_ca`. That is deliberate: the peer in these
//! tests demands exactly what busbar demands, so "busbar can talk to an mTLS peer" is proven against
//! the same rule busbar enforces rather than against a lenient fixture.
//!
//! The server fixtures, the CA/leaf generator and the HTTP responder are `transport_tests`', reused
//! rather than copied. A second TLS harness would be a second thing that could stop matching
//! production — which is the note that file already makes about `transport_pin_tests`.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::transport_tests::{ca_and_leaf, http_response, read_request, url, HOST, LOOPBACK};
use super::*;
use crate::a2a::fetch::{FetchPolicy, Transport};

/// What each connection to the mTLS server did about its client certificate: `Ok(n)` when the
/// handshake completed and the peer presented `n` certificates, `Err(reason)` — the SERVER's own
/// rustls error — when it failed. Recorded so a refusal can be read as "the peer never
/// authenticated, and here is what the peer objected to" rather than inferred from a client-side
/// error string alone.
///
/// The reason is kept, not just the failure, because two refusals that both look like "handshake
/// failed" are different defects: "peer sent no certificates" means the client offered nothing, and
/// an "invalid peer certificate" means it offered SOMETHING the peer would not take — which is the
/// difference between a registration presenting no certificate and one borrowing another
/// registration's. Reading it off the server keeps it portable: the client-side text for the same
/// refusal is the OS socket's on Windows (`os error 10053`, the reset that discards the peer's
/// alert), not TLS's.
type ClientCerts = Arc<Mutex<Vec<Result<usize, String>>>>;

/// A real rustls server that REQUIRES a client certificate chaining to `client_ca_pem`.
///
/// Built with `WebPkiClientVerifier`, which is the same construction `crate::tls::build_server_config`
/// uses for busbar's own inbound mTLS. A client that presents nothing is refused during the
/// handshake and never reaches the HTTP layer at all.
pub(super) fn spawn_mtls(
    server_cert_pem: &str,
    server_key_pem: &str,
    client_ca_pem: &str,
    body: String,
) -> (SocketAddr, ClientCerts) {
    crate::tls::install_crypto_provider();
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("server cert PEM");
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes())
        .expect("server key PEM");
    let mut roots = rustls::RootCertStore::empty();
    for ca in rustls_pki_types::CertificateDer::pem_slice_iter(client_ca_pem.as_bytes()) {
        roots
            .add(ca.expect("client CA PEM"))
            .expect("add client CA");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .expect("server config"),
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let seen: ClientCerts = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            if let Err(e) = conn.complete_io(&mut stream) {
                // The server's OWN reason for refusing, as rustls words it.
                let reason = conn
                    .process_new_packets()
                    .err()
                    .map_or_else(|| e.to_string(), |te| te.to_string());
                recorder.lock().expect("record").push(Err(reason));
                continue;
            }
            recorder
                .lock()
                .expect("record")
                .push(Ok(conn.peer_certificates().map_or(0, <[_]>::len)));
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut reader = std::io::BufReader::new(&mut tls);
            let _ = read_request(&mut reader);
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let _ = tls.write_all(&http_response(200, "OK", &[], &body));
            let _ = tls.flush();
        }
    });
    (addr, seen)
}

/// The server thread records after its own handshake attempt returns; poll rather than sleep a fixed
/// amount, so the assertion is neither flaky nor slow. Mirrors `transport_tests::wait_for_sni`.
pub(super) fn wait_for_conns(seen: &ClientCerts) -> Vec<Result<usize, String>> {
    wait_for_conns_len(seen, 1)
}

/// [`wait_for_conns`] for a peer that takes SEVERAL connections in a test: wait until `n` handshake
/// attempts have been recorded, so the assertion reads a settled sequence rather than a prefix.
fn wait_for_conns_len(seen: &ClientCerts, n: usize) -> Vec<Result<usize, String>> {
    for _ in 0..200 {
        let got = seen.lock().expect("conns").clone();
        if got.len() >= n {
            return got;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    seen.lock().expect("conns").clone()
}

const CARD: &str = r#"{"protocolVersion":"0.3.0","name":"planner"}"#;

/// Build a client identity THE WAY BOOT DOES: write the PEM where a `file:` secret reference can
/// point at it, spell the registration the operator would spell, and run the real
/// [`resolve_client_identities`] over it.
///
/// A test that handed `ReqwestTransport` a `reqwest::Identity` it built itself would prove the
/// transport presents a certificate and say nothing about whether the GRAMMAR can name one — which
/// is the half of this defect that lived in `config.rs`.
pub(super) fn identity_from_config(cert_pem: &str, key_pem: &str) -> reqwest::Identity {
    // A monotonic counter, not a clock read: two tests can read the same nanosecond, and a
    // colliding path means one test reads a file another is still writing.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-a2a-mtls-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let cert_path = dir.join("client.crt");
    let key_path = dir.join("client.key");
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");

    let def: crate::a2a::config::AgentDefCfg = serde_yaml::from_str(&format!(
        "url: https://{HOST}/agent\n\
         pin: {{ mechanism: mtls, key: \"sha256/x\" }}\n\
         client_identity:\n  cert: {{ file: {} }}\n  key: {{ file: {} }}\n",
        cert_path.display(),
        key_path.display()
    ))
    .expect("the registration an operator would write");
    let mut cfg = crate::a2a::config::AgentsCfg::default();
    cfg.agents.insert("planner".to_string(), def);

    let identities = crate::a2a::transport::resolve_client_identities(
        &cfg,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the operator's cert and key resolve into a client identity");
    identities
        .get("planner")
        .expect("an identity for the registration that named one")
        .clone()
}

/// THE DEFECT, WRITTEN AS A TEST: a peer that demands a client certificate refuses busbar.
///
/// This is the state of the tree before the `client_identity:` grammar existed, and it stays here
/// afterwards as the negative half: a registration that names NO client identity still gets refused
/// by an mTLS peer, which is the honest outcome and not a silent downgrade to a one-way handshake.
#[test]
fn an_mtls_peer_refuses_a_card_fetch_that_presents_no_client_certificate() {
    let (server_ca, server_leaf, server_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (client_ca, _client_leaf, _client_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (addr, seen) = spawn_mtls(&server_leaf, &server_key, &client_ca, CARD.to_string());

    let policy = FetchPolicy::default();
    let err = ReqwestTransport::new(&policy)
        .trusting_root(server_ca.as_bytes())
        .get(
            &url("https", addr.port(), "/.well-known/agent-card.json"),
            LOOPBACK,
        )
        .expect_err(
            "a peer that demands a client certificate must not serve a card to a client \
                     that has none",
        );

    let seen = wait_for_conns(&seen);
    let [Err(reason)] = seen.as_slice() else {
        panic!("the refusal must be the PEER's, at the handshake: {seen:?} (client saw: {err})");
    };
    assert!(
        reason.contains("no certificates"),
        "and the peer's objection must be that nothing was presented: {reason}"
    );
}

/// THE FIX: the same peer, the same socket, the same CA — and a client identity to present.
#[test]
fn an_mtls_peer_accepts_the_card_fetch_when_the_registration_names_a_client_identity() {
    let (server_ca, server_leaf, server_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (client_ca, client_leaf, client_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (addr, seen) = spawn_mtls(&server_leaf, &server_key, &client_ca, CARD.to_string());

    // The identity is built the way the boot path builds it: the operator's two `SecretRef`s
    // resolved to PEM and handed to the TLS stack as one buffer. Here the references are `file:`
    // ones over a temporary directory, so this exercises `resolve_client_identities` itself rather
    // than a shortcut past it.
    let identity = identity_from_config(&client_leaf, &client_key);

    let policy = FetchPolicy::default();
    let resp = ReqwestTransport::new(&policy)
        .trusting_root(server_ca.as_bytes())
        .presenting(identity)
        .get(
            &url("https", addr.port(), "/.well-known/agent-card.json"),
            LOOPBACK,
        )
        .expect("the peer demands a client certificate and the registration names one");

    assert_eq!(resp.status, 200);
    assert!(String::from_utf8(resp.body)
        .expect("utf-8")
        .contains("planner"));
    assert_eq!(
        wait_for_conns(&seen),
        vec![Ok(1)],
        "the peer must have completed the handshake against busbar's own certificate"
    );
    let _ = (client_leaf, client_key);
}

/// THE STRUCTURAL FIX, PROVEN AT THE SOCKET: two registrations, two client certificates, and
/// NEITHER IS PRESENTED TO THE OTHER'S PEER.
///
/// This is the assertion the old shape could not have satisfied at any price. `sweep` held ONE
/// transport for the whole plane, so whatever identity it carried went to every endpoint — an
/// operator who gave busbar one vendor's client certificate would have had busbar offer it to every
/// other vendor as well. Here the bundle is the one the re-verification job builds, and each hop is made
/// with the transport `for_agent` hands out.
///
/// The two peers demand certificates from DIFFERENT CAs and are otherwise identical — same server
/// certificate, same trusted root on the client, same loopback. So the only thing that can decide
/// whether a hop succeeds is WHICH CLIENT CERTIFICATE IT PRESENTED.
#[test]
fn each_registration_presents_its_own_certificate_and_not_another_registrations() {
    let (server_ca, server_leaf, server_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (planner_ca, planner_leaf, planner_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (payments_ca, payments_leaf, payments_key) =
        ca_and_leaf(vec!["busbar.example".to_string()]);
    let (planner_peer, planner_seen) =
        spawn_mtls(&server_leaf, &server_key, &planner_ca, CARD.to_string());
    let (payments_peer, payments_seen) =
        spawn_mtls(&server_leaf, &server_key, &payments_ca, CARD.to_string());
    let planner_url = url("https", planner_peer.port(), "/.well-known/agent-card.json");
    let payments_url = url(
        "https",
        payments_peer.port(),
        "/.well-known/agent-card.json",
    );

    let mut identities = crate::a2a::transport::ClientIdentities::new();
    identities.insert(
        "planner".to_string(),
        identity_from_config(&planner_leaf, &planner_key),
    );
    identities.insert(
        "payments".to_string(),
        identity_from_config(&payments_leaf, &payments_key),
    );
    // THE PRODUCTION BUNDLE, built exactly as the re-verification job builds it, plus the one test
    // root that makes the peers' server certificates acceptable.
    let live = LiveCardFetch::presenting(FetchPolicy::default(), &identities)
        .trusting_root(server_ca.as_bytes());

    // EACH AGENT AT ITS OWN PEER: accepted.
    for (agent, at) in [("planner", &planner_url), ("payments", &payments_url)] {
        let resp = live
            .for_agent(agent)
            .get(at, LOOPBACK)
            .expect("a registration's own certificate is accepted by its own peer");
        assert_eq!(resp.status, 200);
    }

    // EACH AGENT AT THE OTHER'S PEER: refused, by the peer, on the certificate.
    for (agent, at) in [("planner", &payments_url), ("payments", &planner_url)] {
        let _err = live
            .for_agent(agent)
            .get(at, LOOPBACK)
            .expect_err("a registration's certificate must not authenticate at another's peer");
    }

    // AND A REGISTRATION THAT NAMED NO IDENTITY presents none — not another agent's. Against an
    // mTLS peer that is a refusal, which is the honest outcome the first test in this file pins.
    let _err = live
        .for_agent("an-agent-that-named-no-identity")
        .get(&planner_url, LOOPBACK)
        .expect_err("no identity means no certificate to present, and an mTLS peer refuses that");

    // THE REFUSALS, READ AT THE PEER RATHER THAN OFF A CLIENT-SIDE ERROR STRING — which is what
    // `ClientCerts` exists for, and what the first test in this file already does.
    //
    // The three cross hops used to be checked by matching "alert"/"certificate"/"CertificateRequired"
    // in the client's error. That text is the OS socket's as often as it is TLS's: on Windows the
    // peer's fatal alert is discarded by the reset that follows it, and the client reports
    // "An established connection was aborted by the software in your host machine. (os error 10053)"
    // for a refusal that did happen exactly as intended (CI, `windows build · test`). The peer's own
    // record is both portable and a STRONGER claim, because it carries the peer's own reason: a
    // foreign certificate is refused as an invalid one, and the registration that named no identity
    // is refused for presenting NOTHING — which is what rules out its having borrowed a certificate
    // from a registration that had one. (Presenting planner's own cert to planner's peer would have
    // succeeded outright; presenting payments' would have been refused too, but as an invalid
    // certificate, not as an absent one. Only the reason separates those.)
    let planner_conns = wait_for_conns_len(&planner_seen, 3);
    let [Ok(1), Err(foreign), Err(none_at_all)] = planner_conns.as_slice() else {
        panic!(
            "planner's peer: its own registration authenticates and the other two do not: \
             {planner_conns:?}"
        );
    };
    assert!(
        foreign.contains("invalid peer certificate"),
        "payments' certificate reaches planner's peer and is rejected as a certificate: {foreign}"
    );
    assert!(
        none_at_all.contains("no certificates"),
        "the registration that named no identity presented NOTHING — it did not borrow another \
         registration's certificate: {none_at_all}"
    );

    let payments_conns = wait_for_conns_len(&payments_seen, 2);
    let [Ok(1), Err(foreign)] = payments_conns.as_slice() else {
        panic!(
            "payments' peer: its own registration authenticates and planner's does not: \
             {payments_conns:?}"
        );
    };
    assert!(
        foreign.contains("invalid peer certificate"),
        "planner's certificate reaches payments' peer and is rejected as a certificate: {foreign}"
    );
}
