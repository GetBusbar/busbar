// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND MUTUAL-TLS LEG, AGAINST A PEER THAT ACTUALLY DEMANDS A CERTIFICATE.
//!
//! `pin.mechanism: mtls` has been spellable since the grammar was written and it could not work:
//! nothing in `agents:` named a client certificate, so busbar had nothing to present, and a peer
//! configured for mutual TLS refused every card fetch at the handshake. A mechanism that cannot
//! complete a connection is a claim, not a control.
//!
//! Every test here drives the production transport over a real socket to a far end that DEMANDS a
//! client certificate — and, where a test needs it, accepts only one particular certificate — behind
//! the kernel's TLS test double (`transport_tests::tls_double`). TLS lives only in the connector,
//! which this crate does not name, so what is proven here is this plane's side: which identity each
//! registration hands the engine, and that a peer's refusal comes back as no card. The same demands
//! made by a REAL `WebPkiClientVerifier` peer — refusing a hop that presents no certificate, refusing
//! a certificate from a CA it does not trust, completing against exactly the carried identity's leaf
//! — are proven where TLS lives, the connector's `tls/engine_tests.rs`
//! (`an_mtls_peer_refuses_a_hop_that_presents_no_client_certificate_for_that_reason`,
//! `an_mtls_peer_accepts_its_own_clients_certificate_and_refuses_a_foreign_one_as_invalid`,
//! `client_cert_fixture_accepts_only_the_carried_identity`).
//!
//! The far end, the CA/leaf generator and the HTTP responder are `transport_tests`', reused rather
//! than copied.

use crate::testkit::engine_boot::engine;
use std::net::SocketAddr;

use super::transport_tests::{
    ca_and_leaf, der, spawn_tls, tls_double, url, wait_for_hellos, DoublePeer, ObservedHellos,
    HOST, LOOPBACK,
};
use super::*;
use crate::a2a::fetch::{FetchPolicy, Transport};

/// A far end presenting `server_leaf_pem`'s certificate that REQUIRES a client certificate and
/// accepts only `client_leaf_pem`'s: a client that presents nothing, or presents another
/// certificate, is refused during the handshake and never reaches the HTTP layer at all. Each
/// connection's hello is recorded — the identity it carried, and whether the peer completed.
pub(super) fn spawn_mutual_tls(
    server_leaf_pem: &str,
    client_leaf_pem: &str,
    body: String,
) -> (SocketAddr, ObservedHellos) {
    spawn_tls(
        DoublePeer {
            leaf: Some(der(server_leaf_pem)),
            require_identity: true,
            accept_only: vec![der(client_leaf_pem)],
            ..DoublePeer::default()
        },
        body,
    )
}

const CARD: &str = r#"{"protocolVersion":"0.3.0","name":"planner"}"#;

/// Build a client identity THE WAY BOOT DOES: write the PEM where a `file:` secret reference can
/// point at it, spell the registration the operator would spell, and run the real
/// [`resolve_client_identities`] over it.
///
/// A test that handed `ReqwestTransport` a `ClientIdentity` it built itself would prove the
/// transport presents a certificate and say nothing about whether the GRAMMAR can name one — which
/// is the half of this defect that lived in `config.rs`.
pub(super) fn identity_from_config(
    cert_pem: &str,
    key_pem: &str,
) -> busbar_kernel::egress::engine::ClientIdentity {
    // A monotonic counter, not a clock read: two tests can read the same nanosecond, and a
    // colliding path means one test reads a file another is still writing.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-a2a-mutual-tls-{}-{}",
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

    // The identity's PEM walk is the TLS wrap's, so the wrap is installed first.
    tls_double();
    let identities = crate::a2a::transport::resolve_client_identities(
        &cfg,
        engine().builtin_secret_resolver().as_ref(),
    )
    .expect("the operator's cert and key resolve into a client identity");
    // THE PEM FILES HAVE DONE THEIR JOB. `resolve_client_identities` has read them into the returned
    // identity, so the fixture directory is dead from here — and leaving one behind per call meant
    // every local and CI run accumulated key material under the OS temp dir forever.
    let _ = std::fs::remove_dir_all(&dir);
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
fn a_mutual_tls_peer_refuses_a_card_fetch_that_presents_no_client_certificate() {
    let (server_ca, server_leaf, _server_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (_client_ca, client_leaf, _client_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (addr, seen) = spawn_mutual_tls(&server_leaf, &client_leaf, CARD.to_string());

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

    let seen = wait_for_hellos(&seen, 1);
    let [hello] = seen.as_slice() else {
        panic!("one hop, one handshake: {seen:?} (client saw: {err})");
    };
    assert!(
        !hello.ok && hello.client_leaf.is_none(),
        "the refusal must be the PEER's, at the handshake, and what it refused is a hop that \
         presented nothing: {hello:?} (client saw: {err})"
    );
}

/// THE FIX: the same peer, the same socket, the same CA — and a client identity to present.
#[test]
fn a_mutual_tls_peer_accepts_the_card_fetch_when_the_registration_names_a_client_identity() {
    let (server_ca, server_leaf, _server_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (_client_ca, client_leaf, client_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (addr, seen) = spawn_mutual_tls(&server_leaf, &client_leaf, CARD.to_string());

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
    assert_completed_with(&seen, &client_leaf);
}

/// THE VERB LAYER REACHES AN mTLS VENDOR TOO, and with THAT registration's certificate.
///
/// `connect` and `approve` go through [`LiveCardFetch::probe`], which used to hard-wire the
/// plane-wide, identity-free transport. So an operator running `connect` against an mTLS vendor got
/// the peer's `CertificateRequired` alert for a registration the sweep re-verifies every tick — one
/// plane with two answers about the same agent, decided by which path asked. The probe now asks
/// `for_agent` exactly as the sweep does.
#[test]
fn the_verb_layers_probe_fetches_a_mutual_tls_vendors_card_with_that_registrations_certificate() {
    use crate::a2a::verbs::CardSource;

    // AN IP-LITERAL ENDPOINT, because the probe carries the PRODUCTION resolver: `LiveCardFetch`
    // holds the real `TokioResolver` and there is deliberately no seam to hand it a fixture, so a
    // `.test` hostname would fail at the lookup and prove nothing about the transport. A literal is
    // judged by the same guard and skips the resolver entirely, which leaves the client certificate
    // as the only thing this test varies.
    let (server_ca, server_leaf, _server_key) = ca_and_leaf(vec!["127.0.0.1".to_string()]);
    let (_client_ca, client_leaf, client_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (addr, seen) = spawn_mutual_tls(&server_leaf, &client_leaf, CARD.to_string());

    let mut identities = crate::a2a::transport::ClientIdentities::new();
    identities.insert(
        "planner".to_string(),
        identity_from_config(&client_leaf, &client_key),
    );
    // `allow_private` on the POLICY, because the probe fetches under the bundle's policy and the
    // vendor here is on loopback. The guard is the real one either way.
    let live = LiveCardFetch::presenting(
        FetchPolicy {
            allow_private: true,
            ..FetchPolicy::default()
        },
        &identities,
    )
    .trusting_root(server_ca.as_bytes());

    let registration = crate::a2a::registry::AgentRegistration::registered(
        "planner",
        format!("https://127.0.0.1:{}/agent", addr.port()),
    );
    let pin_cfg = crate::a2a::config::AgentPinCfg {
        mechanism: crate::a2a::config::PinMechanism::MutualTls,
        key: Some("sha256/whatever-the-verify-tests-pin".to_string()),
        fingerprint: None,
    };

    let sighted = live
        .probe(&registration, &pin_cfg)
        .fetch_card("planner")
        .expect("the probe must present this registration's client certificate to its own vendor");
    assert!(
        sighted.document.get("name").is_some(),
        "the card came back whole: {:?}",
        sighted.document
    );
    assert!(
        sighted.client_identity_offered,
        "and the seam carries the mutual half onward, so the verb layer verifies the same card the \
         sweep does"
    );
    assert_completed_with(&seen, &client_leaf);
}

/// The far end completed exactly one handshake, against exactly `client_leaf_pem`'s certificate.
fn assert_completed_with(seen: &ObservedHellos, client_leaf_pem: &str) {
    let conns = wait_for_hellos(seen, 1);
    assert!(
        conns.len() == 1
            && conns[0].ok
            && conns[0].client_leaf.as_deref() == Some(der(client_leaf_pem).as_slice()),
        "the peer must have completed the handshake against exactly busbar's own certificate for \
         this registration: {conns:?}"
    );
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
/// The two peers each accept only their own registration's certificate and are otherwise identical
/// — same server certificate, same trusted root on the client, same loopback. So the only thing
/// that can decide whether a hop succeeds is WHICH CLIENT CERTIFICATE IT PRESENTED, and each peer
/// records which one that was. (A real peer refusing a certificate from a CA it does not trust, as
/// an invalid certificate, is the connector's
/// `an_mtls_peer_accepts_its_own_clients_certificate_and_refuses_a_foreign_one_as_invalid`.)
#[test]
fn each_registration_presents_its_own_certificate_and_not_another_registrations() {
    let (server_ca, server_leaf, _server_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (_planner_ca, planner_leaf, planner_key) = ca_and_leaf(vec!["busbar.example".to_string()]);
    let (_payments_ca, payments_leaf, payments_key) =
        ca_and_leaf(vec!["busbar.example".to_string()]);
    let (planner_peer, planner_seen) =
        spawn_mutual_tls(&server_leaf, &planner_leaf, CARD.to_string());
    let (payments_peer, payments_seen) =
        spawn_mutual_tls(&server_leaf, &payments_leaf, CARD.to_string());
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
        .expect_err(
            "no identity means no certificate to present, and a mutual-TLS peer refuses that",
        );

    // THE REFUSALS, READ AT THE PEER RATHER THAN OFF A CLIENT-SIDE ERROR STRING: each peer records
    // WHICH certificate every hop carried. Planner's own registration completes; payments' hop
    // carried payments' certificate (and was refused); the registration that named no identity
    // carried NOTHING — which is what rules out its having borrowed a certificate from a
    // registration that had one.
    let planner = der(&planner_leaf);
    let payments = der(&payments_leaf);
    let planner_conns = wait_for_hellos(&planner_seen, 3);
    let carried: Vec<(bool, Option<&[u8]>)> = planner_conns
        .iter()
        .map(|h| (h.ok, h.client_leaf.as_deref()))
        .collect();
    assert_eq!(
        carried,
        vec![
            (true, Some(planner.as_slice())),
            (false, Some(payments.as_slice())),
            (false, None),
        ],
        "planner's peer: its own registration authenticates, payments' certificate is refused, and \
         the registration that named no identity presented NOTHING"
    );

    let payments_conns = wait_for_hellos(&payments_seen, 2);
    let carried: Vec<(bool, Option<&[u8]>)> = payments_conns
        .iter()
        .map(|h| (h.ok, h.client_leaf.as_deref()))
        .collect();
    assert_eq!(
        carried,
        vec![
            (true, Some(payments.as_slice())),
            (false, Some(planner.as_slice()))
        ],
        "payments' peer: its own registration authenticates and planner's certificate is refused"
    );
}
