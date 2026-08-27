// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HONEST DEGRADE, MADE TRUE: `cert_spki` is a pin that is actually checked.
//!
//! An A2A card's signature is OPTIONAL, and the design's answer for a vendor that does not sign is
//! that the pin degrades to a transport-layer authenticity binding — a real network-layer root and
//! still not trust-on-first-use. Until this file existed that degrade was unavailable in the build:
//! nothing read a peer certificate, so `cert_spki` was REFUSED rather than recorded as satisfied.
//! Refusing was the right call — a fetch that succeeded is not a transport binding that was checked
//! — but the consequence was that an unsigned vendor had no root at all.
//!
//! ## Every test here runs a REAL TLS HANDSHAKE
//!
//! Not a fixture that hands back a certificate. The certificate under test is one a real `rustls`
//! server presented, over a real socket, to the real production client, and the pin is read off the
//! response that handshake produced. That matters because the entire safety argument is an
//! ORDERING: the certificate is observable only because the chain-and-name check already accepted
//! it. A fixture could not fail that ordering and so could not test it — and
//! [`no_path_in_this_crate_obtains_a_pin_by_switching_verification_off`] is the ratchet that keeps
//! the ordering from being "fixed" by the obvious shortcut.
//!
//! ## The pin is compared against a value computed OUTSIDE busbar
//!
//! `rcgen` encodes the leaf key as a bare SubjectPublicKeyInfo, quite separately from encoding the
//! certificate. Every expectation below is the SHA-256 of THAT, so a walk that read the wrong
//! member of the certificate produces a stable, plausible value that these tests still reject.

use base64::Engine as _;
use rcgen::{CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::transport_tests::{spawn_tls, url, HOST, LOOPBACK};
use super::*;
use crate::a2a::config::{AgentPinCfg, PinMechanism};
use crate::a2a::fetch::FetchPolicy;
use crate::a2a::pin::{approve_registration, ApproveError, CardPin};
use crate::a2a::verify::{verify_document, Handshake, VerifyRefusal};
use busbar_substrate::trust::{Approval, Observation, Sighting};

/// A CA, a leaf it signed, and — computed independently of the certificate — the pin that leaf's
/// key must produce.
struct Endpoint {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_pem: String,
    /// The expected `sha256/…` value, from `rcgen`'s own SPKI encoding of the leaf key. NOT from
    /// anything in `crate::a2a::spki`.
    expected_pin: String,
}

fn endpoint_for(sans: Vec<String>) -> Endpoint {
    let ca_kp = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).expect("self-signed ca");

    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().expect("leaf key");
    let leaf_cert = CertificateParams::new(sans)
        .expect("leaf params")
        .signed_by(&leaf_kp, &issuer)
        .expect("signed leaf");

    Endpoint {
        ca_pem: ca_cert.pem(),
        leaf_pem: leaf_cert.pem(),
        leaf_key_pem: leaf_kp.serialize_pem(),
        // COMPUTED FROM RCGEN'S OWN SPKI ENCODING, never from `crate::a2a::spki`. This is the
        // oracle; a test whose expectation came from the code under test would agree with a walk
        // that read the wrong member.
        expected_pin: format!(
            "sha256/{}",
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(leaf_kp.subject_public_key_info()))
        ),
    }
}

fn an_unsigned_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "skills": [{ "id": "plan", "name": "Plan", "description": "decompose a goal" }]
    })
}

/// FETCH THE CARD OVER A REAL HANDSHAKE and hand back what the connection proved.
///
/// The two steps the driver performs for one hop, against the production transport: the guard's
/// address, then the transport with it. Loopback is INTERNAL and the SSRF guard refuses it with no
/// override, so the hop is driven at the transport seam exactly as `transport_tests.rs` does —
/// adding a "test addresses are fine" escape hatch to the guard would be a hole in production to
/// make a test pass.
fn observed_pin_over_tls(endpoint: &Endpoint, card: &Value) -> (Value, Option<String>) {
    let (addr, _sni) = spawn_tls(
        &endpoint.leaf_pem,
        &endpoint.leaf_key_pem,
        serde_json::to_string(card).expect("serialize"),
    );
    let policy = FetchPolicy::default();
    let resp = ReqwestTransport::new(&policy)
        .trusting_root(endpoint.ca_pem.as_bytes())
        .get(
            &url("https", addr.port(), "/.well-known/agent-card.json"),
            LOOPBACK,
        )
        .expect("a certificate for the URL's hostname, from a trusted CA, must be accepted");
    assert_eq!(resp.status, 200);
    let document: Value = serde_json::from_slice(&resp.body).expect("a card");
    (document, resp.peer_spki)
}

/// A ONE-WAY HANDSHAKE: what the peer proved, and nothing of busbar's.
///
/// The shape every `cert_spki` and `unpinned` case here is about — those mechanisms are defined as
/// one-way bindings, so naming the mutual half `false` at each call site is the honest spelling
/// rather than a default that hides which question was asked.
fn one_way(peer_spki: Option<&str>) -> Handshake<'_> {
    Handshake {
        peer_spki,
        client_identity_offered: false,
    }
}

fn transport_pin_cfg(mechanism: PinMechanism, pin: &str) -> AgentPinCfg {
    AgentPinCfg {
        mechanism,
        key: Some(pin.to_string()),
        fingerprint: None,
    }
}

// ══ THE PIN IS READ, AND IT IS THE RIGHT ONE ═════════════════════════════════════════════════════

#[test]
fn the_pin_read_off_a_real_handshake_is_the_leaf_keys_own_spki_hash() {
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let (_card, observed) = observed_pin_over_tls(&endpoint, &an_unsigned_card());
    assert_eq!(
        observed.as_deref(),
        Some(endpoint.expected_pin.as_str()),
        "the pin must be the SHA-256 of the leaf key's SubjectPublicKeyInfo, computed by rcgen \
         rather than by us — a walk that read a neighbouring member would produce a stable, \
         plausible and wrong value that only an independent oracle rejects"
    );
}

// ══ A MISMATCHED CERTIFICATE IS REFUSED; THE PINNED ONE IS ACCEPTED ══════════════════════════════

#[test]
fn a_card_served_under_a_certificate_whose_spki_does_not_match_the_pin_is_refused() {
    // The card is fine. The CA is trusted. The name is right. The KEY is somebody else's, which is
    // precisely the case an unsigned card has no other way to notice.
    let serving = endpoint_for(vec![HOST.to_string()]);
    let elsewhere = endpoint_for(vec![HOST.to_string()]);
    assert_ne!(serving.expected_pin, elsewhere.expected_pin);

    let card = an_unsigned_card();
    let (document, observed) = observed_pin_over_tls(&serving, &card);
    let refusal = verify_document(
        &transport_pin_cfg(PinMechanism::CertSpki, &elsewhere.expected_pin),
        &document,
        one_way(observed.as_deref()),
    )
    .expect_err("a certificate that is not the pinned one must be refused");

    assert_eq!(
        refusal,
        VerifyRefusal::TransportPinMismatch {
            mechanism: "cert_spki",
            expected: elsewhere.expected_pin.clone(),
            observed: serving.expected_pin.clone(),
        }
    );
    // And the refusal NAMES BOTH VALUES, because an operator staring at it has to be able to tell
    // a vendor's key rotation from a look-alike endpoint, and cannot if it says only "mismatch".
    let rendered = refusal.to_string();
    assert!(
        rendered.contains(&serving.expected_pin) && rendered.contains(&elsewhere.expected_pin),
        "the refusal must show what was served and what was pinned: {rendered}"
    );
}

#[test]
fn a_card_served_under_the_pinned_certificate_is_accepted_and_pins_what_was_observed() {
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let card = an_unsigned_card();
    let (document, observed) = observed_pin_over_tls(&endpoint, &card);

    let verified = verify_document(
        &transport_pin_cfg(PinMechanism::CertSpki, &endpoint.expected_pin),
        &document,
        one_way(observed.as_deref()),
    )
    .expect("the pinned certificate must be accepted");

    assert_eq!(
        verified.pin,
        CardPin::CertSpki {
            spki: endpoint.expected_pin.clone(),
            card_fingerprint: crate::a2a::card::fingerprint(&document).expect("fingerprint"),
        },
        "the recorded pin carries BOTH halves: the identity the network established and the card \
         that identity served"
    );
    assert!(verified.observation.capabilities.contains_key("plan"));
}

#[test]
fn a_transport_pinned_registration_whose_hop_produced_no_certificate_is_refused() {
    // "We could not look" and "it matched" are the two answers a pin exists to keep apart. A
    // plaintext hop produces no certificate, and that is a refusal rather than a pass — otherwise
    // an upstream downgrades its own pin by serving the card over `http://`.
    let refusal = verify_document(
        &transport_pin_cfg(PinMechanism::CertSpki, "sha256/AAAA"),
        &an_unsigned_card(),
        one_way(None),
    )
    .expect_err("no observed certificate must refuse");
    assert_eq!(refusal, VerifyRefusal::TransportPinNotObserved("cert_spki"));
}

#[test]
fn a_transport_pinned_registration_with_no_pin_material_is_refused_rather_than_degraded() {
    let refusal = verify_document(
        &AgentPinCfg {
            mechanism: PinMechanism::CertSpki,
            key: None,
            fingerprint: None,
        },
        &an_unsigned_card(),
        one_way(Some("sha256/anything")),
    )
    .expect_err("a mechanism with nothing to compare against has no root");
    assert_eq!(refusal, VerifyRefusal::NoTransportPin("cert_spki"));
}

// ══ THE HONEST DEGRADE, END TO END ═══════════════════════════════════════════════════════════════

#[test]
fn an_unsigned_card_with_a_matching_cert_spki_pin_is_a_root_an_operator_can_approve() {
    // THE PROPERTY THE DESIGN CLAIMS AND THE BUILD DID NOT HAVE. An unsigned card is not
    // un-rootable: the certificate its endpoint proved possession of is a real network-layer root,
    // supplied out of band by the operator exactly as an issuer key is.
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let card = an_unsigned_card();
    assert!(
        card.get("signatures").is_none(),
        "this test is about an UNSIGNED card; a signed one would prove nothing about the degrade"
    );

    let (document, observed) = observed_pin_over_tls(&endpoint, &card);
    let verified = verify_document(
        &transport_pin_cfg(PinMechanism::CertSpki, &endpoint.expected_pin),
        &document,
        one_way(observed.as_deref()),
    )
    .expect("an unsigned card bound at the transport layer must verify");

    assert!(
        verified.pin.is_a_root(),
        "a transport binding is an authenticity root, and the approval gate asks exactly that"
    );

    let mut approval: Approval<CardPin> = Approval::registered();
    let sighting = Sighting::Seen(Observation {
        pin: Some(verified.pin.clone()),
        capabilities: verified.observation.capabilities.clone(),
    });
    approve_registration(&mut approval, &sighting, None)
        .expect("a transport-bound unsigned card is approvable, which is what the degrade MEANS");
    assert!(approval.serves(
        "plan",
        &crate::a2a::card::skill_digests(&document).expect("digests")["plan"]
    ));
}

#[test]
fn an_unsigned_card_with_no_pin_at_all_is_still_refused() {
    // THE OTHER HALF, and it must not move. The degrade is to a transport root, never to nothing:
    // an `unpinned` registration stays capturable and stays un-approvable, whatever certificate the
    // endpoint happened to present.
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let (document, observed) = observed_pin_over_tls(&endpoint, &an_unsigned_card());
    assert!(
        observed.is_some(),
        "the endpoint DID present a certificate; the refusal below must therefore be about the \
         absent PIN and not about an absent certificate"
    );

    let verified = verify_document(
        &AgentPinCfg {
            mechanism: PinMechanism::Unpinned,
            key: None,
            fingerprint: None,
        },
        &document,
        one_way(observed.as_deref()),
    )
    .expect("an unpinned registration is capturable");
    assert_eq!(verified.pin, CardPin::Unpinned);

    let mut approval: Approval<CardPin> = Approval::registered();
    let sighting = Sighting::Seen(Observation {
        pin: Some(CardPin::Unpinned),
        capabilities: verified.observation.capabilities.clone(),
    });
    assert_eq!(
        approve_registration(&mut approval, &sighting, None),
        Err(ApproveError::Unpinned),
        "a certificate that nobody pinned is not a root; observing one must not become one"
    );
}

// ══ MTLS: BOTH HALVES, EACH DECIDED BY THE HANDSHAKE THAT ACTUALLY HAPPENED ══════════════════════
//
// `mtls` is TWO claims about one connection: the endpoint that served the card is the one the
// operator pinned, and busbar proved who IT was to that endpoint. The first is `cert_spki`'s check,
// unchanged. The second is answered by the hop — did this registration's client certificate go into
// this handshake — and never by config alone, because a registration does not have to have come
// from a config file to reach the verifier.

/// A resolver that answers [`HOST`] with loopback, so a real server on 127.0.0.1 can stand in for
/// the vendor endpoint while the URL, the SNI and the certificate's name check stay the hostname's.
struct HostOnLoopback;
impl crate::a2a::fetch::Resolver for HostOnLoopback {
    fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        Ok(vec![LOOPBACK])
    }
}

/// The registration an operator writes for an mTLS vendor, pointed at a server on loopback.
///
/// `allow_private` is set on the record as well as on the policy below because that is what the
/// sweep lowers into the policy per registration; the two agreeing is the state a real deployment
/// is in.
fn an_mtls_registration(port: u16) -> crate::a2a::registry::AgentRegistration {
    let mut reg = crate::a2a::registry::AgentRegistration::registered(
        "planner",
        format!("https://{HOST}:{port}/agent"),
    );
    reg.allow_private = true;
    reg
}

/// The operator's own `allow_private:`, and nothing else moved. The vendor under test is on
/// loopback, which the guard refuses by default — teaching the guard that "test addresses are fine"
/// would be a hole in production opened to make a test pass.
fn loopback_policy() -> FetchPolicy {
    FetchPolicy {
        allow_private: true,
        ..FetchPolicy::default()
    }
}

/// THE PROPERTY THE BUILD DID NOT HAVE: an `mtls` registration that DOES present its client
/// certificate verifies.
///
/// The whole pass is driven — guard, hop, verification, ledger — against a peer built with
/// `WebPkiClientVerifier`, so the mutual half is a fact the peer enforced rather than a flag a
/// fixture set. Until this test existed, `verify_document` returned `MutualTlsNotPresented` for
/// EVERY `mtls` registration, justified by a comment claiming the `agents:` grammar named no client
/// certificate — which stopped being true when `client_identity:` landed.
#[test]
fn an_mtls_registration_that_presents_its_client_certificate_verifies() {
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let (client_ca, client_leaf, client_key) =
        super::transport_tests::ca_and_leaf(vec!["busbar.example".to_string()]);
    let card = an_unsigned_card();
    let (addr, seen) = super::transport_mtls_tests::spawn_mtls(
        &endpoint.leaf_pem,
        &endpoint.leaf_key_pem,
        &client_ca,
        serde_json::to_string(&card).expect("serialize"),
    );

    // THE IDENTITY THE OPERATOR NAMED, resolved the way boot resolves it, and carried by the
    // transport the sweep's `CardTransports` bundle hands out for THIS agent.
    let identity = super::transport_mtls_tests::identity_from_config(&client_leaf, &client_key);
    let policy = loopback_policy();
    let transport = ReqwestTransport::new(&policy)
        .trusting_root(endpoint.ca_pem.as_bytes())
        .presenting(identity);

    let mut registration = an_mtls_registration(addr.port());
    let pass = crate::a2a::verify::reverify_once(
        &mut registration,
        &transport_pin_cfg(PinMechanism::Mtls, &endpoint.expected_pin),
        &HostOnLoopback,
        &transport,
        &policy,
        1_000,
        true,
    );

    assert_eq!(
        pass.refusal, None,
        "the peer is the pinned one and busbar presented the certificate this registration names; \
         there is nothing left for `mtls` to refuse"
    );
    let Sighting::Seen(observation) = &registration.sighting else {
        panic!(
            "a verified card is a SEEN contact: {:?}",
            registration.sighting
        );
    };
    assert_eq!(
        observation.pin,
        Some(CardPin::Mtls {
            spki: endpoint.expected_pin.clone(),
            card_fingerprint: crate::a2a::card::fingerprint(&card).expect("fingerprint"),
        }),
        "the recorded pin is the mutual mechanism, carrying the identity the network established \
         and the card that identity served"
    );
    assert_eq!(
        super::transport_mtls_tests::wait_for_conns(&seen),
        vec![Ok(1)],
        "and the mutual half is the PEER's finding: it completed the handshake against exactly one \
         certificate of busbar's"
    );
}

/// THE OTHER HALF, AND IT MUST NOT MOVE: a hop that presented nothing is still refused.
///
/// The endpoint here is an ordinary TLS server that never asks for a client certificate, so the
/// handshake succeeds and the card arrives — which is precisely the case that must NOT be recorded
/// as `mtls` satisfied. An operator who chose `mtls` over `cert_spki` chose it for the mutual half,
/// and a one-way connection did not supply one.
#[test]
fn an_mtls_registration_whose_hop_presented_no_client_certificate_is_still_refused() {
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let card = an_unsigned_card();
    let (addr, _sni) = spawn_tls(
        &endpoint.leaf_pem,
        &endpoint.leaf_key_pem,
        serde_json::to_string(&card).expect("serialize"),
    );

    let policy = loopback_policy();
    // NO `.presenting(..)`: this is the registration that has nothing to offer.
    let transport = ReqwestTransport::new(&policy).trusting_root(endpoint.ca_pem.as_bytes());

    let mut registration = an_mtls_registration(addr.port());
    let pass = crate::a2a::verify::reverify_once(
        &mut registration,
        &transport_pin_cfg(PinMechanism::Mtls, &endpoint.expected_pin),
        &HostOnLoopback,
        &transport,
        &policy,
        1_000,
        true,
    );

    assert_eq!(
        pass.refusal,
        Some(VerifyRefusal::MutualTlsNotPresented),
        "the card arrived and the peer key matched; the MUTUAL half did not happen, and a fetch \
         that succeeded is not a mutual handshake that was made"
    );
    assert!(
        matches!(registration.sighting, Sighting::Failed(_)),
        "a refusal is a FAILED CONTACT, not an absence of one: {:?}",
        registration.sighting
    );
}

/// THE PEER HALF IS DECIDED FIRST, and it stays that way now that the mutual half can pass.
///
/// A look-alike endpoint is reported as a look-alike endpoint whatever busbar presented, because an
/// operator told "you have no client certificate" about an endpoint serving somebody else's key
/// would go and configure a certificate FOR THE IMPOSTOR. The mutual half is only ever the reason
/// once the peer is the one the operator pinned.
#[test]
fn an_mtls_look_alike_endpoint_is_named_as_one_rather_than_as_a_missing_certificate() {
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let elsewhere = endpoint_for(vec![HOST.to_string()]);
    let (document, observed) = observed_pin_over_tls(&endpoint, &an_unsigned_card());

    for offered in [true, false] {
        assert!(
            matches!(
                verify_document(
                    &transport_pin_cfg(PinMechanism::Mtls, &elsewhere.expected_pin),
                    &document,
                    Handshake {
                        peer_spki: observed.as_deref(),
                        client_identity_offered: offered,
                    },
                )
                .expect_err("a look-alike endpoint must be named as one"),
                VerifyRefusal::TransportPinMismatch { .. }
            ),
            "with client_identity_offered = {offered}, the endpoint that answered is still not the \
             one the operator supplied a root for"
        );
    }
}

// ══ THE ORDERING THAT MAKES ALL OF THIS SAFE ═════════════════════════════════════════════════════

#[test]
fn an_untrusted_certificate_produces_no_card_and_therefore_no_pin() {
    // THE SAFETY ARGUMENT, EXECUTED. The pin is readable only off a response, and a handshake the
    // chain check refused produces no response. So there is no arrangement of certificates under
    // which busbar records a transport pin for a connection it did not verify.
    let endpoint = endpoint_for(vec![HOST.to_string()]);
    let (addr, _sni) = spawn_tls(
        &endpoint.leaf_pem,
        &endpoint.leaf_key_pem,
        r#"{"name":"planner"}"#.to_string(),
    );
    let policy = FetchPolicy::default();
    // The same server, the same certificate, the same socket — and its CA is NOT trusted.
    let err = ReqwestTransport::new(&policy)
        .get(&url("https", addr.port(), "/card"), LOOPBACK)
        .expect_err("an untrusted certificate must not produce a response");
    assert!(
        err.contains("invalid peer certificate"),
        "the refusal must be the chain check: {err}"
    );
}

#[test]
fn no_path_in_this_crate_obtains_a_pin_by_switching_verification_off() {
    // THE RATCHET. The obvious way to make a certificate readable in an awkward test environment is
    // to stop verifying it, and a pin obtained that way is worse than no pin: it reads to an
    // operator as a network-layer root while accepting any certificate on the path. This scan is
    // over the WHOLE crate rather than this plane, because the shortcut is equally available to the
    // module next door and would be equally fatal there.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0usize;
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("readable directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            scanned += 1;
            // COMMENTS STRIPPED FIRST. The prose that explains why this shortcut is unavailable has
            // to be allowed to NAME it, or the only way to document the decision is to not document
            // it. This scan is about what the compiler sees.
            let source: String = std::fs::read_to_string(&path)
                .expect("readable source")
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            // SPELLED IN HALVES so the scan does not trip over its own needle list. A scan that had
            // to exclude the file it lives in would be a scan with an exception, and an exception is
            // where the next one goes.
            for needle in [
                concat!("danger_", "accept_invalid_certs"),
                concat!("danger_", "accept_invalid_hostnames"),
                concat!("danger", "ous()"),
            ] {
                assert!(
                    !source.contains(needle),
                    "{} names `{needle}`. The peer certificate is read off a handshake that ALREADY \
                     verified; a pin obtained by switching verification off is strictly worse than \
                     no pin at all.",
                    path.display()
                );
            }
        }
    }
    assert!(
        scanned >= 100,
        "the scan read {scanned} source file(s), which cannot be right: a scan that discovers \
         nothing passes vacuously, which is worse than no scan at all"
    );
}
