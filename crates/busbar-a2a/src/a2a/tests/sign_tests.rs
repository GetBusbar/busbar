// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S CARD IS NOW THE THING EXTERNAL CALLERS PIN AGAINST.
//!
//! That sentence was a design claim the build did not make true: busbar demanded a signed,
//! out-of-band-rooted card from every agent it delegates to, dropped the vendor's signature when it
//! rewrote a card for serving (correctly — the document is no longer the one the vendor signed) and
//! published nothing in its place. A caller of busbar had exactly the trust root busbar refuses to
//! accept from anyone else: none.
//!
//! ## Every assertion here is made with the INBOUND verifier
//!
//! Nothing below re-implements a signature check. `jws::verify_card` is the function busbar points
//! at every vendor's card, and it is the function pointed at busbar's own here. A test that
//! verified with a bespoke checker would prove that the signer agrees with the test, which is the
//! one thing that does not matter — the two halves have to agree with EACH OTHER about what was
//! signed, down to the byte, or the first card containing a number in an unusual form silently
//! stops verifying at somebody else's gateway.

use crate::testkit::engine_boot::engine;
use crate::testkit::TestAppA2aExt;
use busbar_substrate::testkit::engine_kit_plus::EngineAppPlus;
use ed25519_dalek::{Verifier, VerifyingKey};
use serde_json::{json, Value};

use super::*;
use crate::a2a::jws::{self, IssuerKey, JwsError, B64URL};
use crate::a2a::serve::rewrite_card;
use busbar_substrate::governance::signing::{TokenSigner, DEFAULT_KID};

const BACKEND: &str = "https://internal-planner.corp.example/a2a";
const PUBLIC: &str = "https://gateway.example.com";

fn token_signer(seed: u8) -> TokenSigner {
    TokenSigner::from_secret_bytes(&[seed; 32], DEFAULT_KID)
}

/// A live app whose governance holds `token_signer(seed)` — the seam a `CardSigner` reaches its
/// host card-signing capability through. The card subkey is derived and used ENTIRELY host-side
/// (the governance registry's card-sign verb); the plane holds only the public issuer key, exactly
/// as it does now that the A2A plane is a separate crate. Every signature below is therefore
/// produced over the same `token_signer(seed)` the pre-re-seam `CardSigner::derived_from` used, so
/// the bytes are identical.
fn app_signed_by(seed: u8) -> std::sync::Arc<dyn EngineAppPlus> {
    let gov = engine()
        .governance(
            std::sync::Arc::new(busbar_store_memory::MemoryStore::new()),
            None,
            Some(token_signer(seed)),
        )
        .expect("a memory-store governance registry with a signing key constructs");
    // An a2a plane must exist for `card_signer` to reach the public issuer key off the plane's own
    // slot (where the fixture's build stashes it from governance, mirroring the `a2a_start` hook).
    // One unpinned registration is the minimal `agents:` that lowers a plane — the card-signing bytes
    // are over the served card, independent of which agents are registered.
    let def: crate::a2a::config::AgentDefCfg =
        serde_yaml::from_str("url: https://agent.example/a2a\npin: { mechanism: unpinned }\n")
            .expect("a minimal unpinned agent def parses");
    engine()
        .new_app_plus()
        .governance(gov)
        .agent_def("planner", def)
        .build()
}

fn backend_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "decomposes goals",
        "url": format!("{BACKEND}/agents/planner"),
        "supportedInterfaces": [{ "url": format!("{BACKEND}/rpc"), "protocolBinding": "JSONRPC" }],
        "skills": [{ "id": "plan", "name": "Plan", "description": "decompose a goal" }],
        "securitySchemes": { "vendorKey": { "type": "apiKey" } },
        // TWO MEMBERS THAT MAKE THE TWO SERIALIZERS DISAGREE, and they are here because the first
        // version of this fixture did not have them: with only flat ASCII strings under
        // already-sorted keys, `serde_json::to_string` and RFC 8785 produce identical bytes, so the
        // runtime assertion below passed against a signer that had rolled its own serializer. The
        // whole hazard is that the disagreement is invisible until a real card contains a number
        // (`1.0` canonicalises to `1`) or a character above the BMP (which sorts differently in
        // UTF-16 than in code-point order). So the fixture contains both.
        "x-vendor-weight": 1.0,
        "x-vendor-\u{1F680}": "supplementary-plane key",
        "x-vendor-\u{E000}": "private-use key",
        // A VENDOR SIGNATURE THAT CANNOT SURVIVE THE REWRITE. Present so the tests below are about
        // REPLACING a signature rather than about adding one to a document that had none.
        "signatures": [{ "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "AAAA" }]
    })
}

fn served_by(signer: &crate::a2a::sign::CardSigner<'_>) -> Value {
    rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", Some(signer)).expect("rewrite")
}

fn busbars_issuer_key(signer: &crate::a2a::sign::CardSigner<'_>) -> IssuerKey {
    IssuerKey::from_spki_base64(&signer.issuer_spki_base64())
        .expect("busbar's published key must parse under the verifier that consumes it")
}

// ══ THE SERVED CARD IS SIGNED, AND IT VERIFIES ═══════════════════════════════════════════════════

#[test]
fn a_served_card_carries_a_signature_that_verifies_against_busbars_published_key() {
    let app = app_signed_by(7);
    let host = std::sync::Arc::clone(&app).engine_host();
    let signer = card_signer(&host).expect("a deployment with a signing key has a card signer");
    let served = served_by(&signer);

    let verified = jws::verify_card(&served, &busbars_issuer_key(&signer))
        .expect("busbar's own card must verify under busbar's own published key");
    assert_eq!(verified.index, 0);
    assert_eq!(
        verified.kid.as_deref(),
        Some(signer.kid()),
        "the caller reads the kid off the card and must find the one busbar publishes under"
    );
    assert_eq!(
        signer.kid(),
        "busbar-a2a-card-k1",
        "the kid must not be the TOKEN kid: a caller comparing them has to be able to see that one \
         key does not sign both"
    );
}

#[test]
fn the_served_card_carries_busbars_signature_and_only_busbars() {
    let app = app_signed_by(7);
    let host = std::sync::Arc::clone(&app).engine_host();
    let signer = card_signer(&host).expect("a signing key means a card signer");
    let served = served_by(&signer);
    let signatures = served
        .get("signatures")
        .and_then(Value::as_array)
        .expect("the served card is signed");
    assert_eq!(
        signatures.len(),
        1,
        "the vendor's signature cannot verify over a rewritten document. Carrying it alongside \
         busbar's would publish a signature that fails, which is worse than publishing none: got \
         {signatures:?}"
    );
    assert_ne!(
        signatures[0].get("signature").and_then(Value::as_str),
        Some("AAAA"),
        "the vendor's signature value must be GONE, not merely reordered"
    );
}

// ══ ONE CHANGED BYTE BREAKS THE SIGNATURE ════════════════════════════════════════════════════════

#[test]
fn tampering_with_one_byte_of_the_served_document_breaks_verification() {
    let app = app_signed_by(7);
    let host = std::sync::Arc::clone(&app).engine_host();
    let signer = card_signer(&host).expect("a signing key means a card signer");
    let key = busbars_issuer_key(&signer);
    let served = served_by(&signer);
    jws::verify_card(&served, &key).expect("the untampered card verifies — the control");

    // ONE CHARACTER, in a member busbar does not even model on the read path. The fingerprint and
    // the signature are both taken over the document AS RECEIVED precisely so that this registers.
    let mut tampered = served.clone();
    let description = tampered["description"].as_str().expect("a description");
    tampered["description"] = Value::String(description.replacen('d', "D", 1));
    assert_ne!(
        tampered, served,
        "the tamper must actually change something"
    );
    assert_eq!(
        jws::verify_card(&tampered, &key),
        Err(JwsError::NoSignatureVerified),
        "one changed character must break the signature; a card whose bytes can move under a valid \
         signature is not pinned to anything"
    );

    // AND A MEMBER BUSBAR NEVER PARSES. The signing payload is the canonical WHOLE document minus
    // `signatures`, so an unmodelled member is covered too — which is the silent-rug-pull case.
    let mut extended = served.clone();
    extended
        .as_object_mut()
        .expect("object")
        .insert("x-vendor-extension".to_string(), json!({ "region": "eu" }));
    assert_eq!(
        jws::verify_card(&extended, &key),
        Err(JwsError::NoSignatureVerified),
        "a member busbar does not model is still part of what was signed"
    );

    // AND THE SIGNATURE ITSELF. A flipped byte in the signature is a forgery, not a near miss.
    let mut resigned = served.clone();
    let sig = resigned["signatures"][0]["signature"]
        .as_str()
        .expect("a signature");
    let mut raw = B64URL.decode(sig).expect("base64url");
    raw[0] ^= 0x01;
    resigned["signatures"][0]["signature"] = Value::String(B64URL.encode(&raw));
    assert_eq!(
        jws::verify_card(&resigned, &key),
        Err(JwsError::NoSignatureVerified)
    );
}

#[test]
fn a_card_signed_by_a_different_busbar_deployment_does_not_verify_here() {
    // Two deployments, two token secrets, two derived card keys. A caller that pinned one must not
    // accept the other, or the pin identifies "some busbar" rather than "this busbar".
    let ours_app = app_signed_by(7);
    let theirs_app = app_signed_by(9);
    let ours_host = std::sync::Arc::clone(&ours_app).engine_host();
    let theirs_host = std::sync::Arc::clone(&theirs_app).engine_host();
    let ours = card_signer(&ours_host).expect("a signing key means a card signer");
    let theirs = card_signer(&theirs_host).expect("a signing key means a card signer");
    assert_eq!(
        jws::verify_card(&served_by(&theirs), &busbars_issuer_key(&ours)),
        Err(JwsError::NoSignatureVerified)
    );
}

// ══ THE CANONICALISATION IS THE ONE THE INBOUND PATH USES ════════════════════════════════════════

#[test]
fn the_signature_covers_exactly_the_inbound_paths_signing_payload() {
    // THE RUNTIME HALF OF THE CLAIM. The signing input is reconstructed here from
    // `card::signing_payload` — the function the INBOUND verifier calls — and the signature is
    // checked against it with a bare ed25519 verify. If the signer had canonicalised differently,
    // this fails while `verify_card` might not, because `verify_card` would be using the signer's
    // idea of canonical too.
    let app = app_signed_by(7);
    let host = std::sync::Arc::clone(&app).engine_host();
    let signer = card_signer(&host).expect("a signing key means a card signer");
    let served = served_by(&signer);

    let protected_b64 = served["signatures"][0]["protected"]
        .as_str()
        .expect("a protected header");
    let payload_b64 = B64URL.encode(
        crate::a2a::card::signing_payload(&served)
            .expect("the INBOUND path's payload")
            .as_bytes(),
    );
    let signing_input = format!("{protected_b64}.{payload_b64}");

    let spki = base64::engine::general_purpose::STANDARD
        .decode(signer.issuer_spki_base64())
        .expect("SPKI base64");
    let raw: [u8; 32] = spki[12..].try_into().expect("32 key bytes");
    let key = VerifyingKey::from_bytes(&raw).expect("a verifying key");
    let sig_bytes: [u8; 64] = B64URL
        .decode(served["signatures"][0]["signature"].as_str().expect("sig"))
        .expect("base64url")
        .try_into()
        .expect("64 signature bytes");
    key.verify(
        signing_input.as_bytes(),
        &ed25519_dalek::Signature::from_bytes(&sig_bytes),
    )
    .expect(
        "the served signature must cover EXACTLY the bytes the inbound verifier will reconstruct",
    );
}

#[test]
fn there_is_exactly_one_canonicalizer_and_one_signing_payload_on_this_plane() {
    // THE SOURCE-LEVEL HALF, with a floor. Two canonicalizers disagree the first time either one is
    // fixed, and the disagreement is invisible until a real vendor's card contains a number, a
    // supplementary-plane character in an extension key, or a member busbar does not model. So the
    // ratchet is on the COUNT of definitions, not on a comment saying they are shared.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../busbar-a2a/src/a2a");
    let mut sources: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("the plane's source directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect();
    sources.sort();
    assert!(
        sources.len() >= 20,
        "the scan found {} source file(s), which cannot be right: a scan that discovers nothing \
         passes vacuously, which is worse than no scan at all",
        sources.len()
    );

    let mut canonicalizers = Vec::new();
    let mut payloads = Vec::new();
    let mut sign_uses_them = false;
    for path in &sources {
        let source = std::fs::read_to_string(path).expect("readable source");
        let code: String = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("fn canonicalize(") {
            canonicalizers.push(path.display().to_string());
        }
        if code.contains("fn signing_payload(") {
            payloads.push(path.display().to_string());
        }
        if path.file_name().is_some_and(|n| n == "sign.rs") {
            sign_uses_them =
                code.contains("signing_payload(card)") && code.contains("canonicalize(");
        }
    }

    assert_eq!(
        canonicalizers.len(),
        1,
        "exactly one canonicalizer may exist on this plane; found {canonicalizers:?}"
    );
    assert_eq!(
        payloads.len(),
        1,
        "exactly one signing-payload definition may exist on this plane; found {payloads:?}"
    );
    assert!(
        sign_uses_them,
        "the SIGNING half must call the same `signing_payload` and the same `canonicalize` the \
         VERIFYING half calls, rather than serializing a document of its own"
    );
}

// ══ THE KEY: DERIVED, NOT REUSED ═════════════════════════════════════════════════════════════════

#[test]
fn the_card_key_is_not_the_token_key_and_cannot_be_walked_back_to_it() {
    let token = token_signer(7);
    let app = app_signed_by(7);
    let host = std::sync::Arc::clone(&app).engine_host();
    let card = card_signer(&host).expect("a signing key means a card signer");

    let card_spki = base64::engine::general_purpose::STANDARD
        .decode(card.issuer_spki_base64())
        .expect("SPKI");
    assert_ne!(
        &card_spki[12..],
        token.verifying_key().as_bytes().as_slice(),
        "THE WHOLE POINT. A served card is a VENDOR's document with busbar's endpoints substituted \
         in; signing it with the credential-minting key would make the card path a signing oracle \
         over upstream-chosen bytes, holding the key that mints working busbar credentials."
    );
    assert_ne!(
        card_spki[12..],
        token.secret_bytes(),
        "and the derived PUBLIC key must not be the token SECRET either"
    );
}

#[test]
fn the_derivation_is_deterministic_and_domain_separated() {
    let token = token_signer(7);
    let app = app_signed_by(7);
    assert_eq!(
        card_signer(&std::sync::Arc::clone(&app).engine_host())
            .unwrap()
            .issuer_spki_base64(),
        card_signer(&std::sync::Arc::clone(&app).engine_host())
            .unwrap()
            .issuer_spki_base64(),
        "a restart must serve cards under the same key, or every caller's pin breaks on a bounce"
    );
    assert_ne!(
        token.derived_subkey_seed(crate::a2a::sign::CARD_SIGNING_DOMAIN),
        token.derived_subkey_seed("some/other/purpose/v1"),
        "a second plane asking for a subkey must get a DIFFERENT one; a shared derivation is a \
         shared key wearing two names"
    );
    assert_ne!(
        token.derived_subkey_seed(crate::a2a::sign::CARD_SIGNING_DOMAIN),
        token.secret_bytes(),
        "the derivation must not hand back the root secret"
    );
}

#[test]
fn rotating_the_token_key_rotates_the_card_key_with_it() {
    // Stated as a property rather than left to be discovered: an operator rotating the signing key
    // is also rotating what external callers pinned, and they will see it as a kid whose signature
    // no longer verifies — which is the signal `approve-pin` exists to absorb.
    let before_app = app_signed_by(7);
    let after_app = app_signed_by(8);
    let before_host = std::sync::Arc::clone(&before_app).engine_host();
    let after_host = std::sync::Arc::clone(&after_app).engine_host();
    let before = card_signer(&before_host).expect("a signing key means a card signer");
    let after = card_signer(&after_host).expect("a signing key means a card signer");
    assert_ne!(before.issuer_spki_base64(), after.issuer_spki_base64());
    assert_eq!(
        jws::verify_card(&served_by(&after), &busbars_issuer_key(&before)),
        Err(JwsError::NoSignatureVerified)
    );
}

// ══ THE SEAM WHEN THERE IS NO KEY ════════════════════════════════════════════════════════════════

#[test]
fn a_deployment_with_no_signing_key_serves_an_unsigned_card_rather_than_no_card() {
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert!(
        served.get("signatures").is_none(),
        "with no key there is nothing to sign with, and a member spelled `signatures: []` would be \
         a signature-shaped thing that means nothing"
    );
    assert_eq!(
        served["url"],
        format!("{PUBLIC}/a2a/agents/planner"),
        "and the rewrite still happened: refusing to serve would turn `no governance` into `no \
         A2A`, which is a different decision than the one this seam makes"
    );
}

#[test]
fn the_signature_is_taken_over_the_document_that_is_actually_served() {
    // Signing before the rewrite would sign a document nobody sees. The check is that the SERVED
    // bytes — busbar's endpoints, busbar's security scheme, the backend nowhere in them — are the
    // ones under the signature.
    let app = app_signed_by(7);
    let host = std::sync::Arc::clone(&app).engine_host();
    let signer = card_signer(&host).expect("a signing key means a card signer");
    let served = served_by(&signer);
    let flattened = serde_json::to_string(&served).expect("serialize");
    assert!(
        !flattened.contains("internal-planner.corp.example"),
        "the backend must not appear in the served card at all: {flattened}"
    );
    assert_eq!(served["url"], format!("{PUBLIC}/a2a/agents/planner"));
    assert!(served["securitySchemes"]
        .get(crate::a2a::serve::INBOUND_SCHEME_NAME)
        .is_some());
    jws::verify_card(&served, &busbars_issuer_key(&signer))
        .expect("and THAT document is the one the signature covers");
}
