// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAL, exercised against the mutations that actually happen.
//!
//! The conformance suite's `tampered-state` scenario does exactly one thing to the state busbar
//! minted: it appends the literal `-TAMPERED`. That mutation is the FIRST test below and it is
//! deliberately not generalised away, because `-` is a valid base64url character: a decoder
//! configured to tolerate trailing input would accept it, the scenario would go green, and the
//! property the scenario is named after would be absent. A test written only against a random blob
//! would not have caught that.
//!
//! Every other test here is a field of the payload changed one at a time, which is the only way to
//! show that each field is LOAD-BEARING rather than merely present.

use super::*;

const KEY: [u8; 32] = [7u8; 32];
const NOW: u64 = 1_700_000_000;

fn sealer() -> Sealer {
    Sealer::derive(&KEY)
}

fn state() -> AskState {
    AskState {
        principal: "vk_caller_a".to_string(),
        method: "tools/call".to_string(),
        capability: "test_thing".to_string(),
        args_digest: digest_arguments(&serde_json::json!({ "path": "/etc/hosts" })),
        generation: 4,
        round: 0,
        nonce: nonce().expect("entropy"),
        issued_at: NOW,
        ttl_secs: DEFAULT_TTL_SECS,
    }
}

/// The happy path, and the control without which every refusal below is equally consistent with a
/// seal that refuses everything.
#[test]
fn a_state_busbar_minted_opens_and_matches_the_request_it_was_minted_for() {
    let s = state();
    let blob = sealer().mint(&s);
    let opened = sealer().open(&blob, NOW).expect("busbar's own state opens");
    assert_eq!(opened, s);
    opened
        .matches(
            "vk_caller_a",
            "tools/call",
            "test_thing",
            &digest_arguments(&serde_json::json!({ "path": "/etc/hosts" })),
            4,
        )
        .expect("the request it was minted for");
}

/// THE SUITE'S EXACT MUTATION. `sep-2322-reject-tampered-state` sends
/// `r1Result.requestState + '-TAMPERED'` and requires a JSON-RPC error.
#[test]
fn the_conformance_suites_exact_tamper_is_refused() {
    let blob = sealer().mint(&state());
    assert_eq!(
        sealer().open(&format!("{blob}-TAMPERED"), NOW),
        Err(Rejected::BadSignature),
        "`-TAMPERED` is all base64url characters, so a lenient decoder accepts it"
    );
}

/// And the mutation in the other segment, which a suffix-only test would miss: rewriting the PAYLOAD
/// while keeping a valid-looking tag.
#[test]
fn a_rewritten_payload_is_refused_even_though_the_tag_is_untouched() {
    let mut s = state();
    let honest = sealer().mint(&s);
    let (_, tag) = honest.split_once('.').expect("two segments");
    // The caller promotes itself: same everything, different principal.
    s.principal = "vk_caller_b".to_string();
    let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&s).expect("serialises"));
    assert_eq!(
        sealer().open(&format!("{forged_payload}.{tag}"), NOW),
        Err(Rejected::BadSignature)
    );
}

/// Every single byte of the tag matters. A comparison that stopped at a prefix, or one that accepted
/// a short tag, would pass the two tests above and fail this one.
#[test]
fn a_tag_that_is_short_or_altered_in_any_single_position_is_refused() {
    let blob = sealer().mint(&state());
    let (payload, tag) = blob.split_once('.').expect("two segments");
    // A truncated tag is REFUSED, and which refusal it is depends on where it dies: a base64url
    // segment two characters short is not a whole number of bytes, so it fails the decode before it
    // reaches the MAC. The property under test is that it does not verify AS A PREFIX of the honest
    // tag, and both arms are that; pinning one would be asserting the order of two checks rather
    // than the thing they jointly guarantee.
    assert!(
        matches!(
            sealer().open(&format!("{payload}.{}", &tag[..tag.len() - 2]), NOW),
            Err(Rejected::BadSignature) | Err(Rejected::Malformed)
        ),
        "a truncated tag must not verify as a prefix"
    );
    // And one that IS a whole number of bytes, just fewer of them: this one does reach the MAC, so
    // it is the case that proves the comparison rejects on length rather than comparing a prefix.
    let short = URL_SAFE_NO_PAD.encode([0u8; 16]);
    assert_eq!(
        sealer().open(&format!("{payload}.{short}"), NOW),
        Err(Rejected::BadSignature)
    );
    let mut altered: Vec<char> = tag.chars().collect();
    altered[0] = if altered[0] == 'A' { 'B' } else { 'A' };
    let altered: String = altered.into_iter().collect();
    assert_eq!(
        sealer().open(&format!("{payload}.{altered}"), NOW),
        Err(Rejected::BadSignature)
    );
}

/// A DIFFERENT DEPLOYMENT'S key does not open this deployment's state. The fleet shares one signing
/// key by design; two fleets do not.
#[test]
fn another_deployments_seal_does_not_open_here() {
    let blob = Sealer::derive(&[9u8; 32]).mint(&state());
    assert_eq!(sealer().open(&blob, NOW), Err(Rejected::BadSignature));
}

/// `mrtr.mdx:236` — the short expiry, rejected after it lapses. Checked at the boundary in both
/// directions, because an off-by-one here is a replay window that is one TTL wider than declared.
#[test]
fn state_is_refused_the_moment_it_lapses() {
    let s = state();
    let blob = sealer().mint(&s);
    assert!(
        sealer().open(&blob, NOW + DEFAULT_TTL_SECS).is_ok(),
        "still valid at exactly the expiry instant"
    );
    assert_eq!(
        sealer().open(&blob, NOW + DEFAULT_TTL_SECS + 1),
        Err(Rejected::Expired)
    );
}

/// THE CROSS-CALLER REPLAY `mrtr.mdx:235` NAMES. Caller A's state, presented by caller B, with a
/// perfectly valid signature, must not be redeemed. This is the property a relayer cannot have at
/// all, because the only principal an upstream can bind to is busbar.
#[test]
fn caller_a_state_cannot_be_redeemed_by_caller_b() {
    let blob = sealer().mint(&state());
    let opened = sealer().open(&blob, NOW).expect("the signature is honest");
    assert_eq!(
        opened.matches(
            "vk_caller_b",
            "tools/call",
            "test_thing",
            &digest_arguments(&serde_json::json!({ "path": "/etc/hosts" })),
            4,
        ),
        Err(Rejected::WrongPrincipal)
    );
}

/// `mrtr.mdx:237` — the originating request. Each of the three components is changed on its own, so
/// each is shown to be load-bearing rather than carried.
#[test]
fn state_cannot_be_spent_on_a_different_request_than_it_was_minted_for() {
    let blob = sealer().mint(&state());
    let opened = sealer().open(&blob, NOW).expect("honest");
    let honest_digest = digest_arguments(&serde_json::json!({ "path": "/etc/hosts" }));

    // A different METHOD: an ask issued on `tools/call` spent on `prompts/get`.
    assert_eq!(
        opened.matches(
            "vk_caller_a",
            "prompts/get",
            "test_thing",
            &honest_digest,
            4
        ),
        Err(Rejected::WrongRequest)
    );
    // A different CAPABILITY: one tool's ask spent on another tool.
    assert_eq!(
        opened.matches("vk_caller_a", "tools/call", "test_other", &honest_digest, 4),
        Err(Rejected::WrongRequest)
    );
    // Different ARGUMENTS: the ask was about `/etc/hosts`; the retry is about the private key.
    assert_eq!(
        opened.matches(
            "vk_caller_a",
            "tools/call",
            "test_thing",
            &digest_arguments(&serde_json::json!({ "path": "/root/.ssh/id_ed25519" })),
            4,
        ),
        Err(Rejected::WrongRequest)
    );
}

/// The binding the specification does NOT ask for and busbar can give anyway: state minted under an
/// approval that has since been withdrawn does not complete the call the operator withdrew.
#[test]
fn state_minted_under_a_stale_catalogue_generation_is_refused() {
    let blob = sealer().mint(&state());
    let opened = sealer().open(&blob, NOW).expect("honest");
    assert_eq!(
        opened.matches(
            "vk_caller_a",
            "tools/call",
            "test_thing",
            &digest_arguments(&serde_json::json!({ "path": "/etc/hosts" })),
            5,
        ),
        Err(Rejected::WrongGeneration)
    );
}

/// THE `multi-round` REQUIREMENT, which is a requirement about the SEAL and not about the loop:
/// `sep-2322-multi-round-r2` fails unless `r2.requestState !== r1.requestState`. A deterministic
/// seal over an identical payload produces an identical string and can never satisfy it.
#[test]
fn two_mints_of_the_same_logical_ask_differ() {
    let s = sealer();
    let mut a = state();
    a.nonce = nonce().expect("entropy");
    let mut b = a.clone();
    b.nonce = nonce().expect("entropy");
    assert_ne!(a.nonce, b.nonce, "the nonce is what makes the seals differ");
    assert_ne!(s.mint(&a), s.mint(&b));
    // And the round index moves too, so even a nonce collision would not produce equal states.
    let mut r1 = a.clone();
    r1.round = 1;
    assert_ne!(s.mint(&a), s.mint(&r1));
}

/// Malformed input is refused rather than panicking. A `requestState` is attacker-controlled by
/// definition (`mrtr.mdx:232`), so every one of these arrives eventually.
#[test]
fn malformed_state_is_refused_and_never_panics() {
    for blob in [
        "",
        "no-dot-at-all",
        ".",
        "..",
        "not!base64.not!base64",
        "AAAA.AAAA",
        // A valid payload with no tag at all.
        "eyJwIjoieCJ9.",
    ] {
        let got = sealer().open(blob, NOW);
        assert!(
            matches!(got, Err(Rejected::Malformed) | Err(Rejected::BadSignature)),
            "`{blob}` must be refused, got {got:?}"
        );
    }
}

/// The digest is over the VALUE, not the byte order the caller happened to send. Two equal argument
/// objects written in different key orders are the same request and must digest the same, or a
/// caller re-serialising its own retry would be told its state was for a different request.
#[test]
fn the_argument_digest_is_key_order_independent_and_value_sensitive() {
    let a: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).expect("json");
    let b: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).expect("json");
    assert_eq!(digest_arguments(&a), digest_arguments(&b));
    let c: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":3}"#).expect("json");
    assert_ne!(digest_arguments(&a), digest_arguments(&c));
}

/// Every refusal arm has an audit word, and they are DISTINCT — a shared word would make the audit
/// trail unable to tell a lapsed state from a forged one, which are very different events.
#[test]
fn every_refusal_arm_has_its_own_audit_word() {
    let arms = [
        Rejected::Malformed,
        Rejected::BadSignature,
        Rejected::Expired,
        Rejected::WrongPrincipal,
        Rejected::WrongRequest,
        Rejected::WrongGeneration,
    ];
    let words: std::collections::BTreeSet<&str> = arms.iter().map(|r| r.audit_reason()).collect();
    assert_eq!(words.len(), arms.len(), "audit words must be distinct");
}

/// The message a CALLER sees carries no oracle. `mrtr.mdx:269-272` names the client as the attacker
/// on this field, so "which check did I fail" is exactly what must not be answered.
#[test]
fn the_caller_facing_message_does_not_say_which_check_failed() {
    let arms = [
        Rejected::BadSignature,
        Rejected::Expired,
        Rejected::WrongPrincipal,
        Rejected::WrongRequest,
        Rejected::WrongGeneration,
    ];
    let messages: std::collections::BTreeSet<String> = arms.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        messages.len(),
        1,
        "every arm must render the SAME caller-facing message: {messages:?}"
    );
    for r in arms {
        assert!(
            !r.to_string().contains(r.audit_reason()),
            "the audit word must not leak into the caller-facing message"
        );
    }
}
