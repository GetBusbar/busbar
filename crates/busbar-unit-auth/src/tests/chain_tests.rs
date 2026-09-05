// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain walk: order, the open door, the fail-closed all-pass, and the keys arm.

use super::{entry, Canned, DefaultCacheability, OneKey};
use crate::cache::CredentialCache;
use crate::chain::{AuthChain, ChainVerdict, ResolvedKey};
use crate::module::AuthOutcome;
use crate::principal::Principal;

fn chain(entries: Vec<crate::chain::ChainEntry>, keys: bool) -> AuthChain {
    AuthChain::new(entries, keys)
}

#[test]
fn test_chain_identifies_with_module_and_principal() {
    let c = chain(
        vec![
            entry("first", Box::new(Canned::new("mod-a", AuthOutcome::Pass))),
            entry(
                "second",
                Box::new(Canned::new(
                    "mod-b",
                    AuthOutcome::Identify(Principal::from_id("alice")),
                )),
            ),
        ],
        false,
    );
    match c.run_chain(Some("cred")) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(
                module, "second",
                "the PROVIDER name identifies, not the module's own"
            );
            assert_eq!(principal.id, "alice");
        }
        other => panic!("expected an identification, got {other:?}"),
    }
}

#[test]
fn test_first_identify_wins_and_reject_stops_the_chain() {
    let later = Canned::new("later", AuthOutcome::Identify(Principal::from_id("bob")));
    let c = chain(
        vec![
            entry("rejecter", Box::new(Canned::new("r", AuthOutcome::Reject))),
            entry("later", Box::new(later)),
        ],
        false,
    );
    assert_eq!(
        c.run_chain(Some("cred")),
        ChainVerdict::Denied,
        "a rejection stops the chain; nothing after it is consulted"
    );
}

#[test]
fn test_nonempty_chain_fails_closed_on_all_pass() {
    let c = chain(
        vec![
            entry("a", Box::new(Canned::new("a", AuthOutcome::Pass))),
            entry("b", Box::new(Canned::new("b", AuthOutcome::Pass))),
        ],
        false,
    );
    assert_eq!(c.run_chain(Some("cred")), ChainVerdict::Denied);
}

#[test]
fn test_empty_chain_is_open_front_door() {
    let c = chain(Vec::new(), false);
    assert_eq!(c.run_chain(None), ChainVerdict::Open);
    assert_eq!(c.run_chain(Some("anything")), ChainVerdict::Open);
    assert!(c.is_open());
}

#[test]
fn test_keys_in_chain_sets_flag_not_module() {
    // The keys arm keeps the door SHUT even though the module list is empty.
    let c = chain(Vec::new(), true);
    assert!(
        !c.is_open(),
        "a chain naming the keys arm is not an open door"
    );
    assert!(c.has_no_modules());
    assert!(c.keys_in_chain());
    assert_eq!(
        c.run_chain(None),
        ChainVerdict::Denied,
        "the arm is the terminal authenticator and fails closed with nothing presented"
    );
}

#[test]
fn test_keys_arm_runs_after_every_module_and_identifies() {
    let verifier = OneKey {
        token: "vk-token",
        aud: None,
    };
    let c = chain(
        vec![entry(
            "plugin",
            Box::new(Canned::new("p", AuthOutcome::Pass)),
        )],
        true,
    );
    match c.run_chain_cached(Some("vk-token"), None, Some(&verifier), 1000, None) {
        ChainVerdict::Identified {
            module,
            principal,
            resolved,
        } => {
            assert_eq!(module, "keys");
            assert_eq!(principal.id, "vk_one");
            assert!(resolved.is_some(), "only an engine arm resolves a key");
        }
        other => panic!("expected the keys arm to identify, got {other:?}"),
    }
}

#[test]
fn test_audience_bound_token_is_rejected_on_the_data_plane() {
    // The verifier admits only a token minted for this audience; the residual plane expects none.
    let verifier = OneKey {
        token: "vk-token",
        aud: Some("https://mcp.example/"),
    };
    let c = chain(Vec::new(), true);
    assert_eq!(
        c.run_chain_cached(Some("vk-token"), None, Some(&verifier), 1000, None),
        ChainVerdict::Denied,
        "a token carrying an audience is inadmissible where none is expected"
    );
    assert!(matches!(
        c.run_chain_cached(
            Some("vk-token"),
            None,
            Some(&verifier),
            1000,
            Some("https://mcp.example/")
        ),
        ChainVerdict::Identified { .. }
    ));
}

#[test]
fn test_governance_rejects_empty_token_even_if_a_verifier_exists() {
    let verifier = OneKey {
        token: "",
        aud: None,
    };
    let c = chain(Vec::new(), true);
    assert_eq!(
        c.run_chain_cached(Some(""), None, Some(&verifier), 1000, None),
        ChainVerdict::Denied,
        "an empty credential is no credential"
    );
}

#[test]
fn test_keys_arm_with_no_verifier_denies() {
    let c = chain(Vec::new(), true);
    assert_eq!(
        c.run_chain_cached(Some("vk-token"), None, None, 1000, None),
        ChainVerdict::Denied
    );
}

#[test]
fn test_1_5_2_keys_arm_is_cache_exempt() {
    let cache = CredentialCache::new(super::test_digest);
    let verifier = OneKey {
        token: "vk-token",
        aud: None,
    };
    let c = chain(Vec::new(), true);
    for _ in 0..3 {
        assert!(matches!(
            c.run_chain_cached(Some("vk-token"), Some(&cache), Some(&verifier), 1000, None),
            ChainVerdict::Identified { .. }
        ));
    }
    assert!(
        cache.is_empty(),
        "the keys arm must never read or write the credential cache"
    );
}

#[test]
fn test_cacheable_defaults_to_false() {
    let cache = CredentialCache::new(super::test_digest);
    let c = chain(vec![entry("dflt", Box::new(DefaultCacheability))], false);
    for _ in 0..3 {
        assert!(matches!(
            c.run_chain_cached(Some("cred"), Some(&cache), None, 1000, None),
            ChainVerdict::Identified { .. }
        ));
    }
    assert!(
        cache.is_empty(),
        "a module that never declares itself cacheable is re-verified every request"
    );
}

#[test]
fn test_chain_names_are_the_modules_own_names() {
    let c = chain(
        vec![
            entry(
                "alias-one",
                Box::new(Canned::new("mod-a", AuthOutcome::Pass)),
            ),
            entry(
                "alias-two",
                Box::new(Canned::new("mod-b", AuthOutcome::Pass)),
            ),
        ],
        false,
    );
    assert_eq!(c.chain_names(), vec!["mod-a", "mod-b"]);
}

#[test]
fn test_validate_token_is_admit_or_deny() {
    let open = chain(Vec::new(), false);
    assert!(open.validate_token(None));
    let closed = chain(
        vec![entry("a", Box::new(Canned::new("a", AuthOutcome::Pass)))],
        false,
    );
    assert!(!closed.validate_token(Some("cred")));
}

/// PB-92's order (`ARCHITECTURE.md`, `VirtualKey.expires_at`): signature → `exp` → denylist →
/// `by_id` generation, each step short-circuiting the ones after it. This crate does not own the
/// governance implementation of [`crate::chain::KeyVerifier`] — that lives on the composition root's
/// side — so this is a fake that RECORDS the order it was asked to perform each check in, pinning
/// the contract [`crate::chain::KeyVerifier::verify_token`]'s doc now states, over the same shape a
/// real implementation has: four sequential, short-circuiting steps.
struct OrderRecordingVerifier {
    log: std::sync::Mutex<Vec<&'static str>>,
    fail_at: Option<&'static str>,
}

impl OrderRecordingVerifier {
    fn new(fail_at: Option<&'static str>) -> Self {
        OrderRecordingVerifier {
            log: std::sync::Mutex::new(Vec::new()),
            fail_at,
        }
    }

    fn record_and_check(&self, step: &'static str) -> bool {
        self.log.lock().unwrap().push(step);
        self.fail_at != Some(step)
    }

    fn recorded(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().clone()
    }
}

impl crate::chain::KeyVerifier for OrderRecordingVerifier {
    fn verify_token(
        &self,
        _token: &str,
        _now: u64,
        _expected_aud: Option<&str>,
    ) -> Option<ResolvedKey> {
        if !self.record_and_check("signature") {
            return None;
        }
        if !self.record_and_check("exp") {
            return None;
        }
        if !self.record_and_check("denylist") {
            return None;
        }
        if !self.record_and_check("by_id") {
            return None;
        }
        Some(ResolvedKey {
            id: "vk_order".to_string(),
            name: "order-pin".to_string(),
        })
    }
}

#[test]
fn keys_arm_verify_token_order_matches_pb_92_on_full_success() {
    let verifier = OrderRecordingVerifier::new(None);
    let c = chain(Vec::new(), true);
    assert!(matches!(
        c.run_chain_cached(Some("tok"), None, Some(&verifier), 1000, None),
        ChainVerdict::Identified { .. }
    ));
    assert_eq!(
        verifier.recorded(),
        vec!["signature", "exp", "denylist", "by_id"],
        "PB-92: signature, then exp, then denylist, then by_id generation"
    );
}

#[test]
fn keys_arm_verify_token_short_circuits_at_the_failing_step() {
    for (fail_at, expected_log) in [
        ("signature", vec!["signature"]),
        ("exp", vec!["signature", "exp"]),
        ("denylist", vec!["signature", "exp", "denylist"]),
        ("by_id", vec!["signature", "exp", "denylist", "by_id"]),
    ] {
        let verifier = OrderRecordingVerifier::new(Some(fail_at));
        let c = chain(Vec::new(), true);
        assert_eq!(
            c.run_chain_cached(Some("tok"), None, Some(&verifier), 1000, None),
            ChainVerdict::Denied,
            "a failure at {fail_at} denies"
        );
        assert_eq!(
            verifier.recorded(),
            expected_log,
            "a failure at {fail_at} must not reach a later step"
        );
    }
}

#[test]
fn revocation_gates_new_units_only() {
    struct AllRevoked;
    impl crate::chain::RevocationView for AllRevoked {
        fn is_revoked(&self, _credential: &str) -> bool {
            true
        }
    }
    let c = chain(
        vec![entry(
            "a",
            Box::new(Canned::new(
                "a",
                AuthOutcome::Identify(Principal::from_id("alice")),
            )),
        )],
        false,
    );
    // A new unit is gated.
    assert_eq!(
        c.run_chain_for_new_unit(Some("cred"), None, None, 1000, None, Some(&AllRevoked)),
        ChainVerdict::Denied
    );
    // The same walk without the gate — the in-flight unit's path — still identifies.
    assert!(matches!(
        c.run_chain_cached(Some("cred"), None, None, 1000, None),
        ChainVerdict::Identified { .. }
    ));
}
