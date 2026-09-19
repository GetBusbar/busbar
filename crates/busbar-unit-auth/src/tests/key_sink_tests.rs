// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KEY BESIDE THE DECISION: what `Auth::resolve_recording_key` hands back, and on which arms.
//!
//! Before this existed the built-in key arm read a key's grant list and then dropped it. A sealed
//! decision carries a principal and nothing else — deliberately — so no step downstream could ask
//! what the key was ENTITLED to, and anything that wanted a per-resource grant had to resolve the
//! key a second time, off a different shape, in a different crate.

use busbar_caps::{Authenticate, KernelSeal, ReasonCode, UnitToken};

use super::{entry, Canned};
use crate::chain::{AuthChain, KeyScope, KeyVerifier, ResolvedKey};
use crate::module::AuthOutcome;
use crate::principal::Principal;
use crate::unit::{Auth, AuthRequest};

fn request<'a>() -> AuthRequest<'a> {
    AuthRequest {
        candidate: Some("cred"),
        scheme: None,
        declared_schemes: &[],
        expected_aud: None,
        in_handshake: false,
        now: 1000,
        new_unit: true,
    }
}

fn seal_and_token() -> (KernelSeal, UnitToken<Authenticate>) {
    let seal = KernelSeal::acquire_for_kernel();
    let token = UnitToken::mint(&seal);
    (seal, token)
}

/// A key that grants exactly one thing, so a caller enforcing a per-resource grant has BOTH answers
/// to read off it — the one it covers and the one it does not.
fn granting(id: &str, kind: &str, value: &str) -> ResolvedKey {
    ResolvedKey {
        scopes: Some(vec![KeyScope {
            kind: kind.to_string(),
            value: value.to_string(),
        }]),
        ..ResolvedKey::unrestricted(id, "granted")
    }
}

/// THE GRANTS THE CHAIN RESOLVED REACH THE CALLER THAT ENFORCES THEM.
#[test]
fn the_engine_arm_hands_back_the_key_it_resolved() {
    struct Resolves;
    impl KeyVerifier for Resolves {
        fn verify_token(
            &self,
            _token: &str,
            _now: u64,
            _expected_aud: Option<&str>,
        ) -> Option<ResolvedKey> {
            Some(granting("vk_scoped", "agent", "sales"))
        }
    }

    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    let mut key = None;
    let decision = auth.resolve_recording_key(
        &request(),
        None,
        Some(&Resolves),
        None,
        None,
        &token,
        &mut key,
    );
    assert!(decision.into_result(&seal).is_ok(), "the key arm admits");

    let key = key.expect("and the key it resolved is beside the decision");
    assert_eq!(key.id, "vk_scoped");
    assert!(key.scope_allowed("agent", "sales"), "the grant it holds");
    assert!(
        !key.scope_allowed("agent", "support"),
        "and only the grant it holds"
    );
}

/// THE PLAIN `resolve` IS THE SAME WALK WITH THE SINK THROWN AWAY.
#[test]
fn the_sinkless_call_is_the_same_decision() {
    struct Resolves;
    impl KeyVerifier for Resolves {
        fn verify_token(
            &self,
            _token: &str,
            _now: u64,
            _expected_aud: Option<&str>,
        ) -> Option<ResolvedKey> {
            Some(granting("vk_scoped", "agent", "sales"))
        }
    }

    let auth = Auth::new(AuthChain::new(Vec::new(), true));

    let (seal, token) = seal_and_token();
    let plain = auth
        .resolve(&request(), None, Some(&Resolves), None, None, &token)
        .into_result(&seal)
        .expect("the key arm admits")
        .principal()
        .expect("on this identity")
        .as_str()
        .to_string();

    let (seal, token) = seal_and_token();
    let mut key = None;
    let recorded = auth
        .resolve_recording_key(
            &request(),
            None,
            Some(&Resolves),
            None,
            None,
            &token,
            &mut key,
        )
        .into_result(&seal)
        .expect("and so does the recording call")
        .principal()
        .expect("on the same identity")
        .as_str()
        .to_string();

    assert_eq!(plain, recorded);
    assert!(
        key.is_some(),
        "the only difference is what came back beside it"
    );
}

/// THE TWO ARMS THAT RESOLVE NO KEY LEAVE THE SINK EMPTY — and they are not the same posture.
#[test]
fn an_open_door_and_a_boxed_module_both_resolve_no_key() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), false));
    let mut key = Some(granting("vk_stale", "agent", "sales"));
    let req = AuthRequest {
        candidate: None,
        ..request()
    };
    let decision = auth.resolve_recording_key(&req, None, None, None, None, &token, &mut key);
    assert!(decision.into_result(&seal).is_ok(), "the open door admits");
    assert!(
        key.is_none(),
        "and OVERWRITES whatever the sink held: this arm resolved no key, and a sink left \
         untouched would hand the caller one off a walk that never produced it"
    );

    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(
        vec![entry(
            "a",
            Box::new(Canned::new(
                "a",
                AuthOutcome::Identify(Principal::from_id("who")),
            )),
        )],
        false,
    ));
    let mut key = None;
    let decision = auth.resolve_recording_key(&request(), None, None, None, None, &token, &mut key);
    assert!(decision.into_result(&seal).is_ok(), "the module identifies");
    assert!(key.is_none(), "and can carry no key");
}

/// A REFUSAL NEVER WRITES THE SINK.
#[test]
fn a_refusal_leaves_the_sink_alone() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    let mut key = None;
    // The keys arm with no verifier behind it denies.
    let decision = auth.resolve_recording_key(&request(), None, None, None, None, &token, &mut key);
    assert_eq!(
        decision
            .into_result(&seal)
            .expect_err("nothing verified the candidate")
            .reason(),
        ReasonCode::Unauthenticated
    );
    assert!(key.is_none(), "and no key was handed back");
}

/// A REFUSAL LEAVES A PRE-POPULATED SINK ALONE, NOT JUST AN EMPTY ONE.
///
/// The empty case above proves a refusal does not FABRICATE a key. It does not prove a refusal
/// does not CLEAR one a caller already held — an `Open` arm does exactly that on purpose (see
/// `an_open_door_and_a_boxed_module_both_resolve_no_key`), so a refusal that copied the same
/// `*key = None;` habit would look identical to this suite unless the sink starts non-empty.
#[test]
fn a_refusal_leaves_a_pre_populated_sink_untouched() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    let carried = granting("vk_carried", "agent", "sales");
    let mut key = Some(carried.clone());
    // The keys arm with no verifier behind it denies.
    let decision = auth.resolve_recording_key(&request(), None, None, None, None, &token, &mut key);
    assert_eq!(
        decision
            .into_result(&seal)
            .expect_err("nothing verified the candidate")
            .reason(),
        ReasonCode::Unauthenticated
    );
    assert_eq!(
        key,
        Some(carried),
        "a refusal leaves whatever was already in the sink exactly as it found it"
    );
}
