// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KEY BESIDE THE DECISION: what `Auth::resolve_recording_key` hands back, and on which arms.
//!
//! Before this existed the built-in key arm read a key's grant list and then dropped it. A sealed
//! decision carries a principal and nothing else — deliberately — so no step downstream could ask
//! what the key was ENTITLED to, and anything that wanted a per-resource grant had to resolve the
//! key a second time, off a different shape, in a different crate. That second resolution is most
//! of what a plane's own grant body was.

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
///
/// Stated as a test rather than trusted, because the moment the two stop being one walk is the
/// moment a caller that enforces a grant is authenticating against different rules from one that
/// does not.
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
///
/// The open door admitted somebody and has no grants to offer; a boxed module identified somebody
/// and CANNOT offer any, because its answer type does not carry a key. Both read as `None`, so a
/// caller that enforces a grant has to decide what `None` means, and the fail-closed reading is the
/// caller's to take rather than something this unit can take on its behalf.
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
///
/// Written on the admitting arm alone, so a caller cannot end up holding a key off a walk that was
/// denied — the shape of every "checked the grant, forgot the refusal" defect.
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
