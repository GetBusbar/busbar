// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: what the loop actually receives.

use busbar_caps::{Authenticate, KernelSeal, ReasonCode, StepName, UnitToken};

use super::{entry, Canned};
use crate::admin::{admin_grants, kernel_verb_scope_satisfied, Scope};
use crate::chain::AuthChain;
use crate::challenge::{Challenge, ChallengeBounds};
use crate::module::AuthOutcome;
use crate::principal::{Principal, ANONYMOUS};
use crate::unit::{Auth, AuthRequest, Resolved};

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

#[test]
fn anonymous_renders_as_the_literal_word() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), false));
    let req = AuthRequest {
        candidate: None,
        ..request()
    };
    let Resolved::Decided(d) = auth.resolve(&req, None, None, None, None, &token) else {
        panic!("the open door decides rather than challenging");
    };
    let principal = d.into_result(&seal).expect("the open door admits");
    assert_eq!(
        principal.as_str(),
        ANONYMOUS,
        "the anonymous caller renders as the plain word on every surface"
    );
    assert_eq!(Principal::anonymous().actor_id(), "anonymous");
}

#[test]
fn a_denied_chain_refuses_at_the_authenticate_step() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(
        vec![entry("a", Box::new(Canned::new("a", AuthOutcome::Pass)))],
        false,
    ));
    let Resolved::Decided(d) = auth.resolve(&request(), None, None, None, None, &token) else {
        panic!("expected a decision");
    };
    let refusal = d.into_result(&seal).expect_err("an all-pass chain denies");
    assert_eq!(refusal.reason(), ReasonCode::Unauthenticated);
    assert_eq!(
        refusal.step(),
        StepName::Authenticate,
        "the step is stamped by the decision, not claimed by the unit"
    );
    assert!(!refusal.under_hold(), "nothing is charged this early");
}

#[test]
fn a_plane_may_only_narrow_within_the_claims_alternatives() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), false));
    let req = AuthRequest {
        scheme: Some("mutual-tls"),
        declared_schemes: &["bearer", "signature"],
        ..request()
    };
    let Resolved::Decided(d) = auth.resolve(&req, None, None, None, None, &token) else {
        panic!("expected a decision");
    };
    let refusal = d.into_result(&seal).expect_err("an undeclared scheme is refused");
    assert_eq!(refusal.reason(), ReasonCode::SchemeNotDeclared);

    // Narrowing WITHIN the alternatives is fine and the chain runs normally.
    let (seal, token) = seal_and_token();
    let req = AuthRequest {
        scheme: Some("bearer"),
        declared_schemes: &["bearer", "signature"],
        ..request()
    };
    let Resolved::Decided(d) = auth.resolve(&req, None, None, None, None, &token) else {
        panic!("expected a decision");
    };
    assert!(d.into_result(&seal).is_ok());
}

#[test]
fn a_challenge_is_only_offered_inside_a_handshake_unit() {
    let bounds = ChallengeBounds {
        max_rounds: 3,
        max_bytes: 64,
    };
    let auth = Auth::new(AuthChain::new(
        vec![entry("a", Box::new(Canned::new("a", AuthOutcome::Pass)))],
        false,
    ));

    // Inside a handshake unit the challenge is handed back for delivery.
    let (_seal, token) = seal_and_token();
    let req = AuthRequest {
        in_handshake: true,
        ..request()
    };
    let pending = Challenge::open(b"nonce".to_vec(), bounds);
    assert!(matches!(
        auth.resolve(&req, None, None, None, Some(pending), &token),
        Resolved::Challenge(_)
    ));

    // Outside one, the chain's own verdict stands.
    let (seal, token) = seal_and_token();
    let pending = Challenge::open(b"nonce".to_vec(), bounds);
    let Resolved::Decided(d) = auth.resolve(&request(), None, None, None, Some(pending), &token)
    else {
        panic!("a challenge outside a handshake unit is not offered");
    };
    assert_eq!(
        d.into_result(&seal).expect_err("all-pass denies").reason(),
        ReasonCode::Unauthenticated
    );
}

#[test]
fn an_exhausted_exchange_ends_the_unit() {
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    let req = AuthRequest {
        in_handshake: true,
        ..request()
    };
    let spent = Challenge::open(
        b"nonce".to_vec(),
        ChallengeBounds {
            max_rounds: 1,
            max_bytes: 64,
        },
    );
    assert!(spent.exhausted(), "one round, and it was spent opening");
    let Resolved::Decided(d) = auth.resolve(&req, None, None, None, Some(spent), &token) else {
        panic!("an exhausted exchange decides rather than continuing");
    };
    assert_eq!(
        d.into_result(&seal).expect_err("exhausted").reason(),
        ReasonCode::ChallengeExhausted
    );
}

#[test]
fn a_challenge_advances_within_its_bounds_and_then_stops() {
    let c = Challenge::open(
        b"aa".to_vec(),
        ChallengeBounds {
            max_rounds: 3,
            max_bytes: 6,
        },
    );
    assert_eq!(c.rounds_left, 2);
    assert_eq!(c.bytes_left, 4);
    let c = c.advance(b"bb".to_vec()).expect("within both bounds");
    assert_eq!(c.rounds_left, 1);
    assert_eq!(c.bytes_left, 2);
    assert!(
        c.clone().advance(b"ccc".to_vec()).is_none(),
        "a round larger than the remaining byte budget is refused"
    );
    let c = c.advance(b"cc".to_vec()).expect("exactly the budget");
    assert!(c.exhausted());
    assert!(c.advance(b"d".to_vec()).is_none());
}

#[test]
fn revocation_gates_a_new_unit_and_not_one_in_flight() {
    struct AllRevoked;
    impl crate::chain::RevocationView for AllRevoked {
        fn is_revoked(&self, _credential: &str) -> bool {
            true
        }
    }
    let auth = Auth::new(AuthChain::new(
        vec![entry(
            "a",
            Box::new(Canned::new(
                "a",
                AuthOutcome::Identify(Principal::from_id("alice")),
            )),
        )],
        false,
    ));

    let (seal, token) = seal_and_token();
    let Resolved::Decided(d) = auth.resolve(&request(), None, None, Some(&AllRevoked), None, &token)
    else {
        panic!("expected a decision");
    };
    assert_eq!(
        d.into_result(&seal).expect_err("a new unit is gated").reason(),
        ReasonCode::Revoked
    );

    let (seal, token) = seal_and_token();
    let in_flight = AuthRequest {
        new_unit: false,
        ..request()
    };
    let Resolved::Decided(d) =
        auth.resolve(&in_flight, None, None, Some(&AllRevoked), None, &token)
    else {
        panic!("expected a decision");
    };
    assert_eq!(
        d.into_result(&seal)
            .expect("a unit already in flight runs to its end")
            .as_str(),
        "alice"
    );
}

#[test]
fn a_module_may_not_synthesize_a_reserved_identity() {
    for reserved in ["group:admins", "vk_forged"] {
        let (seal, token) = seal_and_token();
        let auth = Auth::new(AuthChain::new(
            vec![entry(
                "a",
                Box::new(Canned::new(
                    "a",
                    AuthOutcome::Identify(Principal::from_id(reserved)),
                )),
            )],
            false,
        ));
        let Resolved::Decided(d) = auth.resolve(&request(), None, None, None, None, &token) else {
            panic!("expected a decision");
        };
        assert_eq!(
            d.into_result(&seal)
                .expect_err("a reserved id is refused")
                .reason(),
            ReasonCode::Unauthenticated,
            "id {reserved}"
        );
    }
}

#[test]
fn open_admin_grants_full_scope_to_an_absent_principal() {
    let grants = admin_grants(true, None).expect("the open posture grants");
    assert_eq!(grants.scope(), Scope::Full);
    assert!(grants.satisfies(Scope::ReadOnly));
    assert!(grants.satisfies(Scope::Full));
    // With a chain configured, an absent principal holds nothing.
    assert!(admin_grants(false, None).is_none());
    // And a resolved principal's grants come from the bindings, not from the posture.
    assert!(admin_grants(true, Some(&Principal::from_id("alice"))).is_none());
}

#[test]
fn the_kernel_verb_scope_check_is_satisfied_for_anonymous_on_the_open_posture() {
    assert!(kernel_verb_scope_satisfied(true, &Principal::anonymous()));
    assert!(
        !kernel_verb_scope_satisfied(false, &Principal::anonymous()),
        "with a chain configured the check is not satisfied by being nobody"
    );
    assert!(
        !kernel_verb_scope_satisfied(true, &Principal::from_id("alice")),
        "a resolved principal is judged on its own scopes"
    );
}
