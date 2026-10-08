// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: what the loop actually receives. Moved from `busbar-kernel-identity`'s own
//! suite (`src/tests/unit_tests.rs`): each test mints the `Pass<Authenticate>` the unit's
//! `Auth::resolve` takes, and minting is the kernel's.

use busbar_contract::caps::{Authenticate, KernelSeal, Pass, ReasonCode, StepName};
use busbar_kernel_identity::chain::{AuthChain, ChainEntry};
use busbar_kernel_identity::challenge::{Challenge, ChallengeBounds};
use busbar_kernel_identity::module::{AuthModule, AuthOutcome};
use busbar_kernel_identity::principal::{Principal, ANONYMOUS};
use busbar_kernel_identity::unit::{Auth, AuthRequest};

/// A stand-in module with a canned answer and a declared cacheability, so a test can state exactly
/// the chain shape it means and nothing else.
struct Canned {
    name: &'static str,
    outcome: AuthOutcome,
    cacheable: bool,
    /// How many times the module was actually consulted — the only way to tell a cache hit from a
    /// re-verification. Shared so a test can watch it after the module is boxed into the chain.
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Canned {
    fn new(name: &'static str, outcome: AuthOutcome) -> Self {
        Canned {
            name,
            outcome,
            cacheable: false,
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl AuthModule for Canned {
    fn name(&self) -> &'static str {
        self.name
    }
    fn authenticate(&self, _candidate: Option<&str>) -> AuthOutcome {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.outcome.clone()
    }
    fn cacheable(&self) -> bool {
        self.cacheable
    }
}

fn entry(provider: &str, module: Box<dyn AuthModule>) -> ChainEntry {
    ChainEntry {
        provider: provider.to_string(),
        module,
    }
}

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

fn seal_and_token() -> (KernelSeal, Pass<Authenticate>) {
    let seal = KernelSeal::acquire_for_kernel();
    let token = Pass::mint(&seal);
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
    let d = auth.resolve(&req, None, None, None, &token);
    let principal = d.into_result(&seal).expect("the open door admits");
    assert_eq!(
        principal
            .principal()
            .expect("the open door settles on an identity")
            .as_str(),
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
    let d = auth.resolve(&request(), None, None, None, &token);
    let refusal = d.into_result(&seal).expect_err("an all-pass chain denies");
    assert_eq!(refusal.reason(), ReasonCode::Unauthenticated);
    assert_eq!(
        refusal.step(),
        Some(StepName::Authenticate),
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
        declared_schemes: &["static-token", "signature"],
        ..request()
    };
    let d = auth.resolve(&req, None, None, None, &token);
    let refusal = d
        .into_result(&seal)
        .expect_err("an undeclared scheme is refused");
    assert_eq!(refusal.reason(), ReasonCode::SchemeNotDeclared);

    // Narrowing WITHIN the alternatives is fine and the chain runs normally.
    let (seal, token) = seal_and_token();
    let req = AuthRequest {
        scheme: Some("static-token"),
        declared_schemes: &["static-token", "signature"],
        ..request()
    };
    let d = auth.resolve(&req, None, None, None, &token);
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
    let (seal, token) = seal_and_token();
    let req = AuthRequest {
        in_handshake: true,
        ..request()
    };
    let pending = Challenge::open(b"nonce".to_vec(), bounds);
    let offered = auth
        .resolve(&req, None, None, Some(pending), &token)
        .into_result(&seal)
        .expect("a handshake unit is offered the round");
    assert!(matches!(
        offered,
        busbar_contract::caps::Authenticated::Challenge(_)
    ));

    // Outside one, the chain's own verdict stands.
    let (seal, token) = seal_and_token();
    let pending = Challenge::open(b"nonce".to_vec(), bounds);
    let d = auth.resolve(&request(), None, None, Some(pending), &token);
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
    let d = auth.resolve(&req, None, None, Some(spent), &token);
    assert_eq!(
        d.into_result(&seal).expect_err("exhausted").reason(),
        ReasonCode::ChallengeExhausted
    );
}

#[test]
fn revocation_gates_a_new_unit_and_not_one_in_flight() {
    struct AllRevoked;
    impl busbar_kernel_identity::chain::RevocationView for AllRevoked {
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
    let d = auth.resolve(&request(), None, Some(&AllRevoked), None, &token);
    assert_eq!(
        d.into_result(&seal)
            .expect_err("a new unit is gated")
            .reason(),
        ReasonCode::Revoked
    );

    let (seal, token) = seal_and_token();
    let in_flight = AuthRequest {
        new_unit: false,
        ..request()
    };
    let d = auth.resolve(&in_flight, None, Some(&AllRevoked), None, &token);
    assert_eq!(
        d.into_result(&seal)
            .expect("a unit already in flight runs to its end")
            .principal()
            .expect("and settles on an identity")
            .as_str(),
        "alice"
    );
}

/// The revocation gate speaks only about a credential the chain ACTUALLY IDENTIFIED.
///
/// Applied to the presented string whatever the chain answered, it does two things it was never
/// asked to do. It tells an unauthenticated caller WHICH of two refusals they earned — a credential
/// the chain rejects and the revocation set names refuses `Revoked`, one it merely rejects refuses
/// `Unauthenticated` — which is a probe for "was this credential ever real", answered before
/// anything has authenticated. And on the open front door, where no chain is authenticating anyone,
/// it turns the anonymous admit into a refusal on the strength of a string nothing verified.
///
/// `AuthChain::run_chain_for_new_unit` collapses both to the one `Denied` it can spell, so the two
/// spellings of one rule inside this crate answered differently for the same input.
#[test]
fn the_revocation_gate_does_not_distinguish_refusals_the_chain_already_made() {
    struct AllRevoked;
    impl busbar_kernel_identity::chain::RevocationView for AllRevoked {
        fn is_revoked(&self, _credential: &str) -> bool {
            true
        }
    }

    // A chain that denies on its own. The revocation set must not upgrade that to a different,
    // more informative code.
    let (seal, token) = seal_and_token();
    let denies = Auth::new(AuthChain::new(
        vec![entry("a", Box::new(Canned::new("a", AuthOutcome::Pass)))],
        false,
    ));
    assert_eq!(
        denies
            .resolve(&request(), None, Some(&AllRevoked), None, &token)
            .into_result(&seal)
            .expect_err("an all-pass chain denies")
            .reason(),
        ReasonCode::Unauthenticated,
        "a credential the chain never identified must refuse for the reason the chain gave, not \
         for one that says whether it was ever a real credential"
    );

    // The open front door authenticates nobody, so there is no identification for a revocation to
    // gate: the anonymous admit stands.
    let (seal, token) = seal_and_token();
    let open = Auth::new(AuthChain::new(Vec::new(), false));
    assert_eq!(
        open.resolve(&request(), None, Some(&AllRevoked), None, &token)
            .into_result(&seal)
            .expect("the open door admits anonymously")
            .principal()
            .expect("and settles on an identity")
            .as_str(),
        ANONYMOUS,
        "the open posture is not authenticating the presented string, so revoking it says nothing"
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
        let d = auth.resolve(&request(), None, None, None, &token);
        assert_eq!(
            d.into_result(&seal)
                .expect_err("a reserved id is refused")
                .reason(),
            ReasonCode::Unauthenticated,
            "id {reserved}"
        );
    }
}

/// The reserved-id rule is about MODULES, and applies only to them.
///
/// A virtual key's own id starts with `vk_` — that prefix is reserved precisely so that nothing
/// BUT the key directory can mint an id in it. Applying the rule to the engine's own signed-key arm
/// therefore refuses every real key: the arm does not synthesize an identity, it resolves the one
/// the directory issued. A boxed module, which cannot resolve a key, is still refused.
#[test]
fn the_reserved_id_rule_binds_modules_and_not_the_engines_own_key_arm() {
    struct Resolves;
    impl busbar_kernel_identity::chain::KeyVerifier for Resolves {
        fn verify_token(
            &self,
            _token: &str,
            _now: u64,
            _expected_aud: Option<&str>,
        ) -> Option<busbar_kernel_identity::chain::ResolvedKey> {
            Some(busbar_kernel_identity::chain::ResolvedKey {
                id: "vk_live".to_string(),
                name: "live".to_string(),
            })
        }
    }

    // The keys arm: a `vk_` id is the key's OWN id, and it is admitted.
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    let d = auth.resolve(&request(), Some(&Resolves), None, None, &token);
    assert_eq!(
        d.into_result(&seal)
            .expect("a resolved key is an identity the directory issued")
            .principal()
            .expect("and it settles on that identity")
            .as_str(),
        "vk_live"
    );

    // A boxed module claiming the same id is still refused: it synthesized it.
    let (seal, token) = seal_and_token();
    let auth = Auth::new(AuthChain::new(
        vec![entry(
            "a",
            Box::new(Canned::new(
                "a",
                AuthOutcome::Identify(Principal::from_id("vk_live")),
            )),
        )],
        false,
    ));
    let d = auth.resolve(&request(), None, None, None, &token);
    assert_eq!(
        d.into_result(&seal)
            .expect_err("a module may not name a key")
            .reason(),
        ReasonCode::Unauthenticated
    );
}
