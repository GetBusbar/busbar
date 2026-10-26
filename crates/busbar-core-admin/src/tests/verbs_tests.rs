// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Integration-level assertions over `Verbs`: scope enforcement, and that a new verb reaches
//! `Governance::execute_new_verb` once its scope admits it — a plain scoped verb (#77(9)).

use crate::governance::{Governance, GovernanceError};
use crate::rate::CONFIG_CLASS_RULES;
use crate::verb::{KernelVerb, VerbScope};
use crate::verbs::Verbs;
use busbar_contract::caps::{AdminVerb, Grant};
use busbar_contract::verb_store::{Store, StoreError};
use std::sync::Mutex;

/// A fresh node-lifetime limiter, as the composition root builds once per node.
fn node_limiter() -> std::sync::Arc<crate::rate::MutationLimiter> {
    std::sync::Arc::new(crate::rate::MutationLimiter::new())
}

fn make_verbs<G: Governance>(gov: G) -> Verbs<G, RecordingStore> {
    Verbs::new(
        gov,
        Some(std::sync::Arc::new(RecordingStore::new())),
        CONFIG_CLASS_RULES,
        node_limiter(),
    )
}

struct FakeGovernance {
    new_verb_calls: Mutex<Vec<KernelVerb>>,
    /// What every mutating governance call should fail with, if anything.
    ///
    /// Without this the fail-closed arm of `GovernanceError::into_refusal` is unreachable from any
    /// test: a double that can only succeed proves the happy path and nothing else, and a store that
    /// went away is the case the mapping exists for.
    fails_with: Mutex<Option<GovernanceError>>,
}

impl FakeGovernance {
    fn new() -> Self {
        FakeGovernance {
            new_verb_calls: Mutex::new(Vec::new()),
            fails_with: Mutex::new(None),
        }
    }

    /// Every mutating call refuses with this error until it is cleared.
    fn failing_with(self, error: GovernanceError) -> Self {
        *self.fails_with.lock().unwrap() = Some(error);
        self
    }

    /// The injected failure, taken fresh for each call so a double can refuse more than once.
    fn injected(&self) -> Option<GovernanceError> {
        match *self.fails_with.lock().unwrap() {
            None => None,
            Some(GovernanceError::NotFound) => Some(GovernanceError::NotFound),
            Some(GovernanceError::Conflict) => Some(GovernanceError::Conflict),
            Some(GovernanceError::Validation) => Some(GovernanceError::Validation),
            Some(GovernanceError::Store) => Some(GovernanceError::Store),
        }
    }
}

impl Governance for FakeGovernance {
    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &Grant<AdminVerb>,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        if let Some(e) = self.injected() {
            return Err(e);
        }
        Ok(b"ok".to_vec())
    }
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &Grant<AdminVerb>,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        if let Some(e) = self.injected() {
            return Err(e);
        }
        self.new_verb_calls.lock().unwrap().push(verb);
        Ok(b"ok".to_vec())
    }
}

fn admin() -> Grant<AdminVerb> {
    busbar_kernel::test_support::tokens::grant::<AdminVerb>()
}

#[test]
fn readonly_caller_is_refused_a_mutation() {
    let verbs = make_verbs(FakeGovernance::new());
    let admin = admin();
    let err = verbs
        .execute(
            KernelVerb::PostGroups,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);
}

#[test]
fn readonly_caller_may_read() {
    let verbs = make_verbs(FakeGovernance::new());
    let admin = admin();
    let out = verbs
        .execute(
            KernelVerb::GetGroups,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            b"{}",
        )
        .unwrap();
    assert_eq!(out, b"ok");
}

/// THE SIX VERBS THAT USED TO WAIT ON AN OPERATOR KEY ARE PLAIN SCOPED VERBS (#77(9), OWNER-LOCKED,
/// `docs/design/BUSBAR-1.6.0.md` l.2279: "no verb carries dual control, escrow or operator
/// signatures. Each verb is a plain scoped verb authorized by the per-verb allow-list on the admin
/// token").
///
/// A grant that covers the verb (`full`, the 1.5.5 shorthand every mutating verb's allow-list
/// resolves to) is admitted with nothing else asked: the governance verbs reach the governance
/// seam and the two recovery verbs reach the store. RED before the fix: each was refused
/// `OperatorUnset` while no operator key was sealed, and nothing reached either seam.
#[test]
fn every_formerly_irreducible_verb_is_admitted_by_its_grant_alone() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));
    for verb in [
        KernelVerb::CommitUpgrade,
        KernelVerb::Adjust,
        KernelVerb::AmendRateHistory,
    ] {
        let out = verbs
            .execute(verb, &admin, "alice", VerbScope::Full, 0, b"{}")
            .unwrap_or_else(|e| panic!("{verb:?} was refused under a full grant: {e:?}"));
        assert_eq!(out, b"new", "{verb:?} did not reach the governance seam");
    }
    assert_eq!(
        log.lock().unwrap().clone(),
        vec![
            (KernelVerb::CommitUpgrade, "new"),
            (KernelVerb::Adjust, "new"),
            (KernelVerb::AmendRateHistory, "new"),
        ]
    );

    let v = recovery_verbs();
    v.chain_break(&admin, "alice", VerbScope::Full, 0)
        .expect("chain_break is admitted by its grant");
    v.store_restore(&admin, "alice", VerbScope::Full, 0, "backup-1")
        .expect("store_restore is admitted by its grant");
    assert_eq!(
        v.store_for_test().reached(),
        vec!["chain_break", "store_restore"]
    );
}

/// The other half of the same rule: a grant that does NOT cover the verb is refused, for every one
/// of the six, and nothing reaches either seam. The allow-list is the whole of the authorization,
/// so it is the one thing that must still refuse.
#[test]
fn every_formerly_irreducible_verb_is_refused_to_a_grant_that_does_not_cover_it() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));
    for verb in [
        KernelVerb::CommitUpgrade,
        KernelVerb::Adjust,
        KernelVerb::AmendRateHistory,
    ] {
        let err = verbs
            .execute(verb, &admin, "alice", VerbScope::ReadOnly, 0, b"{}")
            .expect_err("a read-only grant does not cover a mutating verb");
        assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);
    }
    assert!(log.lock().unwrap().is_empty());

    let v = recovery_verbs();
    for err in [
        v.chain_break(&admin, "alice", VerbScope::ReadOnly, 0)
            .unwrap_err(),
        v.store_restore(&admin, "alice", VerbScope::ReadOnly, 0, "backup-1")
            .unwrap_err(),
    ] {
        assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);
    }
    assert!(v.store_for_test().reached().is_empty());
}

#[test]
fn a_new_verb_admitted_by_its_scope_reaches_governance() {
    let verbs = make_verbs(FakeGovernance::new());
    let admin = admin();
    let out = verbs
        .execute(
            KernelVerb::PlaneRecordWrite,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            b"{}",
        )
        .unwrap();
    assert_eq!(out, b"ok");
}

/// D38 `amend_rate_history` is wired like any other money-governance verb: `full` scope and the
/// `Crud` rate class. A read-only credential is refused at admit; a full one reaches the governance
/// seam with nothing else asked.
#[test]
fn amend_rate_history_is_a_full_scope_new_verb() {
    use crate::rate::MutationClass;
    use crate::verb::NEW_VERBS;

    assert!(NEW_VERBS.contains(&KernelVerb::AmendRateHistory));
    assert_eq!(
        crate::verbs::required_scope(KernelVerb::AmendRateHistory),
        VerbScope::Full
    );
    assert_eq!(
        MutationClass::for_verb(KernelVerb::AmendRateHistory, CONFIG_CLASS_RULES),
        MutationClass::Crud
    );

    let verbs = make_verbs(FakeGovernance::new());
    let admin = admin();

    // Scope refusal: a read-only credential may not amend the money-book's dated history.
    let err = verbs
        .execute(
            KernelVerb::AmendRateHistory,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            b"{}",
        )
        .expect_err("a read-only credential must be refused");
    assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);

    // Admitted with full scope: reaches the governance seam.
    let out = verbs
        .execute(
            KernelVerb::AmendRateHistory,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            b"{}",
        )
        .expect("a full credential is admitted");
    assert_eq!(out, b"ok");
}

/// A store that has gone away refuses, on every governance call, with the reason the mapping names.
///
/// This is the fail-closed arm: it never echoes the cause (several of these calls carry secrets)
/// and it never proceeds as if the call had succeeded. Nothing exercised it end to end before,
/// because the only governance double in this crate could not fail.
#[test]
fn a_governance_store_failure_refuses_with_store_error_on_every_call() {
    let admin = admin();

    // A legacy verb, through the catch-all.
    let verbs = make_verbs(FakeGovernance::new().failing_with(GovernanceError::Store));
    let err = verbs
        .execute(
            KernelVerb::PostGroups,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);

    // And a new 1.6.0 verb, once its scope has admitted it.
    let verbs = make_verbs(FakeGovernance::new().failing_with(GovernanceError::Store));
    let err = verbs
        .execute(
            KernelVerb::PlaneRecordWrite,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::StoreError);
}

/// The other three governance errors map to their own reasons, so `StoreError` is not a catch-all
/// that would hide a validation mistake behind an infrastructure one.
#[test]
fn the_other_governance_errors_keep_their_own_reasons() {
    let admin = admin();
    for (error, expected) in [
        (
            GovernanceError::NotFound,
            crate::refusal::ReasonCode::NotFound,
        ),
        (
            GovernanceError::Conflict,
            crate::refusal::ReasonCode::Conflict,
        ),
        (
            GovernanceError::Validation,
            crate::refusal::ReasonCode::Validation,
        ),
    ] {
        let verbs = make_verbs(FakeGovernance::new().failing_with(error));
        let err = verbs
            .execute(
                KernelVerb::PostGroups,
                &admin,
                "alice",
                VerbScope::Full,
                0,
                b"{}",
            )
            .unwrap_err();
        assert_eq!(err.reason, expected);
    }
}

/// One trust decision through `execute`, as the root's route step makes it.
fn approve_trust(
    verbs: &Verbs<FakeGovernance, RecordingStore>,
    admin: &Grant<AdminVerb>,
) -> Result<Vec<u8>, crate::refusal::Refusal> {
    verbs.execute(
        KernelVerb::TrustApprove,
        admin,
        "alice",
        VerbScope::Full,
        0,
        b"{}",
    )
}

/// A new verb spends the node's mutation budget, and the budget is the NODE's: the 61st `Crud`
/// mutation inside one window is refused even though every call was made through a different
/// `Verbs` — which is how the composition root builds them, one per request, over the one limiter
/// it holds for the life of the node.
#[test]
fn rate_limit_is_enforced_across_execute_calls() {
    let limiter = node_limiter();
    let per_request = || {
        Verbs::new(
            FakeGovernance::new(),
            Some(std::sync::Arc::new(RecordingStore::new())),
            CONFIG_CLASS_RULES,
            std::sync::Arc::clone(&limiter),
        )
    };
    let admin = admin();
    let budget = crate::rate::MutationClass::Crud.limit();
    for i in 0..budget {
        approve_trust(&per_request(), &admin)
            .unwrap_or_else(|e| panic!("attempt {i} should be admitted, got {e:?}"));
    }
    let err = approve_trust(&per_request(), &admin).unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::RateLimited);
}

/// A legacy mutation is NOT spent here. Its own 1.5.5 surface spends it in front of the handler,
/// and a second count on this side would refuse at half the budget 1.5.5 granted: eleven config
/// applies through one limiter all reach the surface, which is where the eleventh is refused.
#[test]
fn a_legacy_mutation_is_not_counted_a_second_time_here() {
    let verbs = make_verbs(FakeGovernance::new());
    let admin = admin();
    let budget = crate::rate::MutationClass::Config.limit();
    for i in 0..=budget {
        verbs
            .execute(
                KernelVerb::PostConfigApply,
                &admin,
                "alice",
                VerbScope::Full,
                0,
                b"{}",
            )
            .unwrap_or_else(|e| panic!("attempt {i} should reach its surface, got {e:?}"));
    }
}

// ── the five 1.6.0 ledger views ─────────────────────────────────────────────────────────────────

/// Which of the governance seam's three execution methods each verb reached.
///
/// Shared with the test rather than owned by the seam, because `Verbs` takes its governance by
/// value: the log has to outlive the executor for the test to read it. Which method a verb reaches
/// is the whole of what this crate decides about a ledger view, so it is what these tests measure.
type SeamLog = std::sync::Arc<Mutex<Vec<(KernelVerb, &'static str)>>>;

struct RoutingGovernance(SeamLog);

impl Governance for RoutingGovernance {
    fn execute_legacy(
        &self,
        verb: KernelVerb,
        _admin: &Grant<AdminVerb>,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "legacy"));
        Ok(b"legacy".to_vec())
    }
    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        _admin: &Grant<AdminVerb>,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "new"));
        Ok(b"new".to_vec())
    }
    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        _admin: &Grant<AdminVerb>,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "ledger"));
        Ok(b"ledger".to_vec())
    }
    fn execute_audit_read(
        &self,
        verb: KernelVerb,
        _admin: &Grant<AdminVerb>,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        self.0.lock().unwrap().push((verb, "audit"));
        Ok(b"audit".to_vec())
    }
}

/// A ledger view reaches the read seam under a read-only grant, the grant that refuses every
/// mutation.
///
/// The control below is a mutating verb refused on the same executor under the same grant, so the
/// green is the views being reads rather than the scope check being unwired.
#[test]
fn a_ledger_view_reaches_the_read_seam_under_a_grant_that_refuses_every_mutation() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));

    for verb in crate::verb::LEDGER_VERBS {
        let body = verbs
            .execute(*verb, &admin, "alice", VerbScope::ReadOnly, 0, b"")
            .unwrap_or_else(|e| panic!("{verb:?} was refused: {e:?}"));
        assert_eq!(body, b"ledger", "{verb:?} did not reach the read seam");
    }

    let refused = verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            b"",
        )
        .unwrap_err();
    assert_eq!(refused.reason, crate::refusal::ReasonCode::Unauthorized);

    let reached = log.lock().unwrap().clone();
    assert!(
        reached.iter().all(|(_, seam)| *seam == "ledger"),
        "a ledger view reached a seam that is not the read one: {reached:?}"
    );
    assert_eq!(reached.len(), crate::verb::LEDGER_VERBS.len());
}

/// A view asks for exactly what the legacy `/usage` read asks for, and no more.
#[test]
fn a_ledger_view_requires_what_the_legacy_usage_read_requires() {
    for verb in crate::verb::LEDGER_VERBS {
        assert_eq!(
            crate::verbs::required_scope(*verb),
            crate::verbs::required_scope(KernelVerb::GetUsage),
            "{verb:?} does not require what /usage requires"
        );
        assert_eq!(crate::verbs::required_scope(*verb), VerbScope::ReadOnly);
    }
}

/// A view never spends a mutation slot.
///
/// The failure this pins is quiet and expensive: a view whose class fell through to `Crud` would
/// consume one of the mutations a minute an operator is allowed, so a dashboard polling four
/// balances would exhaust the budget the operator needed to change a config with — and the refusal
/// would name the config change, not the polling.
#[test]
fn a_ledger_view_never_spends_a_mutation_slot() {
    for verb in crate::verb::LEDGER_VERBS {
        assert_eq!(
            crate::rate::MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            crate::rate::MutationClass::Forbidden,
            "{verb:?} is classified as a mutation"
        );
    }
    // The control: a verb that IS a mutation still classifies as one, so the green above is the
    // views being excluded rather than the classifier answering `Forbidden` to everything.
    assert_ne!(
        crate::rate::MutationClass::for_verb(KernelVerb::Adjust, CONFIG_CLASS_RULES),
        crate::rate::MutationClass::Forbidden
    );
}

/// An integrator who has bound no ledger serves nothing, and says so.
///
/// The default is what makes this addition additive: a `Governance` implementation written before
/// the views existed compiles unchanged and answers `NotFound` — which is true, because it has no
/// ledger behind it — rather than inventing zeros that would read as a deployment whose books
/// balance.
#[test]
fn an_unbound_integrator_serves_no_view_rather_than_an_empty_one() {
    struct NoLedger;
    impl Governance for NoLedger {
        fn execute_legacy(
            &self,
            _verb: KernelVerb,
            _admin: &Grant<AdminVerb>,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            Ok(Vec::new())
        }
        fn execute_new_verb(
            &self,
            _verb: KernelVerb,
            _admin: &Grant<AdminVerb>,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            Ok(Vec::new())
        }
        // `execute_ledger_read` is DELIBERATELY not written here. That absence is the test.
    }

    let admin = admin();
    let verbs = make_verbs(NoLedger);
    for verb in crate::verb::LEDGER_VERBS {
        let err = verbs
            .execute(*verb, &admin, "alice", VerbScope::ReadOnly, 0, b"")
            .unwrap_err();
        assert_eq!(err.reason, crate::refusal::ReasonCode::NotFound);
    }
}

/// AN AUDIT-CHAIN READ REACHES A SEAM AT ALL — which is the whole of this test.
///
/// The three verbs were mounted on the closed table before anything answered them. They resolved,
/// they carried the right scope and the right mutation class, and then `execute` fell past the
/// ledger branch and past the new-verb branch into the legacy catch-all, where the mounted
/// router answered a 404 for a path that release never had. A verb that resolves and then refuses
/// is worse than one that does not resolve: the table says the surface exists and the surface says
/// it does not.
///
/// The grant is the same one the ledger test uses, and for the same reason: a read-only grant
/// refuses every mutating verb, and the control below is one of those refused on the same
/// executor, so the green is the reads being reads rather than the scope check being unwired.
#[test]
fn an_audit_chain_read_reaches_the_read_seam_under_a_grant_that_refuses_every_mutation() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));

    for verb in crate::verb::AUDIT_VERBS {
        let body = verbs
            .execute(*verb, &admin, "alice", VerbScope::ReadOnly, 0, b"")
            .unwrap_or_else(|e| panic!("{verb:?} was refused: {e:?}"));
        assert_eq!(body, b"audit", "{verb:?} did not reach the audit read seam");
    }

    let refused = verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            b"",
        )
        .unwrap_err();
    assert_eq!(refused.reason, crate::refusal::ReasonCode::Unauthorized);

    let reached = log.lock().unwrap().clone();
    assert!(
        reached.iter().all(|(_, seam)| *seam == "audit"),
        "a chain read reached a seam that is not the audit one: {reached:?}"
    );
    assert_eq!(reached.len(), crate::verb::AUDIT_VERBS.len());
}

/// A chain read asks for exactly what the legacy `GET /audit` asks for, and no more.
///
/// A full-scope gate here would mean the only party who can check the evidence is the party the
/// evidence is about.
#[test]
fn an_audit_chain_read_requires_what_the_legacy_audit_read_requires() {
    for verb in crate::verb::AUDIT_VERBS {
        assert_eq!(
            crate::verbs::required_scope(*verb),
            crate::verbs::required_scope(KernelVerb::GetAudit),
            "{verb:?} does not require what /audit requires"
        );
        assert_eq!(crate::verbs::required_scope(*verb), VerbScope::ReadOnly);
    }
}

/// A chain read never spends a mutation slot: an auditor pulling a window must not exhaust the
/// budget an operator needs to change a config with.
#[test]
fn an_audit_chain_read_never_spends_a_mutation_slot() {
    for verb in crate::verb::AUDIT_VERBS {
        assert_eq!(
            crate::rate::MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            crate::rate::MutationClass::Forbidden,
            "{verb:?} is classified as a mutation"
        );
    }
    // The control: a verb that IS a mutation still classifies as one.
    assert_ne!(
        crate::rate::MutationClass::for_verb(KernelVerb::Adjust, CONFIG_CLASS_RULES),
        crate::rate::MutationClass::Forbidden
    );
}

/// An integrator who has bound no chain serves nothing, and says so.
///
/// `NotFound` rather than an empty head, and the distinction is the thirteenth instrument defect's
/// rule (`docs/design/BUSBAR-1.6.0.md:2079`): a node that has sealed nothing and a node nobody wired
/// a chain into are different facts, and an answer that cannot tell them apart is an instrument
/// reporting over nothing. A `Governance` written before these three verbs existed compiles
/// unchanged and answers the true thing.
#[test]
fn an_unbound_integrator_serves_no_chain_read_rather_than_an_empty_head() {
    struct NoChain;
    impl Governance for NoChain {
        fn execute_legacy(
            &self,
            _verb: KernelVerb,
            _admin: &Grant<AdminVerb>,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            Ok(Vec::new())
        }
        fn execute_new_verb(
            &self,
            _verb: KernelVerb,
            _admin: &Grant<AdminVerb>,
            _request: &[u8],
        ) -> Result<Vec<u8>, GovernanceError> {
            Ok(Vec::new())
        }
        // `execute_audit_read` is DELIBERATELY not written here. That absence is the test.
    }

    let admin = admin();
    let verbs = make_verbs(NoChain);
    for verb in crate::verb::AUDIT_VERBS {
        let err = verbs
            .execute(*verb, &admin, "alice", VerbScope::ReadOnly, 0, b"")
            .unwrap_err();
        assert_eq!(err.reason, crate::refusal::ReasonCode::NotFound);
    }
    // THE CONTROL that makes the three refusals mean something: the same executor answers a legacy
    // verb, so the `NotFound` above is the unbound chain and not a dead executor.
    assert_eq!(
        verbs
            .execute(
                KernelVerb::GetAudit,
                &admin,
                "alice",
                VerbScope::ReadOnly,
                0,
                b"",
            )
            .expect("the legacy audit read still answers"),
        Vec::<u8>::new()
    );
}

/// THE TWO MINTING VERBS ARE REFUSED ON THE GENERIC PATH, IN EVERY BUILD.
///
/// The two key mints are answered by the served handlers in `crate::keys`, which hold the replay
/// cache: a retry inside the window must return the first response rather than mint a second
/// credential. The generic dispatcher has none of that, so a caller that routes either verb through
/// it hands the mint straight to the legacy catch-all and every retry mints again — a fresh admin
/// credential per network hiccup, none of which the client asked for and only the last of which it
/// sees.
///
/// A `debug_assert` said so in debug builds and said nothing in a release binary, which is the one
/// build where it matters. The refusal is the same answer every other unresolvable precondition in
/// this crate gets, and it is the same one in both profiles.
#[test]
fn the_two_minting_verbs_are_refused_on_the_generic_dispatcher_rather_than_double_minting() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));

    for verb in [KernelVerb::PostKeys, KernelVerb::PostKeysIdRotate] {
        let Err(err) = verbs.execute(verb, &admin, "alice", VerbScope::Full, 0, b"{}") else {
            panic!("{verb:?} must not be served by the generic dispatcher");
        };
        assert_eq!(err.reason, crate::refusal::ReasonCode::Internal);
        assert_eq!(err.step, crate::refusal::RefusalStep::Admit);
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "a minting verb reached a governance seam through the generic path"
    );

    // The control: another legacy mutation on the same executor still reaches the legacy seam.
    verbs
        .execute(
            KernelVerb::PostGroups,
            &admin,
            "alice",
            VerbScope::Full,
            0,
            b"{}",
        )
        .expect("an ordinary legacy mutation is still served");
    assert_eq!(
        log.lock().unwrap().clone(),
        vec![(KernelVerb::PostGroups, "legacy")]
    );
}

/// The two 1.6.0 verbs the design binds as GETs are reads, and a read-only credential is what they
/// ask for.
///
/// `verify` and `plane_facts` are the two new verbs the architecture document binds as `GET`
/// — "GET for the two read-only verbs" — and everything that follows from a verb being a read
/// follows for them: an operator holding a read-only admin credential is answered. Demanding `full`
/// of them refuses the operator who was only ever allowed to look.
///
/// The control below is a mutating verb on the same executor, so the green above is these two
/// being reads rather than the scope check being unwired.
#[test]
fn the_two_read_only_new_verbs_answer_a_read_only_credential() {
    let admin = admin();
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));

    for verb in [KernelVerb::Verify, KernelVerb::PlaneFacts] {
        assert_eq!(
            crate::verbs::required_scope(verb),
            VerbScope::ReadOnly,
            "{verb:?} is bound as a GET and must ask what a read asks"
        );
        let body = verbs
            .execute(verb, &admin, "alice", VerbScope::ReadOnly, 0, b"")
            .unwrap_or_else(|e| panic!("{verb:?} was refused: {e:?}"));
        assert_eq!(body, b"new", "{verb:?} did not reach the new-verb seam");
    }

    // The control: a mutating new verb still needs `full`, and with it is admitted (#77(9): no
    // approval is waited for).
    let err = verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "alice",
            VerbScope::ReadOnly,
            0,
            b"",
        )
        .unwrap_err();
    assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);
    let body = verbs
        .execute(KernelVerb::Adjust, &admin, "alice", VerbScope::Full, 0, b"")
        .expect("a full grant admits a mutating new verb");
    assert_eq!(body, b"new");
}

/// A store that records which recovery primitive it was asked to perform, so a test can say
/// "nothing reached the store" and mean it rather than inferring it from a return value.
struct RecordingStore(Mutex<Vec<&'static str>>);

impl RecordingStore {
    fn new() -> Self {
        RecordingStore(Mutex::new(Vec::new()))
    }
    fn reached(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

impl Store for RecordingStore {
    fn chain_break(&self, _admin: &Grant<AdminVerb>) -> Result<(), StoreError> {
        self.0.lock().unwrap().push("chain_break");
        Ok(())
    }
    fn store_restore(
        &self,
        _admin: &Grant<AdminVerb>,
        _backup_ref: &str,
    ) -> Result<(), StoreError> {
        self.0.lock().unwrap().push("store_restore");
        Ok(())
    }
}

fn recovery_verbs() -> Verbs<FakeGovernance, RecordingStore> {
    Verbs::new(
        FakeGovernance::new(),
        Some(std::sync::Arc::new(RecordingStore::new())),
        CONFIG_CLASS_RULES,
        node_limiter(),
    )
}

/// The two disaster-recovery verbs are admitted before they reach the store, exactly as every
/// other new verb is admitted before it reaches governance.
///
/// Where a verb's effect lands is not a reason for it to be admitted differently: a read-only
/// caller is refused both, and the store is not touched. Handing the bound store out and
/// trusting the caller to gate it made the check optional.
#[test]
fn the_recovery_verbs_are_gated_before_anything_reaches_the_store() {
    let admin = admin();

    // A read-only caller is refused both.
    let v = recovery_verbs();
    for err in [
        v.chain_break(&admin, "alice", VerbScope::ReadOnly, 0)
            .unwrap_err(),
        v.store_restore(&admin, "alice", VerbScope::ReadOnly, 0, "backup-1")
            .unwrap_err(),
    ] {
        assert_eq!(err.reason, crate::refusal::ReasonCode::Unauthorized);
    }
    assert!(v.store_for_test().reached().is_empty());

    // Admitted, and only then does each one reach its own store primitive.
    let v = recovery_verbs();
    v.chain_break(&admin, "alice", VerbScope::Full, 0)
        .expect("admitted");
    v.store_restore(&admin, "alice", VerbScope::Full, 0, "backup-1")
        .expect("admitted");
    assert_eq!(
        v.store_for_test().reached(),
        vec!["chain_break", "store_restore"]
    );
}

/// A node with NO store (no governance configured) is handed `None`, and each disaster-recovery
/// verb, once admitted, is refused as a store failure: there is nothing for it to reach. The same
/// admitted verb over a bound store lands (the tests above), so the refusal is the absence alone.
#[test]
fn an_admitted_recovery_verb_on_a_node_with_no_store_is_a_store_failure() {
    let admin = admin();
    let v: Verbs<FakeGovernance, RecordingStore> = Verbs::new(
        FakeGovernance::new(),
        None,
        CONFIG_CLASS_RULES,
        node_limiter(),
    );
    let refused = [
        v.chain_break(&admin, "alice", VerbScope::Full, 0),
        v.store_restore(&admin, "alice", VerbScope::Full, 0, "backup-1"),
    ];
    for r in refused {
        assert_eq!(
            r.expect_err("no store, nothing to reach").reason,
            crate::refusal::ReasonCode::StoreError
        );
    }
}
