// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::governance::{Governance, GovernanceError};
use crate::rate::CONFIG_CLASS_RULES;
use crate::verb::{KernelVerb, VerbScope};
use crate::verbs::Verbs;
use busbar_contract::caps::{AdminVerb, Grant};
use busbar_kernel_seams::verb_store::{Store, StoreError};
use std::sync::Mutex;

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

    fails_with: Mutex<Option<GovernanceError>>,
}

impl FakeGovernance {
    fn new() -> Self {
        FakeGovernance {
            new_verb_calls: Mutex::new(Vec::new()),
            fails_with: Mutex::new(None),
        }
    }

    fn failing_with(self, error: GovernanceError) -> Self {
        *self.fails_with.lock().unwrap() = Some(error);
        self
    }

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
    type Answer = Vec<u8>;

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
    busbar_kernel::teller::Kernel::new().admin_token()
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
    let log: SeamLog = std::sync::Arc::new(Mutex::new(Vec::new()));
    let verbs = make_verbs(RoutingGovernance(std::sync::Arc::clone(&log)));
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
    assert_eq!(out, b"new");
    assert_eq!(
        *log.lock().unwrap(),
        vec![(KernelVerb::PlaneRecordWrite, "new")]
    );
}

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

#[test]
fn a_governance_store_failure_refuses_with_store_error_on_every_call() {
    let admin = admin();

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

type SeamLog = std::sync::Arc<Mutex<Vec<(KernelVerb, &'static str)>>>;

struct RoutingGovernance(SeamLog);

impl Governance for RoutingGovernance {
    type Answer = Vec<u8>;

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

#[test]
fn a_ledger_view_never_spends_a_mutation_slot() {
    for verb in crate::verb::LEDGER_VERBS {
        assert_eq!(
            crate::rate::MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            crate::rate::MutationClass::Forbidden,
            "{verb:?} is classified as a mutation"
        );
    }

    assert_ne!(
        crate::rate::MutationClass::for_verb(KernelVerb::Adjust, CONFIG_CLASS_RULES),
        crate::rate::MutationClass::Forbidden
    );
}

#[test]
fn an_unbound_integrator_serves_no_view_rather_than_an_empty_one() {
    struct NoLedger;
    impl Governance for NoLedger {
        type Answer = Vec<u8>;

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

#[test]
fn an_audit_chain_read_never_spends_a_mutation_slot() {
    for verb in crate::verb::AUDIT_VERBS {
        assert_eq!(
            crate::rate::MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            crate::rate::MutationClass::Forbidden,
            "{verb:?} is classified as a mutation"
        );
    }

    assert_ne!(
        crate::rate::MutationClass::for_verb(KernelVerb::Adjust, CONFIG_CLASS_RULES),
        crate::rate::MutationClass::Forbidden
    );
}

#[test]
fn an_unbound_integrator_serves_no_chain_read_rather_than_an_empty_head() {
    struct NoChain;
    impl Governance for NoChain {
        type Answer = Vec<u8>;

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
    }

    let admin = admin();
    let verbs = make_verbs(NoChain);
    for verb in crate::verb::AUDIT_VERBS {
        let err = verbs
            .execute(*verb, &admin, "alice", VerbScope::ReadOnly, 0, b"")
            .unwrap_err();
        assert_eq!(err.reason, crate::refusal::ReasonCode::NotFound);
    }

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

#[test]
fn the_recovery_verbs_are_gated_before_anything_reaches_the_store() {
    let admin = admin();

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
