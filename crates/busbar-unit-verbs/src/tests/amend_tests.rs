// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The amendment verb's own invariants, each one asserted against a history double that records
//! exactly what reached it — because "no figure moved" is a claim about what did NOT happen, and the
//! only way to make it a test is to count the calls that would have moved one.

use crate::amend::{
    canonical_payload, check_card_complete, check_interval, replay_slot, AmendIdentity,
    AmendOutcome, AmendReceipt, AmendRequest, HistoryBounds, RateHistory,
};
use crate::governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
use crate::idempotency::ReplayEncoder;
use crate::posture::{ApprovalState, DualControl, OperatorState, PostureCtx};
use crate::rate::CONFIG_CLASS_RULES;
use crate::refusal::{ReasonCode, RefusalStep};
use crate::store::{Store, StoreError};
use crate::verb::{KernelVerb, VerbScope, IRREDUCIBLE_VERBS, LEDGER_VERBS, NEW_VERBS};
use crate::verbs::{MintedKeyOutcome, NonceSource, Verbs};
use busbar_caps::{AdminToken, KernelSeal};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

// ── the doubles ────────────────────────────────────────────────────────────────────────────────

/// A history double that answers fixed bounds, accepts exactly one signature, and COUNTS the
/// amendments that reached it. The count is the whole point: every refusal test below asserts it is
/// still zero, which is the only honest way to say "no figure moved".
struct FakeHistory {
    bounds: Mutex<HistoryBounds>,
    /// The one signature that verifies, for the one fingerprint that owns it.
    good_signature: Vec<u8>,
    good_fingerprint: String,
    applied: Mutex<Vec<Vec<u8>>>,
    next_seq: AtomicU64,
    fails_with: Mutex<Option<GovernanceError>>,
    bounds_fail: Mutex<bool>,
}

impl FakeHistory {
    fn new() -> Self {
        FakeHistory {
            bounds: Mutex::new(HistoryBounds {
                head: 3,
                opening_effective_from: 1_000,
                newest_amend: None,
            }),
            good_signature: b"a-real-operator-signature".to_vec(),
            good_fingerprint: "op-7f".to_string(),
            applied: Mutex::new(Vec::new()),
            next_seq: AtomicU64::new(4),
            fails_with: Mutex::new(None),
            bounds_fail: Mutex::new(false),
        }
    }

    fn with_newest_amend(self, identity: AmendIdentity) -> Self {
        self.bounds.lock().unwrap().newest_amend = Some(identity);
        self
    }

    fn with_opening_at(self, ms: u64) -> Self {
        self.bounds.lock().unwrap().opening_effective_from = ms;
        self
    }

    /// How many amendments actually landed.
    fn applied_count(&self) -> usize {
        self.applied.lock().unwrap().len()
    }
}

impl RateHistory for FakeHistory {
    fn bounds(&self) -> Result<HistoryBounds, GovernanceError> {
        if *self.bounds_fail.lock().unwrap() {
            return Err(GovernanceError::Store);
        }
        Ok(self.bounds.lock().unwrap().clone())
    }

    fn verify_operator_signature(
        &self,
        fingerprint: &str,
        _canonical: &[u8],
        signature: &[u8],
    ) -> bool {
        fingerprint == self.good_fingerprint && signature == self.good_signature
    }

    fn apply_amendment(
        &self,
        _admin: &AdminToken,
        _request: &AmendRequest<'_>,
        canonical: &[u8],
    ) -> Result<AmendReceipt, GovernanceError> {
        if let Some(e) = self.fails_with.lock().unwrap().take() {
            return Err(e);
        }
        self.applied.lock().unwrap().push(canonical.to_vec());
        Ok(AmendReceipt {
            history_seq: self.next_seq.fetch_add(1, Ordering::SeqCst),
            entries_adjusted: 2,
            deltas: vec![("USD".to_string(), 4_200)],
        })
    }
}

struct SilentGovernance;

impl Governance for SilentGovernance {
    fn group_exists(&self, _name: &str) -> bool {
        false
    }
    fn actual_parent(&self, _name: &str) -> Option<String> {
        None
    }
    fn provision_group(
        &self,
        _admin: &AdminToken,
        _group: &str,
        _parent: &str,
    ) -> Result<(), GovernanceError> {
        Err(GovernanceError::Validation)
    }
    fn mint_key(
        &self,
        _admin: &AdminToken,
        _group: Option<&str>,
    ) -> Result<MintedKey, GovernanceError> {
        Err(GovernanceError::Validation)
    }
    fn rotate_key(&self, _admin: &AdminToken, _id: &str) -> Result<RotateOutcome, GovernanceError> {
        Ok(RotateOutcome::NotFound)
    }
    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        Ok(Vec::new())
    }
    fn execute_new_verb(
        &self,
        _verb: KernelVerb,
        _admin: &AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, GovernanceError> {
        Ok(Vec::new())
    }
}

struct NoStore;

impl Store for NoStore {
    fn chain_break(&self, _admin: &AdminToken) -> Result<(), StoreError> {
        Ok(())
    }
    fn store_restore(&self, _admin: &AdminToken, _backup_ref: &str) -> Result<(), StoreError> {
        Ok(())
    }
    fn reseal_epoch_floor(&self, _admin: &AdminToken) -> Result<(), StoreError> {
        Ok(())
    }
    fn replay_new_verb(&self, _key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(None)
    }
    fn commit_new_verb_replay(
        &self,
        _key: &(String, String),
        _response: &[u8],
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

struct ZeroNonce;

impl NonceSource for ZeroNonce {
    fn fill(&self, buf: &mut [u8; 16]) {
        buf.fill(0);
    }
}

struct NoEncoder;

impl ReplayEncoder<MintedKeyOutcome> for NoEncoder {
    fn encode(&self, _value: &MintedKeyOutcome) -> Vec<u8> {
        Vec::new()
    }
}

fn make_verbs() -> Verbs<SilentGovernance, NoStore, ZeroNonce, NoEncoder> {
    Verbs::new(
        SilentGovernance,
        NoStore,
        ZeroNonce,
        NoEncoder,
        CONFIG_CLASS_RULES,
    )
}

fn admin() -> AdminToken {
    AdminToken::mint(&KernelSeal::acquire_for_kernel())
}

/// The posture a fleet that has run the ceremony and is in `single` is in.
fn ready() -> PostureCtx {
    PostureCtx {
        operator: OperatorState::Set,
        dual_control: DualControl::Single,
    }
}

const NOW_MS: u64 = 5_000;

fn signed_request<'a>(history: &'a FakeHistory) -> AmendRequest<'a> {
    AmendRequest {
        from_ms: 2_000,
        until_ms: Some(3_000),
        card_hash: [7u8; 32],
        card_complete: true,
        reason_hash: [9u8; 32],
        operator_fingerprint: &history.good_fingerprint,
        signature: &history.good_signature,
    }
}

/// Run one amendment through the full executor at the ready posture.
fn amend(
    verbs: &Verbs<SilentGovernance, NoStore, ZeroNonce, NoEncoder>,
    history: &FakeHistory,
    request: &AmendRequest<'_>,
    idempotency_key: Option<&str>,
) -> Result<AmendOutcome, crate::refusal::Refusal> {
    verbs.amend_rate_history(
        history,
        &admin(),
        "alice",
        VerbScope::Full,
        0,
        Some(ready()),
        ApprovalState::NotYetApproved,
        idempotency_key,
        request,
        NOW_MS,
    )
}

// ── the table ──────────────────────────────────────────────────────────────────────────────────

/// The verb is one of the eighteen and it is irreducible in both postures. A verb missing from the
/// irreducible set is one a fleet under `operator: unset` would admit, which is a full-scope
/// credential repricing a booked window on a node that has never run the ceremony. A verb missing
/// from the new-verb set is worse: it would fall through `required_scope` to `ReadOnly` and reach no
/// posture gate at all.
#[test]
fn the_amend_verb_is_a_new_verb_and_an_irreducible_one() {
    assert!(NEW_VERBS.contains(&KernelVerb::AmendRateHistory));
    assert_eq!(NEW_VERBS.len(), 18);
    assert!(IRREDUCIBLE_VERBS.contains(&KernelVerb::AmendRateHistory));
    assert_eq!(
        crate::verbs::required_scope(KernelVerb::AmendRateHistory),
        VerbScope::Full
    );
    // The views the amendment sits beside are unchanged in number and in rung: this verb joined
    // their path prefix, not their list.
    assert_eq!(LEDGER_VERBS.len(), 5);
    assert!(!LEDGER_VERBS.contains(&KernelVerb::AmendRateHistory));
}

/// An amendment spends a mutation slot, and the reads it sits beside still do not.
#[test]
fn the_amendment_spends_a_mutation_budget_and_the_views_still_do_not() {
    for verb in LEDGER_VERBS {
        assert_eq!(
            crate::rate::MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            crate::rate::MutationClass::Forbidden
        );
    }
    assert_eq!(
        crate::rate::MutationClass::for_verb(KernelVerb::AmendRateHistory, CONFIG_CLASS_RULES),
        crate::rate::MutationClass::Crud
    );
}

// ── the canonical payload and the slot key ─────────────────────────────────────────────────────

/// Two amendments that differ only in where one field ends and the next begins must not produce one
/// payload. Joined on a separator, `("op:1", from 2)` and `("op", from "1:2")` are one string, and a
/// signature over one would verify against the other.
#[test]
fn the_canonical_payload_frames_every_field_by_its_own_length() {
    let a = AmendRequest {
        from_ms: 2_000,
        until_ms: Some(3_000),
        card_hash: [1u8; 32],
        card_complete: true,
        reason_hash: [2u8; 32],
        operator_fingerprint: "op:2000",
        signature: b"sig",
    };
    let b = AmendRequest {
        operator_fingerprint: "op",
        ..a
    };
    assert_ne!(canonical_payload(&a), canonical_payload(&b));

    // An open-ended amendment and one that ends at instant 0 are different amendments and must not
    // encode alike.
    let open = AmendRequest {
        until_ms: None,
        from_ms: 0,
        ..a
    };
    let bounded = AmendRequest {
        until_ms: Some(0),
        from_ms: 0,
        ..a
    };
    assert_ne!(canonical_payload(&open), canonical_payload(&bounded));
}

/// The replay slot carries the payload as well as the header value, and it length-frames both. A
/// second amendment sent under a header value the caller reused must not replay the first's
/// receipt: the seq and the delta in it belong to a window this call never named.
#[test]
fn the_replay_slot_never_collapses_two_amendments_onto_one_key() {
    let a = AmendRequest {
        from_ms: 2_000,
        until_ms: Some(3_000),
        card_hash: [1u8; 32],
        card_complete: true,
        reason_hash: [2u8; 32],
        operator_fingerprint: "op",
        signature: b"sig",
    };
    let b = AmendRequest {
        from_ms: 2_001,
        ..a
    };
    assert_ne!(
        replay_slot(&canonical_payload(&a), "k"),
        replay_slot(&canonical_payload(&b), "k")
    );
    // And two header values that differ only in where the boundary falls stay apart.
    let p = canonical_payload(&a);
    assert_ne!(replay_slot(&p, "1:2"), replay_slot(&p, "1:2:"));
}

// ── the refusals ───────────────────────────────────────────────────────────────────────────────

/// **No valid operator signature, no amendment** — and nothing reached the history.
#[test]
fn an_unsigned_amendment_is_refused_and_moves_nothing() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = AmendRequest {
        signature: b"",
        ..signed_request(&history)
    };
    let err = amend(&verbs, &history, &request, None).unwrap_err();
    assert_eq!(err.step, RefusalStep::Approve);
    assert_eq!(err.reason, ReasonCode::OperatorSignatureInvalid);
    assert_eq!(history.applied_count(), 0);
}

/// A signature that verifies for somebody else is not this operator's authority.
#[test]
fn a_signature_from_another_fingerprint_is_refused() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = AmendRequest {
        operator_fingerprint: "op-other",
        ..signed_request(&history)
    };
    let err = amend(&verbs, &history, &request, None).unwrap_err();
    assert_eq!(err.reason, ReasonCode::OperatorSignatureInvalid);
    assert_eq!(history.applied_count(), 0);
}

/// A partial card prices the classes it is silent about at nothing — which on this path would
/// under-bill a window that has already been invoiced.
#[test]
fn a_partial_card_is_refused() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = AmendRequest {
        card_complete: false,
        ..signed_request(&history)
    };
    let err = amend(&verbs, &history, &request, None).unwrap_err();
    assert_eq!(err.reason, ReasonCode::Validation);
    assert_eq!(history.applied_count(), 0);
}

/// A `from` in the future is the config `PUT`, not an amendment.
#[test]
fn a_future_from_is_refused() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = AmendRequest {
        from_ms: NOW_MS + 1,
        until_ms: None,
        ..signed_request(&history)
    };
    let err = amend(&verbs, &history, &request, None).unwrap_err();
    assert_eq!(err.reason, ReasonCode::Validation);
    assert_eq!(history.applied_count(), 0);
    // and the instant `now` itself is not the future.
    let at_now = AmendRequest {
        from_ms: NOW_MS,
        until_ms: None,
        ..signed_request(&history)
    };
    assert!(amend(&verbs, &history, &at_now, None).is_ok());
}

/// An entry dated before the opening claims instants the history has no opening for.
#[test]
fn an_entry_that_predates_the_opening_is_refused() {
    let verbs = make_verbs();
    let history = FakeHistory::new().with_opening_at(2_000);
    let request = AmendRequest {
        from_ms: 1_999,
        ..signed_request(&history)
    };
    let err = amend(&verbs, &history, &request, None).unwrap_err();
    assert_eq!(err.reason, ReasonCode::PredatesOpening);
    assert_eq!(history.applied_count(), 0);
    // The opening's own instant is inside the history, not before it.
    let at_opening = AmendRequest {
        from_ms: 2_000,
        until_ms: Some(2_500),
        ..signed_request(&history)
    };
    assert!(amend(&verbs, &history, &at_opening, None).is_ok());
}

/// An interval that covers no instant is a claim to have repriced a window while repricing nothing.
#[test]
fn an_interval_that_covers_no_instant_is_refused_as_a_hole() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    for until in [2_000u64, 1_999] {
        let request = AmendRequest {
            from_ms: 2_000,
            until_ms: Some(until),
            ..signed_request(&history)
        };
        let err = amend(&verbs, &history, &request, None).unwrap_err();
        assert_eq!(err.reason, ReasonCode::HistoryHole, "until={until}");
    }
    assert_eq!(history.applied_count(), 0);
}

/// A fleet that has never run the operator ceremony refuses the verb outright, because it is in the
/// irreducible set and is not one of the two admitted under `unset`.
#[test]
fn an_unset_operator_refuses_the_amendment() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = signed_request(&history);
    let err = verbs
        .amend_rate_history(
            &history,
            &admin(),
            "alice",
            VerbScope::Full,
            0,
            Some(PostureCtx {
                operator: OperatorState::Unset,
                dual_control: DualControl::Single,
            }),
            ApprovalState::NotYetApproved,
            None,
            &request,
            NOW_MS,
        )
        .unwrap_err();
    assert_eq!(err.reason, ReasonCode::OperatorUnset);
    assert_eq!(history.applied_count(), 0);
}

/// Under `required` dual control the amendment waits for a checker, like every other mutation.
#[test]
fn required_dual_control_holds_the_amendment_until_a_checker_approves() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = signed_request(&history);
    let pending = PostureCtx {
        operator: OperatorState::Set,
        dual_control: DualControl::Required,
    };
    let err = verbs
        .amend_rate_history(
            &history,
            &admin(),
            "alice",
            VerbScope::Full,
            0,
            Some(pending),
            ApprovalState::NotYetApproved,
            None,
            &request,
            NOW_MS,
        )
        .unwrap_err();
    assert_eq!(err.reason, ReasonCode::ApprovalPending);
    assert_eq!(history.applied_count(), 0);

    verbs
        .amend_rate_history(
            &history,
            &admin(),
            "alice",
            VerbScope::Full,
            0,
            Some(pending),
            ApprovalState::Approved,
            None,
            &request,
            NOW_MS,
        )
        .expect("an approved amendment applies");
    assert_eq!(history.applied_count(), 1);
}

/// A read-only credential never amends.
#[test]
fn a_read_only_credential_is_refused() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = signed_request(&history);
    let err = verbs
        .amend_rate_history(
            &history,
            &admin(),
            "alice",
            VerbScope::ReadOnly,
            0,
            Some(ready()),
            ApprovalState::NotYetApproved,
            None,
            &request,
            NOW_MS,
        )
        .unwrap_err();
    assert_eq!(err.reason, ReasonCode::Unauthorized);
    assert_eq!(history.applied_count(), 0);
}

/// The generic dispatch refuses the verb in every build. Routed through it, an amendment would
/// reach the new-verb catch-all with no signature checked at all.
#[test]
fn the_generic_dispatch_refuses_the_amendment_in_every_build() {
    let verbs = make_verbs();
    let err = verbs
        .execute(
            KernelVerb::AmendRateHistory,
            &admin(),
            "alice",
            VerbScope::Full,
            0,
            Some(ready()),
            ApprovalState::NotYetApproved,
            b"{}",
        )
        .unwrap_err();
    assert_eq!(err.step, RefusalStep::Admit);
    assert_eq!(err.reason, ReasonCode::Internal);
}

// ── the idempotencies ──────────────────────────────────────────────────────────────────────────

/// A re-sent amendment whose payload equals the newest `Amend` entry is a no-op returning the seq it
/// already produced — with no `Idempotency-Key` anywhere in sight, because this idempotency is a
/// fact about the sealed history rather than about this process's memory.
#[test]
fn a_payload_equal_to_the_newest_amendment_is_a_no_op_returning_the_existing_seq() {
    let verbs = make_verbs();
    let history = FakeHistory::new().with_newest_amend(AmendIdentity {
        from_ms: 2_000,
        until_ms: Some(3_000),
        card_hash: [7u8; 32],
        operator_fingerprint: "op-7f".to_string(),
        history_seq: 11,
    });
    let request = signed_request(&history);
    let outcome = amend(&verbs, &history, &request, None).expect("a replay is not a refusal");
    assert_eq!(outcome, AmendOutcome::AlreadyAmended { history_seq: 11 });
    assert!(!outcome.appended());
    assert_eq!(history.applied_count(), 0);
}

/// A DIFFERENT amendment over the same window is not that amendment said twice: both apply, and the
/// second is a fresh append.
#[test]
fn a_different_amendment_over_the_same_window_still_applies() {
    let verbs = make_verbs();
    let history = FakeHistory::new().with_newest_amend(AmendIdentity {
        from_ms: 2_000,
        until_ms: Some(3_000),
        card_hash: [7u8; 32],
        operator_fingerprint: "op-7f".to_string(),
        history_seq: 11,
    });
    // Same window, same operator, a different card.
    let request = AmendRequest {
        card_hash: [8u8; 32],
        ..signed_request(&history)
    };
    let outcome = amend(&verbs, &history, &request, None).expect("a second amendment applies");
    assert!(outcome.appended());
    assert_eq!(history.applied_count(), 1);
}

/// The `Idempotency-Key` slot replays the receipt verbatim and appends nothing a second time.
#[test]
fn an_idempotency_key_replay_appends_nothing_and_returns_the_same_receipt() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let request = signed_request(&history);
    let first = amend(&verbs, &history, &request, Some("k-1")).expect("first applies");
    let second = amend(&verbs, &history, &request, Some("k-1")).expect("second replays");
    assert!(first.appended());
    assert!(!second.appended());
    assert_eq!(first.history_seq(), second.history_seq());
    assert_eq!(history.applied_count(), 1);
}

/// Two DIFFERENT amendments sharing one header value must not replay each other — the slot carries
/// the payload too.
#[test]
fn two_amendments_sharing_a_header_value_do_not_replay_each_other() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    let first_req = signed_request(&history);
    let second_req = AmendRequest {
        from_ms: 3_500,
        until_ms: Some(4_000),
        ..signed_request(&history)
    };
    let first = amend(&verbs, &history, &first_req, Some("same-key")).expect("first applies");
    let second = amend(&verbs, &history, &second_req, Some("same-key")).expect("second applies");
    assert!(first.appended());
    assert!(second.appended(), "the second amendment replayed the first");
    assert_ne!(first.history_seq(), second.history_seq());
    assert_eq!(history.applied_count(), 2);
}

/// A failed apply frees the slot: the amendment never landed, so a retry must be allowed to run it.
#[test]
fn a_failed_apply_frees_the_replay_slot() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    *history.fails_with.lock().unwrap() = Some(GovernanceError::Store);
    let request = signed_request(&history);
    let err = amend(&verbs, &history, &request, Some("k-2")).unwrap_err();
    assert_eq!(err.reason, ReasonCode::StoreError);
    assert_eq!(history.applied_count(), 0);
    let retry = amend(&verbs, &history, &request, Some("k-2")).expect("a retry may run it");
    assert!(retry.appended());
    assert_eq!(history.applied_count(), 1);
}

/// A history the node cannot read refuses the amendment rather than appending against a guessed
/// head.
#[test]
fn an_unreadable_history_refuses_rather_than_guessing_a_head() {
    let verbs = make_verbs();
    let history = FakeHistory::new();
    *history.bounds_fail.lock().unwrap() = true;
    let request = signed_request(&history);
    let err = amend(&verbs, &history, &request, None).unwrap_err();
    assert_eq!(err.reason, ReasonCode::StoreError);
    assert_eq!(history.applied_count(), 0);
}

// ── the pure checks, directly ──────────────────────────────────────────────────────────────────

/// The interval rules, exercised without the executor around them, so a change to either can be
/// attributed to the one that changed.
#[test]
fn the_interval_rules_stand_on_their_own() {
    let bounds = HistoryBounds {
        head: 2,
        opening_effective_from: 100,
        newest_amend: None,
    };
    let base = AmendRequest {
        from_ms: 200,
        until_ms: Some(300),
        card_hash: [0u8; 32],
        card_complete: true,
        reason_hash: [0u8; 32],
        operator_fingerprint: "op",
        signature: b"s",
    };
    assert!(check_interval(&base, &bounds, 1_000).is_ok());
    // An open-ended back-dated amendment is legal: it out-ranks what it corrects from `from` on.
    assert!(check_interval(
        &AmendRequest {
            until_ms: None,
            ..base
        },
        &bounds,
        1_000
    )
    .is_ok());
    assert_eq!(
        check_interval(
            &AmendRequest {
                from_ms: 99,
                ..base
            },
            &bounds,
            1_000
        )
        .unwrap_err()
        .reason,
        ReasonCode::PredatesOpening
    );
    assert_eq!(
        check_interval(&base, &bounds, 199).unwrap_err().reason,
        ReasonCode::Validation
    );
    assert!(check_card_complete(&base).is_ok());
    assert_eq!(
        check_card_complete(&AmendRequest {
            card_complete: false,
            ..base
        })
        .unwrap_err()
        .reason,
        ReasonCode::Validation
    );
}
