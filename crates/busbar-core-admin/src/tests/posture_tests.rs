// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Posture-rule assertions for the new verbs: an irreducible one is refused under
//! `operator: unset`; a mutating one is refused under `required` dual control without a matching,
//! non-self, payload-matching approval.

use crate::posture::{
    check_dual_control, check_new_verb_admission, check_operator_gate, ApprovalState, DualControl,
    OperatorState, PostureCtx,
};
use crate::refusal::ReasonCode;
use crate::verb::{KernelVerb, NEW_VERBS};

#[test]
fn every_irreducible_new_verb_is_refused_under_unset() {
    for verb in NEW_VERBS {
        let result = check_operator_gate(*verb, OperatorState::Unset);
        match verb {
            KernelVerb::PlaneFacts | KernelVerb::PlaneRecordWrite | KernelVerb::Verify => {
                // Not in the irreducible set: the operator gate never applies to these.
                assert!(
                    result.is_ok(),
                    "{verb:?} is not irreducible and must not be gated here"
                );
            }
            _ => {
                let err = result.unwrap_err();
                assert_eq!(
                    err.reason,
                    ReasonCode::OperatorUnset,
                    "{verb:?} must be refused OperatorUnset"
                );
            }
        }
    }
}

#[test]
fn every_new_verb_is_admitted_once_operator_is_set() {
    for verb in NEW_VERBS {
        assert!(check_operator_gate(*verb, OperatorState::Set([0u8; 32])).is_ok());
    }
}

#[test]
fn single_posture_admits_every_mutating_verb_with_no_approval() {
    assert!(check_dual_control(
        KernelVerb::PlaneRecordWrite,
        DualControl::Single,
        ApprovalState::NotYetApproved
    )
    .is_ok());
}

#[test]
fn required_posture_refuses_without_a_matching_approval() {
    let err = check_dual_control(
        KernelVerb::PlaneRecordWrite,
        DualControl::Required,
        ApprovalState::NotYetApproved,
    )
    .unwrap_err();
    assert_eq!(err.reason, ReasonCode::ApprovalPending);
}

#[test]
fn required_posture_admits_with_a_matching_approval() {
    assert!(check_dual_control(
        KernelVerb::PlaneRecordWrite,
        DualControl::Required,
        ApprovalState::Approved
    )
    .is_ok());
}

#[test]
fn required_posture_surfaces_self_approval_and_payload_mismatch() {
    let self_approved = check_dual_control(
        KernelVerb::PlaneRecordWrite,
        DualControl::Required,
        ApprovalState::SelfApproved,
    )
    .unwrap_err();
    assert_eq!(self_approved.reason, ReasonCode::SelfApproval);

    let mismatch = check_dual_control(
        KernelVerb::PlaneRecordWrite,
        DualControl::Required,
        ApprovalState::PayloadMismatch,
    )
    .unwrap_err();
    assert_eq!(mismatch.reason, ReasonCode::PayloadMismatch);
}

/// A read is not a mutation, so the maker-checker gate has nothing of its to hold.
///
/// The document scopes maker-checker to every mutating verb, and `verify`/`plane_facts` are the two
/// new verbs bound as GETs. Holding them behind an
/// approval does not delay them — it refuses them forever, because there is no pending mutation for
/// anyone to approve, and `verify` is precisely the check an operator runs to find out what state a
/// fleet under `required` is in.
#[test]
fn a_read_only_new_verb_is_not_held_by_the_maker_checker_gate() {
    for verb in [KernelVerb::Verify, KernelVerb::PlaneFacts] {
        assert!(
            check_dual_control(verb, DualControl::Required, ApprovalState::NotYetApproved).is_ok(),
            "{verb:?} is a read and has no mutation for a checker to approve"
        );
    }
    // The control: a mutating verb on the same gate still waits.
    assert_eq!(
        check_dual_control(
            KernelVerb::PlaneRecordWrite,
            DualControl::Required,
            ApprovalState::NotYetApproved
        )
        .unwrap_err()
        .reason,
        ReasonCode::ApprovalPending
    );
}

#[test]
fn full_admission_checks_operator_before_dual_control() {
    // Under `unset`, a non-admitted irreducible verb is refused OperatorUnset even though dual
    // control would otherwise admit it under `Single`.
    let ctx = PostureCtx {
        operator: OperatorState::Unset,
        dual_control: DualControl::Single,
    };
    let err = check_new_verb_admission(
        KernelVerb::CommitUpgrade,
        ctx,
        ApprovalState::NotYetApproved,
    )
    .unwrap_err();
    assert_eq!(err.reason, ReasonCode::OperatorUnset);
}
