// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Posture-rule assertions for the 17 new verbs: refused under `operator: unset` except
//! `set_operator_key` and `export_keyset`; refused under `required` dual control without a
//! matching, non-self, payload-matching `approve`; `approve` itself is never subject to the
//! dual-control gate.

use crate::posture::{
    check_approve, check_dual_control, check_new_verb_admission, check_operator_gate,
    check_set_dual_control_required, ApprovalState, DualControl, OperatorState, PostureCtx,
};
use crate::refusal::ReasonCode;
use crate::verb::{KernelVerb, NEW_VERBS};

#[test]
fn every_new_verb_except_set_operator_key_and_export_keyset_is_refused_under_unset() {
    for verb in NEW_VERBS {
        let result = check_operator_gate(*verb, OperatorState::Unset);
        match verb {
            KernelVerb::SetOperatorKey | KernelVerb::ExportKeyset => {
                assert!(result.is_ok(), "{verb:?} must be admitted under unset");
            }
            KernelVerb::PlaneFacts
            | KernelVerb::PlaneRecordWrite
            | KernelVerb::SetOverdraftCeiling
            | KernelVerb::SetDisputeMaxAge
            | KernelVerb::ResolveSlice
            | KernelVerb::Approve
            | KernelVerb::Verify => {
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
        assert!(check_operator_gate(*verb, OperatorState::Set).is_ok());
    }
}

#[test]
fn single_posture_admits_every_mutating_verb_with_no_approval() {
    assert!(check_dual_control(
        KernelVerb::SetEscrow,
        DualControl::Single,
        ApprovalState::NotYetApproved
    )
    .is_ok());
}

#[test]
fn required_posture_refuses_without_a_matching_approval() {
    let err = check_dual_control(
        KernelVerb::SetEscrow,
        DualControl::Required,
        ApprovalState::NotYetApproved,
    )
    .unwrap_err();
    assert_eq!(err.reason, ReasonCode::ApprovalPending);
}

#[test]
fn required_posture_admits_with_a_matching_approval() {
    assert!(check_dual_control(
        KernelVerb::SetEscrow,
        DualControl::Required,
        ApprovalState::Approved
    )
    .is_ok());
}

#[test]
fn required_posture_surfaces_self_approval_and_payload_mismatch() {
    let self_approved = check_dual_control(
        KernelVerb::SetEscrow,
        DualControl::Required,
        ApprovalState::SelfApproved,
    )
    .unwrap_err();
    assert_eq!(self_approved.reason, ReasonCode::SelfApproval);

    let mismatch = check_dual_control(
        KernelVerb::SetEscrow,
        DualControl::Required,
        ApprovalState::PayloadMismatch,
    )
    .unwrap_err();
    assert_eq!(mismatch.reason, ReasonCode::PayloadMismatch);
}

#[test]
fn approve_itself_is_never_subject_to_the_dual_control_gate() {
    // Even with `NotYetApproved` (nonsensical for `approve`, but the gate must exempt the verb
    // outright rather than rely on the caller never passing that combination).
    assert!(check_dual_control(
        KernelVerb::Approve,
        DualControl::Required,
        ApprovalState::NotYetApproved
    )
    .is_ok());
}

#[test]
fn check_approve_refuses_self_approval() {
    let err = check_approve("alice", "alice", true).unwrap_err();
    assert_eq!(err.reason, ReasonCode::SelfApproval);
}

#[test]
fn check_approve_refuses_payload_mismatch() {
    let err = check_approve("alice", "bob", false).unwrap_err();
    assert_eq!(err.reason, ReasonCode::PayloadMismatch);
}

#[test]
fn check_approve_admits_a_different_approver_with_a_matching_payload() {
    assert!(check_approve("alice", "bob", true).is_ok());
}

#[test]
fn set_dual_control_required_needs_at_least_two_admin_principals() {
    // The reason, not just the refusal: an operator locking themselves out of their own node needs
    // to be told which precondition they missed, and every other test in this file pins the code
    // its call site returns.
    let err = check_set_dual_control_required(1).unwrap_err();
    assert_eq!(err.reason, ReasonCode::InsufficientApprovers);
    assert_eq!(check_set_dual_control_required(0).unwrap_err().reason, ReasonCode::InsufficientApprovers);
    assert!(check_set_dual_control_required(2).is_ok());
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
