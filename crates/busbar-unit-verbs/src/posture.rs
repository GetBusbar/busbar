// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dual-control posture and the operator-key ceremony gate, for the 17 new 1.6.0 verbs.
//!
//! Two independent gates, both sealed at `Bootstrap` and both read here as plain values the
//! integrator resolves from the sealed `Policy` (the resolution itself — reading the journal — is a
//! `// contract:` seam; see `the integrator's policy read`):
//!
//! - **Operator state.** `unset` (no ceremony run yet) refuses every irreducible verb except
//!   [`KernelVerb::SetOperatorKey`] and [`KernelVerb::ExportKeyset`] — the two verbs a fleet needs
//!   to run the ceremony and to back up its keyset first. `set` lifts that refusal.
//! - **Dual-control posture.** `single` (the default on upgrade and on a fresh install) admits
//!   every verb immediately. `required` needs a matching `approve` for every mutating verb except
//!   `approve` itself, whose only controls are payload-hash equality and the `SelfApproval`
//!   refusal.
//!
//! Both gates apply to the SAME verb call in sequence: operator state is checked first (it is the
//! narrower, harder failure — a fleet that has never run the ceremony has no meaningful
//! maker-checker state to check either), then dual-control posture.

use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use crate::verb::{KernelVerb, ADMITTED_UNDER_UNSET, IRREDUCIBLE_VERBS};

/// Whether the operator-key ceremony (`busbar operator keygen` + `set_operator_key`) has run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorState {
    /// No operator key configured yet — sealed at `Bootstrap` when `operator.pub` is absent.
    Unset,
    /// An operator public key is sealed in `Policy`.
    Set,
}

/// The dual-control posture, sealed at `Bootstrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualControl {
    /// Every verb applies immediately (1.5.5's operating posture; the default on upgrade and on a
    /// fresh install).
    Single,
    /// Every mutating verb except `approve` needs a matching maker-checker approval first.
    Required,
}

/// The resolved posture state a verb call is checked against. The integrator builds this from the
/// sealed `Policy` (see `// contract:` in `the integrator's policy read`) once per
/// call, or caches it per config generation — this crate takes no position on that, it only reads
/// the two fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostureCtx {
    /// The operator-ceremony state.
    pub operator: OperatorState,
    /// The dual-control posture.
    pub dual_control: DualControl,
}

/// Whether an `approve` exists for this pending mutation, and (when it does) whether it is valid:
/// its payload hash equals the pending mutation's, and its approver differs from the maker. The
/// integrator resolves this from the pending-approval journal entry (`// contract:`); this crate
/// only names the three outcomes the architecture document names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    /// No `approve` has been recorded yet for this pending mutation.
    NotYetApproved,
    /// An `approve` was recorded whose payload hash matches and whose approver differs from the
    /// maker.
    Approved,
    /// An `approve` was recorded but its approver is the same principal as the maker
    /// (`Refused(Approve, SelfApproval)`).
    SelfApproved,
    /// An `approve` was recorded but its payload hash does not equal the pending mutation's
    /// (`Refused(Approve, PayloadMismatch)`).
    PayloadMismatch,
}

/// Check the operator-ceremony gate for an irreducible verb. Returns `Ok(())` when the verb is
/// either not irreducible, or irreducible and admitted (operator set, or one of the two verbs
/// admitted under `unset`). A verb this crate does not classify as irreducible is never refused
/// here regardless of operator state — this gate is scoped to exactly the closed
/// [`IRREDUCIBLE_VERBS`] list.
pub fn check_operator_gate(verb: KernelVerb, operator: OperatorState) -> Result<(), Refusal> {
    if operator == OperatorState::Set {
        return Ok(());
    }
    if !IRREDUCIBLE_VERBS.contains(&verb) {
        return Ok(());
    }
    if ADMITTED_UNDER_UNSET.contains(&verb) {
        return Ok(());
    }
    Err(Refusal::new(RefusalStep::Admit, ReasonCode::OperatorUnset))
}

/// Check the dual-control gate for a mutating verb, given the caller's own [`ApprovalState`] for
/// the pending mutation (irrelevant, and never consulted, under `Single`). `approve` itself is
/// never subject to this gate (the architecture document: "maker-checker applies to every mutating
/// verb except `approve` itself"); its own [`ApprovalState::SelfApproved`] /
/// [`ApprovalState::PayloadMismatch`] outcomes are surfaced by calling [`check_approve`] instead.
pub fn check_dual_control(
    verb: KernelVerb,
    dual_control: DualControl,
    approval: ApprovalState,
) -> Result<(), Refusal> {
    if verb == KernelVerb::Approve {
        return Ok(());
    }
    if dual_control == DualControl::Single {
        return Ok(());
    }
    match approval {
        ApprovalState::Approved => Ok(()),
        ApprovalState::NotYetApproved => {
            Err(Refusal::new(RefusalStep::Admit, ReasonCode::ApprovalPending))
        }
        ApprovalState::SelfApproved => {
            Err(Refusal::new(RefusalStep::Approve, ReasonCode::SelfApproval))
        }
        ApprovalState::PayloadMismatch => {
            Err(Refusal::new(RefusalStep::Approve, ReasonCode::PayloadMismatch))
        }
    }
}

/// The `approve` verb's own admission check: the approver must differ from the maker, and the
/// payload hash it carries must equal the pending mutation's. Distinct from
/// [`check_dual_control`], which gates every OTHER mutating verb on `approve`'s outcome; this is
/// the check `approve` itself runs.
pub fn check_approve(maker: &str, approver: &str, payload_matches: bool) -> Result<(), Refusal> {
    if maker == approver {
        return Err(Refusal::new(RefusalStep::Approve, ReasonCode::SelfApproval));
    }
    if !payload_matches {
        return Err(Refusal::new(
            RefusalStep::Approve,
            ReasonCode::PayloadMismatch,
        ));
    }
    Ok(())
}

/// `set_dual_control(required)` needs at least two distinct admin principals configured —
/// otherwise the fleet could seal `required` with no second checker able to ever approve anything.
/// `distinct_admin_principals` is the count the integrator resolves from governance
/// (`// contract:`).
pub fn check_set_dual_control_required(distinct_admin_principals: usize) -> Result<(), Refusal> {
    if distinct_admin_principals < 2 {
        return Err(Refusal::new(
            RefusalStep::Approve,
            ReasonCode::InsufficientApprovers,
        ));
    }
    Ok(())
}

/// The full posture check for the 17 new verbs, run in the order the module doc names: operator
/// gate first, then dual control. Legacy verbs and named surfaces are never subject to either gate
/// here (the architecture document scopes the operator/dual-control machinery to the irreducible
/// set and the mutating-verb maker-checker rule, both of which this crate reads through
/// [`IRREDUCIBLE_VERBS`] and the caller-supplied [`ApprovalState`] respectively) — a caller for a
/// legacy verb should not call this function at all.
pub fn check_new_verb_admission(
    verb: KernelVerb,
    ctx: PostureCtx,
    approval: ApprovalState,
) -> Result<(), Refusal> {
    check_operator_gate(verb, ctx.operator)?;
    check_dual_control(verb, ctx.dual_control, approval)
}

#[cfg(test)]
#[path = "tests/posture_tests.rs"]
mod tests;
