// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dual-control posture and the operator-key gate, for the new 1.6.0 verbs
//! ([`crate::verb::NEW_VERBS`]).
//!
//! Two independent gates, both sealed at `Bootstrap` and both read here as plain values the
//! integrator resolves from the sealed `Policy` (the resolution itself — reading the journal — is a
//! `// contract:` seam; see `the integrator's policy read`):
//!
//! - **Operator state.** `unset` (no operator key sealed) refuses every irreducible verb; `set`
//!   lifts that refusal. The two ceremony verbs that used to be admitted under `unset`
//!   (`set_operator_key`, `export_keyset`) left 1.6.0 by the owner's 2026-09-08 ruling: the
//!   operator key is configured (`auth.operator_pub`), and keyset export is an off-node CLI.
//! - **Dual-control posture.** `single` (the default on upgrade and on a fresh install) admits
//!   every verb immediately. `required` needs a matching approval for every mutating verb. The
//!   `approve` and `set_dual_control` verbs left 1.6.0 by the same ruling, so no node seals
//!   `required` and the integrator resolves [`ApprovalState::NotYetApproved`].
//!
//! Both gates apply to the SAME verb call in sequence: operator state is checked first (it is the
//! narrower, harder failure — a fleet that has never run the ceremony has no meaningful
//! maker-checker state to check either), then dual-control posture.

use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use crate::verb::{KernelVerb, IRREDUCIBLE_VERBS, READ_ONLY_NEW_VERBS};

/// Whether an operator key is sealed (`auth.operator_pub`), and when it is, the raw 32-byte ed25519
/// public key.
///
/// The key travels ON the state on purpose: the gate below only needs to know a ceremony ran, but the
/// verbs whose signatures are checked against the sealed key (D38 `amend_rate_history`) need the key
/// itself, and the posture seam is the one channel a fleet's sealed `Policy` reaches a verb through.
/// So `Set` carries the public key material — the raw 32 bytes, not a parsed key type, so this crate
/// stays free of a crypto dependency and the verifying site (which already owns one) parses and
/// verifies. There is exactly ONE operator key (a single key sealed at `Bootstrap`, not a registry);
/// the `operator_fingerprint` a verb body carries is the digest of THIS key, a which-key
/// confirmation the verifier checks against `sha256(key)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorState {
    /// No operator key configured yet — sealed at `Bootstrap` when `operator.pub` is absent.
    Unset,
    /// An operator public key is sealed in `Policy`: the raw 32-byte ed25519 verifying key.
    Set([u8; 32]),
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
/// either not irreducible, or irreducible and admitted (operator set). A verb this crate does not classify as irreducible is never refused
/// here regardless of operator state — this gate is scoped to exactly the closed
/// [`IRREDUCIBLE_VERBS`] list.
pub fn check_operator_gate(verb: KernelVerb, operator: OperatorState) -> Result<(), Refusal> {
    if matches!(operator, OperatorState::Set(_)) {
        return Ok(());
    }
    if !IRREDUCIBLE_VERBS.contains(&verb) {
        return Ok(());
    }
    Err(Refusal::new(RefusalStep::Admit, ReasonCode::OperatorUnset))
}

/// Check the dual-control gate for a mutating verb, given the caller's own [`ApprovalState`] for
/// the pending mutation (irrelevant, and never consulted, under `Single`).
pub fn check_dual_control(
    verb: KernelVerb,
    dual_control: DualControl,
    approval: ApprovalState,
) -> Result<(), Refusal> {
    // Maker-checker is scoped to MUTATING verbs, and two of the new verbs are not: `verify` and
    // `plane_facts` are bound `GET`. A read has no pending mutation, so there is nothing a checker
    // could ever approve for it — holding one here does not delay it, it refuses it for as long as
    // the posture stands, and `verify` is the check an operator runs to find out what state the
    // fleet is in.
    if READ_ONLY_NEW_VERBS.contains(&verb) {
        return Ok(());
    }
    if dual_control == DualControl::Single {
        return Ok(());
    }
    match approval {
        ApprovalState::Approved => Ok(()),
        ApprovalState::NotYetApproved => Err(Refusal::new(
            RefusalStep::Admit,
            ReasonCode::ApprovalPending,
        )),
        ApprovalState::SelfApproved => {
            Err(Refusal::new(RefusalStep::Approve, ReasonCode::SelfApproval))
        }
        ApprovalState::PayloadMismatch => Err(Refusal::new(
            RefusalStep::Approve,
            ReasonCode::PayloadMismatch,
        )),
    }
}

/// The full posture check for the new verbs, run in the order the module doc names: operator
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
