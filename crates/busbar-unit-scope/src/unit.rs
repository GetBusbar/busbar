// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for ScopeUnit`, in the exemplar's file position.

use busbar_caps::step::Approve;
use busbar_caps::{Decision, ReasonCode, Refusal, ScopeFacts, Unit, UnitToken};

use crate::{approve, Grants, Scope};

/// Everything the loop hands this unit at the approve step.
pub struct ApproveInput {
    /// What the caller holds.
    pub held: Grants,
    /// What this operation requires, as [`crate::required_scope`] read it.
    pub needed: Scope,
}

/// The scope unit, as the thing the loop is handed.
///
/// A zero-sized type because the rule is a pure function of its two inputs: the crate had no unit
/// struct before, and the kind's shape is one type per crate implementing one trait.
pub struct ScopeUnit;

/// The scope unit OWNS the approve step: it answers with a sealed `Decision<Approve>`.
///
/// The lift is the composition root's own, verbatim (`crates/busbar/src/root/units_*.rs`):
/// `Ok(())` proceeds with the default facts, `Err` refuses with `ScopeDenied`. One root wiring
/// additionally pushes the draft's resource onto the facts before proceeding; that is the PLANE's
/// fact about its own request, not the scope rule, so it stays where it is and this impl does not
/// reproduce it.
impl Unit for ScopeUnit {
    type Step = Approve;
    type Input<'a> = ApproveInput;
    type Answer<'a> = Decision<Approve>;
    const OWNS_ITS_STEP: bool = true;

    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<Approve>,
        input: ApproveInput,
    ) -> Decision<Approve> {
        match approve(input.held, input.needed) {
            Ok(()) => Decision::proceed(token, ScopeFacts::default()),
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied)),
        }
    }
}
