// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for AuditChain`, in the exemplar's file position.

use busbar_caps::{Unit, UnitToken};

use crate::record::{Audit, AuditChain, AuditInputs, AuditRecord};

/// Everything the loop hands this unit at the audit step.
pub struct AuditInput {
    /// The facts the record is sealed over.
    pub inputs: AuditInputs,
}

/// The audit unit SERVES the audit step: it seals the record, and the plane assembles the facts.
///
/// `OWNS_ITS_STEP` is `false`, and that is a statement about today rather than a design: the step's
/// `Facts` are `AuditFacts`, and the composition root builds them from the sealed record PLUS
/// values only the plane holds (`crates/busbar/src/root/units_a2a.rs` reads `self.draft.op`). This
/// crate cannot build them without naming a plane, which its kind forbids. The record it does seal
/// is the whole of the audit RULE; what is owed is that `AuditFacts` become derivable from the
/// record alone, at which point this row flips to `true` and the root's lift disappears.
impl Unit for AuditChain {
    type Step = busbar_caps::step::Audit;
    type Input<'a> = AuditInput;
    type Answer<'a> = AuditRecord;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<busbar_caps::step::Audit>,
        input: AuditInput,
    ) -> AuditRecord {
        Audit::seal(self, input.inputs, token)
    }
}
