// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for AdmissionUnit`, in the exemplar's file position.

use busbar_caps::step::Admit;
use busbar_caps::{AdmitToken, Decision, PrincipalId, Unit, UnitToken};

use crate::cells::CellStore;
use crate::chain::BucketChain;
use crate::estimate::Estimate;
use crate::{Admission, AdmissionUnit};

/// Everything the loop hands this unit at the door.
pub struct AdmitInput<'a> {
    /// What the unit is estimated to cost.
    pub estimate: &'a Estimate,
    /// Who is being admitted.
    pub principal: &'a PrincipalId,
    /// The bucket chain the estimate is charged through.
    pub chain: &'a BucketChain,
    /// The token that opens a hold. Only the door is lent it.
    pub admit_token: &'a AdmitToken<Admit>,
}

/// The admission unit OWNS the admit step: it answers with a sealed `Decision<Admit>`.
///
/// A pure delegation to [`Admission::admit`]. The two tokens stay two: the unit token seals the
/// ANSWER and the admit token opens the HOLD inside it, and collapsing them would let a step that
/// may decide also mint the reservation.
impl<S: CellStore> Unit for AdmissionUnit<'_, S> {
    type Step = Admit;
    type Input<'a>
        = AdmitInput<'a>
    where
        Self: 'a;
    type Answer<'a>
        = Decision<Admit>
    where
        Self: 'a;
    const OWNS_ITS_STEP: bool = true;

    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<Admit>,
        input: AdmitInput<'a>,
    ) -> Decision<Admit> {
        Admission::admit(
            self,
            input.estimate,
            input.principal,
            input.chain,
            input.admit_token,
            token,
        )
    }
}
