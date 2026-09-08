// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for UsageUnit`, in the exemplar's file position.

use busbar_caps::step::Meter;
use busbar_caps::{Decision, ReasonCode, Refusal, Unit, UnitToken, UsageToken};

use crate::evidence::{KernelCounts, MeterPolicy, RetainedLocatorValues};
use crate::lane::LegDeclaration;
use crate::meter::meter;

/// Everything the loop hands this unit at the meter step.
pub struct MeterInput<'a> {
    /// The locator values the legs retained.
    pub retained: &'a RetainedLocatorValues,
    /// What the kernel itself counted.
    pub kernel: &'a KernelCounts,
    /// The deployment's meter policy.
    pub policy: &'a MeterPolicy,
    /// What the legs declared.
    pub declared: &'a LegDeclaration,
    /// The token that seals a usage record. Lent for this call only.
    pub usage: &'a UsageToken,
}

/// The usage unit, as the thing the loop is handed.
///
/// A zero-sized type because the rule is a pure function of its inputs; the crate had no unit
/// struct before, and the kind's shape is one type per crate implementing one trait.
pub struct UsageUnit;

/// The usage unit OWNS the meter step: it answers with a sealed `Decision<Meter>`.
///
/// The lift is the composition root's own, verbatim (`crates/busbar/src/root/units_*.rs`):
/// `Err` refuses with `MeterDisputed`, `Ok` proceeds with the metered usage. The root additionally
/// writes `metered` and `disputed` onto the PLANE's progress cell before proceeding; that is the
/// plane's bookkeeping about its own walk, not the metering rule, so it stays where it is and this
/// impl does not reproduce it.
impl Unit for UsageUnit {
    type Step = Meter;
    type Input<'a> = MeterInput<'a>;
    type Answer<'a> = Decision<Meter>;
    const OWNS_ITS_STEP: bool = true;

    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<Meter>,
        input: MeterInput<'a>,
    ) -> Decision<Meter> {
        match meter(
            input.retained,
            input.kernel,
            input.policy,
            input.declared,
            input.usage,
        ) {
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::MeterDisputed)),
            Ok(metered) => Decision::proceed(token, metered.usage),
        }
    }
}
