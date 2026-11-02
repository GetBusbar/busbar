// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Narrow behavioral hooks. Fixture implementations and their state live in kernel-testkit.

/// Actual kernel-owned authority construction for behavior tests.
pub mod tokens {
    use busbar_contract::caps::{
        Capability, DurabilityLost, Exit, Grant, KernelSeal, Origin, OriginKind, Outcome, Pass,
        Posted, Step, UnitEnd,
    };

    /// The kernel seal, for the non-mint calls a test makes that take `&KernelSeal` (reading a verdict
    /// back with `into_result(&seal)`, and the like).
    pub fn seal() -> KernelSeal {
        crate::seal::acquire()
    }

    /// `Pass::<S>::mint`: the stage-pass for step `S`, unbound to any request.
    pub fn pass<S: Step>() -> Pass<S> {
        Pass::mint(&seal())
    }

    /// `Grant::<C>::mint`: the grant for capability `C` (`Admittance` included), unbound to any request.
    pub fn grant<C: Capability>() -> Grant<C> {
        Grant::mint(&seal())
    }

    /// `Origin::seal`: a sealed unit origin of `kind`.
    pub fn origin(kind: OriginKind) -> Origin {
        Origin::seal(&seal(), kind)
    }

    /// `UnitEnd::seal`: a unit's sealed end, its `outcome` and the posting it settled.
    pub fn end(outcome: Outcome, posted: Result<Posted, DurabilityLost>) -> UnitEnd {
        UnitEnd::seal(&grant::<Exit>(), outcome, posted)
    }
}
