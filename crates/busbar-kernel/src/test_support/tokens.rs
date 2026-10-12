// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S OWN TEST-ONLY MINT (ARCHITECT ruling B, GATE-GREEN, 2026-10-02).
//!
//! A token (`Pass<S>`, `Grant<C>`) and the kernel's sealed values (`Origin`) are built only inside
//! `crates/busbar-kernel/src` (construction row `token-sealed*`). A dependent crate's tests (the
//! composition root's, busbar-llm's, busbar-core-admin's) still need real tokens to drive a unit, so
//! the kernel acquires the seal HERE and hands the minted value out: the caller names one of these
//! functions and never the seal acquisition or a constructor.
//!
//! One function per constructor, each with the constructor's own arguments minus the seal. Compiled
//! only under `cfg(test)` or the `test-support` feature (the `test_support` module gate), so no
//! release build carries a path to a token that does not run through the kernel's loop.

use busbar_contract::caps::{
    Capability, DurabilityLost, Exit, Grant, KernelSeal, Origin, OriginKind, Outcome, Pass, Posted,
    Step, UnitEnd,
};

/// The kernel seal, for the non-mint calls a test makes that take `&KernelSeal` (reading a verdict
/// back with `into_result(&seal)`, and the like).
pub fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
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
