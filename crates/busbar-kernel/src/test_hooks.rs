// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod tokens {
    use busbar_contract::caps::{
        Capability, DurabilityLost, Exit, Grant, KernelSeal, Origin, OriginKind, Outcome, Pass,
        Posted, Step, UnitEnd,
    };

    pub fn seal() -> KernelSeal {
        crate::seal::acquire()
    }

    pub fn pass<S: Step>() -> Pass<S> {
        Pass::mint(&seal())
    }

    pub fn grant<C: Capability>() -> Grant<C> {
        Grant::mint(&seal())
    }

    pub fn origin(kind: OriginKind) -> Origin {
        Origin::seal(&seal(), kind)
    }

    pub fn end(outcome: Outcome, posted: Result<Posted, DurabilityLost>) -> UnitEnd {
        UnitEnd::seal(&grant::<Exit>(), outcome, posted)
    }
}
