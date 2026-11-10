// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared runtime kind/phase ceiling. Core still decides namespace, need and unit grants.
use super::{services::Answered, ticket::InstanceWake};
use busbar_contract::abi::{
    host::access::{Phase, Policy},
    mechanism::{call::Outcome, lifecycle::slot},
};
use std::sync::atomic::Ordering;

thread_local! {
    static READ_ONLY_ROUTE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OPERATION: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}
pub(crate) struct Invocation(Option<u32>, bool);
impl Drop for Invocation {
    fn drop(&mut self) {
        OPERATION.with(|slot| slot.set(self.0));
        READ_ONLY_ROUTE.with(|slot| slot.set(self.1));
    }
}
#[cfg(test)]
pub(crate) fn enter(operation: u32) -> Invocation {
    enter_kind(busbar_contract::abi::mechanism::KindCode::Secret, operation)
}
pub(crate) fn enter_kind(
    kind: busbar_contract::abi::mechanism::KindCode,
    operation: u32,
) -> Invocation {
    let restricted = kind == busbar_contract::abi::mechanism::KindCode::Plane
        && operation == busbar_contract::abi::plane::slot::AUTHENTICATED_ROUTE;
    let old = READ_ONLY_ROUTE.with(|slot| {
        let old = slot.get();
        slot.set(old || restricted);
        old
    });
    Invocation(OPERATION.with(|slot| slot.replace(Some(operation))), old)
}
pub(crate) fn read_only_route() -> bool {
    READ_ONLY_ROUTE.with(std::cell::Cell::get)
}

/// Carry an already-proven operation ceiling through cleanup and an FFI thread handoff.
pub(crate) fn inherit_read_only(restricted: bool) -> Invocation {
    let old = READ_ONLY_ROUTE.with(|slot| {
        let old = slot.get();
        slot.set(old || restricted);
        old
    });
    Invocation(operation(), old)
}

pub(crate) fn operation() -> Option<u32> {
    OPERATION.with(std::cell::Cell::get)
}

pub(crate) fn admit(
    wake: &InstanceWake,
    policy: Option<&Policy>,
    operation: Option<u32>,
) -> Result<(), Answered> {
    let refused = || {
        Answered::bare(
            Outcome::Refused,
            "this kind or lifecycle phase has no authority for the host operation",
        )
    };
    let Some(policy) = policy else {
        return Err(refused());
    };
    // This is the actual invocation's phase, independent of a cached callback's HostCtx,
    // ticket, service table, or numeric operation code. Nested crossings cannot widen it.
    if READ_ONLY_ROUTE.with(std::cell::Cell::get)
        && !matches!(policy.name, "CLOCK_NOW" | "RECORDS_GET" | "RECORDS_LIST")
    {
        return Err(refused());
    }
    let Some(caller) = wake.caller.get() else {
        return Err(refused());
    };
    if wake.revoked.load(Ordering::Acquire) || !policy.admits(caller.kind()) {
        return Err(refused());
    }
    if policy.phase == Phase::Active
        && (operation.is_none()
            || matches!(
                operation,
                Some(slot::VALIDATE | slot::RETIRE | slot::CANCEL | slot::RELEASE | slot::CLOSE)
            ))
    {
        return Err(refused());
    }
    Ok(())
}
