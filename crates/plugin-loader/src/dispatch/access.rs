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
    static OPERATION: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}
pub(crate) struct Invocation(Option<u32>);
impl Drop for Invocation {
    fn drop(&mut self) {
        OPERATION.with(|slot| slot.set(self.0));
    }
}
pub(crate) fn enter(operation: u32) -> Invocation {
    Invocation(OPERATION.with(|slot| slot.replace(Some(operation))))
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
