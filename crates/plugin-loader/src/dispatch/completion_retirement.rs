// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit terminal-result consumption, bound to an existing driver and service epoch.

use super::ticket::{InstanceWake, Waking};
use busbar_contract::abi::mechanism::{
    call::{Blob, InHead, OutHead, Outcome, BLOB_OCTETS},
    lifecycle::slot,
};
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Capability};

pub(crate) struct Input {
    input: *mut InHead,
    original: Blob,
    capability: Capability,
    _bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl Drop for Input {
    fn drop(&mut self) {
        // SAFETY: the crossing owns the input, and its nested loan guards drop in reverse order.
        unsafe {
            (*self.input).extensions = self.original;
        }
    }
}

/// # Safety
/// The input and its existing extension bytes belong to this live host crossing.
pub(crate) unsafe fn prepare(
    wake: &'static InstanceWake,
    operation: u32,
    input: *mut InHead,
) -> Result<Option<Input>, ()> {
    if !matches!(operation, slot::TICK | slot::DRIVE) {
        return Ok(None);
    }
    // SAFETY: the host's current frame.
    let head = unsafe { &mut *input };
    let Some(route) = Waking::of(wake).and_then(|w| w.route.upgrade()) else {
        return Ok(None);
    };
    let Some(store) = route.store() else {
        return Ok(None);
    };
    if !store.held.tracks(head.ticket) {
        return Ok(None);
    }
    let original = head.extensions;
    if original.len > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize
        || (original.len != 0 && original.fmt != BLOB_OCTETS)
    {
        return Ok(None);
    }
    // SAFETY: bounded host-owned bytes remain live through the crossing.
    let prior = unsafe { super::validate::lent(original.ptr, original.len) }.ok_or(())?;
    let Ok(previous) = wire::entry(prior, wire::CAPABILITY) else {
        return Ok(None);
    };
    if previous.is_some() || wire::entry(prior, wire::ACK).map_err(|_| ())?.is_some() {
        return Err(());
    }
    let caller = std::ptr::from_ref(wake) as usize;
    let Some(capability) = store.retirement_input(caller, head.host, head.ticket) else {
        return Ok(None);
    };
    let Ok(bytes) = wire::append_capability(prior, capability) else {
        return Ok(None);
    };
    let bytes = zeroize::Zeroizing::new(bytes);
    head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: original.flags,
    };
    Ok(Some(Input {
        input,
        original,
        capability,
        _bytes: bytes,
    }))
}

/// Called only after all other output validation. ACK bytes are decoded while their answer
/// lease is live. Successful retirement wakes the driver to deliver its confirmation nonce.
///
/// # Safety
/// The checked output's extension bytes remain live under its answer lease.
pub(crate) unsafe fn answer(
    wake: &'static InstanceWake,
    operation: u32,
    outcome: Outcome,
    head: &OutHead,
    input: Option<&Input>,
) -> Result<(), ()> {
    // SAFETY: the already-checked output remains leased.
    let bytes =
        unsafe { super::validate::lent(head.extensions.ptr, head.extensions.len) }.ok_or(())?;
    if !wire::present(bytes, wire::ACK) {
        return Ok(());
    }
    if !matches!(operation, slot::TICK | slot::DRIVE)
        || !matches!(outcome, Outcome::Ready | Outcome::Pending)
        || head.extensions.fmt != BLOB_OCTETS
        || bytes.len() > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize
    {
        return Err(());
    }
    let ack = wire::read_ack(bytes).map_err(|_| ())?.ok_or(())?;
    let capability = input.ok_or(())?.capability;
    if ack.capability != capability {
        return Err(());
    }
    let waking = Waking::of(wake).ok_or(())?;
    let store = waking.route.upgrade().and_then(|r| r.store()).ok_or(())?;
    store.retire_results(wake, &ack)?;
    waking.wake(capability.ticket);
    Ok(())
}
