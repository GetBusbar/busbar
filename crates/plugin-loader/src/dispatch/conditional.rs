// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pending-only conditional publication, using the existing service-store operation epoch.

use super::ticket::{InstanceWake, Waking};
use busbar_contract::abi::mechanism::{
    call::{Blob, InHead, OutHead, Outcome, BLOB_OCTETS},
    lifecycle::slot,
    ticket::Ticket,
    KindCode,
};
use busbar_contract::abi::sdk::plane::conditional::{
    self as wire, ConditionalFailure, ConditionalResult,
};
use std::sync::Arc;

pub(crate) struct Input {
    input: *mut InHead,
    original: Blob,
    _bytes: Arc<zeroize::Zeroizing<Vec<u8>>>,
}
impl Drop for Input {
    fn drop(&mut self) {
        // SAFETY: this guard lives within the crossing owning its input head.
        unsafe {
            (*self.input).extensions = self.original;
        }
    }
}
fn caller(wake: &'static InstanceWake) -> usize {
    std::ptr::from_ref(wake) as usize
}

/// # Safety
/// The input frame and its original extension bytes belong to this crossing.
pub(crate) unsafe fn prepare(
    wake: &'static InstanceWake,
    enabled: bool,
    operation: u32,
    input: *mut InHead,
    unit: Option<u64>,
) -> Result<Option<Input>, ()> {
    if !enabled
        || matches!(
            operation,
            slot::CANCEL | slot::RELEASE | slot::CLOSE | slot::VALIDATE
        )
    {
        return Ok(None);
    }
    // SAFETY: host-owned current frame.
    let head = unsafe { &mut *input };
    if head.ticket.is_none() {
        return Ok(None);
    }
    let Some(route) = Waking::of(wake).and_then(|w| w.route.upgrade()) else {
        return Ok(None);
    };
    let Some(served) = route.services() else {
        return Ok(None);
    };
    if wake.caller.get().is_none() || !served.provider.supports_record_transactions() {
        return Ok(None);
    }
    let original = head.extensions;
    if original.len > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err(());
    }
    // SAFETY: original input bytes live with the host frame.
    let prior = unsafe { super::validate::lent(original.ptr, original.len) }.ok_or(())?;
    if (!prior.is_empty() && original.fmt != BLOB_OCTETS)
        || wire::entry(prior, wire::CAPABILITY).is_err()
    {
        return if wire::present(prior) {
            Err(())
        } else {
            Ok(None)
        };
    }
    let (capability, receipt) = served
        .store
        .conditional_input(caller(wake), head.ticket, unit)?;
    if wire::entry(prior, wire::INTENT).map_err(|_| ())?.is_some()
        || wire::entry(prior, wire::OBSERVE).map_err(|_| ())?.is_some()
        || wire::read_capability(prior)
            .map_err(|_| ())?
            .is_some_and(|c| c != capability)
    {
        return Err(());
    }
    let existing = wire::entry(prior, wire::RESULT).map_err(|_| ())?;
    let observed = wire::entry(prior, wire::OBSERVED).map_err(|_| ())?;
    if observed.is_some_and(|value| {
        receipt
            .as_ref()
            .and_then(|r| wire::entry(r, wire::OBSERVED).ok().flatten())
            != Some(value)
    }) {
        return Err(());
    }
    if existing.is_some_and(|value| {
        receipt
            .as_ref()
            .and_then(|r| wire::entry(r, wire::RESULT).ok().flatten())
            != Some(value)
    }) {
        return Err(());
    }
    let added = if wire::read_capability(prior).map_err(|_| ())?.is_none() {
        wire::encode_capability(capability)
    } else {
        Vec::new()
    };
    let receipt = if existing.is_none() && observed.is_none() {
        receipt.as_deref().unwrap_or(&[])
    } else {
        &[]
    };
    let len = prior
        .len()
        .checked_add(added.len())
        .and_then(|n| n.checked_add(receipt.len()))
        .filter(|&n| n <= busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize)
        .ok_or(())?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(len));
    bytes.extend_from_slice(prior);
    bytes.extend_from_slice(&added);
    bytes.extend_from_slice(receipt);
    let bytes = Arc::new(bytes);
    head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: original.flags,
    };
    Ok(Some(Input {
        input,
        original,
        _bytes: bytes,
    }))
}

/// Pending publication may not also expose ordinary writes, an answer, or a queued session.
fn isolated(a: &super::Answer) -> Result<(), ()> {
    use busbar_contract::abi::plane::{self, OnPieceOut, PlaneDriveOut, ServeOut};
    let clean = match a.slot {
        plane::slot::ON_PIECE => {
            let o = a.out::<OnPieceOut>().map_err(|_| ())?;
            o.emitted == 0
                && o.more == 0
                && o.flags == 0
                && o.reply_status == 0
                && o.fields_written == 0
                && o.fields_needed == 0
                && o.units_written == 0
                && o.units_needed == 0
                && o.records_written == 0
                && o.records_needed == 0
                && o.arena_written == 0
                && o.arena_needed == 0
                && o.verb.len == 0
                && o.target.len == 0
                && o.final_status == 0
        }
        plane::slot::SERVE => {
            let o = a.out::<ServeOut>().map_err(|_| ())?;
            o.reply_written == 0
                && o.reply_needed == 0
                && o.status == 0
                && o.fields_written == 0
                && o.fields_needed == 0
                && o.records_written == 0
                && o.records_needed == 0
                && o.arena_written == 0
                && o.arena_needed == 0
                && o.audit == 0
        }
        slot::DRIVE => {
            let o = a.out::<PlaneDriveOut>().map_err(|_| ())?;
            o.sessions_written == 0 && o.sessions_needed == 0
        }
        slot::TICK => true,
        _ => false,
    };
    if clean {
        Ok(())
    } else {
        Err(())
    }
}

/// # Safety
/// The validated answer and every extension byte remain leased for this call.
pub(crate) unsafe fn answer(
    wake: &'static InstanceWake,
    kind: KindCode,
    operation: u32,
    ticket: Ticket,
    unit: Option<u64>,
    outcome: Outcome,
    head: &OutHead,
    answer: &super::Answer,
) -> Result<bool, ()> {
    if kind != KindCode::Plane {
        return Ok(false);
    }
    let waking = Waking::of(wake);
    let route = waking.as_ref().and_then(|w| w.route.upgrade());
    let served = route.as_ref().and_then(|r| r.services());
    let negotiated = answer
        .context::<super::kinds::plane::PlaneFacts>()
        .is_some_and(|facts| facts.declared.conditional_records)
        || served
            .as_ref()
            .is_some_and(|s| s.store.conditional_negotiated(caller(wake), ticket));
    if operation == slot::CANCEL {
        if let Some(served) = &served {
            served.store.conditional_cancel(caller(wake), ticket);
        }
    }
    // An optional, unnegotiated feature cannot inspect an unreadable legacy blob. An active
    // exchange must fail closed instead; never form a slice larger than the shared ABI bound.
    let bytes = if head.extensions.len
        > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize
        || (head.extensions.len != 0 && head.extensions.ptr.is_null())
    {
        if negotiated {
            return Err(());
        }
        &[][..]
    } else {
        // SAFETY: the raw length was bounded above, and leased bytes remain live here.
        unsafe { super::validate::lent(head.extensions.ptr, head.extensions.len) }.ok_or(())?
    };
    if !wire::present(bytes) {
        if operation != slot::CANCEL
            && outcome == Outcome::Ready
            && served.as_ref().is_some_and(|s| {
                !s.store
                    .conditional_output_allowed(caller(wake), ticket, unit)
            })
        {
            return Err(());
        }
        if matches!(outcome, Outcome::Ready | Outcome::Refused) {
            if let Some(s) = &served {
                s.store.conditional_finished(caller(wake), ticket);
            }
        }
        return Ok(false);
    }
    if head.extensions.fmt != BLOB_OCTETS
        || head.extensions.flags & !busbar_contract::abi::mechanism::call::BLOB_SECRET != 0
        || wire::entry(bytes, wire::CAPABILITY)
            .map_err(|_| ())?
            .is_some()
        || wire::entry(bytes, wire::RESULT).map_err(|_| ())?.is_some()
        || wire::entry(bytes, wire::OBSERVED)
            .map_err(|_| ())?
            .is_some()
    {
        return Err(());
    }
    let request = wire::read_request(bytes).map_err(|_| ())?;
    let observation = wire::read_observation(bytes).map_err(|_| ())?;
    if request.is_some() == observation.is_some() {
        return Err(());
    }
    if outcome != Outcome::Pending || ticket.is_none() {
        return Err(());
    }
    isolated(answer)?;
    // Combining independent host effects in one candidate's output is never atomic.
    if busbar_contract::abi::mechanism::extensions::get(
        bytes,
        busbar_contract::abi::mechanism::inspection::EXT_REQUEST,
    )
    .is_some()
    {
        return Err(());
    }
    let served = served.ok_or(())?;
    let waking = waking.ok_or(())?;
    if !served.provider.supports_record_transactions() {
        return Err(());
    }
    let authority = wake.caller.get().ok_or(())?;
    if let Some(observation) = observation {
        if observation.capability.ticket != ticket {
            return Err(());
        }
        if !served
            .store
            .observation_begin(caller(wake), unit, &observation)?
        {
            return Ok(true);
        }
        let store = Arc::clone(served.store);
        let completion = observation.clone();
        let completed = move |result: Result<
            busbar_contract::abi::sdk::store::conditional::Expected,
            &'static str,
        >| {
            let result = wire::ObservationResult {
                correlation: completion.correlation,
                result: result.map_err(ConditionalFailure::Refused),
            };
            let Ok(bytes) = wire::encode_observed(&completion, &result) else {
                return;
            };
            if store.observation_complete(
                caller(wake),
                unit,
                &completion,
                &result,
                Arc::from(bytes),
            ) {
                waking.wake(ticket);
            }
        };
        if let Err(reason) = served.provider.observe_chain_life(
            authority,
            observation.kind,
            &observation.scope,
            Box::new(completed),
        ) {
            let result = wire::ObservationResult {
                correlation: observation.correlation,
                result: Err(ConditionalFailure::Refused(reason)),
            };
            let bytes = wire::encode_observed(&observation, &result).map_err(|_| ())?;
            if served.store.observation_complete(
                caller(wake),
                unit,
                &observation,
                &result,
                Arc::from(bytes),
            ) {
                if let Some(waking) = Waking::of(wake) {
                    waking.wake(ticket);
                }
            }
        }
        return Ok(true);
    }
    let request = request.ok_or(())?;
    if request.capability.ticket != ticket {
        return Err(());
    }
    if !served
        .store
        .conditional_begin(caller(wake), unit, &request)?
    {
        return Ok(true);
    }
    let store = Arc::clone(served.store);
    let completion = request.clone();
    let completed = move |result: ConditionalResult| {
        let Ok(bytes) = wire::encode_result(&completion, &result) else {
            return;
        };
        let receipt = Arc::from(bytes);
        if store.conditional_complete(caller(wake), unit, &completion, &result, receipt) {
            waking.wake(ticket);
        }
    };
    let candidate = request.candidate.clone();
    if let Err(reason) = served.provider.conditional_record_transaction(
        authority,
        unit,
        candidate,
        Box::new(completed),
    ) {
        let result = ConditionalResult {
            correlation: request.candidate.correlation,
            decision: Err(ConditionalFailure::Refused(reason)),
        };
        let receipt = Arc::from(wire::encode_result(&request, &result).map_err(|_| ())?);
        if served
            .store
            .conditional_complete(caller(wake), unit, &request, &result, receipt)
        {
            if let Some(waking) = Waking::of(wake) {
                waking.wake(ticket);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "conditional_tests.rs"]
mod tests;
