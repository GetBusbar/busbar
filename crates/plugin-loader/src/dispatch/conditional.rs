// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptKind {
    Applied,
    Observed,
    Refused,
    Blocked,
}

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
        || wake.revoked.load(std::sync::atomic::Ordering::Acquire)
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
    if wake.caller.get().is_none() {
        return Ok(None);
    }
    let driver = matches!(operation, slot::DRIVE | slot::TICK);
    let settlement = if driver {
        {
            let mut selected = wake
                .conditional_driver
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *selected = Some(head.ticket);
        }
        served
            .store
            .settlement_input(caller(wake))
            .map(|(request, receipt)| {
                let result = wire::read_result(&receipt, &request)
                    .map_err(|_| ())?
                    .ok_or(())?;
                wire::encode_settlement(&request, &result).map_err(|_| ())
            })
            .transpose()?
    } else {
        None
    };
    let normal = if served.provider.supports_record_transactions()
        && !served
            .store
            .conditional_current_retired(caller(wake), head.ticket)
    {
        Some(
            served
                .store
                .conditional_input(caller(wake), head.ticket, unit)?,
        )
    } else {
        None
    };
    if normal.is_none() && settlement.is_none() {
        return Ok(None);
    }
    let original = head.extensions;
    if original.len > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err(());
    }
    // SAFETY: original input bytes live with the host frame and were bounded above.
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
    if wire::entry(prior, wire::INTENT).map_err(|_| ())?.is_some()
        || wire::entry(prior, wire::OBSERVE).map_err(|_| ())?.is_some()
        || wire::entry(prior, wire::SETTLEMENT_ACK)
            .map_err(|_| ())?
            .is_some()
    {
        return Err(());
    }
    let mut added = Vec::new();
    if let Some((capability, receipt)) = normal {
        let prior_capability = wire::read_capability(prior).map_err(|_| ())?;
        if prior_capability.is_some_and(|c| c != capability) {
            return Err(());
        }
        if prior_capability.is_none() {
            added.extend_from_slice(&wire::encode_capability(capability));
        }
        let existing = wire::entry(prior, wire::RESULT).map_err(|_| ())?;
        let observed = wire::entry(prior, wire::OBSERVED).map_err(|_| ())?;
        for (key, value) in [(wire::RESULT, existing), (wire::OBSERVED, observed)] {
            if value.is_some_and(|value| {
                receipt
                    .as_ref()
                    .and_then(|r| wire::entry(r, key).ok().flatten())
                    != Some(value)
            }) {
                return Err(());
            }
        }
        if existing.is_none() && observed.is_none() {
            added.extend_from_slice(receipt.as_deref().unwrap_or(&[]));
        }
    } else if wire::read_capability(prior).map_err(|_| ())?.is_some()
        || wire::entry(prior, wire::RESULT).map_err(|_| ())?.is_some()
        || wire::entry(prior, wire::OBSERVED)
            .map_err(|_| ())?
            .is_some()
    {
        return Err(());
    }
    if let Some(existing) = wire::entry(prior, wire::SETTLEMENT).map_err(|_| ())? {
        if settlement
            .as_ref()
            .and_then(|r| wire::entry(r, wire::SETTLEMENT).ok().flatten())
            != Some(existing)
        {
            return Err(());
        }
    } else if let Some(settlement) = settlement {
        added.extend_from_slice(&settlement);
    }
    let len = prior
        .len()
        .checked_add(added.len())
        .filter(|&n| n <= busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize)
        .ok_or(())?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(len));
    bytes.extend_from_slice(prior);
    bytes.extend_from_slice(&added);
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

pub(super) fn wake_driver(wake: &'static InstanceWake) {
    if wake.revoked.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let driver = *wake
        .conditional_driver
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let (Some(driver), Some(waking)) = (driver, Waking::of(wake)) {
        waking.wake(driver);
    }
}

fn wake_commit(
    wake: &'static InstanceWake,
    store: &super::services::ServiceStore,
    request: &wire::Request,
) {
    if wake.revoked.load(std::sync::atomic::Ordering::Acquire) {
        store.conditional_teardown(caller(wake));
    } else if store.conditional_retired(caller(wake), request) {
        wake_driver(wake);
    } else if let Some(waking) = Waking::of(wake) {
        waking.wake(request.capability.ticket);
    }
}

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

fn nonapplied_output(answer: &super::Answer, receipt: ReceiptKind) -> Result<(), ()> {
    use busbar_contract::abi::mechanism::check::reported;
    use busbar_contract::abi::plane::{
        self, OnPieceIn, OnPieceOut, PlaneDriveOut, ServeIn, ServeOut,
    };
    let observed = receipt == ReceiptKind::Observed;
    match answer.slot {
        plane::slot::ON_PIECE => {
            let input = answer.input::<OnPieceIn>().map_err(|_| ())?;
            let out = answer.out::<OnPieceOut>().map_err(|_| ())?;
            if out.records_needed != 0 || out.fields_needed != 0 || out.arena_needed != 0 {
                return Err(());
            }
            if observed {
                // SAFETY: the host buffer belongs to this validated, still-leased answer;
                // `reported` independently bounds the count before constructing the slice.
                let records = unsafe {
                    reported(
                        input.records_buf.cast_const(),
                        u64::from(out.records_written),
                        input.records_cap as u64,
                        "conditional.observed.records",
                    )
                }
                .map_err(|_| ())?;
                if records
                    .iter()
                    .any(|record| record.op != plane::RECORD_AUDIT)
                {
                    return Err(());
                }
            } else if out.records_written != 0
                || out.units_written != 0
                || out.units_needed != 0
                || out.flags
                    & !(plane::EMIT_DONE | plane::EMIT_MESSAGE_END | plane::EMIT_FINAL_STATUS)
                    != 0
                || out.verb.len != 0
                || out.target.len != 0
                || out.need != 0
                || out.lane.len != 0
                || out.metric_pool.len != 0
                || out.metric_lane.len != 0
                || out.fault != 0
                || out.tap_fault != 0
                || out.verdict != 0
            {
                return Err(());
            }
        }
        plane::slot::SERVE => {
            let input = answer.input::<ServeIn>().map_err(|_| ())?;
            let out = answer.out::<ServeOut>().map_err(|_| ())?;
            if out.records_needed != 0
                || out.fields_needed != 0
                || out.arena_needed != 0
                || out.reply_needed != 0
            {
                return Err(());
            }
            if observed {
                // SAFETY: as ON_PIECE: the host buffer is live and its count is checked here.
                let records = unsafe {
                    reported(
                        input.records_buf.cast_const(),
                        u64::from(out.records_written),
                        input.records_cap as u64,
                        "conditional.observed.records",
                    )
                }
                .map_err(|_| ())?;
                if records
                    .iter()
                    .any(|record| record.op != plane::RECORD_AUDIT)
                {
                    return Err(());
                }
            } else if out.records_written != 0 || out.audit != plane::AUDIT_NONE {
                return Err(());
            }
        }
        slot::DRIVE => {
            let out = answer.out::<PlaneDriveOut>().map_err(|_| ())?;
            if !observed && (out.sessions_written != 0 || out.sessions_needed != 0) {
                return Err(());
            }
        }
        slot::TICK => {}
        _ => return Err(()),
    }
    Ok(())
}

fn output_allowed(
    store: &super::services::ServiceStore,
    wake: &'static InstanceWake,
    ticket: Ticket,
    unit: Option<u64>,
    answer: &super::Answer,
    extensions: &[u8],
) -> bool {
    store.conditional_output_allowed(caller(wake), ticket, unit)
        || store
            .conditional_reply_receipt(caller(wake), ticket, unit)
            .is_some_and(|receipt| {
                (receipt != ReceiptKind::Refused
                    || busbar_contract::abi::mechanism::extensions::get(
                        extensions,
                        busbar_contract::abi::mechanism::inspection::EXT_REQUEST,
                    )
                    .is_none())
                    && nonapplied_output(answer, receipt).is_ok()
            })
}

/// # Safety
/// The validated answer and every extension byte remain leased for this call.
pub(crate) unsafe fn answer(
    wake: &'static InstanceWake,
    kind: KindCode,
    ticket: Ticket,
    unit: Option<u64>,
    head: &OutHead,
    answer: &super::Answer,
) -> Result<bool, ()> {
    let operation = answer.slot;
    let outcome = answer.outcome;
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
    if operation == slot::CLOSE && outcome == Outcome::Ready {
        if let Some(served) = &served {
            served.store.conditional_teardown(caller(wake));
        }
    }

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
    if wire::present(bytes) {
        if wire::entry(bytes, wire::SETTLEMENT)
            .map_err(|_| ())?
            .is_some()
        {
            return Err(());
        }
        if let Some(ack) = wire::read_settlement_ack(bytes).map_err(|_| ())? {
            if !matches!(operation, slot::DRIVE | slot::TICK)
                || !matches!(outcome, Outcome::Ready | Outcome::Pending | Outcome::Failed)
                || head.extensions.fmt != BLOB_OCTETS
                || head.extensions.flags & !busbar_contract::abi::mechanism::call::BLOB_SECRET != 0
            {
                return Err(());
            }
            isolated(answer)?;
            for key in [
                wire::CAPABILITY,
                wire::INTENT,
                wire::OBSERVE,
                wire::RESULT,
                wire::OBSERVED,
                busbar_contract::abi::mechanism::inspection::EXT_REQUEST,
            ] {
                if wire::entry(bytes, key).map_err(|_| ())?.is_some() {
                    return Err(());
                }
            }
            let served = served.ok_or(())?;
            if outcome == Outcome::Ready
                && !served
                    .store
                    .conditional_output_allowed(caller(wake), ticket, unit)
            {
                return Err(());
            }
            let consumed =
                served
                    .store
                    .settlement_ack(caller(wake), &ack, outcome != Outcome::Failed)?;

            if consumed {
                wake_driver(wake);
            }
            return Ok(true);
        }
    }
    if !wire::present(bytes) {
        if operation != slot::CANCEL
            && outcome == Outcome::Ready
            && served
                .as_ref()
                .is_some_and(|s| !output_allowed(s.store, wake, ticket, unit, answer, bytes))
        {
            return Err(());
        }
        if let Some(s) = &served {
            if outcome == Outcome::Ready {
                s.store.conditional_finished(caller(wake), ticket);
            } else if outcome == Outcome::Refused {
                s.store.conditional_cancel(caller(wake), ticket);
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
        || wire::entry(bytes, wire::SETTLEMENT)
            .map_err(|_| ())?
            .is_some()
        || wire::entry(bytes, wire::SETTLEMENT_ACK)
            .map_err(|_| ())?
            .is_some()
    {
        return Err(());
    }
    let request = wire::read_request(bytes)
        .map_err(|_| ())?
        .map(zeroize::Zeroizing::new);
    let observation = wire::read_observation(bytes).map_err(|_| ())?;
    if request.is_some() == observation.is_some() {
        return Err(());
    }
    if outcome != Outcome::Pending || ticket.is_none() {
        return Err(());
    }
    isolated(answer)?;

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
    if !served.store.conditional_begin(wake, unit, &request)? {
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
            wake_commit(wake, &store, &completion);
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
            wake_commit(wake, served.store, &request);
        }
    }
    Ok(true)
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "conditional_tests.rs"]
mod tests;
