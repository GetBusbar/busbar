// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared halves of the kind proxies and session handles (IF §10.4; W1-A4b).
//!
//! Each kind module's `Proxy` (and, for plane and transport, `SessionHandle`) is a thin typed face over
//! busbar-ffi's `Instance<K>` / `Session<K>`, which own the raw entries (UNSAFE-MIN r3.1). What is common to
//! every method lives here, once: refuse a quarantined instance, run the entry under the watchdog word on the
//! caller's buffer, and turn the terminal status into a validated answer (a FAULT, or a broken answer, is
//! reported to the fault sink, which quarantines the instance, and is `Err(CallError::Fault)`).
//!
//! No function here takes or returns a raw `Token`: chain tokens stay in busbar-ffi's `Chain`, session tokens in
//! its `Session`, and the handles built over them are `Send` and not `Sync`, so two entries on one token need
//! two `&mut` borrows, which the borrow checker refuses (I6).

use busbar_ffi::Kind;
use busbar_ffi::host::{OutLease, Session};

use crate::fail::{CallError, FaultReason};
use crate::host_side::answer::{Answer, OwnedAnswer};
use crate::host_side::driver::{Driver, First, Instance, report_fault, step};
use crate::host_side::needs::Needs;
use crate::host_side::pool::PooledOut;
use crate::types::Status;

/// The watchdog's entry index of a kind method: its `M_*` bit number (IF §10.6).
pub(crate) const fn entry(method_bit: u64) -> u8 {
    method_bit.trailing_zeros() as u8
}

/// One sync entry: `call` runs on `buf` (lent to the plugin for it) under the watchdog word of the instance's
/// slot. The answer borrows `buf`.
pub(crate) fn sync<'o>(
    inst: &Instance,
    entry: u8,
    buf: &'o mut PooledOut,
    call: impl FnOnce(&mut OutLease) -> Status,
) -> Result<Answer<'o>, CallError> {
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    // None: busbar-ffi's ACTIVE stack is full, a host fault and not the plugin's (no sink, no quarantine).
    let status = step(inst.slot, entry, None, buf, call)
        .ok_or(CallError::Fault(FaultReason::BadInstance))?;
    Answer::parse(status, buf.bytes()).map_err(|reason| report_fault(inst.slot, false, reason))
}

/// The fixed-storage counterpart of `sync`. Exactly one callback; no pool acquisition, growth or replay.
/// The caller has already admitted and charged the input and the complete output backing.
pub(crate) fn sync_fixed<'o>(
    inst: &Instance,
    entry: u8,
    buf: &'o mut [u8],
    call: impl for<'loan> FnOnce(&mut OutLease<'loan>) -> Status,
) -> Result<(Answer<'o>, usize), CallError> {
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let cap = buf.len().min(inst.max_out);
    let buf = &mut buf[..cap];
    let (status, len) = crate::host_side::driver::step_fixed(inst.slot, entry, buf, |lease| {
        let status = call(lease);
        (status, lease.len())
    })
    .ok_or(CallError::Fault(FaultReason::BadInstance))?;
    let bytes = buf
        .get(..len)
        .ok_or_else(|| report_fault(inst.slot, false, FaultReason::BadInstance))?;
    Answer::parse(status, bytes)
        .map(|answer| (answer, len))
        .map_err(|reason| report_fault(inst.slot, false, reason))
}

/// One session opener: the handle exists if and only if the answer is OK with a leading session TOKEN (which
/// busbar-ffi's `open_sessionN` consumed). REFUSED and FAILED are `(None, answer)`.
pub(crate) fn opener<'o, K: Kind>(
    inst: &Instance,
    entry: u8,
    buf: &'o mut PooledOut,
    call: impl FnOnce(&mut OutLease) -> (Status, Option<Session<K>>),
) -> Result<(Option<Session<K>>, Answer<'o>), CallError> {
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let (status, session) = step(inst.slot, entry, None, buf, call)
        .ok_or(CallError::Fault(FaultReason::BadInstance))?;
    match Answer::parse(status, buf.bytes()) {
        Ok(answer) => Ok((session, answer)),
        // `session` drops here: busbar-ffi cancels the token the plugin minted.
        Err(reason) => Err(report_fault(inst.slot, false, reason)),
    }
}

/// One async entry: the step loop (§10.5) with `start` making the first step, on `req`. The answer is owned.
pub(crate) async fn chain<'a, 'i, K, N, F>(
    inst: &'a Instance,
    drv: &'a mut Driver<'a, N>,
    entry: u8,
    req: PooledOut,
    start: F,
) -> Result<OwnedAnswer, CallError>
where
    K: Kind,
    N: Needs,
    F: FnOnce(&PooledOut, &mut OutLease) -> First<'i, K> + Send,
{
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    drv.run::<K, F>(entry, inst.max_out, req, start)
        .await
        .map(|finished| finished.answer)
}

/// A chain's argument buffers: `req` copied in as buffer 0 (busbar-ffi keeps them until the token retires and
/// zeroes them when they drop, I11), and the index to build the raw argument from.
pub(crate) fn staged(req: &PooledOut) -> (busbar_ffi::host::ChainBufs, usize) {
    let mut bufs = busbar_ffi::host::ChainBufs::new();
    let at = bufs.push(req.bytes().to_vec());
    (bufs, at)
}
