// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one place a call is built and a table entry invoked (DESIGN-interface-revision C.3, G.1 item 7).
//!
//! Every method of every kind crosses through one of the five functions here, one per shim of the
//! boundary crate: [`plain`], [`opens`], [`on`], [`ends`], [`chain`] (and the fixed-storage twin of the
//! hot session call). Each does the same five things, in this order, and nothing else does any of them:
//!
//! 1. refuse a quarantined instance without a call;
//! 2. enter the entry guard (owner for log attribution, the watchdog word, the arena reset) on the
//!    caller's answer block;
//! 3. show the recorder what is about to cross;
//! 4. invoke the table entry by its index;
//! 5. validate the terminal answer with the one validator of the answer envelope, charging the instance
//!    for a break.
//!
//! `frame` builds the call record; `kinds` holds the seven typed faces (one function per method, its
//! head record, its text and blob positions); `record` is the recorder; `ffi` is the bolt onto the
//! boundary crate and the host half.

pub mod ffi;
pub mod frame;
pub mod kinds;
pub mod layout;
pub mod record;

use std::sync::Arc;

use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::{Answer, OwnedAnswer};
use busbar_plugin_abi::host_side::driver::{Driver, Instance};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;
use busbar_plugin_abi::types::Pair;
use zerocopy::IntoBytes;

pub use ffi::{Call, Kind, Live, LiveSession};
pub use frame::{Frame, Head, Mono};

/// One live instance of kind `K` as the adapters hold it: the host's instance record (slot, limits,
/// declared methods and facts, scrub set) and the boundary crate's live instance behind it.
pub struct Bound<K: Kind> {
    live: Arc<Live<K>>,
    inst: Arc<Instance>,
}

impl<K: Kind> Clone for Bound<K> {
    fn clone(&self) -> Self {
        Bound {
            live: Arc::clone(&self.live),
            inst: Arc::clone(&self.inst),
        }
    }
}

impl<K: Kind> Bound<K> {
    /// None when `inst` is an instance of another kind.
    pub fn bind(inst: Arc<Instance>) -> Option<Bound<K>> {
        let live = ffi::live::<K>(&inst)?;
        Some(Bound { live, inst })
    }
    pub fn instance(&self) -> &Arc<Instance> {
        &self.inst
    }
    /// Whether the image declared table entry `method` (its D_METHODS bit).
    pub fn declares(&self, method: u8) -> bool {
        self.inst.methods & (1u64 << method) != 0
    }
}

/// A live session and the instance it runs on (defined beside the ports, which name it). `Send`, not
/// `Sync`: every call takes `&mut`, so one entry per token runs at a time; dropping it cancels the token.
pub use busbar_ports::KindSession as Sess;

/// The answer of a call that opens no session, validated: the envelope (`Answer::parse`), and no context
/// named back. A session TOKEN leads only a session opener's OK answer (§6.4 step 7); a call that opens
/// nothing and is answered with one names a session context the host did not hand it (a forged context),
/// which is FAULT `UnknownTag(TOKEN)` like any TOKEN out of its place.
fn opens_nothing(status: Status, bytes: &[u8]) -> Result<Answer<'_>, FaultReason> {
    let answer = Answer::parse(status, bytes)?;
    match Records::new(bytes).next() {
        Some(Ok(rec)) if rec.tag == tag::TOKEN => Err(FaultReason::UnknownTag(tag::TOKEN)),
        _ => Ok(answer),
    }
}

fn host_fault() -> CallError {
    // The boundary crate's nesting bound was reached: a host fault, not the plugin's (no sink, no
    // quarantine).
    CallError::Fault(FaultReason::BadInstance)
}

/// Shim 1: a plain call. The answer borrows `buf`.
pub fn plain<'o, K: Kind, H: Head, const T: usize, const B: usize>(
    to: &Bound<K>,
    method: u8,
    at: Mono,
    frame: &Frame<'_, H, T, B>,
    list: &[Pair<'_>],
    buf: &'o mut PooledOut,
) -> Result<Answer<'o>, CallError> {
    let inst = &*to.inst;
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let call = frame.call(at);
    let status = ffi::guard(inst.slot, method, buf, |lease| {
        record::toward(inst, method, 0, &call, list);
        ffi::plain(&to.live, method, &call, lease)
    })
    .ok_or_else(host_fault)?;
    record::back(inst, method, status, buf.bytes());
    opens_nothing(status, buf.bytes()).map_err(|reason| inst.charge(reason))
}

/// Shim 2: a call that opens a session. The session exists if and only if the answer is OK with a
/// leading session TOKEN; REFUSED and FAILED are `(None, answer)`.
pub fn opens<'o, K: Kind, H: Head, const T: usize, const B: usize>(
    to: &Bound<K>,
    method: u8,
    at: Mono,
    frame: &Frame<'_, H, T, B>,
    list: &[Pair<'_>],
    buf: &'o mut PooledOut,
) -> Result<(Option<Sess<K>>, Answer<'o>), CallError> {
    let inst = &*to.inst;
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let call = frame.call(at);
    let (status, session) = ffi::guard(inst.slot, method, buf, |lease| {
        record::toward(inst, method, 0, &call, list);
        ffi::opens(&to.live, method, &call, lease)
    })
    .ok_or_else(host_fault)?;
    record::back(inst, method, status, buf.bytes());
    match Answer::parse(status, buf.bytes()) {
        Ok(answer) => Ok((
            session.map(|session| Sess {
                inst: Arc::clone(&to.inst),
                session,
            }),
            answer,
        )),
        // `session` drops here: the boundary crate cancels the token the plugin minted.
        Err(reason) => Err(inst.charge(reason)),
    }
}

/// Shim 3: a call on a live session.
pub fn on<'o, K: Kind, H: Head, const T: usize, const B: usize>(
    s: &mut Sess<K>,
    method: u8,
    at: Mono,
    frame: &Frame<'_, H, T, B>,
    list: &[Pair<'_>],
    buf: &'o mut PooledOut,
) -> Result<Answer<'o>, CallError> {
    let Sess { inst, session } = s;
    let inst = &**inst;
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let call = frame.call(at);
    let token = ffi::token(session);
    let status = ffi::guard(inst.slot, method, buf, |lease| {
        record::toward(inst, method, token, &call, list);
        ffi::on(session, method, &call, lease)
    })
    .ok_or_else(host_fault)?;
    record::back(inst, method, status, buf.bytes());
    Answer::parse(status, buf.bytes()).map_err(|reason| inst.charge(reason))
}

/// Shim 3 on caller-owned fixed storage: exactly one call, no pool, no growth, no replay. The caller has
/// already admitted and charged the input and the whole output backing. Answers the validated answer
/// and the bytes written.
pub fn on_fixed<'o, K: Kind, H: Head, const T: usize, const B: usize>(
    s: &mut Sess<K>,
    method: u8,
    at: Mono,
    frame: &Frame<'_, H, T, B>,
    list: &[Pair<'_>],
    buf: &'o mut [u8],
) -> Result<(Answer<'o>, usize), CallError> {
    let Sess { inst, session } = s;
    let inst = &**inst;
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let cap = buf.len().min(inst.max_out);
    let buf = buf.get_mut(..cap).ok_or_else(host_fault)?;
    let call = frame.call(at);
    let token = ffi::token(session);
    let (status, len) = ffi::guard_fixed(inst.slot, method, buf, |lease| {
        record::toward(inst, method, token, &call, list);
        let status = ffi::on(session, method, &call, lease);
        (status, lease.len())
    })
    .ok_or_else(host_fault)?;
    let bytes = buf
        .get(..len)
        .ok_or_else(|| inst.charge(FaultReason::BadInstance))?;
    record::back(inst, method, status, bytes);
    Answer::parse(status, bytes)
        .map(|answer| (answer, len))
        .map_err(|reason| inst.charge(reason))
}

/// Shim 4: the call that ends a session. It consumes the handle: the plugin removes the session
/// whatever it answers, so nothing is cancelled afterwards.
pub fn ends<'o, K: Kind, H: Head, const T: usize, const B: usize>(
    s: Sess<K>,
    method: u8,
    at: Mono,
    frame: &Frame<'_, H, T, B>,
    buf: &'o mut PooledOut,
) -> Result<Answer<'o>, CallError> {
    let Sess { inst, session } = s;
    let inst = &*inst;
    if !inst.is_live() {
        // `session` drops here: the boundary crate cancels the token.
        return Err(CallError::Quarantined);
    }
    let call = frame.call(at);
    let token = ffi::token(&session);
    let status = ffi::guard(inst.slot, method, buf, |lease| {
        record::toward(inst, method, token, &call, &[]);
        ffi::ends(session, method, &call, lease)
    })
    .ok_or_else(host_fault)?;
    record::back(inst, method, status, buf.bytes());
    Answer::parse(status, buf.bytes()).map_err(|reason| inst.charge(reason))
}

/// Shim 5: an async method, to its terminal answer. `req` holds the method's one byte argument
/// (`blobs[0]`), already encoded; it is lent as it stands and kept by the chain until the token retires.
/// `lends` false: the method takes no bytes and `req` is only the chain's working block. `head` is the
/// method's numbers, read during the starting call only. The answer is owned.
pub async fn chain<'a, K: Kind, N: Needs, H: Head + Send + 'a>(
    to: &'a Bound<K>,
    drv: &'a mut Driver<'a, N>,
    method: u8,
    at: Mono,
    head: H,
    req: PooledOut,
    lends: bool,
) -> Result<OwnedAnswer, CallError> {
    let inst = &*to.inst;
    if !inst.is_live() {
        return Err(CallError::Quarantined);
    }
    let live = &*to.live;
    let owned = ffi::run::<K, N, _>(drv, method, inst.max_out, req, move |req, lease| {
        record::toward_start(
            inst,
            method,
            at.0,
            head.as_bytes(),
            if lends { Some(req.bytes()) } else { None },
        );
        let (bufs, blob_at) = if lends {
            let (bufs, at) = ffi::staged(req);
            (bufs, Some(at))
        } else {
            (ffi::ChainBufs::new(), None)
        };
        ffi::starts(live, method, at.0, head.as_bytes(), bufs, blob_at, lease)
    })
    .await?;
    let answer = owned.answer();
    record::back(inst, method, answer.status, answer.records().rest());
    Ok(owned)
}

/// The operation's one clock reading, as the port call carries it. Every adapter takes its `Mono` from
/// here, so the reading is made once by the caller of the port and never by an adapter or a plugin.
pub fn at(cx: &busbar_ports::CallCx) -> Mono {
    Mono(cx.mono_ns)
}

#[cfg(test)]
#[path = "../tests/forged_context_tests.rs"]
#[deny(unsafe_code)]
mod forged_context_tests;
