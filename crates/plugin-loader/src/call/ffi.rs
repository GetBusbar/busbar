// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOLT: the only file of the loader that names the boundary crate's call shape and its host entry
//! points. Everything else in `call` (the frame builder, the crossing place, the seven kind faces, the
//! recorder) is written against the items here, so a signature that differs in `busbar-ffi` or in the
//! host half is fitted in this file and nowhere else.
//!
//! What it bolts onto (each line is one row of the design's `ASSUMED.tsv`):
//! - `busbar_ffi::vt::Call::new(mono_ns, head, texts, blobs)` and its readers `session()`, `mono_ns()`,
//!   `head()`, `texts()`, `blobs()` (as on `house/iface-solo`; the session of a call is set by the host
//!   handles, never here).
//! - `busbar_ffi::Bytes::of_pairs`: a pair list lent as one blob, nothing rebuilt (as on `house/iface-solo`).
//! - `busbar_ffi::host::Instance<K>`: `call(slot, &Call, lease)`, `open_session(slot, &Call, lease)`,
//!   `start(slot, bufs, pack, lease)` where `pack` builds the call from the kept buffers; a slot past the image's `entries`
//!   answers `Status::FAULT` without a call.
//! - `busbar_ffi::host::Session<K>`: `call(slot, &Call, lease)`, `end(self, slot, &Call, lease)`, `token()`;
//!   `Drop` cancels.
//! - `busbar_ffi::host::{ChainBufs, OutLease, Started<K>}` as today.
//! - the host half (`busbar_plugin_abi::host_side`): `entry::guard`, `entry::guard_fixed`,
//!   `driver::Instance::live::<K>` (public), `driver::Instance::charge`, `driver::Driver::run`,
//!   `driver::First`, `proxy::staged` (public), `pool::PooledOut`, `answer::{Answer, OwnedAnswer}`.

use std::sync::Arc;

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::answer::OwnedAnswer;
use busbar_plugin_abi::host_side::driver::{Driver, First, Instance};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::PooledOut;
use busbar_plugin_abi::types::{Bytes, Pair, Status, Str};

pub use busbar_ffi::host::{ChainBufs, OutLease};
pub use busbar_ffi::vt::Call;
pub use busbar_ffi::Kind;

/// The boundary crate's live instance: the image's table and its instance address.
pub type Live<K> = busbar_ffi::host::Instance<K>;
/// The boundary crate's live session: one token, one caller at a time, cancelled on drop.
pub type LiveSession<K> = busbar_ffi::host::Session<K>;

/// Build the one call record. The only place a `Call` is made in the engine.
#[inline(always)]
pub(crate) fn call<'a>(
    mono_ns: u64,
    head: &'a [u8],
    texts: &'a [Str<'a>],
    blobs: &'a [Bytes<'a>],
) -> Call<'a> {
    Call::new(mono_ns, head, texts, blobs)
}

/// A pair list as one blob position.
#[inline(always)]
pub(crate) fn lend_pairs<'a>(list: &'a [Pair<'a>]) -> Bytes<'a> {
    Bytes::of_pairs(list)
}

/// The live instance of kind `K` behind a host instance record; None when the record is another kind's.
pub(crate) fn live<K: Kind>(inst: &Instance) -> Option<Arc<Live<K>>> {
    inst.live::<K>()
}

/// Shim 1 of 5: a plain call of table entry `method`.
#[inline(always)]
pub(crate) fn plain<K: Kind>(
    live: &Live<K>,
    method: u8,
    call: &Call<'_>,
    lease: &mut OutLease<'_>,
) -> Status {
    live.call(usize::from(method), call, lease)
}

/// Shim 2 of 5: a call that opens a session. The session exists if and only if the answer is OK with a
/// leading session TOKEN.
#[inline(always)]
pub(crate) fn opens<K: Kind>(
    live: &Arc<Live<K>>,
    method: u8,
    call: &Call<'_>,
    lease: &mut OutLease<'_>,
) -> (Status, Option<LiveSession<K>>) {
    live.open_session(usize::from(method), call, lease)
}

/// Shim 3 of 5: a call on a live session. The boundary crate sets the token as the call's session.
#[inline(always)]
pub(crate) fn on<K: Kind>(
    session: &mut LiveSession<K>,
    method: u8,
    call: &Call<'_>,
    lease: &mut OutLease<'_>,
) -> Status {
    session.call(usize::from(method), call, lease)
}

/// Shim 4 of 5: the call that ends a session. It consumes the handle: the plugin removes the session
/// whatever it answers, and no cancel follows.
#[inline(always)]
pub(crate) fn ends<K: Kind>(
    session: LiveSession<K>,
    method: u8,
    call: &Call<'_>,
    lease: &mut OutLease<'_>,
) -> Status {
    session.end(usize::from(method), call, lease)
}

/// The token of a live session, for the recorder only.
#[inline(always)]
pub(crate) fn token<K: Kind>(session: &LiveSession<K>) -> u64 {
    session.token()
}

/// Shim 5 of 5: start an async chain on table entry `method`. `head` is read during the call only;
/// `bufs` is kept by the chain until it retires, and `blob_at` names the one buffer of `bufs` lent as
/// `blobs[0]` (None: the method takes no bytes).
pub(crate) fn starts<'i, K: Kind>(
    live: &'i Live<K>,
    method: u8,
    mono_ns: u64,
    head: &[u8],
    bufs: ChainBufs,
    blob_at: Option<usize>,
    lease: &mut OutLease<'_>,
) -> First<'i, K> {
    live.start(
        usize::from(method),
        bufs,
        |bufs, cross| match blob_at {
            Some(at) => {
                let blobs = [bufs.get(at)];
                cross(&Call::new(mono_ns, head, &[], &blobs))
            }
            None => cross(&Call::new(mono_ns, head, &[], &[])),
        },
        lease,
    )
    .into()
}

/// The chain's request block lent as buffer 0 (no copy, given back to the pool when the token retires).
#[inline(always)]
pub(crate) fn staged(req: &mut PooledOut) -> (ChainBufs, usize) {
    busbar_plugin_abi::host_side::proxy::staged(req)
}

/// The step loop over a started chain, to its validated terminal answer.
pub(crate) async fn run<'a, 'i, K, N, F>(
    drv: &'a mut Driver<'a, N>,
    entry: u8,
    max_out: usize,
    req: PooledOut,
    start: F,
) -> Result<OwnedAnswer, CallError>
where
    K: Kind,
    N: Needs,
    F: FnOnce(&mut PooledOut, &mut OutLease) -> First<'i, K> + Send,
{
    drv.run::<K, F>(entry, max_out, req, start)
        .await
        .map(|finished| finished.answer)
}

/// The entry guard on a pooled answer block: owner, watchdog word, the outermost-exit arena reset. None:
/// the boundary crate's nesting bound is reached, a host fault and not the plugin's.
#[inline(always)]
pub(crate) fn guard<R>(
    slot: u32,
    entry: u8,
    out: &mut PooledOut,
    call: impl FnOnce(&mut OutLease) -> R,
) -> Option<R> {
    busbar_plugin_abi::host_side::entry::guard(slot, entry, out, call)
}

/// The entry guard on caller-owned fixed storage.
#[inline(always)]
pub(crate) fn guard_fixed<R>(
    slot: u32,
    entry: u8,
    out: &mut [u8],
    call: impl for<'loan> FnOnce(&mut OutLease<'loan>) -> R,
) -> Option<R> {
    busbar_plugin_abi::host_side::entry::guard_fixed(slot, entry, out, call)
}
