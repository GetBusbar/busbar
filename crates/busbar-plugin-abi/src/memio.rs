// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `MemIo`: the in-plugin executor and byte pipes for hyper/h2, feature `memio` (IF §9). W0-ABI stub: frozen signatures, `todo!()` bodies; A12 fills it.
//!
//! W0-ABI: the hyper rt trait impls the IF names in comments (`MemStream`: `hyper::rt::Read` + `hyper::rt::Write`;
//! `MemExec`: `hyper::rt::Executor<F>`; `MemTimer`: `hyper::rt::Timer`) are not spelled as code and land with
//! W1-A12, which adds the `hyper` dependency; the stub needs no hyper or tokio item.

use crate::records::{Full, Writer};

/// One connection's in-plugin executor and byte pipes for hyper/h2. Lives in the plugin's session state.
// W0-ABI: `Default` is derived only so clippy's `new_without_default` stays quiet on the stub.
#[derive(Default)]
pub struct MemIo {
    // W0-ABI: task slab, ready queue (Arc wakers + AtomicBool dedupe), read buf, write buf, timer heap (W1-A12).
    _stub: (),
}
impl MemIo {
    pub fn new() -> Self {
        todo!()
    }
    /// The hyper IO object for this conn (implements hyper::rt::Read + hyper::rt::Write). Call once.
    pub fn io(&self) -> MemStream {
        todo!()
    }
    pub fn executor(&self) -> MemExec {
        // implements hyper::rt::Executor<F> for F: Future<Output = ()> + Send + 'static
        todo!()
    }
    pub fn timer(&self) -> MemTimer {
        // implements hyper::rt::Timer over Host::mono_ns
        todo!()
    }
    /// Feed bytes from `ingest` (empty = EOF) and wake the registered reader.
    pub fn feed(&mut self, bytes: &[u8]) {
        let _ = bytes;
        todo!()
    }
    /// Spawn a task on this conn (the connection driver itself, stream handlers).
    pub fn spawn(&mut self, fut: impl Future<Output = ()> + Send + 'static) {
        let _ = fut;
        todo!()
    }
    /// Poll only woken tasks, at most `budget` polls (256 by default), with now = mono_ns.
    pub fn run(&mut self, now_mono_ns: u64, budget: u32) -> Ran {
        let _ = (now_mono_ns, budget);
        todo!()
    }
    /// Drain written bytes into WRITE records, and the earliest timer (or `now` when the budget ran out) into WAKE_AT.
    pub fn flush(&mut self, out: &mut impl Writer) -> Result<(), Full> {
        let _ = out;
        todo!()
    }
}
pub struct MemStream;
pub struct MemExec;
pub struct MemTimer;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ran {
    Idle,
    BudgetLeft,
    Closed,
}
