// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE, REACHED THROUGH ITS TABLE (THE DESIGN, the plugin ABI):
//! [`LoadedStore`] is one store instance loaded through the ONE loader
//! ([`load_linked`](crate::dispatch::load_linked) for a compiled-in row,
//! [`load_dropped`](crate::dispatch::load_dropped) for a dropped-in `cdylib`) and called through
//! the store v3 table (`busbar_contract::abi::store`) by the one dispatcher. Compiled in or dropped
//! in, every call crosses the same table; the kernel names no store crate.
//!
//! It answers two surfaces:
//!
//! * [`StoreCalls`], the typed store v3 surface: every op is SUBMITTED on a ticket to the
//!   dispatcher and AWAITED on the caller's task (no runtime thread is parked, no
//!   `spawn_blocking`); a full instance answers [`StoreFailure::Overloaded`] without a crossing;
//!   a short answer is re-submitted once on the same ticket with the buffers it named.
//! * [`RecordStore`], the 1.5.5 op set, SYNCHRONOUSLY, for the consumers that have not moved to
//!   [`StoreCalls`]. M6: this bridge is deleted when no consumer remains. Every one of its ops is
//!   SUBMITTED ON A TICKET like a [`StoreCalls`] op, and the synchronous caller waits for the
//!   completion: a store that answers PENDING (a remote store waiting on its connection) is
//!   resumed by the dispatcher on its wake and completes the op, never faulted (ARCHITECT ruling
//!   2026-10-03 on Q-L14-1; THE DESIGN, the plugin ABI). The wait is the caller's, exactly where the
//!   compiled-in store's direct calls ran before, so no call site moves from non-blocking to
//!   blocking. Only on a dispatcher's only worker, which cannot run an op while it waits, does an
//!   op cross ticket-less on the caller's thread, where a PENDING is FAULT (loud: logged at error,
//!   and a debug build panics). Remaining consumers: the kernel's governance state and budget flusher
//!   (`busbar-kernel/src/governance/state.rs`), the plane host's record and token ops
//!   (`busbar-kernel/src/plane_host/`), the admin units, the boot ledger's migration read, and
//!   the planes' own record legs.
//!
//! Off-path answers are read out of their lease and the lease is released at once.

use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, ReleaseIn, ValidateIn, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::sdk::store::{Cap, Cell, Dimension, Grant, ReserveRefused};
use busbar_contract::abi::store::{
    self as st, slot, AddUsageBatchIn, AddUsageIn, AppendBatchIn, AppendPlaneRecordIn, BlobIn,
    CellGrant, CountOut, GetPlaneRecordIn, HeadOut, HeadsOut, HostBlobs, HostBuf, HostBytesOut,
    HostListOut, HostRecords, HostSessions, IdIn, IdReasonIn, KeyWithCredentialIn, KindBeforeIn,
    KindIdIn, LeasedBlobOut, LeasedListOut, LeasedStrListOut, ListPlaneRecordsIn, OpBlobIn,
    OpBlobsIn, OpId, PlaneRecordRow, PutUsageIn, RecordEntry, RecordGetIn, RecordPutIn,
    RecordScanIn, ReleaseItem, ReserveIn, ReserveOut, SessionPutIn, SessionRow, SessionsForIn,
    SliceReleaseIn, SliceReleaseOut, TokenIn, U64In, UnitCell, UpsertPlaneRecordIn, UsageCell,
    VerdictOut, WindowCap, WindowCapsIn, WindowIn, DIAG_CAP_CONFLICT, DIAG_OPID_CONFLICT, FOUND,
    OPS, RESERVE_EXHAUSTED, RESERVE_NO_CAP, RESERVE_STALE_EPOCH, RESERVE_UNAVAILABLE, SELECT_ALL,
    SELECT_PARENT, VERDICT_YES,
};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition,
    PlaneRecordRef, PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, UsageDelta,
    UsageLedger, VirtualKey,
};
use busbar_contract::store_calls::{OpIdMint, StoreCall, StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::{Store, StoreFacts};
use crate::dispatch::{
    in_head, now_ns, out_head, Dispatcher, Frame, InFrame, Lent, OutFrame, Plugin,
};

/// The first byte buffer a request-path read is handed; a longer answer is re-asked once at the
/// size it named.
const FIRST_BYTES: usize = 16 * 1024;
/// The first item capacity of a request-path list.
const FIRST_ITEMS: usize = 256;
/// How long a Call-class op may pend before the dispatcher cancels it.
const CALL_DEADLINE: Duration = Duration::from_secs(30);

// ── the handle ───────────────────────────────────────────────────────────────────────────────

/// ONE STORE INSTANCE, opened through the store v3 table.
pub struct LoadedStore {
    plugin: Plugin<Store>,
    dispatcher: Arc<Dispatcher>,
    facts: StoreFacts,
    next_worker: AtomicU32,
    /// The node's one `op_id` allocator, for the bridge's `op_id`-carrying 1.5.5 writes.
    mint: OpIdMint,
}

impl std::fmt::Debug for LoadedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedStore")
            .field("plugin", &self.plugin.name())
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl LoadedStore {
    /// Open `plugin` on the operator's `settings` (the section's JSON), on
    /// `dispatcher`. `mint` is the node's one `op_id` allocator: every `op_id` the synchronous
    /// bridge mints for the 1.5.5 op set's additive writes comes from it.
    ///
    /// # Errors
    /// The store's refusal of its settings, in 1.5.5's words
    /// (`plugin '<name>' open failed: <reason>`), or a Statement with no store tail.
    pub fn open(
        plugin: Plugin<Store>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        mint: OpIdMint,
    ) -> Result<Self, String> {
        let facts = *plugin
            .context::<StoreFacts>()
            .ok_or_else(|| "the store states no tail".to_string())?;
        // The settings the `open` lends, owned so they outlive its crossing ([`Lent`]).
        let settings: Arc<Vec<u8>> = Arc::new(settings.to_vec());
        // `open` is the settings' judge, as it was in 1.5.5: its refusal carries the plugin's own
        // reason (the host's lent reason buffer), which a bare `validate` answer cannot.
        let o = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: octets(&settings),
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
        );
        let c = Self::open_on_ticket(&plugin, &dispatcher, o, settings);
        if c.outcome != Outcome::Ready {
            return Err(c.open_failure(plugin.name()));
        }
        // DISCOVERY AT BOOT: a store door that states `ready` is awaited before it is served.
        plugin.ready(&dispatcher, crate::dispatch::ready::READY_DEADLINE)?;
        Ok(Self {
            plugin,
            dispatcher,
            facts,
            next_worker: AtomicU32::new(0),
            mint,
        })
    }

    /// `open` ON A TICKET (ARCHITECT ruling 2026-10-03 on Q-L16-2; the mechanism: `open` "may
    /// pend", on the control lane): submitted through the dispatcher and waited for, so a store
    /// whose connect step ([`busbar_contract::abi::sdk::store::StoreSlots::connect`]) pends on the
    /// connector is resumed on its wake and completes the open, and an unreachable backend still
    /// refuses the load at open, in the store's own words. Called on the dispatcher's only worker,
    /// it crosses ticket-less on this thread (as the bridge does, [`LoadedStore::inline`]).
    /// `settings` owns what `o` lends: the dispatcher keeps it until the crossing returns.
    fn open_on_ticket(
        plugin: &Plugin<Store>,
        dispatcher: &Dispatcher,
        mut o: Frame<OpenIn, OpenOut>,
        settings: Arc<Vec<u8>>,
    ) -> crate::dispatch::Called {
        let Some(worker) = pick_worker(dispatcher, 0) else {
            return plugin.call(life::OPEN, &mut o);
        };
        let Some(ticket) = dispatcher.mint(worker) else {
            return crate::dispatch::Called {
                outcome: Outcome::Refused,
                error: None,
                lease: 0,
                recall: None,
            };
        };
        let _recycle = Recycle(dispatcher, ticket);
        let deadline = now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64);
        let done = dispatcher
            .submit_lent(
                plugin,
                ticket,
                life::OPEN,
                o,
                DeadlineClass::Call,
                deadline,
                settings,
            )
            .wait_done();
        crate::dispatch::Called {
            outcome: done.outcome,
            error: done.error,
            lease: done.lease,
            recall: None,
        }
    }

    /// The store's own check of `settings`: it PARSES them and never opens a store. `Ok`, or its
    /// refusal's text, verbatim.
    ///
    /// # Errors
    /// The store's refusal of its settings.
    pub fn validate(plugin: &Plugin<Store>, settings: &[u8]) -> Result<(), String> {
        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(settings),
                // The dispatcher lends the reason buffer at the crossing.
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        let c = plugin.call(life::VALIDATE, &mut v);
        match (c.outcome, c.error) {
            (Outcome::Ready, _) => Ok(()),
            // The store's own words reach the operator VERBATIM (1.5.5 printed the plugin's text).
            (_, Some(e)) if !e.is_empty() => Err(String::from_utf8_lossy(&e).into_owned()),
            (o, _) => Err(format!("the store's validate answered {o:?}")),
        }
    }

    /// What the store states in its tail.
    pub fn facts(&self) -> StoreFacts {
        self.facts
    }

    /// The store's name, as its Statement states it.
    pub fn name(&self) -> &str {
        self.plugin.name()
    }

    /// The loaded instance (for the dispatcher's drain and the tests).
    pub fn plugin(&self) -> &Plugin<Store> {
        &self.plugin
    }

    /// A fresh `op_id` for one of the bridge's additive writes.
    fn mint(&self) -> OpId {
        (self.mint)()
    }

    fn release(&self, lease: u64) {
        if lease == 0 {
            return;
        }
        let mut f = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        let _ = self.plugin.call(life::RELEASE, &mut f);
    }

    // ── the two runners ──────────────────────────────────────────────────────────────────────

    /// THE BRIDGE'S RUNNER (ARCHITECT ruling 2026-10-03 on Q-L14-1; THE DESIGN, the plugin ABI: every call
    /// returns Ready or Pending(wake), and slow I/O pends, never a blocking thread): the op is
    /// SUBMITTED on a ticket exactly as [`StoreCalls`] submits it, and this synchronous caller
    /// waits for its completion. A store that answers PENDING is resumed by the dispatcher on its
    /// wake, its crossing never parked; a short answer is re-submitted once on the same ticket.
    /// Called on one of the dispatcher's own workers (whose thread cannot run the op while it
    /// waits), the op goes to another worker; on a dispatcher with that worker alone it crosses
    /// ticket-less on this thread ([`LoadedStore::inline`]).
    // TRANSITIONAL: the synchronous caller waits on its own thread (ARCHITECT ruling 2026-10-03 on
    // Q-L16-1); drains when the governance callers move to StoreCalls (D2/D3; 1.6.0-TODO.md).
    fn now<R: Req>(&self, mut r: R) -> (Ran<R::O>, Arc<Lend<R>>) {
        let s = r.slot();
        let Some(worker) = self.bridge_worker() else {
            let ran = self.inline(&mut r);
            return (ran, Lend::new(r));
        };
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return (Ran::host(Outcome::Refused, r.out()), Lend::new(r));
        };
        let _recycle = Recycle(&self.dispatcher, ticket);
        let (class, deadline) = deadline_of(s);
        let r = Lend::new(r);
        let mut regrown = false;
        loop {
            let frame = r.frame();
            // Settled before it is dropped, so the drop cancels nothing. The request is LENT: the
            // dispatcher holds it until the crossing returns, even past a watchdog fault.
            let done = self
                .dispatcher
                .submit_lent(&self.plugin, ticket, s, frame, class, deadline, r.lent())
                .wait_done();
            let out = done.frame.as_ref().map_or_else(|| r.get().out(), |f| f.out);
            if done.short && !regrown {
                regrown = true;
                r.grow(&out);
                continue;
            }
            let ran = Ran {
                outcome: done.outcome,
                out,
                error: done.error,
                lease: done.lease,
            };
            return (ran, r);
        }
    }

    /// The worker the bridge submits to: the next in turn, never the calling thread's own; `None`
    /// when the calling thread is the dispatcher's only worker.
    fn bridge_worker(&self) -> Option<u32> {
        pick_worker(
            &self.dispatcher,
            self.next_worker.fetch_add(1, Ordering::Relaxed),
        )
    }

    /// A ticket-less crossing on this thread, the one re-call of a short answer: the bridge's path
    /// on a dispatcher's only worker, where a ticketed op could never run.
    // TRANSITIONAL: the one-worker fallback of the bridge's wait (ARCHITECT ruling 2026-10-03 on
    // Q-L16-1); drains with the bridge (D2/D3; 1.6.0-TODO.md).
    fn inline<R: Req>(&self, r: &mut R) -> Ran<R::O> {
        let s = r.slot();
        let mut f = Frame::new(r.input(), r.out());
        let mut c = self.plugin.call(s, &mut f);
        if let Some(token) = c.recall.take() {
            r.grow(&f.out);
            f = Frame::new(r.input(), r.out());
            c = self.plugin.recall(token, s, &mut f);
        }
        // The SDK answers a ticket-less PENDING as FAULT, so a FAULT here is the pend (or worse).
        if c.outcome == Outcome::Fault {
            pended_on_the_bridge(self.plugin.name(), s);
        }
        Ran {
            outcome: c.outcome,
            out: f.out,
            error: c.error,
            lease: c.lease,
        }
    }

    /// THE TYPED RUNNER: submitted on a ticket, awaited, a short answer re-submitted once on the
    /// same ticket.
    async fn submit<R: Req>(&self, r: R) -> (Ran<R::O>, Arc<Lend<R>>) {
        let s = r.slot();
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return (Ran::host(Outcome::Refused, r.out()), Lend::new(r));
        };
        let _recycle = Recycle(&self.dispatcher, ticket);
        let (class, deadline) = deadline_of(s);
        let r = Lend::new(r);
        let mut regrown = false;
        loop {
            let frame = r.frame();
            // The request is LENT: the dispatcher holds it until the crossing returns, even when
            // the watchdog faults the op or this future is dropped first.
            let reply = self.dispatcher.submit_lent(
                &self.plugin,
                ticket,
                s,
                frame,
                class,
                deadline,
                r.lent(),
            );
            let done = reply.await;
            let out = done.frame.as_ref().map_or_else(|| r.get().out(), |f| f.out);
            if done.short && !regrown {
                regrown = true;
                r.grow(&out);
                continue;
            }
            let ran = Ran {
                outcome: done.outcome,
                out,
                error: done.error,
                lease: done.lease,
            };
            return (ran, r);
        }
    }
}

/// The worker a synchronous waiter submits to: the `turn`th in turn, never the calling thread's
/// own; `None` when the calling thread is the dispatcher's only worker.
fn pick_worker(dispatcher: &Dispatcher, turn: u32) -> Option<u32> {
    let workers = dispatcher.workers().max(1);
    let next = turn % workers;
    match dispatcher.current_worker() {
        None => Some(next),
        Some(_) if workers == 1 => None,
        Some(me) if me == next => Some((next + 1) % workers),
        Some(_) => Some(next),
    }
}

/// Op `s`'s deadline class and its deadline: a Call-class op may pend [`CALL_DEADLINE`]; a
/// WriteBehind op is never cancelled, so it carries none.
fn deadline_of(s: u32) -> (DeadlineClass, u64) {
    let class = OPS[(s - LIFECYCLE_SLOTS) as usize].deadline;
    let deadline = match class {
        DeadlineClass::WriteBehind => 0,
        _ => now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64),
    };
    (class, deadline)
}

impl Drop for LoadedStore {
    /// The handle is the instance's owner: dropping it (a reload's retired store, a test's) closes
    /// the instance, so what it holds (its kept connections) goes with it.
    fn drop(&mut self) {
        let mut f: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
        let _ = self.plugin.call(life::CLOSE, &mut f);
    }
}

/// The ticket goes back when the call is over, however it ended.
struct Recycle<'a>(
    &'a Dispatcher,
    busbar_contract::abi::mechanism::ticket::Ticket,
);
impl Drop for Recycle<'_> {
    fn drop(&mut self) {
        self.0.recycle(self.1);
    }
}

/// A ticket-less crossing ([`LoadedStore::inline`], on a dispatcher's only worker) that PENDED
/// faulted the store. Loud: an error line always, and a debug build panics, so a pend there never
/// goes unseen.
fn pended_on_the_bridge(store: &str, s: u32) {
    tracing::error!(
        store,
        op = <Store as crate::dispatch::Kind>::op_name(s),
        "a store op faulted on the bridge's ticket-less crossing (the dispatcher's only worker called it)"
    );
    debug_assert!(
        false,
        "store '{store}' faulted op {s} on the bridge's ticket-less crossing (a pending op is FAULT there)"
    );
}

/// ONE OP'S REQUEST, LENT TO THE DISPATCHER (THE DESIGN §2: "The memory a call lends a plugin
/// lives until that call completes, abandoned or not, for every kind (a submit that the watchdog
/// can abandon uses the lending submit)"). Every pointer an op's `in` carries names memory its
/// request owns ([`Owned`] and its own buffers); the runner hands a clone of this `Arc` to
/// [`Dispatcher::submit_lent`], so a crossing the watchdog abandoned, or one whose caller stopped
/// waiting, still reads and writes live memory until it returns.
struct Lend<R>(UnsafeCell<R>);
// SAFETY: a request is plain data and raw pointers into memory it owns. The host touches it only
// between crossings (building a frame, growing it on a SHORT answer, reading a READY answer, each
// after the crossing that wrote it returned); the dispatcher only holds it and drops it.
unsafe impl<R> Send for Lend<R> {}
// SAFETY: as `Send`: no two threads touch a request at once.
unsafe impl<R> Sync for Lend<R> {}

impl<R: Req> Lend<R> {
    fn new(r: R) -> Arc<Self> {
        Arc::new(Self(UnsafeCell::new(r)))
    }

    /// The request, to read an answer the crossing that wrote it has returned from.
    fn get(&self) -> &R {
        // SAFETY: see `Send`: no crossing writes the request's own fields, and the buffers they
        // own are read only from a READY answer, whose crossing returned.
        unsafe { &*self.0.get() }
    }

    /// The next submit's frame. Called only before the first submit or after a SHORT answer,
    /// when no crossing of the op runs.
    fn frame(&self) -> Frame<R::I, R::O> {
        // SAFETY: as `frame`'s contract: nothing else touches the request now.
        let r = unsafe { &mut *self.0.get() };
        Frame::new(r.input(), r.out())
    }

    /// Grow the buffers a SHORT answer named (its crossing returned).
    fn grow(&self, out: &R::O) {
        // SAFETY: as `frame`.
        unsafe { &mut *self.0.get() }.grow(out);
    }

    /// The owner the dispatcher holds until the op completes.
    fn lent(self: &Arc<Self>) -> Lent {
        Arc::clone(self) as Lent
    }
}

/// WHAT ONE OP'S `in` POINTS AT, OWNED BY ITS REQUEST: every string, byte run and row array the
/// caller only borrowed is copied in, so the request (lent whole to the dispatcher, [`Lend`]) keeps
/// it alive past the caller's own borrow. A heap buffer does not move when its `Vec` does.
#[derive(Default)]
struct Owned {
    bytes: Vec<Vec<u8>>,
    /// Secret material: zeroed when the request drops.
    secrets: Vec<Zeroing>,
    rows: Vec<Box<dyn std::any::Any>>,
}

impl Owned {
    fn keep(&mut self, b: Vec<u8>) -> (*const u8, usize) {
        let at = (b.as_ptr(), b.len());
        self.bytes.push(b);
        at
    }

    fn text(&mut self, s: &str) -> AbiStr {
        let (ptr, len) = self.keep(s.as_bytes().to_vec());
        AbiStr { ptr, len }
    }

    fn opt_text(&mut self, s: Option<&str>) -> AbiStr {
        s.map_or(
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            |s| self.text(s),
        )
    }

    fn octets(&mut self, b: &[u8]) -> Blob {
        let (ptr, len) = self.keep(b.to_vec());
        Blob {
            ptr,
            len,
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    fn json(&mut self, b: Vec<u8>) -> Blob {
        let (ptr, len) = self.keep(b);
        Blob {
            ptr,
            len,
            fmt: BLOB_JSON,
            flags: 0,
        }
    }

    fn secret_json(&mut self, b: Vec<u8>) -> Blob {
        let (ptr, len) = (b.as_ptr(), b.len());
        self.secrets.push(Zeroing(b));
        Blob {
            ptr,
            len,
            fmt: BLOB_JSON,
            flags: BLOB_SECRET,
        }
    }

    fn rows<T: 'static>(&mut self, v: Vec<T>) -> (*const T, usize) {
        let at = (v.as_ptr(), v.len());
        self.rows.push(Box::new(v));
        at
    }
}

/// An `in` built over memory it owns.
fn owned_in<I>(f: impl FnOnce(&mut Owned, InHead) -> I) -> (I, Owned) {
    let mut o = Owned::default();
    let i = f(&mut o, in_head());
    (i, o)
}

/// An `in` that points at nothing.
fn bare<I>(i: I) -> (I, Owned) {
    (i, Owned::default())
}

/// What one op answered.
struct Ran<O> {
    outcome: Outcome,
    out: O,
    error: Option<Vec<u8>>,
    lease: u64,
}

impl<O> Ran<O> {
    fn host(outcome: Outcome, out: O) -> Self {
        Self {
            outcome,
            out,
            error: None,
            lease: 0,
        }
    }

    fn text(&self) -> String {
        self.error
            .as_ref()
            .map(|e| String::from_utf8_lossy(e).into_owned())
            .unwrap_or_default()
    }

    /// A non-READY answer as the typed failure.
    fn failure(&self) -> StoreFailure {
        let text = self.text();
        match self.outcome {
            Outcome::Refused if self.error.is_none() => StoreFailure::Overloaded,
            Outcome::Refused if text.starts_with(DIAG_OPID_CONFLICT) => StoreFailure::Conflict,
            Outcome::Refused if text.contains(DIAG_CAP_CONFLICT) => {
                let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
                digits.parse().map_or(
                    StoreFailure::Refused(text.clone()),
                    StoreFailure::CapConflict,
                )
            }
            Outcome::Refused => StoreFailure::Refused(text),
            Outcome::Failed => StoreFailure::Failed(text),
            o => StoreFailure::Fault(format!("{o:?} {text}")),
        }
    }

    fn ok(&self) -> Result<(), StoreFailure> {
        if self.outcome == Outcome::Ready {
            Ok(())
        } else {
            Err(self.failure())
        }
    }
}

/// The `RecordStore` surface's error for a store call. A FAILED op carries the store's own text
/// unchanged, so the operator reads `store error: <the backend's text>` exactly as 1.5.5 printed it
/// (oracle BOOT-172/BOOT-175: `store error: database disk image is malformed`); the other failures
/// have no 1.5.5 counterpart and keep their typed wording.
fn bridge<T>(r: Result<T, StoreFailure>) -> RecordStoreResult<T> {
    r.map_err(|f| match f {
        StoreFailure::Failed(text) => RecordStoreError(text),
        other => RecordStoreError(other.to_string()),
    })
}

// ── the requests ─────────────────────────────────────────────────────────────────────────────

/// One op's `in`/`out`, built over buffers the request owns (never over the caller's borrow).
trait Req: 'static {
    type I: InFrame;
    type O: OutFrame;
    fn slot(&self) -> u32;
    /// The `in`, pointing at the request's own buffers and borrowed data.
    fn input(&mut self) -> Self::I;
    /// A blank `out`.
    fn out(&self) -> Self::O;
    /// Grow the buffers a short answer named.
    fn grow(&mut self, _out: &Self::O) {}
}

/// An op with no host result buffers: a fixed `in` over what it owns.
struct Fixed<I, O> {
    slot: u32,
    input: I,
    _owned: Owned,
    _o: PhantomData<O>,
}

// SAFETY: the `in`'s pointers point into the request's own `Owned`; a request moves with the
// future that owns it (or is lent whole, [`Lend`]) and is touched by one thread at a time.
unsafe impl<I, O> Send for Fixed<I, O> {}

fn fixed<I: InFrame, O: OutFrame>(slot: u32, (input, owned): (I, Owned)) -> Fixed<I, O> {
    Fixed {
        slot,
        input,
        _owned: owned,
        _o: PhantomData,
    }
}

impl<I: InFrame, O: OutFrame> Req for Fixed<I, O> {
    type I = I;
    type O = O;
    fn slot(&self) -> u32 {
        self.slot
    }
    fn input(&mut self) -> I {
        self.input
    }
    fn out(&self) -> O {
        blank()
    }
}

/// A zeroed `out` with a blank head.
fn blank<O: OutFrame>() -> O {
    // SAFETY: every `OutFrame` is `#[repr(C)]` plain data for which all-zero is valid.
    let mut o: O = unsafe { std::mem::zeroed() };
    // SAFETY: an `OutFrame` leads with its `OutHead`.
    unsafe {
        std::ptr::from_mut(&mut o)
            .cast::<OutHead>()
            .write(out_head())
    };
    o
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn from_json<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, StoreFailure> {
    serde_json::from_slice(b)
        .map_err(|e| StoreFailure::Fault(format!("a store record does not decode: {e}")))
}

/// Copy `len` bytes at `ptr` (the plugin's, valid under the answer's lease, checked by the kind).
fn copy(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: the store kind's validator checked the pointer and length of every READY answer's
    // leased item, and the lease holds the bytes until `release`.
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

fn items<T: Copy>(ptr: *const T, len: usize) -> Vec<T> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: as `copy`: a checked, leased (or host-owned) array of `len` items.
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

impl LoadedStore {
    fn read_one(&self, ran: Ran<LeasedBlobOut>) -> Result<Option<Vec<u8>>, StoreFailure> {
        let r = ran.ok().map(|()| {
            (ran.out.found == FOUND).then(|| copy(ran.out.record.ptr, ran.out.record.len))
        });
        self.release(ran.lease);
        r
    }

    fn read_list(&self, ran: Ran<LeasedListOut>) -> Result<Vec<Vec<u8>>, StoreFailure> {
        let r = ran.ok().map(|()| {
            items(ran.out.items, ran.out.items_len)
                .iter()
                .map(|b| copy(b.ptr, b.len))
                .collect()
        });
        self.release(ran.lease);
        r
    }

    fn read_strs(&self, ran: Ran<LeasedStrListOut>) -> Result<Vec<String>, StoreFailure> {
        let r = ran.ok().map(|()| {
            items(ran.out.items, ran.out.items_len)
                .iter()
                .map(|s| String::from_utf8_lossy(&copy(s.ptr, s.len)).into_owned())
                .collect()
        });
        self.release(ran.lease);
        r
    }

    fn records<T: serde::de::DeserializeOwned>(
        &self,
        ran: Ran<LeasedListOut>,
    ) -> Result<Vec<T>, StoreFailure> {
        self.read_list(ran)?.iter().map(|b| from_json(b)).collect()
    }

    fn record<T: serde::de::DeserializeOwned>(
        &self,
        ran: Ran<LeasedBlobOut>,
    ) -> Result<Option<T>, StoreFailure> {
        self.read_one(ran)?.map(|b| from_json(&b)).transpose()
    }
}

/// A request-path read into one host byte buffer (`record_get`, `get_plane_record`).
struct BytesReq<I> {
    slot: u32,
    input: I,
    _owned: Owned,
    buf: Vec<u8>,
    place: fn(&mut I, HostBuf),
}
// SAFETY: as `Fixed`.
unsafe impl<I> Send for BytesReq<I> {}

impl<I: InFrame> Req for BytesReq<I> {
    type I = I;
    type O = HostBytesOut;
    fn slot(&self) -> u32 {
        self.slot
    }
    fn input(&mut self) -> I {
        let mut i = self.input;
        (self.place)(
            &mut i,
            HostBuf {
                ptr: self.buf.as_mut_ptr(),
                cap: self.buf.len(),
            },
        );
        i
    }
    fn out(&self) -> HostBytesOut {
        blank()
    }
    fn grow(&mut self, out: &HostBytesOut) {
        self.buf = vec![0; out.needed as usize];
    }
}

impl<I> BytesReq<I> {
    fn read(&self, ran: &Ran<HostBytesOut>) -> Result<Option<Vec<u8>>, StoreFailure> {
        ran.ok()?;
        Ok((ran.out.found == FOUND).then(|| self.buf[..ran.out.written as usize].to_vec()))
    }
}

/// A request-path list into host buffers: `items` rows of `T` and one byte buffer.
struct ListReq<I, T> {
    slot: u32,
    input: I,
    _owned: Owned,
    items: Vec<T>,
    bytes: Vec<u8>,
    place: fn(&mut I, *mut T, usize, HostBuf),
}
// SAFETY: as `Fixed`.
unsafe impl<I, T> Send for ListReq<I, T> {}

impl<I: InFrame, T: Copy + 'static> Req for ListReq<I, T> {
    type I = I;
    type O = HostListOut;
    fn slot(&self) -> u32 {
        self.slot
    }
    fn input(&mut self) -> I {
        let mut i = self.input;
        (self.place)(
            &mut i,
            self.items.as_mut_ptr(),
            self.items.len(),
            HostBuf {
                ptr: self.bytes.as_mut_ptr(),
                cap: self.bytes.len(),
            },
        );
        i
    }
    fn out(&self) -> HostListOut {
        blank()
    }
    fn grow(&mut self, out: &HostListOut) {
        let n = (out.needed_items as usize).max(self.items.len());
        // SAFETY: every row type here is `#[repr(C)]` plain data for which all-zero is valid.
        self.items = vec![unsafe { std::mem::zeroed() }; n];
        self.bytes = vec![0; (out.needed_bytes as usize).max(self.bytes.len())];
    }
}

impl<I, T: Copy> ListReq<I, T> {
    fn new(
        slot: u32,
        (input, owned): (I, Owned),
        place: fn(&mut I, *mut T, usize, HostBuf),
    ) -> Self {
        Self {
            slot,
            input,
            _owned: owned,
            // SAFETY: as `grow`.
            items: vec![unsafe { std::mem::zeroed() }; FIRST_ITEMS],
            bytes: vec![0; FIRST_BYTES],
            place,
        }
    }

    fn rows(&self, ran: &Ran<HostListOut>) -> Result<&[T], StoreFailure> {
        ran.ok()?;
        Ok(&self.items[..ran.out.items_written as usize])
    }
}

fn place_blobs(i: &mut ListPlaneRecordsIn, p: *mut Blob, n: usize, bytes: HostBuf) {
    i.out = HostBlobs {
        items: p,
        items_cap: n,
        bytes,
    };
}
fn place_sessions(i: &mut SessionsForIn, p: *mut SessionRow, n: usize, bytes: HostBuf) {
    i.out = HostSessions {
        items: p,
        items_cap: n,
        bytes,
    };
}
fn place_records(i: &mut RecordScanIn, p: *mut RecordEntry, n: usize, bytes: HostBuf) {
    i.out = HostRecords {
        items: p,
        items_cap: n,
        bytes,
    };
}

/// `reserve`: the grants array sized to the cells.
struct ReserveReq {
    input: ReserveIn,
    /// The cells' bucket, pool and class words.
    _owned: Owned,
    cells: Vec<UnitCell>,
    grants: Vec<CellGrant>,
}
// SAFETY: as `Fixed`.
unsafe impl Send for ReserveReq {}

impl Req for ReserveReq {
    type I = ReserveIn;
    type O = ReserveOut;
    fn slot(&self) -> u32 {
        slot::RESERVE
    }
    fn input(&mut self) -> ReserveIn {
        let mut i = self.input;
        i.cells = self.cells.as_ptr();
        i.cells_len = self.cells.len();
        i.grants = self.grants.as_mut_ptr();
        i.grants_cap = self.grants.len();
        i
    }
    fn out(&self) -> ReserveOut {
        blank()
    }
    fn grow(&mut self, out: &ReserveOut) {
        self.grants = vec![zero_grant(); out.needed_grants as usize];
    }
}

fn zero_grant() -> CellGrant {
    CellGrant {
        slice_id: 0,
        granted: 0,
        valid_until_ms: 0,
    }
}

fn unit_cell(o: &mut Owned, c: &Cell<'_>) -> UnitCell {
    let (dimension, class_key) = match c.key.dimension {
        Dimension::NanoUnits => (st::DIM_NANO_UNITS, None),
        Dimension::Requests => (st::DIM_REQUESTS, None),
        Dimension::Concurrency => (st::DIM_CONCURRENCY, None),
        Dimension::Class(k) => (st::DIM_CLASS, Some(k)),
    };
    UnitCell {
        bucket: o.text(c.key.bucket),
        pool: o.opt_text(c.key.pool),
        dimension,
        _r: 0,
        class_key: o.opt_text(class_key),
        amount: c.amount,
        window_start: c.key.window_start,
    }
}

fn window_cap(o: &mut Owned, c: &Cap<'_>) -> WindowCap {
    let u = unit_cell(
        o,
        &Cell {
            key: c.key,
            amount: 0,
        },
    );
    WindowCap {
        bucket: u.bucket,
        pool: u.pool,
        dimension: u.dimension,
        _r: 0,
        class_key: u.class_key,
        window_start: c.key.window_start,
        cap: c.cap,
        config_gen: c.config_gen,
    }
}

/// `slice_release`: the released array sized to the items.
struct ReleaseReq {
    input: SliceReleaseIn,
    items: Vec<ReleaseItem>,
    released: Vec<u64>,
}
// SAFETY: as `Fixed`.
unsafe impl Send for ReleaseReq {}

impl Req for ReleaseReq {
    type I = SliceReleaseIn;
    type O = SliceReleaseOut;
    fn slot(&self) -> u32 {
        slot::SLICE_RELEASE
    }
    fn input(&mut self) -> SliceReleaseIn {
        let mut i = self.input;
        i.items = self.items.as_ptr();
        i.items_len = self.items.len();
        i.released = self.released.as_mut_ptr();
        i.released_cap = self.released.len();
        i
    }
    fn out(&self) -> SliceReleaseOut {
        blank()
    }
    fn grow(&mut self, out: &SliceReleaseOut) {
        self.released = vec![0; out.needed_released as usize];
    }
}

fn plane_row(o: &mut Owned, r: PlaneRecordRef<'_>) -> PlaneRecordRow {
    PlaneRecordRow {
        kind: o.text(r.kind),
        id: o.text(r.id),
        parent: o.opt_text(r.parent),
        seq: r.seq,
        ts: r.ts,
        disposition: match r.disposition {
            PlaneDisposition::Active => st::DISPOSITION_ACTIVE,
            PlaneDisposition::Terminal => st::DISPOSITION_TERMINAL,
        },
        _reserved: 0,
        body: o.octets(r.body),
    }
}

fn in_of<T>(f: impl FnOnce(InHead) -> T) -> T {
    f(in_head())
}

// ── the ops, shared by both surfaces ─────────────────────────────────────────────────────────

/// Run `req` through `$run` (`now` or `submit`), on `$self`.
macro_rules! run {
    ($self:ident, now, $r:expr) => {
        $self.now($r)
    };
    ($self:ident, submit, $r:expr) => {
        $self.submit($r).await
    };
}

/// The typed ops over a runner: the bridge's `now` (submitted on a ticket and waited for) and
/// [`StoreCalls`]' `submit` (submitted on a ticket and awaited).
impl LoadedStore {
    fn reserve_req(op: OpId, epoch: u64, cells: &[Cell<'_>]) -> ReserveReq {
        let mut owned = Owned::default();
        let cells: Vec<UnitCell> = cells.iter().map(|c| unit_cell(&mut owned, c)).collect();
        let n = cells.len();
        ReserveReq {
            input: in_of(|head| ReserveIn {
                head,
                op_id: op,
                epoch,
                cells: std::ptr::null(),
                cells_len: 0,
                grants: std::ptr::null_mut(),
                grants_cap: 0,
            }),
            _owned: owned,
            cells,
            grants: vec![zero_grant(); n],
        }
    }

    fn reserve_read(r: &ReserveReq, ran: &Ran<ReserveOut>) -> Result<Vec<Grant>, StoreFailure> {
        match ran.outcome {
            Outcome::Ready => Ok(r.grants[..ran.out.grants_len]
                .iter()
                .map(|g| Grant {
                    slice_id: g.slice_id,
                    granted: g.granted,
                    valid_until_ms: g.valid_until_ms,
                })
                .collect()),
            Outcome::Failed if ran.out.reason != 0 => {
                let cell = ran.out.failed_cell;
                Err(StoreFailure::Reserve(match ran.out.reason {
                    RESERVE_EXHAUSTED => ReserveRefused::Exhausted { cell },
                    RESERVE_STALE_EPOCH => ReserveRefused::StaleEpoch,
                    RESERVE_UNAVAILABLE => ReserveRefused::Unavailable,
                    RESERVE_NO_CAP => ReserveRefused::NoCap { cell },
                    _ => ReserveRefused::Unavailable,
                }))
            }
            _ => Err(ran.failure()),
        }
    }

    fn release_req(op: OpId, epoch: u64, items: &[(u64, u64)]) -> ReleaseReq {
        let items: Vec<ReleaseItem> = items
            .iter()
            .map(|&(slice_id, unspent)| ReleaseItem { slice_id, unspent })
            .collect();
        let n = items.len();
        ReleaseReq {
            input: in_of(|head| SliceReleaseIn {
                head,
                op_id: op,
                epoch,
                items: std::ptr::null(),
                items_len: 0,
                released: std::ptr::null_mut(),
                released_cap: 0,
            }),
            items,
            released: vec![0; n],
        }
    }

    fn get_plane_req(kind: &str, id: &str) -> BytesReq<GetPlaneRecordIn> {
        let (input, owned) = owned_in(|o, head| GetPlaneRecordIn {
            head,
            kind: o.text(kind),
            id: o.text(id),
            body: HostBuf {
                ptr: std::ptr::null_mut(),
                cap: 0,
            },
        });
        BytesReq {
            slot: slot::GET_PLANE_RECORD,
            input,
            _owned: owned,
            buf: vec![0; FIRST_BYTES],
            place: |i, b| i.body = b,
        }
    }

    fn record_get_req(schema: &str, key: &[u8]) -> BytesReq<RecordGetIn> {
        let (input, owned) = owned_in(|o, head| RecordGetIn {
            head,
            schema: o.text(schema),
            key: o.octets(key),
            value: HostBuf {
                ptr: std::ptr::null_mut(),
                cap: 0,
            },
        });
        BytesReq {
            slot: slot::RECORD_GET,
            input,
            _owned: owned,
            buf: vec![0; FIRST_BYTES],
            place: |i, b| i.value = b,
        }
    }

    fn list_plane_req(kind: &str, selector: &PlaneSelector) -> ListReq<ListPlaneRecordsIn, Blob> {
        let (sel, parent) = match selector {
            PlaneSelector::All => (SELECT_ALL, None),
            PlaneSelector::Parent(p) => (SELECT_PARENT, Some(&**p)),
        };
        ListReq::new(
            slot::LIST_PLANE_RECORDS,
            owned_in(|o, head| ListPlaneRecordsIn {
                head,
                kind: o.text(kind),
                selector: sel,
                _reserved: 0,
                parent: o.opt_text(parent),
                out: HostBlobs {
                    items: std::ptr::null_mut(),
                    items_cap: 0,
                    bytes: HostBuf {
                        ptr: std::ptr::null_mut(),
                        cap: 0,
                    },
                },
            }),
            place_blobs,
        )
    }

    fn sessions_req(principal: &str) -> ListReq<SessionsForIn, SessionRow> {
        ListReq::new(
            slot::SESSIONS_FOR,
            owned_in(|o, head| SessionsForIn {
                head,
                principal: o.text(principal),
                out: HostSessions {
                    items: std::ptr::null_mut(),
                    items_cap: 0,
                    bytes: HostBuf {
                        ptr: std::ptr::null_mut(),
                        cap: 0,
                    },
                },
            }),
            place_sessions,
        )
    }

    fn scan_req(schema: &str, prefix: &[u8], limit: u32) -> ListReq<RecordScanIn, RecordEntry> {
        let mut r = ListReq::new(
            slot::RECORD_SCAN,
            owned_in(|o, head| RecordScanIn {
                head,
                schema: o.text(schema),
                prefix: o.octets(prefix),
                limit,
                _reserved: 0,
                out: HostRecords {
                    items: std::ptr::null_mut(),
                    items_cap: 0,
                    bytes: HostBuf {
                        ptr: std::ptr::null_mut(),
                        cap: 0,
                    },
                },
            }),
            place_records,
        );
        // A scan never answers more than its limit.
        r.items.truncate((limit as usize).clamp(1, FIRST_ITEMS));
        r
    }

    fn token_req(
        slot: u32,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Fixed<TokenIn, VerdictOut> {
        fixed(
            slot,
            owned_in(|o, head| TokenIn {
                head,
                kind: o.text(kind),
                token: o.text(token),
                expires_at,
                now,
            }),
        )
    }
}

/// Read a host-buffer blob the plugin pointed into (inside the host's own byte buffer).
fn host_blob(b: &Blob) -> Vec<u8> {
    copy(b.ptr, b.len)
}

// ── StoreCalls: submitted and awaited ────────────────────────────────────────────────────────

fn boxed<'a, T>(f: impl Future<Output = Result<T, StoreFailure>> + Send + 'a) -> StoreCall<'a, T> {
    Box::pin(f)
}

impl StoreCalls for LoadedStore {
    fn reserve<'a>(
        &'a self,
        op: OpId,
        epoch: u64,
        cells: &'a [Cell<'a>],
    ) -> StoreCall<'a, Vec<Grant>> {
        boxed(async move {
            let (ran, r) = run!(self, submit, Self::reserve_req(op, epoch, cells));
            Self::reserve_read(r.get(), &ran)
        })
    }

    fn slice_release<'a>(
        &'a self,
        op: OpId,
        epoch: u64,
        items: &'a [(u64, u64)],
    ) -> StoreCall<'a, Vec<u64>> {
        boxed(async move {
            let (ran, r) = run!(self, submit, Self::release_req(op, epoch, items));
            ran.ok()?;
            Ok(r.get().released[..ran.out.released_len].to_vec())
        })
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::ADD_USAGE_BATCH,
                owned_in(|o, head| {
                    let rows: Vec<UsageCell> = cells
                        .iter()
                        .map(|(b, w, d)| UsageCell {
                            bucket: o.text(b),
                            window_start: *w,
                            delta: o.json(to_json(d)),
                        })
                        .collect();
                    let (cells, cells_len) = o.rows(rows);
                    AddUsageBatchIn {
                        head,
                        op_id: op,
                        cells,
                        cells_len,
                    }
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::ADD_METERING_BATCH,
                owned_in(|o, head| {
                    let blobs: Vec<Blob> = deltas.iter().map(|d| o.json(to_json(d))).collect();
                    let (records, records_len) = o.rows(blobs);
                    OpBlobsIn {
                        head,
                        op_id: op,
                        records,
                        records_len,
                    }
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn append_audit_batch<'a>(&'a self, op: OpId, entries: &'a [AuditRecord]) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::APPEND_AUDIT_BATCH,
                owned_in(|o, head| {
                    let blobs: Vec<Blob> = entries.iter().map(|e| o.json(to_json(e))).collect();
                    let (records, records_len) = o.rows(blobs);
                    OpBlobsIn {
                        head,
                        op_id: op,
                        records,
                        records_len,
                    }
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn window_caps<'a>(&'a self, op: OpId, caps: &'a [Cap<'a>]) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::WINDOW_CAPS,
                owned_in(|o, head| {
                    let rows: Vec<WindowCap> = caps.iter().map(|c| window_cap(o, c)).collect();
                    let (caps, caps_len) = o.rows(rows);
                    WindowCapsIn {
                        head,
                        op_id: op,
                        caps,
                        caps_len,
                    }
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn append_batch<'a>(
        &'a self,
        op: OpId,
        stream: &'a str,
        records: &'a [RecordBytes],
    ) -> StoreCall<'a, Head> {
        boxed(async move {
            let r = fixed::<_, HeadOut>(
                slot::APPEND_BATCH,
                owned_in(|o, head| {
                    let blobs: Vec<Blob> = records.iter().map(|r| o.octets(r.as_slice())).collect();
                    let stream = o.text(stream);
                    let (records, records_len) = o.rows(blobs);
                    AppendBatchIn {
                        head,
                        op_id: op,
                        stream,
                        records,
                        records_len,
                    }
                }),
            );
            let (ran, _) = run!(self, submit, r);
            ran.ok()?;
            Ok(Head {
                seq: ran.out.seq,
                epoch: ran.out.epoch,
            })
        })
    }

    fn heads(&self) -> StoreCall<'_, Vec<(String, Head)>> {
        boxed(async move {
            let r = fixed::<_, HeadsOut>(slot::HEADS, bare(in_head()));
            let (ran, _) = run!(self, submit, r);
            let out = ran.ok().map(|()| {
                items(ran.out.items, ran.out.items_len)
                    .iter()
                    .map(|h| {
                        (
                            String::from_utf8_lossy(&copy(h.stream.ptr, h.stream.len)).into_owned(),
                            Head {
                                seq: h.seq,
                                epoch: h.epoch,
                            },
                        )
                    })
                    .collect()
            });
            self.release(ran.lease);
            out
        })
    }

    fn session_put<'a>(
        &'a self,
        session: u64,
        node: &'a str,
        principal: &'a str,
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::SESSION_PUT,
                owned_in(|o, head| SessionPutIn {
                    head,
                    session,
                    node: o.text(node),
                    principal: o.text(principal),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn session_remove(&self, session: u64) -> StoreCall<'_, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::SESSION_REMOVE,
                bare(in_of(|head| U64In {
                    head,
                    value: session,
                })),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn sessions_for<'a>(&'a self, principal: &'a str) -> StoreCall<'a, Vec<(u64, String)>> {
        boxed(async move {
            let (ran, r) = run!(self, submit, Self::sessions_req(principal));
            Ok(r.get()
                .rows(&ran)?
                .iter()
                .map(|s| {
                    (
                        s.session,
                        String::from_utf8_lossy(&copy(s.node.ptr, s.node.len)).into_owned(),
                    )
                })
                .collect())
        })
    }

    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::RECORD_PUT,
                owned_in(|o, head| RecordPutIn {
                    head,
                    schema: o.text(schema),
                    key: o.octets(key),
                    value: o.octets(value.as_slice()),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        boxed(async move {
            let (ran, r) = run!(self, submit, Self::record_get_req(schema, key));
            r.get()
                .read(&ran)?
                .map(|v| {
                    RecordBytes::new(v).map_err(|n| {
                        StoreFailure::Fault(format!("a record of {n} bytes is over the ceiling"))
                    })
                })
                .transpose()
        })
    }

    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        boxed(async move {
            if limit == 0 {
                return Ok(Vec::new());
            }
            let (ran, r) = run!(self, submit, Self::scan_req(schema, prefix, limit));
            r.get()
                .rows(&ran)?
                .iter()
                .map(|e| {
                    let v = RecordBytes::new(host_blob(&e.value)).map_err(|n| {
                        StoreFailure::Fault(format!("a record of {n} bytes is over the ceiling"))
                    })?;
                    Ok((host_blob(&e.key), v))
                })
                .collect()
        })
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::UPSERT_PLANE_RECORD,
                owned_in(|o, head| UpsertPlaneRecordIn {
                    head,
                    record: plane_row(o, record),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        boxed(async move {
            let (ran, r) = run!(self, submit, Self::get_plane_req(kind, id));
            r.get().read(&ran)
        })
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::APPEND_PLANE_RECORD,
                owned_in(|o, head| AppendPlaneRecordIn {
                    head,
                    op_id: op,
                    record: plane_row(o, record),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        boxed(async move {
            let (ran, r) = run!(self, submit, Self::list_plane_req(kind, selector));
            Ok(r.get().rows(&ran)?.iter().map(host_blob).collect())
        })
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::DELETE_PLANE_RECORD,
                owned_in(|o, head| KindIdIn {
                    head,
                    kind: o.text(kind),
                    id: o.text(id),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        boxed(async move {
            let r = Self::token_req(slot::REDEEM_PLANE_TOKEN, kind, token, expires_at, now);
            let (ran, _) = run!(self, submit, r);
            ran.ok()?;
            Ok(ran.out.verdict == VERDICT_YES)
        })
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        boxed(async move {
            let r = Self::token_req(slot::PLANE_TOKEN_LIVE, kind, token, expires_at, now);
            let (ran, _) = run!(self, submit, r);
            ran.ok()?;
            Ok(ran.out.verdict == VERDICT_YES)
        })
    }
}

// ── RecordStore: the synchronous bridge (until M6) ────────────────────────────────────────────────

impl LoadedStore {
    fn plain<I: InFrame>(&self, s: u32, input: (I, Owned)) -> RecordStoreResult<()> {
        bridge(self.now(fixed::<I, OutHead>(s, input)).0.ok())
    }

    fn one<I: InFrame, T: serde::de::DeserializeOwned>(
        &self,
        s: u32,
        input: (I, Owned),
    ) -> RecordStoreResult<Option<T>> {
        let (ran, _) = self.now(fixed::<I, LeasedBlobOut>(s, input));
        bridge(self.record(ran))
    }

    fn many<I: InFrame, T: serde::de::DeserializeOwned>(
        &self,
        s: u32,
        input: (I, Owned),
    ) -> RecordStoreResult<Vec<T>> {
        let (ran, _) = self.now(fixed::<I, LeasedListOut>(s, input));
        bridge(self.records(ran))
    }

    fn count<I: InFrame>(&self, s: u32, input: (I, Owned)) -> RecordStoreResult<u64> {
        let (ran, _) = self.now(fixed::<I, CountOut>(s, input));
        bridge(ran.ok().map(|()| ran.out.count))
    }

    fn id(id: &str) -> (IdIn, Owned) {
        owned_in(|o, head| IdIn {
            head,
            id: o.text(id),
        })
    }

    fn value(v: u64) -> (U64In, Owned) {
        bare(in_of(|head| U64In { head, value: v }))
    }

    fn strs<I: InFrame>(&self, s: u32, input: (I, Owned)) -> RecordStoreResult<Vec<String>> {
        let (ran, _) = self.now(fixed::<I, LeasedStrListOut>(s, input));
        bridge(self.read_strs(ran))
    }
}

impl RecordStore for LoadedStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.plain(
            slot::PUT_KEY,
            owned_in(|o, head| BlobIn {
                head,
                record: o.json(to_json(key)),
            }),
        )
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.one(slot::GET_KEY, Self::id(id))
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.many(slot::LIST_KEYS, bare(in_head()))
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.plain(slot::DELETE_KEY, Self::id(id))
    }

    fn scrub_key(&self, id: &str) -> RecordStoreResult<()> {
        self.plain(slot::SCRUB_KEY, Self::id(id))
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.many(slot::LIST_KEYS_SINCE, Self::value(since))
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        let got: Option<UsageLedger> = self.one(
            slot::GET_USAGE,
            owned_in(|o, head| WindowIn {
                head,
                bucket: o.text(bucket_id),
                window_start,
            }),
        )?;
        Ok(got.unwrap_or_default())
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.plain(
            slot::PUT_USAGE,
            owned_in(|o, head| PutUsageIn {
                head,
                bucket: o.text(bucket_id),
                window_start,
                ledger: o.json(to_json(ledger)),
            }),
        )
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.plain(
            slot::ADD_USAGE,
            owned_in(|o, head| AddUsageIn {
                head,
                op_id: self.mint(),
                cell: UsageCell {
                    bucket: o.text(bucket_id),
                    window_start,
                    delta: o.json(to_json(delta)),
                },
            }),
        )
    }

    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.plain(
            slot::ADD_METERING,
            owned_in(|o, head| OpBlobIn {
                head,
                op_id: self.mint(),
                record: o.json(to_json(delta)),
            }),
        )
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.many(slot::LIST_METERING, Self::value(bucket))
    }

    fn purge_windows_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.count(slot::PURGE_WINDOWS_BEFORE, Self::value(before))
    }

    fn purge_metering_before(&self, bucket: &str) -> RecordStoreResult<u64> {
        self.count(slot::PURGE_METERING_BEFORE, Self::id(bucket))
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.plain(
            slot::PUT_CREDENTIAL,
            owned_in(|o, head| BlobIn {
                head,
                record: o.secret_json(to_json(secret)),
            }),
        )
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.plain(
            slot::PUT_KEY_WITH_CREDENTIAL,
            owned_in(|o, head| KeyWithCredentialIn {
                head,
                key: o.json(to_json(key)),
                credential: o.secret_json(to_json(secret)),
            }),
        )
    }

    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.many(slot::LIST_CREDENTIALS, Self::id(key_id))
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        self.one(
            slot::LOOKUP_CREDENTIAL_SECRET,
            owned_in(|o, head| KindIdIn {
                head,
                kind: o.text(kind),
                id: o.text(public_id),
            }),
        )
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.plain(
            slot::REVOKE_CREDENTIAL,
            owned_in(|o, head| IdReasonIn {
                head,
                id: o.text(id),
                reason: o.text(reason),
            }),
        )
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.many(slot::LIST_CREDENTIALS_SINCE, Self::value(since))
    }

    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.plain(
            slot::APPEND_AUDIT,
            owned_in(|o, head| OpBlobIn {
                head,
                op_id: self.mint(),
                record: o.json(to_json(entry)),
            }),
        )
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.many(slot::LIST_AUDIT, bare(in_head()))
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.plain(
            slot::ADD_DENYLIST,
            owned_in(|o, head| IdReasonIn {
                head,
                id: o.text(sub),
                reason: o.text(reason),
            }),
        )
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.strs(slot::LIST_DENYLIST, bare(in_head()))
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.many(slot::LIST_AUDIT_TAIL, Self::value(limit))
    }

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.plain(
            slot::UPSERT_PLANE_RECORD,
            owned_in(|o, head| UpsertPlaneRecordIn {
                head,
                record: plane_row(o, record),
            }),
        )
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        let (ran, r) = run!(self, now, Self::get_plane_req(kind, id));
        bridge(r.get().read(&ran))
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.plain(
            slot::APPEND_PLANE_RECORD,
            owned_in(|o, head| AppendPlaneRecordIn {
                head,
                op_id: self.mint(),
                record: plane_row(o, record),
            }),
        )
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let (ran, r) = run!(self, now, Self::list_plane_req(kind, selector));
        bridge(
            r.get()
                .rows(&ran)
                .map(|rows| rows.iter().map(host_blob).collect()),
        )
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.strs(slot::LIST_PLANE_RECORD_PARENTS, Self::id(kind))
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.count(
            slot::PURGE_PLANE_RECORDS_BEFORE,
            owned_in(|o, head| KindBeforeIn {
                head,
                kind: o.text(kind),
                before,
            }),
        )
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.plain(
            slot::DELETE_PLANE_RECORD,
            owned_in(|o, head| KindIdIn {
                head,
                kind: o.text(kind),
                id: o.text(id),
            }),
        )
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        let r = Self::token_req(slot::REDEEM_PLANE_TOKEN, kind, token, expires_at, now);
        let (ran, _) = run!(self, now, r);
        bridge(ran.ok().map(|()| ran.out.verdict == VERDICT_YES))
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        let r = Self::token_req(slot::PLANE_TOKEN_LIVE, kind, token, expires_at, now);
        let (ran, _) = run!(self, now, r);
        bridge(ran.ok().map(|()| ran.out.verdict == VERDICT_YES))
    }
}

/// Serialized secret material, zeroed when dropped.
struct Zeroing(Vec<u8>);
impl Drop for Zeroing {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// THE STORE AXIS over the process's ONE dispatcher (WIRE-STORE Q8/Q9): the composition root
/// builds it with its dispatcher, its `plugins.logs`, its one connection table and the kernel's
/// `op_id` allocator, and installs it in the kernel, which opens its governance store through it.
/// A compiled-in row is loaded by [`load_linked`](crate::dispatch::load_linked), a dropped-in
/// plugin by [`load_dropped_bytes`](crate::dispatch::load_dropped_bytes) against its stated
/// Statement; both are opened as a [`LoadedStore`].
pub struct DoorStoreAxis {
    /// The process's one dispatcher.
    pub dispatcher: Arc<Dispatcher>,
    /// Where each store instance's plugin log goes.
    pub logs: crate::dispatch::PluginLogConfig,
    /// The host's one connection table, or why a store opens with none
    /// ([`crate::dispatch::Bind::conns`]).
    pub conns: crate::dispatch::ConnTable,
    /// The node's one `op_id` allocator.
    pub mint: OpIdMint,
}

impl busbar_contract::store_calls::StoreAxis for DoorStoreAxis {
    fn open(
        &self,
        door: busbar_contract::store_calls::StoreDoor,
        label: &str,
        settings: &[u8],
    ) -> Result<busbar_contract::store_calls::OpenedStore, String> {
        use busbar_contract::abi::mechanism::KindCode;
        use busbar_contract::store_calls::StoreDoor;
        let sink = self
            .logs
            .sink(label, KindCode::Store, Arc::new(crate::dispatch::NoSink))?;
        let bind = crate::dispatch::Bind {
            instance: Arc::from(label),
            max_inflight_cap: u32::MAX,
            sink: Arc::new(sink),
            dispatcher: self.dispatcher.adopter(),
            conns: self.conns.clone(),
        };
        let plugin = match door {
            StoreDoor::Linked(door) => crate::dispatch::LinkedRow::of(door)
                .and_then(|row| crate::dispatch::load_linked::<Store>(&row, bind)),
            StoreDoor::Dropped {
                file,
                bytes,
                stated,
            } => crate::dispatch::load_dropped_bytes::<Store>(&bytes, &file, &stated, bind),
        }
        .map_err(|e| e.to_string())?;
        let store = Arc::new(LoadedStore::open(
            plugin,
            Arc::clone(&self.dispatcher),
            settings,
            self.mint,
        )?);
        Ok(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        })
    }
}

#[cfg(test)]
#[path = "tests/store_v3_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/store_v3_shortcut_tests.rs"]
mod shortcut_tests;

#[cfg(test)]
#[path = "tests/store_v3_deadline_tests.rs"]
mod deadline_tests;

#[cfg(test)]
#[path = "tests/store_v3_miscount_tests.rs"]
mod miscount_tests;

#[cfg(test)]
#[path = "tests/store_v3_opid_tests.rs"]
mod opid_tests;

#[cfg(test)]
#[path = "tests/store_v3_validate_tests.rs"]
mod validate_tests;

#[cfg(test)]
#[path = "tests/store_v3_wrap.rs"]
pub(crate) mod wrap;

#[cfg(test)]
#[path = "tests/store_v3_pend_tests.rs"]
mod pend_tests;

#[cfg(test)]
#[path = "tests/store_v3_wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "tests/store_v3_axis_tests.rs"]
mod axis_tests;

#[cfg(test)]
#[path = "tests/store_v3_lent_tests.rs"]
mod lent_tests;
