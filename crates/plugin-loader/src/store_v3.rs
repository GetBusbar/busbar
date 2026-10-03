// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE, REACHED THROUGH ITS TABLE (THE DESIGN, the plugin ABI; TODO ABI-b2 for store):
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
//!   [`StoreCalls`]. M6: this bridge is deleted when no consumer remains. Its calls are
//!   TICKET-LESS crossings on the caller's thread, exactly where the compiled-in store's direct
//!   calls ran before, so no call site moves from non-blocking to blocking. A ticket-less op may
//!   not pend: a store that PENDS on one is FAULT (loud: logged at error, and a debug build
//!   panics). Remaining consumers: the kernel's governance state and budget flusher
//!   (`busbar-kernel/src/governance/state.rs`), the plane host's record and token ops
//!   (`busbar-kernel/src/plane_host/`), the admin units, the boot ledger's migration read, and
//!   the planes' own record legs.
//!
//! Off-path answers are read out of their lease and the lease is released at once.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, ReleaseIn, LIFECYCLE_SLOTS,
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
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::{Store, StoreFacts};
use crate::dispatch::{in_head, now_ns, out_head, Dispatcher, Frame, InFrame, OutFrame, Plugin};

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
    /// The op ids this handle mints for the bridge's `op_id`-carrying 1.5.5 writes.
    node: u64,
    counter: AtomicU64,
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
    /// `dispatcher`. `node` is this node's id: the high half of every `op_id` the synchronous
    /// bridge mints for the 1.5.5 op set's additive writes.
    ///
    /// # Errors
    /// The store's refusal of its settings, in 1.5.5's words
    /// (`plugin '<name>' open failed: <reason>`), or a Statement with no store tail.
    pub fn open(
        plugin: Plugin<Store>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        node: u64,
    ) -> Result<Self, String> {
        let facts = *plugin
            .context::<StoreFacts>()
            .ok_or_else(|| "the store states no tail".to_string())?;
        // `open` is the settings' judge, as it was in 1.5.5: its refusal carries the plugin's own
        // reason (the host's lent reason buffer), which a bare `validate` answer cannot.
        let mut o = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: octets(settings),
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
        let c = plugin.call(life::OPEN, &mut o);
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
            node,
            counter: AtomicU64::new(0),
        })
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
        OpId::from_parts(self.node, self.counter.fetch_add(1, Ordering::Relaxed) + 1)
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

    /// THE BRIDGE'S RUNNER: a ticket-less crossing on this thread, the one re-call of a short
    /// answer, the lease read and released.
    fn now<R: Req>(&self, r: &mut R) -> Ran<R::O> {
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
    async fn submit<R: Req>(&self, r: &mut R) -> Ran<R::O> {
        let s = r.slot();
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return Ran::host(Outcome::Refused, r.out());
        };
        let _recycle = Recycle(&self.dispatcher, ticket);
        let class = OPS[(s - LIFECYCLE_SLOTS) as usize].deadline;
        let deadline = match class {
            DeadlineClass::WriteBehind => 0,
            _ => now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64),
        };
        let mut regrown = false;
        loop {
            let frame = Frame::new(r.input(), r.out());
            let reply = self
                .dispatcher
                .submit(&self.plugin, ticket, s, frame, class, deadline);
            let done = reply.await;
            let out = done.frame.as_ref().map_or_else(|| r.out(), |f| f.out);
            if done.short && !regrown {
                regrown = true;
                r.grow(&out);
                continue;
            }
            return Ran {
                outcome: done.outcome,
                out,
                error: done.error,
                lease: done.lease,
            };
        }
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

/// A ticket-less crossing that PENDED on the synchronous bridge faulted the store. Loud: an
/// error line always, and a debug build panics, so a pending store reached from a synchronous
/// consumer never goes unseen (the ARCHITECT's condition on the bridge).
fn pended_on_the_bridge(store: &str, s: u32) {
    tracing::error!(
        store,
        op = <Store as crate::dispatch::Kind>::op_name(s),
        "a store op faulted on the synchronous bridge; a store that pends is reached through StoreCalls"
    );
    debug_assert!(
        false,
        "store '{store}' faulted op {s} on the synchronous bridge (a pending op is FAULT there)"
    );
}

/// Host-built rows that point at data the calling future owns, carried across its await.
struct Held<T>(T);
// SAFETY: the pointers inside point at data owned by the same future (or borrowed by it for its
// whole life); one thread touches the future at a time.
unsafe impl<T> Send for Held<T> {}

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

fn bridge<T>(r: Result<T, StoreFailure>) -> RecordStoreResult<T> {
    r.map_err(|f| RecordStoreError(f.to_string()))
}

// ── the requests ─────────────────────────────────────────────────────────────────────────────

/// One op's `in`/`out`, built over buffers the request owns.
trait Req {
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

/// An op with no host buffers: a fixed `in`.
struct Fixed<I, O> {
    slot: u32,
    input: I,
    _o: PhantomData<O>,
}

// SAFETY: the `in`'s pointers are borrowed data the caller keeps alive across the call; a request
// moves with the future that owns it and is touched by one thread at a time.
unsafe impl<I, O> Send for Fixed<I, O> {}

fn fixed<I: InFrame, O: OutFrame>(slot: u32, input: I) -> Fixed<I, O> {
    Fixed {
        slot,
        input,
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

fn text(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn opt_text(s: Option<&str>) -> AbiStr {
    s.map_or(
        AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        text,
    )
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn json_blob(b: &[u8], secret: bool) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: if secret { BLOB_SECRET } else { 0 },
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
    fn new(slot: u32, input: I, place: fn(&mut I, *mut T, usize, HostBuf)) -> Self {
        Self {
            slot,
            input,
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

fn unit_cell(c: &Cell<'_>) -> UnitCell {
    let (dimension, class_key) = match c.key.dimension {
        Dimension::NanoUnits => (st::DIM_NANO_UNITS, None),
        Dimension::Requests => (st::DIM_REQUESTS, None),
        Dimension::Concurrency => (st::DIM_CONCURRENCY, None),
        Dimension::Class(k) => (st::DIM_CLASS, Some(k)),
    };
    UnitCell {
        bucket: text(c.key.bucket),
        pool: opt_text(c.key.pool),
        dimension,
        _r: 0,
        class_key: opt_text(class_key),
        amount: c.amount,
        window_start: c.key.window_start,
    }
}

fn window_cap(c: &Cap<'_>) -> WindowCap {
    let u = unit_cell(&Cell {
        key: c.key,
        amount: 0,
    });
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

fn plane_row(r: PlaneRecordRef<'_>) -> PlaneRecordRow {
    PlaneRecordRow {
        kind: text(r.kind),
        id: text(r.id),
        parent: opt_text(r.parent),
        seq: r.seq,
        ts: r.ts,
        disposition: match r.disposition {
            PlaneDisposition::Active => st::DISPOSITION_ACTIVE,
            PlaneDisposition::Terminal => st::DISPOSITION_TERMINAL,
        },
        _reserved: 0,
        body: octets(r.body),
    }
}

fn in_of<T>(f: impl FnOnce(InHead) -> T) -> T {
    f(in_head())
}

// ── the ops, shared by both surfaces ─────────────────────────────────────────────────────────

/// Run `req` through `$run` (`now` or `submit`), on `$self`.
macro_rules! run {
    ($self:ident, now, $r:expr) => {
        $self.now(&mut $r)
    };
    ($self:ident, submit, $r:expr) => {
        $self.submit(&mut $r).await
    };
}

/// The typed ops as `async fn`s over a runner; the bridge runs them to completion inline (a
/// ticket-less crossing never pends), and [`StoreCalls`] awaits them.
impl LoadedStore {
    fn reserve_req(op: OpId, epoch: u64, cells: &[Cell<'_>]) -> ReserveReq {
        let cells: Vec<UnitCell> = cells.iter().map(unit_cell).collect();
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
        BytesReq {
            slot: slot::GET_PLANE_RECORD,
            input: in_of(|head| GetPlaneRecordIn {
                head,
                kind: text(kind),
                id: text(id),
                body: HostBuf {
                    ptr: std::ptr::null_mut(),
                    cap: 0,
                },
            }),
            buf: vec![0; FIRST_BYTES],
            place: |i, b| i.body = b,
        }
    }

    fn record_get_req(schema: &str, key: &[u8]) -> BytesReq<RecordGetIn> {
        BytesReq {
            slot: slot::RECORD_GET,
            input: in_of(|head| RecordGetIn {
                head,
                schema: text(schema),
                key: octets(key),
                value: HostBuf {
                    ptr: std::ptr::null_mut(),
                    cap: 0,
                },
            }),
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
            in_of(|head| ListPlaneRecordsIn {
                head,
                kind: text(kind),
                selector: sel,
                _reserved: 0,
                parent: opt_text(parent),
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
            in_of(|head| SessionsForIn {
                head,
                principal: text(principal),
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
            in_of(|head| RecordScanIn {
                head,
                schema: text(schema),
                prefix: octets(prefix),
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
            in_of(|head| TokenIn {
                head,
                kind: text(kind),
                token: text(token),
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
            let mut r = Self::reserve_req(op, epoch, cells);
            let ran = run!(self, submit, r);
            Self::reserve_read(&r, &ran)
        })
    }

    fn slice_release<'a>(
        &'a self,
        op: OpId,
        epoch: u64,
        items: &'a [(u64, u64)],
    ) -> StoreCall<'a, Vec<u64>> {
        boxed(async move {
            let mut r = Self::release_req(op, epoch, items);
            let ran = run!(self, submit, r);
            ran.ok()?;
            Ok(r.released[..ran.out.released_len].to_vec())
        })
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let deltas: Vec<Vec<u8>> = cells.iter().map(|(_, _, d)| to_json(d)).collect();
            let rows: Held<Vec<UsageCell>> = Held(
                cells
                    .iter()
                    .zip(&deltas)
                    .map(|((b, w, _), d)| UsageCell {
                        bucket: text(b),
                        window_start: *w,
                        delta: json_blob(d, false),
                    })
                    .collect(),
            );
            let mut r = fixed::<_, OutHead>(
                slot::ADD_USAGE_BATCH,
                in_of(|head| AddUsageBatchIn {
                    head,
                    op_id: op,
                    cells: rows.0.as_ptr(),
                    cells_len: rows.0.len(),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let bodies: Vec<Vec<u8>> = deltas.iter().map(to_json).collect();
            let blobs = Held(
                bodies
                    .iter()
                    .map(|b| json_blob(b, false))
                    .collect::<Vec<Blob>>(),
            );
            let mut r = fixed::<_, OutHead>(
                slot::ADD_METERING_BATCH,
                in_of(|head| OpBlobsIn {
                    head,
                    op_id: op,
                    records: blobs.0.as_ptr(),
                    records_len: blobs.0.len(),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn append_audit_batch<'a>(&'a self, op: OpId, entries: &'a [AuditRecord]) -> StoreCall<'a, ()> {
        boxed(async move {
            let bodies: Vec<Vec<u8>> = entries.iter().map(to_json).collect();
            let blobs = Held(
                bodies
                    .iter()
                    .map(|b| json_blob(b, false))
                    .collect::<Vec<Blob>>(),
            );
            let mut r = fixed::<_, OutHead>(
                slot::APPEND_AUDIT_BATCH,
                in_of(|head| OpBlobsIn {
                    head,
                    op_id: op,
                    records: blobs.0.as_ptr(),
                    records_len: blobs.0.len(),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn window_caps<'a>(&'a self, op: OpId, caps: &'a [Cap<'a>]) -> StoreCall<'a, ()> {
        boxed(async move {
            let rows = Held(caps.iter().map(window_cap).collect::<Vec<WindowCap>>());
            let mut r = fixed::<_, OutHead>(
                slot::WINDOW_CAPS,
                in_of(|head| WindowCapsIn {
                    head,
                    op_id: op,
                    caps: rows.0.as_ptr(),
                    caps_len: rows.0.len(),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn append_batch<'a>(
        &'a self,
        op: OpId,
        stream: &'a str,
        records: &'a [RecordBytes],
    ) -> StoreCall<'a, Head> {
        boxed(async move {
            let blobs = Held(
                records
                    .iter()
                    .map(|r| octets(r.as_slice()))
                    .collect::<Vec<Blob>>(),
            );
            let mut r = fixed::<_, HeadOut>(
                slot::APPEND_BATCH,
                in_of(|head| AppendBatchIn {
                    head,
                    op_id: op,
                    stream: text(stream),
                    records: blobs.0.as_ptr(),
                    records_len: blobs.0.len(),
                }),
            );
            let ran = run!(self, submit, r);
            ran.ok()?;
            Ok(Head {
                seq: ran.out.seq,
                epoch: ran.out.epoch,
            })
        })
    }

    fn heads(&self) -> StoreCall<'_, Vec<(String, Head)>> {
        boxed(async move {
            let mut r = fixed::<_, HeadsOut>(slot::HEADS, in_head());
            let ran = run!(self, submit, r);
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
            let mut r = fixed::<_, OutHead>(
                slot::SESSION_PUT,
                in_of(|head| SessionPutIn {
                    head,
                    session,
                    node: text(node),
                    principal: text(principal),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn session_remove(&self, session: u64) -> StoreCall<'_, ()> {
        boxed(async move {
            let mut r = fixed::<_, OutHead>(
                slot::SESSION_REMOVE,
                in_of(|head| U64In {
                    head,
                    value: session,
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn sessions_for<'a>(&'a self, principal: &'a str) -> StoreCall<'a, Vec<(u64, String)>> {
        boxed(async move {
            let mut r = Self::sessions_req(principal);
            let ran = run!(self, submit, r);
            Ok(r.rows(&ran)?
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
            let mut r = fixed::<_, OutHead>(
                slot::RECORD_PUT,
                in_of(|head| RecordPutIn {
                    head,
                    schema: text(schema),
                    key: octets(key),
                    value: octets(value.as_slice()),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        boxed(async move {
            let mut r = Self::record_get_req(schema, key);
            let ran = run!(self, submit, r);
            r.read(&ran)?
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
            let mut r = Self::scan_req(schema, prefix, limit);
            let ran = run!(self, submit, r);
            r.rows(&ran)?
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
            let mut r = fixed::<_, OutHead>(
                slot::UPSERT_PLANE_RECORD,
                in_of(|head| UpsertPlaneRecordIn {
                    head,
                    record: plane_row(record),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        boxed(async move {
            let mut r = Self::get_plane_req(kind, id);
            let ran = run!(self, submit, r);
            r.read(&ran)
        })
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let mut r = fixed::<_, OutHead>(
                slot::APPEND_PLANE_RECORD,
                in_of(|head| AppendPlaneRecordIn {
                    head,
                    op_id: op,
                    record: plane_row(record),
                }),
            );
            run!(self, submit, r).ok()
        })
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        boxed(async move {
            let mut r = Self::list_plane_req(kind, selector);
            let ran = run!(self, submit, r);
            Ok(r.rows(&ran)?.iter().map(host_blob).collect())
        })
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        boxed(async move {
            let mut r = fixed::<_, OutHead>(
                slot::DELETE_PLANE_RECORD,
                in_of(|head| KindIdIn {
                    head,
                    kind: text(kind),
                    id: text(id),
                }),
            );
            run!(self, submit, r).ok()
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
            let mut r = Self::token_req(slot::REDEEM_PLANE_TOKEN, kind, token, expires_at, now);
            let ran = run!(self, submit, r);
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
            let mut r = Self::token_req(slot::PLANE_TOKEN_LIVE, kind, token, expires_at, now);
            let ran = run!(self, submit, r);
            ran.ok()?;
            Ok(ran.out.verdict == VERDICT_YES)
        })
    }
}

// ── RecordStore: the synchronous bridge (until M6) ────────────────────────────────────────────────

impl LoadedStore {
    fn plain<I: InFrame>(&self, s: u32, input: I) -> RecordStoreResult<()> {
        bridge(self.now(&mut fixed::<I, OutHead>(s, input)).ok())
    }

    fn one<I: InFrame, T: serde::de::DeserializeOwned>(
        &self,
        s: u32,
        input: I,
    ) -> RecordStoreResult<Option<T>> {
        let ran = self.now(&mut fixed::<I, LeasedBlobOut>(s, input));
        bridge(self.record(ran))
    }

    fn many<I: InFrame, T: serde::de::DeserializeOwned>(
        &self,
        s: u32,
        input: I,
    ) -> RecordStoreResult<Vec<T>> {
        let ran = self.now(&mut fixed::<I, LeasedListOut>(s, input));
        bridge(self.records(ran))
    }

    fn count<I: InFrame>(&self, s: u32, input: I) -> RecordStoreResult<u64> {
        let ran = self.now(&mut fixed::<I, CountOut>(s, input));
        bridge(ran.ok().map(|()| ran.out.count))
    }

    fn id(id: &str) -> IdIn {
        in_of(|head| IdIn { head, id: text(id) })
    }

    fn value(v: u64) -> U64In {
        in_of(|head| U64In { head, value: v })
    }
}

impl RecordStore for LoadedStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        let b = to_json(key);
        self.plain(
            slot::PUT_KEY,
            in_of(|head| BlobIn {
                head,
                record: json_blob(&b, false),
            }),
        )
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.one(slot::GET_KEY, Self::id(id))
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.many(slot::LIST_KEYS, in_head())
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
            in_of(|head| WindowIn {
                head,
                bucket: text(bucket_id),
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
        let b = to_json(ledger);
        self.plain(
            slot::PUT_USAGE,
            in_of(|head| PutUsageIn {
                head,
                bucket: text(bucket_id),
                window_start,
                ledger: json_blob(&b, false),
            }),
        )
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let b = to_json(delta);
        self.plain(
            slot::ADD_USAGE,
            in_of(|head| AddUsageIn {
                head,
                op_id: self.mint(),
                cell: UsageCell {
                    bucket: text(bucket_id),
                    window_start,
                    delta: json_blob(&b, false),
                },
            }),
        )
    }

    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        let b = to_json(delta);
        self.plain(
            slot::ADD_METERING,
            in_of(|head| OpBlobIn {
                head,
                op_id: self.mint(),
                record: json_blob(&b, false),
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
        let b = zeroing(to_json(secret));
        self.plain(
            slot::PUT_CREDENTIAL,
            in_of(|head| BlobIn {
                head,
                record: json_blob(&b.0, true),
            }),
        )
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let k = to_json(key);
        let c = zeroing(to_json(secret));
        self.plain(
            slot::PUT_KEY_WITH_CREDENTIAL,
            in_of(|head| KeyWithCredentialIn {
                head,
                key: json_blob(&k, false),
                credential: json_blob(&c.0, true),
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
            in_of(|head| KindIdIn {
                head,
                kind: text(kind),
                id: text(public_id),
            }),
        )
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.plain(
            slot::REVOKE_CREDENTIAL,
            in_of(|head| IdReasonIn {
                head,
                id: text(id),
                reason: text(reason),
            }),
        )
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.many(slot::LIST_CREDENTIALS_SINCE, Self::value(since))
    }

    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        let b = to_json(entry);
        self.plain(
            slot::APPEND_AUDIT,
            in_of(|head| OpBlobIn {
                head,
                op_id: self.mint(),
                record: json_blob(&b, false),
            }),
        )
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.many(slot::LIST_AUDIT, in_head())
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.plain(
            slot::ADD_DENYLIST,
            in_of(|head| IdReasonIn {
                head,
                id: text(sub),
                reason: text(reason),
            }),
        )
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        let ran = self.now(&mut fixed::<InHead, LeasedStrListOut>(
            slot::LIST_DENYLIST,
            in_head(),
        ));
        bridge(self.read_strs(ran))
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.many(slot::LIST_AUDIT_TAIL, Self::value(limit))
    }

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.plain(
            slot::UPSERT_PLANE_RECORD,
            in_of(|head| UpsertPlaneRecordIn {
                head,
                record: plane_row(record),
            }),
        )
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        let mut r = Self::get_plane_req(kind, id);
        let ran = run!(self, now, r);
        bridge(r.read(&ran))
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.plain(
            slot::APPEND_PLANE_RECORD,
            in_of(|head| AppendPlaneRecordIn {
                head,
                op_id: self.mint(),
                record: plane_row(record),
            }),
        )
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let mut r = Self::list_plane_req(kind, selector);
        let ran = run!(self, now, r);
        bridge(
            r.rows(&ran)
                .map(|rows| rows.iter().map(host_blob).collect()),
        )
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        let ran = self.now(&mut fixed::<IdIn, LeasedStrListOut>(
            slot::LIST_PLANE_RECORD_PARENTS,
            Self::id(kind),
        ));
        bridge(self.read_strs(ran))
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.count(
            slot::PURGE_PLANE_RECORDS_BEFORE,
            in_of(|head| KindBeforeIn {
                head,
                kind: text(kind),
                before,
            }),
        )
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.plain(
            slot::DELETE_PLANE_RECORD,
            in_of(|head| KindIdIn {
                head,
                kind: text(kind),
                id: text(id),
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
        let mut r = Self::token_req(slot::REDEEM_PLANE_TOKEN, kind, token, expires_at, now);
        let ran = run!(self, now, r);
        bridge(ran.ok().map(|()| ran.out.verdict == VERDICT_YES))
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        let mut r = Self::token_req(slot::PLANE_TOKEN_LIVE, kind, token, expires_at, now);
        let ran = run!(self, now, r);
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
fn zeroing(v: Vec<u8>) -> Zeroing {
    Zeroing(v)
}

#[cfg(test)]
#[path = "tests/store_v3_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/store_v3_deadline_tests.rs"]
mod deadline_tests;

#[cfg(test)]
#[path = "tests/store_v3_miscount_tests.rs"]
mod miscount_tests;
