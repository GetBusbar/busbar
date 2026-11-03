// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, LIFECYCLE_SLOTS};
use busbar_contract::abi::sdk::store::{conditional, correction};
use busbar_contract::abi::store::{
    self as st, slot, AddUsageBatchIn, AppendPlaneRecordIn, BlobIn, CountOut, GetPlaneRecordIn,
    HostBlobs, HostBuf, HostBytesOut, HostListOut, HostRecords, IdIn, IdReasonIn,
    KeyWithCredentialIn, KindBeforeIn, KindIdIn, LeasedBlobOut, LeasedListOut, LeasedStrListOut,
    ListPlaneRecordsIn, OpBlobsIn, OpId, PlaneRecordRow, PutUsageIn, RecordEntry, RecordGetIn,
    RecordPutIn, RecordScanIn, TokenIn, U64In, UpsertPlaneRecordIn, UsageCell, VerdictOut,
    WindowIn, DIAG_OPID_CONFLICT, FOUND, OPS, SELECT_ALL, SELECT_PARENT, VERDICT_YES,
};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition,
    PlaneRecordRef, PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, Retention,
    UsageDelta, UsageLedger, VirtualKey,
};
use busbar_contract::store_calls::{OpIdMint, StoreCall, StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::{Store, StoreFacts};
use crate::dispatch::lifecycle::{self, open_frame, validate_call};
use crate::dispatch::{
    in_head, now_ns, out_head, Dispatcher, Frame, InFrame, Lent, OutFrame, Plugin,
};

const FIRST_BYTES: usize = 16 * 1024;

const FIRST_ITEMS: usize = 256;

const CALL_DEADLINE: Duration = Duration::from_secs(30);

pub struct LoadedStore {
    plugin: Plugin<Store>,
    dispatcher: Arc<Dispatcher>,
    facts: StoreFacts,
    next_worker: AtomicU32,

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
    pub fn open(
        plugin: Plugin<Store>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        mint: OpIdMint,
    ) -> Result<Self, String> {
        let facts = plugin
            .context::<StoreFacts>()
            .cloned()
            .ok_or_else(|| "the store states no tail".to_string())?;

        let (settings, secrets) = split_secrets(&facts.secret_refs, settings);

        let lent = Arc::new(OpenLent::new(settings, secrets));

        let mut o = open_frame(octets(&lent.settings));
        if !lent.blobs.is_empty() {
            o.input.secrets = lent.blobs.as_ptr();
            o.input.secrets_len = lent.blobs.len();
        }
        let c = Self::open_on_ticket(&plugin, &dispatcher, o, lent);
        if c.outcome != Outcome::Ready {
            return Err(c.open_failure(plugin.name()));
        }

        let store = Self {
            plugin,
            dispatcher,
            facts,
            next_worker: AtomicU32::new(0),
            mint,
        };

        store
            .plugin
            .ready(&store.dispatcher, crate::dispatch::ready::READY_DEADLINE)?;
        Ok(store)
    }

    fn open_on_ticket(
        plugin: &Plugin<Store>,
        dispatcher: &Dispatcher,
        mut o: Frame<OpenIn, OpenOut>,
        settings: Arc<OpenLent>,
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

    pub fn validate(plugin: &Plugin<Store>, settings: &[u8]) -> Result<(), String> {
        let c = validate_call(plugin, octets(settings));
        match (c.outcome, c.error) {
            (Outcome::Ready, _) => Ok(()),

            (_, Some(e)) if !e.is_empty() => Err(String::from_utf8_lossy(&e).into_owned()),
            (o, _) => Err(format!("the store's validate answered {o:?}")),
        }
    }

    pub fn facts(&self) -> StoreFacts {
        self.facts.clone()
    }

    pub fn name(&self) -> &str {
        self.plugin.name()
    }

    pub fn plugin(&self) -> &Plugin<Store> {
        &self.plugin
    }

    fn mint(&self) -> OpId {
        (self.mint)()
    }

    fn release(&self, lease: u64) {
        lifecycle::release(&self.plugin, lease);
    }

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

    fn bridge_worker(&self) -> Option<u32> {
        pick_worker(
            &self.dispatcher,
            self.next_worker.fetch_add(1, Ordering::Relaxed),
        )
    }

    fn inline<R: Req>(&self, r: &mut R) -> Ran<R::O> {
        let s = r.slot();
        let mut f = Frame::new(r.input(), r.out());
        let mut c = self.plugin.call(s, &mut f);
        if let Some(token) = c.recall.take() {
            r.grow(&f.out);
            f = Frame::new(r.input(), r.out());
            c = self.plugin.recall(token, s, &mut f);
        }

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

    async fn submit<R: Req>(&self, r: R) -> (Ran<R::O>, Arc<Lend<R>>) {
        let s = r.slot();
        let workers = self.dispatcher.workers().max(1);
        let worker = self.next_worker.fetch_add(1, Ordering::Relaxed) % workers;
        let Some(ticket) = self.dispatcher.mint(worker) else {
            return (Ran::host(Outcome::Refused, r.out()), Lend::new(r));
        };
        let _recycle = Recycle(&self.dispatcher, ticket);
        let (class, deadline) = r.schedule();
        let r = Lend::new(r);
        let mut regrown = false;
        loop {
            let frame = r.frame();

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
                self.release(done.lease);
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

fn deadline_of(s: u32) -> (DeadlineClass, u64) {
    let class = OPS[(s - LIFECYCLE_SLOTS) as usize].deadline;
    let deadline = match class {
        DeadlineClass::WriteBehind => 0,
        _ => now_ns().saturating_add(CALL_DEADLINE.as_nanos() as u64),
    };
    (class, deadline)
}

impl Drop for LoadedStore {
    fn drop(&mut self) {
        lifecycle::close(&self.plugin);
    }
}

struct Recycle<'a>(
    &'a Dispatcher,
    busbar_contract::abi::mechanism::ticket::Ticket,
);
impl Drop for Recycle<'_> {
    fn drop(&mut self) {
        self.0.recycle(self.1);
    }
}

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

    fn get(&self) -> &R {
        // SAFETY: see `Send`: no crossing writes the request's own fields, and the buffers they
        // own are read only from a READY answer, whose crossing returned.
        unsafe { &*self.0.get() }
    }

    fn frame(&self) -> Frame<R::I, R::O> {
        // SAFETY: as `frame`'s contract: nothing else touches the request now.
        let r = unsafe { &mut *self.0.get() };
        Frame::new(r.input(), r.out())
    }

    fn grow(&self, out: &R::O) {
        // SAFETY: as `frame`.
        unsafe { &mut *self.0.get() }.grow(out);
    }

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

impl Drop for Owned {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
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

    fn secret_octets(&mut self, mut bytes: zeroize::Zeroizing<Vec<u8>>) -> Blob {
        let (ptr, len) = (bytes.as_ptr(), bytes.len());

        self.secrets.reserve(1);
        self.secrets.push(Zeroing(std::mem::take(&mut *bytes)));
        Blob {
            ptr,
            len,
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        }
    }

    fn rows<T: 'static>(&mut self, v: Vec<T>) -> (*const T, usize) {
        let at = (v.as_ptr(), v.len());
        self.rows.push(Box::new(v));
        at
    }
}

fn owned_in<I>(f: impl FnOnce(&mut Owned, InHead) -> I) -> (I, Owned) {
    let mut o = Owned::default();
    let i = f(&mut o, in_head());
    (i, o)
}

fn bare<I>(i: I) -> (I, Owned) {
    (i, Owned::default())
}

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

    fn failure(&self) -> StoreFailure {
        let text = self.text();
        match self.outcome {
            Outcome::Refused if self.error.is_none() => StoreFailure::Overloaded,
            Outcome::Refused if text.starts_with(DIAG_OPID_CONFLICT) => StoreFailure::Conflict,
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
    r.map_err(|f| match f {
        StoreFailure::Failed(text) => RecordStoreError(text),
        other => RecordStoreError(other.to_string()),
    })
}

trait Req: 'static {
    type I: InFrame;
    type O: OutFrame;
    fn slot(&self) -> u32;

    fn schedule(&self) -> (DeadlineClass, u64) {
        deadline_of(self.slot())
    }

    fn input(&mut self) -> Self::I;

    fn out(&self) -> Self::O;

    fn grow(&mut self, _out: &Self::O) {}
}

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

struct ConditionalReq {
    read: BytesReq<RecordGetIn>,
    candidate: zeroize::Zeroizing<conditional::Request>,
}

struct CorrectionReq {
    write: Fixed<AddUsageBatchIn, OutHead>,
    candidate: correction::Request,
}

impl CorrectionReq {
    fn new(candidate: &correction::Request) -> Result<Self, StoreFailure> {
        let encoded = candidate
            .encode()
            .map_err(|s| StoreFailure::Refused(s.into()))?;
        let write = fixed(
            slot::ADD_USAGE_BATCH,
            owned_in(|o, mut head| {
                head.extensions = o.octets(&extensions::encode(&[(correction::INTENT, &encoded)]));
                AddUsageBatchIn {
                    head,
                    op_id: candidate.op_id,
                    cells: std::ptr::null(),
                    cells_len: 0,
                }
            }),
        );
        Ok(Self {
            write,
            candidate: candidate.clone(),
        })
    }
}

impl Req for CorrectionReq {
    type I = AddUsageBatchIn;
    type O = OutHead;
    fn slot(&self) -> u32 {
        self.write.slot()
    }
    fn input(&mut self) -> Self::I {
        self.write.input()
    }
    fn out(&self) -> Self::O {
        self.write.out()
    }
}

impl ConditionalReq {
    fn new(candidate: &conditional::Request) -> Result<Self, StoreFailure> {
        let encoded = candidate
            .encode_held()
            .map_err(|s| StoreFailure::Refused(s.into()))?;
        let (schema, key) = candidate.carrier().ok_or_else(|| {
            StoreFailure::Refused("record transaction requires a predicate".into())
        })?;
        let mut read = LoadedStore::record_get_req(schema, key);
        let mut extension = zeroize::Zeroizing::new(Vec::with_capacity(extensions::entry_len(
            conditional::INTENT,
            &encoded,
        )));
        extension.extend_from_slice(&(conditional::INTENT.len() as u16).to_le_bytes());
        extension.extend_from_slice(conditional::INTENT.as_bytes());
        extension.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        extension.extend_from_slice(&encoded);
        read.input.head.extensions = read._owned.secret_octets(extension);
        Ok(Self {
            read,
            candidate: zeroize::Zeroizing::new(candidate.clone()),
        })
    }
}

impl Req for ConditionalReq {
    type I = RecordGetIn;
    type O = HostBytesOut;
    fn slot(&self) -> u32 {
        slot::RECORD_GET
    }
    fn schedule(&self) -> (DeadlineClass, u64) {
        (DeadlineClass::WriteBehind, 0)
    }
    fn input(&mut self) -> Self::I {
        self.read.input()
    }
    fn out(&self) -> Self::O {
        self.read.out()
    }
    fn grow(&mut self, out: &Self::O) {
        self.read.grow(out);
    }
}

struct AnswerLease<'a>(&'a LoadedStore, u64);
impl Drop for AnswerLease<'_> {
    fn drop(&mut self) {
        self.0.release(self.1);
    }
}

impl LoadedStore {
    fn correction_result(
        &self,
        ran: Ran<OutHead>,
        candidate: &correction::Request,
    ) -> Result<correction::Decision, StoreFailure> {
        let _lease = AnswerLease(self, ran.lease);
        ran.ok()?;
        let extension = ran.out.extensions;
        if ran.lease == 0 || extension.fmt != BLOB_OCTETS || extension.flags != 0 {
            return Err(StoreFailure::Fault(
                "usage correction outcome unknown: missing leased result".into(),
            ));
        }
        if extension.len as u64 > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES {
            return Err(StoreFailure::Fault(
                "usage correction outcome unknown: oversized result bytes".into(),
            ));
        }
        // SAFETY: bounded bytes remain live under `_lease`; `lent` checks the pointer.
        let bytes = unsafe { crate::dispatch::validate::lent(extension.ptr, extension.len) }
            .ok_or_else(|| {
                StoreFailure::Fault("usage correction outcome unknown: invalid result bytes".into())
            })?;
        correction::read_result(ran.outcome, true, bytes, candidate)
            .map_err(|s| StoreFailure::Fault(format!("usage correction outcome unknown: {s}")))
    }

    fn transaction_result(
        &self,
        ran: Ran<HostBytesOut>,
        candidate: &conditional::Request,
    ) -> Result<conditional::Decision, StoreFailure> {
        let _lease = AnswerLease(self, ran.lease);
        ran.ok()?;
        let extension = ran.out.head.extensions;
        if ran.lease == 0 || extension.fmt != BLOB_OCTETS || extension.flags != 0 {
            return Err(StoreFailure::Fault(
                "record transaction outcome unknown: missing leased result".into(),
            ));
        }
        if extension.len as u64 > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES {
            return Err(StoreFailure::Fault(
                "record transaction outcome unknown: oversized result bytes".into(),
            ));
        }
        // SAFETY: the raw byte length passed HARD_MAX_BYTES before any slice was formed. A READY
        // reply's plugin memory remains live under `_lease`; `lent` checks the pointer as well.
        let bytes = unsafe { crate::dispatch::validate::lent(extension.ptr, extension.len) }
            .ok_or_else(|| {
                StoreFailure::Fault(
                    "record transaction outcome unknown: invalid result bytes".into(),
                )
            })?;
        conditional::read_result(ran.outcome, true, bytes, candidate)
            .map_err(|s| StoreFailure::Fault(format!("record transaction outcome unknown: {s}")))
    }
}

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
fn place_records(i: &mut RecordScanIn, p: *mut RecordEntry, n: usize, bytes: HostBuf) {
    i.out = HostRecords {
        items: p,
        items_cap: n,
        bytes,
    };
}

// SAFETY: as `Fixed`.

// SAFETY: as `Fixed`.

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

/// Run `req` through `$run` (`now` or `submit`), on `$self`.
macro_rules! run {
    ($self:ident, now, $r:expr) => {
        $self.now($r)
    };
    ($self:ident, submit, $r:expr) => {
        $self.submit($r).await
    };
}

impl LoadedStore {
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

fn host_blob(b: &Blob) -> Vec<u8> {
    copy(b.ptr, b.len)
}

fn boxed<'a, T>(f: impl Future<Output = Result<T, StoreFailure>> + Send + 'a) -> StoreCall<'a, T> {
    Box::pin(f)
}

impl StoreCalls for LoadedStore {
    fn supports_usage_correction(&self) -> bool {
        self.facts.usage_correction
    }

    fn apply_usage_correction<'a>(
        &'a self,
        candidate: &'a correction::Request,
    ) -> StoreCall<'a, correction::Decision> {
        boxed(async move {
            if !self.facts.usage_correction {
                return Err(StoreFailure::Refused(
                    "store does not support usage corrections".into(),
                ));
            }
            let request = CorrectionReq::new(candidate)?;
            let (ran, request) = self.submit(request).await;
            self.correction_result(ran, &request.get().candidate)
        })
    }
    fn supports_record_transaction(&self) -> bool {
        self.facts.record_transaction
    }

    fn record_transaction<'a>(
        &'a self,
        candidate: &'a conditional::Request,
    ) -> StoreCall<'a, conditional::Decision> {
        boxed(async move {
            if !self.supports_record_transaction() {
                return Err(StoreFailure::Refused(
                    "store does not support record transactions".into(),
                ));
            }
            let request = ConditionalReq::new(candidate)?;
            let (ran, request) = self.submit(request).await;
            self.transaction_result(ran, &request.get().candidate)
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

    fn put_key<'a>(&'a self, key: &'a VirtualKey) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::PUT_KEY,
                owned_in(|o, head| BlobIn {
                    head,
                    record: o.json(to_json(key)),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn get_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, Option<VirtualKey>> {
        boxed(async move {
            let r = fixed::<_, LeasedBlobOut>(
                slot::GET_KEY,
                owned_in(|o, head| IdIn {
                    head,
                    id: o.text(id),
                }),
            );
            let (ran, _) = run!(self, submit, r);
            self.record(ran)
        })
    }

    fn list_keys(&self) -> StoreCall<'_, Vec<VirtualKey>> {
        boxed(async move {
            let r = fixed::<_, LeasedListOut>(slot::LIST_KEYS, bare(in_head()));
            let (ran, _) = run!(self, submit, r);
            self.records(ran)
        })
    }

    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::DELETE_KEY,
                owned_in(|o, head| IdIn {
                    head,
                    id: o.text(id),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a VirtualKey,
        secret: &'a CredentialSecret,
    ) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::PUT_KEY_WITH_CREDENTIAL,
                owned_in(|o, head| KeyWithCredentialIn {
                    head,
                    key: o.json(to_json(key)),
                    credential: o.secret_json(to_json(secret)),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn list_credentials<'a>(&'a self, key_id: &'a str) -> StoreCall<'a, Vec<CredentialMeta>> {
        boxed(async move {
            let r = fixed::<_, LeasedListOut>(
                slot::LIST_CREDENTIALS,
                owned_in(|o, head| IdIn {
                    head,
                    id: o.text(key_id),
                }),
            );
            let (ran, _) = run!(self, submit, r);
            self.records(ran)
        })
    }

    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::REVOKE_CREDENTIAL,
                owned_in(|o, head| IdReasonIn {
                    head,
                    id: o.text(id),
                    reason: o.text(reason),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn list_credentials_since(&self, since: u64) -> StoreCall<'_, Vec<CredentialSecret>> {
        boxed(async move {
            let r = fixed::<_, LeasedListOut>(
                slot::LIST_CREDENTIALS_SINCE,
                bare(in_of(|head| U64In { head, value: since })),
            );
            let (ran, _) = run!(self, submit, r);
            self.records(ran)
        })
    }

    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        boxed(async move {
            let r = fixed::<_, OutHead>(
                slot::ADD_DENYLIST,
                owned_in(|o, head| IdReasonIn {
                    head,
                    id: o.text(sub),
                    reason: o.text(reason),
                }),
            );
            run!(self, submit, r).0.ok()
        })
    }

    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        boxed(async move {
            let r = fixed::<_, LeasedStrListOut>(slot::LIST_DENYLIST, bare(in_head()));
            let (ran, _) = run!(self, submit, r);
            self.read_strs(ran)
        })
    }

    fn list_metering(&self, bucket: u64) -> StoreCall<'_, Vec<MeteringRow>> {
        boxed(async move {
            let r = fixed::<_, LeasedListOut>(
                slot::LIST_METERING,
                bare(in_of(|head| U64In {
                    head,
                    value: bucket,
                })),
            );
            let (ran, _) = run!(self, submit, r);
            self.records(ran)
        })
    }

    fn list_audit(&self) -> StoreCall<'_, Vec<AuditRecord>> {
        boxed(async move {
            let r = fixed::<_, LeasedListOut>(slot::LIST_AUDIT, bare(in_head()));
            let (ran, _) = run!(self, submit, r);
            self.records(ran)
        })
    }

    fn list_audit_tail(&self, limit: u64) -> StoreCall<'_, Vec<AuditRecord>> {
        boxed(async move {
            let r = fixed::<_, LeasedListOut>(
                slot::LIST_AUDIT_TAIL,
                bare(in_of(|head| U64In { head, value: limit })),
            );
            let (ran, _) = run!(self, submit, r);
            self.records(ran)
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

    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        boxed(async move {
            let r = fixed::<_, LeasedStrListOut>(
                slot::LIST_PLANE_RECORD_PARENTS,
                owned_in(|o, head| IdIn {
                    head,
                    id: o.text(kind),
                }),
            );
            let (ran, _) = run!(self, submit, r);
            self.read_strs(ran)
        })
    }

    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        boxed(async move {
            let r = fixed::<_, CountOut>(
                slot::PURGE_PLANE_RECORDS_BEFORE,
                owned_in(|o, head| KindBeforeIn {
                    head,
                    kind: o.text(kind),
                    before,
                    retention: Retention::Age.code(),
                    _reserved: 0,
                }),
            );
            let (ran, _) = run!(self, submit, r);
            ran.ok().map(|()| ran.out.count)
        })
    }

    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        boxed(async move {
            let r = fixed::<_, CountOut>(
                slot::PURGE_PLANE_RECORDS_BEFORE,
                owned_in(|o, head| KindBeforeIn {
                    head,
                    kind: o.text(""),
                    before,
                    retention: st::RETENTION_USAGE_WINDOWS,
                    _reserved: 0,
                }),
            );
            let (ran, _) = run!(self, submit, r);
            ran.ok().map(|()| ran.out.count)
        })
    }
}

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
    fn supports_usage_correction(&self) -> bool {
        self.facts.usage_correction
    }

    fn apply_usage_correction(
        &self,
        candidate: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        if !self.facts.usage_correction {
            return bridge(Err(StoreFailure::Refused(
                "store does not support usage corrections".into(),
            )));
        }
        let request = CorrectionReq::new(candidate).map_err(|e| RecordStoreError(e.to_string()))?;
        let (ran, request) = self.now(request);
        bridge(self.correction_result(ran, &request.get().candidate))
    }

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
            slot::ADD_USAGE_BATCH,
            owned_in(|o, head| {
                let cell = UsageCell {
                    bucket: o.text(bucket_id),
                    window_start,
                    delta: o.json(to_json(delta)),
                };
                let (cells, cells_len) = o.rows(vec![cell]);
                AddUsageBatchIn {
                    head,
                    op_id: self.mint(),
                    cells,
                    cells_len,
                }
            }),
        )
    }

    fn supports_usage_batch_deduped(&self) -> bool {
        true
    }

    fn supports_metering_batch_deduped(&self) -> bool {
        true
    }

    fn add_usage_batch_deduped(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.plain(
            slot::ADD_USAGE_BATCH,
            owned_in(|o, head| {
                let rows = cells
                    .iter()
                    .map(|(bucket, window_start, delta)| UsageCell {
                        bucket: o.text(bucket),
                        window_start: *window_start,
                        delta: o.json(to_json(delta)),
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
        )
    }

    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.add_metering_batch_deduped(self.mint(), std::slice::from_ref(delta))
    }

    fn add_metering_batch_deduped(
        &self,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.plain(
            slot::ADD_METERING_BATCH,
            owned_in(|o, head| {
                let rows = deltas.iter().map(|delta| o.json(to_json(delta))).collect();
                let (records, records_len) = o.rows(rows);
                OpBlobsIn {
                    head,
                    op_id: op,
                    records,
                    records_len,
                }
            }),
        )
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.many(slot::LIST_METERING, Self::value(bucket))
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

    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        use busbar_contract::abi::mechanism::extensions;
        use busbar_contract::abi::sdk::store::rewrap;
        if !self.facts.credential_rewrap {
            return Err(RecordStoreError(
                "the store does not state credential rewrap CAS support".into(),
            ));
        }
        let request = rewrap::Request::new(expected, replacement);
        let (ran, _lent) = self.now(fixed::<_, OutHead>(
            slot::PUT_CREDENTIAL,
            owned_in(|o, mut head| {
                head.extensions = o.octets(&extensions::encode(&[(rewrap::INTENT, b"1")]));
                BlobIn {
                    head,
                    record: o.secret_json(to_json(&request)),
                }
            }),
        ));
        let result = bridge(ran.ok()).and_then(|()| {
            if ran.lease == 0 {
                return Err(RecordStoreError(
                    "credential rewrap answered without a leased result".into(),
                ));
            }

            let bytes = copy(ran.out.extensions.ptr, ran.out.extensions.len);
            match extensions::get(&bytes, rewrap::RESULT) {
                Some(b"applied") => Ok(true),
                Some(b"conflict") => Ok(false),
                _ => Err(RecordStoreError(
                    "credential rewrap result is missing or invalid".into(),
                )),
            }
        });
        self.release(ran.lease);
        result
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

    fn append_audit(&self, _entry: &AuditRecord) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "append_audit is not a store op: 1.6.0 writes its audit as plane records".to_string(),
        ))
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
        self.purge_plane_records(kind, before, Retention::Age)
    }

    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.count(
            slot::PURGE_PLANE_RECORDS_BEFORE,
            owned_in(|o, head| KindBeforeIn {
                head,
                kind: o.text(kind),
                before,
                retention: retention.code(),
                _reserved: 0,
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

fn split_secrets(refs: &[String], settings: &[u8]) -> (Vec<u8>, Vec<Zeroing>) {
    let Some(mut block) = (!refs.is_empty())
        .then(|| serde_json::from_slice::<serde_json::Value>(settings).ok())
        .flatten()
        .filter(serde_json::Value::is_object)
    else {
        return (settings.to_vec(), Vec::new());
    };
    let as_bytes = |v: Option<serde_json::Value>| match v {
        Some(serde_json::Value::String(s)) => s.into_bytes(),
        _ => Vec::new(),
    };
    let secrets = busbar_contract::secret_fields::lend(
        &mut block,
        refs,
        false,
        |_, v| Ok::<_, std::convert::Infallible>(as_bytes(v)),
        |_, v| Ok(as_bytes(Some(v))),
    )
    .unwrap_or_else(|e| match e {});
    let settings = serde_json::to_vec(&block).unwrap_or_default();
    (settings, secrets.into_iter().map(Zeroing).collect())
}

struct OpenLent {
    // settings-leak-lint: allow — NON-PROJECTION engine type: OPEN's settings bytes,
    settings: Vec<u8>,
    #[allow(dead_code)]
    secrets: Vec<Zeroing>,
    blobs: Vec<Blob>,
}

impl OpenLent {
    fn new(settings: Vec<u8>, secrets: Vec<Zeroing>) -> Self {
        let blobs = secrets
            .iter()
            .map(|s| Blob {
                ptr: s.0.as_ptr(),
                len: s.0.len(),
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            })
            .collect();
        Self {
            settings,
            secrets,
            blobs,
        }
    }
}

// SAFETY: `blobs` points only into `secrets`' heap buffers, which this value owns and never
// moves or writes while it lives; nothing reaches the bytes through `OpenLent` but a read.
unsafe impl Send for OpenLent {}
// SAFETY: as `Send`: shared access only reads.
unsafe impl Sync for OpenLent {}

struct Zeroing(Vec<u8>);
impl Drop for Zeroing {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

pub struct DoorStoreAxis {
    pub dispatcher: Arc<Dispatcher>,

    pub logs: crate::dispatch::PluginLogConfig,

    pub conns: crate::dispatch::ConnTable,

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
#[path = "tests/store_v3_shortcut_tests.rs"]
mod shortcut_tests;

#[cfg(test)]
#[path = "tests/store_v3_deadline_tests.rs"]
mod deadline_tests;


#[cfg(test)]
#[path = "tests/store_v3_validate_tests.rs"]
mod validate_tests;

#[cfg(test)]
#[path = "tests/store_v3_wrap.rs"]
pub(crate) mod wrap;


#[cfg(test)]
#[path = "tests/store_v3_wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "tests/store_v3_axis_tests.rs"]
mod axis_tests;

#[cfg(test)]
#[path = "tests/store_v3_lent_tests.rs"]
mod lent_tests;

#[cfg(test)]
#[path = "tests/store_v3_conditional_tests.rs"]
mod conditional_tests;

#[cfg(test)]
#[path = "tests/store_v3_secrets_tests.rs"]
mod secrets_tests;

#[cfg(test)]
#[path = "tests/store_v3_rewrap_tests.rs"]
mod rewrap_tests;

#[cfg(test)]
#[path = "tests/store_actual_table_tests.rs"]
mod actual_table;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/store_actual_open_pending_tests.rs"]
mod store_actual_open_pending_tests;
