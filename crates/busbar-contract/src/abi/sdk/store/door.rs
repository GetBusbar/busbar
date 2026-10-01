// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE DOOR: every slot of the store v3 table (`abi::store`) as a [`SafeSlot`] over a
//! [`StoreSlots`] backend, and [`store_door!`](crate::store_door), which names them all in
//! [`plugin_door!`](crate::plugin_door). A store crate invokes the macro once and holds no
//! `unsafe`.
//!
//! What each slot does, the same for every store:
//!
//! * decodes the `in` (strings as UTF-8, records as the tree's JSON shapes); a malformed `in` is
//!   REFUSED with its reason, and the store is not called;
//! * CHECKS EVERY HOST CAPACITY FIRST where the answer's size is known before acting (`reserve`,
//!   `slice_release`), so a short answer applies nothing and is never recorded under an `op_id`
//!   (the S1 addendum); a read with no side effect is sized after it reads;
//! * writes a request-path result into the host's buffers (M-SB on
//!   [`OutHead`](crate::abi::mechanism::call::OutHead)), and an off-path result under a LEASE the
//!   host hands back to `release`; a secret blob's bytes are zeroed when its lease is released;
//! * answers an `op_id` conflict REFUSED with the diagnostic
//!   [`DIAG_OPID_CONFLICT`](crate::abi::store::DIAG_OPID_CONFLICT), and a cap conflict REFUSED
//!   with [`DIAG_CAP_CONFLICT`](crate::abi::store::DIAG_CAP_CONFLICT) and an error text that
//!   begins with the conflicting cap's index.
//!
//! ERROR TEXT. A FAILED or REFUSED answer's `error` points at text the instance keeps in a
//! bounded ring of the last [`TEXT_RING`] texts; the host copies it when the op returns.

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, ReserveRefused, StoreSlots,
};
use crate::abi::mechanism::call::{
    AbiStr, Blob, Diag, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET, MAX_TEXT,
    SEVERITY_WARN,
};
use crate::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use crate::abi::sdk::door::abi_str;
use crate::abi::sdk::{HostBuf, Instance, Lent, LentList, SafeSlot};
use crate::abi::store::{
    AddUsageBatchIn, AddUsageIn, AppendBatchIn, AppendPlaneRecordIn, BlobIn, CountOut,
    GetPlaneRecordIn, HeadOut, HeadsOut, HostBytesOut, HostListOut, IdIn, IdReasonIn,
    KeyWithCredentialIn, KindBeforeIn, KindIdIn, LeasedBlobOut, LeasedListOut, LeasedStrListOut,
    ListPlaneRecordsIn, OpBlobIn, OpBlobsIn, PlaneRecordRow, PutUsageIn, RecordEntry, RecordGetIn,
    RecordPutIn, RecordScanIn, ReserveIn, ReserveOut, SessionPutIn, SessionRow, SessionsForIn,
    SliceReleaseIn, SliceReleaseOut, StoreTail, StreamHead, TokenIn, U64In, UnitCell,
    UpsertPlaneRecordIn, VerdictOut, WindowCap, WindowCapsIn, WindowIn, ABSENT, CANCEL_UNKNOWN,
    DIAG_CAP_CONFLICT, DIAG_OPID_CONFLICT, DIM_CLASS, DIM_CONCURRENCY, DIM_NANO_UNITS,
    DIM_REQUESTS, DISPOSITION_TERMINAL, FOUND, RESERVE_EXHAUSTED, RESERVE_NO_CAP,
    RESERVE_NO_FAILED_CELL, RESERVE_OK, RESERVE_STALE_EPOCH, RESERVE_UNAVAILABLE, SELECT_ALL,
    SELECT_PARENT, VERDICT_NO, VERDICT_YES,
};
use crate::kinds::RecordBytes;
use crate::records::{
    AuditRecord, CredentialSecret, MeteringDelta, PlaneDisposition, PlaneRecord, PlaneSelector,
    UsageDelta, UsageLedger, VirtualKey,
};

/// How many error texts one instance keeps alive for the host to copy.
pub const TEXT_RING: usize = 4096;

/// The diagnostic ids a store's Statement declares, in `Diag::id_idx` order.
pub const DIAG_IDS: [AbiStr; 2] = [abi_str(DIAG_OPID_CONFLICT), abi_str(DIAG_CAP_CONFLICT)];

const OPID_CONFLICT_TEXT: &str =
    "STORE_OPID_CONFLICT: the op_id was already used with different value fields";
const DIAG_OPID: &[Diag] = &[Diag {
    id_idx: 0,
    severity: SEVERITY_WARN,
    _reserved: [0; 3],
    text: abi_str(OPID_CONFLICT_TEXT),
}];
const DIAG_CAP: &[Diag] = &[Diag {
    id_idx: 1,
    severity: SEVERITY_WARN,
    _reserved: [0; 3],
    text: abi_str("a cap was pushed again at its config_gen with a different value"),
}];

/// The Statement tail of a store `B` (`abi::store::StoreTail`), for [`store_door!`](crate::store_door).
#[must_use]
pub const fn tail<B: StoreSlots>() -> StoreTail {
    StoreTail {
        head: crate::abi::mechanism::door::KindTailHead {
            size: std::mem::size_of::<StoreTail>() as u32,
            _reserved: 0,
        },
        ephemeral: B::TAIL.ephemeral as u8,
        durable_plane: B::TAIL.durable_plane as u8,
        fork_refusal: B::TAIL.fork_refusal as u8,
        _reserved: [0; 5],
    }
}

// ── the instance ─────────────────────────────────────────────────────────────────────────────

/// What an off-path answer handed the host, held until `release`. The blobs, strings and heads
/// point into `bytes`, which this owns: a `Box`'s contents never move.
struct Leased {
    bytes: Vec<Box<[u8]>>,
    // The arrays the host reads through the `out`; held here, never read by the plugin.
    _blobs: Box<[Blob]>,
    _strs: Box<[AbiStr]>,
    _heads: Box<[StreamHead]>,
    secret: bool,
}

// SAFETY: every pointer inside points into `bytes`, owned by the same value and never shared
// mutably; the host reads it only between the answer and `release`.
unsafe impl Send for Leased {}
// SAFETY: as above; nothing here is mutated through `&Leased`.
unsafe impl Sync for Leased {}

impl Drop for Leased {
    fn drop(&mut self) {
        if self.secret {
            for b in &mut self.bytes {
                b.iter_mut().for_each(|x| *x = 0);
            }
        }
    }
}

/// One store instance as the door serves it: the backend, the leases it has handed out and the
/// error texts it keeps for the host.
pub struct Served<B> {
    store: B,
    leases: Mutex<HashMap<u64, Leased>>,
    next_lease: AtomicU64,
    texts: Mutex<VecDeque<Box<str>>>,
}

impl<B> std::fmt::Debug for Served<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Served").finish_non_exhaustive()
    }
}

impl<B: StoreSlots> Served<B> {
    fn new(store: B) -> Self {
        Self {
            store,
            leases: Mutex::new(HashMap::new()),
            next_lease: AtomicU64::new(0),
            texts: Mutex::new(VecDeque::new()),
        }
    }

    /// The backend.
    pub fn store(&self) -> &B {
        &self.store
    }

    /// How many leases are held (for tests: a released lease is gone).
    pub fn leases_held(&self) -> usize {
        self.leases.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Keep `text` alive in the ring and answer it as an [`AbiStr`].
    fn text(&self, text: &str) -> AbiStr {
        let mut end = text.len().min(MAX_TEXT);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let kept: Box<str> = text[..end].into();
        let s = AbiStr {
            ptr: kept.as_ptr(),
            len: kept.len(),
        };
        let mut ring = self.texts.lock().unwrap_or_else(|p| p.into_inner());
        if ring.len() == TEXT_RING {
            ring.pop_front();
        }
        ring.push_back(kept);
        s
    }

    fn lease(&self, held: Leased) -> u64 {
        let id = self.next_lease.fetch_add(1, Ordering::Relaxed) + 1;
        self.leases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, held);
        id
    }
}

// ── answer helpers ───────────────────────────────────────────────────────────────────────────

/// Every store `out`'s head.
trait Head {
    fn head(&mut self) -> &mut OutHead;
}
macro_rules! heads {
    ($($t:ty),*) => {$(impl Head for $t { fn head(&mut self) -> &mut OutHead { &mut self.head } })*};
}
heads!(
    LeasedBlobOut,
    LeasedListOut,
    LeasedStrListOut,
    CountOut,
    HostBytesOut,
    HostListOut,
    VerdictOut,
    HeadOut,
    ReserveOut,
    SliceReleaseOut,
    HeadsOut,
    OpenOut,
    TickOut,
    CancelOut
);
impl Head for OutHead {
    fn head(&mut self) -> &mut OutHead {
        self
    }
}

fn failed<B: StoreSlots>(s: &Served<B>, out: &mut impl Head, text: &str) -> Outcome {
    out.head().error = s.text(text);
    Outcome::Failed
}

fn refused<B: StoreSlots>(s: &Served<B>, out: &mut impl Head, text: &str) -> Outcome {
    out.head().error = s.text(text);
    Outcome::Refused
}

fn conflict(out: &mut impl Head) -> Outcome {
    let h = out.head();
    h.error = abi_str(OPID_CONFLICT_TEXT);
    h.envelope.diags = DIAG_OPID.as_ptr();
    h.envelope.diags_len = DIAG_OPID.len();
    Outcome::Refused
}

fn op_answer<B: StoreSlots>(
    s: &Served<B>,
    out: &mut impl Head,
    r: Result<(), OpRefused>,
) -> Outcome {
    match r {
        Ok(()) => Outcome::Ready,
        Err(OpRefused::Conflict) => conflict(out),
        Err(OpRefused::Failed(t)) => failed(s, out, &t),
    }
}

fn done<B: StoreSlots>(
    s: &Served<B>,
    out: &mut impl Head,
    r: Result<(), crate::records::RecordStoreError>,
) -> Outcome {
    match r {
        Ok(()) => Outcome::Ready,
        Err(e) => failed(s, out, &e.0),
    }
}

fn text_of(l: Lent<'_, AbiStr>) -> Result<&str, String> {
    l.as_str()
        .map_err(|e| format!("a string is not UTF-8: {e}"))
}

fn opt_text(l: Lent<'_, AbiStr>) -> Result<Option<&str>, String> {
    if l.ptr.is_null() {
        return Ok(None);
    }
    text_of(l).map(Some)
}

fn json<T: DeserializeOwned>(l: Lent<'_, Blob>) -> Result<T, String> {
    serde_json::from_slice(l.bytes()).map_err(|e| format!("a record blob does not decode: {e}"))
}

fn to_json<T: Serialize>(v: &T) -> Box<[u8]> {
    serde_json::to_vec(v).unwrap_or_default().into_boxed_slice()
}

fn blob_over(bytes: &[u8], fmt: u32, secret: bool) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: if secret { BLOB_SECRET } else { 0 },
    }
}

/// Answer one record (or none) under a lease.
fn lease_one<B: StoreSlots>(
    s: &Served<B>,
    out: &mut LeasedBlobOut,
    record: Option<Box<[u8]>>,
    secret: bool,
) -> Outcome {
    match record {
        None => {
            out.found = ABSENT;
            out.record = Blob::ABSENT;
        }
        Some(bytes) => {
            out.found = FOUND;
            out.record = blob_over(&bytes, BLOB_JSON, secret);
            out.head.lease = s.lease(Leased {
                bytes: vec![bytes],
                _blobs: Box::new([]),
                _strs: Box::new([]),
                _heads: Box::new([]),
                secret,
            });
        }
    }
    Outcome::Ready
}

/// Answer a list of records under a lease (an empty list holds no lease).
fn lease_list<B: StoreSlots>(
    s: &Served<B>,
    out: &mut LeasedListOut,
    records: Vec<Box<[u8]>>,
    secret: bool,
) -> Outcome {
    if records.is_empty() {
        out.items = std::ptr::null();
        out.items_len = 0;
        return Outcome::Ready;
    }
    let blobs: Box<[Blob]> = records
        .iter()
        .map(|b| blob_over(b, BLOB_JSON, secret))
        .collect();
    out.items = blobs.as_ptr();
    out.items_len = blobs.len();
    out.head.lease = s.lease(Leased {
        bytes: records,
        _blobs: blobs,
        _strs: Box::new([]),
        _heads: Box::new([]),
        secret,
    });
    Outcome::Ready
}

fn lease_strs<B: StoreSlots>(s: &Served<B>, out: &mut LeasedStrListOut, v: Vec<String>) -> Outcome {
    if v.is_empty() {
        out.items = std::ptr::null();
        out.items_len = 0;
        return Outcome::Ready;
    }
    let bytes: Vec<Box<[u8]>> = v.into_iter().map(|t| t.into_bytes().into()).collect();
    let strs: Box<[AbiStr]> = bytes
        .iter()
        .map(|b| AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        })
        .collect();
    out.items = strs.as_ptr();
    out.items_len = strs.len();
    out.head.lease = s.lease(Leased {
        bytes,
        _blobs: Box::new([]),
        _strs: strs,
        _heads: Box::new([]),
        secret: false,
    });
    Outcome::Ready
}

fn listed<T: Serialize, B: StoreSlots>(
    s: &Served<B>,
    out: &mut LeasedListOut,
    r: crate::records::RecordStoreResult<Vec<T>>,
    secret: bool,
) -> Outcome {
    match r {
        Ok(v) => lease_list(s, out, v.iter().map(to_json).collect(), secret),
        Err(e) => failed(s, out, &e.0),
    }
}

/// Write `value` (or nothing) into a host byte buffer: READY, or the short FAILED.
fn bytes_into(out: &mut HostBytesOut, mut buf: HostBuf<'_, u8>, value: Option<&[u8]>) -> Outcome {
    let Some(v) = value else {
        out.found = ABSENT;
        return Outcome::Ready;
    };
    buf.extend(v);
    if buf.fits() {
        out.found = FOUND;
        out.written = buf.written() as u64;
        Outcome::Ready
    } else {
        out.found = ABSENT;
        out.needed = buf.needed() as u64;
        Outcome::Failed
    }
}

/// A list into host buffers: `items` rows and one byte buffer they point into. `row` builds each
/// row from the addresses its byte runs landed at (NULL for an absent run). READY, or the short
/// FAILED with every dimension's full size (the multi-dimension M-SB).
fn list_into<T: Copy>(
    out: &mut HostListOut,
    mut items: HostBuf<'_, T>,
    mut bytes: HostBuf<'_, u8>,
    runs: &[Vec<Option<&[u8]>>],
    row: impl Fn(usize, &[Option<(*const u8, usize)>]) -> T,
) -> Outcome {
    for (n, parts) in runs.iter().enumerate() {
        let mut at = Vec::with_capacity(parts.len());
        for p in parts {
            at.push(p.map(|b| {
                let off = bytes.extend(b);
                (bytes.as_ptr().wrapping_add(off).cast_const(), b.len())
            }));
        }
        items.push(row(n, &at));
    }
    let short = !items.fits() || !bytes.fits();
    let (iw, ineed) = items.settle(short);
    let (bw, bneed) = bytes.settle(short);
    out.items_written = iw as u64;
    out.bytes_written = bw as u64;
    out.needed_items = ineed as u64;
    out.needed_bytes = bneed as u64;
    if short {
        Outcome::Failed
    } else {
        Outcome::Ready
    }
}

fn span_blob(at: Option<(*const u8, usize)>, fmt: u32) -> Blob {
    match at {
        None => Blob::ABSENT,
        Some((ptr, len)) => Blob {
            ptr,
            len,
            fmt,
            flags: 0,
        },
    }
}

fn span_str(at: Option<(*const u8, usize)>) -> AbiStr {
    match at {
        None => AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        Some((ptr, len)) => AbiStr { ptr, len },
    }
}

fn plane_record(row: Lent<'_, PlaneRecordRow>) -> Result<PlaneRecord, String> {
    Ok(PlaneRecord {
        kind: text_of(row.field(|r| &r.kind))?.to_string(),
        id: text_of(row.field(|r| &r.id))?.to_string(),
        parent: opt_text(row.field(|r| &r.parent))?.map(str::to_string),
        seq: row.seq,
        ts: row.ts,
        disposition: if row.disposition == DISPOSITION_TERMINAL {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: row.field(|r| &r.body).bytes().to_vec(),
    })
}

fn cell_key<'a>(
    bucket: Lent<'a, AbiStr>,
    pool: Lent<'a, AbiStr>,
    dimension: u32,
    class_key: Lent<'a, AbiStr>,
    window_start: u64,
) -> Result<CellKey<'a>, String> {
    let dimension = match dimension {
        DIM_NANO_UNITS => Dimension::NanoUnits,
        DIM_REQUESTS => Dimension::Requests,
        DIM_CONCURRENCY => Dimension::Concurrency,
        DIM_CLASS => Dimension::Class(text_of(class_key)?),
        d => return Err(format!("dimension {d} is not a store dimension")),
    };
    Ok(CellKey {
        bucket: text_of(bucket)?,
        pool: opt_text(pool)?,
        dimension,
        window_start,
    })
}

fn unit_cell(c: Lent<'_, UnitCell>) -> Result<Cell<'_>, String> {
    if c.amount == 0 {
        return Err("a reserve cell's amount is 0".to_string());
    }
    Ok(Cell {
        key: cell_key(
            c.field(|c| &c.bucket),
            c.field(|c| &c.pool),
            c.dimension,
            c.field(|c| &c.class_key),
            c.window_start,
        )?,
        amount: c.amount,
    })
}

fn window_cap(c: Lent<'_, WindowCap>) -> Result<Cap<'_>, String> {
    Ok(Cap {
        key: cell_key(
            c.field(|c| &c.bucket),
            c.field(|c| &c.pool),
            c.dimension,
            c.field(|c| &c.class_key),
            c.window_start,
        )?,
        cap: c.cap,
        config_gen: c.config_gen,
    })
}

fn record_bytes(bytes: &[u8]) -> Result<RecordBytes, String> {
    RecordBytes::new(bytes.to_vec())
        .map_err(|n| format!("a record of {n} bytes is over the ceiling"))
}

/// The host's grants array as `reserve`'s sink: each grant goes straight into the host's memory.
struct GrantsInto<'a>(HostBuf<'a, crate::abi::store::CellGrant>);

impl Extend<Grant> for GrantsInto<'_> {
    fn extend<I: IntoIterator<Item = Grant>>(&mut self, grants: I) {
        for g in grants {
            self.0.push(crate::abi::store::CellGrant {
                slice_id: g.slice_id,
                granted: g.granted,
                valid_until_ms: g.valid_until_ms,
            });
        }
    }
}

/// The host's released array as `slice_release`'s sink, clamping each amount to its item's
/// `unspent` as it goes in.
struct ReleasedInto<'a> {
    items: LentList<'a, crate::abi::store::ReleaseItem>,
    buf: HostBuf<'a, u64>,
}

impl Extend<u64> for ReleasedInto<'_> {
    fn extend<I: IntoIterator<Item = u64>>(&mut self, amounts: I) {
        for b in amounts {
            // Never more than the item's `unspent`, whatever the store said.
            let b = self
                .items
                .get(self.buf.asked())
                .map_or(b, |it| b.min(it.unspent));
            self.buf.push(b);
        }
    }
}

// ── the lifecycle ────────────────────────────────────────────────────────────────────────────

/// Declare one lifecycle or kind slot over `Served<B>`.
macro_rules! slot {
    ($(#[$m:meta])* $name:ident($in:ty, $out:ty) |$s:ident, $i:ident, $o:ident| $body:block) => {
        $(#[$m])*
        #[derive(Debug)]
        pub struct $name<B>(PhantomData<B>);
        impl<B: StoreSlots> SafeSlot for $name<B> {
            type In = $in;
            type Out = $out;
            type State = Served<B>;
            #[allow(unused_variables)]
            fn call(instance: Instance<'_, Served<B>>, $i: Lent<'_, $in>, $o: &mut $out) -> Outcome {
                let Some($s) = instance.get() else {
                    return Outcome::Fault;
                };
                $body
            }
        }
    };
}

/// `validate`: the settings open a store.
#[derive(Debug)]
pub struct Validate<B>(PhantomData<B>);
impl<B: StoreSlots> SafeSlot for Validate<B> {
    type In = ValidateIn;
    type Out = OutHead;
    type State = Served<B>;
    fn call(_: Instance<'_, Served<B>>, input: Lent<'_, ValidateIn>, _: &mut OutHead) -> Outcome {
        match B::open(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            // The instance does not exist yet, so the reason has nowhere to live: REFUSED, bare.
            Err(_) => Outcome::Refused,
        }
    }
}

/// `open`: the store opens on its settings.
#[derive(Debug)]
pub struct Open<B>(PhantomData<B>);
impl<B: StoreSlots> SafeSlot for Open<B> {
    type In = OpenIn;
    type Out = OpenOut;
    type State = Served<B>;
    fn call(
        instance: Instance<'_, Served<B>>,
        input: Lent<'_, OpenIn>,
        _: &mut OpenOut,
    ) -> Outcome {
        match B::open(input.field(|i| &i.settings).bytes()) {
            Ok(store) => {
                instance.open(Served::new(store));
                Outcome::Ready
            }
            Err(_) => Outcome::Refused,
        }
    }
}

slot!(
    /// `refresh`: a store holds its settings for its lifetime; a reload opens a new instance.
    Refresh(RefreshIn, OutHead) |s, i, o| { Outcome::Ready }
);
slot!(
    /// `retire`.
    Retire(GenIn, OutHead) |s, i, o| { Outcome::Ready }
);
slot!(
    /// `tick`: a store asks for no tick.
    Tick(TickIn, TickOut) |s, i, o| {
        o.next_tick_ns = 0;
        Outcome::Ready
    }
);
slot!(
    /// `drive`: a store that never pends has nothing to drive.
    Drive(DriveIn, OutHead) |s, i, o| { Outcome::Ready }
);
slot!(
    /// `cancel`: whether the cancelled op applied is not known here; the kernel re-issues it
    /// under the same `op_id` and dedupe settles it (`CANCEL_UNKNOWN`).
    Cancel(CancelIn, CancelOut) |s, i, o| {
        o.disposition = CANCEL_UNKNOWN;
        Outcome::Ready
    }
);
slot!(
    /// `release`: the host is done with a lease.
    Release(ReleaseIn, OutHead) |s, i, o| {
        s.leases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&i.lease);
        Outcome::Ready
    }
);
slot!(
    /// `close`: the SDK drops the instance when this answers READY.
    Close(InHead, OutHead) |s, i, o| { Outcome::Ready }
);

// ── the 1.5.5 op set ─────────────────────────────────────────────────────────────────────────

slot!(
    /// `put_key` (slot 0).
    PutKey(BlobIn, OutHead) |s, i, o| {
        match json::<VirtualKey>(i.field(|i| &i.record)) {
            Ok(k) => done(s, o, s.store.put_key(&k)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `get_key` (slot 1).
    GetKey(IdIn, LeasedBlobOut) |s, i, o| {
        let id = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.get_key(id) {
            Ok(k) => lease_one(s, o, k.as_ref().map(to_json), false),
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `list_keys` (slot 2).
    ListKeys(InHead, LeasedListOut) |s, i, o| { listed(s, o, s.store.list_keys(), false) }
);
slot!(
    /// `delete_key` (slot 3).
    DeleteKey(IdIn, OutHead) |s, i, o| {
        match text_of(i.field(|i| &i.id)) {
            Ok(id) => done(s, o, s.store.delete_key(id)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `scrub_key` (slot 4).
    ScrubKey(IdIn, OutHead) |s, i, o| {
        match text_of(i.field(|i| &i.id)) {
            Ok(id) => done(s, o, s.store.scrub_key(id)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_keys_since` (slot 5).
    ListKeysSince(U64In, LeasedListOut) |s, i, o| {
        listed(s, o, s.store.list_keys_since(i.value), false)
    }
);
slot!(
    /// `get_usage` (slot 6): an untouched cell is the empty ledger, FOUND.
    GetUsage(WindowIn, LeasedBlobOut) |s, i, o| {
        let bucket = match text_of(i.field(|i| &i.bucket)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.get_usage(bucket, i.window_start) {
            Ok(l) => lease_one(s, o, Some(to_json(&l)), false),
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `put_usage` (slot 7).
    PutUsage(PutUsageIn, OutHead) |s, i, o| {
        let bucket = match text_of(i.field(|i| &i.bucket)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match json::<UsageLedger>(i.field(|i| &i.ledger)) {
            Ok(l) => done(s, o, s.store.put_usage(bucket, i.window_start, &l)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `add_usage` (slot 8), deduped on its `op_id`.
    AddUsage(AddUsageIn, OutHead) |s, i, o| {
        let cell = i.field(|i| &i.cell);
        let bucket = match text_of(cell.field(|c| &c.bucket)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match json::<UsageDelta>(cell.field(|c| &c.delta)) {
            Ok(d) => op_answer(s, o, s.store.add_usage_op(i.op_id, bucket, cell.window_start, &d)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `add_metering` (slot 9), deduped on its `op_id`.
    AddMetering(OpBlobIn, OutHead) |s, i, o| {
        match json::<MeteringDelta>(i.field(|i| &i.record)) {
            Ok(d) => op_answer(s, o, s.store.add_metering_op(i.op_id, &d)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_metering` (slot 10).
    ListMetering(U64In, LeasedListOut) |s, i, o| {
        listed(s, o, s.store.list_metering(i.value), false)
    }
);
slot!(
    /// `purge_windows_before` (slot 11).
    PurgeWindowsBefore(U64In, CountOut) |s, i, o| {
        match s.store.purge_windows_before(i.value) {
            Ok(n) => { o.count = n; Outcome::Ready }
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `purge_metering_before` (slot 12).
    PurgeMeteringBefore(IdIn, CountOut) |s, i, o| {
        let bucket = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.purge_metering_before(bucket) {
            Ok(n) => { o.count = n; Outcome::Ready }
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `put_credential` (slot 13).
    PutCredential(BlobIn, OutHead) |s, i, o| {
        match json::<CredentialSecret>(i.field(|i| &i.record)) {
            Ok(c) => done(s, o, s.store.put_credential(&c)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `put_key_with_credential` (slot 14): both rows or neither.
    PutKeyWithCredential(KeyWithCredentialIn, OutHead) |s, i, o| {
        let k = match json::<VirtualKey>(i.field(|i| &i.key)) { Ok(k) => k, Err(e) => return refused(s, o, &e) };
        match json::<CredentialSecret>(i.field(|i| &i.credential)) {
            Ok(c) => done(s, o, s.store.put_key_with_credential(&k, &c)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_credentials` (slot 15): metadata, never a secret.
    ListCredentials(IdIn, LeasedListOut) |s, i, o| {
        let id = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        listed(s, o, s.store.list_credentials(id), false)
    }
);
slot!(
    /// `lookup_credential_secret` (slot 16): a secret blob; unknown is ABSENT.
    LookupCredentialSecret(KindIdIn, LeasedBlobOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let id = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.lookup_credential_secret(kind, id) {
            Ok(c) => lease_one(s, o, c.as_ref().map(to_json), true),
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `revoke_credential` (slot 17).
    RevokeCredential(IdReasonIn, OutHead) |s, i, o| {
        let id = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match text_of(i.field(|i| &i.reason)) {
            Ok(r) => done(s, o, s.store.revoke_credential(id, r)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_credentials_since` (slot 18): secret blobs.
    ListCredentialsSince(U64In, LeasedListOut) |s, i, o| {
        listed(s, o, s.store.list_credentials_since(i.value), true)
    }
);
slot!(
    /// `append_audit` (slot 19), deduped on its `op_id`.
    AppendAudit(OpBlobIn, OutHead) |s, i, o| {
        match json::<AuditRecord>(i.field(|i| &i.record)) {
            Ok(a) => op_answer(s, o, s.store.append_audit_op(i.op_id, &a)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_audit` (slot 20).
    ListAudit(InHead, LeasedListOut) |s, i, o| { listed(s, o, s.store.list_audit(), false) }
);
slot!(
    /// `add_denylist` (slot 21).
    AddDenylist(IdReasonIn, OutHead) |s, i, o| {
        let id = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match text_of(i.field(|i| &i.reason)) {
            Ok(r) => done(s, o, s.store.add_denylist(id, r)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_denylist` (slot 22).
    ListDenylist(InHead, LeasedStrListOut) |s, i, o| {
        match s.store.list_denylist() {
            Ok(v) => lease_strs(s, o, v),
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `list_audit_tail` (slot 23).
    ListAuditTail(U64In, LeasedListOut) |s, i, o| {
        listed(s, o, s.store.list_audit_tail(i.value), false)
    }
);

// ── plane records ────────────────────────────────────────────────────────────────────────────

slot!(
    /// `upsert_plane_record` (slot 24).
    UpsertPlaneRecord(UpsertPlaneRecordIn, OutHead) |s, i, o| {
        match plane_record(i.field(|i| &i.record)) {
            Ok(r) => done(s, o, s.store.upsert_plane_record(&r)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `get_plane_record` (slot 25): the body into the host buffer.
    GetPlaneRecord(GetPlaneRecordIn, HostBytesOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let id = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.get_plane_record(kind, id) {
            Ok(body) => bytes_into(o, i.field(|i| &i.body).ptr(), body.as_deref()),
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `append_plane_record` (slot 26), deduped on its `op_id`.
    AppendPlaneRecord(AppendPlaneRecordIn, OutHead) |s, i, o| {
        match plane_record(i.field(|i| &i.record)) {
            Ok(r) => op_answer(s, o, s.store.append_plane_record_op(i.op_id, &r)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `list_plane_records` (slot 27): bodies into the host's blobs.
    ListPlaneRecords(ListPlaneRecordsIn, HostListOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let selector = match i.selector {
            SELECT_ALL => PlaneSelector::All,
            SELECT_PARENT => match text_of(i.field(|i| &i.parent)) {
                Ok(p) => PlaneSelector::Parent(p.to_string()),
                Err(e) => return refused(s, o, &e),
            },
            n => return refused(s, o, &format!("selector {n} is not a plane selector")),
        };
        match s.store.list_plane_records(kind, &selector) {
            Ok(bodies) => {
                let runs: Vec<Vec<Option<&[u8]>>> =
                    bodies.iter().map(|b| vec![Some(b.as_slice())]).collect();
                let host = i.field(|i| &i.out);
                list_into(o, host.items(), host.field(|h| &h.bytes).ptr(), &runs, |_, at| {
                    span_blob(at[0], BLOB_OCTETS)
                })
            }
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `list_plane_record_parents` (slot 28).
    ListPlaneRecordParents(IdIn, LeasedStrListOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.id)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.list_plane_record_parents(kind) {
            Ok(v) => lease_strs(s, o, v),
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `purge_plane_records_before` (slot 29).
    PurgePlaneRecordsBefore(KindBeforeIn, CountOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.purge_plane_records_before(kind, i.before) {
            Ok(n) => { o.count = n; Outcome::Ready }
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `delete_plane_record` (slot 30); absent is READY.
    DeletePlaneRecord(KindIdIn, OutHead) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match text_of(i.field(|i| &i.id)) {
            Ok(id) => done(s, o, s.store.delete_plane_record(kind, id)),
            Err(e) => refused(s, o, &e),
        }
    }
);
slot!(
    /// `redeem_plane_token` (slot 31): YES = this call was the first redemption.
    RedeemPlaneToken(TokenIn, VerdictOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let token = match text_of(i.field(|i| &i.token)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.redeem_plane_token(kind, token, i.expires_at, i.now) {
            Ok(y) => { o.verdict = if y { VERDICT_YES } else { VERDICT_NO }; Outcome::Ready }
            Err(e) => failed(s, o, &e.0),
        }
    }
);
slot!(
    /// `plane_token_live` (slot 32): spends nothing.
    PlaneTokenLive(TokenIn, VerdictOut) |s, i, o| {
        let kind = match text_of(i.field(|i| &i.kind)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let token = match text_of(i.field(|i| &i.token)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.plane_token_live(kind, token, i.expires_at, i.now) {
            Ok(y) => { o.verdict = if y { VERDICT_YES } else { VERDICT_NO }; Outcome::Ready }
            Err(e) => failed(s, o, &e.0),
        }
    }
);

// ── the ledger ops ───────────────────────────────────────────────────────────────────────────

slot!(
    /// `append_batch` (slot 33): the head the stream reached.
    AppendBatch(AppendBatchIn, HeadOut) |s, i, o| {
        let stream = match text_of(i.field(|i| &i.stream)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let mut records = Vec::with_capacity(i.records().len());
        for r in i.records().iter() {
            match record_bytes(r.bytes()) {
                Ok(b) => records.push(b),
                Err(e) => return refused(s, o, &e),
            }
        }
        match s.store.append_batch(i.op_id, stream, &records) {
            Ok(h) => { o.seq = h.seq; o.epoch = h.epoch; Outcome::Ready }
            Err(OpRefused::Conflict) => conflict(o),
            Err(OpRefused::Failed(t)) => failed(s, o, &t),
        }
    }
);
slot!(
    /// `reserve` (slot 34): the capacity check first, then one all-or-nothing draw.
    Reserve(ReserveIn, ReserveOut) |s, i, o| {
        o.failed_cell = RESERVE_NO_FAILED_CELL;
        let cells_in = i.cells();
        let grants_buf = i.grants();
        if grants_buf.cap() < cells_in.len() {
            // M-SB before anything else, the replay lookup included (S1 addendum).
            o.needed_grants = cells_in.len() as u64;
            return Outcome::Failed;
        }
        // Every cell decodes before the store is called; the store then reads them in place and
        // its grants go straight into the host's array: nothing is allocated here.
        for c in cells_in.iter() {
            if let Err(e) = unit_cell(c) {
                return refused(s, o, &e);
            }
        }
        let mut grants = GrantsInto(grants_buf);
        let cells = cells_in.iter().filter_map(|c| unit_cell(c).ok()); // every one decodes
        match s.store.reserve(i.op_id, i.epoch, cells, &mut grants) {
            Ok(()) if grants.0.asked() == cells_in.len() => {
                o.grants_len = grants.0.written();
                o.reason = RESERVE_OK;
                Outcome::Ready
            }
            Ok(()) => Outcome::Fault, // committed under the op_id: never FAILED (`StoreSlots::reserve`)
            Err(r) => {
                let (reason, cell) = match r {
                    ReserveRefused::Exhausted { cell } => (RESERVE_EXHAUSTED, cell),
                    ReserveRefused::StaleEpoch => (RESERVE_STALE_EPOCH, RESERVE_NO_FAILED_CELL),
                    ReserveRefused::Unavailable => (RESERVE_UNAVAILABLE, RESERVE_NO_FAILED_CELL),
                    ReserveRefused::NoCap { cell } => (RESERVE_NO_CAP, cell),
                    ReserveRefused::Conflict => return conflict(o),
                };
                o.reason = reason;
                o.failed_cell = cell;
                Outcome::Failed
            }
        }
    }
);
slot!(
    /// `slice_release` (slot 35): the capacity check first, then the clamped release.
    SliceRelease(SliceReleaseIn, SliceReleaseOut) |s, i, o| {
        let items_in = i.items();
        let released_buf = i.released();
        if released_buf.cap() < items_in.len() {
            o.needed_released = items_in.len() as u64;
            return Outcome::Failed;
        }
        // The items read in place, the amounts straight into the host's array: nothing allocated.
        let mut released = ReleasedInto { items: items_in, buf: released_buf };
        let items = items_in.iter().map(|it| (it.slice_id, it.unspent));
        match s.store.slice_release(i.op_id, i.epoch, items, &mut released) {
            Ok(()) if released.buf.asked() == items_in.len() => {
                o.released_len = released.buf.written();
                Outcome::Ready
            }
            Ok(()) => Outcome::Fault, // committed: never FAILED (`StoreSlots::slice_release`)
            Err(OpRefused::Conflict) => conflict(o),
            Err(OpRefused::Failed(t)) => failed(s, o, &t),
        }
    }
);
slot!(
    /// `heads` (slot 36): under a lease.
    Heads(InHead, HeadsOut) |s, i, o| {
        match s.store.heads() {
            Ok(v) if v.is_empty() => {
                o.items = std::ptr::null();
                o.items_len = 0;
                Outcome::Ready
            }
            Ok(v) => {
                let bytes: Vec<Box<[u8]>> = v.iter().map(|(n, _)| n.as_bytes().into()).collect();
                let heads: Box<[StreamHead]> = bytes
                    .iter()
                    .zip(&v)
                    .map(|(b, (_, h))| StreamHead {
                        stream: AbiStr { ptr: b.as_ptr(), len: b.len() },
                        seq: h.seq,
                        epoch: h.epoch,
                    })
                    .collect();
                o.items = heads.as_ptr();
                o.items_len = heads.len();
                o.head.lease = s.lease(Leased {
                    bytes,
                    _blobs: Box::new([]),
                    _strs: Box::new([]),
                    _heads: heads,
                    secret: false,
                });
                Outcome::Ready
            }
            Err(e) => failed(s, o, &e),
        }
    }
);
slot!(
    /// `session_put` (slot 37).
    SessionPut(SessionPutIn, OutHead) |s, i, o| {
        let node = match text_of(i.field(|i| &i.node)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let principal = match text_of(i.field(|i| &i.principal)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.session_put(i.session, node, principal) {
            Ok(()) => Outcome::Ready,
            Err(e) => failed(s, o, &e),
        }
    }
);
slot!(
    /// `session_remove` (slot 38).
    SessionRemove(U64In, OutHead) |s, i, o| {
        match s.store.session_remove(i.value) {
            Ok(()) => Outcome::Ready,
            Err(e) => failed(s, o, &e),
        }
    }
);
slot!(
    /// `sessions_for` (slot 39): rows into the host's sessions.
    SessionsFor(SessionsForIn, HostListOut) |s, i, o| {
        let principal = match text_of(i.field(|i| &i.principal)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.sessions_for(principal) {
            Ok(rows) => {
                let runs: Vec<Vec<Option<&[u8]>>> =
                    rows.iter().map(|(_, n)| vec![Some(n.as_bytes())]).collect();
                let host = i.field(|i| &i.out);
                list_into(o, host.items(), host.field(|h| &h.bytes).ptr(), &runs, |n, at| {
                    SessionRow { session: rows[n].0, node: span_str(at[0]) }
                })
            }
            Err(e) => failed(s, o, &e),
        }
    }
);
slot!(
    /// `record_put` (slot 40).
    RecordPut(RecordPutIn, OutHead) |s, i, o| {
        let schema = match text_of(i.field(|i| &i.schema)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        let value = match record_bytes(i.field(|i| &i.value).bytes()) { Ok(v) => v, Err(e) => return refused(s, o, &e) };
        match s.store.record_put(schema, i.field(|i| &i.key).bytes(), &value) {
            Ok(()) => Outcome::Ready,
            Err(e) => failed(s, o, &e),
        }
    }
);
slot!(
    /// `record_get` (slot 41): the value into the host buffer.
    RecordGet(RecordGetIn, HostBytesOut) |s, i, o| {
        let schema = match text_of(i.field(|i| &i.schema)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.record_get(schema, i.field(|i| &i.key).bytes()) {
            Ok(v) => bytes_into(o, i.field(|i| &i.value).ptr(), v.as_ref().map(RecordBytes::as_slice)),
            Err(e) => failed(s, o, &e),
        }
    }
);
slot!(
    /// `record_scan` (slot 42): entries into the host's records; `limit` 0 is nothing.
    RecordScan(RecordScanIn, HostListOut) |s, i, o| {
        let schema = match text_of(i.field(|i| &i.schema)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
        match s.store.record_scan(schema, i.field(|i| &i.prefix).bytes(), i.limit) {
            Ok(rows) => {
                let rows = &rows[..rows.len().min(i.limit as usize)];
                let runs: Vec<Vec<Option<&[u8]>>> = rows
                    .iter()
                    .map(|(k, v)| vec![Some(k.as_slice()), Some(v.as_slice())])
                    .collect();
                let host = i.field(|i| &i.out);
                list_into(o, host.items(), host.field(|h| &h.bytes).ptr(), &runs, |_, at| {
                    RecordEntry {
                        key: span_blob(at[0], BLOB_OCTETS),
                        value: span_blob(at[1], BLOB_OCTETS),
                    }
                })
            }
            Err(e) => failed(s, o, &e),
        }
    }
);

// ── the money batches and caps ───────────────────────────────────────────────────────────────

slot!(
    /// `add_usage_batch` (slot 43): one `op_id`, the cells in order, atomically.
    AddUsageBatch(AddUsageBatchIn, OutHead) |s, i, o| {
        let mut cells = Vec::with_capacity(i.cells().len());
        for c in i.cells().iter() {
            let bucket = match text_of(c.field(|c| &c.bucket)) { Ok(t) => t, Err(e) => return refused(s, o, &e) };
            match json::<UsageDelta>(c.field(|c| &c.delta)) {
                Ok(d) => cells.push((bucket, c.window_start, d)),
                Err(e) => return refused(s, o, &e),
            }
        }
        op_answer(s, o, s.store.add_usage_batch(i.op_id, &cells))
    }
);
slot!(
    /// `add_metering_batch` (slot 44).
    AddMeteringBatch(OpBlobsIn, OutHead) |s, i, o| {
        let mut rows = Vec::with_capacity(i.records().len());
        for r in i.records().iter() {
            match json::<MeteringDelta>(r) {
                Ok(d) => rows.push(d),
                Err(e) => return refused(s, o, &e),
            }
        }
        op_answer(s, o, s.store.add_metering_batch(i.op_id, &rows))
    }
);
slot!(
    /// `append_audit_batch` (slot 45).
    AppendAuditBatch(OpBlobsIn, OutHead) |s, i, o| {
        let mut rows = Vec::with_capacity(i.records().len());
        for r in i.records().iter() {
            match json::<AuditRecord>(r) {
                Ok(d) => rows.push(d),
                Err(e) => return refused(s, o, &e),
            }
        }
        op_answer(s, o, s.store.append_audit_batch(i.op_id, &rows))
    }
);
slot!(
    /// `window_caps` (slot 46): atomic per push; a conflict names its index first.
    WindowCaps(WindowCapsIn, OutHead) |s, i, o| {
        let mut caps = Vec::with_capacity(i.caps().len());
        for c in i.caps().iter() {
            match window_cap(c) {
                Ok(c) => caps.push(c),
                Err(e) => return refused(s, o, &e),
            }
        }
        match s.store.window_caps(i.op_id, &caps) {
            Ok(()) => Outcome::Ready,
            Err(CapsRefused::CapConflict { index }) => {
                o.error = s.text(&format!("{index}: {DIAG_CAP_CONFLICT}"));
                o.envelope.diags = DIAG_CAP.as_ptr();
                o.envelope.diags_len = DIAG_CAP.len();
                Outcome::Refused
            }
            Err(CapsRefused::Conflict) => conflict(o),
            Err(CapsRefused::Failed(t)) => failed(s, o, &t),
        }
    }
);

/// THE STORE DOOR MACRO: `store_door!(MyStore, "my-store", "1.0.0", 64);` in a store's logic crate
/// expands to its `pub extern "C" fn door()` over the store v3 table, every slot a
/// [`Safe`](crate::abi::sdk::Safe) slot over `MyStore: StoreSlots`. The Statement names the
/// store, declares [`DIAG_IDS`] and carries the store's tail ([`tail`]).
#[macro_export]
macro_rules! store_door {
    ($store:ty, $name:expr, $version:expr, $max_inflight:expr $(,)?) => {
        const __BUSBAR_STORE_TAIL: $crate::abi::store::StoreTail =
            $crate::abi::sdk::store::door::tail::<$store>();
        const __BUSBAR_STORE_DIAGS: [$crate::abi::mechanism::call::AbiStr; 2] =
            $crate::abi::sdk::store::door::DIAG_IDS;
        $crate::plugin_door! {
            ops: $crate::abi::store::Ops,
            statement: $crate::abi::mechanism::door::Statement {
                diag_ids: __BUSBAR_STORE_DIAGS.as_ptr(),
                diag_ids_len: 2,
                kind_tail: ::core::ptr::from_ref(&__BUSBAR_STORE_TAIL)
                    .cast::<$crate::abi::mechanism::door::KindTailHead>(),
                ..$crate::abi::sdk::door::statement($name, $version, $max_inflight)
            },
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Validate<$store>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Open<$store>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Refresh<$store>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Retire<$store>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Tick<$store>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Drive<$store>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Cancel<$store>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Release<$store>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Close<$store>>,
            },
            kind_ops: {
                put_key: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PutKey<$store>>,
                get_key: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::GetKey<$store>>,
                list_keys: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListKeys<$store>>,
                delete_key: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::DeleteKey<$store>>,
                scrub_key: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ScrubKey<$store>>,
                list_keys_since: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListKeysSince<$store>>,
                get_usage: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::GetUsage<$store>>,
                put_usage: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PutUsage<$store>>,
                add_usage: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AddUsage<$store>>,
                add_metering: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AddMetering<$store>>,
                list_metering: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListMetering<$store>>,
                purge_windows_before: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PurgeWindowsBefore<$store>>,
                purge_metering_before: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PurgeMeteringBefore<$store>>,
                put_credential: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PutCredential<$store>>,
                put_key_with_credential: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PutKeyWithCredential<$store>>,
                list_credentials: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListCredentials<$store>>,
                lookup_credential_secret: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::LookupCredentialSecret<$store>>,
                revoke_credential: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::RevokeCredential<$store>>,
                list_credentials_since: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListCredentialsSince<$store>>,
                append_audit: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AppendAudit<$store>>,
                list_audit: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListAudit<$store>>,
                add_denylist: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AddDenylist<$store>>,
                list_denylist: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListDenylist<$store>>,
                list_audit_tail: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListAuditTail<$store>>,
                upsert_plane_record: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::UpsertPlaneRecord<$store>>,
                get_plane_record: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::GetPlaneRecord<$store>>,
                append_plane_record: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AppendPlaneRecord<$store>>,
                list_plane_records: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListPlaneRecords<$store>>,
                list_plane_record_parents: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::ListPlaneRecordParents<$store>>,
                purge_plane_records_before: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PurgePlaneRecordsBefore<$store>>,
                delete_plane_record: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::DeletePlaneRecord<$store>>,
                redeem_plane_token: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::RedeemPlaneToken<$store>>,
                plane_token_live: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::PlaneTokenLive<$store>>,
                append_batch: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AppendBatch<$store>>,
                reserve: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Reserve<$store>>,
                slice_release: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::SliceRelease<$store>>,
                heads: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::Heads<$store>>,
                session_put: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::SessionPut<$store>>,
                session_remove: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::SessionRemove<$store>>,
                sessions_for: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::SessionsFor<$store>>,
                record_put: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::RecordPut<$store>>,
                record_get: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::RecordGet<$store>>,
                record_scan: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::RecordScan<$store>>,
                add_usage_batch: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AddUsageBatch<$store>>,
                add_metering_batch: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AddMeteringBatch<$store>>,
                append_audit_batch: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::AppendAuditBatch<$store>>,
                window_caps: $crate::abi::sdk::Safe<$crate::abi::sdk::store::door::WindowCaps<$store>>,
            },
        }
    };
}
