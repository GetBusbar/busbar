// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE DOOR ALLOCATES NOTHING ON THE REQUEST PATH (THE DESIGN §11; A.8 "Zero allocation on
//! the READY path": a counting-allocator witness is 0 for each request-path op).
//!
//! Its own test binary, because the witness is a counting `#[global_allocator]`. The count is
//! PER THREAD and ARMED only around one door call, so another test thread never lands in it. The
//! store behind the door builds its answers with the witness disarmed: what is measured is the
//! door's own work (the trampoline, the slot body, the host buffers, the error text ring), not
//! the backend's.
//!
//! The slots measured are every request-path slot of the store table that is not money (`OPS`
//! `request_path`, minus `reserve` and `slice_release`). The store traits take borrowed views
//! (`PlaneRecordRef`, the record's `&[u8]`, `PlaneSelector::Parent` over the host's string), so the
//! door hands the store the host's ABI memory as it is (ARCHITECT R7 2026-10-01); a store that
//! keeps a record copies it itself.
//!
//! RED: before the door went allocation-free, the list slots collected their runs into `Vec`s,
//! every refusal or failure text was formatted and copied into a boxed ring entry, and the writes
//! copied the host's row into an owned `PlaneRecord` / `RecordBytes` / `String`, so every case
//! below but the plain reads counted at least one allocation.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell as UnitCell, Grant, OpResult, ReserveRefused, StoreSlots, Tail,
};
use busbar_contract::abi::store::{
    slot, AppendPlaneRecordIn, GetPlaneRecordIn, HostBlobs, HostBuf, HostBytesOut, HostListOut,
    HostRecords, HostSessions, KindIdIn, ListPlaneRecordsIn, OpId, Ops, PlaneRecordRow, RecordEntry,
    RecordGetIn, RecordPutIn, RecordScanIn, SessionRow, SessionsForIn, TokenIn, UpsertPlaneRecordIn,
    VerdictOut, DISPOSITION_ACTIVE, SELECT_ALL, SELECT_PARENT,
};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, PlaneRecordRef, PlaneSelector, RecordStore,
    RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

// ── the witness ──────────────────────────────────────────────────────────────────────────────

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<u64> = const { Cell::new(0) };
}

fn note() {
    let _ = ARMED.try_with(|a| {
        if a.get() {
            let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        }
    });
}

/// `System`, counting this thread's allocations while armed.
struct Witness;

// SAFETY: every method forwards to `System` unchanged; the only addition is a thread-local counter
// bump, which allocates nothing (const-initialised, no destructor).
unsafe impl GlobalAlloc for Witness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: forwarded verbatim; the caller's obligations on `layout` are unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
        // SAFETY: forwarded verbatim; the caller's obligations on `p`/`layout` are unchanged.
        unsafe { System.realloc(p, layout, new_size) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim.
        unsafe { System.dealloc(p, layout) }
    }
}

#[global_allocator]
static WITNESS: Witness = Witness;

/// How many allocations `f` makes on this thread.
fn counted(f: impl FnOnce()) -> u64 {
    COUNT.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    COUNT.with(Cell::get)
}

/// Run `f` with the witness disarmed: the store's own work.
fn unwitnessed<T>(f: impl FnOnce() -> T) -> T {
    let was = ARMED.with(|a| a.replace(false));
    let r = f();
    ARMED.with(|a| a.set(was));
    r
}

// ── a store with canned answers ──────────────────────────────────────────────────────────────

/// The kind (or schema) a store answers FAILED for.
const DOWN: &str = "down";
/// The store's failure text.
const DOWN_TEXT: &str = "the backend is down";

fn down<T>() -> RecordStoreResult<T> {
    Err(RecordStoreError(DOWN_TEXT.to_string()))
}

struct Canned;

impl RecordStore for Canned {
    fn put_key(&self, _: &VirtualKey) -> RecordStoreResult<()> {
        unreachable!("not a request-path slot")
    }
    fn get_key(&self, _: &str) -> RecordStoreResult<Option<VirtualKey>> {
        unreachable!("not a request-path slot")
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        unreachable!("not a request-path slot")
    }
    fn delete_key(&self, _: &str) -> RecordStoreResult<()> {
        unreachable!("not a request-path slot")
    }
    fn get_usage(&self, _: &str, _: u64) -> RecordStoreResult<UsageLedger> {
        unreachable!("not a request-path slot")
    }
    fn put_usage(&self, _: &str, _: u64, _: &UsageLedger) -> RecordStoreResult<()> {
        unreachable!("not a request-path slot")
    }
    fn add_metering(&self, _: &MeteringDelta) -> RecordStoreResult<()> {
        unreachable!("not a request-path slot")
    }
    fn list_metering(&self, _: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        unreachable!("not a request-path slot")
    }
    fn get_plane_record(&self, kind: &str, _: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        unwitnessed(|| {
            if kind == DOWN {
                down()
            } else {
                Ok(Some(b"a body".to_vec()))
            }
        })
    }
    fn upsert_plane_record(&self, _: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(&self, _: &str, _: &PlaneSelector) -> RecordStoreResult<Vec<Vec<u8>>> {
        unwitnessed(|| Ok(vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]))
    }
    fn delete_plane_record(&self, kind: &str, _: &str) -> RecordStoreResult<()> {
        unwitnessed(|| if kind == DOWN { down() } else { Ok(()) })
    }
    fn redeem_plane_token(&self, _: &str, _: &str, _: u64, _: u64) -> RecordStoreResult<bool> {
        Ok(true)
    }
    fn plane_token_live(&self, _: &str, _: &str, _: u64, _: u64) -> RecordStoreResult<bool> {
        Ok(true)
    }
}

impl StoreSlots for Canned {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: false,
    };
    fn open(_: &[u8]) -> Result<Self, String> {
        Ok(Self)
    }
    fn add_usage_op(&self, _: OpId, _: &str, _: u64, _: &UsageDelta) -> OpResult<()> {
        unreachable!("not a request-path slot")
    }
    fn add_metering_op(&self, _: OpId, _: &MeteringDelta) -> OpResult<()> {
        unreachable!("not a request-path slot")
    }
    fn append_audit_op(&self, _: OpId, _: &AuditRecord) -> OpResult<()> {
        unreachable!("not a request-path slot")
    }
    fn append_plane_record_op(&self, _: OpId, _: PlaneRecordRef<'_>) -> OpResult<()> {
        Ok(())
    }
    fn append_batch(&self, _: OpId, _: &str, _: &[RecordBytes]) -> OpResult<Head> {
        unreachable!("not a request-path slot")
    }
    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        unreachable!("not a request-path slot")
    }
    fn session_put(&self, _: u64, _: &str, _: &str) -> Result<(), String> {
        unreachable!("not a request-path slot")
    }
    fn session_remove(&self, _: u64) -> Result<(), String> {
        unreachable!("not a request-path slot")
    }
    fn sessions_for(&self, _: &str) -> Result<Vec<(u64, String)>, String> {
        unwitnessed(|| Ok(vec![(7, "node-a".to_string()), (9, "node-b".to_string())]))
    }
    fn record_put(&self, _: &str, _: &[u8], _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn record_get(&self, schema: &str, _: &[u8]) -> Result<Option<RecordBytes>, String> {
        unwitnessed(|| {
            if schema == DOWN {
                Err(DOWN_TEXT.to_string())
            } else {
                Ok(RecordBytes::new(b"a value".to_vec()).ok())
            }
        })
    }
    fn record_scan(
        &self,
        _: &str,
        _: &[u8],
        _: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        let v = || RecordBytes::new(b"v".to_vec()).expect("a small record");
        unwitnessed(|| Ok(vec![(b"k1".to_vec(), v()), (b"k2".to_vec(), v())]))
    }
    fn reserve(&self, _: OpId, _: u64, _: &[UnitCell<'_>]) -> Result<Vec<Grant>, ReserveRefused> {
        unreachable!("money: not this witness")
    }
    fn slice_release(&self, _: OpId, _: u64, _: &[(u64, u64)]) -> OpResult<Vec<u64>> {
        unreachable!("money: not this witness")
    }
    fn add_usage_batch(&self, _: OpId, _: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        unreachable!("not a request-path slot")
    }
    fn add_metering_batch(&self, _: OpId, _: &[MeteringDelta]) -> OpResult<()> {
        unreachable!("not a request-path slot")
    }
    fn append_audit_batch(&self, _: OpId, _: &[AuditRecord]) -> OpResult<()> {
        unreachable!("not a request-path slot")
    }
    fn window_caps(&self, _: OpId, _: &[Cap<'_>]) -> Result<(), CapsRefused> {
        unreachable!("not a request-path slot")
    }
}

mod canned {
    busbar_contract::store_door!(super::Canned, "canned", "0", 8);
}

// ── driving the door as the host does ────────────────────────────────────────────────────────

fn ops() -> &'static Ops {
    // SAFETY: the macro's door is `'static`, and a store door's table is the store `Ops`.
    unsafe { &*(*canned::door()).ops.cast::<Ops>() }
}

fn in_head<T>(op: u32) -> InHead {
    // SAFETY: `InHead` is plain data (integers, raw pointers); all-zero is valid.
    let mut h: InHead = unsafe { std::mem::zeroed() };
    h.size = size_of::<T>() as u32;
    h.op = op;
    h.ticket = Ticket::NONE;
    h
}

/// An `in` or `out` of plain data, all zero.
fn zeroed<T: Copy>() -> T {
    // SAFETY: every store `in`/`out` is plain data (integers, raw pointers, `AbiStr`/`Blob`);
    // all-zero is valid for each.
    unsafe { std::mem::zeroed() }
}

fn out_head<T>() -> OutHead {
    let mut h: OutHead = zeroed();
    h.size = size_of::<T>() as u32;
    h
}

fn s(t: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    }
}

fn octets(t: &'static [u8]) -> Blob {
    Blob {
        ptr: t.as_ptr(),
        len: t.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    }
}

fn host<T>(buf: &mut [T]) -> (*mut T, usize) {
    (buf.as_mut_ptr(), buf.len())
}

fn bytes_buf(buf: &mut [u8]) -> HostBuf {
    let (ptr, cap) = host(buf);
    HostBuf { ptr, cap }
}

fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    let op = op.expect("the macro fills every slot");
    op(instance, ptr::from_ref(input).cast(), ptr::from_mut(out).cast()).outcome()
}

fn open() -> *mut c_void {
    let t = ops();
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(life::OPEN);
    input.settings = octets(b"{}");
    let mut out: OpenOut = zeroed();
    out.head = out_head::<OpenOut>();
    assert_eq!(call(t.head.open, ptr::null_mut(), &input, &mut out), Outcome::Ready);
    assert!(!out.instance.is_null());
    out.instance
}

fn text(t: AbiStr) -> String {
    if t.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the door's error text lives in its ring until the next TEXT_RING texts, and the
    // call has returned with nothing else in flight.
    let b = unsafe { std::slice::from_raw_parts(t.ptr, t.len) };
    String::from_utf8_lossy(b).into_owned()
}

/// One request-path call: what it answered, its error text, and the allocations it made.
struct Measured {
    case: &'static str,
    outcome: Outcome,
    error: String,
    allocations: u64,
}

/// Call once to warm this thread (the door's per-thread capture is made on first use), then
/// once under the witness.
fn measure<I: Copy, O: Copy>(
    case: &'static str,
    op: Option<Op>,
    instance: *mut c_void,
    input: I,
    fresh: impl Fn() -> O,
    error: impl Fn(&O) -> AbiStr,
) -> Measured {
    let mut out = fresh();
    let _ = call(op, instance, &input, &mut out);
    let mut out = fresh();
    let mut outcome = Outcome::Fault;
    let allocations = counted(|| outcome = call(op, instance, &input, &mut out));
    Measured {
        case,
        outcome,
        error: text(error(&out)),
        allocations,
    }
}

// ── the witness itself ───────────────────────────────────────────────────────────────────────

#[test]
fn the_witness_counts_an_allocation_and_a_disarmed_one_not() {
    assert_eq!(
        counted(|| drop(std::hint::black_box(Box::new(7_u64)))),
        1,
        "an armed allocation is counted"
    );
    assert_eq!(
        counted(|| unwitnessed(|| drop(std::hint::black_box(Box::new(7_u64))))),
        0,
        "the store's own allocation is not the door's"
    );
}

// ── the request path ─────────────────────────────────────────────────────────────────────────

#[test]
fn the_store_doors_request_path_slots_allocate_nothing() {
    let t = ops();
    let inst = open();
    let mut body = [0u8; 64];
    let mut blobs = [Blob::ABSENT; 8];
    let mut list_bytes = [0u8; 64];
    let no_session = SessionRow {
        session: 0,
        node: s(b""),
    };
    let mut sessions = [no_session; 4];
    let mut session_bytes = [0u8; 64];
    let no_entry = RecordEntry {
        key: Blob::ABSENT,
        value: Blob::ABSENT,
    };
    let mut entries = [no_entry; 4];
    let mut entry_bytes = [0u8; 64];
    let over_ceiling: &'static [u8] = Box::leak(vec![b'x'; 513].into_boxed_slice());

    let bytes_out = || HostBytesOut {
        head: out_head::<HostBytesOut>(),
        ..zeroed()
    };
    let list_out = || HostListOut {
        head: out_head::<HostListOut>(),
        ..zeroed()
    };
    let verdict_out = || VerdictOut {
        head: out_head::<VerdictOut>(),
        ..zeroed()
    };
    let head_out = out_head::<OutHead>;

    // The host's buffers, as the `in`s name them: raw pointers, taken once.
    let body_buf = bytes_buf(&mut body);
    let list_buf = bytes_buf(&mut list_bytes);
    let session_buf = bytes_buf(&mut session_bytes);
    let entry_buf = bytes_buf(&mut entry_bytes);
    let get = |kind: &'static [u8], cap: usize| GetPlaneRecordIn {
        head: in_head::<GetPlaneRecordIn>(slot::GET_PLANE_RECORD),
        kind: s(kind),
        id: s(b"id"),
        body: HostBuf {
            ptr: body_buf.ptr,
            cap,
        },
    };
    let (items, items_cap) = host(&mut blobs);
    let list = |selector: u32, items_cap: usize| ListPlaneRecordsIn {
        head: in_head::<ListPlaneRecordsIn>(slot::LIST_PLANE_RECORDS),
        kind: s(b"k"),
        selector,
        _reserved: 0,
        parent: s(b"p-1"),
        out: HostBlobs {
            items,
            items_cap,
            bytes: list_buf,
        },
    };
    let token = |op: u32| TokenIn {
        head: in_head::<TokenIn>(op),
        kind: s(b"k"),
        token: s(b"t"),
        expires_at: 10,
        now: 1,
    };
    let row = PlaneRecordRow {
        kind: s(b"task"),
        id: s(b"t-1"),
        parent: s(b"p-1"),
        seq: 1,
        ts: 2,
        disposition: DISPOSITION_ACTIVE,
        _reserved: 0,
        body: octets(b"a row"),
    };
    let (rows, rows_cap) = host(&mut sessions);
    let (ents, ents_cap) = host(&mut entries);

    let got = [
        measure(
            "get_plane_record READY",
            t.get_plane_record,
            inst,
            get(b"k", 64),
            bytes_out,
            |o| o.head.error,
        ),
        measure(
            "get_plane_record short FAILED",
            t.get_plane_record,
            inst,
            get(b"k", 1),
            bytes_out,
            |o| o.head.error,
        ),
        measure(
            "get_plane_record store FAILED",
            t.get_plane_record,
            inst,
            get(DOWN.as_bytes(), 64),
            bytes_out,
            |o| o.head.error,
        ),
        measure(
            "get_plane_record not-UTF-8 REFUSED",
            t.get_plane_record,
            inst,
            get(b"\xff", 64),
            bytes_out,
            |o| o.head.error,
        ),
        measure(
            "list_plane_records READY",
            t.list_plane_records,
            inst,
            list(SELECT_ALL, items_cap),
            list_out,
            |o| o.head.error,
        ),
        measure(
            "list_plane_records short FAILED",
            t.list_plane_records,
            inst,
            list(SELECT_ALL, 1),
            list_out,
            |o| o.head.error,
        ),
        measure(
            "list_plane_records selector REFUSED",
            t.list_plane_records,
            inst,
            list(9, items_cap),
            list_out,
            |o| o.head.error,
        ),
        measure(
            "delete_plane_record READY",
            t.delete_plane_record,
            inst,
            KindIdIn {
                head: in_head::<KindIdIn>(slot::DELETE_PLANE_RECORD),
                kind: s(b"k"),
                id: s(b"id"),
            },
            head_out,
            |o| o.error,
        ),
        measure(
            "delete_plane_record store FAILED",
            t.delete_plane_record,
            inst,
            KindIdIn {
                head: in_head::<KindIdIn>(slot::DELETE_PLANE_RECORD),
                kind: s(DOWN.as_bytes()),
                id: s(b"id"),
            },
            head_out,
            |o| o.error,
        ),
        measure(
            "redeem_plane_token READY",
            t.redeem_plane_token,
            inst,
            token(slot::REDEEM_PLANE_TOKEN),
            verdict_out,
            |o| o.head.error,
        ),
        measure(
            "plane_token_live READY",
            t.plane_token_live,
            inst,
            token(slot::PLANE_TOKEN_LIVE),
            verdict_out,
            |o| o.head.error,
        ),
        measure(
            "sessions_for READY",
            t.sessions_for,
            inst,
            SessionsForIn {
                head: in_head::<SessionsForIn>(slot::SESSIONS_FOR),
                principal: s(b"p"),
                out: HostSessions {
                    items: rows,
                    items_cap: rows_cap,
                    bytes: session_buf,
                },
            },
            list_out,
            |o| o.head.error,
        ),
        measure(
            "record_get READY",
            t.record_get,
            inst,
            RecordGetIn {
                head: in_head::<RecordGetIn>(slot::RECORD_GET),
                schema: s(b"sc"),
                key: octets(b"key"),
                value: body_buf,
            },
            bytes_out,
            |o| o.head.error,
        ),
        measure(
            "record_get store FAILED",
            t.record_get,
            inst,
            RecordGetIn {
                head: in_head::<RecordGetIn>(slot::RECORD_GET),
                schema: s(DOWN.as_bytes()),
                key: octets(b"key"),
                value: body_buf,
            },
            bytes_out,
            |o| o.head.error,
        ),
        measure(
            "record_scan READY",
            t.record_scan,
            inst,
            RecordScanIn {
                head: in_head::<RecordScanIn>(slot::RECORD_SCAN),
                schema: s(b"sc"),
                prefix: octets(b"k"),
                limit: 10,
                _reserved: 0,
                out: HostRecords {
                    items: ents,
                    items_cap: ents_cap,
                    bytes: entry_buf,
                },
            },
            list_out,
            |o| o.head.error,
        ),
        measure(
            "record_put over-ceiling REFUSED",
            t.record_put,
            inst,
            RecordPutIn {
                head: in_head::<RecordPutIn>(slot::RECORD_PUT),
                schema: s(b"sc"),
                key: octets(b"key"),
                value: octets(over_ceiling),
            },
            head_out,
            |o| o.error,
        ),
        measure(
            "upsert_plane_record READY",
            t.upsert_plane_record,
            inst,
            UpsertPlaneRecordIn {
                head: in_head::<UpsertPlaneRecordIn>(slot::UPSERT_PLANE_RECORD),
                record: row,
            },
            head_out,
            |o| o.error,
        ),
        measure(
            "append_plane_record READY",
            t.append_plane_record,
            inst,
            AppendPlaneRecordIn {
                head: in_head::<AppendPlaneRecordIn>(slot::APPEND_PLANE_RECORD),
                op_id: OpId::from_parts(1, 2),
                record: row,
            },
            head_out,
            |o| o.error,
        ),
        measure(
            "list_plane_records SELECT_PARENT READY",
            t.list_plane_records,
            inst,
            list(SELECT_PARENT, items_cap),
            list_out,
            |o| o.head.error,
        ),
        measure(
            "record_put READY",
            t.record_put,
            inst,
            RecordPutIn {
                head: in_head::<RecordPutIn>(slot::RECORD_PUT),
                schema: s(b"sc"),
                key: octets(b"key"),
                value: octets(b"a value"),
            },
            head_out,
            |o| o.error,
        ),
    ];

    // The answers are the door's, unchanged: outcome and every error text byte for byte.
    let want: [(Outcome, &str); 20] = [
        (Outcome::Ready, ""),
        (Outcome::Failed, ""),
        (Outcome::Failed, DOWN_TEXT),
        (
            Outcome::Refused,
            "a string is not UTF-8: invalid utf-8 sequence of 1 bytes from index 0",
        ),
        (Outcome::Ready, ""),
        (Outcome::Failed, ""),
        (Outcome::Refused, "selector 9 is not a plane selector"),
        (Outcome::Ready, ""),
        (Outcome::Failed, DOWN_TEXT),
        (Outcome::Ready, ""),
        (Outcome::Ready, ""),
        (Outcome::Ready, ""),
        (Outcome::Ready, ""),
        (Outcome::Failed, DOWN_TEXT),
        (Outcome::Ready, ""),
        (Outcome::Refused, "a record of 513 bytes is over the ceiling"),
        (Outcome::Ready, ""),
        (Outcome::Ready, ""),
        (Outcome::Ready, ""),
        (Outcome::Ready, ""),
    ];
    for (m, (outcome, error)) in got.iter().zip(want) {
        assert_eq!((m.outcome, m.error.as_str()), (outcome, error), "{}", m.case);
    }
    // The rows landed where they say, in the host's buffers.
    assert_eq!(&body[..b"a value".len()], b"a value");
    assert_eq!(&list_bytes[..b"onetwothree".len()], b"onetwothree");
    assert_eq!(&session_bytes[..b"node-anode-b".len()], b"node-anode-b");
    assert_eq!(&entry_bytes[..b"k1vk2v".len()], b"k1vk2v");

    let allocating: Vec<String> = got
        .iter()
        .filter(|m| m.allocations != 0)
        .map(|m| format!("{}: {} allocation(s)", m.case, m.allocations))
        .collect();
    assert!(
        allocating.is_empty(),
        "the store door allocated on the request path:\n  {}",
        allocating.join("\n  ")
    );
}
