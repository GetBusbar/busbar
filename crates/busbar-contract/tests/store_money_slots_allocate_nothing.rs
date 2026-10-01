// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE SDK'S MONEY SLOTS ALLOCATE NOTHING (the design's plugin memory rule: "no allocation
//! and no blocking on the hot path"). `reserve` and `slice_release` are request-path ops: the door
//! reads the cells and items in place in the host's `in` and writes the grants and amounts
//! straight into the host's arrays. A store that itself allocates nothing therefore costs the
//! request path nothing in the SDK either.
//!
//! Its own test binary, because proving this needs a counting global allocator, and ONE test,
//! because that counter is global: a second test on another thread would count into it. Each money
//! call is measured against the same trampoline crossing to a slot whose store does nothing
//! (`session_remove`), so only what the money slot's body allocates is counted.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::abi::mechanism::call::{AbiStr, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::slot_at;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, Grant, OpRefused, OpResult, ReserveRefused, StoreSlots, Tail,
};
use busbar_contract::abi::store::{
    CellGrant, OpId, Ops, ReleaseItem, ReserveIn, ReserveOut, SliceReleaseIn, SliceReleaseOut,
    U64In, UnitCell, DIM_REQUESTS,
};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, PlaneRecordRef, RecordStore, RecordStoreResult,
    UsageDelta, UsageLedger, VirtualKey,
};

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting the allocations that go through it.
struct Counting;

// SAFETY: every call forwards to `System` with the caller's own arguments.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// A store whose money slots allocate nothing: every cell is granted whole, every unspent amount
/// is taken back. Nothing else is called.
struct Flat;

impl RecordStore for Flat {
    fn put_key(&self, _: &VirtualKey) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _: &str) -> RecordStoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_usage(&self, _: &str, _: u64) -> RecordStoreResult<UsageLedger> {
        Ok(UsageLedger::default())
    }
    fn put_usage(&self, _: &str, _: u64, _: &UsageLedger) -> RecordStoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _: &MeteringDelta) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        Ok(Vec::new())
    }
}

impl StoreSlots for Flat {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: false,
    };

    fn open(_: &[u8]) -> Result<Self, String> {
        Ok(Self)
    }
    fn add_usage_op(&self, _: OpId, _: &str, _: u64, _: &UsageDelta) -> OpResult<()> {
        Ok(())
    }
    fn add_metering_op(&self, _: OpId, _: &MeteringDelta) -> OpResult<()> {
        Ok(())
    }
    fn append_audit_op(&self, _: OpId, _: &AuditRecord) -> OpResult<()> {
        Ok(())
    }
    fn append_plane_record_op(&self, _: OpId, _: PlaneRecordRef<'_>) -> OpResult<()> {
        Ok(())
    }
    fn append_batch(&self, _: OpId, _: &str, _: &[RecordBytes]) -> OpResult<Head> {
        Err(OpRefused::Conflict)
    }
    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        Ok(Vec::new())
    }
    fn session_put(&self, _: u64, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn session_remove(&self, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn sessions_for(&self, _: &str) -> Result<Vec<(u64, String)>, String> {
        Ok(Vec::new())
    }
    fn record_put(&self, _: &str, _: &[u8], _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn record_get(&self, _: &str, _: &[u8]) -> Result<Option<RecordBytes>, String> {
        Ok(None)
    }
    fn record_scan(
        &self,
        _: &str,
        _: &[u8],
        _: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        Ok(Vec::new())
    }
    fn reserve<'c>(
        &self,
        _: OpId,
        _: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        grants.extend(cells.enumerate().map(|(n, c)| Grant {
            slice_id: n as u64 + 1,
            granted: c.amount,
            valid_until_ms: u64::MAX,
        }));
        Ok(())
    }
    fn slice_release(
        &self,
        _: OpId,
        _: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        released.extend(items.map(|(_, unspent)| unspent));
        Ok(())
    }
    fn add_usage_batch(&self, _: OpId, _: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        Ok(())
    }
    fn add_metering_batch(&self, _: OpId, _: &[MeteringDelta]) -> OpResult<()> {
        Ok(())
    }
    fn append_audit_batch(&self, _: OpId, _: &[AuditRecord]) -> OpResult<()> {
        Ok(())
    }
    fn window_caps(&self, _: OpId, _: &[Cap<'_>]) -> Result<(), CapsRefused> {
        Ok(())
    }
}

mod plugin {
    busbar_contract::store_door!(super::Flat, "flat", "0", 64);
}

fn table() -> &'static Ops {
    // SAFETY: the macro's `'static` door, whose table is the store kind's `Ops`.
    unsafe { &*(*plugin::door()).ops.cast::<Ops>() }
}

fn zeroed<T>() -> T {
    // SAFETY: every `in`/`out` here is plain data; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

/// A zeroed `in` of type `T` whose head names slot `op`; `head` is its `InHead` field.
macro_rules! input {
    ($t:ty, $op:expr) => {{
        let mut i: $t = zeroed();
        i.head.size = size_of::<$t>() as u32;
        i.head.op = $op;
        i
    }};
}

/// A zeroed `out` of type `T` with its head sized.
macro_rules! output {
    ($t:ty) => {{
        let mut o: $t = zeroed();
        o.head.size = size_of::<$t>() as u32;
        o
    }};
}

/// A zeroed bare `OutHead`, sized.
fn out_head() -> OutHead {
    let mut o: OutHead = zeroed();
    o.size = size_of::<OutHead>() as u32;
    o
}

fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    op.expect("every slot is filled")(
        instance,
        ptr::from_ref(input).cast(),
        ptr::from_mut(out).cast(),
    )
    .outcome()
}

/// Allocations `f` made.
fn counted(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    f();
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

const BUCKET: &str = "bucket";

#[test]
fn reserve_and_slice_release_through_the_sdk_allocate_nothing() {
    let open_in = input!(OpenIn, slot::OPEN);
    let mut open_out = output!(OpenOut);
    assert_eq!(
        call(table().head.open, ptr::null_mut(), &open_in, &mut open_out),
        Outcome::Ready
    );
    let instance = open_out.instance;

    let cells = [UnitCell {
        bucket: AbiStr {
            ptr: BUCKET.as_ptr(),
            len: BUCKET.len(),
        },
        dimension: DIM_REQUESTS,
        amount: 3,
        window_start: 1_000,
        ..zeroed()
    }; 4];
    let mut grants = [CellGrant {
        slice_id: 0,
        granted: 0,
        valid_until_ms: 0,
    }; 4];
    let items = [ReleaseItem {
        slice_id: 1,
        unspent: 2,
    }; 4];
    let mut released = [0_u64; 4];

    let reserve_op = slot_at(offset_of!(Ops, reserve));
    let release_op = slot_at(offset_of!(Ops, slice_release));
    let remove_op = slot_at(offset_of!(Ops, session_remove));

    let reserve = |grants: &mut [CellGrant; 4]| {
        let mut i = input!(ReserveIn, reserve_op);
        i.op_id = OpId::from_parts(1, 1);
        i.cells = cells.as_ptr();
        i.cells_len = cells.len();
        i.grants = grants.as_mut_ptr();
        i.grants_cap = grants.len();
        let mut o = output!(ReserveOut);
        let outcome = call(table().reserve, instance, &i, &mut o);
        (outcome, o.grants_len)
    };
    let release = |released: &mut [u64; 4]| {
        let mut i = input!(SliceReleaseIn, release_op);
        i.op_id = OpId::from_parts(1, 2);
        i.items = items.as_ptr();
        i.items_len = items.len();
        i.released = released.as_mut_ptr();
        i.released_cap = released.len();
        let mut o = output!(SliceReleaseOut);
        let outcome = call(table().slice_release, instance, &i, &mut o);
        (outcome, o.released_len)
    };
    let crossing = || {
        let i = input!(U64In, remove_op);
        let mut o = out_head();
        call(table().session_remove, instance, &i, &mut o)
    };

    // The first crossing on this thread builds its call capture; measure after it.
    assert_eq!(crossing(), Outcome::Ready);
    assert_eq!(reserve(&mut grants), (Outcome::Ready, 4));
    assert_eq!(release(&mut released), (Outcome::Ready, 4));

    let floor = counted(|| assert_eq!(crossing(), Outcome::Ready));
    let mut answered = (Outcome::Fault, 0);
    let reserve_cost = counted(|| answered = reserve(&mut grants));
    assert_eq!(answered, (Outcome::Ready, 4));
    assert!(grants.iter().all(|g| g.granted == 3));
    let release_cost = counted(|| answered = release(&mut released));
    assert_eq!(answered, (Outcome::Ready, 4));
    assert_eq!(released, [2; 4]);

    assert_eq!(
        reserve_cost, floor,
        "reserve allocated {reserve_cost} times through the SDK, a bare crossing {floor}"
    );
    assert_eq!(
        release_cost, floor,
        "slice_release allocated {release_cost} times through the SDK, a bare crossing {floor}"
    );
}
