// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO, COMPILED-IN LEG: a tiny lifecycle-only plugin built with `plugin_door!` in this
//! crate, called through its table exactly as a dispatcher would (the dropped-in leg is
//! `tests/sdk_door_cdylib.rs`, over the same plugin as a `cdylib`).

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use crate::abi::mechanism::call::{
    Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT, FLAG_RESUME,
};
use crate::abi::mechanism::door::{Door, DoorFn};
use crate::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn,
    TickIn, TickOut, ValidateIn, LIFECYCLE_SLOTS,
};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

use super::{KindOps, KindSlot, Slot};

/// The lifecycle-only table: the shared head and no kind op.
#[repr(C)]
#[derive(Clone, Copy)]
struct LifecycleOnly {
    head: OpsHead,
}

// SAFETY: `#[repr(C)]`, `head: OpsHead` first, nothing after it.
unsafe impl KindOps for LifecycleOnly {
    const KIND: KindCode = KindCode::Secret;
    type Lifecycle = crate::abi::sdk::door::Lifecycle;
}

/// `validate` with this settings length panics.
const PANIC_LEN: usize = 13;
/// `open`, and the second kind op, panic at this generation.
const PANIC_GEN: u64 = 0xDEAD_0001;
/// `tick` at this `now_ns` answers PENDING.
const PEND_AT: u64 = 42;

struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, input: &ValidateIn, _: &mut OutHead) -> Outcome {
        match input.settings.len {
            PANIC_LEN => panic!("a slot body panics"),
            _ => Outcome::Ready,
        }
    }
}

struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, input: &OpenIn, out: &mut OpenOut) -> Outcome {
        assert_ne!(input.generation, PANIC_GEN, "open panics");
        out.instance = input.generation as usize as *mut c_void;
        Outcome::Ready
    }
}

struct Refresh;
impl Slot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &RefreshIn, _: &mut OutHead) -> Outcome {
        Outcome::Refused
    }
}

struct Retire;
impl Slot for Retire {
    type In = GenIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &GenIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Tick;
impl Slot for Tick {
    type In = TickIn;
    type Out = TickOut;
    fn call(_: *mut c_void, input: &TickIn, out: &mut TickOut) -> Outcome {
        out.next_tick_ns = input.now_ns + 1;
        if input.now_ns == PEND_AT {
            Outcome::Pending
        } else {
            Outcome::Ready
        }
    }
}

struct Drive;
impl Slot for Drive {
    type In = DriveIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &DriveIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(_: *mut c_void, input: &CancelIn, out: &mut CancelOut) -> Outcome {
        out.disposition = input.ticket.slot + 6;
        Outcome::Failed
    }
}

struct Release;
impl Slot for Release {
    type In = ReleaseIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &ReleaseIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Close;
impl Slot for Close {
    type In = InHead;
    type Out = OutHead;
    fn call(instance: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        if instance.is_null() {
            Outcome::Failed
        } else {
            Outcome::Ready
        }
    }
}

mod plugin {
    use super::*;

    crate::plugin_door! {
        ops: super::LifecycleOnly,
        statement: crate::abi::mechanism::door::Statement {
            max_inflight: 8,
            ..crate::abi::sdk::door::statement("sdk-door-test", "0.0.1", 0)
        },
        lifecycle: {
            validate: Validate,
            open: Open,
            refresh: Refresh,
            retire: Retire,
            tick: Tick,
            drive: Drive,
            cancel: Cancel,
            release: Release,
            close: Close,
        },
    }
}

fn the_door() -> &'static Door {
    // SAFETY: the macro's door is a `'static` const.
    unsafe { &*plugin::door() }
}

fn table() -> &'static LifecycleOnly {
    // SAFETY: the door's ops point at the macro's `'static` `LifecycleOnly`.
    unsafe { &*the_door().ops.cast::<LifecycleOnly>() }
}

fn in_head<T>(op: u32, ticket: Ticket) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx {
            ptr: ptr::null_mut(),
        },
        ticket,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: absent(),
    }
}

fn absent() -> Blob {
    Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    }
}

/// The host's pre-fill: `outcome = FAULT`, sentinels everywhere else, `size` as given.
fn prefilled_head(size: usize) -> OutHead {
    OutHead {
        size: size as u32,
        outcome: RawOutcome::of(Outcome::Fault),
        _reserved: [0; 3],
        wake_at_ns: 0xAAAA,
        lease: 0xBBBB,
        error: super::abi_str(""),
        envelope: crate::abi::mechanism::call::Envelope {
            metrics: ptr::null(),
            metrics_len: 0,
            diags: ptr::null(),
            diags_len: 0,
        },
        extensions: absent(),
    }
}

fn call<I, O>(op: Option<Op>, input: &I, out: &mut O) -> Outcome {
    let op = op.expect("the macro fills every slot");
    op(
        ptr::null_mut(),
        ptr::from_ref(input).cast(),
        ptr::from_mut(out).cast(),
    )
    .outcome()
}

fn validate_in(len: usize, op: u32) -> ValidateIn {
    ValidateIn {
        head: in_head::<ValidateIn>(op, Ticket::NONE),
        settings: Blob {
            ptr: ptr::null(),
            len,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        err_buf: ptr::null_mut(),
        err_cap: 0,
    }
}

#[test]
fn the_door_states_magic_versions_kind_statement_and_table() {
    let d = the_door();
    assert_eq!(d.magic, DOOR_MAGIC);
    assert_eq!(d.mechanism_version, MECHANISM_VERSION);
    assert_eq!(d.size as usize, size_of::<Door>());
    assert_eq!(d.kind, KindCode::Secret as u32);
    assert_eq!(d.kind_abi, crate::abi::secret::ABI_VERSION);

    // SAFETY: the macro's Statement is a `'static` const.
    let s = unsafe { &*d.statement };
    assert_eq!(
        s.size as usize,
        size_of::<crate::abi::mechanism::door::Statement>()
    );
    assert_eq!((s.kind, s.kind_abi), (d.kind, d.kind_abi));
    assert_eq!(s.max_inflight, 8);
    // SAFETY: `name` borrows the `'static` literal the Statement was built from.
    let name = unsafe { std::slice::from_raw_parts(s.name.ptr, s.name.len) };
    assert_eq!(name, b"sdk-door-test");

    let head = &table().head;
    assert_eq!(head.size as usize, size_of::<LifecycleOnly>());
    assert_eq!(head.slots, LIFECYCLE_SLOTS);
    assert_eq!(super::slot_count::<LifecycleOnly>(), LIFECYCLE_SLOTS);
    for (i, s) in [
        head.validate,
        head.open,
        head.refresh,
        head.retire,
        head.tick,
        head.drive,
        head.cancel,
        head.release,
        head.close,
    ]
    .iter()
    .enumerate()
    {
        assert!(
            s.is_some(),
            "lifecycle slot {i} is NULL (a NULL slot refuses the load)"
        );
    }
}

#[test]
fn a_compiled_in_row_holds_the_same_door_fn_and_reaches_the_same_static_door() {
    // Rust promises no single address per `const`, so the row's door is compared by contents.
    let row: DoorFn = plugin::door;
    // SAFETY: both are the macro's `'static` door.
    let (a, b) = unsafe { (&*row(), &*plugin::door()) };
    assert_eq!(
        (a.magic, a.mechanism_version, a.size, a.kind, a.kind_abi),
        (b.magic, b.mechanism_version, b.size, b.kind, b.kind_abi)
    );
    // SAFETY: as above; the tables are the macro's `'static` const.
    let (ta, tb) = unsafe { (&*a.ops, &*b.ops) };
    assert_eq!((ta.size, ta.slots), (tb.size, tb.slots));
    assert_eq!(
        ta.validate.map(|f| f as usize),
        tb.validate.map(|f| f as usize)
    );
}

#[test]
fn a_panicking_slot_answers_fault_and_writes_only_the_outcome() {
    let mut out = prefilled_head(size_of::<OutHead>());
    out.outcome = RawOutcome::of(Outcome::Ready); // prove the trampoline writes FAULT itself
    let got = call(
        table().head.validate,
        &validate_in(PANIC_LEN, slot::VALIDATE),
        &mut out,
    );
    assert_eq!(got, Outcome::Fault);
    assert_eq!(out.outcome.outcome(), Outcome::Fault);
    assert_eq!(
        (out.wake_at_ns, out.lease),
        (0xAAAA, 0xBBBB),
        "a panic wrote the body's out"
    );

    // And the plugin still answers afterwards.
    let mut out = prefilled_head(size_of::<OutHead>());
    let got = call(
        table().head.validate,
        &validate_in(0, slot::VALIDATE),
        &mut out,
    );
    assert_eq!(got, Outcome::Ready);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);
}

#[test]
fn the_returned_outcome_is_mirrored_into_out_head() {
    let input = CancelIn {
        head: in_head::<CancelIn>(slot::CANCEL, Ticket::NONE),
        ticket: Ticket {
            slot: 1,
            generation: 1,
        },
    };
    let mut out = CancelOut {
        head: prefilled_head(size_of::<CancelOut>()),
        disposition: 0,
        _reserved: 0,
    };
    let got = call(table().head.cancel, &input, &mut out);
    assert_eq!(got, Outcome::Failed);
    assert_eq!(out.head.outcome.outcome(), Outcome::Failed);
    assert_eq!(out.disposition, 7);
    assert_eq!(out.head.size as usize, size_of::<CancelOut>());

    let input = RefreshIn {
        head: in_head::<RefreshIn>(slot::REFRESH, Ticket::NONE),
        generation: 2,
        settings: absent(),
        secrets: ptr::null(),
        secrets_len: 0,
    };
    let mut out = prefilled_head(size_of::<OutHead>());
    assert_eq!(
        call(table().head.refresh, &input, &mut out),
        Outcome::Refused
    );
    assert_eq!(out.outcome.outcome(), Outcome::Refused);

    let input = OpenIn {
        head: in_head::<OpenIn>(slot::OPEN, Ticket::NONE),
        host: ptr::null(),
        settings: absent(),
        secrets: ptr::null(),
        secrets_len: 0,
        generation: 0x55,
        err_buf: ptr::null_mut(),
        err_cap: 0,
    };
    let mut out = OpenOut {
        head: prefilled_head(size_of::<OpenOut>()),
        instance: ptr::null_mut(),
        err_len: 0,
    };
    assert_eq!(call(table().head.open, &input, &mut out), Outcome::Ready);
    assert_eq!(out.instance as usize, 0x55);
}

/// A host `out` followed by bytes the plugin must never touch.
#[repr(C)]
struct Fenced<T> {
    out: T,
    fence: [u8; 32],
}

#[test]
fn the_plugin_writes_at_most_min_of_host_out_size_and_its_own() {
    // The host says its `out` is only an `OutHead`: `next_tick_ns` (past it) must stay untouched.
    let mut host = Fenced {
        out: TickOut {
            head: prefilled_head(size_of::<OutHead>()),
            next_tick_ns: 0xDEAD,
        },
        fence: [0xEE; 32],
    };
    let input = TickIn {
        head: in_head::<TickIn>(slot::TICK, Ticket::NONE),
        now_ns: 9,
    };
    assert_eq!(
        call(table().head.tick, &input, &mut host.out),
        Outcome::Ready
    );
    assert_eq!(host.out.head.outcome.outcome(), Outcome::Ready);
    // The plugin writes back ITS OWN size (the host clamps); the bytes past the host's stay put.
    assert_eq!(host.out.head.size as usize, size_of::<TickOut>());
    assert_eq!(
        host.out.next_tick_ns, 0xDEAD,
        "wrote past the host's out.size"
    );
    assert_eq!(host.fence, [0xEE; 32]);

    // A full-size host `out` gets the whole answer and the plugin's own size back.
    let mut host = Fenced {
        out: TickOut {
            head: prefilled_head(size_of::<TickOut>()),
            next_tick_ns: 0,
        },
        fence: [0xEE; 32],
    };
    assert_eq!(
        call(table().head.tick, &input, &mut host.out),
        Outcome::Ready
    );
    assert_eq!(host.out.next_tick_ns, 10);
    assert_eq!(host.out.head.size as usize, size_of::<TickOut>());
    assert_eq!(host.fence, [0xEE; 32]);

    // A host `out` larger than the plugin's own: only the plugin's own size is written back.
    let mut host = Fenced {
        out: TickOut {
            head: prefilled_head(size_of::<TickOut>() + 32),
            next_tick_ns: 0,
        },
        fence: [0xEE; 32],
    };
    assert_eq!(
        call(table().head.tick, &input, &mut host.out),
        Outcome::Ready
    );
    assert_eq!(host.out.head.size as usize, size_of::<TickOut>());
    assert_eq!(host.fence, [0xEE; 32]);
}

#[test]
fn an_out_too_small_for_its_head_is_fault_with_nothing_written() {
    let mut bytes = [0x5Au8; size_of::<OutHead>()];
    bytes[..4].copy_from_slice(&((size_of::<OutHead>() - 1) as u32).to_ne_bytes());
    let before = bytes;
    let op = table().head.validate.unwrap();
    let got = op(
        ptr::null_mut(),
        ptr::from_ref(&validate_in(0, slot::VALIDATE)).cast(),
        bytes.as_mut_ptr().cast(),
    );
    assert_eq!(got.outcome(), Outcome::Fault);
    assert_eq!(bytes, before);

    // NULL `out`.
    let got = op(
        ptr::null_mut(),
        ptr::from_ref(&validate_in(0, slot::VALIDATE)).cast(),
        ptr::null_mut(),
    );
    assert_eq!(got.outcome(), Outcome::Fault);
}

#[test]
fn a_bad_in_head_is_fault() {
    let op = table().head.validate;
    // NULL `in`.
    let mut out = prefilled_head(size_of::<OutHead>());
    out.outcome = RawOutcome::of(Outcome::Ready);
    let raw = op.unwrap()(ptr::null_mut(), ptr::null(), ptr::from_mut(&mut out).cast());
    assert_eq!(raw.outcome(), Outcome::Fault);
    assert_eq!(out.outcome.outcome(), Outcome::Fault);

    // An `in.op` naming another slot.
    let mut out = prefilled_head(size_of::<OutHead>());
    assert_eq!(
        call(op, &validate_in(0, slot::OPEN), &mut out),
        Outcome::Fault
    );
    assert_eq!(out.outcome.outcome(), Outcome::Fault);

    // An `in` shorter than its head.
    let mut input = validate_in(0, slot::VALIDATE);
    input.head.size = size_of::<InHead>() as u32 - 1;
    let mut out = prefilled_head(size_of::<OutHead>());
    out.outcome = RawOutcome::of(Outcome::Ready);
    assert_eq!(call(op, &input, &mut out), Outcome::Fault);
    assert_eq!(out.outcome.outcome(), Outcome::Fault);
    assert_eq!(
        (out.size as usize, out.wake_at_ns, out.lease),
        (size_of::<OutHead>(), 0xAAAA, 0xBBBB),
        "a refused `in` wrote more than the outcome"
    );
}

#[test]
fn an_absent_in_tail_reads_as_zero() {
    // The host's `in` is only a head: `settings.len` (garbage past it) must read as 0.
    let mut input = validate_in(PANIC_LEN, slot::VALIDATE);
    input.head.size = size_of::<InHead>() as u32;
    let mut out = prefilled_head(size_of::<OutHead>());
    assert_eq!(
        call(table().head.validate, &input, &mut out),
        Outcome::Ready
    );
}

#[test]
fn pending_is_mirrored_on_a_ticket_and_fault_on_ticket_none() {
    let mut input = TickIn {
        head: in_head::<TickIn>(slot::TICK, Ticket::NONE),
        now_ns: PEND_AT,
    };
    let mut out = TickOut {
        head: prefilled_head(size_of::<TickOut>()),
        next_tick_ns: 0,
    };
    assert_eq!(call(table().head.tick, &input, &mut out), Outcome::Fault);
    assert_eq!(out.head.outcome.outcome(), Outcome::Fault);

    input.head.ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    input.head.flags = FLAG_RESUME;
    let mut out = TickOut {
        head: prefilled_head(size_of::<TickOut>()),
        next_tick_ns: 0,
    };
    assert_eq!(call(table().head.tick, &input, &mut out), Outcome::Pending);
    assert_eq!(out.head.outcome.outcome(), Outcome::Pending);
}

#[test]
fn every_slot_is_the_trampoline_at_its_own_index() {
    // Each lifecycle slot answers only an `in.op` equal to its own index.
    let head = &table().head;
    let slots = [
        (head.drive, slot::DRIVE),
        (head.release, slot::RELEASE),
        (head.retire, slot::RETIRE),
    ];
    for (op, index) in slots {
        let input = ReleaseIn {
            head: in_head::<InHead>(index, Ticket::NONE),
            lease: 0,
        };
        let mut out = prefilled_head(size_of::<OutHead>());
        assert_eq!(call(op, &input, &mut out), Outcome::Ready, "slot {index}");
        let wrong = ReleaseIn {
            head: in_head::<InHead>(index + 1, Ticket::NONE),
            lease: 0,
        };
        let mut out = prefilled_head(size_of::<OutHead>());
        assert_eq!(call(op, &wrong, &mut out), Outcome::Fault, "slot {index}");
    }
    // `close` forwards the instance pointer it was called on.
    let input = in_head::<InHead>(slot::CLOSE, Ticket::NONE);
    let mut out = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(head.close, &input, &mut out), Outcome::Failed);
    let mut out = prefilled_head(size_of::<OutHead>());
    let raw = head.close.unwrap()(
        ptr::NonNull::<u8>::dangling().as_ptr().cast(),
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(raw.outcome(), Outcome::Ready);
}

#[test]
fn kind_op_indices_follow_the_slot_layout() {
    // The first slot after the lifecycle is LIFECYCLE_SLOTS, and so on, contiguous.
    let first = size_of::<OpsHead>();
    assert_eq!(super::slot_at(first), LIFECYCLE_SLOTS);
    assert_eq!(
        super::slot_at(first + size_of::<Option<Op>>()),
        LIFECYCLE_SLOTS + 1
    );
    assert_eq!(
        super::slot_at(std::mem::offset_of!(OpsHead, close)),
        slot::CLOSE
    );
    assert_eq!(
        super::slot_at(std::mem::offset_of!(OpsHead, validate)),
        slot::VALIDATE
    );
}

/// A table WITH kind ops: the head, then two kind slots.
#[repr(C)]
#[derive(Clone, Copy)]
struct TwoKindOps {
    head: OpsHead,
    first: Option<Op>,
    second: Option<Op>,
}

// SAFETY: `#[repr(C)]`, `head: OpsHead` first, then only `Option<Op>` slots.
unsafe impl KindOps for TwoKindOps {
    const KIND: KindCode = KindCode::Store;
    type Lifecycle = crate::abi::sdk::door::Lifecycle;
}

// SAFETY: this test kind states these structs for its two ops.
unsafe impl KindSlot<{ LIFECYCLE_SLOTS }> for TwoKindOps {
    type In = InHead;
    type Out = OutHead;
}
// SAFETY: as above.
unsafe impl KindSlot<{ LIFECYCLE_SLOTS + 1 }> for TwoKindOps {
    type In = GenIn;
    type Out = TickOut;
}

struct First;
impl Slot for First {
    type In = InHead;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Second;
impl Slot for Second {
    type In = GenIn;
    type Out = TickOut;
    fn call(_: *mut c_void, input: &GenIn, out: &mut TickOut) -> Outcome {
        assert_ne!(input.generation, PANIC_GEN, "a kind op panics");
        out.next_tick_ns = input.generation;
        Outcome::Refused
    }
}

mod kind_plugin {
    use super::*;

    crate::plugin_door! {
        ops: super::TwoKindOps,
        statement: crate::abi::sdk::door::statement("sdk-door-kind-ops", "0.0.1", 1),
        lifecycle: {
            validate: Validate,
            open: Open,
            refresh: Refresh,
            retire: Retire,
            tick: Tick,
            drive: Drive,
            cancel: Cancel,
            release: Release,
            close: Close,
        },
        kind_ops: { second: Second, first: First },
    }
}

#[test]
fn kind_ops_sit_at_lifecycle_slots_plus_k_whatever_order_they_are_named_in() {
    // SAFETY: the macro's `'static` door and table.
    let d = unsafe { &*kind_plugin::door() };
    let t = unsafe { &*d.ops.cast::<TwoKindOps>() };
    assert_eq!(d.kind, KindCode::Store as u32);
    assert_eq!(d.kind_abi, crate::abi::store::ABI_VERSION);
    assert_eq!(t.head.size as usize, size_of::<TwoKindOps>());
    assert_eq!(t.head.slots, LIFECYCLE_SLOTS + 2);
    // Kind op 0 (`InHead` -> `OutHead`) answers only its own index.
    let input = in_head::<InHead>(LIFECYCLE_SLOTS, Ticket::NONE);
    let mut out = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.first, &input, &mut out), Outcome::Ready);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);
    let wrong = in_head::<InHead>(LIFECYCLE_SLOTS + 1, Ticket::NONE);
    let mut out = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.first, &wrong, &mut out), Outcome::Fault);

    // Kind op 1 (`GenIn` -> `TickOut`) answers its own index, with its own structs.
    let gen_in = |op, generation| GenIn {
        head: in_head::<GenIn>(op, Ticket::NONE),
        generation,
    };
    let tick_out = || TickOut {
        head: prefilled_head(size_of::<TickOut>()),
        next_tick_ns: 0,
    };
    let mut out = tick_out();
    let got = call(t.second, &gen_in(LIFECYCLE_SLOTS + 1, 77), &mut out);
    assert_eq!(got, Outcome::Refused);
    assert_eq!(out.head.outcome.outcome(), Outcome::Refused);
    assert_eq!(out.next_tick_ns, 77);
    let mut out = tick_out();
    let got = call(t.second, &gen_in(LIFECYCLE_SLOTS, 77), &mut out);
    assert_eq!(got, Outcome::Fault);
}

#[test]
fn a_panicking_kind_op_answers_fault_and_writes_only_the_outcome() {
    // SAFETY: the macro's `'static` door and table.
    let t = unsafe { &*(*kind_plugin::door()).ops.cast::<TwoKindOps>() };
    let input = GenIn {
        head: in_head::<GenIn>(LIFECYCLE_SLOTS + 1, Ticket::NONE),
        generation: PANIC_GEN,
    };
    let mut out = TickOut {
        head: prefilled_head(size_of::<TickOut>()),
        next_tick_ns: 0x5EED,
    };
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    assert_eq!(call(t.second, &input, &mut out), Outcome::Fault);
    assert_eq!(out.head.outcome.outcome(), Outcome::Fault);
    assert_eq!(
        (out.next_tick_ns, out.head.wake_at_ns, out.head.lease),
        (0x5EED, 0xAAAA, 0xBBBB),
        "a panicking kind op wrote its out"
    );
}

#[test]
fn a_panicking_open_answers_fault_and_hands_back_no_instance() {
    let input = OpenIn {
        head: in_head::<OpenIn>(slot::OPEN, Ticket::NONE),
        host: ptr::null(),
        settings: absent(),
        secrets: ptr::null(),
        secrets_len: 0,
        generation: PANIC_GEN,
        err_buf: ptr::null_mut(),
        err_cap: 0,
    };
    let mut out = OpenOut {
        head: prefilled_head(size_of::<OpenOut>()),
        instance: ptr::null_mut(),
        err_len: 0,
    };
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    assert_eq!(call(table().head.open, &input, &mut out), Outcome::Fault);
    assert_eq!(out.head.outcome.outcome(), Outcome::Fault);
    assert!(
        out.instance.is_null(),
        "a panicking open handed back an instance"
    );
}

mod auth_plugin {
    //! A REAL kind table: every auth kind op wired to the structs `abi::auth` states for it.
    use super::*;
    use crate::abi::auth::{
        BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
        OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, VerifyIn,
    };

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(Verify, VerifyIn, IdentifyOut, Outcome::Ready);
    answers!(Begin, BeginLoginIn, BeginLoginOut, Outcome::Refused);
    answers!(Complete, CompleteLoginIn, IdentifyOut, Outcome::Failed);
    answers!(OpenOb, OpenOutboundIn, OpenOutboundOut, Outcome::Ready);
    answers!(ObReady, OutboundReadyIn, OutboundReadyOut, Outcome::Ready);
    answers!(Fields, FieldsIn, FieldsOut, Outcome::Refused);

    crate::plugin_door! {
        ops: crate::abi::auth::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-auth", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            verify: Verify, begin_login: Begin, complete_login: Complete,
            open_outbound: OpenOb, outbound_ready: ObReady, fields: Fields,
        },
    }
}

#[test]
fn an_auth_plugin_wires_every_kind_op() {
    use crate::abi::auth::{slot as auth_slot, FieldsIn, FieldsOut, IdentifyOut, Ops, VerifyIn};
    // SAFETY: the macro's `'static` door and its auth table.
    let d = unsafe { &*auth_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Auth as u32);
    assert_eq!(d.kind_abi, crate::abi::auth::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::auth::SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `verify` answers only its own index, reading a whole `VerifyIn`.
    // SAFETY: `VerifyIn` is plain data; all-zero is valid.
    let mut input: VerifyIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<VerifyIn>(auth_slot::VERIFY, Ticket::NONE);
    // SAFETY: as above.
    let mut out: IdentifyOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<IdentifyOut>());
    assert_eq!(call(t.verify, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    input.head.op = auth_slot::FIELDS;
    out.head = prefilled_head(size_of::<IdentifyOut>());
    assert_eq!(call(t.verify, &input, &mut out), Outcome::Fault);

    // `fields`, the last slot, likewise.
    // SAFETY: plain data; all-zero is valid.
    let mut input: FieldsIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<FieldsIn>(auth_slot::FIELDS, Ticket::NONE);
    // SAFETY: as above.
    let mut out: FieldsOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<FieldsOut>());
    assert_eq!(call(t.fields, &input, &mut out), Outcome::Refused);
    assert_eq!(out.head.outcome.outcome(), Outcome::Refused);
    for (i, s) in [
        t.verify,
        t.begin_login,
        t.complete_login,
        t.open_outbound,
        t.outbound_ready,
        t.fields,
    ]
    .iter()
    .enumerate()
    {
        assert!(s.is_some(), "auth kind op {i} is NULL");
    }
}

mod secret_plugin {
    //! A REAL kind table: the secret kind's one op wired to the structs `abi::secret` states for
    //! it.
    use super::*;
    use crate::abi::secret::{ResolveIn, ResolveOut};

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(Resolve, ResolveIn, ResolveOut, Outcome::Ready);

    crate::plugin_door! {
        ops: crate::abi::secret::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-secret", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            resolve: Resolve,
        },
    }
}

#[test]
fn a_secret_plugin_wires_every_kind_op() {
    use crate::abi::secret::{slot as secret_slot, Ops, ResolveIn, ResolveOut};
    // SAFETY: the macro's `'static` door and its secret table.
    let d = unsafe { &*secret_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Secret as u32);
    assert_eq!(d.kind_abi, crate::abi::secret::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::secret::SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `resolve` answers only its own index, reading a whole `ResolveIn`.
    // SAFETY: `ResolveIn` is plain data; all-zero is valid.
    let mut input: ResolveIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<ResolveIn>(secret_slot::RESOLVE, Ticket::NONE);
    // SAFETY: as above.
    let mut out: ResolveOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<ResolveOut>());
    assert_eq!(call(t.resolve, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    input.head.op = secret_slot::RESOLVE + 1;
    out.head = prefilled_head(size_of::<ResolveOut>());
    assert_eq!(call(t.resolve, &input, &mut out), Outcome::Fault);

    assert!(t.resolve.is_some(), "secret kind op resolve is NULL");
}

mod export_plugin {
    //! A REAL kind table: every export kind op wired to the structs `abi::export` states for it.
    use super::*;
    use crate::abi::export::{
        CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut, StatusOut,
    };

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(Deliver, DeliverIn, OutHead, Outcome::Ready);
    answers!(Scrape, ScrapeIn, ScrapeOut, Outcome::Refused);
    answers!(Status, InHead, StatusOut, Outcome::Ready);
    answers!(Check, CheckIn, CheckOut, Outcome::Failed);
    answers!(Serve, ServeIn, ServeOut, Outcome::Ready);

    crate::plugin_door! {
        ops: crate::abi::export::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-export", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            deliver: Deliver, scrape: Scrape, status: Status, check: Check, serve: Serve,
        },
    }
}

#[test]
fn an_export_plugin_wires_every_kind_op() {
    use crate::abi::export::{slot as export_slot, DeliverIn, Ops, ServeIn, ServeOut};
    // SAFETY: the macro's `'static` door and its export table.
    let d = unsafe { &*export_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Export as u32);
    assert_eq!(d.kind_abi, crate::abi::export::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::export::SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `deliver` answers only its own index, reading a whole `DeliverIn`.
    // SAFETY: `DeliverIn` is plain data; all-zero is valid.
    let mut input: DeliverIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<DeliverIn>(export_slot::DELIVER, Ticket::NONE);
    let mut out: OutHead = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.deliver, &input, &mut out), Outcome::Ready);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);
    input.head.op = export_slot::SCRAPE;
    out = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.deliver, &input, &mut out), Outcome::Fault);

    // `serve`, the last slot, likewise.
    // SAFETY: plain data; all-zero is valid.
    let mut input: ServeIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<ServeIn>(export_slot::SERVE, Ticket::NONE);
    // SAFETY: as above.
    let mut out: ServeOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<ServeOut>());
    assert_eq!(call(t.serve, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    for (i, s) in [t.deliver, t.scrape, t.status, t.check, t.serve]
        .iter()
        .enumerate()
    {
        assert!(s.is_some(), "export kind op {i} is NULL");
    }
}

mod hook_plugin {
    //! A REAL kind table: every hook kind op wired to the structs `abi::hook` states for it.
    use super::*;
    use crate::abi::hook::{
        ConfigureIn, ConfigureOut, DecideIn, DecideOut, DescribeOut, NotifyIn, ServeIn, ServeOut,
        StatusOut, TransformOut,
    };

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(Decide, DecideIn, DecideOut, Outcome::Ready);
    answers!(Transform, DecideIn, TransformOut, Outcome::Refused);
    answers!(Notify, NotifyIn, OutHead, Outcome::Ready);
    answers!(Configure, ConfigureIn, ConfigureOut, Outcome::Failed);
    answers!(Status, InHead, StatusOut, Outcome::Ready);
    answers!(Describe, InHead, DescribeOut, Outcome::Ready);
    answers!(Serve, ServeIn, ServeOut, Outcome::Ready);

    crate::plugin_door! {
        ops: crate::abi::hook::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-hook", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            decide: Decide, transform: Transform, notify: Notify, configure: Configure,
            status: Status, describe: Describe, serve: Serve,
        },
    }
}

#[test]
fn a_hook_plugin_wires_every_kind_op() {
    use crate::abi::hook::{slot as hook_slot, DecideIn, DecideOut, Ops, ServeIn, ServeOut};
    // SAFETY: the macro's `'static` door and its hook table.
    let d = unsafe { &*hook_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Hook as u32);
    assert_eq!(d.kind_abi, crate::abi::hook::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::hook::SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `decide` answers only its own index, reading a whole `DecideIn`.
    // SAFETY: `DecideIn` is plain data; all-zero is valid.
    let mut input: DecideIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<DecideIn>(hook_slot::DECIDE, Ticket::NONE);
    // SAFETY: as above.
    let mut out: DecideOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<DecideOut>());
    assert_eq!(call(t.decide, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    input.head.op = hook_slot::TRANSFORM;
    out.head = prefilled_head(size_of::<DecideOut>());
    assert_eq!(call(t.decide, &input, &mut out), Outcome::Fault);

    // `serve`, the last slot, likewise.
    // SAFETY: plain data; all-zero is valid.
    let mut input: ServeIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<ServeIn>(hook_slot::SERVE, Ticket::NONE);
    // SAFETY: as above.
    let mut out: ServeOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<ServeOut>());
    assert_eq!(call(t.serve, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    for (i, s) in [
        t.decide,
        t.transform,
        t.notify,
        t.configure,
        t.status,
        t.describe,
        t.serve,
    ]
    .iter()
    .enumerate()
    {
        assert!(s.is_some(), "hook kind op {i} is NULL");
    }
}

mod store_plugin {
    //! A REAL kind table: every store kind op wired to the structs `abi::store` states for
    //! it.
    use super::*;
    use crate::abi::store::{AddUsageBatchIn, AddUsageIn, AppendBatchIn, AppendPlaneRecordIn};
    use crate::abi::store::{BlobIn, CountOut, GetPlaneRecordIn, HeadOut, HeadsOut};
    use crate::abi::store::{HostBytesOut, HostListOut, IdIn, IdReasonIn, KeyWithCredentialIn};
    use crate::abi::store::{KindBeforeIn, KindIdIn, LeasedBlobOut, LeasedListOut};
    use crate::abi::store::{LeasedStrListOut, ListPlaneRecordsIn, OpBlobIn, OpBlobsIn};
    use crate::abi::store::{PutUsageIn, RecordGetIn, RecordPutIn, RecordScanIn, ReserveIn};
    use crate::abi::store::{ReserveOut, SessionPutIn, SessionsForIn, SliceReleaseIn};
    use crate::abi::store::{SliceReleaseOut, TokenIn, U64In, UpsertPlaneRecordIn, VerdictOut};
    use crate::abi::store::{WindowCapsIn, WindowIn};

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(PutKey, BlobIn, OutHead, Outcome::Ready);
    answers!(GetKey, IdIn, LeasedBlobOut, Outcome::Refused);
    answers!(ListKeys, InHead, LeasedListOut, Outcome::Failed);
    answers!(DeleteKey, IdIn, OutHead, Outcome::Ready);
    answers!(ScrubKey, IdIn, OutHead, Outcome::Refused);
    answers!(ListKeysSince, U64In, LeasedListOut, Outcome::Failed);
    answers!(GetUsage, WindowIn, LeasedBlobOut, Outcome::Ready);
    answers!(PutUsage, PutUsageIn, OutHead, Outcome::Refused);
    answers!(AddUsage, AddUsageIn, OutHead, Outcome::Failed);
    answers!(AddMetering, OpBlobIn, OutHead, Outcome::Ready);
    answers!(ListMetering, U64In, LeasedListOut, Outcome::Refused);
    answers!(PurgeWindowsBefore, U64In, CountOut, Outcome::Failed);
    answers!(PurgeMeteringBefore, IdIn, CountOut, Outcome::Ready);
    answers!(PutCredential, BlobIn, OutHead, Outcome::Refused);
    answers!(
        PutKeyWithCredential,
        KeyWithCredentialIn,
        OutHead,
        Outcome::Failed
    );
    answers!(ListCredentials, IdIn, LeasedListOut, Outcome::Ready);
    answers!(
        LookupCredentialSecret,
        KindIdIn,
        LeasedBlobOut,
        Outcome::Refused
    );
    answers!(RevokeCredential, IdReasonIn, OutHead, Outcome::Failed);
    answers!(ListCredentialsSince, U64In, LeasedListOut, Outcome::Ready);
    answers!(AppendAudit, OpBlobIn, OutHead, Outcome::Refused);
    answers!(ListAudit, InHead, LeasedListOut, Outcome::Failed);
    answers!(AddDenylist, IdReasonIn, OutHead, Outcome::Ready);
    answers!(ListDenylist, InHead, LeasedStrListOut, Outcome::Refused);
    answers!(ListAuditTail, U64In, LeasedListOut, Outcome::Failed);
    answers!(
        UpsertPlaneRecord,
        UpsertPlaneRecordIn,
        OutHead,
        Outcome::Ready
    );
    answers!(
        GetPlaneRecord,
        GetPlaneRecordIn,
        HostBytesOut,
        Outcome::Refused
    );
    answers!(
        AppendPlaneRecord,
        AppendPlaneRecordIn,
        OutHead,
        Outcome::Failed
    );
    answers!(
        ListPlaneRecords,
        ListPlaneRecordsIn,
        HostListOut,
        Outcome::Ready
    );
    answers!(
        ListPlaneRecordParents,
        IdIn,
        LeasedStrListOut,
        Outcome::Refused
    );
    answers!(
        PurgePlaneRecordsBefore,
        KindBeforeIn,
        CountOut,
        Outcome::Failed
    );
    answers!(DeletePlaneRecord, KindIdIn, OutHead, Outcome::Ready);
    answers!(RedeemPlaneToken, TokenIn, VerdictOut, Outcome::Refused);
    answers!(PlaneTokenLive, TokenIn, VerdictOut, Outcome::Failed);
    answers!(AppendBatch, AppendBatchIn, HeadOut, Outcome::Ready);
    answers!(Reserve, ReserveIn, ReserveOut, Outcome::Refused);
    answers!(
        SliceRelease,
        SliceReleaseIn,
        SliceReleaseOut,
        Outcome::Failed
    );
    answers!(Heads, InHead, HeadsOut, Outcome::Ready);
    answers!(SessionPut, SessionPutIn, OutHead, Outcome::Refused);
    answers!(SessionRemove, U64In, OutHead, Outcome::Failed);
    answers!(SessionsFor, SessionsForIn, HostListOut, Outcome::Ready);
    answers!(RecordPut, RecordPutIn, OutHead, Outcome::Refused);
    answers!(RecordGet, RecordGetIn, HostBytesOut, Outcome::Failed);
    answers!(RecordScan, RecordScanIn, HostListOut, Outcome::Ready);
    answers!(AddUsageBatch, AddUsageBatchIn, OutHead, Outcome::Refused);
    answers!(AddMeteringBatch, OpBlobsIn, OutHead, Outcome::Failed);
    answers!(AppendAuditBatch, OpBlobsIn, OutHead, Outcome::Ready);
    answers!(WindowCaps, WindowCapsIn, OutHead, Outcome::Ready);

    crate::plugin_door! {
        ops: crate::abi::store::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-store", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            put_key: PutKey, get_key: GetKey, list_keys: ListKeys, delete_key: DeleteKey,
            scrub_key: ScrubKey, list_keys_since: ListKeysSince, get_usage: GetUsage,
            put_usage: PutUsage, add_usage: AddUsage, add_metering: AddMetering,
            list_metering: ListMetering, purge_windows_before: PurgeWindowsBefore,
            purge_metering_before: PurgeMeteringBefore, put_credential: PutCredential,
            put_key_with_credential: PutKeyWithCredential, list_credentials: ListCredentials,
            lookup_credential_secret: LookupCredentialSecret,
            revoke_credential: RevokeCredential, list_credentials_since: ListCredentialsSince,
            append_audit: AppendAudit, list_audit: ListAudit, add_denylist: AddDenylist,
            list_denylist: ListDenylist, list_audit_tail: ListAuditTail,
            upsert_plane_record: UpsertPlaneRecord, get_plane_record: GetPlaneRecord,
            append_plane_record: AppendPlaneRecord, list_plane_records: ListPlaneRecords,
            list_plane_record_parents: ListPlaneRecordParents,
            purge_plane_records_before: PurgePlaneRecordsBefore,
            delete_plane_record: DeletePlaneRecord, redeem_plane_token: RedeemPlaneToken,
            plane_token_live: PlaneTokenLive, append_batch: AppendBatch, reserve: Reserve,
            slice_release: SliceRelease, heads: Heads, session_put: SessionPut,
            session_remove: SessionRemove, sessions_for: SessionsFor, record_put: RecordPut,
            record_get: RecordGet, record_scan: RecordScan, add_usage_batch: AddUsageBatch,
            add_metering_batch: AddMeteringBatch, append_audit_batch: AppendAuditBatch,
            window_caps: WindowCaps
        },
    }
}

#[test]
fn a_store_plugin_wires_every_kind_op() {
    use crate::abi::store::{slot as store_slot, BlobIn, Ops, WindowCapsIn};
    // SAFETY: the macro's `'static` door and its store table.
    let d = unsafe { &*store_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Store as u32);
    assert_eq!(d.kind_abi, crate::abi::store::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::store::TABLE_SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `put_key`, the first kind slot, answers only its own index, reading a whole `BlobIn`.
    // SAFETY: `BlobIn` is plain data; all-zero is valid.
    let mut input: BlobIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<BlobIn>(store_slot::PUT_KEY, Ticket::NONE);
    // SAFETY: as above.
    let mut out: OutHead = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.put_key, &input, &mut out), Outcome::Ready);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);
    input.head.op = store_slot::GET_KEY;
    out = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.put_key, &input, &mut out), Outcome::Fault);

    // `window_caps`, the last kind slot, likewise.
    // SAFETY: plain data; all-zero is valid.
    let mut input: WindowCapsIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<WindowCapsIn>(store_slot::WINDOW_CAPS, Ticket::NONE);
    // SAFETY: as above.
    let mut out: OutHead = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.window_caps, &input, &mut out), Outcome::Ready);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);

    for (i, s) in [
        t.put_key,
        t.get_key,
        t.list_keys,
        t.delete_key,
        t.scrub_key,
        t.list_keys_since,
        t.get_usage,
        t.put_usage,
        t.add_usage,
        t.add_metering,
        t.list_metering,
        t.purge_windows_before,
        t.purge_metering_before,
        t.put_credential,
        t.put_key_with_credential,
        t.list_credentials,
        t.lookup_credential_secret,
        t.revoke_credential,
        t.list_credentials_since,
        t.append_audit,
        t.list_audit,
        t.add_denylist,
        t.list_denylist,
        t.list_audit_tail,
        t.upsert_plane_record,
        t.get_plane_record,
        t.append_plane_record,
        t.list_plane_records,
        t.list_plane_record_parents,
        t.purge_plane_records_before,
        t.delete_plane_record,
        t.redeem_plane_token,
        t.plane_token_live,
        t.append_batch,
        t.reserve,
        t.slice_release,
        t.heads,
        t.session_put,
        t.session_remove,
        t.sessions_for,
        t.record_put,
        t.record_get,
        t.record_scan,
        t.add_usage_batch,
        t.add_metering_batch,
        t.append_audit_batch,
        t.window_caps,
    ]
    .iter()
    .enumerate()
    {
        assert!(s.is_some(), "store kind op {i} is NULL");
    }
}

mod plane_plugin {
    //! A REAL kind table: every plane kind op wired to the structs `abi::plane` states for it.
    use super::*;
    use crate::abi::plane::{ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, RefusalIn, RefusalOut};
    use crate::abi::plane::{PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut};
    use crate::abi::plane::{PlaneRefreshOut, PlaneSnapshot};
    use crate::abi::plane::{ProjectIn, ProjectOut, ServeIn, ServeOut};

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(Arrive, ArriveIn, ArriveOut, Outcome::Ready);
    answers!(OnPiece, OnPieceIn, OnPieceOut, Outcome::Refused);
    answers!(Refusal, RefusalIn, RefusalOut, Outcome::Failed);
    answers!(Serve, ServeIn, ServeOut, Outcome::Ready);
    answers!(Hydrate, GenIn, OutHead, Outcome::Ready);
    answers!(Start, GenIn, OutHead, Outcome::Ready);
    answers!(Project, ProjectIn, ProjectOut, Outcome::Ready);
    answers!(Refresh, RefreshIn, PlaneRefreshOut, Outcome::Failed);

    /// The generation snapshot `open` publishes.
    pub const SNAPSHOT: &PlaneSnapshot = &PlaneSnapshot {
        size: size_of::<PlaneSnapshot>() as u32,
        _reserved: 0,
        generation: 7,
        claims: std::ptr::null(),
        claims_len: 0,
        admin_routes: std::ptr::null(),
        admin_routes_len: 0,
        openapi: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: crate::abi::mechanism::call::BLOB_ABSENT,
            flags: 0,
        },
        audience: crate::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        resource_metadata: crate::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
    };

    /// `open`: the plane's own `out`, carrying the snapshot.
    pub struct Open;
    impl Slot for Open {
        type In = PlaneOpenIn;
        type Out = PlaneOpenOut;
        fn call(_: *mut c_void, _: &PlaneOpenIn, out: &mut PlaneOpenOut) -> Outcome {
            out.snapshot = SNAPSHOT;
            Outcome::Ready
        }
    }

    /// `drive`: names the session `41` ready in the host's buffer.
    pub struct Drive;
    impl Slot for Drive {
        type In = PlaneDriveIn;
        type Out = PlaneDriveOut;
        fn call(_: *mut c_void, input: &PlaneDriveIn, out: &mut PlaneDriveOut) -> Outcome {
            if input.sessions_cap == 0 {
                out.sessions_needed = 1;
                return Outcome::Failed;
            }
            // SAFETY: the host's buffer of `sessions_cap >= 1` streams.
            unsafe { input.sessions_buf.write(41) };
            out.sessions_written = 1;
            Outcome::Ready
        }
    }

    crate::plugin_door! {
        ops: crate::abi::plane::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-plane", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            arrive: Arrive, on_piece: OnPiece, refusal: Refusal, serve: Serve, hydrate: Hydrate,
            start: Start, project: Project,
        },
    }
}

#[test]
fn a_plane_plugin_wires_every_kind_op() {
    use crate::abi::plane::{slot as plane_slot, ArriveIn, ArriveOut, Ops, ProjectIn, ProjectOut};
    use crate::abi::plane::{
        PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneSnapshot,
    };
    // SAFETY: the macro's `'static` door and its plane table.
    let d = unsafe { &*plane_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Plane as u32);
    assert_eq!(d.kind_abi, crate::abi::plane::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::plane::SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `arrive`, the first kind slot, answers only its own index, reading a whole `ArriveIn`.
    // SAFETY: `ArriveIn` is plain data; all-zero is valid.
    let mut input: ArriveIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<ArriveIn>(plane_slot::ARRIVE, Ticket::NONE);
    // SAFETY: as above.
    let mut out: ArriveOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<ArriveOut>());
    assert_eq!(call(t.arrive, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    input.head.op = plane_slot::ON_PIECE;
    out.head = prefilled_head(size_of::<ArriveOut>());
    assert_eq!(call(t.arrive, &input, &mut out), Outcome::Fault);

    // `start` likewise.
    // SAFETY: plain data; all-zero is valid.
    let mut input: GenIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<GenIn>(plane_slot::START, Ticket::NONE);
    // SAFETY: as above.
    let mut out: OutHead = prefilled_head(size_of::<OutHead>());
    assert_eq!(call(t.start, &input, &mut out), Outcome::Ready);
    assert_eq!(out.outcome.outcome(), Outcome::Ready);

    // `project`, the last kind slot, reads a whole `ProjectIn` and writes a whole `ProjectOut`.
    // SAFETY: plain data; all-zero is valid.
    let mut input: ProjectIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<ProjectIn>(plane_slot::PROJECT, Ticket::NONE);
    // SAFETY: as above.
    let mut out: ProjectOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<ProjectOut>());
    assert_eq!(call(t.project, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);

    // `open` writes the plane's whole `PlaneOpenOut`: the snapshot reaches the host.
    // SAFETY: plain data; all-zero is valid.
    let mut input: PlaneOpenIn = unsafe { std::mem::zeroed() };
    input.open.head = in_head::<PlaneOpenIn>(slot::OPEN, Ticket::NONE);
    // SAFETY: as above.
    let mut out: PlaneOpenOut = unsafe { std::mem::zeroed() };
    out.open.head = prefilled_head(size_of::<PlaneOpenOut>());
    assert_eq!(call(t.head.open, &input, &mut out), Outcome::Ready);
    // A `const` has no one address: the snapshot is compared by its contents.
    assert!(!out.snapshot.is_null());
    // SAFETY: the plugin's `'static` snapshot.
    let snap = unsafe { &*out.snapshot };
    assert_eq!(
        (snap.size as usize, snap.generation),
        (
            size_of::<PlaneSnapshot>(),
            plane_plugin::SNAPSHOT.generation
        )
    );
    assert_eq!(out.open.head.size as usize, size_of::<PlaneOpenOut>());

    // `drive` names the ready session in the host's buffer; a zero cap is the short answer.
    let mut sessions = [0_u64; 2];
    // SAFETY: plain data; all-zero is valid.
    let mut input: PlaneDriveIn = unsafe { std::mem::zeroed() };
    input.drive.head = in_head::<PlaneDriveIn>(slot::DRIVE, Ticket::NONE);
    input.sessions_buf = sessions.as_mut_ptr();
    input.sessions_cap = sessions.len();
    // SAFETY: as above.
    let mut out: PlaneDriveOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<PlaneDriveOut>());
    assert_eq!(call(t.head.drive, &input, &mut out), Outcome::Ready);
    assert_eq!((out.sessions_written, sessions[0]), (1, 41));
    input.sessions_cap = 0;
    out.head = prefilled_head(size_of::<PlaneDriveOut>());
    assert_eq!(call(t.head.drive, &input, &mut out), Outcome::Failed);
    assert_eq!(out.sessions_needed, 1);

    for (i, s) in [
        t.arrive, t.on_piece, t.refusal, t.serve, t.hydrate, t.start, t.project,
    ]
    .iter()
    .enumerate()
    {
        assert!(s.is_some(), "plane kind op {i} is NULL");
    }
}

mod transport_plugin {
    //! A REAL kind table: every transport kind op wired to the structs `abi::transport`
    //! states for it.
    use super::*;
    use crate::abi::transport::{AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn};
    use crate::abi::transport::{ConnIn, ConnOut, DialIn, EmitIn, EncodeIn, FinishIn, FramerOut};
    use crate::abi::transport::{FramingIn, IngestIn, IoOut, ListenIn, ListenOut, LocateIn};
    use crate::abi::transport::{LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn};

    macro_rules! answers {
        ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
            pub struct $name;
            impl Slot for $name {
                type In = $in;
                type Out = $out;
                fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                    $outcome
                }
            }
        };
    }
    answers!(Listen, ListenIn, ListenOut, Outcome::Ready);
    answers!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
    answers!(Dial, DialIn, ConnOut, Outcome::Failed);
    answers!(Read, ReadIn, IoOut, Outcome::Ready);
    answers!(Write, WriteIn, IoOut, Outcome::Refused);
    answers!(Flush, ConnIn, OutHead, Outcome::Failed);
    answers!(Shut, ShutIn, OutHead, Outcome::Ready);
    answers!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);
    answers!(Locate, LocateIn, LocateOut, Outcome::Failed);
    answers!(Begin, BeginIn, FramerOut, Outcome::Ready);
    answers!(Ingest, IngestIn, FramerOut, Outcome::Refused);
    answers!(Emit, EmitIn, FramerOut, Outcome::Failed);
    answers!(Encode, EncodeIn, FramerOut, Outcome::Ready);
    answers!(Refuse, RefuseIn, FramerOut, Outcome::Refused);
    answers!(Finish, FinishIn, FramerOut, Outcome::Failed);
    answers!(Detach, FramingIn, FramerOut, Outcome::Ready);
    answers!(Adopt, AdoptIn, FramerOut, Outcome::Refused);
    answers!(Timer, FramingIn, FramerOut, Outcome::Ready);

    crate::plugin_door! {
        ops: crate::abi::transport::Ops,
        statement: crate::abi::sdk::door::statement("sdk-door-transport", "0.0.1", 1),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
        kind_ops: {
            listen: Listen, accept: Accept, dial: Dial, read: Read, write: Write, flush: Flush,
            shut: Shut, arrival: Arrival, locate: Locate, begin: Begin, ingest: Ingest,
            emit: Emit, encode: Encode, refuse: Refuse, finish: Finish, detach: Detach,
            adopt: Adopt, timer: Timer
        },
    }
}

#[test]
fn a_transport_plugin_wires_every_kind_op() {
    use crate::abi::transport::{
        slot as transport_slot, FramerOut, FramingIn, ListenIn, ListenOut, Ops,
    };
    // SAFETY: the macro's `'static` door and its transport table.
    let d = unsafe { &*transport_plugin::door() };
    let t = unsafe { &*d.ops.cast::<Ops>() };
    assert_eq!(d.kind, KindCode::Transport as u32);
    assert_eq!(d.kind_abi, crate::abi::transport::ABI_VERSION);
    assert_eq!(t.head.slots, crate::abi::transport::SLOTS);
    assert_eq!(t.head.size as usize, size_of::<Ops>());

    // `listen`, the first kind slot, answers only its own index, reading a whole `ListenIn`.
    // SAFETY: `ListenIn` is plain data; all-zero is valid.
    let mut input: ListenIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<ListenIn>(transport_slot::LISTEN, Ticket::NONE);
    // SAFETY: as above.
    let mut out: ListenOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<ListenOut>());
    assert_eq!(call(t.listen, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);
    input.head.op = transport_slot::ACCEPT;
    out.head = prefilled_head(size_of::<ListenOut>());
    assert_eq!(call(t.listen, &input, &mut out), Outcome::Fault);

    // `timer`, the last kind slot, likewise.
    // SAFETY: plain data; all-zero is valid.
    let mut input: FramingIn = unsafe { std::mem::zeroed() };
    input.head = in_head::<FramingIn>(transport_slot::TIMER, Ticket::NONE);
    // SAFETY: as above.
    let mut out: FramerOut = unsafe { std::mem::zeroed() };
    out.head = prefilled_head(size_of::<FramerOut>());
    assert_eq!(call(t.timer, &input, &mut out), Outcome::Ready);
    assert_eq!(out.head.outcome.outcome(), Outcome::Ready);

    for (i, s) in [
        t.listen, t.accept, t.dial, t.read, t.write, t.flush, t.shut, t.arrival, t.locate, t.begin,
        t.ingest, t.emit, t.encode, t.refuse, t.finish, t.detach, t.adopt, t.timer,
    ]
    .iter()
    .enumerate()
    {
        assert!(s.is_some(), "transport kind op {i} is NULL");
    }
}
