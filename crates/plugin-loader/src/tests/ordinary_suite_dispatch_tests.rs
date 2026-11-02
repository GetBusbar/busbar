// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former suite's wake/deadline controls, through the production dispatcher.
//! Only TICK's hostile scheduling answer is substituted; MCP owns the real
//! descriptor, lifecycle, and instance. No fold formatter or runner is involved.

use crate::dispatch::kinds::plane::{open_door, Plane};
use crate::dispatch::{
    in_head, load_linked, now_ns, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};
use busbar_contract::abi::mechanism::call::{
    DeadlineClass, InHead, Outcome, RawOutcome, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{slot, TickIn, TickOut};
use busbar_contract::abi::plane::Ops;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

extern "C" fn wakes(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: this is the TICK slot; the dispatcher supplies initialized frames.
    unsafe {
        let head = &*input.cast::<InHead>();
        if head.flags & FLAG_RESUME == 0 {
            crate::dispatch::ticket::host_wake(head.host, head.ticket);
            (*out.cast::<TickOut>()).head.outcome = RawOutcome::of(Outcome::Pending);
            RawOutcome::of(Outcome::Pending)
        } else {
            (*out.cast::<TickOut>()).head.outcome = RawOutcome::of(Outcome::Ready);
            RawOutcome::of(Outcome::Ready)
        }
    }
}

extern "C" fn never_wakes(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: this is the TICK slot's exclusive initialized output frame.
    unsafe { (*out.cast::<TickOut>()).head.outcome = RawOutcome::of(Outcome::Pending) };
    RawOutcome::of(Outcome::Pending)
}

fn restated(
    slot: &OnceLock<usize>,
    tick: busbar_contract::abi::mechanism::call::Op,
) -> &'static Door {
    let ptr = *slot.get_or_init(|| {
        let real = *crate::actual_mcp::door();
        // SAFETY: actual_mcp retains the validated descriptor and its full plane table.
        let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        ops.head.tick = Some(tick);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: same genuine descriptor and table layout; only the adversarial
        // scheduling slot above is replaced, with permanently retained storage.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: the immutable descriptor was leaked above and stays live forever.
    unsafe { &*(ptr as *const Door) }
}

extern "C" fn waking_door() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    restated(&SLOT, wakes)
}

extern "C" fn unwoken_door() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    restated(&SLOT, never_wakes)
}

fn opened(d: &Dispatcher, door: busbar_contract::abi::mechanism::door::DoorFn) -> Plugin<Plane> {
    let p = bound(d, door);
    open_door(&p, b"{}", b"{}", None).expect("actual MCP opens");
    p
}

fn bound(d: &Dispatcher, door: busbar_contract::abi::mechanism::door::DoorFn) -> Plugin<Plane> {
    let p = load_linked::<Plane>(
        &LinkedRow::of(door).expect("actual MCP metadata"),
        Bind {
            instance: "suite-wake-control".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual MCP binds");
    p
}

fn tick() -> Frame<TickIn, TickOut> {
    Frame::new(
        TickIn {
            head: in_head(),
            now_ns: now_ns(),
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    )
}

#[test]
fn a_wait_that_is_woken_passes() {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = opened(&d, waking_door);
    let before = (
        p.inner.crossings.load(Ordering::SeqCst),
        p.inner.resumes.load(Ordering::SeqCst),
    );
    let ticket = d.mint(0).expect("ticket");
    let done = d
        .submit(
            &p,
            ticket,
            slot::TICK,
            tick(),
            DeadlineClass::Call,
            now_ns().saturating_add(10_000_000_000),
        )
        .wait(Duration::from_secs(15))
        .expect("a real wake resumes the op");
    assert_eq!(done.outcome, Outcome::Ready);
    assert_eq!(p.inner.crossings.load(Ordering::SeqCst) - before.0, 1);
    assert_eq!(p.inner.resumes.load(Ordering::SeqCst) - before.1, 1);
    assert_eq!(d.stats().deadline_without_wake, 0);
}

#[test]
fn red_a_wait_a_deadline_ended_is_refused() {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = opened(&d, unwoken_door);
    let before = d.stats().deadline_without_wake;
    let ticket = d.mint(0).expect("ticket");
    let done = d
        .submit(
            &p,
            ticket,
            slot::TICK,
            tick(),
            DeadlineClass::Call,
            now_ns().saturating_add(50_000_000),
        )
        .wait(Duration::from_secs(10))
        .expect("the actual deadline ends the wait");
    assert_ne!(
        done.outcome,
        Outcome::Ready,
        "a deadline cannot manufacture a wake"
    );
    assert_eq!(d.stats().deadline_without_wake - before, 1);
}

extern "C" fn open_after_wake(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
    // SAFETY: this is the plane OPEN slot, receiving complete initialized frames.
    unsafe {
        let head = &*input.cast::<InHead>();
        if head.flags & FLAG_RESUME == 0 {
            if !head.ticket.is_none() {
                crate::dispatch::ticket::host_wake(head.host, head.ticket);
            }
            (*out.cast::<PlaneOpenOut>()).open.head.outcome = RawOutcome::of(Outcome::Pending);
            return RawOutcome::of(Outcome::Pending);
        }
        // Delay the genuine product OPEN until the requested wake. This local
        // copy retains every host loan, while the real SDK sees its first OPEN.
        let mut real_input = input.cast::<PlaneOpenIn>().read();
        real_input.open.head.flags &= !FLAG_RESUME;
        let ops = crate::actual_mcp::door()
            .ops()
            .cast::<Ops>()
            .read_unaligned();
        ops.head.open.expect("actual MCP has OPEN")(
            instance,
            std::ptr::from_ref(&real_input).cast(),
            out,
        )
    }
}

extern "C" fn pending_open_door() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    let ptr = *SLOT.get_or_init(|| {
        let real = *crate::actual_mcp::door();
        // SAFETY: actual_mcp validates and retains this complete immutable table.
        let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        ops.head.open = Some(open_after_wake);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: unchanged genuine descriptor layout; OPEN is the adversarial
        // scheduling wrapper above and all storage is retained permanently.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: immutable allocation retained above.
    unsafe { &*(ptr as *const Door) }
}

fn open_frame(
) -> Frame<busbar_contract::abi::plane::PlaneOpenIn, busbar_contract::abi::plane::PlaneOpenOut> {
    use crate::dispatch::lifecycle::{blob, lend_or_null, open_in, open_out};
    use busbar_contract::abi::mechanism::call::BLOB_JSON;
    use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
    Frame::new(
        PlaneOpenIn {
            open: open_in(blob(b"{}", BLOB_JSON, 0)),
            public_url: lend_or_null(""),
            owned: blob(b"{}", BLOB_JSON, 0),
            providers: std::ptr::null(),
            providers_len: 0,
        },
        PlaneOpenOut {
            open: open_out(),
            snapshot: std::ptr::null(),
        },
    )
}

#[test]
fn red_a_pending_open_is_resumed_by_the_kernels_open_never_one_raw_crossing() {
    let d = Dispatcher::new(DispatchConfig::default());
    let raw = bound(&d, pending_open_door);
    assert_eq!(
        raw.call(slot::OPEN, &mut open_frame()).outcome,
        Outcome::Fault
    );
    assert!(
        !raw.is_open(),
        "one ticketless crossing cannot complete pending OPEN"
    );

    let p = bound(&d, pending_open_door);
    let before = (
        p.inner.crossings.load(Ordering::SeqCst),
        p.inner.resumes.load(Ordering::SeqCst),
    );
    let ticket = d.mint(0).expect("OPEN ticket");
    let done = d
        .submit(
            &p,
            ticket,
            slot::OPEN,
            open_frame(),
            DeadlineClass::Call,
            now_ns().saturating_add(10_000_000_000),
        )
        .wait(Duration::from_secs(15))
        .expect("OPEN resumes on its actual wake");
    assert_eq!(done.outcome, Outcome::Ready);
    assert!(
        p.is_open(),
        "the genuine MCP OPEN committed its actual instance"
    );
    assert_eq!(p.inner.crossings.load(Ordering::SeqCst) - before.0, 1);
    assert_eq!(p.inner.resumes.load(Ordering::SeqCst) - before.1, 1);
}
