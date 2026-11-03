// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The suite's pending-hook control using the actual first-party Ranking image.
//! Only its scheduling boundary is delayed; the resumed answer is Ranking's.

use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{
    in_head, load_linked, now_ns, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink,
};
use busbar_contract::abi::hook::{slot, DecideIn, DecideOut, Ops, VERB_ABSTAIN};
use busbar_contract::abi::mechanism::call::{
    DeadlineClass, InHead, Outcome, RawOutcome, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::sdk::door::RawDoorFn;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

fn actual() -> &'static Door {
    static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let path = std::env::var_os("BUSBAR_TEST_RANKING_CDYLIB")
            .expect("BUSBAR_TEST_RANKING_CDYLIB names the actual qualified Ranking image");
        let library = crate::dlopen_on_worker(&path).expect("load actual Ranking image");
        // SAFETY: the actual product exports the typed ABI symbol; IMAGE retains
        // the mapping for every descriptor loan and live instance.
        let entry = unsafe {
            *library
                .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("actual Ranking mechanism export")
        };
        (library, entry)
    });
    let ptr = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<Hook>(ptr).expect("actual Ranking hook validates");
    // SAFETY: validated immutable descriptor in IMAGE's retained mapping.
    unsafe { &*ptr }
}

extern "C" fn pending_decide(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: this is the Hook DECIDE slot with complete initialized frames.
    unsafe {
        let head = &*input.cast::<InHead>();
        if head.flags & FLAG_RESUME == 0 {
            crate::dispatch::ticket::host_wake(head.host, head.ticket);
            (*out.cast::<DecideOut>()).head.outcome = RawOutcome::of(Outcome::Pending);
            return RawOutcome::of(Outcome::Pending);
        }
        let ops = actual().ops().cast::<Ops>().read_unaligned();
        ops.decide.expect("actual Ranking decides")(instance, input, out)
    }
}

extern "C" fn pending_door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let ptr = *DOOR.get_or_init(|| {
        let real = *actual();
        // SAFETY: validated retained immutable Hook table.
        let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        ops.decide = Some(pending_decide);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: same genuine descriptor and full Hook table, only DECIDE's
        // scheduling wrapper changed; table and descriptor are process-retained.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: immutable leaked allocation above.
    unsafe { &*(ptr as *const Door) }
}

#[test]
fn red_a_gate_that_waits_is_resumed_on_its_ticket_never_faulted_ticketless() {
    use crate::dispatch::lifecycle::{blob, open_frame};
    use busbar_contract::abi::mechanism::call::BLOB_JSON;
    use busbar_contract::abi::mechanism::lifecycle::slot as life;
    let d = Dispatcher::new(DispatchConfig::default());
    let p = load_linked::<Hook>(
        &LinkedRow::of(pending_door).expect("actual Ranking descriptor"),
        Bind {
            instance: "ranking-ticket-control".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual Ranking binds");
    assert_eq!(
        p.call(
            life::OPEN,
            &mut open_frame(blob(br#"{"policy":"fastest"}"#, BLOB_JSON, 0))
        )
        .outcome,
        Outcome::Ready
    );
    // SAFETY: DecideIn/Out contain only integer and pointer ABI fields; null/0
    // is the specified absent request view, no candidates, and unused buffers.
    let mut input: DecideIn = unsafe { std::mem::zeroed() };
    let mut output: DecideOut = unsafe { std::mem::zeroed() };
    input.head = in_head();
    output.head = out_head();
    let before = (
        p.inner.crossings.load(Ordering::SeqCst),
        p.inner.resumes.load(Ordering::SeqCst),
    );
    let ticket = d.mint(0).expect("Hook DECIDE ticket");
    let done = d
        .submit(
            &p,
            ticket,
            slot::DECIDE,
            Frame::new(input, output),
            DeadlineClass::Call,
            now_ns().saturating_add(10_000_000_000),
        )
        .wait(Duration::from_secs(15))
        .expect("the actual wake resumes Hook DECIDE");
    assert_eq!(done.outcome, Outcome::Ready);
    let frame = done.frame.expect("a completed Hook answer frame");
    assert_eq!(
        frame.out.verbs, VERB_ABSTAIN,
        "actual Ranking abstains on an empty candidate set"
    );
    assert_eq!(p.inner.crossings.load(Ordering::SeqCst) - before.0, 1);
    assert_eq!(p.inner.resumes.load(Ordering::SeqCst) - before.1, 1);
}
