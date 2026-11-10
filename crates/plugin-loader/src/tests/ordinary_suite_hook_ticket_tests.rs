// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The suite's pending-hook control using the neutral SDK Hook witness.

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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

fn witness() -> &'static Door {
    crate::hook_door_conformance_tests::hook_door_plugin::conforming::door()
}

static PENDING_ENTRIES: AtomicUsize = AtomicUsize::new(0);
static WITNESS_DECISIONS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn pending_decide(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: this is the Hook DECIDE slot with complete initialized frames.
    unsafe {
        let head = &*input.cast::<InHead>();
        if head.flags & FLAG_RESUME == 0 {
            PENDING_ENTRIES.fetch_add(1, Ordering::SeqCst);
            crate::dispatch::ticket::host_wake(head.host, head.ticket);
            (*out.cast::<DecideOut>()).head.outcome = RawOutcome::of(Outcome::Pending);
            return RawOutcome::of(Outcome::Pending);
        }
        let ops = witness().ops().cast::<Ops>().read_unaligned();
        WITNESS_DECISIONS.fetch_add(1, Ordering::SeqCst);
        ops.decide.expect("neutral Hook witness decides")(instance, input, out)
    }
}

extern "C" fn pending_door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let ptr = *DOOR.get_or_init(|| {
        let real = *witness();
        // SAFETY: validated retained immutable Hook table.
        let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        ops.decide = Some(pending_decide);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: same valid SDK descriptor and full Hook table, only DECIDE's
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
    PENDING_ENTRIES.store(0, Ordering::SeqCst);
    WITNESS_DECISIONS.store(0, Ordering::SeqCst);
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let p = load_linked::<Hook>(
        &LinkedRow::of(pending_door).expect("neutral Hook witness descriptor"),
        Bind {
            instance: "hook-ticket-control".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("neutral Hook witness binds");
    assert_eq!(
        p.call(
            life::OPEN,
            &mut open_frame(blob(br#"{"reject_over_messages":3}"#, BLOB_JSON, 0))
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
        .expect("the witness wake resumes Hook DECIDE");
    assert_eq!(done.outcome, Outcome::Ready);
    let frame = done.frame.expect("a completed Hook answer frame");
    assert_eq!(
        frame.out.verbs, VERB_ABSTAIN,
        "neutral Hook witness abstains below its configured message limit"
    );

    assert_eq!(p.inner.crossings.load(Ordering::SeqCst) - before.0, 2);
    assert_eq!(PENDING_ENTRIES.load(Ordering::SeqCst), 1);
    assert_eq!(WITNESS_DECISIONS.load(Ordering::SeqCst), 1);
    assert_eq!(p.inner.resumes.load(Ordering::SeqCst) - before.1, 1);
}
