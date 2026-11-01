// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::framing_context::{self, FramingContext};
use busbar_contract::abi::mechanism::call::{Blob, OutHead, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::ReleaseIn;
use busbar_contract::abi::transport::{slot, FramerOut, IngestIn, Ops};
use busbar_contract::framing_scope::FramingScope;
use std::ffi::c_void;
use std::sync::OnceLock;

extern "C" fn report(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    // SAFETY: this restated ingest slot is called with its checked kind's input and output.
    let (i, o) = unsafe { (&*input.cast::<IngestIn>(), &mut *out.cast::<FramerOut>()) };
    let mode = i.len;
    let value = if mode == 9 {
        vec![1]
    } else {
        (mode as u64).to_le_bytes().to_vec()
    };
    let bytes = Box::new(extensions::encode(&[("framer.retained_input", &value)]));
    o.head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    o.head.lease = Box::into_raw(bytes) as u64;
    let outcome = if mode == 7 {
        Outcome::Pending
    } else {
        Outcome::Ready
    };
    o.head.outcome = RawOutcome::of(outcome);
    RawOutcome::of(outcome)
}

extern "C" fn release(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    // SAFETY: each lease is the Box<Vec<u8>> minted by report and is released exactly once.
    unsafe {
        let i = &*input.cast::<ReleaseIn>();
        if i.lease != 0 {
            let mut bytes = Box::from_raw(i.lease as *mut Vec<u8>);
            bytes.fill(0);
        }
        (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn reporting_door() -> *const Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    *DOOR.get_or_init(|| {
        // SAFETY: the linked fixture publishes a static complete transport door/table.
        let real = *busbar_stub_transport::door::door();
        let mut ops = unsafe { *real.ops().cast::<Ops>() };
        ops.ingest = Some(report);
        ops.head.release = Some(release);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: the complete restated table has the same layout and all original other slots.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(&ops.head),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    }) as *const Door
}

#[test]
fn retained_input_is_copied_on_pending_and_ready_only_to_the_current_leg() {
    use crate::dispatch::kinds::transport::Transport;
    use crate::dispatch::{load_linked, LinkedRow};
    let row = LinkedRow::of_raw(reporting_door).unwrap();
    let plugin = load_linked::<Transport>(&row, bind()).unwrap();
    let mut open = Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>());
    assert_eq!(plugin.call(life::OPEN, &mut open).outcome, Outcome::Ready);
    let a = FramingContext::new(plugin.instance().0, 0, 0, None).unwrap();
    let b = FramingContext::new(plugin.instance().0, 0, a.connection(), None).unwrap();
    assert_ne!(a.leg(), b.leg());
    let ticket = busbar_contract::abi::mechanism::ticket::Ticket {
        slot: 13,
        generation: 17,
    };
    let crossing = |scope: Arc<FramingContext>, n: usize| {
        let input_bytes = vec![0; n];
        let mut input: IngestIn = blank_in();
        input.head = in_head();
        input.head.ticket = ticket;
        input.bytes = input_bytes.as_ptr();
        input.len = n;
        let mut output: FramerOut = blank_out();
        output.head = out_head();
        let mut frame = Frame::new(input, output);
        let erased: Arc<dyn FramingScope> = scope;
        let called = framing_context::with_context(Some(erased), || {
            plugin.call_inline(ticket, false, slot::INGEST, &mut frame)
        });
        if called.lease != 0 {
            let mut input: ReleaseIn = blank_in();
            input.lease = called.lease;
            let mut frame = Frame::new(input, blank_out::<OutHead>());
            assert_eq!(
                plugin.call(life::RELEASE, &mut frame).outcome,
                Outcome::Ready
            );
        }
        called.outcome
    };
    assert_eq!(crossing(a.clone(), 7), Outcome::Pending);
    assert_eq!(
        a.retained_input(),
        7,
        "the leased bytes were copied before release"
    );
    assert_eq!(
        b.retained_input(),
        0,
        "a second leg shares no accounting state"
    );
    assert_eq!(crossing(b.clone(), 3), Outcome::Ready);
    assert_eq!((a.retained_input(), b.retained_input()), (7, 3));
    assert_eq!(crossing(a.clone(), 0), Outcome::Ready);
    assert_eq!((a.retained_input(), b.retained_input()), (0, 3));
    assert_eq!(
        crossing(b.clone(), 9),
        Outcome::Fault,
        "a present non-u64 report is refused"
    );
    assert_eq!(
        b.retained_input(),
        3,
        "malformed reports cannot clear existing pressure"
    );
}
