// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PR-05 (LEASE-LEAK): a transport op answer's lease is consumed inside its crossing, so the
//! dispatcher retires it there and hands the caller none. The connector drops `Called.lease` for
//! every transport op, so any lease handed out is held by the plugin for the process lifetime.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{slot, FramerOut, IngestIn};

use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::{in_head, load_linked, out_head, Adopter, Bind, Frame, LinkedRow, NoSink};

/// The answers this fixture has leased and not yet seen released, by lease id.
static HELD: OnceLock<Mutex<BTreeMap<u64, Box<[u8]>>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);

fn held() -> &'static Mutex<BTreeMap<u64, Box<[u8]>>> {
    HELD.get_or_init(Mutex::default)
}

/// INGEST answers READY with a small reply extension it leases into its own map, as a framer that
/// reports through `Out::lease` does.
extern "C" fn ingest(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let bytes = busbar_contract::abi::mechanism::extensions::encode(&[("test.answer_note", &[1])])
        .into_boxed_slice();
    let lease = NEXT.fetch_add(1, Ordering::SeqCst);
    let blob = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    assert!(held().lock().unwrap().insert(lease, bytes).is_none());
    // SAFETY: the output is the host's exclusive INGEST frame; the map keeps the leased bytes live.
    unsafe {
        let answer = &mut *out.cast::<FramerOut>();
        answer.head.outcome = RawOutcome::of(Outcome::Ready);
        answer.head.extensions = blob;
        answer.head.lease = lease;
    }
    RawOutcome::of(Outcome::Ready)
}

/// RELEASE frees exactly the named lease from the fixture's map.
extern "C" fn release(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    // SAFETY: RELEASE receives the host's exclusive initialized release input/output.
    let lease = unsafe { (*input.cast::<ReleaseIn>()).lease };
    assert!(
        held().lock().unwrap().remove(&lease).is_some(),
        "a transport answer lease is released exactly once"
    );
    // SAFETY: the output is the host's exclusive RELEASE head.
    unsafe {
        (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// The neutral transport door with only INGEST and RELEASE overridden.
extern "C" fn door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let address = *DOOR.get_or_init(|| {
        let actual = crate::neutral_transport::door();
        // SAFETY: the neutral transport door's ops table is a transport `Ops`.
        let mut ops = unsafe {
            actual
                .ops()
                .cast::<busbar_contract::abi::transport::Ops>()
                .read_unaligned()
        };
        ops.ingest = Some(ingest);
        ops.head.release = Some(release);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: the same neutral descriptor and operation table layout; only the two leasing
        // slots use permanently retained overrides.
        let descriptor = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..actual.parts()
            })
        };
        Box::into_raw(Box::new(descriptor)) as usize
    });
    // SAFETY: this immutable descriptor is permanently retained above.
    unsafe { &*(address as *const Door) }
}

fn bind() -> Bind {
    Bind {
        accept: Default::default(),
        instance: Arc::from("the-lease-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

fn ingest_frame(ticket: Ticket, bytes: &[u8]) -> Frame<IngestIn, FramerOut> {
    let mut input: IngestIn = blank_in();
    input.head = in_head();
    input.head.ticket = ticket;
    input.bytes = bytes.as_ptr();
    input.len = bytes.len();
    let mut output: FramerOut = blank_out();
    output.head = out_head();
    Frame::new(input, output)
}

#[test]
fn transport_op_answer_leases_are_retired_inside_the_crossing() {
    let row = LinkedRow::of(door).unwrap();
    let plugin = load_linked::<Transport>(&row, bind()).unwrap();
    let mut open = Frame::new(blank_in::<OpenIn>(), blank_out::<OpenOut>());
    assert_eq!(plugin.call(life::OPEN, &mut open).outcome, Outcome::Ready);
    let held_before = held().lock().unwrap().len();
    let bytes = [0_u8; 4];
    let ticket = Ticket {
        slot: 21,
        generation: 5,
    };
    let mut handed = 0_usize;
    for _ in 0..64 {
        let mut frame = ingest_frame(ticket, &bytes);
        let called = plugin.call_inline(ticket, false, slot::INGEST, &mut frame);
        assert_eq!(called.outcome, Outcome::Ready);
        handed += usize::from(called.lease != 0);
    }
    for _ in 0..64 {
        let mut frame = ingest_frame(Ticket::NONE, &bytes);
        let called = plugin.call(slot::INGEST, &mut frame);
        assert_eq!(called.outcome, Outcome::Ready);
        handed += usize::from(called.lease != 0);
    }
    let held_after = held().lock().unwrap().len();
    assert_eq!(
        (handed, held_after - held_before),
        (0, 0),
        "no transport op answer lease is handed to the caller or left held by the plugin \
         (handed, held)"
    );
}
