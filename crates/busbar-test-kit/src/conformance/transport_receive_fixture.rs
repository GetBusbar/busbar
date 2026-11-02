// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::ReleaseIn;
use busbar_contract::abi::transport::{FramerOut, IngestIn, Ops};
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

pub(crate) extern "C" fn door() -> *const Door {
    static DOOR: OnceLock<super::StaticDoor> = OnceLock::new();
    DOOR.get_or_init(|| {
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
        // SAFETY: the Statement is static and the complete copied ops table was leaked above;
        // nested ranges keep their original static backing and no reference points into door.
        unsafe { super::StaticDoor::new(door) }
    })
    .get()
}
