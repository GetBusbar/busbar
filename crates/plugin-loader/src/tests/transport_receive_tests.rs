// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::framing_context::{self, FramingContext};
use busbar_contract::abi::mechanism::call::OutHead;
use busbar_contract::abi::mechanism::lifecycle::ReleaseIn;
use busbar_contract::abi::transport::{slot, FramerOut, IngestIn};
use busbar_contract::framing_scope::FramingScope;

// This is an adversarial ABI accounting control, not a wire-protocol producer.
// The qualified TCP image owns the real descriptor, lifecycle, and instance.
mod pressure_boundary {
    use super::*;
    use busbar_contract::abi::mechanism::call::{Blob, RawOutcome, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::sdk::door::RawDoorFn;
    use std::collections::BTreeMap;
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex, OnceLock,
    };
    static LOANS: OnceLock<Mutex<BTreeMap<u64, Box<[u8]>>>> = OnceLock::new();
    static NEXT: AtomicU64 = AtomicU64::new(1);
    pub(super) static RELEASED: AtomicUsize = AtomicUsize::new(0);
    fn loans() -> &'static Mutex<BTreeMap<u64, Box<[u8]>>> {
        LOANS.get_or_init(Mutex::default)
    }
    extern "C" fn ingest(
        _: *mut std::ffi::c_void,
        input: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        // SAFETY: the production INGEST crossing owns initialized, correctly sized frames.
        let n = unsafe { (*input.cast::<IngestIn>()).len };
        let outcome = if n == 7 {
            Outcome::Pending
        } else {
            Outcome::Ready
        };
        let bytes = if n == 9 {
            busbar_contract::abi::mechanism::extensions::encode(&[("framer.retained_input", &[1])])
        } else {
            busbar_contract::abi::sdk::transport::receive::encode(n as u64)
        }
        .into_boxed_slice();
        let lease = NEXT.fetch_add(1, Ordering::SeqCst);
        let blob = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        assert!(loans().lock().unwrap().insert(lease, bytes).is_none());
        // SAFETY: the output is the host's exclusive INGEST frame; the map keeps its loan live.
        unsafe {
            let answer = &mut *out.cast::<FramerOut>();
            answer.head.outcome = RawOutcome::of(outcome);
            answer.head.extensions = blob;
            answer.head.lease = lease;
        }
        RawOutcome::of(outcome)
    }
    extern "C" fn release(
        _: *mut std::ffi::c_void,
        input: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        // SAFETY: RELEASE receives the host's exclusive initialized release input/output.
        let lease = unsafe { (*input.cast::<ReleaseIn>()).lease };
        assert!(
            loans().lock().unwrap().remove(&lease).is_some(),
            "every extension answer loan is freed exactly once"
        );
        RELEASED.fetch_add(1, Ordering::SeqCst);
        unsafe {
            (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready);
        }
        RawOutcome::of(Outcome::Ready)
    }
    pub(super) extern "C" fn door() -> &'static Door {
        static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
        static DOOR: OnceLock<usize> = OnceLock::new();
        let image = IMAGE.get_or_init(|| {
            let path =
                std::env::var_os("BUSBAR_TEST_TCP_CDYLIB").expect("qualified actual TCP image");
            let library = crate::dlopen_on_worker(path.as_os_str()).expect("load actual TCP");
            // SAFETY: the qualified actual product exports the typed ABI entry; IMAGE retains it.
            let entry = unsafe {
                *library
                    .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                    .expect("TCP entry")
            };
            (library, entry)
        });
        let address = *DOOR.get_or_init(|| {
            let raw = crate::dispatch::load::enter_door(image.1);
            crate::dispatch::load::validate_door::<crate::dispatch::kinds::transport::Transport>(
                raw,
            )
            .expect("actual TCP descriptor");
            // SAFETY: validation established live immutable retained product metadata and table.
            let actual = unsafe { &*raw };
            let mut ops = unsafe {
                actual
                    .ops()
                    .cast::<busbar_contract::abi::transport::Ops>()
                    .read_unaligned()
            };
            ops.ingest = Some(ingest);
            ops.head.release = Some(release);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: same actual TCP descriptor and operation table layout, only the two
            // explicitly hostile accounting boundary slots use permanently retained overrides.
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
}

#[test]
fn retained_input_is_copied_on_pending_and_ready_only_to_the_current_leg() {
    use crate::dispatch::kinds::transport::Transport;
    use crate::dispatch::{load_linked, LinkedRow};
    let row = LinkedRow::of(pressure_boundary::door).unwrap();
    let released = pressure_boundary::RELEASED.load(std::sync::atomic::Ordering::SeqCst);
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
    assert_eq!(
        pressure_boundary::RELEASED.load(std::sync::atomic::Ordering::SeqCst) - released,
        4,
        "all four extension loans are retired exactly once"
    );
}
