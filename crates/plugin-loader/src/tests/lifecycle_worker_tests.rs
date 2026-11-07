// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};

use crate::dispatch::kinds::store_v4::StoreV4 as Store;
use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink,
};
use crate::store_v4::{Limits, LoadedPersistence};

use crate::actual_store;

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

fn open_frame(settings: &[u8]) -> Frame<OpenIn, OpenOut> {
    Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: Blob {
                ptr: settings.as_ptr(),
                len: settings.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            },
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    )
}

#[test]
fn lifecycle_on_permanent_workers_open_and_close_from_a_throwaway_thread() {
    let outcomes = std::thread::Builder::new()
        .name("throwaway".into())
        .spawn(|| {
            let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
            let row = LinkedRow::of(actual_store::door).expect("the store states its Statement");
            let plugin = load_linked::<Store>(&row, bind(&d)).expect("the door loads");
            let opened = plugin
                .call(slot::OPEN, &mut open_frame(&actual_store::settings()))
                .outcome;
            let mut c: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
            let closed = plugin.call(slot::CLOSE, &mut c).outcome;
            (opened, closed)
        })
        .expect("spawn")
        .join()
        .expect("no lifecycle slot entered plugin code off a permanent FFI worker");
    assert_eq!(outcomes, (Outcome::Ready, Outcome::Ready));
}

crate::dispatch_tests::c_abi! {
    /// A slot that answers READY without reading its pointers.
    #[cfg(debug_assertions)]
    fn a_slot(
        _instance: *mut std::os::raw::c_void,
        _input: *const std::os::raw::c_void,
        _out: *mut std::os::raw::c_void,
    ) -> busbar_contract::abi::mechanism::call::RawOutcome {
        busbar_contract::abi::mechanism::call::RawOutcome(Outcome::Ready as u8)
    }
}

#[cfg(debug_assertions)]
#[test]
fn lifecycle_on_permanent_workers_the_assertion_trips_off_the_workers() {
    use busbar_contract::abi::mechanism::call::RawOutcome;

    use super::enter_lifecycle;

    fn enter_a_slot() -> RawOutcome {
        enter_lifecycle(
            "open",
            a_slot,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    }
    let off = std::thread::spawn(enter_a_slot)
        .join()
        .expect_err("a lifecycle slot entered off the workers trips the assertion");
    let said = off.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        said.contains("open entered plugin code") && said.contains("not a permanent FFI worker"),
        "{said}"
    );
    let on = crate::ffi_thread::on_plugin_thread(enter_a_slot);
    assert!(on.is_ok(), "on a permanent worker the assertion holds");
}

#[test]
fn lifecycle_on_permanent_workers_dropped_store_200_rounds() {
    const ROUNDS: usize = 200;
    const THREADS: usize = 8;
    let path = Arc::new(actual_store::path());
    let stated = rendering_of(actual_store::door).expect("the store renders its Statement");
    let stated = Arc::new(stated);
    let threads: Vec<_> = (0..THREADS)
        .map(|t| {
            let (path, stated) = (Arc::clone(&path), Arc::clone(&stated));
            std::thread::Builder::new()
                .name(format!("stress-{t}"))
                .spawn(move || {
                    for round in (t..ROUNDS).step_by(THREADS) {
                        let d = Arc::new(Dispatcher::new(DispatchConfig {
                            workers: 2,
                            ..DispatchConfig::default()
                        }));
                        let p = load_dropped::<Store>(&path, &stated, bind(&d))
                            .unwrap_or_else(|e| panic!("round {round}: the door loads: {e}"));
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        let s = runtime
                            .block_on(LoadedPersistence::open(
                                p,
                                d,
                                &actual_store::settings(),
                                Limits {
                                    descriptor_bytes: 64 * 1024 * 1024,
                                    output_items: 4096,
                                    output_bytes: 64 * 1024 * 1024,
                                    decode_bytes: 64 * 1024 * 1024,
                                },
                            ))
                            .unwrap_or_else(|e| panic!("round {round}: it opens: {e}"));
                        use busbar_contract::persistence::PersistenceBackend;
                        let clock = runtime
                            .block_on(s.clock(s.info().dataset))
                            .expect("native clock");
                        assert_eq!(clock.authority, s.info().clock_authority);
                        drop(s);
                    }
                })
                .expect("spawn")
        })
        .collect();
    for (t, h) in threads.into_iter().enumerate() {
        assert!(h.join().is_ok(), "stress thread {t} panicked");
    }
}

mod failed_pending_open {
    use super::*;
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureRetention, CaptureSlot};
    use busbar_contract::abi::sdk::conn::Host;
    use busbar_contract::abi::sdk::door::{kind_op, Lifecycle, RawSlot};
    use busbar_contract::abi::sdk::life::{self, Life, Opening, Refusal};
    use busbar_contract::abi::sdk::Safe;
    use std::cell::RefCell;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, OnceLock};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    static CLOSES: AtomicUsize = AtomicUsize::new(0);
    static FAILURE_PAIR: OnceLock<Barrier> = OnceLock::new();

    struct Capture;
    impl CaptureHome for Capture {
        fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
            thread_local! {
                static SLOT: RefCell<CaptureSlot> = RefCell::new(CaptureSlot::new());
            }
            SLOT.with(|slot| f(&mut slot.borrow_mut()))
        }
        fn retention() -> &'static CaptureRetention {
            static RETENTION: OnceLock<CaptureRetention> = OnceLock::new();
            RETENTION.get_or_init(CaptureRetention::default)
        }
    }

    struct PendingFailure;
    impl Drop for PendingFailure {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Life for PendingFailure {
        const CANCEL: u32 = 0;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self)
        }
        fn opening(
            &self,
            _: Option<&Host>,
            _: busbar_contract::abi::mechanism::ticket::Ticket,
            parked: Option<Box<dyn std::any::Any + Send + Sync>>,
        ) -> Opening {
            if parked.is_none() {
                Opening::Pending {
                    wake_at_ns: crate::dispatch::now_ns().saturating_add(1_000_000),
                    parked: Box::new(()),
                }
            } else {
                FAILURE_PAIR.get_or_init(|| Barrier::new(2)).wait();
                Opening::Failed(Refusal::failed("connection refused after pending"))
            }
        }
    }
    // Observe cleanup without dereferencing its pointer: the SDK has already
    // freed the failed OPEN's box. Calling the real SDK CLOSE would be UB on
    // the regression path rather than producing a useful assertion failure.
    struct ObserveClose;
    impl RawSlot for ObserveClose {
        type In = InHead;
        type Out = OutHead;
        unsafe fn call(_: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
            CLOSES.fetch_add(1, Ordering::SeqCst);
            Outcome::Ready
        }
    }
    extern "C" fn door() -> &'static Door {
        static DOOR: OnceLock<usize> = OnceLock::new();
        let address = *DOOR.get_or_init(|| {
            let source = actual_store::door();
            // SAFETY: the fixture's admitted Store door contains this complete table.
            let mut ops = unsafe { *source.ops().cast::<busbar_contract::abi::store::v4::Ops>() };
            ops.head.open =
                kind_op::<Lifecycle, Safe<life::Open<PendingFailure>>, Capture, { slot::OPEN }>();
            ops.head.close = kind_op::<Lifecycle, ObserveClose, Capture, { slot::CLOSE }>();
            let ops = Box::leak(Box::new(ops));
            // SAFETY: the immutable complete table and source metadata are permanent.
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..source.parts()
                })
            })) as usize
        });
        // SAFETY: OnceLock retains this immutable permanent fixture allocation.
        unsafe { &*(address as *const Door) }
    }

    #[tokio::test]
    async fn concurrent_resumed_open_failures_do_not_close_sdk_freed_instances() {
        // OPEN tickets use worker zero. Independent loader owners exercise
        // concurrent native failures rather than queuing both behind that worker.
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let other_dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let make_plugin = |dispatcher: &Dispatcher| {
            let row = LinkedRow::of(door).unwrap();
            load_linked::<Store>(&row, bind(dispatcher)).unwrap()
        };
        let limits = Limits {
            descriptor_bytes: 1024,
            output_items: 16,
            output_bytes: 1024,
            decode_bytes: 1024,
        };
        let first =
            LoadedPersistence::open(make_plugin(&dispatcher), dispatcher.clone(), b"{}", limits);
        let second = LoadedPersistence::open(
            make_plugin(&other_dispatcher),
            other_dispatcher.clone(),
            b"{}",
            limits,
        );
        let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            futures::join!(first, second)
        })
        .await
        .expect("both concurrent native opens must resume and fail");
        assert!(first.is_err());
        assert!(second.is_err());
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            2,
            "SDK retires each failed pending box once"
        );
        assert_eq!(
            CLOSES.load(Ordering::SeqCst),
            0,
            "neither native cleanup nor Session::drop may close the freed boxes"
        );
    }
}
