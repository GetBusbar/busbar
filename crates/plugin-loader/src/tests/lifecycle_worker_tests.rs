// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{RecordStore, VirtualKey};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;

#[path = "actual_store.rs"]
mod actual_store;

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x7e5f,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
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

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: "t".to_string(),
        enabled: true,
        ..Default::default()
    }
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
                        let s = LoadedStore::open(p, d, &actual_store::settings(), mint)
                            .unwrap_or_else(|e| panic!("round {round}: it opens: {e}"));
                        let id = format!("k{round}");
                        s.put_key(&key(&id)).expect("put");
                        assert_eq!(
                            s.get_key(&id).expect("get").map(|k| k.id),
                            Some(id),
                            "round {round}"
                        );
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
