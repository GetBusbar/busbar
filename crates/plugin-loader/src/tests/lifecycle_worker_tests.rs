// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN'S LIFECYCLE RUNS ONLY ON THE PERMANENT FFI WORKERS (`crate::ffi_thread`), whoever calls
//! it: a dispatcher worker, or a ticket-less caller thread that exits right after.
//!
//! A thread that runs plugin code and exits after the plugin's library is unmapped runs the
//! plugin's Rust thread-exit cleanup out of unmapped memory and dies on SIGSEGV. `open` is where a
//! plugin first touches its thread-locals and `close` runs its `Drop`, so both, with the rest of
//! the lifecycle and the door function, cross on a worker that never exits.
//!
//! RED ARM: [`lifecycle_on_permanent_workers_open_and_close_from_a_throwaway_thread`] calls `open`
//! and `close` ticket-less from a thread that then exits. Before the routing, both crossed on that
//! thread and the debug assertion at the FFI call
//! ([`lifecycle_on_permanent_workers_the_assertion_trips_off_the_workers`] proves it trips there)
//! panicked it.

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

fn open_frame(settings: &'static [u8]) -> Frame<OpenIn, OpenOut> {
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

/// The build's store, compiled in, opened and closed TICKET-LESS from a thread that exits right
/// after: both answer READY, and neither enters plugin code on that thread (in a debug build the
/// FFI call's assertion would panic it, and the join would fail).
#[test]
fn lifecycle_on_permanent_workers_open_and_close_from_a_throwaway_thread() {
    let outcomes = std::thread::Builder::new()
        .name("throwaway".into())
        .spawn(|| {
            let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
            let row = LinkedRow::of(crate::both_ways::store_fixture::door)
                .expect("the store states its Statement");
            let plugin = load_linked::<Store>(&row, bind(&d)).expect("the door loads");
            let opened = plugin.call(slot::OPEN, &mut open_frame(b"{}")).outcome;
            let mut c: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
            let closed = plugin.call(slot::CLOSE, &mut c).outcome;
            (opened, closed)
        })
        .expect("spawn")
        .join()
        .expect("no lifecycle slot entered plugin code off a permanent FFI worker");
    assert_eq!(outcomes, (Outcome::Ready, Outcome::Ready));
}

/// The assertion at the FFI call is real: a lifecycle slot entered on a thread that is not a
/// permanent worker panics it, naming the slot; the same slot entered on a worker does not.
#[cfg(debug_assertions)]
#[test]
fn lifecycle_on_permanent_workers_the_assertion_trips_off_the_workers() {
    use busbar_contract::abi::mechanism::call::RawOutcome;

    use super::enter_lifecycle;

    extern "C" fn a_slot(
        _: *mut std::os::raw::c_void,
        _: *const std::os::raw::c_void,
        _: *mut std::os::raw::c_void,
    ) -> RawOutcome {
        RawOutcome(Outcome::Ready as u8)
    }
    /// `a_slot` entered as lifecycle slot `open`, on the calling thread.
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

/// THE STRESS: the store DROPPED IN (its `cdylib`), loaded, opened on a dispatcher worker, used,
/// closed from the caller and unloaded 200 times across 8 caller threads that exit as they finish,
/// each with dispatchers of their own. Every round answers, and no thread dies.
#[test]
fn lifecycle_on_permanent_workers_dropped_store_200_rounds() {
    const ROUNDS: usize = 200;
    const THREADS: usize = 8;
    let path = Arc::new(crate::both_ways::example_cdylib("store_v3_door"));
    let stated = rendering_of(crate::both_ways::store_fixture::door)
        .expect("the store renders its Statement");
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
                        let s = LoadedStore::open(p, d, b"{}", mint)
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
