// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The configuration-time kind ops never enter plugin code on the calling thread.
//!
//! A crossing that enters an image inline arms that image's own `std` thread-exit key on the
//! caller's thread; a caller that retires after the image is unloaded then jumps into the hole
//! from `__nptl_deallocate_tsd` (`ffi_thread`). The secret checker's `check` crashed that way
//! (`secret_calls_tests::a_dropped_checker_never_enters_plugin_code_on_the_checking_thread`).
//! Transport `locate` before open and export `check` are the same shape — per load or per
//! configuration check, not per request — so they are confined to the permanent FFI workers too.
//! The crash itself fires only at thread exit and races process exit, so each test counts the
//! crossings that entered plugin code on the calling thread instead.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::transport::{slot as transport_slot, LocateIn, LocateOut};

use crate::dispatch::kinds::export::Export;
use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::lifecycle::{blob, open_frame};
use crate::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow,
    NoSink,
};

fn inline() -> usize {
    crate::dispatch::plugin::INLINE_CROSSINGS.with(std::cell::Cell::get)
}

fn bind(dispatcher: &Dispatcher, label: &str, conns: ConnTable) -> Bind {
    Bind {
        instance: Arc::from(label),
        max_inflight_cap: 4,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns,
    }
}

fn dispatcher() -> Dispatcher {
    Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    )
}

#[test]
fn a_transport_locate_before_open_never_enters_plugin_code_on_the_calling_thread() {
    std::thread::spawn(|| {
        let d = dispatcher();
        let row = LinkedRow::of(crate::neutral_transport::door).expect("the door states itself");
        let plugin =
            load_linked::<Transport>(&row, bind(&d, "transport.locate", ConnTable::NoNeeds))
                .expect("the linked transport loads");
        assert!(
            !plugin.is_open(),
            "locate is checked on an unopened instance"
        );
        let target = "witness.example:443";
        let mut authority = [0_u8; 256];
        let mut name = [0_u8; 256];
        // SAFETY: plain C data; all-zero is a valid value of each field.
        let mut input: LocateIn = unsafe { std::mem::zeroed() };
        input.head = in_head();
        input.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
        input.authority_buf = authority.as_mut_ptr();
        input.authority_cap = authority.len();
        input.name_buf = name.as_mut_ptr();
        input.name_cap = name.len();
        // SAFETY: as above.
        let mut output: LocateOut = unsafe { std::mem::zeroed() };
        output.head = out_head();
        let mut frame = Frame::new(input, output);
        let before = inline();
        let crossings = plugin
            .inner
            .crossings
            .load(std::sync::atomic::Ordering::SeqCst);
        let called = plugin.call(transport_slot::LOCATE, &mut frame);
        assert_ne!(called.outcome, Outcome::Fault, "{:?}", called.error);
        assert!(
            plugin
                .inner
                .crossings
                .load(std::sync::atomic::Ordering::SeqCst)
                > crossings,
            "locate reached the plugin"
        );
        assert_eq!(
            inline(),
            before,
            "a pre-open locate ran on the caller thread, not a permanent FFI worker"
        );
    })
    .join()
    .expect("the locating thread retires");
}

#[test]
fn an_export_check_never_enters_plugin_code_on_the_calling_thread() {
    std::thread::spawn(|| {
        let d = dispatcher();
        let row = LinkedRow::of(crate::neutral_export::door).expect("the door states itself");
        let plugin = load_linked::<Export>(&row, bind(&d, "export.check", ConnTable::Probe))
            .expect("the linked export loads");
        let settings = b"{}";
        let opened = plugin.call(
            busbar_contract::abi::mechanism::lifecycle::slot::OPEN,
            &mut open_frame(blob(
                settings,
                busbar_contract::abi::mechanism::call::BLOB_JSON,
                0,
            )),
        );
        assert_eq!(opened.outcome, Outcome::Ready, "{:?}", opened.error);
        let before = inline();
        let crossings = plugin
            .inner
            .crossings
            .load(std::sync::atomic::Ordering::SeqCst);
        let checked = crate::export_door::check(
            &plugin,
            busbar_contract::abi::export::CHECK_PHASE_LIMITS,
            &[],
        );
        assert!(checked.is_ok(), "{checked:?}");
        assert!(
            plugin
                .inner
                .crossings
                .load(std::sync::atomic::Ordering::SeqCst)
                > crossings,
            "check reached the plugin"
        );
        assert_eq!(
            inline(),
            before,
            "an export check ran on the caller thread, not a permanent FFI worker"
        );
        crate::dispatch::lifecycle::close(&plugin);
    })
    .join()
    .expect("the checking thread retires");
}
