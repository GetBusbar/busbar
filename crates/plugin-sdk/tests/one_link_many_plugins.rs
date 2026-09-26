// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **MANY PLUGINS, ONE LINK** — the frozen dropped-in symbols are defined once, in the SDK.
//!
//! A first-party plugin is `crate-type = ["cdylib", "rlib"]`, and the composition root LINKS the
//! `rlib` half. When each plugin's `export_*!` macro defined its own `#[no_mangle] busbar_abi` (and
//! the other frozen names), two plugins linked into one binary were two strong definitions of each:
//! the release profile's fat LTO refused the second ("Linking globals named 'busbar_abi': symbol
//! multiply defined!" → "failed to load bitcode of module busbar_export_webhook"), so `cargo build -p
//! busbar --release` broke the moment a second export sink was linked. The same two definitions in ONE
//! crate are a compile error ("symbol `busbar_abi` is already defined"), which is what this file is:
//! two plugins in one link, which only compiles when no plugin defines a frozen symbol of its own.
//!
//! It also pins the other half: each plugin's LINKED entry is still its own, and with more than one
//! door registered the SDK's symbols answer as no plugin — never as whichever registered last.

use busbar_plugin::cold::STATUS_PROTOCOL;
use busbar_plugin_sdk::__door;

mod first {
    fn open(_cfg: &str) -> Result<Box<dyn busbar_contract::records::RecordStore>, String> {
        Err("first plugin refuses".into())
    }
    busbar_plugin_sdk::export_store_plugin!(open);
}

mod second {
    fn open(_cfg: &str) -> Result<Box<dyn busbar_contract::records::RecordStore>, String> {
        Err("second plugin refuses".into())
    }
    busbar_plugin_sdk::export_store_plugin!(open);
}

/// Open `entry` with an empty config and return (status, error text).
fn open_through(entry: &busbar_plugin_sdk::ColdEntry) -> (i32, String) {
    let cfg = b"{}";
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut err: *mut u8 = std::ptr::null_mut();
    let mut err_len = 0usize;
    // SAFETY: every pointer is a live local; the buffer is returned through the same entry's `free`.
    unsafe {
        let status = (entry.open)(cfg.as_ptr(), cfg.len(), &mut handle, &mut err, &mut err_len);
        let text = if err.is_null() {
            String::new()
        } else {
            let text =
                String::from_utf8_lossy(std::slice::from_raw_parts(err, err_len)).into_owned();
            (entry.free)(err, err_len);
            text
        };
        (status, text)
    }
}

#[test]
fn each_linked_entry_is_its_own_plugin() {
    let (s1, e1) = open_through(&first::BUSBAR_COLD_ENTRY);
    let (s2, e2) = open_through(&second::BUSBAR_COLD_ENTRY);
    assert_eq!(s1, busbar_plugin::cold::STATUS_ERR);
    assert_eq!(s2, busbar_plugin::cold::STATUS_ERR);
    assert!(e1.contains("first plugin refuses"), "{e1}");
    assert!(e2.contains("second plugin refuses"), "{e2}");
}

#[test]
fn two_doors_in_one_image_answer_as_no_plugin() {
    assert!(
        __door::the_door().is_none(),
        "two registered doors must not resolve to either one"
    );
    assert!(__door::busbar_plugin_kind().is_null());
    // SAFETY: the SDK symbols with no single door never dereference their arguments.
    unsafe {
        assert!(__door::busbar_plane_decl().is_null());
        let status = __door::busbar_open(
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(status, STATUS_PROTOCOL);
    }
}

/// The source half: the only `#[no_mangle]` items in the SDK are the ones in `pub mod __door`. A
/// frozen symbol stamped by an `export_*!` macro would be one per plugin crate again.
#[test]
fn every_frozen_symbol_is_defined_in_the_sdk_door() {
    let src = include_str!("../src/lib.rs");
    let mut owner = "";
    let mut stray = Vec::new();
    for (n, line) in src.lines().enumerate() {
        if line.starts_with("pub mod ") || line.starts_with("macro_rules! ") {
            owner = line;
        }
        if line.trim_start().starts_with("#[no_mangle]") && owner != "pub mod __door {" {
            stray.push(format!("src/lib.rs:{} (inside `{owner}`)", n + 1));
        }
    }
    assert!(
        src.contains("pub mod __door {") && stray.is_empty(),
        "a #[no_mangle] outside `pub mod __door` is defined once per plugin crate: {stray:?}"
    );
}
