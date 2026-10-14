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
//! It also pins the other half: each plugin's LINKED door is still its own, and with more than one
//! door registered the SDK's symbols answer as no plugin — never as whichever registered last.

use busbar_contract::abi::sdk::__door;

/// Two planes' doors in one link. Each registers through the SDK's shared door, so two of them in
/// one link define no frozen symbol twice. (Transports registered the same way until the HOT
/// transport lane was deleted, row 84: a transport now serves its memory-ABI door.)
mod first {
    pub(super) static DECL: busbar_contract::abi::hot::PlaneDecl =
        busbar_contract::abi::hot::PlaneDecl::STUB;
    busbar_contract::export_plane!(DECL);
}

mod second {
    pub(super) static DECL: busbar_contract::abi::hot::PlaneDecl =
        busbar_contract::abi::hot::PlaneDecl::STUB;
    busbar_contract::export_plane!(DECL);
}

/// The decl a module's door hands back.
fn decl_of(door: &__door::Door) -> *const u8 {
    match door {
        __door::Door::Plane(decl) => std::ptr::addr_of!(**decl).cast(),
    }
}

#[test]
fn each_linked_door_is_its_own_plugin() {
    assert_eq!(
        decl_of(&first::__BUSBAR_DOOR),
        std::ptr::addr_of!(first::DECL).cast::<u8>()
    );
    assert_eq!(
        decl_of(&second::__BUSBAR_DOOR),
        std::ptr::addr_of!(second::DECL).cast::<u8>()
    );
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
    }
}

/// The source half: the only `#[no_mangle]` items in the SDK are the ones in `pub mod __door`. A
/// frozen symbol stamped by an `export_*!` macro would be one per plugin crate again.
#[test]
fn every_frozen_symbol_is_defined_in_the_sdk_door() {
    let src = include_str!("../src/abi/sdk/mod.rs");
    let mut owner = "";
    let mut stray = Vec::new();
    for (n, line) in src.lines().enumerate() {
        if line.starts_with("pub mod ") || line.starts_with("macro_rules! ") {
            owner = line;
        }
        if line.trim_start().starts_with("#[no_mangle]") && owner != "pub mod __door {" {
            stray.push(format!("src/abi/sdk/mod.rs:{} (inside `{owner}`)", n + 1));
        }
    }
    assert!(
        src.contains("pub mod __door {") && stray.is_empty(),
        "a #[no_mangle] outside `pub mod __door` is defined once per plugin crate: {stray:?}"
    );
}
