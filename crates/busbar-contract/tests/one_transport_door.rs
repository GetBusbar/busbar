// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE TRANSPORT IMAGE, THE SHARED DOOR** — a transport registers through the same frozen symbols
//! every other plugin kind does.
//!
//! A transport used to define `busbar_abi`, `busbar_plugin_kind` and `busbar_transport_decl` in its
//! own crate. Those were a second definition of the handshake the plugin SDK defines once, so a link
//! that held a transport's door beside any SDK-built plugin was refused under fat LTO ("symbol
//! multiply defined"), and outside LTO kept whichever definition the linker met first. Since the
//! #84 merge the door is `busbar-contract`'s: `export_transport!` registers the transport's decl as
//! the image's ONE door, and the frozen symbols answer through it — exactly as a store's or a
//! plane's do. This test binary holds exactly one transport, as a dropped-in `cdylib` does.

use busbar_contract::abi::sdk::__door;

/// The decl this image's transport publishes. The door hands back its ADDRESS and never reads it,
/// so any `'static` stands in for the published `#[repr(C)]` layout here.
static DECL: [u8; 8] = *b"BUSPLANE";

busbar_contract::export_transport!(DECL);

#[test]
fn the_frozen_symbols_answer_through_the_registered_transport() {
    assert!(
        __door::the_door().is_some(),
        "the constructor registered no door"
    );

    let kind = __door::busbar_plugin_kind();
    assert!(!kind.is_null());
    // SAFETY: a non-null kind is the door's `'static` NUL-terminated string.
    let kind = unsafe { std::ffi::CStr::from_ptr(kind.cast()) };
    assert_eq!(
        kind.to_str().unwrap(),
        busbar_contract::abi::cold::kind::TRANSPORT
    );
    assert_eq!(
        __door::busbar_abi(),
        busbar_contract::abi::cold::TRANSPORT_VERSION
    );

    // SAFETY: the door symbols never dereference anything for a transport image.
    unsafe {
        assert_eq!(
            __door::busbar_transport_decl().cast::<u8>(),
            std::ptr::addr_of!(DECL).cast::<u8>(),
            "busbar_transport_decl answers the registered transport's own decl"
        );
        assert!(
            __door::busbar_plane_decl().is_null(),
            "a transport image is not a plane"
        );
        assert_eq!(
            __door::busbar_open(
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            busbar_contract::abi::cold::STATUS_PROTOCOL,
            "a transport image speaks no cold-lane call"
        );
    }
}
