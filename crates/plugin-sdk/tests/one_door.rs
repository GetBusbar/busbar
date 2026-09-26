// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE IMAGE, ONE DOOR** — the SDK's frozen symbols answer through the one plugin that registered.
//!
//! This test binary holds exactly one plugin, as a dropped-in `cdylib` does. Its load-time
//! constructor registered its door before `main`; the frozen symbols the loader looks up
//! (`busbar_plugin_kind`, `busbar_open`, `busbar_free`, `busbar_plane_decl`) must reach that
//! plugin's own boundary, exactly as its linked `BUSBAR_COLD_ENTRY` does.

use busbar_plugin::cold::STATUS_ERR;
use busbar_plugin_sdk::__door;

fn open(_cfg: &str) -> Result<Box<dyn busbar_api::Store>, String> {
    Err("the one plugin refuses".into())
}
busbar_plugin_sdk::export_store_plugin!(open);

#[test]
fn the_frozen_symbols_answer_through_the_registered_plugin() {
    assert!(
        __door::the_door().is_some(),
        "the constructor registered no door"
    );

    let kind = __door::busbar_plugin_kind();
    assert!(!kind.is_null());
    // SAFETY: a non-null kind is the plugin's `'static` NUL-terminated string.
    let kind = unsafe { std::ffi::CStr::from_ptr(kind.cast()) };
    assert_eq!(kind.to_str().unwrap(), busbar_plugin::cold::kind::STORE);

    let cfg = b"{}";
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut err: *mut u8 = std::ptr::null_mut();
    let mut err_len = 0usize;
    // SAFETY: every pointer is a live local; the error buffer goes back through `busbar_free`.
    unsafe {
        let status =
            __door::busbar_open(cfg.as_ptr(), cfg.len(), &mut handle, &mut err, &mut err_len);
        assert_eq!(status, STATUS_ERR);
        assert!(handle.is_null());
        let text = String::from_utf8_lossy(std::slice::from_raw_parts(err, err_len)).into_owned();
        __door::busbar_free(err, err_len);
        assert!(text.contains("the one plugin refuses"), "{text}");
        assert!(
            __door::busbar_plane_decl().is_null(),
            "a store image is not a plane"
        );
    }

    // The same boundary as the linked door.
    // SAFETY: `kind` is the boundary function the macro emitted.
    let linked = unsafe { std::ffi::CStr::from_ptr((BUSBAR_COLD_ENTRY.kind)().cast()) };
    assert_eq!(linked, kind);
}
