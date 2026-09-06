// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/export.rs`.

use super::*;
use busbar_plugin::cold::{STATUS_OK, STATUS_PANIC, STATUS_UNSUPPORTED};
use std::ffi::c_void;

/// The status the fake `busbar_call` answers the `Routes` op with. `Streams` is always answered
/// well, so a load that fails can only have failed on the routes query.
static ROUTES_STATUS: std::sync::Mutex<i32> = std::sync::Mutex::new(STATUS_OK);

/// A fake `busbar_call` that answers `Streams` with the empty stream list and `Routes` with
/// whatever status the test chose. Mimics the plugin side of the allocation contract: the plugin
/// allocates, the engine frees through `busbar_free`.
unsafe extern "C-unwind" fn fake_call(
    _handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let asked: ExportRequest =
        serde_json::from_slice(std::slice::from_raw_parts(req, req_len)).expect("decode request");
    let (status, body) = match asked {
        ExportRequest::Streams => (
            STATUS_OK,
            serde_json::to_vec(&ExportResponse::Streams(Vec::new())).expect("encode streams"),
        ),
        ExportRequest::Routes => {
            let status = *ROUTES_STATUS.lock().unwrap_or_else(|p| p.into_inner());
            if status == STATUS_OK {
                (
                    STATUS_OK,
                    serde_json::to_vec(&ExportResponse::Routes(Vec::new())).expect("encode routes"),
                )
            } else {
                (status, b"the plugin did not answer".to_vec())
            }
        }
        _ => (
            STATUS_OK,
            serde_json::to_vec(&ExportResponse::Delivered).expect("encode ack"),
        ),
    };
    let boxed: Box<[u8]> = body.into_boxed_slice();
    let len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    *out_len = len;
    status
}

/// Free a buffer `fake_call` allocated.
unsafe extern "C-unwind" fn fake_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// Locate the hermetic `busbar-export-example-plugin` cdylib, checking BOTH the uplifted
/// `<profile_dir>/<name>` copy and the raw `<profile_dir>/deps/<name>` compiler output (a scoped
/// `cargo test -p busbar-plugin-loader` only produces the latter). Under CI a missing cdylib is a
/// hard failure rather than a silent skip, so this coverage of the load seam cannot quietly vanish.
fn export_example_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename("busbar_export_example_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the export example plugin cdylib is not built under CI: `cargo test --workspace` \
             must build busbar_export_example_plugin (checked both the uplifted target dir and \
             target/deps). Refusing to silently skip the routes-query load rules."
        );
    }
    candidate
}

/// Stage the hermetic export example plugin (a genuine `Library`, handle and `close`), then splice
/// in the fake `call`/`free` so the answer to each op is the test's to choose.
fn raw_with_fake_call() -> Option<RawPlugin> {
    let path = export_example_plugin_path()?;
    let bytes = std::fs::read(&path).expect("read the export example plugin cdylib");
    let (lib, staged) = stage::load_library_from_bytes(&bytes, "fake-call-export")
        .expect("stage the export example plugin cdylib for the fake-call harness");
    let mut raw = wire_up_raw(
        lib,
        "{}",
        "fake-call-export".to_string(),
        abi_kind::EXPORT,
        abi_kind::EXPORT,
        Some(staged),
    )
    .expect("wire up raw");
    raw.call = fake_call;
    raw.free = fake_free;
    Some(raw)
}

/// A sink that PANICS on the routes query has not said "I carry no HTTP surface" — it has said
/// nothing at all, and loading it as a healthy sink with an empty route table would mount a plugin
/// whose gates nobody has heard from. The load fails and names the plugin.
#[test]
fn a_panic_on_the_routes_query_fails_the_load() {
    let Some(raw) = raw_with_fake_call() else {
        eprintln!("skip: export example plugin cdylib not built (run under --workspace)");
        return;
    };
    *ROUTES_STATUS.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_PANIC;
    let loaded = export_from_raw(raw, "fake-call-export");
    *ROUTES_STATUS.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_OK;
    let Err(message) = loaded else {
        panic!("a panicking routes query must not load as a healthy sink with no routes");
    };
    assert!(
        message.contains("fake-call-export"),
        "the load failure must name the plugin, said: {message}"
    );
}

/// A sink built against an older SDK cannot decode the routes op and says so. That IS "no HTTP
/// surface", and it keeps loading with an empty route table exactly as it did before the op
/// existed.
#[test]
fn an_unsupported_routes_query_loads_with_no_routes() {
    let Some(raw) = raw_with_fake_call() else {
        eprintln!("skip: export example plugin cdylib not built (run under --workspace)");
        return;
    };
    *ROUTES_STATUS.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_UNSUPPORTED;
    let loaded = export_from_raw(raw, "fake-call-export");
    *ROUTES_STATUS.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_OK;
    let sink = loaded.expect("a sink that predates the routes op still loads");
    assert!(
        sink.routes().is_empty(),
        "a sink that cannot answer the routes op carries no HTTP surface"
    );
}
