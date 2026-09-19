// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/export.rs`.

use super::*;
use busbar_plugin::cold::{export::ExportAck, STATUS_OK, STATUS_PANIC, STATUS_UNSUPPORTED};
use std::ffi::c_void;

/// The status the fake `busbar_call` answers the `Routes` op with. `Streams` is always answered
/// well, so a load that fails can only have failed on the routes query.
static ROUTES_STATUS: std::sync::Mutex<i32> = std::sync::Mutex::new(STATUS_OK);

/// The acknowledgement the fake `busbar_call` answers `Deliver` with — the test's to choose, so a
/// cell can drive a sink that REFUSES and watch what the loader makes of it.
static DELIVER_ACK: std::sync::Mutex<ExportAck> = std::sync::Mutex::new(ExportAck::Received);

/// Every cell in this file drives the ONE fake `busbar_call` through process-global answer knobs,
/// so they take turns. Held for the whole of each cell, not just the mutation: a cell that set its
/// answer and then loaded while a sibling was mid-load would read the sibling's.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            serde_json::to_vec(&ExportResponse::Delivered(
                *DELIVER_ACK.lock().unwrap_or_else(|p| p.into_inner()),
            ))
            .expect("encode ack"),
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
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
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
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
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

/// A DLOPEN'd SINK THAT REFUSES IS `Retry` THROUGH THE LOADER, and never `Received`.
///
/// Red before ABI v3: `deliver` returned `Result<(), String>` and answered `Ok(())` to any
/// `Delivered` reply, so a sink that took a record and put it nowhere was indistinguishable HERE
/// from one that took it — the caller was told a delivery happened and had no way to learn
/// otherwise. The word is now the SINK'S, relayed, and this cell drives both answers through the
/// same seam so the relay cannot be a constant.
#[test]
fn a_dlopend_sink_that_refuses_is_retry_through_the_loader() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    let Some(raw) = raw_with_fake_call() else {
        eprintln!("skip: the reference sink cdylib is not built (run under --workspace)");
        return;
    };
    let sink = export_from_raw(raw, "fake-call-export").expect("the sink loads");

    *DELIVER_ACK.lock().unwrap_or_else(|p| p.into_inner()) = ExportAck::Retry;
    let refused = sink.deliver(ExportStream::Metrics, &serde_json::json!({"reqs": 1}));
    *DELIVER_ACK.lock().unwrap_or_else(|p| p.into_inner()) = ExportAck::Received;
    let took = sink.deliver(ExportStream::Metrics, &serde_json::json!({"reqs": 1}));

    assert_eq!(
        refused,
        Ok(ExportAck::Retry),
        "a sink that took the record nowhere is Retry all the way up"
    );
    assert_eq!(
        took,
        Ok(ExportAck::Received),
        "and a sink that took it is Received, so the relay is not a constant"
    );
}
