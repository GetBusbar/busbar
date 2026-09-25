// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/export.rs`.

use super::*;
use crate::{stage, wire_up_raw};
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
fn hermetic_export_plugin_path() -> Option<std::path::PathBuf> {
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
             must build the in-tree export-example-plugin (checked both the uplifted target \
             dir and target/deps). Refusing to silently skip the routes-query load rules."
        );
    }
    candidate
}

/// Stage the hermetic export example plugin (a genuine `Library`, handle and `close`), then splice
/// in the fake `call`/`free` so the answer to each op is the test's to choose.
fn raw_with_fake_call() -> Option<RawPlugin> {
    let path = hermetic_export_plugin_path()?;
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ADAPTER WITNESS — a v2 (pre-envelope) sink and a v3 (enveloped) one, over the SAME loader.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Which response shape the fake below answers in. `false` = the BARE `ExportResponse` a sink built
/// before DECISIONS #85 returns; `true` = the `{ result, metrics[], diagnostics[] }` envelope.
static ANSWER_ENVELOPED: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// A fake `busbar_call` that answers every op in whichever shape [`ANSWER_ENVELOPED`] selects, so
/// ONE loader can be driven against BOTH generations of the export wire without two fixtures.
unsafe extern "C-unwind" fn shaped_call(
    _handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let asked: ExportRequest =
        serde_json::from_slice(std::slice::from_raw_parts(req, req_len)).expect("decode request");
    let result = match asked {
        ExportRequest::Streams => ExportResponse::Streams(vec![ExportStream::Metrics]),
        ExportRequest::Routes => ExportResponse::Routes(Vec::new()),
        _ => ExportResponse::Delivered,
    };
    let enveloped = *ANSWER_ENVELOPED.lock().unwrap_or_else(|p| p.into_inner());
    let body = if enveloped {
        // A v3 sink that also REPORTS — the whole point of the envelope, and the half a v2 sink
        // structurally cannot express.
        serde_json::to_vec(
            &busbar_plugin::cold::observe::Observations::none()
                .metric(busbar_plugin::cold::observe::PluginMetric::counter(
                    "adapter_witness_total",
                    1.0,
                ))
                .into_envelope(result),
        )
        .expect("encode envelope")
    } else {
        serde_json::to_vec(&result).expect("encode bare")
    };
    let boxed: Box<[u8]> = body.into_boxed_slice();
    let len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    *out_len = len;
    STATUS_OK
}

/// Stage the real cdylib and splice in [`shaped_call`].
fn raw_with_shaped_call() -> Option<RawPlugin> {
    let mut raw = raw_with_fake_call()?;
    raw.call = shaped_call;
    Some(raw)
}

/// **THE ADAPTER WITNESS, and this is its only possible home.** DECISIONS #85 moved the export
/// payload schema to v3 by WIDENING the window to `[2, 3]` rather than moving it — a sink built
/// against the bare response keeps loading and keeps serving. Nothing else in the tree can witness
/// that: no export plugin has ever been published, so the oracle corpus has no
/// `plugins.load|export-*` cell to diverge, and writing one would mean minting a signed v2 artifact
/// into the corpus and pinning its digest.
///
/// So it is witnessed HERE, over the real loader, against BOTH shapes in one test: the same
/// `load_export_from_bytes` path, the same `transport_call`, the same `DynExport` — only the bytes
/// the sink answers in differ.
#[test]
fn a_pre_envelope_v2_sink_and_an_enveloped_v3_sink_both_load_and_serve() {
    for enveloped in [false, true] {
        *ANSWER_ENVELOPED.lock().unwrap_or_else(|p| p.into_inner()) = enveloped;
        let Some(raw) = raw_with_shaped_call() else {
            eprintln!("skip: export example plugin cdylib not built (run under --workspace)");
            return;
        };
        let shape = if enveloped { "v3 enveloped" } else { "v2 bare" };
        let sink = export_from_raw(raw, "adapter-witness")
            .unwrap_or_else(|e| panic!("a {shape} sink must load: {e}"));
        // It LOADS: the load-time `streams` and `routes` queries both decoded.
        assert_eq!(sink.streams(), &[ExportStream::Metrics], "{shape}");
        assert!(sink.routes().is_empty(), "{shape}");
        // And it SERVES: a delivery round-trips to an ack.
        sink.deliver(ExportStream::Metrics, &serde_json::json!({"n": 1}))
            .unwrap_or_else(|e| panic!("a {shape} sink must serve a delivery: {e}"));
    }
    *ANSWER_ENVELOPED.lock().unwrap_or_else(|p| p.into_inner()) = false;
}

/// THE TWO SHAPES ARE DISJOINT, which is what makes the probe total rather than a guess: every
/// response variant is externally tagged by its Rust variant name and not one of them is named
/// `result`, so a bare response can never be mis-read as an envelope and an envelope can never be
/// mis-read as a bare response.
///
/// Asserted on the BYTES, because that is where the property actually lives — a decoder that got
/// this wrong would still typecheck.
#[test]
fn a_bare_response_and_an_enveloped_one_cannot_be_confused() {
    let bare = serde_json::to_vec(&ExportResponse::Streams(vec![ExportStream::Metrics]))
        .expect("encode bare");
    let enveloped = serde_json::to_vec(&busbar_plugin::cold::observe::Envelope::bare(
        ExportResponse::Streams(vec![ExportStream::Metrics]),
    ))
    .expect("encode envelope");
    assert_ne!(bare, enveloped);
    // The bare form has no `result` key, so the envelope decode refuses it...
    assert!(
        serde_json::from_slice::<busbar_plugin::cold::observe::Envelope<ExportResponse>>(&bare)
            .is_err()
    );
    // ...and the enveloped form is not a variant name, so the bare decode refuses that.
    assert!(serde_json::from_slice::<ExportResponse>(&enveloped).is_err());
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE `status` OP — the host's pull at exposition time, folded down the ONE observability path.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// How the fake below answers `status`: `STATUS_OK` with one gauge, or the out-of-band status a
/// sink built before the op answers with.
static STATUS_ANSWER: std::sync::Mutex<i32> = std::sync::Mutex::new(STATUS_OK);

/// A fake `busbar_call` that answers `streams`/`routes` like a healthy sink and `status` per
/// [`STATUS_ANSWER`].
unsafe extern "C-unwind" fn status_call(
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
            serde_json::to_vec(&ExportResponse::Streams(vec![ExportStream::Logs])).unwrap(),
        ),
        ExportRequest::Routes => (
            STATUS_OK,
            serde_json::to_vec(&ExportResponse::Routes(Vec::new())).unwrap(),
        ),
        ExportRequest::Status => match *STATUS_ANSWER.lock().unwrap_or_else(|p| p.into_inner()) {
            STATUS_OK => (
                STATUS_OK,
                serde_json::to_vec(&ExportResponse::Status {
                    metrics: vec![serde_json::json!({
                        "name": "sink_queue_depth", "type": "gauge", "value": 7.0
                    })],
                    diagnostics: Vec::new(),
                })
                .unwrap(),
            ),
            other => (other, b"unknown variant `status`".to_vec()),
        },
        _ => (
            STATUS_OK,
            serde_json::to_vec(&ExportResponse::Delivered).unwrap(),
        ),
    };
    let boxed: Box<[u8]> = body.into_boxed_slice();
    let len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    *out_len = len;
    status
}

/// A sink that answers `status` has its report FOLDED — through the loader's one observer seam,
/// under the host-assigned name and the `export` kind — which is how a plugin sink contributes to
/// the host's `/metrics` exposition between deliveries. A sink that predates the op answers
/// `STATUS_UNSUPPORTED`: that is "nothing to report", not a fault, and folds nothing.
#[test]
fn status_folds_what_the_sink_reports_and_an_older_sink_reports_nothing() {
    let Some(mut raw) = raw_with_fake_call() else {
        eprintln!("skip: export example plugin cdylib not built (run under --workspace)");
        return;
    };
    raw.call = status_call;
    let sink = export_from_raw(raw, "status-witness").expect("load");
    let _guard = crate::observe::testing::exclusive();

    *STATUS_ANSWER.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_OK;
    sink.status_report().expect("a sink that answers status");
    let folds: Vec<_> = crate::observe::testing::folds()
        .into_iter()
        .filter(|(who, ..)| who == "fake-call-export")
        .collect();
    assert_eq!(folds.len(), 1, "one report, one fold: {folds:?}");
    let (_, kind, metrics, diagnostics) = &folds[0];
    assert_eq!(kind, abi_kind::EXPORT);
    assert_eq!(metrics[0]["name"], "sink_queue_depth");
    assert!(diagnostics.is_empty());

    *STATUS_ANSWER.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_UNSUPPORTED;
    let older = sink.status_report();
    *STATUS_ANSWER.lock().unwrap_or_else(|p| p.into_inner()) = STATUS_OK;
    older.expect("a sink that predates the status op has nothing to report — not a fault");
    assert_eq!(
        crate::observe::testing::folds()
            .into_iter()
            .filter(|(who, ..)| who == "fake-call-export")
            .count(),
        1,
        "an unsupported status folds nothing"
    );
}
