// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Loader-side assertions on the STATUS a panicking plugin actually returns.
//!
//! `hook_tests.rs` already proves a panicking gate surfaces as a fail-closed `Err`. That is the
//! behaviour the engine depends on, but it is satisfied by SEVERAL different statuses, so it cannot
//! tell whether the panic arrived as the distinct `STATUS_PANIC` or as a bare `STATUS_PROTOCOL` —
//! and the difference is load-bearing. The loader keys its safe-default fallback on the
//! unsupported-shaped statuses, and a caught panic must never be able to reach that door. These
//! tests pin the status itself, over the real dlopen seam, against the real panic fixture.

use super::*;

/// Drive the panic fixture across the RAW transport, so the classification the loader made is
/// observable rather than already flattened into a policy-level `Err`.
#[test]
fn panicking_plugin_returns_status_panic_with_a_body() {
    let Some(path) = tests::hook_plugin_path() else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read hook cdylib");
    let (lib, staged) =
        crate::stage::load_library_from_bytes(&bytes, "test-hook").expect("stage cdylib");
    let raw = crate::wire_up_raw(
        lib,
        r#"{"panic_decide": true}"#,
        "test-hook".to_string(),
        crate::abi_kind::HOOK,
        "hook",
        Some(staged),
    )
    .expect("load hook plugin over the ABI");

    let err = raw
        .transport_call_status::<_, serde_json::Value>(&serde_json::json!({
            "op": "decide",
            "payload": { "request": {}, "candidates": [] },
        }))
        .expect_err("a panicking gate must not return a decoded reply");

    // A caught panic is a FAULT, never `Unsupported` — the only kind that opens the loader's
    // safe-default fallback — and never the bare `Protocol` shape either.
    assert!(
        matches!(err.kind, crate::TransportErrorKind::Fault),
        "a caught plugin panic must classify as Fault, not the unsupported/protocol shapes: {}",
        err.message
    );

    // And it arrives with a BODY. An empty out-buffer is the caller-protocol / pre-`STATUS_PANIC`
    // shape, and the loader would then have had to synthesize "call failed (status N)" itself. The
    // SDK's own panic marker in the message is the proof that the plugin wrote one.
    assert!(
        err.message.contains("plugin panicked"),
        "a caught plugin panic must carry the SDK's panic body, got: {}",
        err.message
    );
    assert!(
        !err.message.contains("call failed (status"),
        "an empty body would have forced the loader to synthesize a message: {}",
        err.message
    );
}

/// Pin the accepted `export` payload-schema window. The comment beside that entry described it as
/// v1 long after 1.5.3 removed the `audit` stream and moved it to v2, so a reader checking whether
/// a v1 sink would still load got the wrong answer from the only documentation there was. A const
/// assertion cannot drift with the prose: if the window ever moves, this fails to COMPILE.
/// The compile-time half: the CEILING the window is BUILT from. `supported_abi` itself matches on a
/// `&str` kind and so cannot be a `const fn`, but the constant it reads can be pinned here, and a
/// change to it fails the build rather than a test.
///
/// 2 -> 3 (DECISIONS #85): the ceiling moved when an export response became
/// `Envelope<ExportResponse>` — `{ result, metrics[], diagnostics[] }` — so a sink can report the
/// metrics it produced and the diagnostics it raised. This assertion did exactly its job: it failed
/// the BUILD, not a test, on the day the window moved.
const _: () = assert!(busbar_plugin::cold::export::EXPORT_ABI_VERSION == 3);

/// The runtime half: the window `export` actually resolves to.
///
/// `[2, 3]`, and the FLOOR is the load-bearing half. v1 is still refused (1.5.3 removed the `audit`
/// stream, so a v1 sink declares a stream the engine cannot route), but v2 is NOT: a sink built
/// before the observability envelope answers a bare `ExportResponse` and the loader's decoder reads
/// both shapes, so #85 widened the window rather than moving it. Refusing v2 here would have been
/// the one outcome a migration may not produce — a working deployment that stops loading on upgrade
/// — in exchange for nothing, since no published sink exists to be protected from the old shape.
#[test]
fn export_abi_window_admits_the_pre_envelope_sink_and_the_enveloped_one() {
    assert_eq!(
        crate::registry::supported_abi("export"),
        &[2, 3],
        "v1 must not load (1.5.3 removed the `audit` stream); v2 (bare response) and v3 (the #85 \
         envelope) must both load"
    );
}
