// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATIONS-AXIS SOURCE WITNESS — relocated from core `handlers/tests/dispatch_tests.rs`
//! (money-path Phase 3-4 C) WITH the forward engine it scans: the engine now lives under
//! `busbar-llm/src/engine/`, so the include-witness reads those files instead of the deleted
//! `busbar-core/src/proxy/*`.

/// The load-bearing invariant of the operations axis: the forward engine branches on the
/// *capabilities* an OperationHandler declares, never on an operation's *identity*. If someone adds
/// `if op.name() == "embeddings"` or `match op.name() { ... }` to the engine, chat stops being
/// just operation #1 and the "add an operation without touching the engine" property is lost.
/// (`op.name()` used as a value — a tracing span field — is fine; only comparisons/matches are
/// forbidden.)
#[test]
fn engine_never_branches_on_operation_identity() {
    crate::testkit::install_test_seams();
    // Scan EVERY file of the forward engine (the module split must not open a blind spot): the engine
    // hub, each area-module, and the engine core + failover walk.
    let engine_files = [
        ("src/engine/mod.rs", include_str!("../mod.rs")),
        ("src/engine/wire.rs", include_str!("../wire.rs")),
        ("src/engine/hooks.rs", include_str!("../hooks.rs")),
        ("src/engine/select.rs", include_str!("../select.rs")),
        ("src/engine/usage.rs", include_str!("../usage.rs")),
        ("src/engine/egress.rs", include_str!("../egress.rs")),
        (
            "src/engine/response_body.rs",
            include_str!("../response_body.rs"),
        ),
        ("src/engine/pipeline.rs", include_str!("../pipeline.rs")),
        (
            "src/engine/attempt/mod.rs",
            include_str!("../attempt/mod.rs"),
        ),
        (
            "src/engine/attempt/assemble.rs",
            include_str!("../attempt/assemble.rs"),
        ),
        (
            "src/engine/attempt/send.rs",
            include_str!("../attempt/send.rs"),
        ),
        (
            "src/engine/attempt/classify.rs",
            include_str!("../attempt/classify.rs"),
        ),
        (
            "src/engine/attempt/respond.rs",
            include_str!("../attempt/respond.rs"),
        ),
        (
            "src/engine/attempt/buffered.rs",
            include_str!("../attempt/buffered.rs"),
        ),
        (
            "src/engine/exhaustion/mod.rs",
            include_str!("../exhaustion/mod.rs"),
        ),
        (
            "src/engine/exhaustion/queue.rs",
            include_str!("../exhaustion/queue.rs"),
        ),
        (
            "src/engine/exhaustion/fallback.rs",
            include_str!("../exhaustion/fallback.rs"),
        ),
        (
            "src/engine/exhaustion/least_bad.rs",
            include_str!("../exhaustion/least_bad.rs"),
        ),
    ];
    let forbidden = [
        "op.name() ==",
        "op.name()==",
        "== op.name()",
        "==op.name()",
        "match op.name()",
    ];
    for (file, engine) in engine_files {
        for pat in forbidden {
            assert!(
                !engine.contains(pat),
                "{file} contains a forbidden operation-identity branch (`{pat}`). The \
                 engine must read capabilities off the OperationHandler, never branch on op.name()."
            );
        }
    }
}

/// ONE SHELL AROUND THE ENGINE, NOT TWO.
///
/// `forward_with_pool_parsed` is the shell that wraps the dispatch core
/// (`forward_with_pool_parsed_inner`): it stamps the per-request correlation id, opens the `forward`
/// span, captures the completion shape before the parsed body moves into the core, times the
/// `WrapSetup` profiler stage, and fires the response-stage taps once the head is known. Every one
/// of those is a STEP, and a step is served once.
///
/// When the LLM plane was switched onto the composition root, the Route step re-implemented that
/// shell beside the original and called the dispatch core directly — the same span, the same
/// `next_request_id`, the same completion-shape capture, the same `fire_stage_taps` projection,
/// written twice. Two copies of one step is exactly the shape that drifts, and it already had:
/// the copy omitted `profile::Stage::WrapSetup`, so the SHIPPED leg (`root-llm`, default on)
/// reported zero samples for a stage the legacy leg timed, and no oracle cell could see it because
/// the profiler is not on the wire.
///
/// The invariant that makes that class of drift impossible: the dispatch core has exactly ONE
/// caller, and it is the shell. Anything else reaching past the shell is a second shell growing
/// beside the first.
#[test]
fn the_dispatch_core_has_exactly_one_caller() {
    // Production source only — a test may call the core directly to probe it in isolation.
    let production = [
        ("src/engine/pipeline.rs", include_str!("../pipeline.rs")),
        ("src/unit/route.rs", include_str!("../../unit/route.rs")),
    ];
    const CORE: &str = "forward_with_pool_parsed_inner(";
    // The definition site is not a call.
    const DEF: &str = "async fn forward_with_pool_parsed_inner(";

    let mut callers: Vec<String> = Vec::new();
    for (file, src) in production {
        for (i, line) in src.lines().enumerate() {
            // `//` and `//!` lines name the core in prose all over this engine; prose is not a call.
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if line.contains(CORE) && !line.contains(DEF) {
                callers.push(format!("{file}:{}", i + 1));
            }
        }
    }
    assert_eq!(
        callers.len(),
        1,
        "the dispatch core must have exactly ONE caller — the shell that stamps the request id, \
         times WrapSetup and fires the response taps. Found {}: {:?}. A second caller is a second \
         shell, and the two drift in exactly the fields no wire byte records.",
        callers.len(),
        callers
    );
}
