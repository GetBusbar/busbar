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
        ("src/engine/walk.rs", include_str!("../walk.rs")),
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
