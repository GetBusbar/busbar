// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request-log SEAM: what the engine's request-finish path does when the composition root has
//! not installed a fan-out. That is the path EVERY request-finish takes on an unconfigured
//! deployment, and the property is that it costs one null pointer read and spawns nothing.

use super::*;

/// AN UNINSTALLED SEAM IS A TRUE NO-OP.
///
/// The predecessor of this test called the webhook exporter's `deliver_logs` and asserted NOTHING,
/// so the no-op it claimed to prove was unmeasured — deleting the `TARGETS` guard left it green.
/// The no-op is asserted here on what it OBSERVABLY means: nothing is installed, and the call
/// spawns NO delivery task. Neuter the guard (make the unset `REQUEST_LOG_SINK` read fall through,
/// e.g. via `.expect`) and this test fails instead of passing.
#[tokio::test]
async fn deliver_request_log_is_noop_when_no_root_fan_out_is_installed() {
    // The precondition this test measures against: nothing in this binary is a composition root, so
    // the seam is unset.
    assert!(
        REQUEST_LOG_SINK.get().is_none(),
        "this test measures the UNINSTALLED path; something installed a fan-out"
    );
    let rt = tokio::runtime::Handle::current();
    let tasks_before = rt.metrics().num_alive_tasks();

    deliver_request_log(&RequestLogFacts {
        ts: 0,
        ingress_protocol: "openai",
        pool: "p",
        outcome: "ok",
        latency_ms: 1,
    });

    // Yield once so a spawned task would have been polled (and, if it completed, still counted at
    // spawn time — `num_alive_tasks` rises the moment `tokio::spawn` runs).
    tokio::task::yield_now().await;
    assert_eq!(
        rt.metrics().num_alive_tasks(),
        tasks_before,
        "an uninstalled seam must not spawn a delivery task"
    );
}
