// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIVE `busbar_pool_queued` GAUGE reads the plane's real park depth — relocated from core
//! `src/tests/metrics_tests.rs` (money-path Phase 3-4 C) because it parks against the plane's own
//! `QueuedDepth` through the `AppEngineExt`/`EngineTables` seam, which core no longer names.

use crate::engine::AppEngineExt as _;
use crate::test_support::{LaneSpec, TestApp};
use busbar_substrate::testkit::BuiltAppSeam as _;

const POOL_QUEUED: &str = "busbar_pool_queued";

/// Find the trailing numeric value of the exposition line for `metric` labeled with `pool`.
fn gauge_value(out: &str, metric: &str, pool: &str) -> Option<f64> {
    let needle = format!("{metric}{{");
    out.lines()
        .find(|l| {
            !l.starts_with('#') && l.starts_with(&needle) && l.contains(&format!("pool=\"{pool}\""))
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.trim().parse::<f64>().ok())
}

/// The `busbar_pool_queued` gauge must read the REAL live park depth off the plane's `QueuedDepth`,
/// not a literal 0.
#[test]
fn test_scrape_gauges_pool_queued_reads_live_depth() {
    crate::testkit::install_test_seams();
    busbar_core::metrics::init();
    // Unique pool/model labels: the `metrics` recorder is process-global, so sharing a label with
    // another test would cross-contaminate this gauge across tests.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "q-live-model",
            crate::proto_codec::PROTO_OPENAI,
            "http://q",
        ))
        .pool("q-live-pool", &[(0, 1)])
        .build();

    // Hold a park guard, as a real queued request would for the duration of its wait.
    let guard = app.engine_tables().queued_depth().park("q-live-pool");
    app.refresh_scrape_gauges();
    let out = busbar_core::metrics::render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, "q-live-pool"),
        Some(1.0),
        "busbar_pool_queued must reflect the live park depth (1 while parked); got:\n{out}"
    );

    // Dropping the guard (request left the queue) returns the depth to 0.
    drop(guard);
    app.refresh_scrape_gauges();
    let out = busbar_core::metrics::render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, "q-live-pool"),
        Some(0.0),
        "busbar_pool_queued must return to 0 once the parked request leaves; got:\n{out}"
    );
}
