// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE LINKED SCRAPE SINK RENDERS THE RECORDER'S BYTES BACK.** The scrape sink this build links
//! (`module: prometheus`, GetBusbar/busbar-export-prometheus), registered on the export axis through
//! its door exactly as the composition root registers it and opened as boot opens it, handed the
//! snapshot of an exposition carrying every family type the recorder writes (a HELP-less counter,
//! labels with escapes, a histogram, a quantile summary), answers exactly those bytes.
//!
//! This proof moved here from busbar-kernel's `export/tests/scrape_tests.rs` (R-FIX3: the kernel's
//! own tests run on the stand-in axis's scrape double and name no plugin; the composition root may
//! name every kind). The dropped-in copy of the same sink renders through
//! `export_plugin_dropped_in_serves.rs`.

#![cfg(feature = "export-prometheus")]

use busbar_contract::export_calls::ExportAxis as _;

#[test]
fn the_scrape_sink_renders_the_recorder_snapshot_byte_identically() {
    busbar_kernel::test_support::export_axis::install_first_party_door(
        busbar_export_prometheus::NAME,
        busbar_export_prometheus::ALIAS,
        busbar_export_prometheus::door::door,
    );
    let sink = busbar_kernel::test_support::export_axis::STAND_IN
        .open(
            busbar_export_prometheus::ALIAS,
            "export.metrics",
            &serde_json::json!({"buffer_seconds": 60}),
        )
        .expect("the scrape sink opens");
    // Listed in the sink's stable order — every counter, then every gauge, then every
    // histogram/summary (v1.5.5's own renderer drains its maps in that fixed order), name-sorted
    // within a kind — so the bytes come back unchanged.
    let own = "# TYPE busbar_requests_total counter\n\
               busbar_requests_total{pool=\"a\\\"b\\\\c\\nd\",outcome=\"ok\"} 3\n\
               \n\
               # TYPE busbar_plane_request_duration_seconds summary\n\
               busbar_plane_request_duration_seconds{quantile=\"0.99\"} 0.0125\n\
               busbar_plane_request_duration_seconds_sum 1e-3\n\
               busbar_plane_request_duration_seconds_count 4\n\
               \n\
               # HELP busbar_request_duration_seconds request latency\n\
               # TYPE busbar_request_duration_seconds histogram\n\
               busbar_request_duration_seconds_bucket{le=\"0.5\"} 1\n\
               busbar_request_duration_seconds_bucket{le=\"+Inf\"} 2\n\
               busbar_request_duration_seconds_sum 0.75\n\
               busbar_request_duration_seconds_count 2\n\
               \n";
    let families = busbar_contract::export_calls::parse_families(own).expect("the text snapshots");
    let body = sink.scrape(&families).expect("the sink renders");
    assert_eq!(
        body,
        own.as_bytes(),
        "the scrape is the recorder's bytes, back"
    );
}
