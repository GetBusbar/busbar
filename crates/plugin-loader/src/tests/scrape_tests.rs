// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The recorder snapshot reader (K9a S6): what it reads, and what it refuses rather than guess.

use super::*;

/// A recorder exposition in the host recorder's own shape: a described counter, an undescribed
/// counter, a gauge with escaped label values, a quantile summary and a bucketed histogram.
pub(crate) const EXPOSITION: &str = "\
# HELP busbar_requests_total Total ingress requests, by ingress protocol, pool, and outcome
# TYPE busbar_requests_total counter
busbar_requests_total{ingress_protocol=\"anthropic\",pool=\"p\",outcome=\"ok\"} 3
busbar_requests_total{ingress_protocol=\"openai\",pool=\"p\",outcome=\"error\"} 1

# TYPE busbar_billing_truncated_total counter
busbar_billing_truncated_total 0

# HELP busbar_lane_state Per-(pool,lane) circuit-breaker health: 0=healthy, 1=half-open
# TYPE busbar_lane_state gauge
busbar_lane_state{pool=\"a \\\"quoted\\\" pool\",lane=\"x\\\\y\\nz\"} 2
busbar_lane_state{pool=\"b,c\",lane=\"{}\"} 0.5

# HELP busbar_request_duration_seconds End-to-end request duration in seconds
# TYPE busbar_request_duration_seconds summary
busbar_request_duration_seconds{ingress_protocol=\"anthropic\",pool=\"p\",quantile=\"0\"} 0.001
busbar_request_duration_seconds{ingress_protocol=\"anthropic\",pool=\"p\",quantile=\"0.99\"} 0.25
busbar_request_duration_seconds_sum{ingress_protocol=\"anthropic\",pool=\"p\"} 0.3120000000000001
busbar_request_duration_seconds_count{ingress_protocol=\"anthropic\",pool=\"p\"} 4

# TYPE plugin_latency_seconds histogram
plugin_latency_seconds_bucket{plugin=\"s\",le=\"0.1\"} 1
plugin_latency_seconds_bucket{plugin=\"s\",le=\"+Inf\"} 2
plugin_latency_seconds_sum{plugin=\"s\"} 0.35
plugin_latency_seconds_count{plugin=\"s\"} 2

";

#[test]
fn the_snapshot_reads_every_family_type_in_order_losslessly() {
    let families = snapshot(EXPOSITION).expect("reads");
    let shape: Vec<(&str, &str, usize)> = families
        .iter()
        .map(|f| (f.name.as_str(), f.kind.as_str(), f.samples.len()))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("busbar_requests_total", "counter", 2),
            ("busbar_billing_truncated_total", "counter", 1),
            ("busbar_lane_state", "gauge", 2),
            ("busbar_request_duration_seconds", "summary", 4),
            ("plugin_latency_seconds", "histogram", 4),
        ]
    );
    let lane = &families[2].samples[0];
    assert_eq!(
        lane.labels[0].1, "a \\\"quoted\\\" pool",
        "escaped as written"
    );
    assert_eq!(families[3].samples[2].value, "0.3120000000000001");
    assert_eq!(families[1].help, None);
    assert!(snapshot("").expect("an empty recorder").is_empty());
}

#[test]
fn what_the_snapshot_cannot_place_is_refused() {
    for bad in [
        "# TYPE x counter\nx 1\n",
        "# TYPE x counter\nx 1",
        "x 1\n\n",
        "\n",
        "# TYPE x counter\nx{a=\"1\" 1\n\n",
        "# TYPE x counter\nx{} 1\n\n",
        "# TYPE x counter\nx 1 1700000000\n\n",
        "# HELP x h\n# TYPE y counter\n\n",
    ] {
        assert!(snapshot(bad).is_err(), "{bad:?} must be refused");
    }
}
