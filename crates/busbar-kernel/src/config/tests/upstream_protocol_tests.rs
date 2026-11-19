// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// `upstream_http1_only` and `upstream_h2_prior_knowledge` can both be true. The engine does not
/// choose between them: it hands both to the HTTP transport, which owns the rule (http1_only wins:
/// on TLS it offers `http/1.1` alone, on cleartext it offers no h2c; `transport-http`
/// `door::offer_for`, tested there in `door_tests.rs`). This pins that the engine passes both
/// through untouched, so the transport's rule is the one in force.
#[test]
fn both_upstream_protocol_switches_reach_the_transport_unchanged() {
    let advanced: AdvancedCfg = busbar_contract::yaml::from_str(
        "upstream_http1_only: true\nupstream_h2_prior_knowledge: true\n",
    )
    .expect("both together are accepted");
    let limits = LimitsResolved::from_sections(
        &LimitsCfg::default(),
        &advanced,
        ExportLimits::default(),
        &HealthDefaultsCfg::default(),
        &RoutingCfg::default(),
    );
    assert!(limits.upstream_http1_only);
    assert!(limits.upstream_h2_prior_knowledge);
}
