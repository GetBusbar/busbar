// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE p95 RESERVOIR'S COLLECTION GATE on the pools door's egress: the walk's served-latency sample
//! always moves the lane's latency average, and reaches the lane's p95 reservoir only while the
//! generation declares the p95 signal.

use std::collections::HashMap;
use std::sync::Arc;

use busbar_contract::dest::DestinationId;
use busbar_contract::Signal;
use busbar_kernel_egress::ports::Telemetry as _;

use super::{LatencyReservoir, ModelSignals, ModelTelemetry};
use crate::root::egress_ports::{MemberPermits, WalkTelemetry};

/// The egress telemetry and the members' standing over one lane `m0` in pool `p`, its generation
/// declaring `signals`.
fn over(signals: &[Signal]) -> (Arc<busbar_kernel::state::App>, ModelTelemetry, ModelSignals) {
    let mut app = busbar_kernel::test_support::TestApp::new()
        .lane(busbar_kernel::test_support::LaneSpec::new(
            "m0",
            "openai",
            "http://127.0.0.1:1",
        ))
        .pool("p", &[(0, 1)])
        .build();
    {
        let a = Arc::get_mut(&mut app).expect("sole owner");
        for s in signals {
            a.requested_signals.insert(*s);
        }
    }
    let source: super::AppSource = {
        let app = Arc::clone(&app);
        Arc::new(move || Arc::clone(&app))
    };
    let reservoirs: Arc<HashMap<usize, LatencyReservoir>> =
        Arc::new(std::iter::once((0, LatencyReservoir::default())).collect());
    let telemetry = ModelTelemetry {
        app: Arc::clone(&source),
        queued: WalkTelemetry::new([(DestinationId::new(0), "m0".to_string())]),
        reservoirs: Arc::clone(&reservoirs),
    };
    let signals = ModelSignals {
        app: source,
        permits: Arc::new(MemberPermits::new(Vec::new())),
        reservoirs,
    };
    (app, telemetry, signals)
}

/// With no hook declaring p95, served requests never write the latency reservoir, so the store has
/// no p95 to give even though the lane has served traffic and its latency average (the always-on
/// `fastest` signal) has moved; declared, the same samples are collected.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::undeclared_latency_p95_is_never_collected`
/// (the reservoir half; the door half is
/// `serve_door_hooks_ported::an_undeclared_p95_is_never_shown_though_the_latency_average_moves`).
#[test]
fn an_undeclared_p95_is_never_collected_and_a_declared_one_is() {
    use busbar_kernel::plane_driver::MemberSignals as _;
    let m0 = DestinationId::new(0);

    let (app, telemetry, signals) = over(&[Signal::CandidateErrorRate]);
    telemetry.upstream_latency(m0, 5.0);
    assert!(
        app.store.lane_latency_ms(0).is_some(),
        "the latency average is always-on"
    );
    assert_eq!(
        telemetry.reservoirs[&0].p95_ms(),
        None,
        "an undeclared p95 must never write its reservoir"
    );
    assert_eq!(signals.standing("p", m0).latency_p95_ms, None);

    let (_app, telemetry, signals) = over(&[Signal::CandidateLatencyP95Ms]);
    telemetry.upstream_latency(m0, 5.0);
    assert_eq!(
        signals.standing("p", m0).latency_p95_ms,
        Some(5),
        "a declared p95 is collected from the served sample"
    );
}
