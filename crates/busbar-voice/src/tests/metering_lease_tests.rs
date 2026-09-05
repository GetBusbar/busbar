// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REAL PER-KEY METERING LEASE — a served session reserves against the HOST, capped by the
//! principal's own remaining budget.
//!
//! Two facts, proven separately because they fail separately:
//!
//!  1. THE CEILING IS THE CALLER'S. A session's cap is the tightest remaining bucket across the
//!     presenting key's whole budget chain, widened from the budget projection's micro-units into the
//!     lease's nanodollars. A chain with nothing capped leaves the session uncapped (there is no
//!     ceiling to impose); a chain already spent yields a refuse-all ceiling the lease denies at the
//!     door, so such a caller never opens a session at all.
//!  2. THE LEASE IS THE HOST'S. Opening a session through a mounted route reserves on the host's own
//!     cost lease — visible on the host, not in a plane-local cell — and each turn's usage settles
//!     onto the same key's ledger through the core meter seam.
//!
//! RED before the wiring: every session reserved an uncapped in-process lease, so the host saw no
//! lease at all and no caller's budget could ever hard-close a live session.

use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::metering::TurnMeter;
use crate::runtime::{cap_nanos_from_buckets, EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::testkit::fixture_host::FixtureHost;
use std::collections::BTreeMap;
use std::sync::Arc;

/// One bucket of a key's budget chain, with `remaining` micro-units (`None` = an uncapped bucket).
fn bucket(id: &str, remaining: Option<i64>) -> busbar_api::BudgetBucketState {
    busbar_api::BudgetBucketState {
        bucket_id: id.to_string(),
        budget_group: None,
        pool: None,
        spend_micros_at_current_rate: 0,
        remaining_micros: remaining,
        window_start: 0,
        budget_period: "day".to_string(),
    }
}

#[test]
fn a_sessions_ceiling_is_the_tightest_bucket_in_the_callers_chain() {
    // Nothing to read: an unbudgeted (or ungoverned) caller has no ceiling to impose.
    assert_eq!(cap_nanos_from_buckets(&[]), None);
    assert_eq!(cap_nanos_from_buckets(&[bucket("vk", None)]), None);

    // The TIGHTEST bucket wins — a session may not spend past the narrowest limit above it — and the
    // projection's micro-units widen into the lease's nanodollars.
    assert_eq!(
        cap_nanos_from_buckets(&[
            bucket("vk", Some(9_000)),
            bucket("group:team@day", Some(250)),
            bucket("group:org@month", None),
        ]),
        Some(250_000),
        "the narrowest remaining bucket becomes the session ceiling, in nanodollars"
    );

    // Already spent: a refuse-all ceiling, which the lease denies at reserve so no session opens.
    assert_eq!(cap_nanos_from_buckets(&[bucket("vk", Some(0))]), Some(0));
    assert_eq!(cap_nanos_from_buckets(&[bucket("vk", Some(-5))]), Some(0));
}

#[tokio::test]
async fn opening_a_session_reserves_on_the_hosts_own_lease() {
    let host = Arc::new(FixtureHost::new().governed());
    assert_eq!(
        host.leases_opened(),
        0,
        "no session has been opened, so the host holds no lease"
    );

    let rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        // The pre-host default the dispatch slot carries. The route must NOT keep it: it rebinds the
        // money hop onto the live host, which is exactly what this test reads back.
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    );
    let key = busbar_api::VirtualKey {
        id: "vk-voice-session".to_string(),
        name: "voice-session".to_string(),
        ..Default::default()
    };

    let resp = open_governed(GovernedOpen {
        rt: &rt,
        host: Arc::clone(&host) as Arc<dyn busbar_substrate::plane_host::EngineHost>,
        provider: None,
        ingress: Ingress::Mint,
        owner: "acct-lease".to_string(),
        call_id: "call-lease".to_string(),
        vkey: Some(key.clone()),
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 5,
    })
    .await;
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "the governed open succeeded (nothing to dial here)"
    );
    assert_eq!(
        host.leases_opened(),
        1,
        "the session reserved on the HOST's cost lease, not a plane-local cell"
    );

    // And the turn that follows settles onto the same key's ledger through the core meter seam — the
    // ledger a voice session's spend shows up on, exactly like a model call's.
    let mut usage_units = BTreeMap::new();
    usage_units.insert(busbar_api::UNIT_INPUT.to_string(), 120u64);
    usage_units.insert(busbar_api::UNIT_OUTPUT.to_string(), 80u64);
    TurnMeter::new(
        Arc::clone(&host) as Arc<dyn busbar_substrate::plane_host::EngineHost>,
        key.clone(),
        "voice-server",
        crate::OPENAI_REALTIME,
    )
    .record_turn(
        "voice-model",
        &busbar_substrate::billing::Usage { usage_units },
    );
    assert_eq!(
        host.ledger_usage(&key.id).map(|u| u.tokens),
        Some(200),
        "the turn's tokens land on the presenting key's ledger"
    );
}
