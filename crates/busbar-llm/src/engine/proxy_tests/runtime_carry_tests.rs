// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! APPLY-PATH CARRY-OVER of the LLM data-plane runtime across a config rebuild — relocated from core
//! `src/tests/tests.rs` (money-path Phase 3-4 C) because these assertions read the plane's own
//! `NativeRuntime` (probe schedule Arc identity, warm-client pool sharing) through the
//! `AppEngineExt` seam, which core no longer names.

use crate::engine::AppEngineExt as _;
use crate::test_support::{build_once, cfg_with_provider_api_key};
use busbar_core::store::LaneRuntime as _;

/// An unchanged lane set must CARRY the probe schedule (same `Arc`) across a rebuild — otherwise a
/// mutation cadence faster than the probe interval resets every generation before its first tick and
/// probing goes dark while still logging that it is enabled. A lane-set CHANGE must mint a fresh one,
/// because deadlines are index-keyed. No clock in this assertion — synchronous pointer identity.
#[test]
fn a_rebuild_carries_the_probe_schedule() {
    busbar_core::metrics::init();
    let no_lane_cfg = || {
        cfg_with_provider_api_key(busbar_core::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_PROBE_SCHEDULE",
        ))
    };
    let one_lane_cfg = || {
        let mut cfg = no_lane_cfg();
        cfg.models.insert(
            "m0".to_string(),
            busbar_core::config::ModelCfg {
                reasoning: None,
                prompt_caching: None,
                max_requests: -1,
                provider: "acme".into(),
                max_concurrent: Some(1),
                default_max_tokens: None,
                upstream_model: None,
                attempt_timeout_ms: None,
            },
        );
        cfg
    };

    // Positive half: zero lanes both times (the zip is vacuously true), but the buggy code still
    // mints a fresh `Arc` unconditionally, so this alone discriminates.
    let prior = build_once(no_lane_cfg(), None).expect("boot");
    let next = build_once(no_lane_cfg(), Some(&prior)).expect("rebuild, unchanged config");
    assert!(
        std::sync::Arc::ptr_eq(
            &prior.llm_runtime().probe_schedule,
            &next.llm_runtime().probe_schedule
        ),
        "an unchanged lane set must carry the probe schedule across a rebuild"
    );

    // Negative half: a lane REMOVED must NOT carry — the old indices would mean something else.
    let prior2 = build_once(one_lane_cfg(), None).expect("boot with one lane");
    let next2 = build_once(no_lane_cfg(), Some(&prior2)).expect("rebuild with the lane removed");
    assert!(
        !std::sync::Arc::ptr_eq(
            &prior2.llm_runtime().probe_schedule,
            &next2.llm_runtime().probe_schedule
        ),
        "a lane-set change must NOT carry the probe schedule"
    );
}

/// A hot config apply that CHANGES a client-affecting limit (here the upstream request timeout) must
/// REBUILD the sharded upstream client so the new setting takes effect. An apply that changes nothing
/// client-relevant must REUSE the prior client (keeping its warm connection pool). Observed by shard
/// -set pointer identity: reuse clones the same `Arc<[Client]>`, a rebuild allocates a fresh one.
#[test]
fn a_changed_upstream_timeout_rebuilds_the_client_an_unrelated_apply_reuses_it() {
    busbar_core::metrics::init();
    let cfg = || {
        cfg_with_provider_api_key(busbar_core::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_CLIENT_REBUILD",
        ))
    };

    // Reuse half: an apply with an identical client-affecting settings snapshot carries the warm
    // pool forward (same shard-set Arc).
    let prior = build_once(cfg(), None).expect("boot");
    let unchanged =
        build_once(cfg(), Some(&prior)).expect("apply, nothing client-relevant changed");
    assert!(
        unchanged
            .llm_runtime()
            .client
            .shares_pool_with(&prior.llm_runtime().client),
        "an apply that changes no client-affecting setting must REUSE the prior client's warm pool"
    );

    // Rebuild half: bump the upstream request timeout and re-apply — the client MUST be rebuilt, or
    // the new timeout never takes effect until restart.
    let prior2 = build_once(cfg(), None).expect("boot");
    let mut changed_cfg = cfg();
    changed_cfg.limits.upstream_request_timeout_secs =
        prior2.client_settings.upstream_request_timeout_secs + 7;
    let rebuilt = build_once(changed_cfg, Some(&prior2)).expect("apply with a changed timeout");
    assert!(
        !rebuilt
            .llm_runtime()
            .client
            .shares_pool_with(&prior2.llm_runtime().client),
        "an apply that changes upstream_request_timeout_secs must REBUILD the client so the new \
         timeout takes effect"
    );
    assert_eq!(
        rebuilt.client_settings.upstream_request_timeout_secs,
        prior2.client_settings.upstream_request_timeout_secs + 7,
        "the rebuilt client's carried settings snapshot must reflect the new timeout"
    );
}
