// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/govern.rs`.

use crate::plane_host::with_dispatch_scope;
use busbar_plugin::hot::{
    AdmissionId, Decision, Facts, GovRefusal, MeterOutcome, Usage, UsageComponent,
};
use core::mem::MaybeUninit;
use std::sync::Arc;

/// A cost model with ONE budget group (`name`, `cap` cents on the total window, no parent) and a
/// 1c flat fee — so `cap` requests fit before the group's total-window bucket blocks. Mirrors the
/// governance suite's `group_cost`, inlined here to keep this module's tests self-contained.
fn group_cost(name: &str, cap: i64) -> crate::cost::CostModel {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let mut groups = std::collections::BTreeMap::new();
    groups.insert(
        name.to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: u64::try_from(cap).unwrap_or(0),
                per: Some(LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    );
    crate::cost::CostModel::resolve_parts(None, 1, &groups)
}

/// Like [`group_cost`] but the single group is FROZEN (`enabled: false`), so every request
/// charging through it is rejected with [`LimitBlocked::Disabled`].
fn disabled_group_cost(name: &str) -> crate::cost::CostModel {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let mut groups = std::collections::BTreeMap::new();
    groups.insert(
        name.to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: false,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: 100,
                per: Some(LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    );
    crate::cost::CostModel::resolve_parts(None, 1, &groups)
}

/// The minimal [`VirtualKey`](busbar_api::VirtualKey) `try_admit`/`chain_for` read — `id` + `group`
/// — so a direct `try_admit` and the host `govern_admit_reason` drive the identical chain.
fn test_key(id: &str, group: Option<&str>) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        generation_hash: String::new(),
        name: id.to_string(),
        id: id.to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: group.map(str::to_string),
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

fn gov() -> Arc<crate::governance::GovState> {
    Arc::new(
        crate::governance::GovState::new(Arc::new(crate::governance::MemoryStore::new()), None)
            .expect("memory store constructs"),
    )
}

/// THE GOVERN FAITHFULNESS PROOF: driving `govern_admit` over a [`Facts`] carrying the caller's
/// REAL `(key_id, group)` admits against the EXACT SAME budget bucket the plane's own
/// `try_admit(&real_key, pool)` charges — the govern analogue of the breaker's
/// `settle_through_host_matches_direct_record_signal`. A group with a 5c total cap at 1c/request
/// fits exactly 5 admissions; 3 taken directly through the real key leave exactly 2 for the host
/// path (proving they share the `group:<name>@total` bucket, not two disjoint buckets).
#[test]
fn admit_over_facts_matches_try_admit() {
    let gov = gov();
    let cost = group_cost("team", 5); // 5c cap, 1c/request → 5 requests fit
    let now = crate::store::now_ms() / 1_000;
    // The real key the plane would resolve: `chain_for` reads only `id` + `group`.
    let key = busbar_api::VirtualKey {
        generation_hash: String::new(),
        name: "k".to_string(),
        id: "vk_faithful_admit".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: Some("team".to_string()),
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    };
    // DIRECT: take 3 of the 5 through the real `try_admit`, exactly as `charge_round` does.
    for _ in 0..3 {
        assert!(
            gov.try_admit(&cost, &key, "pool-x", now).is_ok(),
            "the real key admits under the cap"
        );
    }
    // HOST: admit through the vtable over a Facts carrying the SAME (id, group). Exactly 2 fit.
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(group_cost("team", 5))
        .build();
    let admitted = with_dispatch_scope(&app, |host, vt| {
        let mut n = 0;
        for _ in 0..4 {
            let facts = Facts::with_attribution(
                1,
                1_000,
                0,
                0,
                0,
                b"pool-x",
                key.id.as_bytes(),
                Some(b"team"),
            );
            if (vt.govern_admit.unwrap())(host, &*facts as *const Facts) == Decision::Admit {
                n += 1;
            }
        }
        n
    });
    assert_eq!(
        admitted, 2,
        "3 direct + 2 host = the 5-request cap; the host path shares the real key's group bucket"
    );
}

/// A [`Facts`] WITHOUT the identity tail (`Facts::new`) still admits against the synthesized
/// ungrouped key — the pre-enrichment fallback is unchanged, so the enrichment is behavior-additive.
#[test]
fn admit_without_identity_falls_back_to_synth() {
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .cost(group_cost("team", 1))
        .build();
    with_dispatch_scope(&app, |host, vt| {
        // No attribution → synth ungrouped key → the unlimited 1-bucket chain admits.
        let facts = Facts::new(1, 1_000, 42, 0, 0, b"pool-x");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*facts as *const Facts),
            Decision::Admit
        );
    });
}

/// THE GOVERN-REFUSAL FAITHFULNESS PROOF (the govern analogue of the breaker's
/// `settle_through_host_matches_direct_record_signal`): for every blocked-limit shape, driving the
/// host `govern_admit_reason` slot yields the SAME `Decision::Deny` AND the SAME rendered reason
/// bytes as the direct `try_admit(...)`→`format!("{blocked:?}")` the mcp `charge_round` returns
/// today — the byte-identity Option A rests on. Covers `MissingGroup`, `Disabled`, and an
/// exhausted `Limit{..}`.
#[test]
fn govern_admit_reason_reason_bytes_match_direct_try_admit() {
    // Run ONE blocked shape over a SHARED gov: drain `drain` requests, capture the direct block's
    // `{blocked:?}`, then drive the host slot over an identical cost + Facts and compare.
    fn faithful_case(
        make_cost: &dyn Fn() -> crate::cost::CostModel,
        key_group: Option<&str>,
        facts_group: Option<&[u8]>,
        drain: usize,
    ) {
        let pool = "pool-x";
        let key = test_key("vk_reason", key_group);
        let gov = gov();
        let cost = make_cost();
        let now = crate::store::now_ms() / 1_000;
        // Exhaust the budget for the Limit case (a no-op for MissingGroup/Disabled, drain = 0).
        for _ in 0..drain {
            let _ = gov.try_admit(&cost, &key, pool, now);
        }
        // DIRECT: the exact `LimitBlocked` the mcp `charge_round` renders today.
        let blocked = gov
            .try_admit(&cost, &key, pool, now)
            .expect_err("this shape must block");
        let expected = format!("{blocked:?}");

        // HOST: drive the slot over the SAME gov (shared drained state) + an identical cost.
        let app = crate::test_support::TestApp::new()
            .governance(Arc::clone(&gov))
            .cost(make_cost())
            .build();
        with_dispatch_scope(&app, |host, vt| {
            let facts = Facts::with_attribution(
                0,
                0,
                0,
                0,
                0,
                pool.as_bytes(),
                key.id.as_bytes(),
                facts_group,
            );
            let mut buf = [0u8; 512];
            let mut out = MaybeUninit::<GovRefusal>::uninit();
            let decision = (vt.govern_admit_reason.unwrap())(
                host,
                &*facts as *const Facts,
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::from_mut(&mut out),
            );
            assert_eq!(decision, Decision::Deny, "a blocked limit denies");
            // SAFETY: the host always initializes `out`.
            let refusal = unsafe { out.assume_init() };
            assert!(
                refusal.reason_len <= buf.len(),
                "written length fits the buffer"
            );
            let actual = String::from_utf8_lossy(&buf[..refusal.reason_len]).into_owned();
            assert_eq!(
                actual, expected,
                "host-rendered reason must be byte-identical to the direct {{blocked:?}}"
            );
        });
    }

    // MissingGroup: the key names a group the cost model does not have.
    faithful_case(&|| group_cost("team", 5), Some("ghost"), Some(b"ghost"), 0);
    // Disabled: the key's group is frozen (`enabled: false`).
    faithful_case(
        &|| disabled_group_cost("frozen"),
        Some("frozen"),
        Some(b"frozen"),
        0,
    );
    // Limit: a 5c total cap at 1c/request → the 6th request blocks after draining 5.
    faithful_case(&|| group_cost("team", 5), Some("team"), Some(b"team"), 5);
}

/// A live admit through `govern_admit_reason` returns `Admit`, leaves `reason_len == 0`, and
/// registers the RAII grant in the arena exactly as `govern_admit` does.
#[test]
fn govern_admit_reason_admits_and_registers_grant() {
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .cost(group_cost("team", 5))
        .build();
    with_dispatch_scope(&app, |host, vt| {
        let facts = Facts::with_attribution(0, 0, 0, 0, 0, b"pool-x", b"vk_ok", Some(b"team"));
        let mut buf = [0u8; 64];
        let mut out = MaybeUninit::<GovRefusal>::uninit();
        let decision = (vt.govern_admit_reason.unwrap())(
            host,
            &*facts as *const Facts,
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::from_mut(&mut out),
        );
        assert_eq!(decision, Decision::Admit, "under the cap → admit");
        // SAFETY: the host always initializes `out`.
        assert_eq!(
            unsafe { out.assume_init() }.reason_len,
            0,
            "an admit renders no reason"
        );
        // SAFETY: live HostState from `with_dispatch_scope`.
        let state: &crate::plane_host::HostState = unsafe { crate::plane_host::recover(host) };
        assert_eq!(
            state.scope.registered(),
            1,
            "the RAII grant is registered in the arena"
        );
    });
}

/// THE METER FAITHFULNESS PROOF: charging a [`Usage`] carrying the REAL `(key_id, model, provider)`
/// records the EXACT metering row the plane's own `record_metering(key_id, model, provider, ..)`
/// does — so a direct record and a host charge COALESCE into ONE `(key_id, bucket, model,
/// provider)` cell rather than two. A wrong attribution would leave two distinct cells.
#[test]
fn charge_over_usage_matches_record_metering() {
    let gov = gov();
    let now = crate::store::now_ms() / 1_000;
    // DIRECT: the plane's own metering row.
    gov.record_metering(
        "vk_faithful_meter",
        "tool:fs",
        "plane:mcp",
        Some(&crate::billing::TokenUsage {
            input: 100,
            ..Default::default()
        }),
        now,
    );
    // HOST: charge a Usage carrying the SAME (key_id, model, provider).
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .build();
    with_dispatch_scope(&app, |host, vt| {
        let usage = Usage::with_attribution(
            UsageComponent::Tokens,
            100,
            1,
            AdmissionId(7),
            b"vk_faithful_meter",
            b"tool:fs",
            b"plane:mcp",
        );
        assert_eq!(
            (vt.meter_charge.unwrap())(host, &*usage as *const Usage),
            MeterOutcome::Charged
        );
    });
    // The two accruals coalesced into ONE cell (same attribution key) with summed counts.
    let (cells, counts) = gov.pending_metering_totals();
    assert_eq!(
        cells, 1,
        "direct + host recorded the SAME (key_id, model, provider) cell"
    );
    assert_eq!(counts.requests, 2, "both accruals counted");
    assert_eq!(
        counts.tokens_input, 200,
        "100 direct + 100 host input tokens"
    );
}

/// A [`Usage`] WITHOUT the attribution tail (`Usage::charge`) still records against the synthetic
/// admission-derived attribution — the pre-enrichment fallback is unchanged.
#[test]
fn charge_without_attribution_falls_back_to_synth() {
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .build();
    with_dispatch_scope(&app, |host, vt| {
        let usage = Usage::charge(UsageComponent::Tokens, 10, 1, AdmissionId(99));
        assert_eq!(
            (vt.meter_charge.unwrap())(host, &*usage as *const Usage),
            MeterOutcome::Charged
        );
    });
    let (cells, counts) = gov.pending_metering_totals();
    assert_eq!(cells, 1, "one synthetic cell recorded");
    assert_eq!(counts.requests, 1);
    // The synthetic key is `plane:admission:99`, distinct from any real id.
}
