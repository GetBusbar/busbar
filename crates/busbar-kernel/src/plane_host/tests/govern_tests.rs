// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/plane_host/govern.rs`.

use crate::plane_host::{
    govern_admit_reason_over, AdmissionId, DispatchScope, GovAdmit, HostCaller, HostState,
    MeterAttribution, MeterUsage, UsageComponent,
};
use std::collections::BTreeMap;
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
                admission: None,
                on_exhaustion: None,
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
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    );
    crate::cost::CostModel::resolve_parts(None, 1, &groups)
}

/// A BILLING-ON cost model: a `rate_card:` is PRESENT (one priced model), so
/// [`CostModel::pricing_enabled`] is `true`. The host charge path records a metering row with or
/// without a card (DECISION #43 — the ledger write is unconditional; see
/// `billing_off_charge_still_appends_the_counts_to_the_ledger`); the attribution tests below use the
/// billed posture because it is the one every priced deployment runs.
fn billing_on_cost() -> crate::cost::CostModel {
    let mut card = std::collections::BTreeMap::new();
    card.insert(
        "m".to_string(),
        crate::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 1.0,
            ..Default::default()
        },
    );
    crate::cost::CostModel::resolve_parts(Some(&card), 1, &std::collections::BTreeMap::new())
}

/// The minimal [`VirtualKey`](busbar_contract::records::VirtualKey) `try_admit`/`chain_for` read — `id` + `group`
/// — so a direct `try_admit` and the host admission drive the identical chain.
fn test_key(id: &str, group: Option<&str>) -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
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

/// Run `f` over a [`HostState`] for `key` — the middleware-resolved caller (DEC-SERVE G1b), exactly
/// as the host's `EngineHost` methods build it — or for no caller.
fn with_caller<R>(
    app: &crate::state::App,
    key: Option<&busbar_contract::records::VirtualKey>,
    f: impl FnOnce(&HostState) -> R,
) -> R {
    let ctx = key.map(|k| busbar_contract::records::PlaneRequestCtx {
        key: Some(Arc::new(k.clone())),
    });
    let scope = DispatchScope::new();
    crate::plane_host::with_state(HostCaller::of(ctx.as_ref()), app, &scope, f)
}

/// A usage of `amount` `component`s under `admission`, attributed to `(model, provider)` or not.
fn usage<'a>(
    component: UsageComponent,
    amount: u64,
    admission: u64,
    attribution: Option<(&'a str, &'a str)>,
    units: &'a BTreeMap<String, u64>,
) -> MeterUsage<'a> {
    MeterUsage {
        component,
        amount,
        admission: AdmissionId(admission),
        attribution: attribution.map(|(model, provider)| MeterAttribution { model, provider }),
        units,
    }
}

/// THE GOVERN FAITHFULNESS PROOF: the host admission for the caller's REAL key admits against the
/// EXACT SAME budget bucket the plane's own `try_admit(&real_key, pool)` charges. A group with a 5c
/// total cap at 1c/request fits exactly 5 admissions; 3 taken directly through the real key leave
/// exactly 2 for the host path (proving they share the `group:<name>@total` bucket).
#[test]
fn admit_for_the_caller_matches_try_admit() {
    let gov = gov();
    let cost = group_cost("team", 5); // 5c cap, 1c/request → 5 requests fit
    let now = busbar_kernel::store::now_ms() / 1_000;
    let key = test_key("vk_faithful_admit", Some("team"));
    // DIRECT: take 3 of the 5 through the real `try_admit`, exactly as `charge_round` does.
    for _ in 0..3 {
        assert!(
            gov.try_admit(&cost, &key, "pool-x", now).is_ok(),
            "the real key admits under the cap"
        );
    }
    // HOST: admit for the SAME caller. Exactly 2 fit.
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(group_cost("team", 5))
        .build();
    let admitted = with_caller(&app, Some(&key), |state| {
        (0..4)
            .filter(|_| super::admit_reason(state, b"pool-x").is_ok())
            .count()
    });
    assert_eq!(
        admitted, 2,
        "3 direct + 2 host = the 5-request cap; the host path shares the real key's group bucket"
    );
}

/// DEC-SERVE G1b, THE NAMED SYNTHETIC ADMISSION PATH: an admission with NO caller admits as
/// `SYNTH_TENANT_KEY` + the unnamed tenant — an ungrouped key whose unlimited chain admits.
#[test]
fn an_admission_with_no_caller_admits_the_named_synthetic_key() {
    assert_eq!(super::SYNTH_TENANT_KEY, "plane:tenant:");
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .cost(group_cost("team", 1))
        .build();
    with_caller(&app, None, |state| {
        for _ in 0..2 {
            assert!(
                super::admit_reason(state, b"pool-x").is_ok(),
                "the synthetic ungrouped key admits without limit"
            );
        }
    });
}

/// DEC-SERVE G1b (#65/#40): the REAL caller's budget chain decides. The caller sits in `team` (1c
/// cap at 1c/request → one request fits), so the second admission is refused.
#[test]
fn the_real_callers_chain_decides_the_admission() {
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .cost(group_cost("team", 1))
        .build();
    let decisions = with_caller(
        &app,
        Some(&test_key("vk_real_caller", Some("team"))),
        |state| {
            (0..2)
                .map(|_| super::admit_reason(state, b"pool-x").is_ok())
                .collect::<Vec<_>>()
        },
    );
    assert_eq!(
        decisions,
        vec![true, false],
        "the real caller's 1-request chain decides"
    );
}

/// THE GOVERN-REFUSAL FAITHFULNESS PROOF: for every blocked-limit shape, the host admission yields a
/// refusal with the SAME rendered reason bytes as the direct `try_admit(...)`→`format!("{blocked:?}")`
/// the mcp `charge_round` returns today. Covers `MissingGroup`, `Disabled`, and an exhausted
/// `Limit{..}`.
#[test]
fn govern_admit_reason_reason_bytes_match_direct_try_admit() {
    // Run ONE blocked shape over a SHARED gov: drain `drain` requests, capture the direct block's
    // `{blocked:?}`, then admit through the host over an identical cost and compare.
    fn faithful_case(
        make_cost: &dyn Fn() -> crate::cost::CostModel,
        key_group: Option<&str>,
        drain: usize,
    ) {
        let pool = "pool-x";
        let key = test_key("vk_reason", key_group);
        let gov = gov();
        let cost = make_cost();
        let now = busbar_kernel::store::now_ms() / 1_000;
        // Exhaust the budget for the Limit case (a no-op for MissingGroup/Disabled, drain = 0).
        for _ in 0..drain {
            let _ = gov.try_admit(&cost, &key, pool, now);
        }
        // DIRECT: the exact `LimitBlocked` the mcp `charge_round` renders today.
        let blocked = gov
            .try_admit(&cost, &key, pool, now)
            .expect_err("this shape must block");
        let expected = format!("{blocked:?}");

        // HOST: admit over the SAME gov (shared drained state) + an identical cost.
        let app = crate::test_support::TestApp::new()
            .governance(Arc::clone(&gov))
            .cost(make_cost())
            .build();
        let scope = DispatchScope::new();
        let caller = busbar_contract::records::PlaneRequestCtx {
            key: Some(Arc::new(key.clone())),
        };
        match govern_admit_reason_over(&app, &scope, &caller, pool.as_bytes()) {
            GovAdmit::Blocked { reason, .. } => assert_eq!(
                reason, expected,
                "host-rendered reason must be byte-identical to the direct {{blocked:?}}"
            ),
            GovAdmit::Admitted => panic!("a blocked limit refuses"),
        }
        assert_eq!(scope.registered(), 0, "a refusal registers no grant");
    }

    // MissingGroup: the key names a group the cost model does not have.
    faithful_case(&|| group_cost("team", 5), Some("ghost"), 0);
    // Disabled: the key's group is frozen (`enabled: false`).
    faithful_case(&|| disabled_group_cost("frozen"), Some("frozen"), 0);
    // Limit: a 5c total cap at 1c/request → the 6th request blocks after draining 5.
    faithful_case(&|| group_cost("team", 5), Some("team"), 5);
}

/// A live admission returns `Admitted` and registers the RAII grant in the caller's arena.
#[test]
fn govern_admit_reason_admits_and_registers_grant() {
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(gov)
        .cost(group_cost("team", 5))
        .build();
    let scope = DispatchScope::new();
    let caller = busbar_contract::records::PlaneRequestCtx {
        key: Some(Arc::new(test_key("vk_ok", Some("team")))),
    };
    assert!(
        matches!(
            govern_admit_reason_over(&app, &scope, &caller, b"pool-x"),
            GovAdmit::Admitted
        ),
        "under the cap → admit"
    );
    assert_eq!(
        scope.registered(),
        1,
        "the RAII grant is registered in the arena"
    );
}

/// THE METER FAITHFULNESS PROOF: charging a usage attributed to the REAL `(model, provider)` for the
/// real caller records the EXACT metering row the plane's own `record_metering(key_id, model,
/// provider, ..)` does — so a direct record and a host charge COALESCE into ONE `(key_id, bucket,
/// model, provider)` cell rather than two.
#[test]
fn charge_over_usage_matches_record_metering() {
    let gov = gov();
    let now = busbar_kernel::store::now_ms() / 1_000;
    // DIRECT: the plane's own metering row.
    gov.record_metering(
        "vk_faithful_meter",
        "tool:fs",
        "plane:tools",
        Some(&crate::billing::TokenUsage {
            input: 100,
            ..Default::default()
        }),
        now,
    );
    // HOST: charge a usage carrying the SAME (model, provider) for the SAME caller.
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(billing_on_cost())
        .build();
    let none = BTreeMap::new();
    with_caller(&app, Some(&test_key("vk_faithful_meter", None)), |state| {
        super::charge(
            state,
            &usage(
                UsageComponent::Tokens,
                100,
                7,
                Some(("tool:fs", "plane:tools")),
                &none,
            ),
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

/// A usage with no attribution and no caller still records, against the synthetic admission key.
#[test]
fn charge_without_attribution_falls_back_to_synth() {
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(billing_on_cost())
        .build();
    let none = BTreeMap::new();
    with_caller(&app, None, |state| {
        super::charge(state, &usage(UsageComponent::Tokens, 10, 99, None, &none));
    });
    let (cells, counts) = gov.pending_metering_totals();
    assert_eq!(cells, 1, "one synthetic cell recorded");
    assert_eq!(counts.requests, 1);
    // The synthetic key is `plane:admission:99`, distinct from any real id.
}

/// ITEM 36 / DECISION #43 (owner ruling 2026-09-22, "planes always ledger"): the LEDGER WRITE IS
/// UNCONDITIONAL. With `rate_card:` ABSENT (billing off, #42) a host charge STILL appends the plane's
/// counts to the metering ledger — the card decides only whether a READ can turn those counts into
/// money, never whether the write happens. Billing-off is a property of the VIEW (it reads 0 —
/// `busbar_kernel_ledger::cost::price_exact`'s `!card.pricing_enabled()` arm), not of the ledger.
#[test]
fn billing_off_charge_still_appends_the_counts_to_the_ledger() {
    let gov = gov();
    // NO card, NO fee: the purest billing-off posture — nothing here can be priced.
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    assert!(
        !cost.pricing_enabled(),
        "precondition: this deployment is billing-OFF (no rate_card)"
    );
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(cost)
        .build();
    let none = BTreeMap::new();
    with_caller(&app, Some(&test_key("vk_billing_off", None)), |state| {
        super::charge(
            state,
            &usage(
                UsageComponent::Tokens,
                42,
                36,
                Some(("tool:fs", "plane:tools")),
                &none,
            ),
        );
    });
    let (cells, counts) = gov.pending_metering_totals();
    assert_eq!(
        cells, 1,
        "billing off still ledgers: the plane's counts are appended unconditionally (#43)"
    );
    assert_eq!(counts.requests, 1, "the request is on the ledger");
    assert_eq!(
        counts.tokens_input, 42,
        "the ledger is exactly what the plane did: 42 means 42, card or no card"
    );
}

/// ITEM 123: every keyed unit a plane counted is appended VERBATIM to the attributed key's
/// enforcement bucket (#71), where the card prices it: 7 `search_units` at 2000 micro-units each
/// (0.2 cents) read as 1.4 cents, truncated once to 1.
#[test]
fn charge_decodes_the_keyed_unit_tail_into_the_ledger() {
    let spend = units_charge(Some("vk_units"), &["vk_units"]);
    assert_eq!(spend, vec![1], "7 × 0.2 cents = 1.4, truncated once");
}

/// Charge 7 `search_units` under admission 5 — for the caller `caller`, or with none; return the
/// spend each key in `read` reads.
fn units_charge(caller: Option<&str>, read: &[&str]) -> Vec<i64> {
    let card: std::collections::BTreeMap<String, crate::config::RateEntryCfg> =
        serde_yaml::from_str("rerank: { units: { search_units: 2000 } }\n").expect("parses");
    let cost =
        crate::cost::CostModel::resolve_parts(Some(&card), 1, &std::collections::BTreeMap::new());
    let gov = gov();
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(cost)
        .build();
    let units = BTreeMap::from([("search_units".to_string(), 7u64)]);
    let key = caller.map(|id| test_key(id, None));
    with_caller(&app, key.as_ref(), |state| {
        super::charge(
            state,
            &usage(
                UsageComponent::Queries,
                0,
                5,
                Some(("rerank", "plane:example")),
                &units,
            ),
        );
    });
    let now = busbar_kernel::store::now_ms() / 1_000;
    read.iter()
        .map(|id| {
            gov.derived_bucket_usage(&app.cost, id, "total", false, now)
                .expect("the bucket prices")
                .spend_cents
        })
        .collect()
}

/// DEC-SERVE G1 (#65/#40 zero trust): a charge is billed to the caller the auth middleware
/// resolved, never to the synthetic key.
#[test]
fn a_charge_is_billed_to_the_real_caller() {
    let synth = format!("{}5", super::SYNTH_ADMISSION_KEY);
    let spend = units_charge(Some("vk_real_caller"), &["vk_real_caller", &synth]);
    assert_eq!(
        spend,
        vec![1, 0],
        "billed to the real caller, never the synthetic key"
    );
}

/// DEC-SERVE G1b, THE NAMED SYNTHETIC BILLING PATH: a charge with NO caller bills
/// `SYNTH_ADMISSION_KEY` + the admission id.
#[test]
fn a_charge_with_no_caller_bills_the_synthetic_key() {
    let synth = format!("{}5", super::SYNTH_ADMISSION_KEY);
    assert_eq!(synth, "plane:admission:5");
    let spend = units_charge(None, &[&synth, "vk_victim"]);
    assert_eq!(
        spend,
        vec![1, 0],
        "the synthetic key pays; no other key does"
    );
}
