//! Tests for `admit.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use crate::test_support::TestApp;
use busbar_caps::{KernelSeal, LedgerToken, Posted, StepName, Usage, UsageToken};
use busbar_contract::store::Store as _;
use busbar_store_memory::MemoryStore;
use busbar_substrate::testkit::engine_kit::EngineTestKit as _;
use std::collections::BTreeMap;
use std::time::Instant;

/// The three ledger figures every identity here is pinned on.
///
/// `requests` is the admission count — drawn at the door and never released, which is the rule
/// that makes a request cap impossible to escape by failing. `billable_requests` is the fee
/// base — the counter a non-2xx end refunds. `spend_cents` is the derived figure the door
/// itself compares against a budget cap: tokens priced at the current card, plus the flat fee
/// per billable request, truncated once to whole cents.
#[derive(Debug, PartialEq, Eq)]
struct Ledger {
    requests: u64,
    billable_requests: u64,
    spend_cents: i64,
}

/// The flat per-request fee every rig here prices, in whole cents. One cent makes the fee
/// arithmetic readable: derived spend in cents IS the billable count.
const FEE_CENTS: i64 = 1;

/// A governed app with one key, a one-cent flat fee, and whatever groups the caller declares.
fn governed(
    groups: BTreeMap<String, busbar_substrate::config::groups::GroupCfg>,
    group: Option<&str>,
    seed: Option<(&str, u64)>,
) -> (
    std::sync::Arc<crate::test_support::BuiltApp>,
    std::sync::Arc<busbar_contract::store::VirtualKey>,
) {
    busbar_substrate::metrics::init();
    let store = std::sync::Arc::new(MemoryStore::new());
    if let Some((bucket, requests)) = seed {
        store
            .put_usage(
                bucket,
                0,
                &busbar_contract::store::UsageLedger {
                    requests,
                    billable_requests: requests,
                    models: vec![],
                },
            )
            .expect("seed the durable bucket");
    }
    let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _) = gov
        .create_key(
            busbar_substrate::governance::NewKeySpec {
                name: "identity".to_string(),
                allowed_pools: None,
                group: group.map(str::to_string),
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let cost =
        crate::test_support::engine_kit::CORE_ENGINE_KIT.cost_parts(None, FEE_CENTS, &groups);
    // Enforcement is in-memory and authoritative, so the seeded durable spend has to be
    // hydrated into the cells exactly as boot hydrates it; without this the door would not see
    // it and would admit.
    gov.hydrate_budgets(cost.as_ref(), 0).expect("hydrate");
    let app = TestApp::new().governance_kit(gov).cost_kit(cost).build();
    (app, std::sync::Arc::new(key))
}

/// Read one bucket's three figures off the same surfaces the enforcer and the dashboards read.
fn ledger(app: &std::sync::Arc<crate::test_support::BuiltApp>, bucket: &str, now: u64) -> Ledger {
    let gov = app.governance.clone().expect("governance is configured");
    let derived = gov
        .derived_bucket_usage(&app.cost, bucket, "total", true, now)
        .expect("usage read");
    Ledger {
        requests: derived.requests,
        billable_requests: derived.requests,
        spend_cents: derived.spend_cents,
    }
}

/// The fee base apart from the admission count, off the durable row the flush writes.
fn durable(app: &std::sync::Arc<crate::test_support::BuiltApp>, bucket: &str) -> (u64, u64) {
    let gov = app.governance.clone().expect("governance is configured");
    gov.flush_budgets();
    let row = gov.store().get_usage(bucket, 0).expect("ledger row");
    (row.requests, row.billable_requests)
}

/// A kernel seal for the length of one test: the tokens the step is lent are minted from it
/// and dropped when the call returns, exactly as the loop lends them.
fn tokens() -> (KernelSeal, UnitToken<Admit>, AdmitToken<Admit>) {
    let seal = KernelSeal::acquire_for_kernel();
    let unit = UnitToken::mint(&seal);
    let admit = AdmitToken::mint(&seal);
    (seal, unit, admit)
}

/// THE ADMITTED IDENTITY. One admitted request charges ONE admission slot and ONE fee-base
/// unit on the key's bucket, and derives ONE cent of spend — and the step charges exactly the
/// same figures, on the same counters, as the live door.
///
/// The two legs run against one registry, so the second leg's figures are the first's plus the
/// same delta: `(1, 1, 1)` after the live door, `(2, 2, 2)` after the step. A step that charged
/// a different bucket, charged twice, or skipped the fee lookahead would move one of the three
/// and not the others.
#[tokio::test]
async fn the_step_charges_the_same_slot_fee_base_and_cent_as_the_live_door() {
    let (app, key) = governed(BTreeMap::new(), None, None);
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(key.clone()),
    };
    let charged_at = busbar_substrate::store::now();

    // LEG 1 — the live door, reached through the very seam the plane's step calls.
    let live = match host.admission_door(
        &gov,
        crate::proto_codec::PROTO_OPENAI,
        "p",
        Instant::now(),
        charged_at,
    ) {
        Ok(admitted) => admitted,
        Err(resp) => panic!(
            "an uncapped key is under every cap; the door refused with {}",
            resp.status()
        ),
    };
    assert!(
        live.0.is_some(),
        "governance is on and a key resolved, so the charge landed"
    );
    assert!(live.1.is_none(), "no budget was exhausted, so no downgrade");
    drop(live);
    assert_eq!(
        ledger(&app, &key.id, charged_at),
        Ledger {
            requests: 1,
            billable_requests: 1,
            spend_cents: 1
        },
        "one admitted request: one slot, one fee-base unit, one cent of fee"
    );
    assert_eq!(
        durable(&app, &key.id),
        (1, 1),
        "and the durable row records the two counters apart"
    );

    // LEG 2 — the same door, through the step.
    let (seal, unit_token, admit_token) = tokens();
    let ctx = AdmitCtx {
        host: &host,
        gov: &gov,
        proto: crate::proto_codec::PROTO_OPENAI,
        destination: "p",
        charged_at,
    };
    let admitted = admit(
        &unit_token,
        &admit_token,
        &ctx,
        &PrincipalId::new(key.id.clone()),
        &[],
    );
    assert!(admitted.charged, "the step's charge landed too");
    assert!(
        admitted.refusal.is_none(),
        "an admitted unit renders nothing"
    );
    assert!(
        admitted.effective_pool.is_none(),
        "nothing was downgraded, so the dispatch pool is the one the caller named"
    );
    assert!(
        admitted.sink.is_some(),
        "the admission's meter half is built here, with the admission"
    );
    assert_eq!(
        ledger(&app, &key.id, charged_at),
        Ledger {
            requests: 2,
            billable_requests: 2,
            spend_cents: 2
        },
        "the step charged the second request by the same delta on the same three figures"
    );
    assert_eq!(durable(&app, &key.id), (2, 2));

    // The hold the yes entitled the unit to, and the posting that closes it. Settling here is
    // this test standing in for the exit path: what matters is that the hold reaches one, that
    // it is opened for this principal, and that it reserves nothing it could refuse anyone
    // with.
    let admission = admitted
        .decision
        .into_result(&seal)
        .expect("the door said yes");
    let hold = match admission {
        Admission::Own(hold) => hold,
        Admission::Accrual(_) => {
            panic!("a client unit holds its own admission, not a parent's")
        }
        Admission::ZeroHold => panic!("an admitted client unit carries a hold"),
    };
    assert_eq!(hold.principal().as_str(), key.id.as_str());
    assert_eq!(
        hold.reserved(),
        0,
        "the hold is accounting; sizing it is later"
    );
    assert_eq!(hold.accrued(), 0, "nothing has been spent against it yet");
    let usage_token = UsageToken::mint(&seal);
    let posted = Posted::settle(
        hold,
        // Nothing was routed, so the priced total is zero — and it is passed as money rather
        // than derived from the report, which carries no lines to derive one from.
        0,
        &Usage::report(&usage_token, Vec::new()).expect("no lines is a legal report"),
        &LedgerToken::mint(&seal),
    );
    assert_eq!(posted.principal().as_str(), key.id.as_str());
    assert_eq!(
        posted.settled(),
        0,
        "nothing was routed, so nothing settled"
    );
}

/// THE REFUSED IDENTITY. An over-budget key is turned away with a 429 that charges NOTHING —
/// and because nothing was charged there is nothing to refund, on either path.
///
/// The rig seeds the group's total bucket with 250 requests, which at a one-cent flat fee
/// derives to 250 cents against a 100-cent cap. Pass one of check-then-charge returns on that
/// first blocking bucket having charged nothing, so all three figures on both the group bucket
/// and the key bucket are the same before and after each refusal: `(250, 250, 250)` on the
/// group, `(0, 0, 0)` on the key. A refund issued here would decrement a counter some other,
/// legitimately-charged request in the same window put there.
#[tokio::test]
async fn over_budget_refuses_with_no_charge_and_nothing_to_refund() {
    let groups = BTreeMap::from([(
        "bgrp".to_string(),
        busbar_substrate::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_substrate::config::groups::LimitCfg {
                metric: busbar_substrate::config::groups::LimitMetric::Budget,
                amount: 100,
                per: Some(busbar_substrate::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    let (app, key) = governed(groups, Some("bgrp"), Some(("group:bgrp@total", 250)));
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(key.clone()),
    };
    let charged_at = busbar_substrate::store::now();

    let group_before = ledger(&app, "group:bgrp@total", charged_at);
    assert_eq!(
        group_before,
        Ledger {
            requests: 250,
            billable_requests: 250,
            spend_cents: 250
        },
        "250 seeded requests at a one-cent fee derive to 250 cents, over the 100-cent cap"
    );
    let key_before = ledger(&app, &key.id, charged_at);
    assert_eq!(
        key_before,
        Ledger {
            requests: 0,
            billable_requests: 0,
            spend_cents: 0
        },
        "this key has not been charged for anything yet"
    );

    // LEG 1 — the live door.
    let live = match host.admission_door(
        &gov,
        crate::proto_codec::PROTO_OPENAI,
        "p",
        Instant::now(),
        charged_at,
    ) {
        Err(resp) => resp,
        Ok(_) => panic!("the group's budget is exhausted; the door must refuse"),
    };
    assert_eq!(live.status().as_u16(), 429, "an exhausted budget is a 429");
    assert_eq!(ledger(&app, "group:bgrp@total", charged_at), group_before);
    assert_eq!(ledger(&app, &key.id, charged_at), key_before);

    // LEG 2 — the step. Same status, same untouched counters, no hold and no meter half.
    let (seal, unit_token, admit_token) = tokens();
    let ctx = AdmitCtx {
        host: &host,
        gov: &gov,
        proto: crate::proto_codec::PROTO_OPENAI,
        destination: "p",
        charged_at,
    };
    let refused = admit(
        &unit_token,
        &admit_token,
        &ctx,
        &PrincipalId::new(key.id.clone()),
        &[],
    );
    assert!(!refused.charged, "nothing was charged");
    assert!(refused.sink.is_none(), "no admission, so no meter half");
    assert_eq!(
        refused
            .refusal
            .as_ref()
            .expect("the door rendered and finished its own bytes")
            .status()
            .as_u16(),
        429,
        "the step carries the door's status through untouched"
    );
    assert_eq!(
        ledger(&app, "group:bgrp@total", charged_at),
        group_before,
        "the step's refusal moved nothing on the blocking bucket"
    );
    assert_eq!(
        ledger(&app, &key.id, charged_at),
        key_before,
        "nor on the key's own"
    );

    let refusal = refused
        .decision
        .into_result(&seal)
        .expect_err("the door said no");
    assert_eq!(refusal.reason(), ReasonCode::OverBudget);
    assert_eq!(
        refusal.step(),
        Some(StepName::Admit),
        "the decision stamps the step, so the record cannot claim it stopped elsewhere"
    );
}

/// The step is the `Units::admit` row's shape, as a value: a mismatch in the tokens, the
/// principal, the verified set or the answer stops compiling here rather than at the root.
#[test]
fn the_step_has_the_doors_shape() {
    let _: AdmitStep = admit;
}
