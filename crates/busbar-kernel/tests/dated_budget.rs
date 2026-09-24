// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OWNER RULING Q14 — DATE EVERYTHING (#79): after a rate-card edit in the middle of a budget
//! window, every money read of the ENFORCEMENT ledger and the budget gate itself price each part of
//! the window at the card in force when it was earned, and agree with the dated metering read.
//!
//! The reads, and where each lands in this crate:
//!
//! - `GET /keys/{id}/usage` — `GovState::usage_for` (busbar-core-admin `keys.rs`);
//! - `GET /groups/{name}/usage` — `GovState::derived_bucket_usage` (`service_operations.rs`);
//! - the `/metrics` spend gauges — both of the above (`metrics/money.rs`);
//! - the hook seam's `budget_state`;
//! - the budget gate — `GovState::try_admit`.
//!
//! `GET /admin/usage` prices metering rows through `busbar_kernel_ledger::cost::price_in_view` at
//! each row's own instant; this test asks that function for the same consumption at the same
//! instants and holds every read above to its answer.
//!
//! A test BINARY of its own, because the dated history is reached through the process-wide
//! rate-epoch holder, which this file installs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_api::{Store, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::{GovState, LimitBlocked, MemoryStore};
use busbar_kernel::rate_apply::{install_rate_epoch, RateEpoch};
use busbar_kernel_ledger::cost::{
    price_in_view, Author, CardEntryDraft, History, LaneClass, LedgerEntry, RateCard,
};

/// The deployment's dated history, as the composition root holds it.
struct Holder(Mutex<Arc<History>>);

impl RateEpoch for Holder {
    fn effective_from_at(&self, at_ms: u64) -> u64 {
        let history = self.0.lock().unwrap().clone();
        let view = history.current();
        view.entry_at(at_ms).map_or(0, |e| e.effective_from())
    }

    fn history(&self) -> Option<Arc<History>> {
        Some(self.0.lock().unwrap().clone())
    }
}

/// The card the history holds for `input_utok` micro-units a token on lane `m`, built the way the
/// configuration builds it.
fn history_card(input_utok: f64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", "input"), input_utok)], 0)
}

/// The engine's cost model for the same figures, with one group `team` capped at `cap` cents a day.
fn cost(input_utok: f64, cap: u64) -> CostModel {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let card = BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok,
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: cap,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), 0, &groups)
}

fn input(n: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".to_string(), n)])
}

/// **THE WORKED EXAMPLE.** 300,000 tokens at 20 micro-units, then the card is edited to 10 and
/// 900,000 more are served. Dated: 600 + 900 = 1,500. Priced at the current card alone: 1,200.
/// Every read answers 1,500, and a gate capped at 1,300 REFUSES — on the undated figure it admitted.
#[test]
fn a_card_edit_mid_window_prices_every_budget_read_and_the_gate_at_the_card_in_force() {
    let holder: &'static Holder = Box::leak(Box::new(Holder(Mutex::new(Arc::new(
        History::opening(history_card(20.0), 0),
    )))));
    install_rate_epoch(holder);

    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let key = VirtualKey {
        id: "vk_dated".to_string(),
        generation_hash: "hash-dated".to_string(),
        name: "dated".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let now = busbar_kernel::store::now();

    // Before the edit: admitted and served at 20.
    let before = cost(20.0, 1_300);
    gov.try_admit(&before, &key, "", now)
        .expect("under the cap");
    gov.record_usage(&before, &key, "", "m", &input(300_000), now);

    // THE EDIT: the configuration now prices at 10, from this instant.
    let edit_ms = busbar_kernel::store::now_ms();
    {
        let mut history = holder.0.lock().unwrap();
        let mut next = History::clone(&history);
        next.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: history_card(10.0),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        *history = Arc::new(next);
    }
    std::thread::sleep(std::time::Duration::from_millis(2));
    let after = cost(10.0, 1_300);
    gov.try_admit(&after, &key, "", now)
        .expect("600 spent, under the cap");
    gov.record_usage(&after, &key, "", "m", &input(900_000), now);

    // What `GET /admin/usage` answers for the same consumption: each part at its own instant.
    let reference = {
        let history = holder.0.lock().unwrap().clone();
        price_in_view(
            &[
                LedgerEntry::new("m", 0).with_whole("input", 300_000),
                LedgerEntry::new("m", edit_ms).with_whole("input", 900_000),
            ],
            &history.current(),
        )
        .unwrap()
        .minor_i64()
        .unwrap()
    };
    assert_eq!(reference, 1_500, "the dated read of the worked example");

    let team = &after.group_named("team").expect("configured").buckets[0];
    let group_read = gov
        .derived_bucket_usage(&after, &team.bucket_id, team.window, true, now)
        .expect("priced");
    assert_eq!(
        group_read.spend_cents, reference,
        "GET /groups/team/usage and the group spend gauge (1,200 = the current card repricing the \
         window's first 300,000 tokens)"
    );
    let key_read = gov
        .usage_for(&after, &key.id, now)
        .expect("priced")
        .expect("the key exists");
    assert_eq!(
        key_read.spend_cents, reference,
        "GET /keys/vk_dated/usage and the key spend gauge"
    );
    let hook = gov.budget_state(&after, &key, now);
    assert!(
        hook.iter()
            .all(|b| b.spend_micros_at_current_rate == reference * 10_000),
        "the hook seam's budget_state: {hook:?}"
    );

    // THE GATE, ON THE DATED FIGURE: 1,500 is over a 1,300 cap. The current card alone reads 1,200
    // and would have admitted.
    match gov.try_admit(&after, &key, "", now) {
        Err(LimitBlocked::Limit { metric, group, .. }) => {
            assert_eq!((metric, group.as_str()), ("budget", "team"));
        }
        other => panic!("the gate must refuse on the dated 1,500: {other:?}"),
    }

    // The durable write-behind row is per model and carries no era: the two eras flush as ONE
    // model's counts, the wire a store has always been sent.
    gov.flush_budgets();
    let window = busbar_kernel::governance::budget_window(team.window, now);
    let row = store.get_usage(&team.bucket_id, window).unwrap();
    assert_eq!(row.models.len(), 1, "{row:?}");
    assert_eq!(row.models[0].usage_units.get("input"), Some(&1_200_000));
}
