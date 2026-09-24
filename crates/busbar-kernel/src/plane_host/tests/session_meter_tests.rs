//! THE KERNEL SESSION METER IS FIGURE-NEUTRAL (BUSBAR-1.6.0 #43, #71). The arithmetic moved out of the
//! voice plane's D2 lease; these pin that it did not change on the way: the same stored figure after
//! every turn, the same cap comparison, and the same hard-close turn for a fixed script — the figures
//! the plane-side lease produced for the same script (its oracle pinned them: settled 3 then 6
//! against a cap of 5, hard-closing on the SECOND turn).
use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// A host lease slice that behaves as the engine's `CostHold` registry does, and prices every reserved
/// unit at ONE nanodollar — so a turn's unit sum IS its settled increment and every figure is legible.
#[derive(Default)]
struct UnitRateHost {
    leases: Mutex<HashMap<u64, (u128, Option<u128>)>>,
    next: Mutex<u64>,
}

const UNPRICED: &str = "__unpriced__";

impl MeteringHost for UnitRateHost {
    fn cost_reserve(&self, _e: u128, _f: u128, cap: Option<u128>) -> Option<CostLeaseId> {
        if cap == Some(0) {
            return None;
        }
        let mut next = self.next.lock().unwrap();
        *next += 1;
        self.leases.lock().unwrap().insert(*next, (0, cap));
        Some(CostLeaseId(*next))
    }
    fn cost_settle(&self, lease: CostLeaseId, exact: u128) -> Option<SettleOutcome> {
        let mut leases = self.leases.lock().unwrap();
        let (settled, cap) = leases.get_mut(&lease.0)?;
        *settled += exact;
        Some(SettleOutcome {
            exhausted: matches!(*cap, Some(c) if *settled >= c),
        })
    }
    fn cost_settled(&self, lease: CostLeaseId) -> Option<u128> {
        self.leases.lock().unwrap().get(&lease.0).map(|l| l.0)
    }
    fn cost_close(&self, lease: CostLeaseId) -> Option<u128> {
        self.leases.lock().unwrap().remove(&lease.0).map(|l| l.0)
    }
    fn price_usage(&self, model: &str, usage: &Usage) -> Option<u128> {
        (model != UNPRICED).then(|| usage.usage_units.values().copied().map(u128::from).sum())
    }
}

fn turn(units: u64) -> Usage {
    let mut usage = Usage::default();
    usage.usage_units.insert("output_tokens".into(), units);
    usage
}

fn budget(cap: Option<u64>) -> SessionBudget {
    SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: cap,
    }
}

/// THE NEUTRALITY SCRIPT: cap 5, turns of 3 units. Before the move the plane-side lease stored 3 then
/// 6 and hard-closed on the second turn; the kernel meter must store and close identically.
#[test]
fn fixed_script_stores_the_same_figure_and_closes_on_the_same_turn() {
    let meter = HostMeteringPort::new(Arc::new(UnitRateHost::default()));
    let id = meter.open(&budget(Some(5))).expect("a capped budget opens");
    let mut stored = Vec::new();
    let mut must_close_at = None;
    for n in 1..=3 {
        let verdict = meter.report_turn(id, "gpt-realtime", &turn(3));
        stored.push(meter.settled(id));
        if verdict == TurnVerdict::MustClose && must_close_at.is_none() {
            must_close_at = Some(n);
        }
    }
    assert_eq!(
        stored[..2],
        [3, 6],
        "the same stored figure after each turn"
    );
    assert_eq!(must_close_at, Some(2), "the same hard-close turn: 6 >= 5");
}

#[test]
fn a_refuse_all_budget_never_opens_and_uncapped_never_closes() {
    let meter = HostMeteringPort::new(Arc::new(UnitRateHost::default()));
    assert!(meter.open(&budget(Some(0))).is_none());
    let id = meter.open(&budget(None)).expect("uncapped opens");
    assert_eq!(
        meter.report_turn(id, "m", &turn(u64::MAX)),
        TurnVerdict::Live
    );
    assert_eq!(meter.settled(id), u64::MAX);
}

#[test]
fn an_unpriced_model_or_an_unknown_session_closes_the_carrier() {
    let meter = HostMeteringPort::new(Arc::new(UnitRateHost::default()));
    let id = meter.open(&budget(Some(100))).expect("opens");
    assert_eq!(
        meter.report_turn(id, UNPRICED, &turn(1)),
        TurnVerdict::MustClose
    );
    assert_eq!(meter.settled(id), 0, "an unpriced turn settles nothing");
    meter.close(id);
    meter.close(id);
    assert_eq!(meter.report_turn(id, "m", &turn(1)), TurnVerdict::MustClose);
    assert_eq!(meter.settled(id), 0, "a closed session reads 0 settled");
}

#[test]
fn the_local_meter_prices_nothing_and_refuses_only_a_refuse_all_cap() {
    assert!(LocalMeteringPort.open(&budget(Some(0))).is_none());
    let id = LocalMeteringPort.open(&budget(Some(1))).expect("opens");
    assert_eq!(
        LocalMeteringPort.report_turn(id, "m", &turn(u64::MAX)),
        TurnVerdict::Live
    );
    assert_eq!(LocalMeteringPort.settled(id), 0);
}

#[test]
fn a_budget_chain_caps_at_its_tightest_bucket_widened_to_nanos() {
    let bucket = |remaining: Option<i64>| busbar_api::BudgetBucketState {
        bucket_id: "k".into(),
        budget_group: None,
        pool: None,
        spend_micros_at_current_rate: 0,
        remaining_micros: remaining,
        window_start: 0,
        budget_period: "total".into(),
    };
    assert_eq!(cap_nanos_from_buckets(&[]), None);
    assert_eq!(cap_nanos_from_buckets(&[bucket(None)]), None);
    assert_eq!(
        cap_nanos_from_buckets(&[bucket(Some(7)), bucket(Some(3))]),
        Some(3_000)
    );
    assert_eq!(cap_nanos_from_buckets(&[bucket(Some(-1))]), Some(0));
}
