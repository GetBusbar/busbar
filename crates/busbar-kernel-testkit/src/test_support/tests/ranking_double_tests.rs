use super::{rank, Strategy};
use busbar_contract::abi::sdk::hook::{DecodedCandidate, Verdict};
use busbar_contract::signal::SignalBag;

fn cand(
    idx: usize,
    cost: Option<f64>,
    latency: Option<f64>,
    conc: usize,
    headroom: Option<f64>,
) -> DecodedCandidate<'static> {
    DecodedCandidate {
        idx,
        model: "m".into(),
        provider: "p".into(),
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: cost,
        tags: Vec::new(),
        latency_ms: latency,
        available_concurrency: conc,
        budget_remaining: None,
        rate_headroom: headroom,
        signals: SignalBag::default(),
    }
}

fn cost(idx: usize, c: Option<f64>) -> DecodedCandidate<'static> {
    cand(idx, c, None, 1, None)
}

fn headroom(idx: usize, h: Option<f64>) -> DecodedCandidate<'static> {
    cand(idx, None, None, 1, h)
}

fn prefer(order: &[usize]) -> Verdict {
    Verdict::Prefer(order.to_vec())
}

#[test]
fn an_all_infinite_cost_pool_ranks_by_index_as_1_5_5_did() {
    let pool = [cost(0, Some(f64::INFINITY)), cost(1, Some(f64::INFINITY))];
    assert_eq!(rank(Strategy::Cheapest, &pool), prefer(&[0, 1]));
}

#[test]
fn a_negative_infinite_cost_ranks_first_as_1_5_5_did() {
    let pool = [
        cost(0, Some(3.0)),
        cost(1, Some(f64::NEG_INFINITY)),
        cost(2, None),
    ];
    assert_eq!(rank(Strategy::Cheapest, &pool), prefer(&[1, 0, 2]));
}

#[test]
fn an_infinite_headroom_ranks_first_under_usage_as_1_5_5_did() {
    let pool = [
        headroom(0, Some(0.5)),
        headroom(1, None),
        headroom(2, Some(f64::INFINITY)),
    ];
    assert_eq!(rank(Strategy::Usage, &pool), prefer(&[2, 0, 1]));
}

#[test]
fn signed_zeros_tie_and_the_index_decides_as_1_5_5_did() {
    let pool = [cost(0, Some(0.0)), cost(1, Some(-0.0))];
    assert_eq!(rank(Strategy::Cheapest, &pool), prefer(&[0, 1]));
    let pool = [headroom(0, Some(-0.0)), headroom(1, Some(0.0))];
    assert_eq!(rank(Strategy::Usage, &pool), prefer(&[0, 1]));
}

#[test]
fn a_nan_cost_sorts_after_every_number_and_ties_an_absent_one() {
    let pool = [
        cost(0, Some(2.0)),
        cost(1, Some(f64::NAN)),
        cost(2, Some(1.0)),
    ];
    assert_eq!(rank(Strategy::Cheapest, &pool), prefer(&[2, 0, 1]));
    let pool = [cost(0, None), cost(1, Some(f64::NAN)), cost(2, Some(5.0))];
    assert_eq!(rank(Strategy::Cheapest, &pool), prefer(&[2, 0, 1]));
}

#[test]
fn an_all_nan_headroom_pool_ranks_by_index_as_1_5_5_did() {
    let pool = [headroom(0, Some(f64::NAN)), headroom(1, Some(f64::NAN))];
    assert_eq!(rank(Strategy::Usage, &pool), prefer(&[0, 1]));
}

#[test]
fn finite_and_absent_keys_rank_as_before() {
    let pool = [cost(0, Some(15.0)), cost(1, Some(3.0)), cost(2, None)];
    assert_eq!(rank(Strategy::Cheapest, &pool), prefer(&[1, 0, 2]));
    let none = [cost(0, None), cost(1, None)];
    assert_eq!(rank(Strategy::Cheapest, &none), Verdict::Abstain);
    let busy = [
        cand(0, None, None, 2, None),
        cand(1, None, None, 9, None),
        cand(2, None, None, 5, None),
    ];
    assert_eq!(rank(Strategy::LeastBusy, &busy), prefer(&[1, 2, 0]));
    assert_eq!(rank(Strategy::Weighted, &busy), Verdict::Abstain);
}
