// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hold as a ledger reservation, and the one property that makes it safe to be one.
//!
//! The door's decision is the previous release's, and nothing added on top of it may change who
//! gets served. So every case here is about the same claim from a different angle: sizing a
//! reservation, growing one, and running past one are all ACCOUNTING, and none of the three has a
//! path that turns into a refusal. The last case says it directly — the door admits, the slice is
//! empty, the spend lands anyway.

use busbar_caps::{step::Admit, AdmitToken, Hold, KernelSeal, PrincipalId, UnitToken};

use super::*;
use crate::{Admission as _, AdmissionUnit, ClassEstimate, Estimate};

/// The estimate of a unit expected to consume `quantity` of one class at `price` per unit.
fn estimate(quantity: u64, price: u64, fee_nanos: u64) -> Estimate {
    Estimate {
        per_class: vec![ClassEstimate {
            class: "tokens".to_string(),
            quantity,
            max_unit_price_nanos: price,
        }],
        fee_nanos,
    }
}

/// A chain with no spend cap anywhere has no ceiling a reservation could grow into, so the answer
/// is "as far as you like" rather than a figure. Reading it as zero would turn every over-running
/// unit on an uncapped deployment into an overdraft.
#[test]
fn an_uncapped_chain_has_unbounded_headroom() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_h", Some("g"));
    let now = 1_700_000_000;
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), None);
    let unit = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit.headroom_nanos(&c), u64::MAX);
}

/// The headroom is what the tightest capped bucket has left, and it shrinks as the window fills.
/// It is a read: asking for it charges nothing, so asking twice gives the same answer.
#[test]
fn headroom_is_what_the_tightest_capped_bucket_has_left() {
    let d = door();
    // 10 micro-units per input token: 100_000 input tokens is 100 cents.
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Budget, 1_000, Some(MONTH)),
                limit(LimitMetric::Budget, 100, Some(DAY)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_h2", Some("g"));
    let now = 1_700_000_000;
    // The day cap is the tighter of the two, and nothing is spent yet.
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), Some(100));
    d.record_usage(&c, "", "m", &toks(60_000, 0), now); // 60 cents
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), Some(40));
    assert_eq!(
        d.budget_headroom_cents(&p, &c, "", now),
        Some(40),
        "reading the headroom charges nothing"
    );
    let unit = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit.headroom_nanos(&c), 40 * 10_000_000);
}

/// A window already at its cap has nothing left to grow a reservation into, and says so as zero.
/// Zero is a top-up that does not happen; the next case is what it means for the unit.
#[test]
fn a_spent_window_reports_zero_headroom_rather_than_a_refusal() {
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_h3", Some("g"));
    let now = 1_700_000_000;
    d.record_usage(&c, "", "m", &toks(150_000, 0), now); // 150 cents against a 100-cent cap
    assert_eq!(d.budget_headroom_cents(&p, &c, "", now), Some(0));
    let unit = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit.headroom_nanos(&c), 0);
}

/// The reservation is sized off the estimate and the chain's tier, and the door's answer carries
/// it. Nothing about the size is a decision: a bigger estimate is a bigger hold, not a refusal.
#[test]
fn the_door_sizes_the_reservation_off_the_estimate() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let d = door();
    let p = no_card(0);
    let t = table(&[("g", group_cfg(None, true, Vec::new()))]);
    let c = chain(&t, "vk_h4", Some("g"));
    let mut unit = AdmissionUnit::new(&d, &p, "", 1_700_000_000);
    let who = PrincipalId::new("vk_h4");
    let decision = unit.admit(
        &estimate(1_000, 7, 500),
        &who,
        &c,
        &admit,
        &UnitToken::<Admit>::mint(&seal),
    );
    let admission = decision
        .into_result(&seal)
        .expect("nothing in this chain refuses");
    match admission {
        busbar_caps::Admission::Own(hold) => {
            // 1_000 x 7 + 500 = 7_500, at the neutral tier.
            assert_eq!(hold.reserved(), 7_500);
            assert_eq!(hold.accrued(), 0);
            let _ = busbar_caps::Posted::settle(
                hold,
                &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
                    .expect("no lines"),
                &busbar_caps::LedgerToken::mint(&seal),
            );
        }
        other => panic!("a priced unit opens a hold of its own, got {other:?}"),
    }
}

/// **The property.** A unit the decision admits is never refused by anything the hold does.
///
/// The chain here is at its spend cap for tokens already ledgered, but the request counter and the
/// prospective-spend check both pass — which is exactly the case where the previous release served
/// the request. The unit is admitted, its reservation is far too small, the slice has nothing to
/// grow it with, and the spend still lands in full as an overdraft the unit carries out.
#[test]
fn a_unit_the_door_admits_is_never_refused_by_hold_sizing() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 10, Some(MINUTE))],
        ),
    )]);
    let capped = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let now = 1_700_000_000;
    let who = PrincipalId::new("vk_h5");
    // Fill the capped chain's window past its cap, so the headroom read is zero.
    let spent = chain(&capped, "vk_h5", Some("g"));
    d.record_usage(&spent, "", "m", &toks(200_000, 0), now);

    // The decision the previous release made: a requests limit this unit is under. It admits.
    let c = chain(&t, "vk_h5", Some("g"));
    let mut unit = AdmissionUnit::new(&d, &p, "", now);
    let admission = unit
        .admit(
            &estimate(1, 1, 0),
            &who,
            &c,
            &admit,
            &UnitToken::<Admit>::mint(&seal),
        )
        .into_result(&seal)
        .expect("the door admits: the unit is under every configured limit");

    let busbar_caps::Admission::Own(mut hold) = admission else {
        panic!("a priced unit opens a hold of its own");
    };
    assert_eq!(
        hold.reserved(),
        1,
        "a reservation sized off a tiny estimate"
    );

    // The slice the top-up would come from is empty. There is no arm here that refuses: the spend
    // lands, in full, and what nothing could back is carried.
    let unit_on_spent = AdmissionUnit::new(&d, &p, "", now);
    assert_eq!(unit_on_spent.headroom_nanos(&spent), 0);
    let spend = unit_on_spent.spend(&mut hold, &spent, 9_000);
    assert_eq!(spend.accrued, 9_000);
    assert_eq!(spend.topped_up, 0);
    assert_eq!(spend.overdraft, 8_999);
    assert_eq!(hold.accrued(), 9_000);

    let usage = busbar_caps::Usage::report(
        &busbar_caps::UsageToken::mint(&seal),
        vec![busbar_caps::UsageLine {
            class: busbar_caps::MeterClassId::new("tokens"),
            quantity: 9_000,
            source: busbar_caps::QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    let posted = busbar_caps::Posted::settle(hold, &usage, &busbar_caps::LedgerToken::mint(&seal));
    assert_eq!(posted.settled(), 9_000, "the unit ran and posted in full");
    assert_eq!(posted.overdraft(), 8_999);
    assert!(posted
        .flags()
        .contains(busbar_caps::PostingFlags::OVERDRAFT));
}

/// A reservation that turns out too small and a slice that CAN cover it grows rather than carries.
/// The overdraft is the last resort, not the ordinary path.
#[test]
fn a_reservation_that_can_grow_grows_instead_of_carrying() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_h6", Some("g"));
    let now = 1_700_000_000;
    let mut hold = Hold::open(&admit, PrincipalId::new("vk_h6"), 1_000);
    let unit = AdmissionUnit::new(&d, &p, "", now);
    // 100 cents of headroom is a billion nano-units: far more than the shortfall.
    let spend = unit.spend(&mut hold, &c, 5_000);
    assert_eq!(spend.topped_up, 4_000);
    assert_eq!(spend.overdraft, 0);
    assert_eq!(hold.reserved(), 5_000);
    let _ = busbar_caps::Posted::settle(
        hold,
        &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
            .expect("no lines"),
        &busbar_caps::LedgerToken::mint(&seal),
    );
}
