// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A posting that settles above its reservation carries the excess as its overdraft FIGURE, not
//! only as its flag (item 318). The figures here are the ledger identity's own: for one posting,
//! `settled - reserved + released - overdraft` is the whole of what the identity reads, and it has
//! to be zero.

use crate::caps::step::MeterClassId;
use crate::caps::usage::{QuantitySource, UsageLine};
use crate::caps::*;
use crate::caps::{Consumption, KernelSeal};

fn settle_without_spend(reserved: u64, priced: u128) -> Posted {
    let seal = KernelSeal::acquire_for_kernel();
    let hold = Hold::open(
        &Grant::<Admittance>::mint(&seal),
        PrincipalId::new("acct-318"),
        reserved,
    );
    let usage = Usage::report(
        &Grant::<Consumption>::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("tokens"),
            quantity: 1,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line is within the bound");
    Posted::settle(hold, priced, &usage, &Grant::<WriteMoney>::mint(&seal))
}

fn identity_residual(p: &Posted) -> i128 {
    i128::from(p.settled()) - i128::from(p.reserved()) + i128::from(p.released())
        - i128::from(p.overdraft())
}

#[test]
fn a_settlement_above_a_reservation_the_hold_never_overran_carries_the_excess() {
    // The hold was never spent past, so its own counter is zero; the priced total is 150 on a
    // reservation of 100. 50 settled that nothing drew is the overdraft.
    let posted = settle_without_spend(100, 150);
    assert!(posted.flags().contains(PostingFlags::OVERDRAFT));
    assert_eq!(
        posted.overdraft(),
        50,
        "the flag and the figure say the same thing"
    );
    assert_eq!(
        identity_residual(&posted),
        0,
        "the posting closes the identity"
    );
}

#[test]
fn every_reserved_and_priced_pair_closes_the_identity() {
    let amounts = [0u64, 1, 99, 100, 101, 999, 1_000_000];
    for &reserved in &amounts {
        for &priced in &amounts {
            let posted = settle_without_spend(reserved, u128::from(priced));
            assert_eq!(
                identity_residual(&posted),
                0,
                "reserved {reserved}, priced {priced}: {posted:?}"
            );
            assert_eq!(
                posted.flags().contains(PostingFlags::OVERDRAFT),
                posted.overdraft() > 0,
                "reserved {reserved}, priced {priced}: flag without figure or figure without flag"
            );
        }
    }
}
