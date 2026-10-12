// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pricing law under test.
//!
//! The three files below split by clause: rates and the pin, the stored posting and the tier, and
//! the read-time derivation. The identity file is the one that ties the two readers together — the
//! older release's derivation at a pinned card against the sum of the stored nano-units.

use busbar_contract::caps::step::MeterClassId;
use busbar_contract::caps::{QuantitySource, UsageLine};

use crate::cost::{LaneClass, RateCard};

/// A nano-unit total in whole MINOR units through the CHECKED projection (item 28): the one money
/// type, which refuses a figure the served type cannot hold rather than pinning it at a ceiling.
pub(crate) fn minor_nanos(nanos: u128) -> Result<i64, crate::cost::MoneyError> {
    crate::cost::Money::of_nanos(nanos).and_then(crate::cost::Money::minor_i64)
}

/// [`minor_nanos`] at the micro scale: the same checked projection, the finer narrowing.
pub(crate) fn micros_nanos(nanos: u128) -> Result<i64, crate::cost::MoneyError> {
    crate::cost::Money::of_nanos(nanos).and_then(crate::cost::Money::micros_i64)
}

mod derive_tests;
mod fee_lane_tests;
mod history_tests;
mod identity_tests;
mod posting_tests;
mod rate_tests;
mod scale_tests;
mod view_tests;

/// The four classes the older release priced, under the names it used for them.
pub(crate) const INPUT: &str = "input";
pub(crate) const OUTPUT: &str = "output";
pub(crate) const CACHE_READ: &str = "cache_read";
pub(crate) const CACHE_WRITE: &str = "cache_write";

/// The plain line form the read-time derivation takes.
pub(crate) fn lines(entries: &[(&'static str, u64)]) -> Vec<UsageLine> {
    entries
        .iter()
        .map(|(class, quantity)| UsageLine {
            class: MeterClassId::new(class),
            quantity: *quantity,
            source: QuantitySource::Count,
            estimated: false,
        })
        .collect()
}

/// A card over one lane, priced in micro-units per token for the two reserved classes the older
/// release's tests used.
pub(crate) fn card(
    lane: &'static str,
    input_micro: f64,
    output_micro: f64,
    fee_cents: i64,
) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(lane, INPUT), input_micro),
            (LaneClass::new(lane, OUTPUT), output_micro),
        ],
        fee_cents,
    )
}

/// A card over one lane pricing all four of the older release's classes.
pub(crate) fn card4(lane: &'static str, rates: [f64; 4], fee_cents: i64) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(lane, INPUT), rates[0]),
            (LaneClass::new(lane, OUTPUT), rates[1]),
            (LaneClass::new(lane, CACHE_READ), rates[2]),
            (LaneClass::new(lane, CACHE_WRITE), rates[3]),
        ],
        fee_cents,
    )
}
