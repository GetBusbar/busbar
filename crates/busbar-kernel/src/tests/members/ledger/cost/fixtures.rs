// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::step::MeterClassId;
use busbar_contract::caps::{Consumption, Grant, KernelSeal, QuantitySource, Usage, UsageLine};

use busbar_kernel_ledger::cost::{price, History, LaneClass, Posting, Priced, RateCard};

pub(crate) fn minor_nanos(nanos: u128) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
    busbar_kernel_ledger::cost::Money::of_nanos(nanos)
        .and_then(busbar_kernel_ledger::cost::Money::minor_i64)
}

pub(crate) fn micros_nanos(nanos: u128) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
    busbar_kernel_ledger::cost::Money::of_nanos(nanos)
        .and_then(busbar_kernel_ledger::cost::Money::micros_i64)
}

pub(crate) fn minor(p: &Priced) -> i64 {
    minor_nanos(p.priced_nanos).expect("the fixture's figure is in range")
}

pub(crate) fn micros(p: &Priced) -> i64 {
    micros_nanos(p.priced_nanos).expect("the fixture's figure is in range")
}

pub(crate) const INPUT: &str = "input";
pub(crate) const OUTPUT: &str = "output";
pub(crate) const CACHE_READ: &str = "cache_read";
pub(crate) const CACHE_WRITE: &str = "cache_write";

pub(crate) fn usage(entries: &[(&'static str, u64)]) -> Usage {
    let seal = KernelSeal::acquire_for_kernel();
    let token = Grant::<Consumption>::mint(&seal);
    Usage::report(&token, lines(entries)).expect("a test report stays within the line bound")
}

pub(crate) fn estimated_usage(entries: &[(&'static str, u64)]) -> Usage {
    let seal = KernelSeal::acquire_for_kernel();
    let token = Grant::<Consumption>::mint(&seal);
    Usage::estimate(&token, lines(entries)).expect("a test report stays within the line bound")
}

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

pub(crate) fn priced(
    card: &RateCard,
    lane: &str,
    usage: &busbar_contract::caps::Usage,
    fee_count: u64,
    tier_bp: u32,
) -> Priced {
    let history = History::opening(card.clone(), 0);
    let posting = Posting::from_usage(lane, usage, fee_count, tier_bp, 0, 0);
    price(&history.current(), &posting).expect("a card at instant zero covers a posting at zero")
}

pub(crate) fn posting_at(lane: &str, arrived_ms: u64, lines: &[(&'static str, u64)]) -> Posting {
    Posting::from_usage(
        lane,
        &usage(lines),
        0,
        busbar_kernel_ledger::cost::STANDARD_TIER_BP,
        arrived_ms,
        arrived_ms,
    )
}
