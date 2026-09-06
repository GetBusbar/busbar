// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The spend derivation the budget comparison reads.
//!
//! No spend figure is ever stored. A bucket holds token counts and a request count; the money is
//! recomputed from those against the current rate table every time the door is asked. That is why
//! an operator's rate correction takes effect on the next request with no data fix, and it is why
//! this arithmetic is part of the decision rather than a reporting detail: change the truncation
//! and you change who gets admitted.
//!
//! Everything here is integer. Rates come in as micro-units per token, are multiplied by a
//! thousand and rounded ONCE at load, and are integers from then on.

use std::collections::BTreeMap;

/// Nano-units per cent: the divisor that lands a derived nano-unit total in whole cents, and the
/// multiplier that takes a configured cent cap back into the nano-units a hold is sized in.
pub const NANOS_PER_CENT: u128 = 10_000_000;

/// The uncached input token key.
pub const UNIT_INPUT: &str = "input";
/// The output token key.
pub const UNIT_OUTPUT: &str = "output";
/// The cache-read token key — a prompt read back from cache, priced apart from uncached input.
pub const UNIT_CACHE_READ: &str = "cache_read";
/// The cache-write (cache creation) token key.
pub const UNIT_CACHE_WRITE: &str = "cache_write";

/// The four reserved token keys, in canonical order. A ledger map may carry other keys; only
/// these four price through the rate table.
pub const RESERVED_UNITS: [&str; 4] = [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE];

/// Saturating sum of every count in a keyed unit map — the scalar "total tokens" view over a
/// ledger cell's per-model counters.
pub fn units_total(units: &BTreeMap<String, u64>) -> u64 {
    units.values().fold(0u64, |acc, v| acc.saturating_add(*v))
}

/// One model's per-token rates in integer nano-units per token: config micro-units times a
/// thousand, rounded once at resolve. All the hot-path money math is integer over these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateNanos {
    /// Nano-units per uncached input token.
    pub input: u64,
    /// Nano-units per output token.
    pub output: u64,
    /// Nano-units per cache-read token.
    pub cache_read: u64,
    /// Nano-units per cache-write token.
    pub cache_write: u64,
}

impl RateNanos {
    /// Project the four raw micro-units-per-token config floats into this integer rate. The clamp
    /// is defence in depth: a value that is not finite, or is negative, becomes 0 rather than a
    /// garbage integer.
    pub fn from_micros_per_token(
        input: f64,
        output: f64,
        cache_read: f64,
        cache_write: f64,
    ) -> Self {
        fn nanos(utok: f64) -> u64 {
            let v = (utok * 1000.0).round();
            if v.is_finite() && v > 0.0 {
                v as u64
            } else {
                0
            }
        }
        Self {
            input: nanos(input),
            output: nanos(output),
            cache_read: nanos(cache_read),
            cache_write: nanos(cache_write),
        }
    }

    /// The nano rate for one reserved key (0 for any other key — open keys price through a
    /// separate per-model table that the enforcement summation deliberately does not consult).
    #[inline]
    pub fn reserved_rate(&self, unit: &str) -> u64 {
        match unit {
            UNIT_INPUT => self.input,
            UNIT_OUTPUT => self.output,
            UNIT_CACHE_READ => self.cache_read,
            UNIT_CACHE_WRITE => self.cache_write,
            _ => 0,
        }
    }

    /// The nano-unit cost of a unit map's reserved four at this rate: four multiply-adds in u128
    /// (a u64 count times a u64 nano rate cannot overflow a u128).
    #[inline]
    pub fn reserved_nanos(&self, units: &BTreeMap<String, u64>) -> u128 {
        RESERVED_UNITS.iter().fold(0u128, |acc, u| {
            let n = units.get(*u).copied().unwrap_or(0);
            acc + (n as u128) * (self.reserved_rate(u) as u128)
        })
    }
}

/// The rate table plus the flat per-request fee: everything the budget comparison needs to turn a
/// bucket's counters into cents.
///
/// `rates` absent means no rate card is configured, and then every model prices at zero — token
/// caps still work (they count tokens, not money) and the flat fee still bills. `rates` present
/// means the table is authoritative: a model with no entry derives at zero, which is the operator's
/// rate-card edit taking effect retroactively, by design.
#[derive(Debug, Clone, Default)]
pub struct Pricer {
    rates: Option<BTreeMap<String, RateNanos>>,
    price_per_request_cents: i64,
}

impl Pricer {
    /// A pricer with no rate card: token pricing is zero everywhere, the flat fee still applies.
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self {
            rates: None,
            price_per_request_cents,
        }
    }

    /// A pricer with a rate card.
    pub fn with_card(price_per_request_cents: i64, rates: BTreeMap<String, RateNanos>) -> Self {
        Self {
            rates: Some(rates),
            price_per_request_cents,
        }
    }

    /// Whether a rate card is configured.
    pub fn pricing_enabled(&self) -> bool {
        self.rates.is_some()
    }

    /// The flat per-request fee, in cents. This is the fee lookahead the budget check adds to a
    /// bucket's derived spend before comparing against the cap.
    pub fn price_per_request_cents(&self) -> i64 {
        self.price_per_request_cents
    }

    /// The effective rate for a model. Card absent: a zero rate, so every model prices at 0. Card
    /// present and the model priced: its rate. Card present and the model unknown: `None`, and the
    /// derive paths price it at 0.
    #[inline]
    pub fn rate_for(&self, model: &str) -> Option<RateNanos> {
        match &self.rates {
            None => Some(RateNanos::default()),
            Some(table) => table.get(model).copied(),
        }
    }

    /// Whether a request for this model must be refused because the rate card is present but has
    /// no entry for it. Fail-closed, and consistent with the completeness rule: you either price
    /// nothing or price everything.
    #[inline]
    pub fn model_unpriced(&self, model: &str) -> bool {
        match &self.rates {
            None => false,
            Some(table) => !table.contains_key(model),
        }
    }

    /// Derive the spend, in cents, of a ledger view: a few multiply-adds over the models the
    /// bucket actually used, plus — when `include_request_fee` — the flat fee times the billable
    /// request count. Every enforcement path passes `true`; the flag exists for callers that want
    /// a tokens-only projection.
    ///
    /// The saturation matters and is not decoration. An adversarially large ledger (u64-scale token
    /// counts against a large configured rate) can push the cent total past the signed maximum, and
    /// a wrapping cast would land negative, which the floor below would then turn into zero — an
    /// over-the-top ledger deriving as FREE and bypassing every budget cap. Pinning at the maximum
    /// instead gives an astronomically over-cap spend that blocks.
    pub fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> i64 {
        let mut nanos: u128 = 0;
        for (model, units) in models {
            if let Some(rate) = self.rate_for(model) {
                nanos = nanos.saturating_add(rate.reserved_nanos(units));
            }
        }
        let mut cents = i64::try_from(nanos / NANOS_PER_CENT).unwrap_or(i64::MAX);
        if include_request_fee {
            let fee = self
                .price_per_request_cents
                .saturating_mul(i64::try_from(fee_requests).unwrap_or(i64::MAX));
            cents = cents.saturating_add(fee);
        }
        cents.max(0)
    }
}
