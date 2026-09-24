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
///
/// RE-EXPORTED, not re-declared. This crate sizes the hold that GATES ADMISSION; the ledger bills
/// against the same divisor. Two independently written copies of it is exactly the drift that lets
/// a request be judged at one rate and billed at another, so there is one declaration and everyone
/// else points at it.
pub use busbar_kernel_ledger::cost::NANOS_PER_CENT;

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
    /// Project the four raw micro-units-per-token config floats into this integer rate.
    ///
    /// ONE ARITHMETIC, AND IT IS THE COST UNIT'S. This used to be a second copy of the same three
    /// lines, written here because this crate named nothing else in the workspace, with a test
    /// asking both of them the same ten thousand questions to catch the day they drifted. They then
    /// drifted: a clamp for a finite-but-overflowing rate went onto one copy and not the other, and
    /// the two answered a config typo with too many zeros as "nothing" on one side and "the largest
    /// rate there is" on the other. A request JUDGED at one rate and BILLED at another is the exact
    /// failure that test was written to notice, and having it notice is not as good as not having
    /// the second copy.
    ///
    /// So the door consults the pricing law rather than restating it. The clamp, the rounding rule
    /// and the multiply are [`busbar_kernel_ledger::cost::nano_rate`]'s, once, and a change to any of them
    /// moves the decision and the bill together by construction. The agreement test stays: it is now
    /// a guard against the copy coming back rather than a check that two copies match.
    pub fn from_micros_per_token(
        input: f64,
        output: f64,
        cache_read: f64,
        cache_write: f64,
    ) -> Self {
        Self {
            input: busbar_kernel_ledger::cost::nano_rate(input),
            output: busbar_kernel_ledger::cost::nano_rate(output),
            cache_read: busbar_kernel_ledger::cost::nano_rate(cache_read),
            cache_write: busbar_kernel_ledger::cost::nano_rate(cache_write),
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

    /// The nano-unit cost of a unit map's reserved four at this rate.
    ///
    /// THE ARITHMETIC IS [`busbar_kernel_ledger::cost::nanos_sum`]'S, on the same terms the rate
    /// projection above already reads [`busbar_kernel_ledger::cost::nano_rate`]: what is left here
    /// is which rate each reserved key prices at, and the multiply, the sum and the saturation at
    /// both steps belong to the one fold. This function's own copy of that fold was correct, which
    /// is exactly what made it dangerous to keep — a THIRD copy in the kernel's cost projection had
    /// no overflow guard at all, and two right copies are no evidence about a third. One
    /// implementation is the only arrangement in which there is nothing left to drift.
    #[inline]
    pub fn reserved_nanos(&self, units: &BTreeMap<String, u64>) -> u128 {
        busbar_kernel_ledger::cost::nanos_sum(
            RESERVED_UNITS
                .iter()
                .map(|u| (units.get(*u).copied().unwrap_or(0), self.reserved_rate(u))),
        )
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
            price_per_request_cents: price_per_request_cents.max(0),
        }
    }

    /// A pricer with a rate card.
    pub fn with_card(price_per_request_cents: i64, rates: BTreeMap<String, RateNanos>) -> Self {
        Self {
            rates: Some(rates),
            // Clamped here, once, in both constructors — exactly where the tag's cost model clamps
            // it. A negative fee is not a discount: the derivation ADDS the fee times the billable
            // count to the token spend, so an unclamped one subtracts, and a bucket already over
            // its cap on tokens alone derives back under it and is admitted. The ledger's own
            // pricing card clamps at resolve too, so leaving it unclamped here would also mean a
            // request judged at one fee and billed at another.
            price_per_request_cents: price_per_request_cents.max(0),
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

    /// The effective rate for a model. Card absent: a zero rate, so every model prices at 0 — the
    /// ONLY circumstance in which a silent zero is a correct answer (#42,
    /// `docs/design/BUSBAR-1.6.0.md:370`: *"A silent 0 is ONLY ever returned when rate_card is
    /// absent"*). Card present and the model priced: its rate. Card present and the model UNKNOWN:
    /// `None`, which means **UNPRICED, not free**.
    ///
    /// THE SENTENCE THAT USED TO END THIS COMMENT — *"and the derive paths price it at 0"* — was a
    /// SECOND COPY of #42's ruling, and it was the wrong copy. #42 resolves a present card silent
    /// about a hit class to a REFUSAL (*"a hit class not priced ⇒ REFUSE (money-sacred, never a
    /// silent 0)"*), which is what the one function answers
    /// ([`busbar_kernel_ledger::cost::MoneyError::LaneUnpriced`], raised at
    /// `busbar-kernel-ledger/src/cost/view.rs`). The derive path below no longer restates the
    /// ruling in its own words: it asks [`Self::model_unpriced`] — the one place in this crate that
    /// states it — and fails closed. See [`Self::derive_spend_cents`].
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
    /// **AN UNPRICED MODEL BLOCKS; IT DOES NOT COST NOTHING.** This loop used to read
    /// `if let Some(rate) = self.rate_for(model)`, which reaches "price at nothing" through a
    /// control-flow arm indistinguishable from "there was nothing to price": a present card with no
    /// entry for a model dropped that model's whole consumption, and the bucket derived as free.
    /// This function GATES ADMISSION, so that arm admitted a model against a `budget:` cap it never
    /// accrued against — the exact silent 0 #42 (`docs/design/BUSBAR-1.6.0.md:370`) confines to a
    /// card that is ABSENT. The question "is this model unpriced?" is not answered again here; it
    /// is [`Self::model_unpriced`]'s, once, and the answer is resolved the way this function
    /// already resolves its other fail-closed case — pinned at the top, an astronomically over-cap
    /// spend that blocks — rather than at the bottom, where it would admit.
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
            if self.model_unpriced(model) {
                return i64::MAX;
            }
            // `rate_for` cannot be `None` past the guard above: with the card absent it answers a
            // zero rate, and with the card present `model_unpriced` already returned for every
            // model the table does not hold. The `unwrap_or_default` is the unreachable arm made
            // total, not a second resolution of the ruling.
            nanos = nanos.saturating_add(
                self.rate_for(model)
                    .unwrap_or_default()
                    .reserved_nanos(units),
            );
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
