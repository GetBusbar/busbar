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

/// The four reserved token keys, in canonical order. A ledger map may carry other (open) keys too;
/// each prices through the card by its own class name (item 123), and an unpriced one refuses.
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
}

/// The rate table plus the flat per-request fee: everything the budget comparison needs to turn a
/// bucket's counters into cents.
///
/// `rates` absent means no rate card is configured, and then every model prices at zero — token
/// caps still work (they count tokens, not money) and the flat fee still bills. `rates` present
/// means the table is authoritative: a model with no entry derives at zero, which is the operator's
/// rate-card edit taking effect retroactively, by design.
#[derive(Debug, Clone)]
pub struct Pricer {
    /// THE CARD, in the one function's own type. Every figure this pricer answers is
    /// [`busbar_kernel_ledger::cost::Tally`] over it (items 104, 25, 124); the per-model
    /// [`RateNanos`] view is read off it, never the other way round.
    card: busbar_kernel_ledger::cost::RateCard,
}

impl Default for Pricer {
    fn default() -> Self {
        Pricer::flat(0)
    }
}

impl Pricer {
    /// A pricer with no rate card: token pricing is zero everywhere, the flat fee still applies.
    pub fn flat(price_per_request_cents: i64) -> Self {
        Self {
            card: busbar_kernel_ledger::cost::RateCard::absent(price_per_request_cents),
        }
    }

    /// A pricer with a rate card.
    ///
    /// The rates are ALREADY quantised nano-units ([`RateNanos::from_micros_per_token`] ran
    /// [`busbar_kernel_ledger::cost::nano_rate`] once), so the card is built from them without a
    /// second rounding. A negative fee is clamped by the card's constructor, exactly where the
    /// ledger's card clamps it — a request judged at one fee and billed at another is the drift
    /// one card rules out.
    pub fn with_card(price_per_request_cents: i64, rates: BTreeMap<String, RateNanos>) -> Self {
        use busbar_kernel_ledger::cost::LaneClass;
        let card = busbar_kernel_ledger::cost::RateCard::from_nano_rates(
            rates.iter().flat_map(|(model, r)| {
                [
                    (UNIT_INPUT, r.input),
                    (UNIT_OUTPUT, r.output),
                    (UNIT_CACHE_READ, r.cache_read),
                    (UNIT_CACHE_WRITE, r.cache_write),
                ]
                .map(|(u, nanos)| (LaneClass::new(model.as_str(), u), nanos))
            }),
            price_per_request_cents,
        );
        Self { card }
    }

    /// A pricer holding THE card the ledger built — `RateCard::from_config`, the one card
    /// constructor, with its quantisation, its representability refusal (item 22) and its fee
    /// clamp. The door and the bill then hold one card rather than two copies of one.
    pub fn from_card(card: busbar_kernel_ledger::cost::RateCard) -> Self {
        Self { card }
    }

    /// Whether a rate card is configured.
    pub fn pricing_enabled(&self) -> bool {
        self.card.pricing_enabled()
    }

    /// The flat per-request fee, in cents. This is the fee lookahead the budget check adds to a
    /// bucket's derived spend before comparing against the cap.
    pub fn price_per_request_cents(&self) -> i64 {
        self.card.fee()
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
        if !self.card.pricing_enabled() {
            return Some(RateNanos::default());
        }
        self.card.lane_rates(model).map(|r| RateNanos {
            input: r.nanos_per_unit(UNIT_INPUT),
            output: r.nanos_per_unit(UNIT_OUTPUT),
            cache_read: r.nanos_per_unit(UNIT_CACHE_READ),
            cache_write: r.nanos_per_unit(UNIT_CACHE_WRITE),
        })
    }

    /// Whether a request for this model must be refused because the rate card is present but has
    /// no entry for it. Fail-closed, and consistent with the completeness rule: you either price
    /// nothing or price everything.
    #[inline]
    pub fn model_unpriced(&self, model: &str) -> bool {
        self.card.lane_unpriced(model)
    }

    /// Derive the spend, in cents, of a ledger view: every model the bucket used, plus — when
    /// `include_request_fee` — the flat fee times the billable request count. Every enforcement
    /// path passes `true`; the flag exists for callers that want a tokens-only projection.
    ///
    /// **THE ONE FUNCTION** (items 104, 25, 124): [`busbar_kernel_ledger::cost::Tally`] over
    /// this pricer's card, one row per model (every class it counted, item 123), then the fee row.
    ///
    /// **AN UNPRICED MODEL REFUSES; IT DOES NOT COST NOTHING — AND IT DOES NOT COST `i64::MAX`
    /// EITHER.** The first answer was #42's silent zero on the admission path. The second, which
    /// replaced it, blocked correctly but said so by pinning the figure at the top of the range —
    /// a spend nobody consumed, indistinguishable from a real one to any reader of the number. The
    /// door now receives the refusal itself (`Err`) and blocks on it; an overflow is the same
    /// refusal (item 28), never a pinned bill.
    pub fn derive_spend_cents<'m>(
        &self,
        models: impl Iterator<Item = (&'m str, &'m BTreeMap<String, u64>)>,
        fee_requests: u64,
        include_request_fee: bool,
    ) -> Result<i64, busbar_kernel_ledger::cost::MoneyError> {
        use busbar_kernel_ledger::cost::{whole, Tally, STANDARD_TIER_BP};
        let mut tally = Tally::at_card(&self.card);
        for (model, units) in models {
            // EVERY class the bucket counted (item 123) — an open class the card prices is charged
            // and one it does not REFUSES (#42); nothing is filtered out to price as nothing.
            tally.row(
                model,
                0,
                STANDARD_TIER_BP,
                units.iter().map(|(u, n)| (u.as_str(), whole(*n))),
                whole(0),
            )?;
        }
        if include_request_fee {
            tally.fee(0, STANDARD_TIER_BP, whole(fee_requests))?;
        }
        tally.money()?.minor_i64()
    }
}
