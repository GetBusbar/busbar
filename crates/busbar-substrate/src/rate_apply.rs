// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE-APPLY SEAM: the one notification that says "this deployment's configured rates are now
//! these", raised wherever the engine resolves them and answered by whoever holds a card.
//!
//! Rates are resolved from configuration in exactly one place, and that place runs at BOOT and again
//! on every live apply/reload — which is what makes a rate-card correction reprice the derived spend
//! figures on the next read. A holder that read those figures ONCE, at boot, would keep pricing on
//! rates the operator has already replaced: the projection and the holder would be two numbers for
//! one request, and only one of them would be the configuration.
//!
//! So the resolution raises this seam and the holder swaps. The seam carries the NEUTRAL raw view of
//! the figures ([`RawRates`]) and nothing else — no card, no currency, no ledger — because the shape
//! of a card is the holder's business and the shape of a config is the engine's, and this is the one
//! line between them. Nothing in a plane reaches it: a plane reports what it consumed and never what
//! it cost, and this seam carries a price.

use crate::billing::RawTierRates;

/// The configured rates, as the neutral view a holder rebuilds its card from.
///
/// One entry per configured lane in the deployment's own order, plus the flat per-request fee, plus
/// whether a rate card was configured AT ALL. The third is not the emptiness of the first: an ABSENT
/// card prices every class at nothing and still charges the fee, and a PRESENT card that happens to
/// name no lane is a different statement. Collapsing them would silently turn one deployment's
/// configuration into another's.
pub struct RawRates<'r> {
    /// `(lane, its four raw micro-per-token tier rates)`, as configured.
    pub lanes: &'r [(String, RawTierRates)],
    /// **WHAT THE DEPLOYMENT'S COUNTS ARE WORTH**: the amounts half of its tariff, in the
    /// currency's minor units, as the neutral raw view a holder rebuilds its schedule from.
    ///
    /// A whole schedule rather than one scalar, because there is more than one thing a unit is
    /// charged for and a seam that carried only the flat figure would leave every other amount to
    /// be read off a configuration somewhere else — which is the second pricing policy this seam
    /// exists to prevent.
    pub schedule: RawSchedule,
    /// Whether the deployment configured a rate card at all.
    pub present: bool,
}

/// **THE AMOUNTS, AS NEUTRAL RAW VALUES.** One record of the deployment's own figures in a
/// canonical order, and deliberately nothing more: the config GRAMMAR that produced them belongs to
/// whoever parses it, and the shape of a card belongs to whoever holds one. Only the numbers cross.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSchedule {
    /// What one admitted visit costs.
    pub entry: i64,
    /// What one completed transaction costs, flat.
    pub transaction: i64,
    /// `(dimension, per, amount)` — what one `per` units of a declared dimension costs.
    pub per_units: Vec<(String, u64, i64)>,
    /// The floor under one unit's charge.
    pub minimum: i64,
    /// The cap over it; `None` is uncapped.
    pub maximum: Option<i64>,
    /// Which way a fraction of one minor unit goes: half to even, away from zero, toward zero.
    /// Spelled as the three cases rather than as a shared enum, for the same reason the rest of
    /// this record is scalars: the seam carries figures and choices, not another crate's type.
    pub rounding: RawRounding,
}

impl RawSchedule {
    /// **WHICH WAY A FRACTION GOES, SAID AS WHAT IT DOES** rather than as which rule it is:
    /// `(away from zero, toward zero)`, and both false is half to even.
    ///
    /// The holder is the composition root, which is where a deployment's configuration becomes a
    /// running node and which must learn as few spellings as possible from the crates the
    /// retirement is emptying. A rule IS what it does to a remainder — that is the whole of its
    /// meaning at the site that applies it — so the seam carries the two answers and not the name,
    /// exactly as the dispute policy's own seam carries what a policy charges and not which policy
    /// it is. A shared enum would be a third vocabulary neither side owns.
    #[must_use]
    pub fn rounding_choice(&self) -> (bool, bool) {
        (
            matches!(self.rounding, RawRounding::Up),
            matches!(self.rounding, RawRounding::Down),
        )
    }
}

/// Which way a fraction of one minor unit goes. See [`RawSchedule::rounding`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RawRounding {
    /// Half to even — the teller's rule.
    #[default]
    Bankers,
    /// Away from zero.
    Up,
    /// Toward zero.
    Down,
}

/// A holder of rates that a live apply must reach.
///
/// Implemented by the composition root and by nothing else, because the root is the one place
/// entitled to hold a deployment's configuration.
pub trait RateApply: Send + Sync {
    /// The configured rates are now these. Called on the boot resolution and on every apply/reload,
    /// with the same figures the engine's own projection was rebuilt from.
    ///
    /// Must be atomic from a reader's point of view: a request that pinned the previous rates keeps
    /// them for its whole life, and the next request sees these.
    fn rates_applied(&self, rates: &RawRates<'_>);
}

/// THE PROCESS-WIDE rate holder, installed once by the composition root ([`install_rate_apply`]).
static APPLY: std::sync::OnceLock<&'static dyn RateApply> = std::sync::OnceLock::new();

/// Install the process rate holder — the composition root's one write, at boot, before the first
/// resolution it wants to hear about. Idempotent by `OnceLock`: a second install is a no-op.
pub fn install_rate_apply(holder: &'static dyn RateApply) {
    let _ = APPLY.set(holder);
}

/// Raise the seam: the configured rates are now `rates`.
///
/// A no-op in a build that installed no holder, which is the honest answer for a binary with no root
/// ledger in it — not a swap quietly dropped.
pub fn rates_applied(rates: &RawRates<'_>) {
    if let Some(holder) = APPLY.get() {
        holder.rates_applied(rates);
    }
}

#[cfg(test)]
#[path = "tests/rate_apply.rs"]
mod tests;
