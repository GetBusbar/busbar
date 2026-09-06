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
    /// The flat per-request fee, in abstract minor units.
    pub fee_cents: i64,
    /// Whether the deployment configured a rate card at all.
    pub present: bool,
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
mod tests {
    use super::*;

    /// With nothing installed the seam is silent, and that is the whole of what a build without a
    /// root ledger should do with a rate change.
    #[test]
    fn an_uninstalled_seam_swallows_the_apply() {
        rates_applied(&RawRates {
            lanes: &[],
            fee_cents: 7,
            present: false,
        });
    }
}
