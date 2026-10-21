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
use crate::governance::GovState;

/// The configured rates, as the neutral view a holder rebuilds its card from.
///
/// One entry per configured lane in the deployment's own order, plus the flat per-request figure,
/// plus whether a rate card was configured AT ALL. The third is not the emptiness of the first: an
/// ABSENT card prices every class at nothing and still carries the flat figure, and a PRESENT card
/// that happens to name no lane is a different statement. Collapsing them would silently turn one
/// deployment's configuration into another's.
///
/// The flat figure is carried NEUTRALLY. This seam is a rate-carrier and nothing more: it names the
/// number, not what it means. Reading that number AS a per-request fee — the clamp, the billing
/// semantics — is the holder's, on the card it builds, because a fee read outside the crate that owns
/// the card is a price derived where nobody can see it. So the seam spells a flat minor-unit figure
/// and leaves the word "fee" to the crate entitled to say it.
pub struct RawRates<'r> {
    /// `(lane, its four tier rates)` in exact nano-units per token, as the config intake converted
    /// them once (#81: no float crosses this seam).
    pub lanes: &'r [(String, RawTierRates)],
    /// `(lane, open class, nano-units per unit)` for every open-class rate a lane's `units:` names
    /// (item 123) — so a card rebuilt from this view prices the open classes the live one does.
    pub units: &'r [(String, String, u64)],
    /// The flat per-request figure, in abstract minor units — a neutral rate-carrier value the
    /// holder reads as the per-request fee. Never interpreted here.
    pub flat_minor: i64,
    /// Whether the deployment configured a rate card at all.
    pub present: bool,
    /// Each other plane's own fees (#47), by plane registry key — dated with the card, like the flat
    /// figure, so an era before a fee edit prices at the fees in force then.
    pub plane_fees: &'r crate::config::PlaneFeesMap,
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

    /// STAGE the rates a config change is about to commit: make them durable BEFORE the change is
    /// saved (MONEY-AUDIT D-6, ARCHITECT ruling 2026-10-02). `Err` refuses the WHOLE config change,
    /// so the old configuration and the old card both stay; the message is the operator's. A
    /// holder with no journal has nothing to make durable: the default stages nothing.
    ///
    /// # Errors
    ///
    /// The holder could not make the rates durable.
    fn rates_staged(&self, _rates: &RawRates<'_>) -> Result<(), String> {
        Ok(())
    }

    /// The config change the staged rates were made durable for did NOT commit (its persist or its
    /// swap never landed): the holder puts the card that stays in force back on its record.
    fn rates_withdrawn(&self) {}
}

/// **THE READ-SIDE TWIN**: a holder that can DATE a price — for an instant, the `effective_from`
/// of the dated rate-card entry in force at it.
///
/// [`RateApply`] carries figures TO the holder; this asks the holder WHEN the figures it is
/// currently serving started. It is the same holder, the same composition root and the same one
/// line between the engine and the card, read in the other direction.
///
/// It carries a DATE and never a price, which is why it may be called from the metering accrual at
/// all. A metering cell is an aggregate over a UTC DAY, so without an instant of its own the read
/// had nothing between midnight and midnight to resolve at and a card published at noon repriced
/// the whole day (DECISION #79). Stamping the entry's `effective_from` onto the cell — a timestamp,
/// never a version, so a back-dated correction can still reach it — is what splits the day at the
/// edit. The accrual learns no rate and no fee: it learns when the current one began.
pub trait RateEpoch: Send + Sync {
    /// The `effective_from` of the entry in force at `at_ms`, in wall-clock milliseconds.
    ///
    /// `0` when no entry covers the instant, which is the OPENING entry's own `effective_from` and
    /// therefore the reading that covers everything — never a refusal, because an accrual that
    /// could not be dated must still be recorded.
    fn effective_from_at(&self, at_ms: u64) -> u64;

    /// THE HISTORY ITSELF, for the budget ledger's reads and its gate (OWNER RULING Q14): a budget
    /// cell's counts are dated by [`Self::effective_from_at`] and priced at the card each era
    /// resolves to. `None` — the default, and a build with no root ledger — prices every era at
    /// the live card, the undated derivation.
    fn history(&self) -> Option<std::sync::Arc<busbar_kernel_ledger::cost::History>> {
        None
    }
}

/// THE RATE HOLDER `gov` answers to: the one the composition root lent on its install record
/// ([`crate::preflight::RootInstall::rate_apply`]), carried by the governance book the build made
/// from that record ([`GovState::rate_apply`]) — never a static of this module. `None`: the record
/// lent no holder.
#[must_use]
pub fn holder(gov: &GovState) -> Option<&'static dyn RateApply> {
    gov.rate_apply()
}

/// THE RATE DATER `gov` answers to, beside [`holder`]: the one on the install record
/// ([`crate::preflight::RootInstall::rate_epoch`]) the governance book carries
/// ([`GovState::rate_epoch`]). `None`: the record lent no dater.
#[must_use]
pub fn dater(gov: &GovState) -> Option<&'static dyn RateEpoch> {
    gov.rate_epoch()
}

/// The `effective_from` of the entry in force at `at_ms`, by `gov`'s dater.
///
/// `0` when the book carries no dater — the honest answer for a binary with no root ledger in it,
/// and the same value the opening entry carries, so a cell dated by it resolves to the card the
/// deployment opened with rather than to whatever is newest.
#[must_use]
pub fn effective_from_at(gov: &GovState, at_ms: u64) -> u64 {
    dater(gov).map_or(0, |h| h.effective_from_at(at_ms))
}

/// `gov`'s dater's dated history, if it holds one — see [`RateEpoch::history`].
#[must_use]
pub fn dated_history(
    gov: &GovState,
) -> Option<std::sync::Arc<busbar_kernel_ledger::cost::History>> {
    dater(gov).and_then(|holder| holder.history())
}

/// Stage the rates a config change is about to commit with the holder of the governance book the
/// change was built with — see [`RateApply::rates_staged`]. `Ok` when there is no book or it
/// carries no holder: there is no journal to refuse.
///
/// # Errors
///
/// The holder could not make the rates durable; the config change must be refused.
pub fn rates_staged(gov: Option<&GovState>, rates: &RawRates<'_>) -> Result<(), String> {
    gov.and_then(holder)
        .map_or(Ok(()), |h| h.rates_staged(rates))
}

/// The staged rates' config change did not commit — see [`RateApply::rates_withdrawn`].
pub fn rates_withdrawn(gov: Option<&GovState>) {
    gov.and_then(holder)
        .into_iter()
        .for_each(|h| h.rates_withdrawn());
}

/// Raise the seam: the configured rates are now `rates`, to the holder of the governance book the
/// change was built with.
///
/// A no-op when there is no book or it carries no holder, which is the honest answer for a binary
/// with no root ledger in it — not a swap quietly dropped.
pub fn rates_applied(gov: Option<&GovState>, rates: &RawRates<'_>) {
    gov.and_then(holder)
        .into_iter()
        .for_each(|h| h.rates_applied(rates));
}

#[cfg(test)]
#[path = "tests/rate_apply.rs"]
mod tests;
