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
use crate::config::card::{CardFields, CardSet, EditRefused};

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

    /// The SEED: the card the boot's own configuration resolved (the file plus the overlay, as boot
    /// merges them). It opens an EMPTY history and is never priced after that (MONEY-DESIGN section 3a,
    /// owner ruling 2026-10-25). Raised once per build, before [`Self::rates_applied`].
    fn seed_card(&self, _card: &CardFields) {}

    /// The card IN FORCE: what every generation is built to price with once a history holds one.
    /// `None` — the default, and a holder whose history is not loaded yet — leaves the
    /// configuration's own card in place.
    fn card_in_force(&self) -> Option<CardFields> {
        None
    }

    /// The card `GET /config/settings` renders: the card in force, but only once a PUT has made it
    /// differ from the seed. `None` otherwise.
    fn rendered_card(&self) -> Option<RenderedCard> {
        None
    }

    /// JUDGE A DISK CARD (MONEY-DESIGN section 3a "Disk loads"): `file` is the configuration file's
    /// card, `merged` the file with the overlay's card fields laid over it. The file card is
    /// compared against the file-only seed and the card in force. `Ok(Some(fields))`: the file
    /// was edited BACK to the seed after a PUT changed the card (`card.file_differs`).
    ///
    /// # Errors
    ///
    /// The file card differs from both: an edit, naming the fields.
    fn judge_disk_card(
        &self,
        _file: &CardFields,
        _merged: &CardFields,
    ) -> Result<Option<String>, EditRefused> {
        Ok(None)
    }

    /// JUDGE A REQUEST BODY'S CARD (`POST /config/apply`): refused when it differs from the card
    /// in force.
    ///
    /// # Errors
    ///
    /// The edit, naming the fields.
    fn judge_body_card(&self, _path: &str, _card: &CardFields) -> Result<(), EditRefused> {
        Ok(())
    }

    /// **THE ONE CARD PATH** (`PUT /config/settings`): rescan the history's head, build the head's
    /// card with `set`'s fields replaced, hand it to `check` (the caller builds and validates the
    /// generation that prices with it), and only then write it to the history, write-before-apply.
    ///
    /// # Errors
    ///
    /// The refusal, in the operator's words: no history, a pending entry, a far-future entry, the
    /// check's own refusal, or a first-attempt REFUSED from the store.
    fn put_card(
        &self,
        _set: &CardSet,
        _actor: &str,
        _check: &mut dyn FnMut(&CardFields) -> Result<(), String>,
    ) -> Result<CardPut, String> {
        Ok(CardPut::NoHistory)
    }
}

/// The card `GET /config/settings` renders and which of its fields to show.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedCard {
    /// The card in force.
    pub card: CardFields,
    /// The fields a PUT set that differ from the merged seed.
    pub fields: Vec<String>,
}

/// What [`RateApply::put_card`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardPut {
    /// This build keeps no rate-card history (no holder, or a holder whose history is not in the
    /// store): the caller keeps the card as the configuration does.
    NoHistory,
    /// The request's fields equal the card in force: nothing was written.
    Unchanged,
    /// The new entry is READY in the store and in force fleet-wide.
    Ready {
        /// The entry's key, hex.
        key: String,
    },
    /// The store has not confirmed the new entry: it is in force on this node, which refuses
    /// admissions until the store confirms it.
    Pending {
        /// The entry's key, hex.
        key: String,
    },
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

/// THE RATE HOLDER this process answers to: the one the composition root hands in on its install
/// record ([`crate::preflight::RootInstall::rate_apply`]), never a static of this module. A test
/// binary's own holder (`test_support::rate_holders::install_rate_apply`) stands in front
/// of the record's. `None`: the build installed no holder.
fn holder() -> Option<&'static dyn RateApply> {
    #[cfg(any(test, feature = "test-support"))]
    {
        if let Some(holder) = crate::test_support::rate_holders::apply() {
            return Some(holder);
        }
    }
    crate::preflight::root_rows().rate_apply
}

/// THE RATE DATER this process answers to: the one on the composition root's install record
/// ([`crate::preflight::RootInstall::rate_epoch`]), beside [`holder`]. A test binary's own dater
/// (`test_support::rate_holders::install_rate_epoch`) stands in front of the record's.
/// `None`: the build installed no dater.
fn dater() -> Option<&'static dyn RateEpoch> {
    #[cfg(any(test, feature = "test-support"))]
    {
        if let Some(dater) = crate::test_support::rate_holders::epoch() {
            return Some(dater);
        }
    }
    crate::preflight::root_rows().rate_epoch
}

/// The `effective_from` of the entry in force at `at_ms`.
///
/// `0` in a build that installed no holder — the honest answer for a binary with no root ledger in
/// it, and the same value the opening entry carries, so a cell dated by it resolves to the card the
/// deployment opened with rather than to whatever is newest.
#[must_use]
pub fn effective_from_at(at_ms: u64) -> u64 {
    dater().map_or(0, |h| h.effective_from_at(at_ms))
}

/// The installed holder's dated history, if it holds one — see [`RateEpoch::history`].
#[must_use]
pub fn dated_history() -> Option<std::sync::Arc<busbar_kernel_ledger::cost::History>> {
    dater().and_then(|holder| holder.history())
}

/// Run `f` with every generation built on this thread pricing with `card` (see [`build_card`]).
pub fn with_card<T>(card: &CardFields, f: impl FnOnce() -> T) -> T {
    crate::config::card::scope::with_override(card, f)
}

/// THE CARD A BUILD PRICES WITH: the candidate [`with_card`] names on this thread, else the card in
/// force, else `None` (the configuration's own card stands: no history yet).
#[must_use]
pub fn build_card() -> Option<CardFields> {
    crate::config::card::scope::override_card()
        .or_else(|| holder().and_then(RateApply::card_in_force))
}

/// The card in force, if the holder's history holds one.
#[must_use]
pub fn card_in_force() -> Option<CardFields> {
    holder().and_then(RateApply::card_in_force)
}

/// The card `GET /config/settings` renders ([`RateApply::rendered_card`]).
#[must_use]
pub fn rendered_card() -> Option<RenderedCard> {
    holder().and_then(RateApply::rendered_card)
}

/// Raise the seed ([`RateApply::seed_card`]).
pub fn seed_card(card: &CardFields) {
    holder().into_iter().for_each(|h| h.seed_card(card));
}

/// Judge a disk card ([`RateApply::judge_disk_card`]); a refusal is audited
/// (`card.edit_refused`) before it is answered.
///
/// # Errors
///
/// The refusal's sentence, opening with [`crate::config::card::EDIT_REFUSED_PREFIX`].
pub fn judge_disk_card(file: &CardFields, merged: &CardFields) -> Result<(), String> {
    match holder().map(|h| h.judge_disk_card(file, merged)) {
        Some(Err(refused)) => {
            refused.audit();
            if crate::config::card::scope::is_lenient() {
                // PUT's own re-read never refuses on the file card: its 200 says so.
                crate::config::card::scope::note(refused.to_string());
                return Ok(());
            }
            Err(refused.to_string())
        }
        Some(Ok(Some(fields))) => {
            crate::audit_ring::AUDIT.record_by(
                crate::config::card::FILE_DIFFERS_ACTION,
                &format!("rate_card fields={fields}"),
                crate::audit_ring::OUTCOME_APPLIED,
                "busbar",
            );
            crate::config::card::scope::note(format!(
                "the configuration file's rate card was edited back to its first-boot seed and \
                 differs from the card in force in {fields}; the card in force stands \
                 ({})",
                crate::config::card::ONLY_PUT
            ));
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Run `f` as `PUT /config/settings`'s disk re-read: a file-card edit is audited and NOTED rather
/// than refused.
pub fn lenient<T>(f: impl FnOnce() -> T) -> T {
    crate::config::card::scope::lenient(f)
}

/// Take the notes the card checks left on this thread.
#[must_use]
pub fn take_notes() -> Vec<String> {
    crate::config::card::scope::take_notes()
}

/// Judge a request body's card ([`RateApply::judge_body_card`]); a refusal is audited.
///
/// # Errors
///
/// The refusal's sentence, opening with [`crate::config::card::EDIT_REFUSED_PREFIX`].
pub fn judge_body_card(path: &str, card: &CardFields) -> Result<(), String> {
    match holder().map(|h| h.judge_body_card(path, card)) {
        Some(Err(refused)) => {
            refused.audit();
            Err(refused.to_string())
        }
        _ => Ok(()),
    }
}

/// The one card path ([`RateApply::put_card`]).
///
/// # Errors
///
/// As [`RateApply::put_card`]; a build with no holder keeps no history and refuses.
pub fn put_card(
    set: &CardSet,
    actor: &str,
    check: &mut dyn FnMut(&CardFields) -> Result<(), String>,
) -> Result<CardPut, String> {
    match holder() {
        Some(h) => h.put_card(set, actor, check),
        None => Ok(CardPut::NoHistory),
    }
}

/// Raise the seam: the configured rates are now `rates`.
///
/// A no-op in a build that installed no holder, which is the honest answer for a binary with no root
/// ledger in it — not a swap quietly dropped.
pub fn rates_applied(rates: &RawRates<'_>) {
    holder().into_iter().for_each(|h| h.rates_applied(rates));
}

#[cfg(test)]
#[path = "tests/rate_apply.rs"]
mod tests;
