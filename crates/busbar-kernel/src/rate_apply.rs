// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::card::CardFields;
use busbar_contract::billing::RawTierRates;

pub struct RawRates<'r> {
    pub lanes: &'r [(String, RawTierRates)],

    pub units: &'r [(String, String, u64)],

    pub flat_minor: i64,

    pub present: bool,

    pub plane_fees: &'r crate::config::PlaneFeesMap,
}

pub trait RateApply: Send + Sync {
    fn prepare(
        &self,
        _card: &CardFields,
        _rates: &RawRates<'_>,
        _origin: &str,
    ) -> Result<Box<dyn PreparedRates>, String> {
        Err("the installed rate holder does not support confirmed preparation".into())
    }

    fn prepare_recovery(
        &self,
        card: &CardFields,
        rates: &RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn PreparedRates>, String> {
        self.prepare(card, rates, origin)
    }

    fn rates_applied(&self, rates: &RawRates<'_>);

    fn card_applied(&self, _card: &CardFields, _origin: &str) {}
}

pub trait RateCommit: Send {
    fn commit(self: Box<Self>);
}

pub trait PreparedRates: Send {
    fn confirm_activation(self: Box<Self>) -> Result<Box<dyn RateCommit>, String>;
}

struct NoRates;

impl RateCommit for NoRates {
    fn commit(self: Box<Self>) {}
}

impl PreparedRates for NoRates {
    fn confirm_activation(self: Box<Self>) -> Result<Box<dyn RateCommit>, String> {
        Ok(self)
    }
}

pub fn prepare(card: &CardFields, rates: &RawRates<'_>) -> Result<Box<dyn PreparedRates>, String> {
    let origin = crate::config::card::origin::current();
    match holder() {
        Some(holder) => holder.prepare(card, rates, &origin),
        None => Ok(Box::new(NoRates)),
    }
}

pub fn prepare_recovery(
    card: &CardFields,
    rates: &RawRates<'_>,
) -> Result<Box<dyn PreparedRates>, String> {
    let origin = crate::config::card::origin::current();
    match holder() {
        Some(holder) => holder.prepare_recovery(card, rates, &origin),
        None => Ok(Box::new(NoRates)),
    }
}

pub trait RateEpoch: Send + Sync {
    fn era_at(&self, at_ms: u64) -> busbar_kernel_ledger::cost::RawRateEra {
        busbar_kernel_ledger::cost::RawRateEra::legacy(self.effective_from_at(at_ms))
    }

    fn effective_from_at(&self, at_ms: u64) -> u64;

    fn history(&self) -> Option<std::sync::Arc<busbar_kernel_ledger::cost::History>> {
        None
    }
}

fn holder() -> Option<&'static dyn RateApply> {
    crate::preflight::root_rows().rate_apply
}

fn dater() -> Option<&'static dyn RateEpoch> {
    crate::preflight::root_rows().rate_epoch
}

#[must_use]
pub fn effective_from_at(at_ms: u64) -> u64 {
    dater().map_or(0, |h| h.effective_from_at(at_ms))
}

#[must_use]
pub fn era_at(at_ms: u64) -> busbar_kernel_ledger::cost::RawRateEra {
    dater().map_or_else(
        || busbar_kernel_ledger::cost::RawRateEra::legacy(0),
        |holder| holder.era_at(at_ms),
    )
}

#[must_use]
pub fn dated_history() -> Option<std::sync::Arc<busbar_kernel_ledger::cost::History>> {
    dater().and_then(|holder| holder.history())
}

pub fn card_applied(card: &CardFields) {
    let origin = crate::config::card::origin::current();
    holder()
        .into_iter()
        .for_each(|h| h.card_applied(card, &origin));
}

pub fn with_origin<T>(origin: &str, f: impl FnOnce() -> T) -> T {
    crate::config::card::origin::with(origin, f)
}

pub fn rates_applied(rates: &RawRates<'_>) {
    holder().into_iter().for_each(|h| h.rates_applied(rates));
}

#[cfg(test)]
#[path = "tests/rate_apply.rs"]
mod tests;
