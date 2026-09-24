// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL-OWNED SESSION METER — a live carrier metered and budget-governed by COUNTS alone
//! (BUSBAR-1.6.0 #43: a plane is pricing-blind; #71: the ledger event is raw counts per class, priced
//! at read; OWNER RULING Q21b: voice runs on the streaming plane's units and the kernel's budget gate
//! governs it).
//!
//! A plane opens a [`SessionAccount`] for the presenting key and reports each turn's raw counts per
//! class. The kernel appends them through the ONE metering path every plane ledgers through
//! ([`BudgetHost::meter_ledger`](super::BudgetHost::meter_ledger)), unconditionally, and answers
//! [`TurnVerdict::Live`] or [`TurnVerdict::MustClose`] — never a figure. No price is computed or
//! stored here: the money is the read-time view over those counts and the plane's own card.
//!
//! The verdict is the kernel's budget view of the key's chain, read after the counts landed — the
//! same derived spend (`budget_state`) and request/token headroom (`rate_headroom`) the other planes'
//! doors are judged against. So a session is refused at the open when its chain is already dry, and
//! hard-closed at the first turn that dries it.
//!
//! What the retired D2 lease did, for the record: it read the tightest remaining budget bucket ONCE at
//! the open as a nanodollar cap, priced every turn through the flat llm card into nanodollars, kept
//! the running sum as a stored figure, and hard-closed when that sum reached the cap (an unpriced
//! model closed at once). This check reads the live view instead: nothing is priced at write, nothing
//! is stored but counts, and spend the chain takes from other traffic counts too.

use super::{EngineHost, MeterPin};
use crate::billing::Usage;
use busbar_api::VirtualKey;
use std::sync::Arc;

/// What a reported turn means for the carrier. The plane never learns why a session must close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnVerdict {
    Live,
    MustClose,
}

/// The caller's budget chain is already dry: the session must not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetRefused;

/// ONE GOVERNED SESSION'S ACCOUNT: the presenting key, the pool its buckets are filtered by, and the
/// lane its counts are ledgered under (plane-qualified by the plane, so the view prices them with the
/// plane's own card). Holds no figure.
pub struct SessionAccount {
    host: Arc<dyn EngineHost>,
    pin: MeterPin,
    key: VirtualKey,
    pool: String,
    lane: String,
}

impl SessionAccount {
    /// Open the account. `Ok(None)` is an ungoverned deployment or a keyless caller — nothing to
    /// ledger against and nothing to refuse, as on every other plane. `Err` is a chain already dry.
    pub fn open(
        host: Arc<dyn EngineHost>,
        key: Option<&VirtualKey>,
        pool: &str,
        lane: String,
    ) -> Result<Option<Self>, BudgetRefused> {
        let (Some(pin), Some(key)) = (host.meter_pin(), key) else {
            return Ok(None);
        };
        let account = SessionAccount {
            host,
            pin,
            key: key.clone(),
            pool: pool.to_string(),
            lane,
        };
        if account.dry() {
            return Err(BudgetRefused);
        }
        Ok(Some(account))
    }

    /// Ledger ONE turn's raw counts per class, unconditionally, then answer whether the carrier stays
    /// open. The turn that dries the chain is delivered and ledgered; the verdict closes what follows.
    pub fn report_turn(&self, counts: &Usage) -> TurnVerdict {
        let now = self.host.clock_now_secs();
        let (pin, key) = (&self.pin, &self.key);
        self.host
            .meter_ledger(pin, key, &self.pool, &self.lane, counts, now);
        if self.dry() {
            TurnVerdict::MustClose
        } else {
            TurnVerdict::Live
        }
    }

    /// Whether any bucket of the key's chain this pool reaches has nothing left: a budget cap whose
    /// derived spend is at or past it (a spend the view refuses to price reads as none left, #42), or
    /// a request/token cap whose headroom is gone.
    fn dry(&self) -> bool {
        let now = self.host.clock_now_secs();
        let (pin, key, pool) = (&self.pin, &self.key, self.pool.as_str());
        let spent = self.host.budget_state(pin, key, now).iter().any(|b| {
            b.pool.as_deref().is_none_or(|p| p == pool)
                && b.remaining_micros.is_some_and(|r| r <= 0)
        });
        spent
            || self
                .host
                .rate_headroom(pin, key, Some(pool), now)
                .is_some_and(|h| h <= 0.0)
    }
}
