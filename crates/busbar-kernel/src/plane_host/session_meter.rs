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
use busbar_contract::records::VirtualKey;
use busbar_kernel_ledger::cost::{plane_fee_lane, split_plane_lane, PER_SESSION};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// THE OPEN GATE: an account's dry check and its session count are one step. Held across both, so
/// two opens racing on a near-dry chain cannot both read the room one of them is about to take: each
/// open's check sees every session counted before it, and a chain passes its cap by at most the one
/// session fee the last open that found room counted (Q44(5)). An open is a session-level event, so
/// one gate per process costs a lock per session and never one per turn.
static OPEN_GATE: Mutex<()> = Mutex::new(());

/// The account's session fee, counted at the open, is still owed back if the open fails.
const OPENED: u8 = 0;
/// The session is served: its fee is final, and no refund can follow.
const SERVED: u8 = 1;
/// The open failed and its fee went back: given back once, never again.
const REFUNDED: u8 = 2;

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
    /// The clock reading the open's session count landed at: a refund of that count lands in the
    /// same budget window.
    opened_at: u64,
    /// Where the open's session fee stands: `OPENED`, `SERVED` or `REFUNDED`. Leaves
    /// `OPENED` once, so a fee is given back at most once and never after the session served.
    fee: AtomicU8,
}

impl SessionAccount {
    /// Open the account. `Ok(None)` is an ungoverned deployment or a keyless caller — nothing to
    /// ledger against and nothing to refuse, as on every other plane. `Err` is a chain already dry.
    ///
    /// THE SESSION FEE IS COUNTED HERE, AT THE OPEN, under the same dry check (TODO 17(b), ARCHITECT
    /// R4): the check and the count are one step under `OPEN_GATE`, so a chain passes its cap by at
    /// most one session fee however many opens race on it (Q44(5)). An open that then fails — its
    /// mint, SDP broker or provider dial, or its durable open — gives the fee back through
    /// [`SessionAccount::refund_open`].
    pub fn open(
        host: Arc<dyn EngineHost>,
        key: Option<&VirtualKey>,
        pool: &str,
        lane: String,
    ) -> Result<Option<Self>, BudgetRefused> {
        let (Some(pin), Some(key)) = (host.meter_pin(), key) else {
            return Ok(None);
        };
        let _gate = OPEN_GATE.lock().unwrap_or_else(PoisonError::into_inner);
        let opened_at = host.clock_now_secs();
        let account = SessionAccount {
            host,
            pin,
            key: key.clone(),
            pool: pool.to_string(),
            lane,
            opened_at,
            fee: AtomicU8::new(OPENED),
        };
        if account.dry() {
            return Err(BudgetRefused);
        }
        account.count_open();
        Ok(Some(account))
    }

    /// ONE COUNT PER OPENED SESSION (#47 `fees.per_session`, OWNER RULING Q32): a count of the
    /// reserved session class on the plane's own fee lane, through the same one metering path — the
    /// plane's `fees.per_session` prices it at read, and a plane with none reads 0. A lane no plane
    /// qualifies has no session fee to count.
    fn count_open(&self) {
        let Some(plane) = self.fee_plane() else {
            return;
        };
        let one = Usage {
            usage_units: std::collections::BTreeMap::from([(PER_SESSION.to_string(), 1)]),
        };
        let lane = plane_fee_lane(plane);
        self.host.meter_ledger(
            &self.pin,
            &self.key,
            &self.pool,
            &lane,
            &one,
            self.opened_at,
        );
    }

    /// The session is SERVED: its provider leg is up (a socket session) or its one-shot pass answered
    /// success (a mint, an SDP broker). The fee the open counted is final: no refund follows. Marking
    /// it again, from another serving site, changes nothing.
    pub fn served(&self) {
        let _ = self
            .fee
            .compare_exchange(OPENED, SERVED, Ordering::AcqRel, Ordering::Acquire);
    }

    /// GIVE BACK THE OPEN'S SESSION COUNT (TODO 17(b), ARCHITECT R4): a session whose open failed
    /// after the account counted it — its mint, SDP broker, provider dial or durable open — never
    /// opened, and a unit that never opened charges nothing. Given back EXACTLY ONCE: a second call,
    /// or a call after [`SessionAccount::served`], is a no-op. Through `GovState::refund_fee_unit`, in
    /// the window the count landed in. The budget book only: the metering row the count reached
    /// stays, as v1.5.5's fee refund left it.
    pub fn refund_open(&self) {
        if self
            .fee
            .compare_exchange(OPENED, REFUNDED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let Some(plane) = self.fee_plane() else {
            return;
        };
        self.host.meter_refund_fee(
            &self.pin,
            &self.key,
            &self.pool,
            plane,
            PER_SESSION,
            self.opened_at,
        );
    }

    /// The plane whose fee lane the session count lands on; `None` for a lane no plane qualifies,
    /// which has no session fee to count.
    fn fee_plane(&self) -> Option<&str> {
        let (plane, _) = split_plane_lane(&self.lane);
        (!plane.is_empty()).then_some(plane)
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

#[cfg(test)]
#[path = "tests/session_meter_tests.rs"]
mod tests;
