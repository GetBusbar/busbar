// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTINUOUS-METERING LEASE — the marquee guarantee (design §2.5, §4 "the D2 lease").
//!
//! A live voice carrier cannot be priced after the fact the way a one-shot request is: the session is
//! open-ended and the plane must be able to HARD-CLOSE it mid-stream the instant the budget is dry.
//! That is what the frozen D2 `cost_reserve`/`cost_settle` ABI exists for — open a reserve-then-settle
//! lease over ALREADY-PRICED nanodollars at session start, settle EXACT increments per turn, and read
//! back exhaustion so the carrier is closed the moment `settled ≥ cap`.
//!
//! THE NEUTRAL-SEAM GAP (reported, not worked around — HARD RULE 2). The host wires that ABI
//! (`busbar_core::plane_host::cost_host::{cost_reserve, cost_settle}`), but the NEUTRAL seam a
//! statically-linked plane is handed at request time — `busbar_substrate::plane_host::EngineHost` —
//! exposes `meter_charge` (one-shot) and NOT the two lease methods. So a static voice plane cannot
//! reach the host-owned budget cell today without two methods added to that neutral trait. Rather than
//! leak plane shape into neutral code, the runtime depends on a plane-local PORT ([`MeteringLease`] /
//! [`MeteringPort`]) whose contract is byte-for-byte the D2 lease's (reserve = estimate+fee, settle
//! accrues exact increments, exhausted = `settled ≥ cap`, refuse-all cap denies at the door). The
//! composition root binds the real host lease behind this port the instant `EngineHost` exposes it;
//! [`LocalLease`] is the faithful, fully-wired implementation the runtime and its tests drive today.

use crate::ir::usage::IrDuplexUsage;
use std::sync::atomic::{AtomicU64, Ordering};

/// THE POST-SETTLE STATE the plane reads back to decide whether to hard-close — the mirror of the D2
/// `CostSettleOut.exhausted` flag plus the `StatusClass::Refused`/`Fault` fail-closed cases folded in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Budget remains — keep the carrier open.
    Live,
    /// The lease's budget is now DRY (`settled ≥ cap`) — the plane MUST hard-close the carrier. The one
    /// thing post-hoc metering structurally cannot do.
    Exhausted,
    /// The settle was REFUSED (unknown / already-closed lease) or FAULTED — the plane fails CLOSED and
    /// hard-closes the carrier just as an exhaustion would.
    Refused,
}

impl LeaseState {
    /// Whether this state demands a carrier hard-close (everything but [`LeaseState::Live`]).
    #[must_use]
    pub fn must_close(self) -> bool {
        !matches!(self, LeaseState::Live)
    }
}

/// ONE OPEN METERING LEASE — the plane-side port over the D2 `cost_settle` leg. `Send + Sync` so the
/// per-frame session handlers (which run concurrently under `Arc<Self>`) can settle against it.
pub trait MeteringLease: Send + Sync {
    /// Settle ONE exact already-priced increment (nanodollars) against this lease and read back the
    /// post-settle state — the `cost_settle` leg. Idempotent after exhaustion: once dry it stays dry.
    fn settle(&self, nanos: u64) -> LeaseState;

    /// The total nanodollars settled so far — the audit tap the caller journals (and the tests assert).
    fn settled_nanos(&self) -> u64;
}

/// OPENS a metering lease at session start — the plane-side port over the D2 `cost_reserve` leg. The
/// plane hands ALREADY-PRICED nanodollars: `estimate` (the coarse over-estimate debited up front),
/// `fee` (the once-per-session flat fee, `0` = none), and `cap` (the TRUE budget ceiling exhaustion is
/// judged against — `None` = uncapped, `Some(0)` = refuse-all).
pub trait MeteringPort: Send + Sync {
    /// Open a reserve-then-settle lease. `None` mirrors a `cost_reserve` `StatusClass::Refused` (a
    /// refuse-all cap): the plane reads it as "no lease" and fails closed — the session never opens.
    fn reserve(
        &self,
        estimate_nanos: u64,
        fee_nanos: u64,
        cap_nanos: Option<u64>,
    ) -> Option<Box<dyn MeteringLease>>;
}

/// THE PER-TOKEN PRICE BOOK the plane prices a turn's [`IrDuplexUsage`] with BEFORE handing the money
/// across the D2 lease (core prices nothing — the plane hands already-priced nanodollars, §2.5). Audio
/// and text are separate classes (audio dominates); cached input bills at the cache rate.
#[derive(Debug, Clone, Copy)]
pub struct Pricing {
    /// Nanodollars per audio input token.
    pub audio_in_nanos: u64,
    /// Nanodollars per audio output token.
    pub audio_out_nanos: u64,
    /// Nanodollars per text input token.
    pub text_in_nanos: u64,
    /// Nanodollars per text output token.
    pub text_out_nanos: u64,
    /// Nanodollars per cached input token (billed at the cache rate, distinct from a fresh input).
    pub cached_nanos: u64,
}

impl Pricing {
    /// Price ONE turn's extracted usage into a single already-priced nanodollar increment — the value
    /// the plane settles against the lease. Saturating throughout: a runaway turn can never wrap the
    /// budget arithmetic into a small number and dodge the cap.
    #[must_use]
    pub fn price(&self, u: &IrDuplexUsage) -> u64 {
        [
            (u.audio_in, self.audio_in_nanos),
            (u.audio_out, self.audio_out_nanos),
            (u.text_in, self.text_in_nanos),
            (u.text_out, self.text_out_nanos),
            (u.cached, self.cached_nanos),
        ]
        .into_iter()
        .fold(0u64, |acc, (tokens, rate)| {
            acc.saturating_add(tokens.saturating_mul(rate))
        })
    }
}

/// THE FAITHFUL, FULLY-WIRED LEASE the runtime drives today — the plane-side twin of the host's
/// `CostHold` (busbar-core `plane/cost.rs`): `reserved = estimate + fee` debited up front, `settled`
/// accrues exact increments, and exhaustion is `matches!(cap, Some(c) if settled ≥ c)`. It holds the
/// budget cell in-process rather than in the host's global registry (the reported neutral-seam gap),
/// but the reserve/settle/exhaustion CONTRACT — and therefore the hard-close behaviour the marquee
/// guarantee rests on — is byte-for-byte the D2 lease's.
#[derive(Debug)]
pub struct LocalLease {
    /// The coarse over-estimate + flat fee debited at reserve (audit tap; not itself a ceiling).
    reserved_nanos: u64,
    /// Exact nanodollars settled so far — the value compared to the cap.
    settled_nanos: AtomicU64,
    /// The TRUE budget ceiling; `None` = uncapped (never exhausts).
    cap_nanos: Option<u64>,
}

impl LocalLease {
    /// The reserved (estimate + fee) nanodollars this lease debited up front.
    #[must_use]
    pub fn reserved_nanos(&self) -> u64 {
        self.reserved_nanos
    }
}

impl MeteringLease for LocalLease {
    fn settle(&self, nanos: u64) -> LeaseState {
        // Saturating accrual: the budget arithmetic can never wrap below the cap.
        let prior = self.settled_nanos.fetch_add(nanos, Ordering::SeqCst);
        let total = prior.saturating_add(nanos);
        // Re-store the saturated total so a near-u64::MAX run cannot silently roll the counter.
        self.settled_nanos.store(total, Ordering::SeqCst);
        match self.cap_nanos {
            Some(cap) if total >= cap => LeaseState::Exhausted,
            _ => LeaseState::Live,
        }
    }

    fn settled_nanos(&self) -> u64 {
        self.settled_nanos.load(Ordering::SeqCst)
    }
}

/// THE DEFAULT [`MeteringPort`] — mints [`LocalLease`]s. Binds the real host lease's REFUSE-ALL rule at
/// the door: a `Some(0)` cap denies the reserve (`None`), so the session never opens on a zero budget.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalMeteringPort;

impl MeteringPort for LocalMeteringPort {
    fn reserve(
        &self,
        estimate_nanos: u64,
        fee_nanos: u64,
        cap_nanos: Option<u64>,
    ) -> Option<Box<dyn MeteringLease>> {
        // A refuse-all cap (`Some(0)`) denies at the door, exactly like the host `cost_reserve`.
        if matches!(cap_nanos, Some(0)) {
            return None;
        }
        Some(Box::new(LocalLease {
            reserved_nanos: estimate_nanos.saturating_add(fee_nanos),
            settled_nanos: AtomicU64::new(0),
            cap_nanos,
        }))
    }
}
