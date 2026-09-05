// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's own capability types: where a unit came from, how it is keyed, which session it
//! belongs to, and — the one that closes every unit — how it ended.
//!
//! These four are not built by any unit. The kernel builds the first three and the exit path builds
//! the last, which is why they are sealed on the kernel seal and the exit token rather than on a
//! unit's token.
//!
//! # What a unit cannot do
//!
//! It cannot declare that a unit ended. Only the exit path can, and it needs its token:
//!
//! ```compile_fail,E0061
//! use busbar_caps::{Outcome, UnitEnd};
//! fn fake_end() -> UnitEnd {
//!     UnitEnd::seal(Outcome::Completed, Ok(unimplemented!()))
//! }
//! ```
//!
//! The exit path, holding its token, seals the same end without ceremony:
//!
//! ```
//! use busbar_caps::{Admit, AdmitToken, ExitToken, Hold, KernelSeal, LedgerToken, Outcome,
//!                   Posted, Principal, UnitEnd, Usage, UsageToken};
//! let seal = KernelSeal::acquire_for_kernel();
//! let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
//! let hold = Hold::open(&admit, Principal::new("acct-1"), 10);
//! let usage = Usage::report(&UsageToken::mint(&seal), Vec::new()).unwrap();
//! let posted = Posted::settle(hold, &usage, &LedgerToken::mint(&seal));
//! let end = UnitEnd::seal(&ExitToken::mint(&seal), Outcome::Completed, Ok(posted));
//! assert!(end.outcome().is_completed());
//! ```

use crate::hold::{DurabilityLost, Posted};
use crate::step::{StepName, UnitKey};
use crate::token::{ExitToken, KernelSeal};
use crate::ReasonCode;

/// Where a unit came from, sealed.
///
/// The kernel is the sole writer of a unit's origin — a plane that could claim to be a tick could
/// skip the door — so the value itself is opaque: [`OriginKind`] says what the eight possibilities
/// are and can be matched on freely, but turning one into an `Origin` needs the kernel's seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Origin(OriginKind);

impl Origin {
    /// Seal an origin. Kernel only.
    pub fn seal(_seal: &KernelSeal, kind: OriginKind) -> Self {
        Origin(kind)
    }

    /// Which of the eight this is.
    pub fn kind(self) -> OriginKind {
        self.0
    }

    /// The origin as the journal spells it.
    pub fn as_str(self) -> &'static str {
        self.0.as_str()
    }
}

/// The eight places a unit can come from. A closed list: what a unit is allowed to reach is decided
/// from this and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginKind {
    /// A caller's request.
    Client,
    /// Something an upstream sent us, solicited or not.
    Provider,
    /// The node's own clock: heartbeats, sweeps, session accruals.
    Tick,
    /// A connection that never got as far as a plane.
    Arrival,
    /// A protocol's own authentication exchange.
    Handshake,
    /// The node bringing itself up.
    Bootstrap,
    /// A unit a plane opened inside another unit.
    Nested {
        /// The unit that opened it.
        parent: UnitKey,
    },
    /// One recipient's share of a fan-out.
    Delivery {
        /// The unit that scattered.
        parent: UnitKey,
    },
}

impl OriginKind {
    /// The origin as the journal spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            OriginKind::Client => "client",
            OriginKind::Provider => "provider",
            OriginKind::Tick => "tick",
            OriginKind::Arrival => "arrival",
            OriginKind::Handshake => "handshake",
            OriginKind::Bootstrap => "bootstrap",
            OriginKind::Nested { .. } => "nested",
            OriginKind::Delivery { .. } => "delivery",
        }
    }
}

/// The session a unit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u64);

impl SessionId {
    /// Mint a session id. Kernel only.
    pub fn mint(_seal: &KernelSeal, id: u64) -> Self {
        SessionId(id)
    }

    /// The id as the session table keys it.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The key a repeated request is recognised by.
///
/// Kernel-built from the principal, the operation class, the target resource and a hash of the
/// client's own key. A hash, never the client's key itself, so a key that arrives in a header does
/// not end up in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyKey([u8; 32]);

impl IdempotencyKey {
    /// Mint the key. Kernel only.
    pub fn mint(_seal: &KernelSeal, digest: [u8; 32]) -> Self {
        IdempotencyKey(digest)
    }

    /// The digest, as the claim table stores it.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Why a unit was cut short rather than refused or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    /// The client went away.
    Client,
    /// The node cut it, for a named reason.
    Kernel {
        /// The reason.
        reason: ReasonCode,
    },
    /// The node is draining.
    Drain,
    /// A later unit took its place.
    Superseded {
        /// The unit that took over.
        by: UnitKey,
    },
}

/// How a unit ended, before the posting is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every step proceeded.
    Completed,
    /// A step said no.
    Refused(StepName, ReasonCode),
    /// A step broke.
    Failed(StepName, ReasonCode),
    /// The unit was cut short.
    Aborted(Abort),
    /// A step ran past its deadline.
    TimedOut(StepName),
}

impl Outcome {
    /// The step the unit stopped at, where the outcome names one.
    pub fn step(self) -> Option<StepName> {
        match self {
            Outcome::Refused(s, _) | Outcome::Failed(s, _) | Outcome::TimedOut(s) => Some(s),
            Outcome::Completed | Outcome::Aborted(_) => None,
        }
    }

    /// Whether the unit ran to the end.
    pub fn is_completed(self) -> bool {
        matches!(self, Outcome::Completed)
    }
}

/// The end of a unit: how it finished, and the posting that finished it.
///
/// There is exactly one of these per unit and only the exit path can build one — the same place
/// that takes the hold out of its cell, so an end and a settlement are the same event and cannot
/// drift apart. The posting is a result because durability can fail: a unit that delivered value
/// but could not record it ends with the loss recorded rather than with the value forgotten.
#[derive(Debug)]
pub struct UnitEnd {
    outcome: Outcome,
    posted: Result<Posted, DurabilityLost>,
}

impl UnitEnd {
    /// Seal the unit's end. Exit path only.
    pub fn seal(
        _token: &ExitToken,
        outcome: Outcome,
        posted: Result<Posted, DurabilityLost>,
    ) -> Self {
        UnitEnd { outcome, posted }
    }

    /// How the unit finished.
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The posting, or the durability failure that stood in its place.
    pub fn posted(&self) -> Result<&Posted, &DurabilityLost> {
        self.posted.as_ref()
    }

    /// Take the posting out, for the record writer.
    pub fn into_posted(self) -> Result<Posted, DurabilityLost> {
        self.posted
    }
}
