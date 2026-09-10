// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's own capability types: where a unit came from, how it is keyed, which session it
//! belongs to, and — the one that closes every unit — how it ended. None of the four is built by
//! any unit: the kernel builds the first three and the exit path builds the last, so all four are
//! sealed on the kernel seal or the exit token rather than on a unit's own token.
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
//!                   Posted, PrincipalId, UnitEnd, Usage, UsageToken};
//! let seal = KernelSeal::acquire_for_kernel();
//! let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
//! let hold = Hold::open(&admit, PrincipalId::new("acct-1"), 10);
//! let usage = Usage::report(&UsageToken::mint(&seal), Vec::new()).unwrap();
//! let posted = Posted::settle(hold, 0, &usage, &LedgerToken::mint(&seal));
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
///
/// One encoding, not two. `Client`, `Drain` and `Superseded` were once variants here as well as
/// reasons in the closed vocabulary, so the same ending could be written down two ways and nothing
/// reading the record could tell whether the two spellings were the same event. What is left is
/// the reason itself, plus the one shape that carries something a reason cannot: which unit took
/// this one's place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    /// The node cut it, for a named reason — a client that went away and a node that is draining
    /// both arrive here, as `ClientGone` and `Drain`.
    Kernel {
        /// The reason.
        reason: ReasonCode,
    },
    /// A later unit took its place. Its own variant because it names that unit, which no reason
    /// code carries.
    Superseded {
        /// The unit that took over.
        by: UnitKey,
    },
}

impl Abort {
    /// The reason this abort is recorded under. Every abort has one, and no two shapes share one,
    /// so the journal row and the reason vocabulary say the same thing.
    pub fn reason(self) -> ReasonCode {
        match self {
            Abort::Kernel { reason } => reason,
            Abort::Superseded { .. } => ReasonCode::Superseded,
        }
    }
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
    /// Whether the posting has already been lent for a settlement.
    ///
    /// The by-value door — [`UnitEnd::into_posted`] — carries exactly-once in its signature: it
    /// consumes the end, so there is no second call to make. The LENT door cannot, because a
    /// `&Posted` is a reference and a reference can be taken again. So the property moves off the
    /// move and onto this flag: the end that OWNS the posting is the one thing that can say whether
    /// it has already been handed to a settlement, and it says it once.
    lent: bool,
}

impl UnitEnd {
    /// Seal the unit's end. Exit path only.
    pub fn seal(
        _token: &ExitToken,
        outcome: Outcome,
        posted: Result<Posted, DurabilityLost>,
    ) -> Self {
        UnitEnd {
            outcome,
            posted,
            lent: false,
        }
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
    ///
    /// The door for a driver that is FINISHED with the end. It consumes the end, which is what has
    /// always made a second settlement of one hold unwritable, and it is left exactly as it was:
    /// every caller of it settles and then drops. A driver that must hand the end ON after settling
    /// cannot use this door at all — settling through it destroys the thing it still owes — and
    /// reaches for [`UnitEnd::lend_posting`] instead.
    ///
    /// ## THE RESIDUAL HOLE, NAMED RATHER THAN DISCOVERED
    ///
    /// One end can be settled TWICE: lend the posting, settle through the borrow, drop the witness,
    /// then call this and settle again by value. The `lent` flag knows it happened and this door
    /// cannot say so, because its return type has exactly two arms and neither is "already settled"
    /// — the `Err` arm is a `DurabilityLost`, a record of an observed write failure, and minting one
    /// here would be a lie about what happened to the money.
    ///
    /// It is not reachable today: nothing in this tree lends and then takes, the one path that lends
    /// is a plane's exit arm which hands the end straight on, and the callers of this door all
    /// settle and drop. It is written down because a hole that nobody has named is a hole the next
    /// caller walks into.
    ///
    /// Closing it means widening this signature — `Option<Result<…>>`, or a second by-value door
    /// with a refusal arm and this one retired — which is a change to every call site and a review
    /// of its own rather than a line squeezed into a slot about a mount.
    pub fn into_posted(self) -> Result<Posted, DurabilityLost> {
        self.posted
    }

    /// **LEND THE POSTING FOR EXACTLY ONE SETTLEMENT, and keep the end intact.**
    ///
    /// The door for a driver that settles and then owes the END to something else — a plane whose
    /// walk is behind a mount, where the mount is owed the kernel's own ending and the plane's exit
    /// arm has to settle before it can hand one over.
    ///
    /// ## The exactly-once property, and where it now lives
    ///
    /// It used to live in the MOVE. A [`Posted`] is not `Clone`, settling consumes it, and a second
    /// settlement of one hold was therefore unwritable — no flag, no check, nothing to get wrong.
    /// A borrow cannot carry that, because a reference can be taken twice.
    ///
    /// So it lives HERE, in the end that owns the posting, and it is a REFUSAL rather than a type
    /// error: the first call hands back the witness, every later call answers `None`. That is the
    /// honest description of the mechanism, and it is deliberately not dressed up as the old one.
    ///
    /// What the TYPE still carries is the other half. [`PostingLent`] has a private field and no
    /// public constructor, so the only way to reach a settlement that takes a borrow is through this
    /// method: a caller cannot manufacture the witness out of a `&Posted` it came by some other way,
    /// and there is no other way, because [`UnitEnd::posted`] lends a plain reference that no
    /// settlement accepts.
    ///
    /// `None` on the first call means the unit ended with a durability loss recorded in the
    /// posting's place — there is nothing to settle, which is the same answer
    /// [`UnitEnd::into_posted`]'s `Err` arm gives. Read [`UnitEnd::posted`] to tell that `None`
    /// apart from the already-lent one where it matters; no settlement path needs to, because both
    /// mean settle nothing.
    pub fn lend_posting(&mut self) -> Option<PostingLent<'_>> {
        if self.lent {
            return None;
        }
        // Marked only where there IS a posting. An end carrying a durability loss lends nothing and
        // has nothing to protect, and marking it would make a later reading of this flag say that a
        // settlement happened.
        let posted = self.posted.as_ref().ok()?;
        self.lent = true;
        Some(PostingLent(posted))
    }
}

/// **ONE LEND OF ONE POSTING**, and the only way to reach a settlement that does not consume it.
///
/// A witness rather than a bare `&Posted`, and the difference is the whole point: the field is
/// private and this crate builds one in exactly one place — [`UnitEnd::lend_posting`], which hands
/// out at most one per end. A ledger door that took `&Posted` could be driven from any borrow
/// anybody happened to be holding, including one taken off an end that had already settled through
/// it. A door that takes THIS can only be driven by a lend, and a lend happens once.
///
/// It borrows the end for as long as it lives, so the end cannot be consumed out from under a
/// settlement that is still using it.
#[derive(Debug)]
pub struct PostingLent<'a>(&'a Posted);

impl PostingLent<'_> {
    /// The posting this lend is OF.
    pub fn posted(&self) -> &Posted {
        self.0
    }
}
