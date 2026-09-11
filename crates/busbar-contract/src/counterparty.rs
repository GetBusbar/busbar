// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COUNTERPARTY VOCABULARY: what one side asserts about the other side, and the verdict that
//! answers it.
//!
//! A counterparty is the remote a unit is about to deal with. Two different readers hold two
//! different halves of what is known about one: the side that just looked at it holds the
//! OBSERVATION — is the principal behind this ask still live, is the ask inside what was granted,
//! what does the register say about it, is it still offering what was approved, is the snapshot it
//! was admitted under still the snapshot in force — and the side that keeps the books holds the
//! STANDING, which is the durable disposition an earlier observation settled. Neither half is the
//! answer on its own, and the answer is a single closed word.
//!
//! Both halves are spelled HERE, in the one crate every kind is granted, for the reason every
//! shared vocabulary is minted rather than restated: the fold that turns facts into a verdict is
//! one decision, and a decision written twice is a decision that disagrees with itself the first
//! time either copy is edited. Before this existed the facts could only be spelled in a wire
//! encoding and the verdict only in the same encoding's enum, so the fold could only be written
//! where that encoding could be named — which is one crate, and not the crate whose step it is.
//!
//! ## Facts are asserted, never authoritative
//!
//! [`CounterpartyFacts`] is what a side SAYS. It is not a permission: a fold that reads these may
//! narrow a standing that already allows, and may never widen one that refuses — otherwise a
//! counterparty the books have already demoted could assert [`RegistrationState::Approved`] about
//! itself and buy its way back, which is the confused deputy with extra steps. The rule lives with
//! the fold, not here; what belongs here is that this type carries a CLAIM and the reader is told
//! so by its name.
//!
//! ## Every default is the closed one
//!
//! `Default` is implemented on every type below, and every default is the refusing value:
//! [`Liveness::NotLive`], [`RegistrationState::Unknown`], [`Verdict::Denied`]. A reader that
//! cannot fill a field, or cannot decide at all, therefore lands on the value that refuses rather
//! than on the value that serves — a fact nobody wrote must never read as a fact that passes.

/// Where a counterparty stands in the register that admits it.
///
/// [`Approved`](Self::Approved) is the ONLY state that serves. Every other state is a distinct
/// reason for not serving, and they are kept apart because each names a different remedy: a
/// quarantine is re-established by a fresh look, a pending registration by redeeming an approval, a
/// suspension by the operator who imposed it, and an unknown state by finding out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RegistrationState {
    /// Nothing is on record, or what is on record cannot be read. The fail-closed default.
    #[default]
    Unknown,
    /// Registered but not yet approved: a one-time approval has still to be redeemed.
    Pending,
    /// Approved, and serving. The one state that passes.
    Approved,
    /// Demoted on drift, and refused until it is re-established.
    Quarantined,
    /// Held back by the operator's own standing decision.
    Suspended,
    /// The last attempt to establish it did not complete.
    Failed,
}

/// Whether the principal behind the ask is still live.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Liveness {
    /// Deleted, disabled or expired. The fail-closed default.
    #[default]
    NotLive,
    /// Live.
    Live,
    /// There is no principal, honestly and by configuration. It is not a way past the gate: the
    /// later steps still run, and it is kept apart from [`NotLive`](Self::NotLive) because an
    /// ungoverned deployment and a revoked identity are not the same fact.
    NoPrincipal,
}

/// Whether the ask is inside what was granted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Grant {
    /// Every grant the ask needs is held.
    #[default]
    Held,
    /// The asker's own grant does not reach what was asked for.
    NotGranted,
    /// The target's standing list of who may reach it does not name the asker. Kept apart from
    /// [`NotGranted`](Self::NotGranted) because the two are fixed by different people.
    EgressDenied,
}

/// Whether what the counterparty offers is still what was approved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Artifact {
    /// The ask names no artifact, so there is nothing to compare. The default.
    #[default]
    NotAsked,
    /// What is offered is what was approved.
    Serves,
    /// What is offered is not what was approved.
    Drifted,
    /// Nothing that could be compared could be read. Refused with drift rather than passed,
    /// because a fingerprint nobody could take is not a fingerprint that matched.
    Unobservable,
}

/// The facts one side asserts about a counterparty at one moment.
///
/// The two generations are carried rather than compared for the same reason the rest are carried
/// as facts: the asserting side knows which snapshot the ask was admitted under and which is in
/// force now, and the folding side decides what a difference between them means.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CounterpartyFacts {
    /// Is the principal behind the ask still live?
    pub liveness: Liveness,
    /// Is the ask inside what was granted?
    pub grant: Grant,
    /// What does the register say?
    pub registration: RegistrationState,
    /// Is what is offered what was approved?
    pub artifact: Artifact,
    /// The catalogue generation the ask was admitted under.
    pub generation_admitted: u64,
    /// The catalogue generation in force now.
    pub generation_live: u64,
}

/// May this counterparty be dealt with NOW?
///
/// [`Allow`](Self::Allow) is the only value that serves; every other value is a refusal that KEEPS
/// THE STEP THAT PRODUCED IT. Collapsing them to one word would be cheaper to write and would cost
/// the operator the only thing a refusal is good for, which is knowing what to fix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Trusted: proceed.
    Allow,
    /// Demoted on drift; refused until it is re-established.
    Quarantined,
    /// Refused, with no narrower reason available. The fail-closed default.
    #[default]
    Denied,
    /// Not yet approved: a one-time approval must be redeemed first.
    NeedsApproval,
    /// The principal behind the ask is no longer live.
    IdentityNotLive,
    /// The asker's grant does not reach what was asked for.
    NotGranted,
    /// The target's standing list does not name the asker.
    EgressDenied,
    /// What is offered is not what was approved, or could not be read at all.
    ArtifactDrifted,
    /// The snapshot moved between admission and the deal.
    GenerationMoved,
}
