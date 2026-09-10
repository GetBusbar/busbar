// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the other two planes' mounts carry the same
// line: a mount is composition of the SERVING path, and it names items that exist only under this
// feature. Declared in `root/mod.rs` under `root-llm` instead, so a plane-gated module is not named
// from code under a different feature.
#![cfg(feature = "root-llm-serve")]

//! THE LLM PLANE'S MOUNT: this plane's claim table, this plane's leg, and this plane's media type.
//!
//! ## Three answers, and the body is not here
//!
//! The body a mount needs is [`crate::root::plane_mount`] — the claim walk over the closed grammar,
//! the operator's ingress cap read before the router's own, the reserved facts, the channel between
//! a synchronous loop and an asynchronous router, and the rule that a unit refused before Route
//! executes nothing. None of that is about this plane, and the two mounts beside this one prove it
//! by being three lines each.
//!
//! Two of the three answers are here and are complete: the claim table this plane declares, and the
//! media type its document answers carry. The third — the leg — is stated below rather than
//! written, because writing it today would mean writing something untrue. See [`WHY_NO_LEG_YET`].
//!
//! ## What the claim walk had to be fixed to see
//!
//! This plane declares its surface differently from the two mounted before it. A2A and MCP name
//! ADDRESSES — `Selector::ExactPath` and `Selector::PathPattern` — and the mount's path walk read
//! exactly those two shapes. This plane's fourteen-rung ladder names most of its surface as a path
//! SUFFIX or a CONTAINED literal, because a deployment puts the same dialect behind different
//! prefixes and the dialect is what the suffix identifies.
//!
//! Both of those forms are in the grammar's own `Path` family, and both fell into the walk's
//! "everything else is not a path" arm. So this plane could have been mounted and would never have
//! been reached: every address of it would have walked around the loop to the router underneath,
//! with nothing failing to say so. That is fixed in `plane_mount` as its own seam commit, over the
//! grammar's shapes and naming no protocol, and the cell at the bottom of this file is the
//! plane-side proof that this plane's own declared surface is now claimed.

use crate::root::plane_mount::{self, MEDIA_JSON};

/// Whether one path is an address THIS plane claims.
///
/// The walk is [`plane_mount::claims_a_path`] and the table is the plane's own; this file supplies
/// neither. A path list here would be a second declaration of where this protocol lives, and the one
/// that drifts is the one nobody re-derived — which on this plane is fourteen rungs long and
/// therefore the last list anybody would notice going stale.
#[must_use]
pub fn claims_the_path(path: &str) -> bool {
    plane_mount::claims_a_path(busbar_plane_llm::claims::CLAIMS, path)
}

/// The media type this protocol's document answers carry.
///
/// The one type this plane's dialects answer with for every operation that returns a document rather
/// than a run of events. The streamed shape is the same request's event framing and is not a second
/// media type this file names: the plane declares it as `claims::STREAM_TRANSPORT`, and what a
/// mounted answer is FRAMED as is carried on the plane's own response, which the mount hands back
/// untouched.
#[must_use]
pub fn media_type() -> &'static str {
    MEDIA_JSON
}

/// **THE MONEY SEAM THAT BLOCKED THIS PLANE'S LEG, AND HOW IT WAS OPENED.**
///
/// A [`plane_mount::MountedLeg`] must hand back two things from one walk: the kernel's own
/// [`busbar_kernel::teller::Ended`], and the plane's answer. This plane could always produce the
/// answer. It could not hand back the end, for a reason that was about money and not about wiring.
///
/// The exit arm of `units_llm::LlmNode` SETTLES: it took the `Ended`, destructured
/// `Ended::Settled { end, .. }`, and moved the `UnitEnd`'s `Posted` into the root's books. Every one
/// of those moves was by value ON PURPOSE — a `Posted` exists exactly once per hold, and the
/// by-value move is what made a second settlement of one hold unwritable. So the plane's settlement
/// CONSUMED the end the mount is owed.
///
/// Two of the three ways out were refused and stay refused:
///
/// - Return [`busbar_kernel::teller::Ended::AlreadySettled`] instead. It compiles, and it is a lie:
///   it tells the mount the kernel settled this unit at its own exit, which is the one thing that
///   did not happen. A mount that believed it would render a refusal for the wrong reason on the one
///   path where the answer is absent.
/// - Skip the settlement on the mounted path. Worse than a lie: the unit runs, the loop posts, and
///   the posting is dropped on the floor. That path serves traffic and bills none of it.
///
/// **The third is the one taken: the plane settles from a BORROW.** `UnitEnd::lend_posting` hands
/// the posting out once and refuses the second; `Durability::settle_lent` and
/// `busbar_unit_ledger`'s `post_lent` move the same books through the same arithmetic and write the
/// same two records through the same builder; and the ending walks out of the exit arm intact.
///
/// ## Where exactly-once lives now, said plainly
///
/// It used to live in the MOVE, with no flag and no check. A borrow cannot carry that, because a
/// reference can be taken twice. So it is a REFUSAL: the end that owns the posting lends it once.
/// What the type still carries is the other half — `busbar_caps::PostingLent` has a private field
/// and comes out of exactly one place, so a settlement that takes a borrow cannot be reached from a
/// `&Posted` anybody happened to be holding.
///
/// The byte-identity cell is `a_posting_the_exit_path_built_settles_exactly_as_a_hold_does` in
/// `root/tests/durability.rs`: three doors — a hold, an owned posting, a lend — one balance, one
/// set of four columns, and one chain head, which is what "identical ledger bytes" means.
pub const WHY_NO_LEG_YET: &str =
    "the blocker is lifted: the plane's exit arm settles from a lend and the Ended survives it";

#[cfg(test)]
#[path = "tests/units_llm_mount.rs"]
mod tests;
