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

/// **WHY THERE IS NO `MountedLeg` IMPL IN THIS FILE YET, stated rather than worked around.**
///
/// A [`plane_mount::MountedLeg`] must hand back two things from one walk: the kernel's own
/// [`busbar_kernel::teller::Ended`], and the plane's answer. This plane can produce the answer — it
/// already walks `run_unit_async` and returns the terminal's response — and it cannot yet hand back
/// the end, for a reason that is about money and not about wiring.
///
/// The exit arm of `units_llm::LlmNode` SETTLES: it takes the `Ended`, destructures
/// `Ended::Settled { end, .. }`, and moves the `UnitEnd`'s `Posted` into the root's books through
/// `durability.settle_posted`. Every one of those moves is by value ON PURPOSE — a `Posted` exists
/// exactly once per hold, and the by-value move is what makes a second settlement of one hold
/// unwritable. So the plane's settlement CONSUMES the end the mount is owed.
///
/// The three ways out, and why none of them is taken here:
///
/// - Return [`busbar_kernel::teller::Ended::AlreadySettled`] instead. That is the free-standing
///   variant and it would compile, and it would be a lie: it tells the mount the kernel settled this
///   unit at its own exit, which is the one thing that did not happen. A mount that believed it
///   would render a refusal for the wrong reason on the one path where the answer is absent.
/// - Skip the settlement on the mounted path. That is worse than a lie: the unit runs, the loop
///   posts, and the posting is dropped on the floor. The mounted path would serve traffic and bill
///   none of it, and the paired money cell this slot owes would be comparing a settled leg against
///   an unsettled one.
/// - Let the plane settle from a BORROW. `UnitEnd::posted` already lends `&Posted`, so the read
///   exists; what does not is a settlement that takes one. `Durability::settle_posted` hands the
///   posting to `busbar_unit_ledger`'s own `post`, which takes it by value for the same
///   exactly-once reason. Making that read by reference is a change to the money seam, and a money
///   seam is not something to change in the last minutes of a slot with the paired byte-identity
///   cell unwritten.
///
/// The third is the one that is right, and it is the next commit rather than this one. Until then
/// this plane's mount answers the two questions it can answer truthfully and does not claim to be
/// servable: `root-llm-serve` is default OFF, nothing boots it, and the surface is the one that
/// shipped.
pub const WHY_NO_LEG_YET: &str =
    "the plane's exit arm consumes the Posted the mount's Ended carries";

#[cfg(test)]
#[path = "tests/units_llm_mount.rs"]
mod tests;
