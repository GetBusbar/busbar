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
//! All three are here. The claim table this plane declares, the media type its document answers
//! carry, and — as of the leg beside this file — the walk itself. The third one used to be STATED
//! rather than written, because writing it then would have meant writing something untrue: the
//! plane's exit arm consumed the ending a mount is owed. [`WHAT_UNBLOCKED_THE_LEG`] is that account,
//! kept because the answer to "why is this shaped like this" is in it.
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

use std::sync::Arc;

use crate::root::plane_mount::{self, MountedLeg, MEDIA_JSON};
use crate::root::units_llm_leg::LlmLeg;
use busbar_contract::{grammar::Claim, plane::PlaneMeta, transport::Arrival};

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
/// What the type still carries is the other half — `PostingLent` has a private field
/// and comes out of exactly one place, so a settlement that takes a borrow cannot be reached from a
/// `&Posted` anybody happened to be holding.
///
/// The byte-identity cell is `a_posting_the_exit_path_built_settles_exactly_as_a_hold_does` in
/// `root/tests/durability.rs`: three doors — a hold, an owned posting, a lend — one balance, one
/// set of four columns, and one chain head, which is what "identical ledger bytes" means.
pub const WHAT_UNBLOCKED_THE_LEG: &str =
    "the plane's exit arm settles from a lend, so the Ended survives it and a leg can hand it on";

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LEG, ON THE MOUNT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

impl MountedLeg for LlmLeg {
    fn claims(&self) -> &'static [Claim] {
        busbar_plane_llm::claims::CLAIMS
    }

    fn recognises(&self, arrival: &Arrival<'_>) -> bool {
        LlmLeg::recognises(self, arrival)
    }

    fn serve<'a>(
        &'a self,
        arrival: &'a Arrival<'a>,
        _kernel: &'a busbar_kernel::teller::Kernel,
        _ctx: &'a busbar_kernel::teller::UnitCtx,
        _run: busbar_kernel::teller::Run<'a>,
        _dispatch: Option<&'a dyn crate::root::transports::MountDispatch>,
    ) -> plane_mount::Walked<'a> {
        // **THIS LEG'S WALK IS GENUINELY ASYNCHRONOUS**, and it is the first one that is. The two
        // legs mounted before this step through the kernel's teller synchronously and take
        // themselves off the reactor with `sync_leg`; this one AWAITS — its Route step dials an
        // upstream and its answer may be a body that has not finished — so it simply awaits, which
        // is exactly the case the mount widened its seam for.
        //
        // AND THE FOUR ARGUMENTS THE MOUNT OFFERS ARE UNREAD. Not ignored: refused, for a reason
        // written out in the leg's own module note. This plane's walk already exists on the driven
        // path, over a node that owns one in-flight table, one gauge, one canary, one door and one
        // book. Running the same protocol against the mount's second set would give the node two of
        // each for one plane, and which one a request was counted on would depend on whether an
        // operator had composed a mount — a difference in the admission bound and in the money,
        // arrived at silently. The dispatch seam is unread for a plainer reason still: this plane's
        // Route dials its own destination, so there is no surface underneath to ask.
        Box::pin(async move {
            let (ended, response) = LlmLeg::serve(self, arrival).await;
            // AND THE PLANE'S RESPONSE GOES BACK UNTOUCHED. No frame is built here and none is read:
            // this plane's answer is already a response, its body may still be streaming, and the
            // cell the late accrual reads rides on it as an extension. The two mounts beside this
            // one build a frame because their legs hand back buffered bytes; that is the cost of
            // their own choice and this plane does not pay it.
            (ended, Some(response))
        })
    }

    fn render_refusal(
        &self,
        _arrival: &Arrival<'_>,
        _ended: &busbar_kernel::teller::Ended,
    ) -> Option<Vec<u8>> {
        // NOTHING FOR THE MOUNT TO RENDER, and that is a property of this plane rather than a gap.
        // The mount renders a refusal only where the leg handed back NO answer, and this leg always
        // has one: every way out of this plane's walk — the two audit doors, the veto, the
        // pre-admission guard, the table declining — leaves the terminal's own response behind, in
        // the caller's own dialect, already accounted. A document rendered here would be a second
        // answer to a request that has one.
        None
    }

    fn media_type(&self) -> &'static str {
        media_type()
    }
}

/// Wrap a mounted LLM surface so every unit of this plane on it travels through the kernel.
///
/// `request_body_max_bytes` is the operator's own ingress cap, the same figure the mounted router's
/// body limit was built with. It is a parameter rather than a constant because the wrap reads the
/// body BEFORE that limit gets a chance to.
pub fn mount(
    inner: axum::Router,
    leg: Arc<LlmLeg>,
    kernel: busbar_kernel::teller::Kernel,
    parts: Arc<crate::root::data_plane::NodeParts>,
    request_body_max_bytes: usize,
) -> axum::Router {
    plane_mount::mount(inner, leg, kernel, parts, request_body_max_bytes)
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE ROW THE BOOT READS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **THIS PLANE'S MOUNT, AS ONE DATA ROW** — the only thing the boot reads to serve it.
///
/// Declared here, beside the leg it assembles, rather than spelled out in the composition step: the
/// boot folds rows and names no plane, so this plane's presence on the shipped serving path is a row
/// in this file and not a line in `main.rs`.
pub const MOUNT_ROW: crate::root::registry::MountRow = crate::root::registry::MountRow {
    plane: <busbar_plane_llm::LlmPlane as PlaneMeta>::KEY,
    compose,
};

/// Assemble this plane's leg over what the boot holds.
///
/// **NO SOURCE OF THIS PLANE'S CAN BE ABSENT, so this never refuses** — and that is the same fact
/// the leg's own `assemble` states by having no `MissingSource` arm. The two things a walk here
/// needs are a node, which this composes, and the deployment's ingress source, which the boot holds
/// by definition at the instant it calls this.
///
/// **THE NODE IS BOUND TO THE PROCESS'S BOOK BEFORE THE LEG IS BUILT.** An unbound node settles its
/// postings nowhere, and a node whose postings go nowhere serves traffic that looks healthy and
/// prices nothing — so the binding happens here, where the book is in hand, rather than being left
/// to a caller who might not know this plane settles at all.
fn compose(
    inputs: &crate::root::registry::MountInputs,
) -> Result<Arc<dyn plane_mount::MountedLeg>, crate::root::registry::MountAbsent> {
    let node = crate::root::units_llm::LlmNode::new();
    node.bind_book(Arc::clone(&inputs.book));
    Ok(Arc::new(LlmLeg::assemble(
        node,
        Arc::clone(&inputs.ingress),
    )))
}

#[cfg(test)]
#[path = "tests/units_llm_mount.rs"]
mod tests;
