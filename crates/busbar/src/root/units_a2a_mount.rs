// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the leg beside it carries the same line: a
// mount is composition of the SERVING path, and it names items that exist only under this feature.
// Declared in `root/mod.rs` under `root-a2a` instead, so a plane-gated module is not named from code
// under a different feature.
#![cfg(feature = "root-a2a-serve")]

//! THE A2A PLANE'S MOUNT: this plane's claim table, this plane's leg, and this plane's media type.
//!
//! ## What used to be here, and where it went
//!
//! Six hundred lines: a claim walk over the closed grammar's selector shapes, an ingress cap read
//! before the router's own, a fact publication over the kernel's reserved keys, a request/answer
//! channel between a synchronous loop and an asynchronous router, an ending narrowed to a status,
//! and the rule that a unit refused before Route executes nothing.
//!
//! **Not one line of it was about A2A.** It was written here because this was the first plane whose
//! leg had a surface to reach, and when the MCP leg needed a mount the honest reading of "the same
//! shape" turned out to be "the same code". So the body moved to [`crate::root::plane_mount`] and
//! this file became what it always was: a claim table, a leg, and a media type. Two files with the
//! same six hundred lines are two things that can drift, and the first thing to drift between them
//! would have been a difference nobody meant.
//!
//! Everything the shared mount does and why is documented there, including the two questions it asks
//! before it takes a request off the surface that already answers it.

use std::sync::Arc;

use crate::root::plane_mount::{self, MountedLeg};
use crate::root::units_a2a_leg::A2aLeg;

// The helpers this plane's own cells drive directly, and the two grammar shapes they walk.
// Re-exported rather than re-declared: a second copy of the header conversion or the status
// narrowing is a second answer, and the cells below are asserting about the ONE the mount uses.
pub use crate::root::plane_mount::MEDIA_JSON;
#[cfg(test)]
pub(crate) use crate::root::plane_mount::{drive, header_pairs, status_of, RequestDispatch};
#[cfg(test)]
use busbar_contract::grammar::{PathSeg, Selector};

/// Whether one path is an address THIS plane claims.
///
/// The walk is [`plane_mount::claims_a_path`] and the table is the plane's own; this file supplies
/// neither. A path list here would be a second declaration of where this protocol lives, and the one
/// that drifts is the one nobody re-derived.
#[must_use]
pub fn claims_the_path(path: &str) -> bool {
    plane_mount::claims_a_path(busbar_plane_a2a::claims::CLAIMS, path)
}

impl MountedLeg for A2aLeg {
    fn claims(&self) -> &'static [busbar_contract::grammar::Claim] {
        busbar_plane_a2a::claims::CLAIMS
    }

    fn recognises(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool {
        A2aLeg::recognises(self, arrival)
    }

    fn serve(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        kernel: &busbar_kernel::teller::Kernel,
        ctx: &busbar_kernel::teller::UnitCtx,
        run: busbar_kernel::teller::Run<'_>,
        dispatch: Option<&dyn crate::root::transports::PlaneDispatch>,
    ) -> (
        busbar_kernel::teller::Ended,
        Option<crate::root::transports::PlaneAnswer>,
    ) {
        A2aLeg::serve(self, arrival, kernel, ctx, run, dispatch)
    }

    fn render_refusal(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        ended: &busbar_kernel::teller::Ended,
    ) -> Option<Vec<u8>> {
        A2aLeg::render_refusal(self, arrival, ended)
    }

    fn media_type(&self) -> &'static str {
        // The one type this protocol's declaration names for every operation that answers with a
        // document rather than a run of events.
        MEDIA_JSON
    }
}

/// Wrap a mounted A2A surface so every unit of this plane on it travels through the kernel.
///
/// `request_body_max_bytes` is the operator's own ingress cap, the same figure the mounted router's
/// body limit was built with. It is a parameter rather than a constant because the wrap reads the
/// body BEFORE that limit gets a chance to.
pub fn mount(
    inner: axum::Router,
    leg: Arc<A2aLeg>,
    kernel: busbar_kernel::teller::Kernel,
    request_body_max_bytes: usize,
) -> axum::Router {
    plane_mount::mount(inner, leg, kernel, request_body_max_bytes)
}

#[cfg(test)]
#[path = "tests/units_a2a_mount.rs"]
mod tests;
