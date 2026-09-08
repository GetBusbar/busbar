// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the leg beside it carries the same line: a
// mount is composition of the SERVING path, and it names items that exist only under this feature.
// Declared in `root/mod.rs` under `root-mcp` instead, so a plane-gated module is not named from code
// under a different feature.
#![cfg(feature = "root-mcp-serve")]

//! THE MCP PLANE'S MOUNT: this plane's claim table, this plane's leg, and this plane's media type.
//!
//! ## Three lines, and that is the whole point
//!
//! The body a mount needs is [`crate::root::plane_mount`] — the claim walk over the closed grammar,
//! the ingress cap read before the router's own, the reserved facts, the request/answer channel
//! between a synchronous loop and an asynchronous router, and the rule that a unit refused before
//! Route executes nothing. None of that is about MCP, and none of it was about A2A either: it was
//! written in the A2A mount because that plane's leg had a surface to reach first, and it moved out
//! when this leg needed the same thing.
//!
//! So there is no MCP-shaped twin of any of it here. What is here is the three answers only this
//! plane can give.
//!
//! ## What this mount claims, and what it deliberately hands straight through
//!
//! The plane declares four claims and this mount walks all four. Two of them are addresses on this
//! listener:
//!
//! - **`/mcp`** — the request surface, and `/mcp/` with it, because a trailing slash is the same
//!   address to every router in this tree and to every client of this protocol. The normalisation is
//!   [`crate::root::plane_mount::claims_a_path`]'s and is stated there.
//! - **`/.well-known/oauth-protected-resource/mcp`** — the discovery document, which is CLAIMED and
//!   is not a unit. It carries no JSON-RPC body, so the plane's own decode names no operation for
//!   it, and the second question every mount asks hands it straight to the surface that already
//!   serves it. That surface answers with the deployment's `mcp.canonical_uri` — the RFC 8707
//!   resource indicator this node PUBLISHES — and the mount does not re-derive it, because a second
//!   reading of the audience is a second answer to which tokens open this surface.
//!
//! The other two claims are made over carriers this listener is not: the streamed surface has its
//! own transport and the locally launched one has no path at all. Neither matches a path, which is
//! why the walk can be over the whole table without this file reading a transport.
//!
//! ## The audience is the PLANE'S, and is demanded by the leg's authenticate step
//!
//! `units_mcp::authenticate` supplies the expected audience from the plane's own canonical key, on
//! every credentialed claim and on no open one. There is nothing for this mount to supply: a mount
//! that carried an audience of its own would be the second answer named above.

use std::sync::Arc;

use crate::root::plane_mount::{self, MountedLeg, MEDIA_JSON};
use crate::root::units_mcp_leg::McpLeg;

/// Whether one path is an address THIS plane claims.
///
/// The walk is [`plane_mount::claims_a_path`] and the table is the plane's own; this file supplies
/// neither. A path list here would be a second declaration of where this protocol lives, and the one
/// that drifts is the one nobody re-derived.
#[must_use]
pub fn claims_the_path(path: &str) -> bool {
    plane_mount::claims_a_path(busbar_plane_mcp::claims::CLAIMS, path)
}

impl MountedLeg for McpLeg {
    fn claims(&self) -> &'static [busbar_contract::grammar::Claim] {
        busbar_plane_mcp::claims::CLAIMS
    }

    fn recognises(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool {
        McpLeg::recognises(self, arrival)
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
        McpLeg::serve(self, arrival, kernel, ctx, run, dispatch)
    }

    fn render_refusal(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        ended: &busbar_kernel::teller::Ended,
    ) -> Option<Vec<u8>> {
        McpLeg::render_refusal(self, arrival, ended)
    }

    fn media_type(&self) -> &'static str {
        // The one type this protocol's declaration names for every operation that answers with a
        // document rather than a run of events.
        MEDIA_JSON
    }
}

/// Wrap a mounted MCP surface so every unit of this plane on it travels through the kernel.
///
/// `request_body_max_bytes` is the operator's own ingress cap, the same figure the mounted router's
/// body limit was built with. It is a parameter rather than a constant because the wrap reads the
/// body BEFORE that limit gets a chance to.
pub fn mount(
    inner: axum::Router,
    leg: Arc<McpLeg>,
    kernel: busbar_kernel::teller::Kernel,
    request_body_max_bytes: usize,
) -> axum::Router {
    plane_mount::mount(inner, leg, kernel, request_body_max_bytes)
}

#[cfg(test)]
#[path = "tests/units_mcp_mount.rs"]
mod tests;
