// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S HALF of busbar-as-an-OAuth-2.1-authorization-server — which, after the 1.6.0
//! control-kind ruling, is very nearly nothing.
//!
//! ## What moved, and where the rest of it went
//!
//! Everything that IS the authorization server — the `oauth_as:` grammar and its boot refusals, the
//! ES256 signer, the consent sessions, the registration ceiling, the Client ID Metadata Document
//! checks, the running server object and the route table — is now `busbar-control-oauth2`, a
//! CONTROL-kind crate. `docs/design/control-oauth2.md` is the module map; `docs/design/PLUGIN-TREE.md`
//! carries the control-kind row and the rule this obeys: *a control surface declares routes as data;
//! no plugin names a transport.*
//!
//! Two things stayed, and each stayed for a reason that is about the NODE rather than about OAuth:
//!
//! * [`fetch`] — the guarded CIMD fetch. The URL is attacker-supplied on an endpoint that takes no
//!   credential, so what makes it safe is [`crate::net_guard`]'s resolve-then-pin, which is the
//!   node's security control and must have exactly one copy. The surface declares the seam and its
//!   own bounds; the node supplies the mechanism.
//! * The re-exports below, so the config lowering, the secret-ref walker and the boot path keep
//!   naming `crate::oauth_as::…` while the types they name live in the surface crate. Those are a
//!   TRANSITION, not a design: they disappear when the `oauth_as:` lowering moves to the config home
//!   and the surface is constructed by the composition root rather than by `appbuild`. See the
//!   design doc's staging section — this is the one edge that is named there as owed.
//!
//! ## What it costs when it is off
//!
//! Nothing, and it is CHECKED rather than asserted. "Off" is the composition holding no
//! `OAuth2Control`: no server, no store, no signing key, no sweeper, no route — so the auth
//! middleware has nothing to consult and the route table has nothing to describe. The check is
//! [`mount_tests`]: it subtracts the unconfigured route table from the configured one, requires the
//! difference to be exactly the surface's declared path inventory, and then requires the
//! unconfigured table to contain none of it. The second half is the claim; the first half is what
//! stops the second half from passing because the mount was deleted.

pub(crate) mod control;
pub(crate) mod fetch;

pub use control::{install_control_surfaces, CONTROL_DECL};

// ── THE TRANSITIONAL RE-EXPORTS ────────────────────────────────────────────────────────────────
// Each of these is one name a core call site still spells `crate::oauth_as::…`. They are listed
// individually rather than as a glob so that the surface this node still couples to is READABLE:
// the day the list is empty is the day the edge is gone, and a glob would hide the difference
// between a list of four and a list of forty.

/// The `oauth_as:` grammar and the validated identity every endpoint is derived from. Read by
/// `config::resolve` (which lowers the block), `config::prepass` (which lifts it) and
/// `config_validate::secret_refs` (which DESTRUCTURES `AsIdentity` exhaustively, so that a newly
/// added secret-bearing field is a compile error rather than an oversight).
pub(crate) mod config {
    pub(crate) use busbar_control_oauth2::config::{AsIdentity, OauthAsCfg};
}

/// The running surface, held for one config generation. Built by `appbuild`, read by the control
/// mount, dropped with the generation.
pub(crate) mod surface {
    pub(crate) use busbar_control_oauth2::surface::{spawn_sweeper, OAuth2Control, SweepFault};
}

/// The consent sessions' vocabulary and the `Set-Cookie` enumeration, named by the flow proof.
#[cfg(test)]
pub(crate) mod consent {
    pub(crate) use busbar_control_oauth2::consent::SESSION_TTL;
}

/// The declared route table's own vocabulary and the `Set-Cookie` enumeration behind it, named by
/// the flow proof and by the mount proof.
#[cfg(test)]
pub(crate) mod routes {
    pub(crate) use busbar_control_oauth2::routes::session_cookies;
}

/// The Client ID Metadata Document seam — the trait `fetch::GuardedFetch` implements, and the one
/// the flow proof stands a stub in for.
#[cfg(test)]
pub(crate) mod cimd {
    pub(crate) use busbar_control_oauth2::cimd::CimdFetch;
}

/// THE BUILT SURFACE FOR ONE GENERATION, read back out of the control-slot map — `None` when this
/// deployment is not an authorization server.
///
/// The two proofs below used to spell this `app.oauth_as`, a typed `Option` field. It is a downcast
/// now because `App` holds control surfaces the way it holds planes: type-erased, keyed by the
/// surface's own registry key, so core names no control surface in a struct field. `None` and
/// "absent from the map" are the same fact, which is what makes the gating proof's `is_none()` arm
/// mean what it meant.
#[cfg(test)]
pub(crate) fn surface_of(app: &crate::state::App) -> Option<&surface::OAuth2Control> {
    app.control_slots
        .get(busbar_control_oauth2::meta::KEY)
        .map(|slot| {
            slot.downcast_ref::<surface::OAuth2Control>()
                .expect("the oauth2 control slot holds an OAuth2Control")
        })
}

// THE GATING PROOF, attached to the module root rather than to a mount, because what it checks is
// not a property of the mount alone: it spans the config lowering, the built surface and the route
// table, and it is only a proof if it holds across all three at once.
#[cfg(test)]
#[path = "tests/mount_tests.rs"]
mod mount_tests;

// THE FLOW, driven over a socket through a path-scoping cookie jar. Attached here for the same
// reason the gating proof is: it spans the mount, the consent route and the `oauth-as` callbacks,
// and it is only a proof of "this deployment can mint a code" if it holds across all of them at
// once.
#[cfg(test)]
#[path = "tests/flow_tests.rs"]
mod flow_tests;
