// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN OAUTH 2.1 AUTHORIZATION SERVER (`oauth_as:`), off unless configured.
//!
//! ## 1.6.0: this crate is the plane half of the `oauth_as` split
//!
//! `busbar-core::oauth_as` used to hold this whole plane. 1.6.0 moved everything EXCEPT the config
//! carrier out to this sibling crate, which depends on busbar-core ONE-WAY (Cargo hard-refuses the
//! reverse edge, so this is enforced by the compiler, not by convention):
//!
//! * [`plane`] — `AsPlane`, the built runtime object for one config generation.
//! * [`routes`] — the mount: which paths this plane serves, at what admission bar.
//! * [`consent`] — the consent screen's session state and `oauth-as`'s subject/approval resolvers.
//! * [`cimd`] — Client ID Metadata Document fetch-and-validate (the CIMD registration mechanism).
//! * [`policy`] — the DCR registration ceiling and the impersonation refusal.
//! * [`signer`] — the plane's own ES256 key (distinct from `busbar_core::governance::signing`'s
//!   token signer; this plane never touches busbar's own resource-server signing material).
//! * [`testkit`] — the `TestAppOauthExt` extension trait, the plane's `busbar_core::test_support`
//!   fixture builder, kept here so busbar-core names no plane type in its own fixtures.
//!
//! `busbar_core::oauth_as::config` (`OauthAsCfg`/`AsIdentity`) STAYS in core — `DeployConfig` and
//! its validated twin embed those types by value for the single-document config pipeline, and
//! `config_validate::secret_refs` exhaustively destructures `AsIdentity`. Moving them here would
//! need core to name them back, which is the cycle Cargo refuses. See that module's doc for the
//! full rationale.
//!
//! ## The seam
//!
//! Core's `App::oauth_as` field, `router::base_data_router`'s mount call and `appbuild`'s plane
//! construction all go through `busbar_core::oauth_as::seam::AsPlaneSeam` — a small fn-pointer pair
//! (`build`/`mount`) rather than the full `PlaneDecl` vocabulary the CRUD-shaped planes (MCP/A2A)
//! use: `oauth_as` is a SINGLETON plane (no named-definition map, no scope-kind grants, no admin
//! CRUD verbs), so most of `PlaneDecl`'s fields would be fictions here. [`install`] registers this
//! crate's implementation of that seam; the composition root (`crates/busbar`'s `main`) calls it
//! once, unconditionally — `oauth_as` carries no feature flag, unlike MCP/A2A/voice, because
//! `oauth-as` (the underlying crate) is a normal dependency and costs nothing until configured.

pub mod cimd;
pub mod consent;
pub mod plane;
pub mod policy;
pub mod routes;
pub mod signer;
// `testkit` names `busbar_core::test_support::TestApp`, which only exists when core compiles with
// its own `test-support` feature (or under `cfg(test)`) — so this module is gated the same way, and
// a production build of this crate (the shipped binary's dependency) never reaches for it.
#[cfg(any(test, feature = "test-support"))]
pub mod testkit;

// `cimd`, `policy` and `signer` wire their own `tests/*_tests.rs` from inside themselves
// (`#[path = "tests/…"] mod …;`), unchanged by the move — the relative path from
// `src/{cimd,policy,signer}.rs` to `src/tests/*.rs` is the same shape it was inside
// `busbar-core/src/oauth_as/`. Only `mount_tests`/`flow_tests` were wired from the OLD `mod.rs`
// (they span the config lowering, `App::oauth_as` and the route table / the whole mount + consent
// + callback flow, so they were never one file's own test), so they are wired here instead, at the
// crate root — the direct analogue of the old `oauth_as/mod.rs` wiring.
#[cfg(test)]
#[path = "tests/mount_tests.rs"]
mod mount_tests;
#[cfg(test)]
#[path = "tests/flow_tests.rs"]
mod flow_tests;

/// Register this crate's implementation of the authorization-server plane seam
/// (`busbar_core::oauth_as::seam::AsPlaneSeam`) into busbar-core's process-wide registration slot.
///
/// Called EXACTLY ONCE, by the composition root (`crates/busbar`'s `main`), unconditionally and
/// before any config loads — mirroring `busbar_core::plane::registry::install_planes`'s discipline
/// for the same reason. `oauth_as:` carries no feature flag (it is a normal dependency, like the
/// underlying `oauth-as` crate always was), so every real build calls this.
pub fn install() {
    busbar_core::oauth_as::seam::install_as_plane_seam(busbar_core::oauth_as::seam::AsPlaneSeam {
        build: plane::seam_build,
        mount: routes::seam_mount,
    });
}
