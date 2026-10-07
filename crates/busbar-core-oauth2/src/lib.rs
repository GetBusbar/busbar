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
//! * [`signer`] — the plane's own ES256 key (distinct from `busbar_kernel::governance::signing`'s
//!   token signer; this plane never touches busbar's own resource-server signing material).
//! * [`testkit`] — the `TestAppOauthExt` extension trait, the plane's `busbar_kernel::test_support`
//!   fixture builder, kept here so busbar-core names no plane type in its own fixtures.
//!
//! * [`config`] — the `oauth_as:` block (`OauthAsCfg`/`AsIdentity`), its boot refusals and its
//!   secret-reference walk. The kernel carries the block as an OPAQUE value (`DeployCfg::oauth_as`)
//!   and hands it to this crate through the seam's `check` (parse, validate, list secret
//!   references) and `build`; it never names these types (ARCHITECT ruling 2026-10-03, D4).
//!
//! ## The seam
//!
//! Core's `App::oauth_as` field, `router::base_data_router`'s mount call and `appbuild`'s
//! construction all go through `busbar_kernel::oauth_as::seam::AsPlaneSeam` — a small fn-pointer
//! set (`check`/`build`/`mount`/`verify_dpop`) for a SINGLETON server: no named-definition map, no
//! scope-kind grants, no admin CRUD verbs. [`install`] registers this crate's implementation of
//! that seam; the composition root (`crates/busbar`'s `main`) calls it once, unconditionally —
//! `oauth_as` carries no feature flag, because `oauth-as` (the underlying crate) is a normal
//! dependency and costs nothing until configured.
//!
//! ## The connection table
//!
//! The one outbound fetch this crate makes (a Client ID Metadata Document, [`cimd`]) rides the
//! deployment's ONE root Connector (THE DESIGN §5), whose destination guard is the only check on
//! where it goes. The composition root names that table through [`Connections`], a type it hands
//! [`install`] as a parameter: the seam's `build` is instantiated over it, so the table reaches
//! every built server without a process-wide slot of this crate's own.

pub mod cimd;
pub mod config;
pub mod consent;
pub mod plane;
pub mod policy;
pub mod routes;
pub mod signer;
// `testkit` names `busbar_kernel::test_support::TestApp`, which only exists when core compiles with
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
#[path = "tests/config_tests.rs"]
mod config_tests;
#[cfg(test)]
#[path = "tests/fapi2_tests.rs"]
mod fapi2_tests;
#[cfg(test)]
#[path = "tests/flow_tests.rs"]
mod flow_tests;
#[cfg(test)]
#[path = "tests/mount_tests.rs"]
mod mount_tests;

/// THE CONNECTION TABLE THE COMPOSITION ROOT HANDS THIS CRATE: the root Connector's table, read
/// as the connection-table traits the contract defines, and the instance identity this crate's
/// needs are declared under on it. `None` = no table (a build with no connector): every outbound
/// fetch then fails closed.
pub trait Connections: 'static {
    /// The table, read at the moment a fetch needs it.
    fn table() -> Option<Table>;
}

/// One connection table as a fetch reaches it.
#[derive(Clone)]
pub struct Table {
    /// The identity this crate's needs are declared and opened under.
    pub owner: busbar_contract::conn::InstanceId,
    /// Where the needs are declared.
    pub declared: std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>,
    /// Where the connections are opened and read.
    pub conns: std::sync::Arc<dyn busbar_contract::conn::PollConns>,
}

/// The table of a build with no connector: none, so every outbound fetch fails closed.
pub struct NoConnections;

impl Connections for NoConnections {
    fn table() -> Option<Table> {
        None
    }
}

/// Register this crate's implementation of the authorization-server seam
/// (`busbar_kernel::oauth_as::seam::AsPlaneSeam`) into the kernel's process-wide registration slot,
/// every server it builds fetching over `C`'s connection table.
///
/// Called EXACTLY ONCE, by the composition root (`crates/busbar`'s `main`), unconditionally and
/// before any config loads — mirroring `busbar_kernel::plane::registry::install_planes`'s discipline
/// for the same reason. `oauth_as:` carries no feature flag (it is a normal dependency, like the
/// underlying `oauth-as` crate always was), so every real build calls this.
pub fn install<C: Connections>() {
    busbar_kernel::oauth_as::seam::install_as_plane_seam(
        busbar_kernel::oauth_as::seam::AsPlaneSeam {
            check: config::seam_check,
            build: plane::seam_build::<C>,
            mount: routes::seam_mount,
            verify_dpop: plane::seam_verify_dpop,
        },
    );
}
