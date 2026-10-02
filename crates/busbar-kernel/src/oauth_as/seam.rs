// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM core's own `router.rs`/`appbuild.rs` call through to reach the authorization-server
//! plane's runtime object and mount its routes, without naming `busbar_oauth2::plane::AsPlane` —
//! the reverse edge Cargo refuses (`busbar-oauth2` depends on `busbar-core`, never the other way).
//!
//! Registered once by the composition root (`crates/busbar`'s `main`), exactly the discipline
//! `plane::registry::install_planes` documents for the CRUD-shaped planes (MCP/A2A). `oauth_as` is
//! a SINGLETON plane — no named-definition map, no scope-kind grants, no admin CRUD verbs — so it
//! rides this small bespoke fn-pointer pair rather than the full `PlaneDecl` vocabulary, which was
//! built for a different shape of plane and would force several of its fields to fictions here.

use std::any::Any;
use std::sync::{Arc, OnceLock};

use super::config::AsIdentity;
use crate::core_routes::CoreRouter;

/// The plane's runtime-build entry point (the type of [`AsPlaneSeam::build`]), named as an alias so
/// the fn-pointer signature reads once here rather than inline in the struct field. Behaviour is
/// identical to the inline type; the alias exists only to keep the field legible (and satisfy
/// `clippy::type_complexity`).
type AsPlaneBuildFn =
    fn(&AsIdentity, Option<&str>, Vec<String>) -> Result<Arc<dyn Any + Send + Sync>, String>;

/// The two functions core calls through this seam. Every field type here is either core-owned
/// (`AsIdentity`, `CoreRouter`) or fully type-erased (`Arc<dyn Any + Send + Sync>`), so the seam
/// itself names no `busbar_oauth2` item.
pub struct AsPlaneSeam {
    /// Build the plane's runtime object for one config generation, from the VALIDATED identity
    /// (`busbar_kernel::oauth_as::config::AsIdentity` — stays in core; see the module doc on
    /// `crate::oauth_as`), the resolved signing-key material (`None` ⇒ an ephemeral key), and this
    /// deployment's protected-resource audiences (RFC 8707 `allowed_resources`). Also spawns the
    /// plane's own expired-record sweeper, mirroring what `appbuild.rs` did inline before the
    /// extraction — the seam owns the whole "how do I come alive" act, not just allocation.
    /// Returns the type-erased object `App::oauth_as` stores, or the plane's own build error
    /// rendered to a string (boot refuses with it exactly as it did when this call was inline).
    pub build: AsPlaneBuildFn,

    /// Mount the plane's routes onto the router, or return it untouched when `plane` is `None` —
    /// the zero-cost-when-off property at the routing layer, preserved unchanged by this move.
    /// `plane` is the SAME type-erased object [`Self::build`] returned; only the plane crate names
    /// its concrete type, so only it can downcast this back.
    pub mount: fn(CoreRouter, Option<&Arc<dyn Any + Send + Sync>>) -> CoreRouter,
}

static SEAM: OnceLock<AsPlaneSeam> = OnceLock::new();

/// Register the authorization-server plane's seam. Called EXACTLY ONCE, by the composition root
/// (`crates/busbar`'s `main`, alongside `plane::registry::install_planes`), before any config is
/// loaded. `oauth-as` is a NORMAL (always-linked, non-optional) dependency of the shipped binary —
/// unlike MCP/A2A/voice, `oauth_as:` carries no feature flag — so every real build registers this.
/// Only busbar-core's OWN test binary (`cargo test -p busbar-core`) never links `busbar-oauth2`
/// (linking it would be the forbidden reverse edge) and so never calls this; that binary also never
/// configures `oauth_as:` on any `App` it builds, so an unregistered seam and an always-`None` plane
/// agree with each other there.
///
/// # Panics
/// If called more than once — one composition root, one registration, the same discipline
/// `install_planes` documents for the identical reason.
pub fn install_as_plane_seam(seam: AsPlaneSeam) {
    assert!(
        SEAM.set(seam).is_ok(),
        "install_as_plane_seam called twice: there is one composition root, and it registers once"
    );
}

/// Read the registered seam, or `None` when this binary never linked `busbar-oauth2`.
pub(crate) fn seam() -> Option<&'static AsPlaneSeam> {
    SEAM.get()
}
