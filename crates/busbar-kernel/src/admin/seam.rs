// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM core's own `router.rs` calls through to MOUNT the admin API service (`/api/v1/admin/*`)
//! without naming `busbar_admin::v1::json::JsonV1` — the reverse edge Cargo refuses (`busbar-admin`
//! depends on `busbar-core`, never the other way).
//!
//! Registered once by the composition root (`crates/busbar`'s `main`), unconditionally — exactly the
//! discipline `oauth_as::seam`/`plane::registry::install_planes` document. `busbar-admin` is a
//! MANDATORY, always-linked (non-optional) dependency of the shipped binary, so every real build
//! registers this. Only busbar-core's OWN test binary (`cargo test -p busbar-core`) never links
//! `busbar-admin` (linking it would be the forbidden reverse edge) and so never registers the seam;
//! that binary's `build_router` therefore produces a router WITHOUT the admin surface, which is why
//! every busbar-core test that drove `/api/v1/admin/*` was moved to `busbar-admin` with the service.

use std::sync::{Arc, OnceLock};

use crate::state::AppHandle;

/// The one function core calls through this seam: nest the admin API's routes onto `router` at its
/// computed `/api/v1/admin` prefix. Every type here is core-owned (`axum::Router`, `AppHandle`), so
/// the seam itself names no `busbar_admin` item.
pub struct AdminMountSeam {
    /// Mount the admin service's routes onto the router. `busbar-admin` supplies this; only it names
    /// its own `JsonV1` transport, so only it can build the nested router.
    pub mount: fn(axum::Router<Arc<AppHandle>>) -> axum::Router<Arc<AppHandle>>,
}

static SEAM: OnceLock<AdminMountSeam> = OnceLock::new();

/// Register the admin-service mount seam. Called by the composition root (`crates/busbar`'s `main`)
/// before any router is built, and by integration/unit tests that build the admin surface without a
/// composition root. FIRST-WINS and idempotent: re-registering the same mount is harmless, and a test
/// binary with several tests (or a test plus a stray composition-root call) must not fault on the
/// second registration.
pub fn install_admin_mount_seam(seam: AdminMountSeam) {
    let _ = SEAM.set(seam);
}

/// Mount the admin surface through the registered seam, or return `router` UNTOUCHED when this
/// binary never linked `busbar-admin` (only busbar-core's own test binary). The zero-cost-when-absent
/// property at the routing layer, exactly as the pre-extraction direct `admin::transport::mount` call
/// produced when the surface was in-core.
pub(crate) fn mount_admin(router: axum::Router<Arc<AppHandle>>) -> axum::Router<Arc<AppHandle>> {
    match SEAM.get() {
        Some(seam) => (seam.mount)(router),
        None => router,
    }
}
