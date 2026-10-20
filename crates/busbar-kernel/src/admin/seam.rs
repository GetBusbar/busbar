// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM the kernel's own `router.rs` calls through to MOUNT the admin API service
//! (`/api/v1/admin/*`) without naming `busbar-core-admin`'s service type — the reverse edge Cargo
//! refuses (`busbar-core-admin` depends on `busbar-kernel`, never the other way).
//!
//! Registered once by the composition root (`crates/busbar`'s `main`), unconditionally — exactly the
//! discipline `oauth_as::seam`/`plane::registry::install_planes` document. `busbar-core-admin` is a
//! MANDATORY, always-linked (non-optional) dependency of the shipped binary, so every real build
//! registers this. Only the kernel's OWN test binary (`cargo test -p busbar-kernel`) never links
//! `busbar-core-admin` (linking it would be the forbidden reverse edge) and so never registers the
//! seam; that binary's `build_router` therefore produces a router WITHOUT the admin surface, which
//! is why every kernel test that drove `/api/v1/admin/*` lives in `busbar-core-admin` with the
//! service.

use std::any::Any;
use std::sync::{Arc, OnceLock};

use crate::state::{App, AppHandle};

/// The one function core calls through this seam: nest the admin API's routes onto `router` at its
/// computed `/api/v1/admin` prefix. Every type here is core-owned (`axum::Router`, `AppHandle`), so
/// the seam itself names no `busbar_core_admin` item.
pub struct AdminMountSeam {
    /// Mount the admin service's routes onto the router. `busbar-core-admin` supplies this; only it names
    /// its own `JsonV1` transport, so only it can build the nested router.
    pub mount: fn(axum::Router<Arc<AppHandle>>) -> axum::Router<Arc<AppHandle>>,
    /// Record the boot snapshot of `app` as the admin state's rollback floor (version 0).
    pub record_boot: fn(&App),
}

/// THE ONE FIELD `App` keeps for the admin side: an opaque, process-lifetime slot the admin service
/// types and fills on first use. Arc-shared across every config-apply snapshot, so what lives in it
/// (the config version history) survives each swap. The kernel names no admin type in it.
#[derive(Default)]
pub struct AdminSlot(OnceLock<Box<dyn Any + Send + Sync>>);

impl AdminSlot {
    /// The slot's value, made by `init` the first time. Every caller names the same `T` (the admin
    /// service's own state type), so the downcast cannot fail.
    pub fn get_or_init<T: Any + Send + Sync>(&self, init: impl FnOnce() -> T) -> &T {
        self.0
            .get_or_init(|| Box::new(init()))
            .downcast_ref::<T>()
            .expect("the admin slot holds one state type")
    }
}

impl std::fmt::Debug for AdminSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminSlot")
    }
}

/// Record `app`'s boot snapshot through the registered seam (a no-op in a binary that never linked
/// the admin service). The composition root and the test app builder both call it once.
pub fn record_boot(app: &App) {
    if let Some(seam) = SEAM.get() {
        (seam.record_boot)(app);
    }
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
/// binary never linked `busbar-core-admin` (only the kernel's own test binary). The
/// zero-cost-when-absent property at the routing layer, exactly as the pre-extraction direct `admin::transport::mount` call
/// produced when the surface was in-core.
pub(crate) fn mount_admin(router: axum::Router<Arc<AppHandle>>) -> axum::Router<Arc<AppHandle>> {
    match SEAM.get() {
        Some(seam) => (seam.mount)(router),
        None => router,
    }
}

/// THE CLOSED ADMIN VERB TABLE, as the kernel reads it: the per-verb allow-list's vocabulary
/// (#77(9), OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md` l.2279 — "Each verb is a plain scoped verb
/// authorized by the per-verb allow-list on the admin token").
///
/// The table is `busbar-core-admin`'s (the 66 pinned 1.5.5 operations and the 1.6.0 verbs, each
/// with its snake-case operation name), and the kernel cannot name it — the same reverse edge
/// [`AdminMountSeam`] exists for. So the admin service hands in two questions over it, registered
/// beside the mount by the same `install`: validation asks whether a `role_bindings.…verbs` name
/// is a verb (and which rung it needs), and the admin gate asks which verb a request line is.
#[derive(Clone, Copy)]
pub struct AdminVerbTable {
    /// The rung the operation NAMED this requires; `None` = the table declares no such operation.
    pub rung_of: fn(&str) -> Option<busbar_contract::authz::Scope>,
    /// The operation name a request line (method, path) resolves to; `None` = the table declares
    /// no such pair.
    pub verb_at: fn(&str, &str) -> Option<&'static str>,
}

static VERB_TABLE: OnceLock<AdminVerbTable> = OnceLock::new();

/// Register the closed admin verb table. Called by the admin service's `install`, beside
/// [`install_admin_mount_seam`]; FIRST-WINS, like it.
pub fn install_admin_verb_table(table: AdminVerbTable) {
    let _ = VERB_TABLE.set(table);
}

/// The rung the admin verb named `name` requires, or `None` when no table is registered or the
/// table declares no such verb. FAIL CLOSED: a name nothing can vouch for is no verb, so
/// validation refuses it and a grant never admits it.
pub fn admin_verb_rung(name: &str) -> Option<busbar_contract::authz::Scope> {
    VERB_TABLE.get().and_then(|t| (t.rung_of)(name))
}

/// The admin verb a request line names, or `None` when no table is registered or the table
/// declares no such pair — which no verb allow-list admits.
pub fn admin_verb_at(method: &str, path: &str) -> Option<&'static str> {
    VERB_TABLE.get().and_then(|t| (t.verb_at)(method, path))
}
