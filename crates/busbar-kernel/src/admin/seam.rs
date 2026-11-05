// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::sync::{Arc, OnceLock};

use crate::state::{App, AppHandle};

pub struct AdminMountSeam {
    pub mount: fn(axum::Router<Arc<AppHandle>>) -> axum::Router<Arc<AppHandle>>,

    pub record_boot: fn(&App),
}

/// THE ONE FIELD `App` keeps for the admin side: an opaque, process-lifetime slot the admin service
/// types and fills on first use. Arc-shared across every config-apply snapshot, so what lives in it
/// (the config version history) survives each swap. The kernel names no admin type in it.
#[derive(Default)]
pub struct AdminSlot(OnceLock<Box<dyn Any + Send + Sync>>);

impl AdminSlot {
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

pub fn record_boot(app: &App) {
    if let Some(seam) = SEAM.get() {
        (seam.record_boot)(app);
    }
}

static SEAM: OnceLock<AdminMountSeam> = OnceLock::new();

pub fn install_admin_mount_seam(seam: AdminMountSeam) {
    let _ = SEAM.set(seam);
}

pub(crate) fn mount_admin(router: axum::Router<Arc<AppHandle>>) -> axum::Router<Arc<AppHandle>> {
    match SEAM.get() {
        Some(seam) => (seam.mount)(router),
        None => router,
    }
}

/// THE CLOSED ADMIN VERB TABLE, as the kernel reads it: the per-verb allow-list's vocabulary
/// Each verb is authorized by the per-verb allow-list on the admin token.
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

pub fn install_admin_verb_table(table: AdminVerbTable) {
    let _ = VERB_TABLE.set(table);
}

pub fn admin_verb_rung(name: &str) -> Option<busbar_contract::authz::Scope> {
    VERB_TABLE.get().and_then(|t| (t.rung_of)(name))
}

pub fn admin_verb_at(method: &str, path: &str) -> Option<&'static str> {
    VERB_TABLE.get().and_then(|t| (t.verb_at)(method, path))
}
