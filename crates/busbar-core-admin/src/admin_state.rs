// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin side's process-lifetime state, held on `App` behind the admin seam's ONE slot
//! ([`busbar_kernel::admin::seam::AdminSlot`]). The kernel names no type here: the slot is opaque to
//! it, shared (Arc) across every config-apply snapshot so the history survives each swap, and typed
//! only by this crate.

use busbar_kernel::state::App;

use crate::versions::VersionLog;

/// Everything the admin API keeps on the process: today the config version history.
#[derive(Default)]
pub struct AdminState {
    pub versions: VersionLog,
}

/// The admin accessors on `App`: the state, and the version-history record every config-plane
/// mutation makes.
pub trait AppAdmin {
    fn admin_state(&self) -> &AdminState;
    fn versions(&self) -> &VersionLog {
        &self.admin_state().versions
    }
    /// Record this app's own hook-surface snapshot as `version`.
    fn record_version_at(&self, version: u64, principal: &str, summary: &str);
    /// Record this app's snapshot at its own `config_version`.
    fn record_version(&self, principal: &str, summary: &str);
}

impl AppAdmin for App {
    fn admin_state(&self) -> &AdminState {
        self.admin.get_or_init(AdminState::default)
    }

    fn record_version_at(&self, version: u64, principal: &str, summary: &str) {
        let snapshot = serde_json::to_value(&self.hook_registry).unwrap_or(serde_json::Value::Null);
        self.versions()
            .record(version, principal, summary, snapshot, &self.global_hooks);
    }

    fn record_version(&self, principal: &str, summary: &str) {
        self.record_version_at(self.config_version, principal, summary);
    }
}
