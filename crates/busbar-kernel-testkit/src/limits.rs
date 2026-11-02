// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::limits::{swap_installed, LimitsResolved};

#[must_use = "an uncommitted InstallGuard rolls the limits back when dropped"]
pub struct InstallGuard {
    prior: Option<LimitsResolved>,
    committed: bool,
}

impl InstallGuard {
    pub fn install(resolved: &LimitsResolved) -> Self {
        Self {
            prior: swap_installed(Some(resolved.clone())),
            committed: false,
        }
    }

    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        if !self.committed {
            swap_installed(self.prior.take());
        }
    }
}

pub static LIMITS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
