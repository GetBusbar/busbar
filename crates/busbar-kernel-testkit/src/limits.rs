// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INSTALL A LIMITS POSTURE PROCESS-WIDE FOR A TEST'S DURATION, AND ROLL IT BACK ON DROP unless
//! [`InstallGuard::commit`] is called.
//!
//! Production never installs through this: a configuration build reads its candidate's limits
//! through `busbar_kernel::config::limits::BuildScope`, and the live slot is written by `publish`
//! when the generation goes live. Tests that need a non-default posture in force process-wide (a
//! small body cap, a short handshake bound) use this, undone on drop. Serialize them with
//! `busbar_kernel::config::limits::LIMITS_TEST_LOCK`.

use busbar_kernel::config::limits::{swap_installed, LimitsResolved};

/// See the module doc.
#[must_use = "an uncommitted InstallGuard rolls the limits back when dropped"]
pub struct InstallGuard {
    /// What was installed before — `None` when nothing was (a test process).
    prior: Option<LimitsResolved>,
    committed: bool,
}

impl InstallGuard {
    /// Snapshot the currently-installed limits and install `resolved` in their place.
    pub fn install(resolved: &LimitsResolved) -> Self {
        Self {
            prior: swap_installed(Some(resolved.clone())),
            committed: false,
        }
    }

    /// KEEP the installed limits.
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
