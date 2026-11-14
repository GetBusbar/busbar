// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Walk fixtures for tests in this crate and its dependents (`test-support`). A child of `select`
//! so it can read the request's deadline and the guard's arming. Never in a shipped build.

use super::{ProbeGuard, RequestCtx};

impl RequestCtx {
    /// How many whole seconds are left of the walk's deadline.
    #[must_use]
    pub fn remaining_secs(&self, now_secs: u64) -> u64 {
        self.deadline_secs.saturating_sub(now_secs)
    }
}

impl ProbeGuard<'_> {
    /// Whether the guard would still release on drop.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed
    }
}
