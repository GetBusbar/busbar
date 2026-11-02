// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Metrics setup for tests. The fixture retention window is long enough that observations do not
//! age out during assertions; the kernel owns only the explicit-duration recorder installation.

/// Install the real recorder using the shared test fixture's retention policy.
pub fn init() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
}
