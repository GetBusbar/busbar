// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn init() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
}
