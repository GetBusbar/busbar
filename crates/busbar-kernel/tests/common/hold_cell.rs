// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{Hold, HoldCell};
use busbar_kernel::teller::Kernel;

use super::principal::principal;

pub fn cell(kernel: &Kernel) -> HoldCell {
    HoldCell::new(Hold::open(&kernel.admit_token(), principal()))
}
