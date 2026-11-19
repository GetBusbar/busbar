// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// The off-path half (the configuration projection, the kernel sections, the root's rules).
pub(crate) use crate::root::off_path::door_steps::*;

#[cfg(test)]
#[path = "tests/door_steps.rs"]
pub(crate) mod tests;
