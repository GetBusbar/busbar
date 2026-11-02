// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The attempt's one bound the walk owns: the cap on time to the first answer.

/// The per-attempt cap on time to the first answer, floored by what the walk has left

#[must_use]
pub fn attempt_cap_ms(ms: u64, remaining_ms: u64) -> u64 {
    ms.min(remaining_ms.max(1))
}

#[cfg(test)]
#[path = "tests/attempt_tests.rs"]
mod attempt_tests;
