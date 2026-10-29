// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared props: a small deterministic source of pseudo-random numbers.
//!
//! The generator is a plain linear congruential one, written out rather than pulled in, for two
//! reasons. A random test that cannot be replayed from its seed is a test that fails once and is
//! then muted; and a crate whose entire dependency list is the capability crate should not grow a
//! second one to shuffle some integers.

/// A replayable pseudo-random source.
pub struct Rng(u64);

impl Rng {
    /// Seed it. The same seed always produces the same run, so a failure is reproducible from the
    /// number printed in the message.
    pub fn seeded(seed: u64) -> Self {
        Rng(seed | 1)
    }

    /// The next value.
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    /// A value below `bound`.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next() % bound
        }
    }
}
