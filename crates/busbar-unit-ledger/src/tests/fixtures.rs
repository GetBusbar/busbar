// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared props: tokens, keys, and a small deterministic source of pseudo-random numbers.
//!
//! The generator is a plain linear congruential one, written out rather than pulled in, for two
//! reasons. A random test that cannot be replayed from its seed is a test that fails once and is
//! then muted; and a crate whose entire dependency list is the capability crate should not grow a
//! second one to shuffle some integers.

use busbar_caps::{
    Admit, AdmitToken, Hold, KernelSeal, LedgerToken, MeterClassId, Principal, Usage, UsageLine,
    UsageToken,
};

use crate::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

/// An admission token.
pub fn admit_token() -> AdmitToken<Admit> {
    AdmitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// A ledger token.
pub fn ledger_token() -> LedgerToken {
    LedgerToken::mint(&KernelSeal::acquire_for_kernel())
}

/// A usage token.
pub fn usage_token() -> UsageToken {
    UsageToken::mint(&KernelSeal::acquire_for_kernel())
}

/// A hold for `who`, reserving `reserved`.
pub fn hold(who: &str, reserved: u64) -> Hold {
    Hold::open(&admit_token(), Principal::new(who), reserved)
}

/// A usage report of one line.
pub fn usage(class: &str, quantity: u64) -> Usage {
    Usage::report(
        &usage_token(),
        vec![UsageLine {
            class: MeterClassId::new(class),
            quantity,
        }],
    )
    .unwrap()
}

/// The ordinary key: a bucket, counted in money, over everything.
pub fn key(bucket: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// A key narrowed to a pool.
pub fn pool_key(bucket: &str, pool: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::Pool(pool.to_string()),
    )
}

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
