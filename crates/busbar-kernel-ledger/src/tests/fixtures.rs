// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared props: the keys the batteries address the book by.

use crate::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

/// The ordinary key: a bucket, counted in money, over everything.
pub fn key(bucket: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}
