// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/billing.rs`.

use super::*;

#[test]
fn billing_variants_are_distinct() {
    assert_ne!(Billing::Flat, Billing::Characters { count: 0 });
    assert_ne!(
        Billing::Duration { seconds: 1.0 },
        Billing::Duration { seconds: 2.0 }
    );
}
