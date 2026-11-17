// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests of items the verifier keeps private or test-gated; moved unchanged from the loader.
use super::*;

#[test]
fn rejected_display_carries_the_reason() {
    let r = Rejected::new(
        RejectKind::Unsigned,
        "manifest carries no signature".to_string(),
    );
    assert_eq!(
        r.to_string(),
        "plugin rejected: manifest carries no signature"
    );
}
