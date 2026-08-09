// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/admin/mod.rs`.

use super::{validate_mint_labels, MAX_LABEL_COUNT};

/// The count boundary is exact: `MAX_LABEL_COUNT` labels is fine; one more is rejected. A
/// mutated `>` → `>=` would reject the boundary count itself as "too many".
#[test]
fn label_count_boundary_is_exact() {
    let at_cap: std::collections::BTreeMap<String, String> = (0..MAX_LABEL_COUNT)
        .map(|i| (format!("l{i}"), "v".to_string()))
        .collect();
    assert!(
        validate_mint_labels(&at_cap).is_ok(),
        "exactly MAX_LABEL_COUNT labels must be accepted"
    );

    let mut over_cap = at_cap;
    over_cap.insert("one_more".to_string(), "v".to_string());
    assert!(
        validate_mint_labels(&over_cap).is_err(),
        "MAX_LABEL_COUNT + 1 labels must be rejected"
    );
}
