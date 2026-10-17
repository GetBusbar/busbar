// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/mod.rs`.

use super::{reject_overlong_id, KeyAudit, MAX_KEY_ID_LEN};

/// The bound is exact: an id of exactly `MAX_KEY_ID_LEN` chars is acceptable (`None`); one char
/// past it is rejected (`Some`). A mutated `>` → `>=` would reject the boundary length itself,
/// which a real minted id (`vk_` + 16 hex = 19 chars) never reaches but a caller passing exactly
/// the documented max legitimately could.
#[test]
fn id_length_boundary_is_exact() {
    let at_max = "a".repeat(MAX_KEY_ID_LEN);
    assert!(
        reject_overlong_id(KeyAudit::Read, &at_max).is_none(),
        "an id of exactly MAX_KEY_ID_LEN chars must be accepted"
    );

    let over_max = "a".repeat(MAX_KEY_ID_LEN + 1);
    assert!(
        reject_overlong_id(KeyAudit::Read, &over_max).is_some(),
        "an id one char past MAX_KEY_ID_LEN must be rejected"
    );
}
