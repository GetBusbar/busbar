// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn json_v1_mount_prefix_matches_contract_const() {
    let t = crate::v1::json::JsonV1;
    let computed = format!(
        "{}/{}/{}",
        crate::v1::contract::API_ROOT,
        t.version(),
        t.area()
    );
    assert_eq!(computed, crate::v1::contract::ADMIN_PREFIX);
}
