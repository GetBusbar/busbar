// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/transport.rs`.

use super::*;

/// CONTRACT LOCK: the algorithmic mount prefix computed from JsonV1's version()/area() must be
/// byte-identical to `contract::ADMIN_PREFIX` — the constant the scope matrix, the rate-class
/// gate, and the OpenAPI doc all key on. A drift here would mount the surface at a path the
/// authorization matrix doesn't recognize.
#[test]
fn json_v1_mount_prefix_matches_contract_const() {
    let t = crate::admin::JsonV1;
    let computed = format!(
        "{}/{}/{}",
        crate::admin::v1::contract::API_ROOT,
        t.version(),
        t.area()
    );
    assert_eq!(computed, crate::admin::v1::contract::ADMIN_PREFIX);
}
