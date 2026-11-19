// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn plane_supported_abi_is_the_plane_kinds_one_version() {
    assert_eq!(
        crate::registry::supported_abi("plane"),
        Some(busbar_plugin_abi::versions::PLANE)
    );
    assert!(crate::registry::supported_abi("store").is_some());
    assert_eq!(crate::registry::supported_abi("nonsense"), None);
}
