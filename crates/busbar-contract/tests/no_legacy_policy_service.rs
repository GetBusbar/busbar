// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The public host boundary has no retired commercial-policy service.

#[test]
fn the_public_host_boundary_has_no_retired_policy_service() {
    for (path, source) in [
        ("services.rs", include_str!("../src/services.rs")),
        (
            "abi/host/service.rs",
            include_str!("../src/abi/host/service.rs"),
        ),
        (
            "abi/host/access.rs",
            include_str!("../src/abi/host/access.rs"),
        ),
        (
            "abi/sdk/services.rs",
            include_str!("../src/abi/sdk/services.rs"),
        ),
        ("abi/sdk/conn.rs", include_str!("../src/abi/sdk/conn.rs")),
        (
            "busbar_plugin.h",
            include_str!("../include/busbar_plugin.h"),
        ),
        (
            "loader/dispatch/services.rs",
            include_str!("../../plugin-loader/src/dispatch/services.rs"),
        ),
    ] {
        for retired in [
            "entitlement_check",
            "EntitlementCheckIn",
            "ENTITLEMENT_CHECK",
            "ENTITLEMENT_STANDING",
        ] {
            assert!(!source.contains(retired), "{path} still exposes {retired}");
        }
    }
}
