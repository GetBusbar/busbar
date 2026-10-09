// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! THE PINNED OIDC PLUGIN'S EGRESS CLASS: every outbound need the linked busbar-auth-oidc door
//! states (discovery, the JWKS, the token exchange) declares `operator-infrastructure`, the class
//! the oauth mint needs use (architect ruling 2026-10-09). Under it the connector admits http to a
//! private or loopback IdP's token endpoint, as 1.5.5's `vet_hop_url` did; the plugin keeps
//! discovery and the JWKS https-only itself. Under `open-web` (the pin before 4d9e8f4) the token
//! exchange to a plaintext private IdP is refused, which 1.5.5 never did.

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::rendering;

#[test]
fn the_linked_oidc_plugins_needs_declare_operator_infrastructure() {
    let stated = busbar_plugin_loader::dispatch::rendering_of(busbar_auth_oidc::door::door)
        .expect("the oidc door renders its Statement");
    let read = rendering::read(&stated).expect("its Statement reads back");
    let outbound: Vec<&rendering::ReadNeed> = read
        .needs
        .iter()
        .filter(|n| n.direction == DIRECTION_OUTBOUND)
        .collect();
    assert!(
        !outbound.is_empty(),
        "the oidc plugin states no outbound need: {:?}",
        read.needs
    );
    let other: Vec<(&str, u32)> = outbound
        .iter()
        .filter(|n| n.egress_class != EGRESS_OPERATOR_INFRASTRUCTURE)
        .map(|n| (n.transport.as_str(), n.egress_class))
        .collect();
    assert!(
        other.is_empty(),
        "every oidc need (the token exchange among them) must declare operator-infrastructure \
         ({EGRESS_OPERATOR_INFRASTRUCTURE}); these declare another class: {other:?}"
    );
}
