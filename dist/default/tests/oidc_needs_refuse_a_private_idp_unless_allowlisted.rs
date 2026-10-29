// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! THE PINNED OIDC PLUGIN'S EGRESS CLASSES (security item 3; security.md:169: "a provider upstream
//! or identity provider ... is refused when it is, or resolves to, a private ... address, unless
//! `allow_destinations` names it"): every outbound need the linked OIDC door states (discovery,
//! the JWKS, the token exchange), judged in the class the connector judges it in
//! (`guard::judged_class`: a default-class need whose config names its target is lifted to
//! operator infrastructure), is one the destination guard refuses a private address in unless
//! allowlisted, and none is operator infrastructure. The token exchange keeps a class that takes
//! the target's own scheme (1.5.5's http to an allowlisted private IdP token endpoint).
//! Supersedes `the_linked_oidc_plugins_needs_declare_operator_infrastructure` (the class that
//! admitted a private IdP with no allow entry; busbar-auth-oidc #59, #62).

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::rendering;
use busbar_core_connector::guard::{judged_class, PRIVATE_REFUSED_IN};

#[test]
fn the_linked_oidc_plugins_needs_refuse_a_private_idp_unless_allowlisted() {
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
    for (i, n) in outbound.iter().enumerate() {
        let judged = judged_class(n.egress_class, !n.target_from.is_empty());
        assert!(
            judged != EGRESS_OPERATOR_INFRASTRUCTURE && PRIVATE_REFUSED_IN.contains(&judged),
            "oidc need {i} (class {}, target_from {:?}) is judged in class {judged}, which admits \
             a private IdP address with no allow entry",
            n.egress_class,
            n.target_from
        );
    }
    let token = outbound
        .iter()
        .filter(|n| n.target_from.is_empty())
        .map(|n| n.egress_class)
        .filter(|c| *c != EGRESS_OPEN_WEB)
        .count();
    assert!(
        token > 0,
        "a token-exchange need takes its target's own scheme (not open-web): {:?}",
        read.needs
    );
}
