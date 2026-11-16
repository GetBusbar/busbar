// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use super::tests::base_deploy;
use super::*;

#[test]
fn the_destination_keys_parse_under_advanced() {
    let a: AdvancedCfg = busbar_contract::yaml::from_str(
        "block_private_addresses: false\nallow_destinations: [\x310.0.0.0/8, '*.corp.example']\n",
    )
    .expect("the destination keys are advanced keys");
    assert!(!a.block_private_addresses);
    assert_eq!(a.allow_destinations, ["\x310.0.0.0/8", "*.corp.example"]);
}

#[test]
fn private_addresses_are_blocked_by_default() {
    assert!(AdvancedCfg::default().block_private_addresses);
    let omitted: AdvancedCfg =
        busbar_contract::yaml::from_str("rate_sweep_interval: 256\n").expect("parses");
    assert!(omitted.block_private_addresses);
    let cfg = resolve(&base_deploy(), &HashMap::new()).expect("resolve");
    let d = cfg.destinations();
    assert!(d.block_private_addresses);
    assert!(d.allow.is_empty() && d.blocked.is_empty());
}

/// The one 1.5.5 security key that still feeds the guard is `blocked_metadata_hosts`; the retired
/// carve-outs never reach it (they are refused at validation, BUSBAR-3136).
#[test]
fn the_1_5_5_security_keys_feed_the_one_guard() {
    let mut deploy = base_deploy();
    deploy.advanced.allow_destinations = vec!["127.0.0.1".into()];
    deploy.security = Some(SecurityCfg {
        blocked_metadata_hosts: vec!["imds.corp.example".into()],
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
    });
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert_eq!(
        cfg.destinations(),
        Destinations {
            block_private_addresses: true,
            allow: vec!["127.0.0.1".into()],
            blocked: vec!["imds.corp.example".into()],
        }
    );
}
