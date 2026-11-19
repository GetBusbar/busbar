// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use super::tests::base_deploy;
use super::*;

#[test]
fn the_destination_keys_parse_under_advanced() {
    let a: AdvancedCfg = busbar_contract::yaml::from_str("block_private_addresses: false\n")
        .expect("the destination keys are advanced keys");
    assert!(!a.block_private_addresses);
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
    assert!(d.blocked.is_empty());
}

/// The one 1.5.5 security key that still feeds the guard is `blocked_metadata_hosts`; the retired
/// carve-outs never reach it (they are refused at validation, BUSBAR-3136).
#[test]
fn the_1_5_5_security_keys_feed_the_one_guard() {
    let mut deploy = base_deploy();
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
            blocked: vec!["imds.corp.example".into()],
            listens: vec![
                crate::config::DEFAULT_LISTEN_ADDR.into(),
                crate::config::DEFAULT_ADMIN_LISTEN_ADDR.into(),
            ],
        }
    );
}

/// UPSTREAMS-DECLARED r3 section 2.4 removes the global destination grant.
#[test]
fn allow_destinations_is_refused_as_an_unknown_key() {
    for yaml in [
        "allow_destinations: [127.0.0.1]\n",
        "allow_destinations: []\n",
    ] {
        let err = busbar_contract::yaml::from_str::<AdvancedCfg>(yaml)
            .expect_err("the deleted advanced key is refused")
            .to_string();
        assert!(err.contains("unknown field"), "{yaml}: {err}");
    }
}

#[test]
fn allow_destinations_is_refused_by_the_settings_patch() {
    let err = busbar_contract::yaml::from_str::<crate::config::patch::AdvancedPatch>(
        "allow_destinations: [127.0.0.1]\n",
    )
    .expect_err("the settings door refuses the deleted advanced key")
    .to_string();
    assert!(err.contains("unknown field"), "{err}");
}
