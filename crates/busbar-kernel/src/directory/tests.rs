// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::min3::{ProvisioningCfg, ProvisioningGuard, ProvisioningLink};

use super::holds::{empty, Held};
use super::{check_provisioning, HoldSet, ProvisioningFacts};

fn cfg() -> ProvisioningCfg {
    ProvisioningCfg {
        clients: vec!["scim-client".into()],
        link: Some(ProvisioningLink {
            index: "email".into(),
            auth: vec!["oidc".into()],
            refresh_ms: 1000,
        }),
        guard: ProvisioningGuard {
            max: 10,
            window_s: 3600,
        },
    }
}

const OK: ProvisioningFacts = ProvisioningFacts {
    fb_provision: true,
    verifies: true,
};

fn held(of: &[&str]) -> Held {
    let mut set = empty();
    for p in of {
        set.insert((*p).into());
    }
    set
}

#[test]
fn a_well_formed_block_is_accepted() {
    assert!(check_provisioning("scim", &cfg(), OK, &|n| n == "oidc").is_ok());
}

#[test]
fn every_refusal_names_the_instance_and_the_key() {
    let mut bad = cfg();
    bad.clients.clear();
    bad.guard.max = 0;
    bad.guard.window_s = 1;
    if let Some(link) = bad.link.as_mut() {
        link.refresh_ms = 5;
        link.auth = vec!["nope".into()];
    }
    let facts = ProvisioningFacts {
        fb_provision: false,
        verifies: false,
    };
    let refused = check_provisioning("scim", &bad, facts, &|_| false).unwrap_err();
    for key in [
        "auth.scim.provisioning:",
        "auth.scim.provisioning.clients",
        "auth.scim.provisioning.link.refresh_ms",
        "auth.scim.provisioning.link.auth[0]",
        "auth.scim.provisioning.guard.max",
        "auth.scim.provisioning.guard.window_s",
    ] {
        assert!(
            refused.iter().any(|r| r.starts_with(key)),
            "{key}: {refused:?}"
        );
    }
}

#[test]
fn the_guard_has_no_off_switch() {
    let mut bad = cfg();
    bad.guard.max = 0;
    assert!(check_provisioning("scim", &bad, OK, &|_| true).is_err());
}

#[test]
fn holds_answers_from_the_snapshot() {
    let set = HoldSet::new(held(&["ann"]), 1);
    assert!(set.holds("ann"));
    assert!(!set.holds("bob"));
}

#[test]
fn an_empty_set_holds_nobody() {
    let set = HoldSet::new(empty(), 1);
    assert!(!set.holds("ann"));
}

#[test]
fn a_local_write_is_visible_before_the_need_answers() {
    let set = HoldSet::new(empty(), 1);
    set.local("ann", true);
    assert!(set.holds("ann"));
    set.local("ann", false);
    assert!(!set.holds("ann"));
    assert_eq!(set.len(), 0);
}

#[test]
fn a_swap_replaces_the_snapshot() {
    let set = HoldSet::new(held(&["ann"]), 1);
    set.swap(held(&["bob"]));
    assert!(!set.holds("ann"));
    assert!(set.holds("bob"));
}
