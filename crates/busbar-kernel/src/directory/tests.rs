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

// C-PROVISION two-replica arm (FU5 (a), IF §12.29 "The hold"): two replicas are two directories built over one
// store. `held_ns` in the store is the truth; the writing replica swaps locally before its Need answers; the
// other replica holds the principal within `refresh_ms` plus one rescan, with no write of its own.
mod two_replicas {
    use std::sync::Arc;
    use std::time::Duration;

    use busbar_contract::Secret;

    use super::super::store::{self, Committed, Tx, HELD};
    use super::super::{KernelDirectory, LogEvents, ProvisioningInstance};
    use super::cfg;

    const INBOUND: u64 = 7;

    async fn replica(store: &Arc<crate::persistence::facade::CoreStore>) -> super::super::Holds {
        let spec = ProvisioningInstance {
            plugin: "scim".into(),
            name: "scim".into(),
            cfg: {
                let mut c = cfg();
                if let Some(link) = c.link.as_mut() {
                    link.refresh_ms = 20;
                }
                c
            },
            link_auth_ids: vec![INBOUND],
        };
        let (_dir, holds) =
            KernelDirectory::build(Arc::clone(store), Arc::new(LogEvents), vec![spec])
                .await
                .expect("the replica loads its (empty) hold set");
        holds
    }

    fn holds(h: &super::super::Holds, principal: &str) -> bool {
        h.for_inbound(INBOUND)
            .is_some_and(|sets| sets.iter().any(|s| s.holds(principal)))
    }

    async fn commit_held(store: &Arc<crate::persistence::facade::CoreStore>, principal: &str) {
        let scope = store::scope(store, "scim", "scim").expect("scope");
        let mut tx = Tx::new(&scope);
        tx.put(
            HELD,
            principal.as_bytes().to_vec(),
            Secret::new(b"subject-1".to_vec()),
        );
        assert!(matches!(tx.commit(store).await, Ok(Committed::Applied)));
    }

    #[tokio::test]
    async fn the_other_replica_holds_within_the_refresh_bound() {
        let store = crate::real_store::core().await;
        let a = replica(&store).await;
        let b = replica(&store).await;
        assert!(!holds(&a, "ann") && !holds(&b, "ann"));

        commit_held(&store, "ann").await;
        // The writing replica swaps locally before its answer.
        if let Some(sets) = a.for_inbound(INBOUND) {
            for s in sets {
                s.local("ann", true);
            }
        }
        assert!(holds(&a, "ann"), "the writer holds at once");

        let mut seen = false;
        for _ in 0..200 {
            if holds(&b, "ann") {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(seen, "the other replica never saw the committed hold");
        assert!(!holds(&b, "bob"));
    }
}
