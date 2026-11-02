// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::governance::{GovState, NewKeySpec};

use busbar_kernel_testkit::test_support::governance::GovStateFixtures;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use std::sync::Arc;

fn gov() -> Arc<GovState> {
    Arc::new(GovState::new(Arc::new(MemoryStore::new()), Some("t".into())).unwrap())
}

fn mint(gov: &GovState, name: &str, group: Option<&str>) -> busbar_kernel::governance::VirtualKey {
    gov.create_key(
        NewKeySpec {
            name: name.into(),
            allowed_pools: None,
            group: group.map(str::to_string),
            labels: Default::default(),
            ..Default::default()
        },
        0,
    )
    .expect("mint")
    .0
}

#[test]
fn zero_cap_is_unlimited_and_under_cap_admits() {
    let g = gov();
    for i in 0..5 {
        mint(&g, &format!("k{i}"), Some("team"));
    }
    assert!(super::check_key_cap(&g, 0, Some("team"), None)
        .unwrap()
        .is_none());
    assert!(super::check_key_cap(&g, 6, Some("team"), None)
        .unwrap()
        .is_none());
    let hit = super::check_key_cap(&g, 5, Some("team"), None)
        .unwrap()
        .expect("at cap");
    assert_eq!(hit, ("team".to_string(), 5));
}

#[test]
fn revoked_and_disabled_keys_do_not_hold_a_cap_slot() {
    let g = gov();
    let a = mint(&g, "a", Some("team"));
    let b = mint(&g, "b", Some("team"));
    mint(&g, "c", Some("team"));
    assert!(
        super::check_key_cap(&g, 3, Some("team"), None)
            .unwrap()
            .is_some(),
        "three live keys fill a cap of 3"
    );

    g.revoke(&a.id, "test").expect("revoke");
    assert!(
        super::check_key_cap(&g, 3, Some("team"), None)
            .unwrap()
            .is_none(),
        "a revoked key must not hold a cap slot forever"
    );

    g.update_key(&b.id, Some(false), None).expect("disable");
    assert!(
        super::check_key_cap(&g, 2, Some("team"), None)
            .unwrap()
            .is_none(),
        "a disabled key must not hold a cap slot"
    );
}

#[test]
fn the_unbound_bucket_is_counted_too() {
    let g = gov();
    mint(&g, "a", None);
    mint(&g, "b", None);
    let hit = super::check_key_cap(&g, 2, None, None)
        .unwrap()
        .expect("the no-group bucket is capped");
    assert_eq!(hit, (super::UNBOUND_BUCKET_LABEL.to_string(), 2));

    mint(&g, "c", Some("team"));
    assert_eq!(
        super::check_key_cap(&g, 2, None, None).unwrap(),
        Some((super::UNBOUND_BUCKET_LABEL.to_string(), 2)),
        "buckets are independent"
    );
}

#[test]
fn rebind_excludes_the_mover_but_still_refuses_a_full_target() {
    let g = gov();
    let a = mint(&g, "a", Some("team"));
    mint(&g, "b", Some("team"));

    assert!(
        super::check_key_cap(&g, 2, Some("team"), Some(&a.id))
            .unwrap()
            .is_none(),
        "a no-op rebind of an at-cap bucket onto itself must not 409"
    );

    let outsider = mint(&g, "c", None);
    assert!(
        super::check_key_cap(&g, 2, Some("team"), Some(&outsider.id))
            .unwrap()
            .is_some(),
        "a rebind must not walk a principal past its ceiling"
    );
}
