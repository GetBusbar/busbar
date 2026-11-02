// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::VirtualKey;
use std::collections::HashSet;

fn push_key(keys: &mut Vec<VirtualKey>, name: &str, group: Option<&str>) -> VirtualKey {
    let key = VirtualKey {
        id: name.into(),
        name: name.into(),
        enabled: true,
        group: group.map(str::to_string),
        ..Default::default()
    };
    keys.push(key.clone());
    key
}

#[test]
fn zero_cap_is_unlimited_and_under_cap_admits() {
    let mut g = Vec::new();
    for i in 0..5 {
        push_key(&mut g, &format!("k{i}"), Some("team"));
    }
    assert!(super::check_key_cap_for_keys(&g, 0, Some("team"), None, |_| false).is_none());
    assert!(super::check_key_cap_for_keys(&g, 6, Some("team"), None, |_| false).is_none());
    let hit = super::check_key_cap_for_keys(&g, 5, Some("team"), None, |_| false).expect("at cap");
    assert_eq!(hit, ("team".to_string(), 5));
}

#[test]
fn revoked_and_disabled_keys_do_not_hold_a_cap_slot() {
    let mut g = Vec::new();
    let mut revoked = HashSet::new();
    let a = push_key(&mut g, "a", Some("team"));
    let b = push_key(&mut g, "b", Some("team"));
    push_key(&mut g, "c", Some("team"));
    assert!(
        super::check_key_cap_for_keys(&g, 3, Some("team"), None, |id| revoked.contains(id))
            .is_some(),
        "three live keys fill a cap of 3"
    );

    revoked.insert(a.id.clone());
    assert!(
        super::check_key_cap_for_keys(&g, 3, Some("team"), None, |id| revoked.contains(id))
            .is_none(),
        "a revoked key must not hold a cap slot forever"
    );

    g.iter_mut().find(|key| key.id == b.id).unwrap().enabled = false;
    assert!(
        super::check_key_cap_for_keys(&g, 2, Some("team"), None, |id| revoked.contains(id))
            .is_none(),
        "a disabled key must not hold a cap slot"
    );
}

#[test]
fn the_unbound_bucket_is_counted_too() {
    let mut g = Vec::new();
    push_key(&mut g, "a", None);
    push_key(&mut g, "b", None);
    let hit = super::check_key_cap_for_keys(&g, 2, None, None, |_| false)
        .expect("the no-group bucket is capped");
    assert_eq!(hit, (super::UNBOUND_BUCKET_LABEL.to_string(), 2));

    push_key(&mut g, "c", Some("team"));
    assert_eq!(
        super::check_key_cap_for_keys(&g, 2, None, None, |_| false),
        Some((super::UNBOUND_BUCKET_LABEL.to_string(), 2)),
        "buckets are independent"
    );
}

#[test]
fn rebind_excludes_the_mover_but_still_refuses_a_full_target() {
    let mut g = Vec::new();
    let a = push_key(&mut g, "a", Some("team"));
    push_key(&mut g, "b", Some("team"));

    assert!(
        super::check_key_cap_for_keys(&g, 2, Some("team"), Some(&a.id), |_| false).is_none(),
        "a no-op rebind of an at-cap bucket onto itself must not 409"
    );

    let outsider = push_key(&mut g, "c", None);
    assert!(
        super::check_key_cap_for_keys(&g, 2, Some("team"), Some(&outsider.id), |_| false).is_some(),
        "a rebind must not walk a principal past its ceiling"
    );
}
