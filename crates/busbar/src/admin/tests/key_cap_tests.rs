// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/admin/mod.rs`.

use crate::governance::{GovState, MemoryStore, NewKeySpec};
use std::sync::Arc;

fn gov() -> Arc<GovState> {
    Arc::new(GovState::new(Arc::new(MemoryStore::new()), Some("t".into())).unwrap())
}

fn mint(gov: &GovState, name: &str, group: Option<&str>) -> crate::governance::VirtualKey {
    gov.create_key(
        NewKeySpec {
            name: name.into(),
            allowed_pools: None,
            group: group.map(str::to_string),
            labels: Default::default(),
        },
        0,
    )
    .expect("mint")
    .0
}

/// `cap == 0` is unlimited, and a bucket under its ceiling admits.
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

/// The cap counts LIVE keys only. A revoked or disabled key holds no usable credential, so
/// counting it forever made the ceiling a ONE-WAY RATCHET — and made the rejection's own advice
/// ("revoke or delete an existing key") false for `revoke`.
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

    // REVOKE one: its credential is dead, so its slot must come back.
    g.revoke(&a.id, "test").expect("revoke");
    assert!(
        super::check_key_cap(&g, 3, Some("team"), None)
            .unwrap()
            .is_none(),
        "a revoked key must not hold a cap slot forever"
    );

    // DISABLE another: same reasoning.
    g.update_key(&b.id, Some(false), None).expect("disable");
    assert!(
        super::check_key_cap(&g, 2, Some("team"), None)
            .unwrap()
            .is_none(),
        "a disabled key must not hold a cap slot"
    );
}

/// The UNBOUND bucket is capped too. A groupless key escapes the limit tree entirely, so
/// exempting it from the key-count ceiling made the ceiling evadable by omitting one field.
#[test]
fn the_unbound_bucket_is_counted_too() {
    let g = gov();
    mint(&g, "a", None);
    mint(&g, "b", None);
    let hit = super::check_key_cap(&g, 2, None, None)
        .unwrap()
        .expect("the no-group bucket is capped");
    assert_eq!(hit, (super::UNBOUND_BUCKET_LABEL.to_string(), 2));
    // Bound keys live in their own bucket and do not spend the unbound one's slots.
    mint(&g, "c", Some("team"));
    assert_eq!(
        super::check_key_cap(&g, 2, None, None).unwrap(),
        Some((super::UNBOUND_BUCKET_LABEL.to_string(), 2)),
        "buckets are independent"
    );
}

/// The REBIND path excludes the key being MOVED, so re-PATCHing a key onto the group it
/// is already bound to is not spuriously refused — while a genuine move into a full bucket is.
#[test]
fn rebind_excludes_the_mover_but_still_refuses_a_full_target() {
    let g = gov();
    let a = mint(&g, "a", Some("team"));
    mint(&g, "b", Some("team"));
    // `a` re-bound onto its OWN group: excluding the mover leaves 1 < 2, so it admits.
    assert!(
        super::check_key_cap(&g, 2, Some("team"), Some(&a.id))
            .unwrap()
            .is_none(),
        "a no-op rebind of an at-cap bucket onto itself must not 409"
    );
    // A key from elsewhere moving IN sees 2 >= 2 and is refused.
    let outsider = mint(&g, "c", None);
    assert!(
        super::check_key_cap(&g, 2, Some("team"), Some(&outsider.id))
            .unwrap()
            .is_some(),
        "a rebind must not walk a principal past its ceiling"
    );
}
