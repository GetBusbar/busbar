// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::host_records::tests::{attach, Backend};
use std::sync::atomic::Ordering;

fn candidate(version: &str, rollback_pinned: bool) -> Candidate<'_> {
    Candidate {
        name: "plugin",
        version,
        file: "plugin.so",
        first_party: true,
        linked: false,
        rollback_pinned,
    }
}

#[tokio::test]
async fn floors_remain_monotonic_and_prepared_admission_names_one_exact_archive() {
    let backend = Arc::new(Backend::default());
    let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    owner
        .enforce_candidate("host", candidate("2.0.0", false), true)
        .await
        .unwrap();
    owner
        .enforce_candidate("host", candidate("1.0.0", true), true)
        .await
        .unwrap();
    assert!(owner
        .enforce_candidate("host", candidate("1.0.0", false), false)
        .await
        .is_err());
    owner
        .enforce_release_keys("host", &[42], true)
        .await
        .unwrap();
    assert!(owner
        .enforce_release_keys("host", &[41], false)
        .await
        .is_err());
    let archive = "a".repeat(64);
    let proof = owner
        .prepare_admission("host", candidate("2.0.0", false), Some(42), &archive)
        .await
        .unwrap();
    assert_eq!(proof.release_keys_floor(), 42);
    assert!(proof
        .scope_generations()
        .iter()
        .all(|generation| *generation > 0));
    proof
        .check("host", candidate("2.0.0", false), Some(42), &archive)
        .unwrap();
    assert!(proof
        .check("host", candidate("2.0.0", false), Some(42), &"b".repeat(64))
        .is_err());
    assert!(proof
        .check("host", candidate("1.0.0", true), Some(42), &archive)
        .is_err());
}

#[tokio::test]
async fn cancelled_raise_is_confirmed_before_a_later_lower_candidate_is_checked() {
    let backend = Arc::new(Backend::default());
    let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
    backend.hang.store(true, Ordering::SeqCst);
    {
        let write = owner.enforce_candidate("host", candidate("3.0.0", false), true);
        tokio::pin!(write);
        assert!(futures::poll!(&mut write).is_pending());
    }
    backend.hang.store(false, Ordering::SeqCst);
    assert!(owner
        .enforce_candidate("host", candidate("2.0.0", false), true)
        .await
        .is_err());
    owner
        .prepare_admission("host", candidate("3.0.0", false), None, &"a".repeat(64))
        .await
        .unwrap();
}

#[test]
fn decimal_version_order_preserves_large_components_and_legacy_suffix_semantics() {
    assert!(version_at_least(
        "184467440737095516160.0.0",
        "184467440737095516159.9.9"
    ));
    // DES-359 r3 L11 (PM ruling 2026-11-17): a pre-release sorts below its release.
    assert!(!version_at_least("01.002.0003-beta", "1.2.3+build"));
    assert!(version_at_least("01.002.0003+other", "1.2.3+build"));
    assert!(!version_at_least("1.2.2", "1.2.3"));
    assert!(!version_at_least("1.2.3", "malformed"));
}

#[tokio::test]
async fn mixed_keys_set_holds_the_floor_at_its_lowest_member_across_restarts() {
    let backend = Arc::new(Backend::default());
    let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
    owner
        .enforce_release_keys("host", &[7, 5], true)
        .await
        .unwrap();
    assert_eq!(owner.release_keys_floor("host").await.unwrap(), 5);
    owner
        .enforce_release_keys("host", &[5, 7], true)
        .await
        .expect("a restart with an unchanged mixed set must not trip the keys floor");
    owner
        .enforce_release_keys("host", &[7], true)
        .await
        .unwrap();
    assert_eq!(owner.release_keys_floor("host").await.unwrap(), 7);
    assert!(owner
        .enforce_release_keys("host", &[5, 7], false)
        .await
        .is_err());
}

/// #359 SEC-L11 (B-M7.2, B-R5): a first-party candidate whose version does not read is refused with
/// its remedy, never exempted from the floor.
#[tokio::test]
async fn an_unreadable_first_party_version_is_refused_with_its_remedy() {
    let backend = Arc::new(Backend::default());
    let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
    let refused = owner
        .enforce_candidate("host", candidate("not-a-version", false), true)
        .await
        .expect_err("an unreadable version is never exempt from the floor");
    assert!(
        refused.contains("plugin") && refused.contains("MAJOR.MINOR.PATCH"),
        "names the plugin and the remedy: {refused}"
    );
}

/// #359 SEC-L11: a 1.6.0 floor refuses a 1.6.0 pre-release, and a pre-release floor admits a later
/// pre-release.
#[tokio::test]
async fn a_release_floor_refuses_its_pre_release() {
    let backend = Arc::new(Backend::default());
    let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
    owner
        .enforce_candidate("host", candidate("1.6.0-rc.2", false), true)
        .await
        .unwrap();
    owner
        .enforce_candidate("host", candidate("1.6.0-rc.3", false), true)
        .await
        .unwrap();
    owner
        .enforce_candidate("host", candidate("1.6.0", false), true)
        .await
        .unwrap();
    assert!(owner
        .enforce_candidate("host", candidate("1.6.0-rc.3", false), false)
        .await
        .is_err());
}

/// UPG-7 (#332): carrying host-keyed floors is idempotent, keeps the deployment's own higher
/// floor, never touches the deployment's rows, and a rerun carries nothing.
#[tokio::test]
async fn carrying_host_floors_keeps_the_highest_and_is_idempotent() {
    let backend = Arc::new(Backend::default());
    let owner = PluginFloor::new(Arc::new(attach(backend).await)).unwrap();
    owner
        .enforce_candidate("deployment", candidate("2.0.0", false), true)
        .await
        .unwrap();
    owner
        .enforce_candidate("pod-a", candidate("1.5.0", false), true)
        .await
        .unwrap();
    owner
        .enforce_release_keys("pod-a", &[9], true)
        .await
        .unwrap();
    owner
        .enforce_release_keys("deployment", &[3], true)
        .await
        .unwrap();
    assert_eq!(owner.adopt_host_floors("deployment").await.unwrap(), 2);
    assert!(owner
        .enforce_candidate("deployment", candidate("1.9.0", false), false)
        .await
        .is_err());
    assert_eq!(owner.release_keys_floor("deployment").await.unwrap(), 9);
    assert_eq!(owner.release_keys_floor("pod-a").await.unwrap(), 0);
    owner
        .enforce_candidate("pod-a", candidate("0.1.0", false), false)
        .await
        .unwrap();
    assert_eq!(owner.adopt_host_floors("deployment").await.unwrap(), 0);
}
