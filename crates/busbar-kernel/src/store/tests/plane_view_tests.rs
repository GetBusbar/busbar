// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DemoRow {
    server: String,
    reason: String,
    recorded_at: u64,
}

#[tokio::test]
async fn native_history_preserves_opaque_bodies_and_claims_redeem_once() {
    use crate::host_records_async::{AsyncHistory, HistoryOutcome};
    use crate::persistence::scoped::{ClaimOutcome, ScopedStore};
    let core = crate::real_store::core().await;
    let store = AsyncHistory::authorized_upserts(
        core.clone(),
        "plane-view",
        [super::KIND_DEMOTION.to_string()],
    )
    .unwrap();
    assert!(store
        .list(super::KIND_DEMOTION, &PlaneSelector::All)
        .await
        .unwrap()
        .is_empty());
    let row = PlaneRecord {
        kind: super::KIND_DEMOTION.into(),
        id: "srv-1".into(),
        parent: None,
        seq: 0,
        ts: 100,
        disposition: PlaneDisposition::Active,
        body: super::encode(&DemoRow {
            server: "srv-1".into(),
            reason: "drift".into(),
            recorded_at: 100,
        })
        .unwrap(),
    };
    assert!(matches!(
        store.upsert(row.view()).await.unwrap(),
        HistoryOutcome::Applied
    ));
    let rows = store
        .list(super::KIND_DEMOTION, &PlaneSelector::All)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let decoded: DemoRow = super::decode(&rows[0].body).unwrap();
    assert_eq!(decoded.server, "srv-1");
    assert_eq!(
        rows[0].body, row.body,
        "the native backend preserves the opaque body"
    );
    let scoped = ScopedStore::authorized(
        core.clone(),
        "plane-view",
        [super::KIND_DEMOTION.to_string()],
    )
    .unwrap();
    let now = core
        .backend()
        .clock(core.info().dataset)
        .await
        .unwrap()
        .unix_seconds;
    assert!(matches!(
        scoped.redeem("ask", "nonce-a", now + 1000).await.unwrap(),
        ClaimOutcome::Claimed
    ));
    assert!(matches!(
        scoped.redeem("ask", "nonce-a", now + 1000).await.unwrap(),
        ClaimOutcome::AlreadyClaimed
    ));
}

#[test]
fn a_plane_owned_kind_is_its_planes_alone_and_never_a_kernel_kind() {
    use super::{plane_owned_kind, KERNEL_RECORD_KINDS};
    let alpha = plane_owned_kind("alpha", "note").expect("fit");
    let beta = plane_owned_kind("beta", "note").expect("fit");
    assert_eq!(alpha, "\u{1}plane\u{1}alpha\u{1}note");
    assert_ne!(alpha, beta);
    for kind in KERNEL_RECORD_KINDS {
        assert!(
            !kind.chars().any(char::is_control),
            "{kind} holds no control character"
        );
        let owned = plane_owned_kind("mcp", kind).expect("fit");
        assert!(!KERNEL_RECORD_KINDS.contains(&owned.as_str()));
    }
    assert_eq!(plane_owned_kind("a\u{1}b", "c"), None);
    assert_eq!(plane_owned_kind("a", "b\u{1}c"), None);
    assert_eq!(plane_owned_kind("", "c"), None);
    assert_eq!(plane_owned_kind("a", ""), None);
}
