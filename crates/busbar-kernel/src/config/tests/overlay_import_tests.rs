// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::overlay::{OverlayDoc, OverlayStore};
use crate::hashing::Sha256;

#[tokio::test]
async fn old_overlay_import_survives_reopen_and_never_replays_over_admin_changes() {
    let calls = crate::real_store::core().await;
    let source = Sha256::digest(b"old deployment and overlay");
    let doc = OverlayDoc {
        deleted: vec!["removed-security-hook".into()],
        deleted_groups: vec!["removed-grant".into()],
        root: Some(super::super::super::overlay::RootSettings {
            per_request_fee: Some(7),
            ..Default::default()
        }),
        ..Default::default()
    };
    let store = OverlayStore::from_core(calls.clone()).unwrap();
    assert!(store.import_once_async(source, &doc).await.unwrap());
    let restarted = OverlayStore::from_core(calls.clone()).unwrap();
    let loaded = restarted.read_required_async().await.unwrap().unwrap();
    assert_eq!(loaded.deleted, doc.deleted);
    assert_eq!(loaded.deleted_groups, doc.deleted_groups);
    assert_eq!(loaded.root.unwrap().per_request_fee, Some(7));
    restarted
        .update_async(|current| current.deleted_groups.push("later-revocation".into()))
        .await
        .unwrap();
    let again = OverlayStore::from_core(calls).unwrap();
    assert!(!again.import_once_async(source, &doc).await.unwrap());
    assert!(again
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .deleted_groups
        .contains(&"later-revocation".into()));
    assert!(again
        .import_once_async([9; 32], &doc)
        .await
        .unwrap_err()
        .contains("differs"));
}

#[tokio::test]
async fn legacy_import_state_agrees_with_the_importer() {
    use crate::config::overlay::LegacyImportState;
    let calls = crate::real_store::core().await;
    let source: [u8; 32] = Sha256::digest(b"legacy probe source").into();
    let store = OverlayStore::from_core(calls.clone()).unwrap();
    assert_eq!(
        store.legacy_import_state_async().await.unwrap(),
        LegacyImportState::Empty
    );
    assert!(store
        .import_once_async(source, &OverlayDoc::default())
        .await
        .unwrap());
    let reopened = OverlayStore::from_core(calls).unwrap();
    assert_eq!(
        reopened.legacy_import_state_async().await.unwrap(),
        LegacyImportState::Imported(source)
    );

    let written = OverlayStore::from_core(crate::real_store::core().await).unwrap();
    written
        .update_async(|doc| doc.deleted_groups.push("current-revocation".into()))
        .await
        .unwrap();
    assert_eq!(
        written.legacy_import_state_async().await.unwrap(),
        LegacyImportState::StoreOverlayPresent
    );
    assert!(written
        .import_once_async(source, &OverlayDoc::default())
        .await
        .is_err());
}

#[tokio::test]
async fn an_unreadable_legacy_import_receipt_is_an_error() {
    use crate::persistence::scoped::{Outcome, ScopedStore};
    let calls = crate::real_store::core().await;
    let schema = "busbar.config.overlay.v1";
    let owner =
        ScopedStore::host_private(calls.clone(), "busbar.config.overlay", [schema.into()]).unwrap();
    assert_eq!(
        owner
            .put(
                schema,
                b"migration:1.5.5:file",
                busbar_contract::Secret::new(b"not a receipt".to_vec()),
            )
            .await
            .unwrap(),
        Outcome::Applied
    );
    assert!(OverlayStore::from_core(calls)
        .unwrap()
        .legacy_import_state_async()
        .await
        .is_err());
}

#[tokio::test]
async fn old_overlay_import_refuses_an_unrelated_existing_destination() {
    let store = OverlayStore::from_core(crate::real_store::core().await).unwrap();
    store
        .update_async(|doc| doc.deleted_groups.push("current-revocation".into()))
        .await
        .unwrap();
    assert!(store
        .import_once_async([1; 32], &OverlayDoc::default())
        .await
        .unwrap_err()
        .contains("existing Store overlay"));
    assert_eq!(
        store
            .read_required_async()
            .await
            .unwrap()
            .unwrap()
            .deleted_groups,
        ["current-revocation"]
    );
}
