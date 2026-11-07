// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit migration into an empty Store overlay, never a runtime file fallback.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::config) struct Receipt {
    pub(in crate::config) version: u32,
    pub(in crate::config) source_sha256: [u8; 32],
    pub(in crate::config) overlay_sha256: [u8; 32],
}

pub(in crate::config) fn check_receipt(bytes: &[u8], expected: &Receipt) -> Result<(), String> {
    let receipt: Receipt =
        serde_json::from_slice(bytes).map_err(|_| "overlay migration receipt is unreadable")?;
    if &receipt != expected {
        return Err("overlay migration source or converted configuration differs from the committed receipt".into());
    }
    Ok(())
}

pub(in crate::config) fn canonicalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let ordered: std::collections::BTreeMap<_, _> =
                std::mem::take(map).into_iter().collect();
            for (key, mut child) in ordered {
                canonicalize(&mut child);
                map.insert(key, child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(canonicalize),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::config::overlay::{OverlayDoc, OverlayStore};
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn old_overlay_import_survives_reopen_and_never_replays_over_admin_changes() {
        let calls = crate::real_store::core().await;
        let source = Sha256::digest(b"old deployment and overlay").into();
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
}
