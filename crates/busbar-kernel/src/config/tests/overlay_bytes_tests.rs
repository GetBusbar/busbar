// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::tests::seed_bytes;
use super::*;
use crate::config::overlay::{
    clear_section_async, persist_groups_async, persist_root_async, OverlaySection, RootSettings,
};
use std::collections::{BTreeMap, HashSet};

fn sample_root() -> RootSettings {
    serde_json::from_value(serde_json::json!({
        "listen": "0.0.0.0:9000",
        "per_request_fee": 7,
        "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
        "limits": { "max_inbound_concurrent": 512 }
    }))
    .expect("root settings parse")
}

#[tokio::test]
async fn corrupt_overlay_refuses_reads_and_all_mutations_without_clobbering() {
    let store = crate::real_store::core().await;
    let bytes = b"invalid JSON".to_vec();
    seed_bytes(store.clone(), &bytes).await;
    let backend = OverlayStore::from_core(store).unwrap();
    assert!(backend.read_required_async().await.is_err());
    assert!(persist_root_async(Some(&backend), &sample_root())
        .await
        .is_err());
    assert!(persist_groups_async(
        Some(&backend),
        &BTreeMap::new(),
        None,
        None,
        &HashSet::new()
    )
    .await
    .is_err());
    assert!(clear_section_async(Some(&backend), OverlaySection::Root)
        .await
        .is_err());
    assert_eq!(
        backend.read_bytes_async().await.unwrap().unwrap(),
        b"invalid JSON"
    );
}

#[tokio::test]
async fn store_reader_refuses_legacy_hook_spellings_without_rewriting() {
    let store = crate::real_store::core().await;
    let bytes =
        br#"{"hooks":{"legacy":{"kind":"gate","plugin":"test-hook","at":"request"}}}"#.to_vec();
    seed_bytes(store.clone(), &bytes).await;
    let backend = OverlayStore::from_core(store).unwrap();
    assert!(backend.read_required_async().await.is_err());
    assert_eq!(backend.read_bytes_async().await.unwrap().unwrap(), bytes);
}
