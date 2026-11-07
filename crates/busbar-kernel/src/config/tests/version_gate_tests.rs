// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::tests::seed_bytes;
use super::*;
use crate::config::overlay::{
    persist_root_async, read_state_async, OverlayReadState, RootSettings, OVERLAY_VERSION,
};
#[tokio::test]
async fn newer_store_overlay_is_refused_without_overwrite() {
    let store = crate::real_store::core().await;
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":OVERLAY_VERSION+1,"future_security":{"required":true}}),
    )
    .unwrap();
    seed_bytes(store.clone(), &bytes).await;
    let backend = OverlayStore::from_core(store).unwrap();
    assert!(
        matches!(read_state_async(&backend).await, OverlayReadState::VersionTooNew(v) if v == OVERLAY_VERSION + 1)
    );
    assert!(backend.read_required_async().await.is_err());
    assert!(persist_root_async(Some(&backend), &RootSettings::default())
        .await
        .is_err());
    assert_eq!(backend.read_bytes_async().await.unwrap().unwrap(), bytes);
}
