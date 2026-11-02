// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::config::overlay::{
    persist_root, read_state, OverlayReadState, RootSettings, OVERLAY_VERSION,
};
#[test]
fn newer_store_overlay_is_refused_without_overwrite() {
    let store = crate::real_store::store();
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":OVERLAY_VERSION+1,"future_security":{"required":true}}),
    )
    .unwrap();
    let generation = crate::door::op_id().0;
    let chunk = RecordBytes::new(bytes.clone()).unwrap();
    wait(store.record_put(SCHEMA, &chunk_key(&generation, 0), &chunk)).unwrap();
    let head = Head {
        version: 1,
        generation,
        length: bytes.len() as u64,
        digest: Sha256::digest(&bytes).into(),
    };
    let head = RecordBytes::new(serde_json::to_vec(&head).unwrap()).unwrap();
    wait(store.record_put(SCHEMA, HEAD, &head)).unwrap();
    let backend = OverlayStore::new(store).unwrap();
    assert!(
        matches!(read_state(&backend), OverlayReadState::VersionTooNew(v) if v == OVERLAY_VERSION + 1)
    );
    assert!(backend.read_required().is_err());
    assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
    assert_eq!(backend.read_bytes().unwrap().unwrap(), bytes);
}
