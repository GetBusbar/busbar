// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::test_support::TestOverlayStore;
#[test]
fn newer_store_overlay_is_refused_without_overwrite() {
    let fixture = TestOverlayStore::new();
    let bytes = serde_json::to_vec(
        &serde_json::json!({"version":OVERLAY_VERSION+1,"future_security":{"required":true}}),
    )
    .unwrap();
    fixture.seed_bytes(&bytes);
    let backend = fixture.backend();
    assert!(
        matches!(read_state(&backend), OverlayReadState::VersionTooNew(v) if v == OVERLAY_VERSION + 1)
    );
    assert!(backend.read_required().is_err());
    assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
    assert_eq!(fixture.read_bytes().unwrap(), bytes);
}
