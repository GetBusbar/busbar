// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::overlay::{
    clear_section, persist_groups, persist_root, OverlaySection, RootSettings,
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

#[test]
fn corrupt_overlay_refuses_reads_and_all_mutations_without_clobbering() {
    let store = crate::real_store::store();
    let bytes = b"invalid JSON".to_vec();
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
    assert!(backend.read_required().is_err());
    assert!(persist_root(Some(&backend), &sample_root()).is_err());
    assert!(persist_groups(
        Some(&backend),
        &BTreeMap::new(),
        None,
        None,
        &HashSet::new()
    )
    .is_err());
    assert!(clear_section(Some(&backend), OverlaySection::Root).is_err());
    assert_eq!(backend.read_bytes().unwrap().unwrap(), b"invalid JSON");
}

#[test]
fn legacy_hook_spelling_is_migrated_from_store_bytes() {
    let store = crate::real_store::store();
    let bytes =
        br#"{"hooks":{"legacy":{"kind":"gate","plugin":"test-hook","at":"request"}}}"#.to_vec();
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
    let doc = backend.read_required().unwrap().unwrap();
    assert_eq!(doc.hooks["legacy"].plugin, "test-hook");
}
