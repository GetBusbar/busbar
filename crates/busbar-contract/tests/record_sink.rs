// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NARROW RECORD SINK, standing on its own.
//!
//! A plane's kernel-held durable records land in three verbs — `record_put`, `record_get`,
//! `record_scan` — and those three used to be reachable only as part of the twenty-two-verb
//! [`Store`] protocol. That made the sink a store backend answers and the sink the node BINDS two
//! different shapes, and the only trait that named the narrow one lived in the kernel crate: a crate
//! a store-kind plugin may not name. The three verbs are their own trait here, and `Store` declares
//! them by BEING one.
//!
//! What this file proves is the whole point of that: something that is not a `Store` — not a
//! plugin, not twenty-two verbs — can be the record sink, and a `Store` still is one.

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, RecordSink, Store, StoreError};

/// Object-safe, because the node holds its record sink behind a pointer.
const _RECORD_SINK: Option<&dyn RecordSink> = None;

/// A `Store` IS a record sink, and is usable as one without being re-wrapped.
fn _store_is_a_record_sink(store: &dyn Store) -> &dyn RecordSink {
    store
}

/// A record sink that is nothing else: no `Plugin`, no journal, no leases.
#[derive(Default)]
struct Rows(std::sync::Mutex<Vec<(&'static str, Vec<u8>, RecordBytes)>>);

impl RecordSink for Rows {
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        let mut rows = self.0.lock().unwrap_or_else(|e| e.into_inner());
        rows.retain(|(s, k, _)| *s != schema.as_str() || k != key);
        rows.push((schema.as_str(), key.to_vec(), value.clone()));
        Ok(())
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(s, k, _)| *s == schema.as_str() && k == key)
            .map(|(_, _, v)| v.clone()))
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(s, k, _)| *s == schema.as_str() && k.starts_with(prefix))
            .take(limit as usize)
            .map(|(_, k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

fn schema() -> RecordSchemaId {
    RecordSchemaId::new("tasks")
}

fn bytes(b: &[u8]) -> RecordBytes {
    RecordBytes::new(b.to_vec()).expect("fixture bodies are inside the record ceiling")
}

#[test]
fn a_bare_record_sink_answers_the_three_verbs_behind_a_pointer() {
    let sink: &dyn RecordSink = &Rows::default();

    sink.record_put(schema(), b"t-1", &bytes(b"one")).unwrap();
    sink.record_put(schema(), b"t-2", &bytes(b"two")).unwrap();

    assert_eq!(sink.record_get(schema(), b"t-1"), Ok(Some(bytes(b"one"))));
    assert_eq!(sink.record_get(schema(), b"absent"), Ok(None));
    assert_eq!(
        sink.record_scan(schema(), b"t-", 8),
        Ok(vec![
            (b"t-1".to_vec(), bytes(b"one")),
            (b"t-2".to_vec(), bytes(b"two")),
        ])
    );
}

#[test]
fn a_scan_limit_of_zero_is_nothing_and_not_everything() {
    let sink = Rows::default();
    sink.record_put(schema(), b"t-1", &bytes(b"one")).unwrap();

    assert_eq!(sink.record_scan(schema(), b"t-", 0), Ok(vec![]));
}
