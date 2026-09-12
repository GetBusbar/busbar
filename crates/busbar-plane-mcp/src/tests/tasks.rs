//! Tests for `tasks.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::{detailed_document, get};
use busbar_contract::tasks::{TaskRecord, TaskStore};

fn minimal_record() -> TaskRecord {
    TaskRecord {
        id: "t-1".into(),
        status: "working".into(),
        created_at: "2026-09-11T00:00:00.000Z".into(),
        updated_at: "2026-09-11T00:00:01.000Z".into(),
        ttl_ms: 300_000,
        poll_interval_ms: 250,
        result: None,
        error: None,
        input_requests: Vec::new(),
    }
}

/// The bare minimum a working task carries, and NOTHING else: no `result`, no `error`, no
/// `inputRequests` member at all — their absence is load-bearing, matching `busbar-mcp`'s own
/// `McpTask::detailed()`.
#[test]
fn a_working_task_carries_no_terminal_members() {
    let doc = detailed_document(&minimal_record());
    let obj = doc.as_object().unwrap();
    assert_eq!(obj.get("taskId").unwrap(), "t-1");
    assert_eq!(obj.get("status").unwrap(), "working");
    assert_eq!(obj.get("createdAt").unwrap(), "2026-09-11T00:00:00.000Z");
    assert_eq!(
        obj.get("lastUpdatedAt").unwrap(),
        "2026-09-11T00:00:01.000Z"
    );
    assert_eq!(obj.get("ttlMs").unwrap(), 300_000);
    assert_eq!(obj.get("pollIntervalMs").unwrap(), 250);
    assert!(!obj.contains_key("result"));
    assert!(!obj.contains_key("error"));
    assert!(!obj.contains_key("inputRequests"));
}

/// A completed task's `result` bytes are decoded into the document as a real value, not a string.
#[test]
fn a_completed_task_inlines_its_result() {
    let mut record = minimal_record();
    record.status = "completed".into();
    record.result = Some(serde_json::to_vec(&serde_json::json!({"isError": false})).unwrap());
    let doc = detailed_document(&record);
    assert_eq!(doc["result"]["isError"], false);
}

/// A failed task inlines `error` and never `result`.
#[test]
fn a_failed_task_inlines_its_error_only() {
    let mut record = minimal_record();
    record.status = "failed".into();
    record.error = Some(serde_json::to_vec(&serde_json::json!({"code": -32000})).unwrap());
    let doc = detailed_document(&record);
    assert_eq!(doc["error"]["code"], -32000);
    assert!(doc.get("result").is_none());
}

/// Outstanding asks are inlined under `inputRequests`, keyed as the store keyed them.
#[test]
fn input_requests_are_inlined_by_key() {
    let mut record = minimal_record();
    record.status = "input_required".into();
    record.input_requests = vec![(
        "confirm".into(),
        serde_json::to_vec(&serde_json::json!({"type": "boolean"})).unwrap(),
    )];
    let doc = detailed_document(&record);
    assert_eq!(doc["inputRequests"]["confirm"]["type"], "boolean");
}

struct FakeStore(Option<TaskRecord>);

impl TaskStore for FakeStore {
    fn get(&self, _id: &str, _principal: &str) -> Option<TaskRecord> {
        self.0.clone()
    }
}

/// `get` renders the store's record when there is one.
#[test]
fn get_renders_the_stores_record() {
    let store = FakeStore(Some(minimal_record()));
    let doc = get(&store, "t-1", "principal").unwrap();
    assert_eq!(doc["taskId"], "t-1");
}

/// `get` answers `None`, and does not name a JSON-RPC code, when the store has nothing — the same
/// answer whether the id never existed or belongs to another principal.
#[test]
fn get_answers_none_when_the_store_has_nothing() {
    let store = FakeStore(None);
    assert_eq!(get(&store, "unknown", "principal"), None);
}
