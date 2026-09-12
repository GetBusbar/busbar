//! Tests for `tasks.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::{cancel, detailed_document, get, update};
use busbar_contract::tasks::{TaskAnswers, TaskRecord, TaskStore};

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

impl TaskAnswers for FakeStore {
    fn update(
        &self,
        _id: &str,
        _principal: &str,
        _answers: &[(String, Vec<u8>)],
        _now_ms: u64,
    ) -> Option<()> {
        // The record's presence stands in for "this caller owns it", which is the only thing the
        // writes branch on.
        self.0.as_ref().map(|_| ())
    }

    fn cancel(&self, _id: &str, _principal: &str, _now_ms: u64) -> Option<()> {
        self.0.as_ref().map(|_| ())
    }
}

/// A store that ASSERTS what crossed the face instead of recording it.
///
/// Recording would mean a `static` with interior mutability, and `tests/purity.rs` forbids this
/// crate from holding interior state — in a test double as much as in the adapter, because the
/// scanner is over the whole of `src/` and the rule it enforces is the one this crate exists to
/// keep. Asserting inside the implementor is the stateless form of the same observation: the cell
/// fails on the store's side, which is exactly where the encoding is owed.
struct AssertingStore(&'static [(&'static str, &'static str)]);

impl TaskAnswers for AssertingStore {
    fn update(
        &self,
        _id: &str,
        _principal: &str,
        answers: &[(String, Vec<u8>)],
        _now_ms: u64,
    ) -> Option<()> {
        assert_eq!(answers.len(), self.0.len(), "answer count");
        for ((key, bytes), (want_key, want_json)) in answers.iter().zip(self.0) {
            assert_eq!(key, want_key, "the key crossed unchanged");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(bytes).expect("valid codec bytes"),
                serde_json::from_str::<serde_json::Value>(want_json).unwrap(),
                "the value crossed as its own codec's bytes and round-trips unchanged"
            );
        }
        Some(())
    }

    fn cancel(&self, _id: &str, _principal: &str, _now_ms: u64) -> Option<()> {
        Some(())
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

/// `update` encodes the caller's answers to the face's opaque bytes, keyed the way the record's own
/// `input_requests` are, and acks with the EMPTY document — no task envelope, because `tasks/get` is
/// the one reader of a task's state.
#[test]
fn update_encodes_the_answers_and_acks_empty() {
    let store = AssertingStore(&[("first", r#"{"action":"accept"}"#)]);
    let mut responses = serde_json::Map::new();
    responses.insert("first".into(), serde_json::json!({ "action": "accept" }));
    let ack = update(&store, "t-1", "principal", &responses, 7).expect("the task is this caller's");
    assert_eq!(ack, serde_json::json!({}));
}

/// An EMPTY answer set is well-formed, not an error: a caller that has nothing yet has said so.
#[test]
fn an_empty_answer_set_is_delivered_rather_than_refused() {
    let store = AssertingStore(&[]);
    let ack = update(&store, "t-1", "principal", &serde_json::Map::new(), 7);
    assert_eq!(ack, Some(serde_json::json!({})));
}

/// `cancel` acks with the SAME empty document `update` does, and both answer `None` — naming no
/// JSON-RPC code — when the store holds nothing for this (id, principal) pair.
#[test]
fn cancel_acks_the_same_empty_document_and_absence_names_no_code() {
    let held = FakeStore(Some(minimal_record()));
    assert_eq!(
        cancel(&held, "t-1", "principal", 7),
        Some(serde_json::json!({}))
    );

    let nothing = FakeStore(None);
    assert_eq!(cancel(&nothing, "t-1", "principal", 7), None);
    assert_eq!(
        update(&nothing, "t-1", "principal", &serde_json::Map::new(), 7),
        None,
        "a foreign task is absent to the write exactly as it is to the read"
    );
}
