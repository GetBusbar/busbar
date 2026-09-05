// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
//! extraction). The neutral `busbar_api::Store` contract speaks ONLY the opaque
//! `busbar_api::PlaneRecord` envelope; a plane owns its concrete row schema and serializes it into
//! (and back out of) that envelope's opaque `body` with `serde_json` — byte-for-byte the same the
//! store plugins persist it with. The neutral crates name none of these types.

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, StoreError, StoreResult};

/// The `task` kind — the A2A task row's neutral `PlaneRecord.kind` tag.
pub const KIND_TASK: &str = "task";
/// The `task_event` kind — the A2A per-task provenance event's neutral `PlaneRecord.kind` tag.
pub const KIND_TASK_EVENT: &str = "task_event";

/// DIGEST FRAMING VERSION 1 — the LEGACY ambiguous pipe-join (`{prev_hash}|{task_id}|…|{state}`). The
/// free-text fields (`context_id`, `principal`, `agent_id`) are NOT length-framed, so a value that
/// itself contains `|` shifts the field boundaries: two distinct event tuples can hash the SAME
/// preimage (field-injection forgery / ambiguous canonicalization). RETAINED only so a chain persisted
/// before the fix — whose rows carry no `digest_version` and thus default to this — still verifies.
/// NEVER emitted for a new event.
pub const DIGEST_VERSION_LEGACY_PIPE: u8 = 1;

/// DIGEST FRAMING VERSION 2 — the INJECTIVE length-prefixed framing every new event is sealed under:
/// a fixed domain tag, then each string field as `<u64-le len><bytes>` and each integer field as its
/// fixed 8-byte little-endian encoding. Because the length precedes the bytes, no field's content can
/// ever be read as another field's — the boundary is unambiguous, so the pipe-injection collision is
/// impossible.
pub const DIGEST_VERSION_LEN_PREFIXED: u8 = 2;

/// The framing a row that predates the versioned digest is read under: rows persisted before the fix
/// carry no `digest_version` and serde defaults them to the legacy pipe-join so they keep verifying.
fn default_digest_version() -> u8 {
    DIGEST_VERSION_LEGACY_PIPE
}

/// The A2A task states that are FINAL — the terminal set the `task` kind's retention contract drops.
/// Kept beside the row so the `disposition` a record carries and the purge that reads it agree.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

/// ONE A2A TASK, as it crosses the store seam for DURABLE persistence. The engine's canonical
/// `a2a::task::Task` mirrors this field-for-field; this side of the seam is plain data with the
/// enums flattened to their stable wire tokens, so a store plugin compiled against an older engine
/// does not fail to deserialize a row because a new task state was added to a Rust enum.
///
/// Carries no secret. `principal` is a busbar key id; `agent_id` is a busbar-local registration id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskRow {
    /// Protocol task id — unique, and the row's primary key.
    pub task_id: String,
    /// The A2A `contextId` grouping related tasks into a session — the resume key.
    pub context_id: String,
    /// The busbar key id this task is attributed to and billed against.
    pub principal: String,
    /// `inbound` (busbar is the server) or `outbound` (busbar is the client).
    pub direction: String,
    /// The canonical task-state token (`submitted`, `working`, `input-required`, `auth-required`,
    /// `completed`, `failed`, `canceled`, `rejected`).
    pub state: String,
    /// The chosen (outbound) or fronted (inbound) agent's busbar-local id. Empty before dispatch.
    pub agent_id: String,
    /// The LAST ARTIFACT CURSOR: how many artifact chunks have been durably relayed.
    pub artifact_cursor: u64,
    /// The push-notification callback URL registered for this task, or empty for none.
    pub push_callback: String,
    /// Unix seconds the task was first recorded.
    pub created_at: u64,
    /// Unix seconds of the most recent state change. The retention sweep's age key.
    pub updated_at: u64,
}

impl TaskRow {
    /// Serialize this task into the opaque `task` [`PlaneRecord`] envelope. `ts` is `updated_at` (the
    /// axis retention compares against) and `disposition` is `Terminal` exactly when the task's state
    /// is final, so `purge_plane_records_before` can honor the terminal-only contract from the typed
    /// sidecar without decoding the body.
    pub fn to_plane_record(&self) -> StoreResult<PlaneRecord> {
        let disposition = if TERMINAL_TASK_STATES.contains(&self.state.as_str()) {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        };
        Ok(PlaneRecord {
            kind: KIND_TASK.to_string(),
            id: self.task_id.clone(),
            parent: None,
            seq: 0,
            ts: self.updated_at,
            disposition,
            body: encode(self)?,
        })
    }

    /// Reconstruct a task from an opaque `task` body — the inverse of [`Self::to_plane_record`].
    pub fn from_body(body: &[u8]) -> StoreResult<Self> {
        decode(body)
    }
}

/// ONE PER-TASK PROVENANCE EVENT, as it crosses the store seam. Hash-chained WITHIN a task, and
/// `prev_hash` is the preceding event's `hash` (empty for `seq` 1). Per-TASK rather than one global
/// chain: tasks are concurrent and long-lived, and a per-task chain is independently verifiable and
/// independently exportable to the caller whose task it is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskEventRow {
    /// The task this event belongs to — the chain's scope.
    pub task_id: String,
    /// 1-based sequence WITHIN this task. Gaps and reordering are detectable, which is the point.
    pub seq: u64,
    /// Unix seconds the event was emitted.
    pub ts: u64,
    /// The event kind (`task.submitted`, `task.working`, …). Stable tokens; tooling branches on them.
    pub kind: String,
    /// The session id (see [`TaskRow::context_id`]).
    pub context_id: String,
    /// The attributed busbar key id.
    pub principal: String,
    /// The agent this event concerns, or empty.
    pub agent_id: String,
    /// The task state AFTER this event.
    pub state: String,
    /// The correlation id joining this event to the downstream L2 records it caused. Not chained into
    /// the digest: it is a join key supplied by the request spine.
    pub request_id: String,
    /// The preceding event's `hash` (empty for `seq` 1).
    pub prev_hash: String,
    /// The tamper-evidence digest over this event's chained fields (computed + verified engine-side).
    pub hash: String,
    /// WHICH DIGEST FRAMING `hash` was computed under — the version gate that lets a chain persisted
    /// before the field-injection fix (framing v1, ambiguous pipe-join) keep verifying while every new
    /// event is sealed under the injective framing v2. Absent on pre-fix rows, where serde defaults it
    /// to [`DIGEST_VERSION_LEGACY_PIPE`]; new events set [`DIGEST_VERSION_LEN_PREFIXED`].
    #[serde(default = "default_digest_version")]
    pub digest_version: u8,
}

impl TaskEventRow {
    /// Serialize this event into the opaque `task_event` [`PlaneRecord`] envelope, hung off its task
    /// via `parent` and ordered by the event's own `seq`.
    pub fn to_plane_record(&self) -> StoreResult<PlaneRecord> {
        Ok(PlaneRecord {
            kind: KIND_TASK_EVENT.to_string(),
            id: self.task_id.clone(),
            parent: Some(self.task_id.clone()),
            seq: self.seq,
            ts: self.ts,
            disposition: PlaneDisposition::Active,
            body: encode(self)?,
        })
    }

    /// The list selector that reads one task's `task_event` chain back, oldest-first.
    pub fn parent_selector(task_id: &str) -> PlaneSelector {
        PlaneSelector::Parent(task_id.to_string())
    }

    /// Reconstruct an event from an opaque `task_event` body — the inverse of
    /// [`Self::to_plane_record`].
    pub fn from_body(body: &[u8]) -> StoreResult<Self> {
        decode(body)
    }
}

/// Serialize a typed plane row into an opaque `PlaneRecord::body`. `serde_json`.
fn encode<T: serde::Serialize>(row: &T) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| StoreError(format!("plane body encode: {e}")))
}

/// Decode an opaque `PlaneRecord::body` back into its typed plane row — the inverse of [`encode`].
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> StoreResult<T> {
    serde_json::from_slice(body).map_err(|e| StoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/record_tests.rs"]
mod record_tests;
