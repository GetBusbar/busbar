// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LIVE SESSION'S DURABLE ROW — the shape this plane owns for one session, and the record it is
//! kept as. The kernel's handle engine stores the row opaquely; what a row holds, and how it reads as
//! a durable record, is the plane's.

use busbar_contract::records::{PlaneDisposition, PlaneRecord};
use serde::{Deserialize, Serialize};

/// The durable-audit kind stamped on a voice session's records — matches `PLANE_DECLARATION.audit_kind`.
pub const VOICE_SESSION_KIND: &str = "voice_session";

/// THE OPAQUE DURABLE ROW for one voice session — the neutral engine stores it as `Arc<dyn Any>`; the
/// plane owns its shape. Carries the session `(owner, id)` (the engine's scoped key), a monotonic
/// `turns` cursor bumped per settled turn, and whether the session has reached its terminal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceSessionRow {
    /// The session id — the working-set key (must equal the session scope's id).
    pub id: String,
    /// The principal the session is attributed to (must equal the session scope's owner).
    pub owner: String,
    /// Monotonic turn counter — bumped each metered turn.
    pub turns: u64,
    /// Unix seconds of the last mutation (the retention age key).
    pub updated_at: u64,
    /// Whether the session has settled into its terminal state (gates eviction).
    pub terminal: bool,
    /// The provider's `rtc_<call_id>` correlation key for a browser-WebRTC session — the `Location`
    /// header the SDP broker preserved from `POST /v1/realtime/calls`. It ties the brokered media call
    /// and busbar's sideband control socket to the SAME session, so governance applied here provably
    /// governs the media that flows there. `None` until the SDP broker sets it (and for topologies
    /// with no brokered media call). `#[serde(default)]` so a row written before this field existed
    /// rehydrates cleanly.
    #[serde(default)]
    pub rtc_call_id: Option<String>,
}

impl VoiceSessionRow {
    /// The row as the durable record the store keeps: its body IS the row.
    #[must_use]
    pub fn record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: VOICE_SESSION_KIND.to_string(),
            id: self.id.clone(),
            parent: None,
            seq: self.turns,
            ts: self.updated_at,
            disposition: if self.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            // The durable body IS the row: a boot rehydrate reconstructs the working-set entry from it
            // (see the session rehydrate). An in-memory-only posture (no sink attached) simply never
            // reads it back; the encode is infallible for these scalar fields.
            body: serde_json::to_vec(self).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
#[path = "tests/session_row_tests.rs"]
mod tests;
