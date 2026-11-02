// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    Usage,
    Metering,
    Correction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Intent,
    Applied,
    ConditionConflict,
    LandedUnknown,
    VerdictLanded,
    VerdictNotLanded,
    Settled,
}

/// An immutable, versioned custody transition. The payload contains raw operation
/// and dependency facts, never a derived price or credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvent {
    pub operation_id: [u8; 16],
    pub revision: u64,
    pub kind: RecoveryKind,
    pub body_fingerprint: [u8; 32],
    pub state: RecoveryState,
    pub first_sent_at_ms: Option<u64>,
    pub payload: Vec<u8>,
}

/// Per-opened-Store persistence. A repeated operation/revision must name exactly
/// the same event; success confirms its full immutable identity in the Store.
pub trait RecoverySink: Send + Sync {
    fn persist(&self, event: &RecoveryEvent) -> Result<(), String>;
    fn replay(&self) -> Result<Vec<RecoveryEvent>, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryVerdict {
    Landed,
    NotLanded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResolution {
    pub operation_id: [u8; 16],
    pub body_fingerprint: [u8; 32],
    pub expected_revision: u64,
    pub verdict: RecoveryVerdict,
    pub actor: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    pub operation_id: [u8; 16],
    pub body_fingerprint: [u8; 32],
    pub revision: u64,
    pub kind: RecoveryKind,
    pub state: RecoveryState,
    pub first_sent_at_ms: Option<u64>,
    pub can_resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    Unavailable(String),
    Conflict(String),
    Invalid(String),
}
