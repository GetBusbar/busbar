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
    pub previous_event: Option<[u8; 32]>,
    pub kind: RecoveryKind,
    pub body_fingerprint: [u8; 32],
    pub state: RecoveryState,
    pub first_sent_at_ms: Option<u64>,
    pub payload: Vec<u8>,
}

/// Per-opened-Store persistence. A repeated operation/revision must name exactly
/// the same event; success confirms its full immutable identity in the Store.
pub trait RecoverySink: Send + Sync {
    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError>;
    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError>;
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

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) | Self::Conflict(reason) | Self::Invalid(reason) => {
                reason.fmt(f)
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

impl RecoveryEvent {
    pub fn fingerprint(&self) -> Result<[u8; 32], RecoveryError> {
        use sha2::Digest;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| RecoveryError::Invalid(format!("invalid recovery event: {error}")))?;
        let mut digest = sha2::Sha256::new();
        digest.update(b"busbar.usage-recovery.event.v1\0");
        digest.update(&encoded);
        Ok(digest.finalize().into())
    }

    pub fn follows(&self, previous: Option<&Self>) -> Result<(), RecoveryError> {
        let invalid = || RecoveryError::Invalid("invalid recovery transition chain".into());
        let Some(previous) = previous else {
            return if self.revision == 0
                && self.previous_event.is_none()
                && self.state == RecoveryState::Intent
            {
                Ok(())
            } else {
                Err(invalid())
            };
        };
        if self.operation_id != previous.operation_id
            || self.kind != previous.kind
            || self.body_fingerprint != previous.body_fingerprint
            || self.first_sent_at_ms != previous.first_sent_at_ms
            || previous.revision.checked_add(1) != Some(self.revision)
            || self.previous_event != Some(previous.fingerprint()?)
        {
            return Err(invalid());
        }
        use RecoveryState::*;
        match (previous.state, self.state) {
            (Intent, Applied | ConditionConflict | LandedUnknown)
            | (
                LandedUnknown,
                LandedUnknown | Applied | ConditionConflict | VerdictLanded | VerdictNotLanded,
            )
            | (Applied | ConditionConflict | VerdictLanded | VerdictNotLanded, Settled) => Ok(()),
            _ => Err(invalid()),
        }
    }
}
