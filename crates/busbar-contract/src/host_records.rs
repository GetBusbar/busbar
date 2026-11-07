// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared host-record conditions, decisions and retention vocabulary for every plugin kind.

use zeroize::Zeroize;

/// The exact state a predicate requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// No record at this address.
    Absent,
    /// Exactly these bytes at this address.
    Bytes(Vec<u8>),
}

impl Zeroize for Expected {
    fn zeroize(&mut self) {
        if let Self::Bytes(bytes) = self {
            bytes.zeroize();
        }
    }
}

/// A definitive transaction decision, distinct from an operation-id body conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// All mutations and their applied receipt committed, or that exact receipt replayed.
    Applied,
    /// A predicate failed; no mutations or receipt were written.
    ConditionConflict,
}

/// Retain records by age: every row older than the declared cutoff is eligible for removal.
pub const RETENTION_AGE: u32 = 0;
/// Retain active records: only terminal rows older than the cutoff are eligible for removal.
pub const RETENTION_TERMINAL_ONLY: u32 = 1;
/// Retention of usage-ledger windows.
pub const RETENTION_USAGE_WINDOWS: u32 = 2;

/// Shared conditional host-record codec.
pub mod conditional;
/// Historical exact accounting correction codec.
pub mod correction;
/// Shared logical operation fingerprints and replay results.
pub mod dedupe;

/// One host-record call in flight.
pub type RecordCall<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, RecordFailure>> + Send + 'a>>;

/// Why a host-record call answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordFailure {
    /// FAILED: the store's text. For an `op_id`-carrying write this proves nothing (S5): the commit
    /// may have landed, so the caller replays the same `op_id` with the same body.
    Failed(String),
    /// REFUSED: the store would not take the op; its text. For an `op_id`-carrying write, decided
    /// before commit: nothing applied and nothing recorded (S3, S5).
    Refused(String),
    /// The `op_id` was already used with different value fields (`STORE_OPID_CONFLICT`); nothing
    /// applied.
    Conflict,
    /// The instance is at its `max_inflight`: REFUSED without a crossing.
    Overloaded,
    /// The instance faulted, or the op did not answer within its deadline.
    Fault(String),
}

impl std::fmt::Display for RecordFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(t) => write!(f, "the store failed the op: {t}"),
            Self::Refused(t) => write!(f, "the store refused the op: {t}"),
            Self::Conflict => f.write_str(crate::abi::store::DIAG_OPID_CONFLICT),
            Self::Overloaded => f.write_str("the store is at its in-flight limit"),
            Self::Fault(t) => write!(f, "the store faulted: {t}"),
        }
    }
}

impl std::error::Error for RecordFailure {}
