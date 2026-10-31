// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared refusal wording for a different record at an occupied chain position.

use crate::records::RecordStoreError;

/// `append_audit`'s refusal of a different record at an occupied `seq`.
#[must_use]
pub fn audit_fork(seq: u64) -> RecordStoreError {
    RecordStoreError(format!(
        "append_audit: seq {seq} already holds a DIFFERENT record — the audit chain has forked"
    ))
}

/// `append_plane_record`'s refusal of a different record at an occupied chain position.
#[must_use]
pub fn chain_fork(kind: &str, chain: &str, seq: u64) -> RecordStoreError {
    RecordStoreError(format!(
        "append_plane_record: kind '{kind}' parent '{chain}' seq {seq} already holds a DIFFERENT \
         record — the chain has forked"
    ))
}
