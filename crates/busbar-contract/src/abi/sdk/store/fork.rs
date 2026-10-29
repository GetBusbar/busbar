// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A FORKED CHAIN, IN ONE WORDING FOR EVERY STORE. An append on an occupied chain position is
//! either the write-through retrying (an identical record: success) or a second writer forking the
//! chain (a different record: this error). The texts name the position and never echo a record's
//! content.

use crate::records::RecordStoreError;

/// `append_audit`'s refusal of a different record at an occupied `seq`.
#[must_use]
pub fn audit_fork(seq: u64) -> RecordStoreError {
    RecordStoreError(format!(
        "append_audit: seq {seq} already holds a DIFFERENT record — the audit chain has forked"
    ))
}

/// `append_plane_record`'s refusal of a different record at an occupied position: record kind
/// `kind`, the chain `chain` (the record's parent, or its own id when it has none), sequence `seq`.
#[must_use]
pub fn chain_fork(kind: &str, chain: &str, seq: u64) -> RecordStoreError {
    RecordStoreError(format!(
        "append_plane_record: kind '{kind}' parent '{chain}' seq {seq} already holds a DIFFERENT \
         record — the chain has forked"
    ))
}

#[cfg(test)]
#[path = "../tests/store_fork_tests.rs"]
mod tests;
