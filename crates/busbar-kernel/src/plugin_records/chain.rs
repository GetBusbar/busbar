// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host chains in a plugin-records namespace (IF §12.5 round 12, §8.6 LK_CHAIN, §16.111). W1-K5 red: the row
//! layout only; append and the verified read are held in store.rs.

use super::store::scoped_key;
use super::Scope;

pub(super) fn head_key(scope: Scope, chain: &[u8]) -> Vec<u8> {
    let mut key = scoped_key(scope, b"h");
    key.extend_from_slice(chain);
    key
}

/// Every entry key of `chain` is this prefix and 8 more bytes (the sequence).
pub(super) fn entries_prefix(scope: Scope, chain: &[u8]) -> Vec<u8> {
    let mut key = scoped_key(scope, b"e");
    key.extend_from_slice(&u32::try_from(chain.len()).unwrap_or(u32::MAX).to_be_bytes());
    key.extend_from_slice(chain);
    key
}

pub(super) fn entry_key(prefix: &[u8], seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}
