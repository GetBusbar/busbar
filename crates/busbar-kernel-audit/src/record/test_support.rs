// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit-chain fixtures for tests in this crate and its dependents (`test-support`). A child of
//! `record` so it can read the chain's private signer. Never in a shipped build.

use super::AuditChain;

impl AuditChain {
    /// Which key this chain signs with, by identifier. `None` on a node that seals unsigned.
    pub fn signing_key_id(&self) -> Option<&str> {
        self.signer.as_ref().map(|k| k.key_id())
    }
}
