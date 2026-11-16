// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Audit-chain fixtures for tests in this crate and its dependents (`test-support`). A child of
//! `record` so it can read the chain's private signer. Never in a shipped build.

use super::AuditChain;

impl AuditChain {
    /// Whether this chain is a legacy-signing chain (built with [`AuditChain::signing_with`]).
    pub fn signs_lines(&self) -> bool {
        self.signer.is_some()
    }
}
