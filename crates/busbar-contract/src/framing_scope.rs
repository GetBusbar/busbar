// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only connection ownership shared by the connector and loader. This is Rust metadata;

/// The source of a host-authorized adoption. Never accepted from plugin input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptionSource {
    /// The original loaded owner.
    pub owner: u64,
    /// The original accepting listener.
    pub listener: u64,
    /// The original host framing incarnation.
    pub leg: u64,
    /// The confirmed original plugin-local token.
    pub conn: u64,
}

/// Host metadata for a staged transfer, before its new local token is confirmed.
#[derive(Debug, Clone, Copy)]
pub struct SessionTransfer {
    /// The pointer-free input loan to the new owner.
    pub session: crate::abi::transport::adopted_session::AdoptedSession,
    /// The admitted unit's original policy generation.
    pub generation: u64,
}
