// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STAND-IN TRANSPORTS' FACTS, as DATA. The loader's test connection tables
//! ([`crate::tcp_conns::TcpConns`], [`crate::https_conns::HttpsConns`]) are doubles of a transport,
//! and only the thing itself may name itself in Rust source (BUSBAR-1.6.0.md l.115-120): the core
//! never knows what a scheme means, it is data passing through it (l.98-102). So each double takes
//! the transport it stands in for — the claim word a need names, its secured URL scheme and default
//! port, its local-socket prefix — as constructor data, and the conformance case supplies it from
//! `stand_in.json` beside this file. Never shipped: test-support and the published conformance
//! suite only.

use serde::Deserialize;

/// The facts a STREAM double ([`crate::tcp_conns::TcpConns`]) stands in for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamFacts {
    /// The transport claim a need names to be served by the double.
    pub transport: String,
    /// The target prefix that names a local (domain) socket path rather than `host:port`.
    pub local_prefix: String,
}

/// The facts a FRAMED double ([`crate::https_conns::HttpsConns`]) stands in for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FramedFacts {
    /// The transport claim a need names to be served by the double.
    pub transport: String,
    /// The URL scheme of a target the double reaches: a secured one, as the framer's `locate`
    /// answers it (every far end is reached over the trust its need names).
    pub secure_scheme: String,
    /// The port a target that names none is reached at.
    pub default_port: u16,
}

/// Both doubles' facts, as `stand_in.json` states them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Facts {
    stream: StreamFacts,
    framed: FramedFacts,
}

fn facts() -> Facts {
    serde_json::from_str(include_str!("stand_in.json"))
        .unwrap_or_else(|e| panic!("stand_in.json does not read: {e}"))
}

impl StreamFacts {
    /// The stream double's facts, as `stand_in.json` states them.
    ///
    /// # Panics
    /// When `stand_in.json` does not read.
    #[must_use]
    pub fn stand_in() -> Self {
        facts().stream
    }
}

impl FramedFacts {
    /// The framed double's facts, as `stand_in.json` states them.
    ///
    /// # Panics
    /// When `stand_in.json` does not read.
    #[must_use]
    pub fn stand_in() -> Self {
        facts().framed
    }
}

#[cfg(test)]
#[path = "tests/stand_in_tests.rs"]
mod tests;
