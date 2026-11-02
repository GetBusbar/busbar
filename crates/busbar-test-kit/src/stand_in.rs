// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    #[must_use]
    pub fn stand_in() -> Self {
        facts().stream
    }
}

impl FramedFacts {
    #[must_use]
    pub fn stand_in() -> Self {
        facts().framed
    }
}

#[cfg(all(test, loader_self_tests))]
#[path = "tests/stand_in_tests.rs"]
mod tests;
