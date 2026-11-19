// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The fact keys the kernel reserves for a transport, and the transport settings with their defaults.
//! The transport kind's ABI generation, the fact keys the kernel reserves, and the boot check that

/// The transport fact keys the kernel reserves, spelled once.
pub mod facts {
    /// The request target's path.
    pub const PATH: &str = "path";
    /// The request method, where the transport has one.
    pub const METHOD: &str = "method";
    /// The authority the request named.
    pub const AUTHORITY: &str = "authority";
    /// The protocol negotiated during the handshake.
    pub const ALPN: &str = "alpn";
    /// The server name offered during the handshake.
    pub const SNI: &str = "sni";
    /// The peer's source address as the bottom layer saw it.
    pub const PEER: &str = "peer";

    /// Every reserved key, for callers checking declarations and the boot cell that walks them.
    pub const RESERVED: &[&str] = &[PATH, METHOD, AUTHORITY, ALPN, SNI, PEER];

    /// Whether a key is one the kernel reserves.
    #[must_use]
    pub fn is_reserved(key: &str) -> bool {
        RESERVED.contains(&key)
    }

    /// The first reserved key a transport publishes without having declared it.
    #[must_use]
    pub fn undeclared<'a>(declared: &[&'a str], published: &[&'a str]) -> Option<&'a str> {
        published
            .iter()
            .copied()
            .find(|key| is_reserved(key) && !declared.contains(key))
    }
}

/// The deployment's settings every transport is built from — the operator's `limits:` knobs a wire
/// holds itself to, resolved once by the composition root and handed to each transport's build.
///
/// A shape of the contract because the root that resolves it and the host wire that reads it sit in
/// different crates: the root's host-wire build takes it, and no transport plugin reads it — a
/// transport's knobs reach it as the settings its door declares. The body cap is the SAME number the door's inbound limit is
/// built from, on either side of an exchange; the request timeout is the operator's own
/// `limits.upstream_request_timeout_secs`.
#[derive(Clone, Copy, Debug)]
pub struct TransportSettings {
    /// Per-host idle keep-alive socket budget.
    pub pool_max_idle_per_host: usize,
    /// Idle keep-alive lifetime, in seconds.
    pub pool_idle_timeout_secs: u64,
    /// Pin the egress client to HTTP/1.1.
    pub upstream_http1_only: bool,
    /// Force cleartext HTTP/2 prior-knowledge.
    pub upstream_h2_prior_knowledge: bool,
    /// The largest request body a transport accumulates, in bytes — `limits.request_body_max_bytes`.
    pub request_body_max_bytes: usize,
    /// The largest response body a transport carries for one exchange, in bytes.
    pub response_body_max_bytes: usize,
    /// The ceiling on one egress exchange up to the response head, in seconds.
    pub request_timeout_secs: u64,
}

/// The uninstalled-config fallback for [`TransportSettings::request_body_max_bytes`] — the value the
pub const DEFAULT_REQUEST_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;

/// The uninstalled-config fallback for [`TransportSettings::request_timeout_secs`] — the value the
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;

impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 32,
            pool_idle_timeout_secs: 4,
            upstream_http1_only: false,
            upstream_h2_prior_knowledge: false,
            request_body_max_bytes: DEFAULT_REQUEST_BODY_MAX_BYTES,
            response_body_max_bytes: DEFAULT_REQUEST_BODY_MAX_BYTES,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }
}
