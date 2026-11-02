// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind's ABI generation, the fact keys the kernel reserves, and the boot check that

use core::fmt;

/// The transport kind's ABI generation, named here for the transports that reach it on this path.
pub use crate::abi::transport::TRANSPORT_ABI;

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

/// The status numberings the kernel reserves, spelled once.

pub mod status_ns {
    /// The status-line numbering: three-digit codes, as the request-response transports (and the

    pub const HTTP: &str = "http";
    /// The trailer numbering, as a call-per-path transport reads it off an answer's trailer.
    pub const GRPC: &str = "grpc";

    /// Every reserved numbering, for the readers that walk them.
    pub const RESERVED: &[&str] = &[HTTP, GRPC];

    /// Whether a numbering is one the kernel reserves.
    #[must_use]
    pub fn is_reserved(namespace: &str) -> bool {
        RESERVED.contains(&namespace)
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

/// One registered transport, as the registry holds it for the boot check.
///
/// The declarations are associated constants, which a trait object cannot read; this is them as
/// data, recorded at registration by the composition root that named the transport. Nothing here is
/// derived — every field is what the crate declared or what the root wired — because a check that
/// re-derived its own inputs would agree with itself for free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    /// The transport's registry key.
    pub key: &'static str,
    /// The layers it declares it can be built over.
    pub composes_over: std::borrow::Cow<'static, [&'static str]>,
    /// The layer it was ACTUALLY built over, where the root composed it over one.
    pub composed_over: Option<&'static str>,
}

/// A composition the registry will not boot on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionError {
    /// A transport declares it composes over a layer no registered transport provides.
    ///
    /// A declaration nothing checks is the frame-honesty problem one layer up: the stack a node
    /// reports is the stack its declarations describe, and a name that resolves to nothing means
    /// the description was never true.
    UnregisteredLayer {
        /// The transport that declared it.
        transport: &'static str,
        /// The layer it named.
        layer: &'static str,
    },
    /// A transport was composed over a layer it does not declare.
    ///
    /// The other direction of the same rule: a declared composition must be the one actually used,
    /// or the declaration describes a node nobody is running.
    UndeclaredComposition {
        /// The transport that was composed.
        transport: &'static str,
        /// What it was actually built over.
        used: &'static str,
    },
    /// Two transports registered under one key.
    DuplicateKey(&'static str),
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredLayer { transport, layer } => write!(
                f,
                "transport `{transport}` composes over `{layer}`, which no registered transport \
                 provides"
            ),
            Self::UndeclaredComposition { transport, used } => write!(
                f,
                "transport `{transport}` was composed over `{used}`, which it does not declare"
            ),
            Self::DuplicateKey(key) => {
                write!(f, "two transports registered under the key `{key}`")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// The boot check over a registry's transports: every declared layer exists, and every composition

pub fn check_composition(registered: &[Registered]) -> Result<(), CompositionError> {
    for (i, r) in registered.iter().enumerate() {
        if registered[..i].iter().any(|other| other.key == r.key) {
            return Err(CompositionError::DuplicateKey(r.key));
        }
    }
    for r in registered {
        for layer in r.composes_over.iter() {
            if !registered.iter().any(|other| other.key == *layer) {
                return Err(CompositionError::UnregisteredLayer {
                    transport: r.key,
                    layer,
                });
            }
        }
        if let Some(used) = r.composed_over {
            if !r.composes_over.contains(&used) {
                return Err(CompositionError::UndeclaredComposition {
                    transport: r.key,
                    used,
                });
            }
        }
    }
    Ok(())
}
