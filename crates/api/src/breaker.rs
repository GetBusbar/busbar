// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM-FAULT VOCABULARY — what a protocol plugin says about an upstream failure, and the
//! exact limit of what it is allowed to say.
//!
//! This module exists because [`crate::ir::IrStreamEvent::Error`] carries a [`CanonicalSignal`]: the
//! IR cannot be expressed without the fault vocabulary, so the fault vocabulary is part of the
//! protocol ABI. It is the smallest surface that makes that true.
//!
//! ## The division of labour, and why it is the whole point
//!
//! A protocol plugin CLASSIFIES — it reads its own upstream's error shape (which only it knows) and
//! reports a [`StatusClass`]. The ENGINE DECIDES — what a class means for the breaker, the failover
//! walk, the audit record and the operator's dashboard is core's, and it is not on this trait.
//!
//! That split is what keeps *"a protocol doesn't change breakers or failover or auditing"* true by
//! CONSTRUCTION rather than by every plugin author's good behaviour. `Disposition` (the
//! ClientFault / TransientUpstream / HardDown / ContextLength verdict that drives the lane write
//! path) is deliberately NOT here: a plugin that could name it could declare its own failures
//! harmless and quietly opt out of circuit breaking. It classifies; it does not sentence.

/// THE CLASS OF AN UPSTREAM FAILURE, as the protocol that read it understands it.
///
/// Stage 1 output: emitted by a plugin's per-protocol normalizer, consumed by the engine's Stage 2,
/// which maps it to a disposition the plugin cannot see or influence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// Rate limit / slow down — transient, may recover with retry-after.
    RateLimit,
    /// Overloaded server — transient.
    Overloaded,
    /// Server error (5xx) — transient.
    ServerError,
    /// Request timeout — transient.
    Timeout,
    /// Network failure — transient.
    Network,
    /// Authentication failure (401/403) — hard down, credential invalid.
    Auth,
    /// Billing / insufficient balance — hard down, account issue.
    Billing,
    /// Client error (4xx other than 401/403) — caller's fault, do not penalize the lane.
    ClientError,
    /// Request exceeds this model's context window — the LANE is healthy; fail over (ideally to a
    /// larger-context model) WITHOUT penalizing the breaker.
    ContextLength,
}

/// Parse a [`StatusClass`] from its operator-facing token. `None` for an unknown value, so a
/// misspelled `error_map` entry is a diagnosable refusal rather than a silent reclassification.
///
/// The tokens are OPERATOR-VISIBLE: they are what a lane's `error_map:` names, so renaming one
/// invalidates a config file.
pub fn status_class_from_str(s: &str) -> Option<StatusClass> {
    match s {
        "rate_limit" => Some(StatusClass::RateLimit),
        "overloaded" => Some(StatusClass::Overloaded),
        "server_error" => Some(StatusClass::ServerError),
        "timeout" => Some(StatusClass::Timeout),
        "network" => Some(StatusClass::Network),
        "auth" => Some(StatusClass::Auth),
        "billing" => Some(StatusClass::Billing),
        "client_error" => Some(StatusClass::ClientError),
        "context_length" => Some(StatusClass::ContextLength),
        _ => None,
    }
}

/// RAW UPSTREAM ERROR extracted from an HTTP response — Stage 1a output, the plugin's reading of
/// its own upstream's error body BEFORE any classification.
#[derive(Debug, Clone)]
pub struct RawUpstreamError {
    pub http_status: u16,
    /// Provider-specific error *code* (e.g. a numeric `code` field), checked against `error_map`.
    pub provider_code: Option<String>,
    /// Provider-specific structured error *type* (e.g. a `type`/`error.type` string), checked
    /// against `error_map` as a second signal when the code doesn't match.
    pub structured_type: Option<String>,
    /// Upstream `Retry-After` in whole seconds, when present. A plugin's `extract_error` only sees
    /// the BODY (no headers), so the forwarding layer — which has the response headers — parses and
    /// sets this after `extract_error` returns, and the engine then propagates it into
    /// [`CanonicalSignal::retry_after`] so the cooldown floor is honored.
    pub retry_after_secs: Option<u64>,
}

impl RawUpstreamError {
    /// THE STATUS ALONE, claiming no provider vocabulary — what one outbound attempt reports when
    /// nothing on the path could read its upstream's error shape. It is the most restrictive USEFUL
    /// answer rather than the most restrictive possible one: classification still places the failure
    /// from the status, which is strictly better than a non-2xx the breaker never hears about.
    pub fn from_status(status: u16) -> Self {
        Self {
            http_status: status,
            provider_code: None,
            structured_type: None,
            retry_after_secs: None,
        }
    }
}

/// THE CANONICAL SIGNAL a protocol normalizer emits — Stage 1 output, Stage 2 input, and the type
/// [`crate::ir::IrStreamEvent::Error`] carries mid-stream.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalSignal {
    pub class: StatusClass,
    /// The provider's own word for what happened, preserved for the audit record and the operator's
    /// dashboard. Never parsed by the engine for control flow — it is evidence, not an instruction.
    pub provider_signal: Option<String>,
    pub retry_after: Option<u64>,
}
