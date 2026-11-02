// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What an upstream's answer MEANS, in one table: the status class a dialect reads off the

macro_rules! dispositions {
    ($($(#[$doc:meta])* $name:ident => $label:literal,)*) => {
        /// Where a classified upstream failure sends the request next.
        ///
        /// Closed and exhaustive on purpose: a new disposition breaks the build at every reader
        /// rather than falling through some default arm on the request path.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Disposition {
            $($(#[$doc])* $name,)*
        }

        impl Disposition {
            /// Every disposition, in declaration order.
            pub const ALL: &'static [Disposition] = &[$(Disposition::$name,)*];

            /// The metric label a failure with this disposition is recorded under. A dashboard
            /// dimension, so it is reworded only with the dashboards that read it.
            #[must_use]
            pub const fn label(self) -> &'static str {
                match self {
                    $(Disposition::$name => $label,)*
                }
            }
        }
    };
}

dispositions! {
    /// The caller's own bad input. The destination is not penalised and the answer is relayed.
    ClientFault => "client_fault",
    /// A transient upstream failure: cooldown and error counter; the request fails over.
    TransientUpstream => "transient_upstream",
    /// A definitive signal about the shared destination — a rejected key, an exhausted account.
    HardDown => "hard_down",
    /// The request is too large for this destination's window. The destination is healthy; the
    /// request fails over and nothing is recorded against it.
    ContextLength => "context_length",
}

macro_rules! status_classes {
    ($($(#[$doc:meta])* $name:ident => $token:literal, $disposition:ident,)*) => {
        /// A dialect-normalised reading of what an upstream answered.
        ///
        /// Nine classes, and no vendor's vocabulary among them: a dialect reduces its own error
        /// shape to one of these, and renders one of these back in its own words.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum StatusClass {
            $($(#[$doc])* $name,)*
        }

        impl StatusClass {
            /// Every class, in declaration order.
            pub const ALL: &'static [StatusClass] = &[$(StatusClass::$name,)*];

            /// The class as an operator spells it in configuration.
            #[must_use]
            pub const fn token(self) -> &'static str {
                match self {
                    $(StatusClass::$name => $token,)*
                }
            }

            /// The class an operator's spelling names, or `None` for a spelling that names none.
            #[must_use]
            pub fn parse(token: &str) -> Option<StatusClass> {
                match token {
                    $($token => Some(StatusClass::$name),)*
                    _ => None,
                }
            }

            /// The disposition this class carries.
            #[must_use]
            pub const fn disposition(self) -> Disposition {
                match self {
                    $(StatusClass::$name => Disposition::$disposition,)*
                }
            }
        }
    };
}

status_classes! {
    /// Rate limit / slow down — transient, may recover after the upstream's own wait.
    RateLimit => "rate_limit", TransientUpstream,
    /// Overloaded server — transient.
    Overloaded => "overloaded", TransientUpstream,
    /// Server error (5xx) — transient.
    ServerError => "server_error", TransientUpstream,
    /// Request timeout — transient.
    Timeout => "timeout", TransientUpstream,
    /// Network failure — transient.
    Network => "network", TransientUpstream,
    /// Authentication failure (401/403) — the destination's key is bad.
    Auth => "auth", HardDown,
    /// Billing / insufficient balance — the destination's account is exhausted.
    Billing => "billing", HardDown,
    /// Client error (4xx other than 401/403) — the caller's fault; the destination is not
    /// penalised.
    ClientError => "client_error", ClientFault,
    /// Request exceeds this destination's window — the destination is healthy; fail over
    /// without penalising it.
    ContextLength => "context_length", ContextLength,
}

/// Raw upstream error extracted from HTTP response (Stage 1a output).
#[derive(Debug, Clone)]
pub struct RawUpstreamError {
    /// The upstream's HTTP status code.
    pub http_status: u16,
    /// Provider-specific error *code* (e.g. a numeric `code` field), checked against `error_map`.
    pub provider_code: Option<String>,
    /// Provider-specific structured error *type* (e.g. a `type`/`error.type` string), checked
    /// against `error_map` as a second signal when the code doesn't match.
    pub structured_type: Option<String>,
    /// Upstream `Retry-After` header value in whole seconds, when present. The per-protocol
    /// `extract_error` methods only see the body (no headers), so the forwarding layer — which has
    /// the response headers — parses and sets this after `extract_error` returns. `normalize_raw_error`
    /// then propagates it into `CanonicalSignal.retry_after` so the cooldown floor is honored.
    pub retry_after_secs: Option<u64>,
}

impl RawUpstreamError {
    /// THE STATUS ALONE, claiming no provider vocabulary — what one outbound attempt reports when

    pub fn from_status(status: u16) -> Self {
        Self {
            http_status: status,
            provider_code: None,
            structured_type: None,
            retry_after_secs: None,
        }
    }
}

/// Canonical signal emitted by protocol normalizers.
/// Stage 1 output → Stage 2 input.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalSignal {
    /// The status class the signal was placed in.
    pub class: StatusClass,
    /// The provider code or structured type that placed it, when one did.
    pub provider_signal: Option<String>,
    /// The upstream's stated cooldown floor in whole seconds, when it stated one.
    pub retry_after: Option<u64>,
}
