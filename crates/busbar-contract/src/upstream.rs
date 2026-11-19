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
