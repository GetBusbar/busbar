// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEND — the two deadlines every attempt rides and the three ways a send can end. The send verb
//! itself lives in [`super::attempt`] (the one place it may appear); this module owns the envelope
//! around it.
//!
//! ONE deadline per attempt (the re-provision of what used to be the HTTP client's own timeout):
//!   * NON-streaming: the failover-budget remainder, on the send AND every buffered read.
//!   * STREAMING: the client-level ceiling (`limits.upstream_request_timeout_secs`), anchored at
//!     send start and carried into the stream body's own ceiling. Bounding a stream with the (much
//!     shorter) failover budget would truncate healthy long generations; bounding it with NOTHING
//!     let a black-holed upstream hold the send open forever with no breaker signal.
//!
//! Inside that, the PER-ATTEMPT time-to-response-headers cap (`attempt_timeout_ms`, the hang
//! detector) is raced inline at the send site: the pool-member override wins over the model-level
//! value; either is floored by the remaining budget. Expiry on either arm classifies as a
//! transport timeout.

use super::Hop;
use crate::engine::*;

/// The send stage's three exits, so the attempt-cap and budget-deadline wrappers compose without
/// nesting error types: a response (or client error), the per-attempt hang cap firing, or the
/// non-streaming failover budget expiring.
pub(crate) enum SendOutcome {
    Sent(Result<http::Response<hyper::body::Incoming>, crate::engine::EgressError>),
    AttemptTimeout(u64),
    BudgetTimeout,
}

/// The unified send error the classification arm reads — the same two-way split the old
/// HTTP-client arm made (`is_timeout()` vs everything-else-is-connect), preserved exactly:
/// * the failover-budget deadline and a connect that exceeded its 10s bound are TIMEOUTS;
/// * every other client error (refused, TLS failure, reset before headers) is CONNECT class.
pub(crate) enum EgressSendError {
    Timeout,
    Client(crate::engine::EgressError),
}

impl EgressSendError {
    pub(crate) fn is_timeout(&self) -> bool {
        match self {
            EgressSendError::Timeout => true,
            // Walk the source chain for an io timeout: hyper surfaces our connector's 10s connect
            // bound as a connect error wrapping `io::ErrorKind::TimedOut`, which the old client
            // classified as timeout — keep that split byte-identical for the breaker.
            EgressSendError::Client(e) => {
                let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
                while let Some(cur) = src {
                    if let Some(io) = cur.downcast_ref::<std::io::Error>() {
                        if io.kind() == std::io::ErrorKind::TimedOut {
                            return true;
                        }
                    }
                    src = cur.source();
                }
                false
            }
        }
    }
}

/// The attempt's outer deadline: the budget remainder for a non-stream request, the client-level
/// ceiling for a stream. Anchored now, at send start.
pub(super) fn deadline(hop: &Hop<'_>) -> tokio::time::Instant {
    tokio::time::Instant::now()
        + std::time::Duration::from_secs(if hop.wants_stream {
            EngineTables::new(hop.rt)
                .client_settings()
                .upstream_request_timeout_secs
                .max(1)
        } else {
            hop.remaining_secs.max(1)
        })
}
