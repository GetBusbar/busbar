// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`TransportError::is_own_refusal`] — the ONE fact `issue.rs`'s call-log outcome and `wire::send`'s
//! telemetry counter both need: did busbar ever open a socket to this upstream?
//!
//! Pure and synchronous on purpose: the claim is about a `match` over a closed four-variant enum,
//! and driving it through a real dispatch would exercise a hundred lines of gate and I/O machinery
//! to prove one `matches!`.

use crate::mcp::client::ssrf::SsrfRefusal;
use crate::mcp::client::wire::TransportError;

/// [`TransportError::Refused`] AND [`TransportError::Supervision`] are busbar's OWN refusals: nothing
/// left busbar, so a caller that records "was this dispatched" must not say yes.
#[test]
fn refused_and_supervision_are_busbars_own_refusal() {
    assert!(TransportError::Refused(SsrfRefusal::Scheme("no scheme".to_string())).is_own_refusal());
    assert!(TransportError::Supervision("quarantined".to_string()).is_own_refusal());
}

/// [`TransportError::Unreachable`] AND [`TransportError::Io`] are the OPPOSITE fact: busbar attempted
/// the hop, so they must NOT read as busbar's own refusal — this is what proves the predicate is
/// narrowed to the two pre-socket arms rather than defaulting true for every failure.
#[test]
fn unreachable_and_io_are_not_busbars_own_refusal() {
    assert!(!TransportError::Unreachable("connection refused".to_string()).is_own_refusal());
    assert!(!TransportError::Io("connection reset".to_string()).is_own_refusal());
}
