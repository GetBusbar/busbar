// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The attempt's one bound the walk owns: the cap on time to the first answer.
//!
//! The attempt itself — the durable dispatch record, the auth fields, the dial, the read of the
//! answer and what the breaker is told about it — is its caller's, one attempt per member the walk
//! takes. What the walk decides about it is how long it may take before the first answer, because
//! that is a share of the walk's own deadline.

/// The per-attempt cap on time to the first answer, floored by what the walk has left
/// (`remaining_ms`). A cap can never grant more time than the request still has, and it is never
/// zero.
#[must_use]
pub fn attempt_cap_ms(ms: u64, remaining_ms: u64) -> u64 {
    ms.min(remaining_ms.max(1))
}
