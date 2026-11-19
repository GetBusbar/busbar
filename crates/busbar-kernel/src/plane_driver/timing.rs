// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An attempt's span, carried by the existing bounded trace exporter. These are wall intervals,
//! not CPU time or token events. Missing fields remain unknown, never zero-filled.

pub(super) fn attempt_span() -> tracing::Span {
    tracing::span!(
        target: "busbar::proxy::engine::walk",
        crate::observability::HOTPATH_LEVEL,
        "forward_once",
        lane = tracing::field::Empty,
        degraded = tracing::field::Empty,
        unit_id = tracing::field::Empty,
        attempt = tracing::field::Empty,
        retry_of_attempt = tracing::field::Empty,
        route_wait_us = tracing::field::Empty,
        response_ready_us = tracing::field::Empty,
        first_body_us = tracing::field::Empty,
        far_end_last_us = tracing::field::Empty,
        producer_complete_us = tracing::field::Empty,
        cancelled_us = tracing::field::Empty,
        cancel_reason = tracing::field::Empty,
        attempt_end_us = tracing::field::Empty,
        outcome = tracing::field::Empty,
        timing_profile = "observed-pump-v1",
        first_token = "unavailable",
        content_policy = "identity-and-timing-only",
        sampling = "all-enabled-attempts",
        delivery = "bounded-best-effort"
    )
}
