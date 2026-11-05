// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observed pump boundaries, carried by the existing bounded trace exporter. These are wall
//! intervals, not CPU time or token events. Missing fields remain unknown, never zero-filled.

use std::time::{Duration, Instant};

use super::route::{End, FarPiece};

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

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

pub(super) struct AttemptTiming {
    pub(super) span: tracing::Span,
    start: Instant,
    ready: bool,
    body: bool,
    terminal: bool,
}

impl AttemptTiming {
    pub(super) fn new(span: tracing::Span, unit: u64, attempt: u32, wait: Duration) -> Self {
        span.record("unit_id", unit);
        span.record("attempt", attempt);
        if attempt > 1 {
            span.record("retry_of_attempt", attempt - 1);
        }
        span.record("route_wait_us", micros(wait));
        Self {
            span,
            start: Instant::now(),
            ready: false,
            body: false,
            terminal: false,
        }
    }

    pub(super) fn piece(&mut self, piece: &FarPiece) {
        // A synthetic failure/completion without status or bytes is not response readiness.
        if !self.ready && (piece.status.is_some() || !piece.bytes.is_empty()) {
            self.mark("response_ready_us");
            self.ready = true;
        }
        if !self.body && !piece.bytes.is_empty() && !piece.fields {
            self.mark("first_body_us");
            self.body = true;
        }
        if piece.last && !piece.cut && !piece.fail_over {
            self.mark("far_end_last_us");
        }
    }

    fn mark(&self, field: &'static str) {
        self.span.record(field, micros(self.start.elapsed()));
    }

    pub(super) fn finish(&mut self, outcome: &'static str) {
        if !self.terminal {
            self.mark("attempt_end_us");
            self.span.record("outcome", outcome);
            self.terminal = true;
        }
    }

    pub(super) fn ended(&mut self, end: &End, cut: bool) {
        match end {
            End::Done if !cut => {
                self.mark("producer_complete_us");
                self.finish("complete");
            }
            End::Done => self.finish("cut"),
            End::Cancel(reason, _) => {
                self.mark("cancelled_us");
                self.span.record(
                    "cancel_reason",
                    busbar_contract::abi::plane::reason_code(*reason),
                );
                self.finish("cancelled");
            }
            _ => self.finish("failed"),
        }
    }
}

impl Drop for AttemptTiming {
    fn drop(&mut self) {
        // Dropping a future establishes abandonment, not its cause or successful completion.
        self.finish("abandoned");
    }
}
