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
    /// The attempt's start, read only when its span records (a disabled span reads no clock).
    start: Option<Instant>,
    ready: bool,
    body: bool,
    terminal: bool,
    /// The attempt's note for the unit's DEBUG summary, only while that summary is enabled.
    trail: Option<crate::observability::request::AttemptTrail>,
}

impl AttemptTiming {
    pub(super) fn new(
        span: tracing::Span,
        unit: u64,
        attempt: u32,
        wait: Option<Duration>,
        trail: Option<crate::observability::request::AttemptTrail>,
    ) -> Self {
        let start = (!span.is_disabled()).then(|| {
            span.record("unit_id", unit);
            span.record("attempt", attempt);
            if attempt > 1 {
                span.record("retry_of_attempt", attempt - 1);
            }
            if let Some(wait) = wait {
                span.record("route_wait_us", micros(wait));
            }
            Instant::now()
        });
        Self {
            span,
            start,
            ready: false,
            body: false,
            terminal: false,
            trail,
        }
    }

    /// The walk is failing over from this attempt for `reason`: it ends as a retry.
    pub(super) fn retry(&mut self, reason: Option<&'static str>) {
        if let Some(trail) = self.trail.as_mut() {
            trail.failover(reason);
        }
        self.finish("retry");
    }

    pub(super) fn piece(&mut self, piece: &FarPiece) {
        if let (Some(trail), Some((status, _))) = (self.trail.as_mut(), piece.status) {
            trail.status(status);
        }
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
        if let Some(start) = self.start {
            self.span.record(field, micros(start.elapsed()));
        }
    }

    pub(super) fn finish(&mut self, outcome: &'static str) {
        if !self.terminal {
            self.mark("attempt_end_us");
            self.span.record("outcome", outcome);
            self.terminal = true;
            if let Some(trail) = self.trail.as_mut() {
                trail.close(outcome);
            }
        }
    }

    pub(super) fn ended(&mut self, end: &End, cut: bool) {
        match end {
            End::Done if !cut => {
                self.mark("producer_complete_us");
                self.finish("complete");
            }
            End::Done => self.finish("cut"),
            End::RetiredByCompletion => self.finish("retired"),
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

/// THE FORWARD PATH'S PER-REQUEST INSTRUMENTATION, in the order one unit runs it, for the
/// `request_debug_overhead` bench: the unit's summary trail (`PlaneDriver::unit`), the `forward`
/// span and its fields (`DoorSteps::request_span`), `request_attempts`, and per attempt the route
/// wait, the `forward_once` span (`EgressFarEnd::attempt_span`, its fields under the far end's
/// lock), [`AttemptTiming`] over one far-end piece, then the summary (`PlaneUnits::encode`).
/// `attempts - 1` attempts fail over. No I/O: what is left is exactly the work the log level
/// decides.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn forward_instrumentation(
    attempts: u32,
    pool: &[u8],
    downgraded: &std::sync::Mutex<Option<String>>,
    live: &std::sync::Mutex<(u64, bool)>,
) {
    use crate::observability::{hotpath_enabled, request, HOTPATH_LEVEL};
    use std::sync::Arc;

    let mut trail = request::Trail::start();

    let span = tracing::span!(
        target: "busbar::proxy::engine",
        HOTPATH_LEVEL,
        "forward",
        pool = tracing::field::Empty,
        ingress = tracing::field::Empty,
        op = "chat",
        request_id = tracing::field::Empty
    );
    if !span.is_disabled() {
        let pool = downgraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .or_else(|| Some(String::from_utf8_lossy(pool).into_owned()));
        if let Some(pool) = pool.as_deref() {
            span.record("pool", tracing::field::display(pool));
        }
        span.record("ingress", "openai");
        span.record("request_id", 7_u64);
    }
    let entered = span.enter();

    let outer = tracing::span!(
        target: "busbar::proxy::engine::walk",
        HOTPATH_LEVEL,
        "request_attempts",
        unit_id = 1_u64,
        request_id = 7_u64,
    );
    let walking = outer.enter();
    let log = if request::enabled() {
        trail.as_ref().map(|t| Arc::clone(&t.attempts))
    } else {
        None
    };
    for attempt in 1..=attempts {
        let route_started = hotpath_enabled().then(Instant::now);
        let route_wait = route_started.map(|started| started.elapsed());
        let span = if hotpath_enabled() {
            let w = live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let span = attempt_span();
            span.record("lane", w.0);
            span.record("degraded", w.1);
            span
        } else {
            tracing::Span::none()
        };
        let note = log
            .as_ref()
            .map(|log| request::AttemptTrail::open(Arc::clone(log), "lane-a", "openai"));
        let mut timing = AttemptTiming::new(span, 1, attempt, route_wait, note);
        let failing = attempt < attempts;
        timing.piece(&FarPiece {
            status: Some((if failing { 503 } else { 200 }, 0)),
            last: true,
            fail_over: failing,
            ..FarPiece::default()
        });
        if failing {
            timing.retry(Some("upstream_5xx"));
        } else {
            timing.ended(&End::Done, false);
        }
    }
    if let Some(trail) = trail.as_mut() {
        trail.walk = Some(("done", None));
    }
    drop(walking);
    drop(entered);

    if let Some(trail) = trail {
        let noted = trail.attempts();
        request::finished(&request::Summary {
            request_id: Some(7),
            unit_id: 1,
            plane: "llm",
            ingress: Some("openai"),
            op: Some("chat"),
            requested: Some("gpt-4o"),
            pool: Some("gpt-4o"),
            governance: "admitted",
            lane: noted.last().map(|a| a.lane.as_str()),
            provider: noted.last().map(|a| a.provider.as_str()),
            outcome: "completed",
            walk: Some("done"),
            status: 200,
            attempts: &noted,
            latency_us: trail.elapsed_us(),
            ..request::Summary::default()
        });
    }
}

#[cfg(test)]
#[path = "tests/timing_tests.rs"]
mod tests;
