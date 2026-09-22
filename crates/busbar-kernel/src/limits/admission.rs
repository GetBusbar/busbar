// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `AdmissionGate`: the ONE non-blocking "try to get a slot, or don't" mechanic shared by every
//! hand-rolled `tokio::sync::Semaphore` + `try_acquire` capacity gate in the gateway (the inbound
//! request cap, the webhook-delivery cap, the tap-notification cap). Each such site is a distinct
//! POLICY (what happens on denial — shed a 503, drop a log, skip a tap) wrapped around the SAME
//! mechanic (acquire-or-count-and-tell-the-caller-no). `AdmissionGate` unifies only the mechanic;
//! it deliberately does not know or care what a caller does with a `None`.
//!
//! Explicitly OUT of scope (left as-is; NOT admission control): the per-lane dispatch semaphore
//! (`main.rs`'s `sem: Semaphore::new(max_concurrent)`), `proxy/engine/walk.rs`'s deadline-racing
//! `acquire_owned()`, and `store::in_memory`'s `try_acquire`/`try_acquire_probe` — those are the
//! load balancer's bespoke lane-capacity model (weighted routing, breaker probes, deadline races),
//! not a "gate at the door" admission decision, and mixing the two would blur a real architectural
//! seam for no benefit.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A single non-blocking capacity gate: `permits` slots, handed out via [`try_enter`](Self::try_enter)
/// and returned automatically when the returned permit is dropped. `name` identifies the gate on the
/// shared `busbar_admission_denied_total{gate="..."}` counter — pick a short, stable, non-request-derived
/// string (a compile-time constant at every call site today, so the label space is fixed at build time).
pub(crate) struct AdmissionGate {
    sem: Arc<Semaphore>,
    name: &'static str,
}

impl AdmissionGate {
    /// `permits == Semaphore::MAX_PERMITS` is the crate-wide "unbounded" sentinel already used by the
    /// store's lane semaphores (`Semaphore::new` accepts it directly — it is not a magic infinity,
    /// just the largest permit count `Semaphore` supports) — a gate built with it will, for any
    /// realistic request volume, never observe `try_enter` return `None`.
    pub(crate) fn new(permits: usize, name: &'static str) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(permits)),
            name,
        }
    }

    /// Free slots right now — a point-in-time read, racy under concurrent `try_enter`/permit-drop
    /// like `Semaphore::available_permits` itself. TEST-ONLY observability (production call sites
    /// never branch on it; they always go through `try_enter`).
    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.sem.available_permits()
    }

    /// Try to take one slot, without waiting. `Some` carries an owned, `'static` permit — drop it (or
    /// let it fall out of scope, including inside a spawned task or an async block it was moved into)
    /// to return the slot. `None` means the gate is saturated: the caller decides what that means
    /// (shed, drop, skip — this function has no opinion), but every denial is counted here first, so
    /// `busbar_admission_denied_total{gate}` observes EVERY gate uniformly even if a call site also
    /// keeps its own bespoke drop counter.
    pub(crate) fn try_enter(&self) -> Option<OwnedSemaphorePermit> {
        match self.sem.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                metrics::counter!(crate::metrics::ADMISSION_DENIED_TOTAL, "gate" => self.name)
                    .increment(1);
                None
            }
        }
    }
}

/// The static "gateway is at capacity" 503 the inbound cap sheds an over-cap arrival with. Fixed
/// bytes, fixed `Retry-After: 1` — no per-request formatting and no protocol sniffing, because a
/// shed happens BEFORE any routing or body work and must stay the cheapest possible response to
/// produce. Callers depend on these exact bytes (the shed body is part of the gateway's observable
/// contract), so change it only alongside the tests that pin it.
fn inbound_overloaded_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut resp = (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
        )],
        r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#,
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("1"),
    );
    resp
}

/// Lean, hand-rolled `Layer`/`Service` pair for the OUTERMOST inbound-concurrency cap. The cap is
/// an OOM DEFENSE — a bound on how many requests are concurrently BUFFERED AND PROCESSED — and an
/// arrival that finds the cap FULL is SHED IMMEDIATELY with the static 503 above, never queued
/// behind the cap. Shedding, not queueing, is the contract callers see: a client that is told "at
/// capacity, retry in a second" can shed load itself, fail over, or back off, whereas a silently
/// parked request looks indistinguishable from a hung gateway and burns the caller's own deadline
/// while holding its connection. A queueing arm was tried here and is exactly what that costs — an
/// over-cap burst turns into a stall whose latency grows without bound with the size of the burst.
/// A shed costs one non-blocking permit attempt and nothing else: no inner call, no body buffering,
/// no allocation beyond the response. Every shed counts on
/// `busbar_admission_denied_total{gate="inbound"}` so operator dashboards keep their pressure
/// signal. The memory invariant: this layer sits OUTSIDE body buffering, so at most
/// `max_inbound_concurrent` requests are ever in flight past it, and a shed arrival never buffered
/// a body at all.
#[derive(Clone)]
pub(crate) struct InboundAdmissionLayer {
    gate: Arc<AdmissionGate>,
}

impl InboundAdmissionLayer {
    /// `max_inbound_concurrent == 0` ⇒ NO layer (a true no-op) — see the caller in `main.rs`, which
    /// gates installing this layer at all on `> 0`; this constructor itself has no zero-permit
    /// special case, since a caller building one with `0` would just never admit anything.
    pub(crate) fn new(max_inbound_concurrent: usize) -> Self {
        Self {
            gate: Arc::new(AdmissionGate::new(max_inbound_concurrent, "inbound")),
        }
    }
}

impl<S> tower::Layer<S> for InboundAdmissionLayer {
    type Service = InboundAdmissionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InboundAdmissionService {
            inner,
            gate: self.gate.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct InboundAdmissionService<S> {
    inner: S,
    gate: Arc<AdmissionGate>,
}

impl<S> tower::Service<axum::extract::Request> for InboundAdmissionService<S>
where
    S: tower::Service<
            axum::extract::Request,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    /// Always ready: admission never parks the caller — it either grabs a free slot synchronously
    /// in `call` or sheds immediately, so there is nothing for `poll_ready` to wait on. Propagating
    /// backpressure through `poll_ready` would also head-of-line-block unrelated requests sharing
    /// the same connection.
    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        match self.gate.try_enter() {
            Some(permit) => {
                // tower's standard clone-out-of-`self` idiom: `inner` may not be `Poll::Ready`
                // again until this call's future resolves, so the service driving THIS request
                // must be a fresh clone, not `&mut self.inner` (which stays in `self`, ready for
                // the NEXT call).
                let mut inner = self.inner.clone();
                Box::pin(async move {
                    // Move the permit into the future so it is held for the ENTIRE inner call and
                    // released (by the permit's `Drop`) the instant this future resolves —
                    // including on early drop (a client disconnect cancels the future, which still
                    // runs the permit's destructor, so a slot is never leaked).
                    let _permit = permit;
                    inner.call(req).await
                })
            }
            // Gate saturated: shed immediately rather than queue behind the cap — no inner call at
            // all, so a full gate costs one non-blocking permit attempt and nothing else.
            None => Box::pin(async move { Ok(inbound_overloaded_response()) }),
        }
    }
}

#[cfg(test)]
#[path = "tests/admission_tests.rs"]
mod tests;
