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

    /// Take one slot, WAITING FIFO when the gate is saturated — the inbound layer's arm. The wait
    /// is naturally cancelled when the caller's future drops (a disconnecting client leaves the
    /// queue with no residue: tokio semaphore waiters are cancel-safe), so parked arrivals cost a
    /// waker each and nothing more. Saturation waits are counted on the same denial counter the
    /// shed arm uses — the operator's pressure signal survives the semantics change.
    pub(crate) async fn enter_queued(self: &Arc<Self>) -> OwnedSemaphorePermit {
        if let Some(permit) = self.try_enter_uncounted() {
            return permit;
        }
        metrics::counter!(crate::metrics::ADMISSION_DENIED_TOTAL, "gate" => self.name).increment(1);
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("admission semaphores are never closed")
    }

    /// The uncontended fast path of [`enter_queued`](Self::enter_queued) — one atomic, no metric
    /// (nothing was denied).
    fn try_enter_uncounted(&self) -> Option<OwnedSemaphorePermit> {
        self.sem.clone().try_acquire_owned().ok()
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

/// Lean, hand-rolled `Layer`/`Service` pair for the OUTERMOST inbound-concurrency cap. The cap is
/// an OOM DEFENSE — a bound on how many requests are concurrently BUFFERED AND PROCESSED — and an
/// over-cap arrival now WAITS FIFO for a slot instead of being shed with an instant 503. The shed
/// semantics this replaces caused a measured collapse under a connection herd: at 12k clients
/// against the 8192 default, the gateway spent its cores minting fast 503s that deadline-driven
/// clients instantly retried — a self-sustaining fail/retry storm (17k rps goodput, 130k failures
/// per 20s run) where queueing serves the full ~46k rps with ~tens of ms of added wait (Little's
/// law: the slots turn over in ~180ms). 1.5.5 behaved gracefully here precisely because it had no
/// shed layer — over-cap work queued implicitly in the runtime; this layer makes that queueing
/// EXPLICIT and BOUNDED. The memory invariant is unchanged: this layer sits OUTSIDE body
/// buffering, so a parked arrival holds its connection and headers only (bounded by the fd
/// budget), never a buffered body; at most `max_inbound_concurrent` requests are ever in flight
/// past it. A parked waiter whose client disconnects leaves the queue with no residue
/// (cancel-safe), and saturation still counts on `busbar_admission_denied_total{gate="inbound"}`
/// so operator dashboards keep their pressure signal.
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

    /// Always ready: saturation parks the REQUEST FUTURE (in `call`'s returned future, where the
    /// connection's own cancellation reaches it), never the service — propagating backpressure
    /// through `poll_ready` would head-of-line-block unrelated requests on a shared connection.
    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        // tower's standard clone-out-of-`self` idiom: `inner` may not be `Poll::Ready` again
        // until this call's future resolves, so the service driving THIS request must be a
        // fresh clone, not `&mut self.inner` (which stays in `self`, ready for the NEXT call).
        let mut inner = self.inner.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            // FIFO admission: immediate on a free slot (one atomic — the steady-state path), a
            // parked waiter under saturation. The permit is held for the ENTIRE inner call and
            // released by Drop the instant this future resolves — including on early drop
            // (client disconnect cancels the future, which still runs the destructor, and a
            // still-WAITING arrival just leaves the queue).
            let _permit = gate.enter_queued().await;
            inner.call(req).await
        })
    }
}

#[cfg(test)]
#[path = "tests/admission_tests.rs"]
mod tests;
