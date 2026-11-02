// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) struct AdmissionGate {
    sem: Arc<Semaphore>,
    name: metrics::SharedString,
}

impl AdmissionGate {
    pub(crate) fn new(permits: usize, name: impl Into<metrics::SharedString>) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(permits)),
            name: name.into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.sem.available_permits()
    }

    pub(crate) fn try_enter(&self) -> Option<OwnedSemaphorePermit> {
        match self.sem.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                metrics::counter!(crate::snapshot::ADMISSION_DENIED_TOTAL, "gate" => self.name.clone())
                    .increment(1);
                None
            }
        }
    }
}

pub(crate) fn inbound_overloaded_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut resp = (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(busbar_contract::protocol::APPLICATION_JSON),
        )],
        r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#,
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static(OVERLOADED_RETRY_AFTER),
    );
    resp
}

pub(crate) const OVERLOADED_RETRY_AFTER: &str = "1";

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

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        match self.gate.try_enter() {
            Some(permit) => {
                let mut inner = self.inner.clone();
                Box::pin(async move {
                    let _permit = permit;
                    inner.call(req).await
                })
            }

            None => Box::pin(async move { Ok(inbound_overloaded_response()) }),
        }
    }
}

#[cfg(test)]
#[path = "tests/admission_tests.rs"]
mod tests;
