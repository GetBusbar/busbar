// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECT DEADLINE — one wall-clock bound over the WHOLE connect (TCP + tunnel + TLS).
//!
//! Closes a parity gap: reqwest's `connect_timeout(10s)` bounds TCP PLUS the TLS handshake, while
//! hyper's `set_connect_timeout` bounds TCP only and hyper-rustls's handshake is unbounded — so a
//! black-holing TLS peer (SYN-ACKs, then silence) would wedge the connect until the request
//! deadline. On the pinned postures this layer IS reqwest parity; on the LLM lanes it is a strict
//! tightening of that latent gap — the one deliberate deviation there, applied to both postures
//! (the design's Q2 default) and changing nothing on any successful path.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Wraps a connector's whole connect future in `tokio::time::timeout`. Per-CONNECT cost only —
/// nothing on the per-request path.
#[derive(Clone)]
pub struct ConnectDeadline<C> {
    inner: C,
    deadline: Duration,
}

impl<C> ConnectDeadline<C> {
    pub fn new(inner: C, deadline: Duration) -> Self {
        ConnectDeadline { inner, deadline }
    }
}

impl<C> tower::Service<http::Uri> for ConnectDeadline<C>
where
    C: tower::Service<http::Uri>,
    C::Future: Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<C::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: http::Uri) -> Self::Future {
        let deadline = self.deadline;
        let connect = self.inner.call(dst);
        Box::pin(async move {
            match tokio::time::timeout(deadline, connect).await {
                Ok(done) => done.map_err(Into::into),
                Err(_) => Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "egress connect (TCP + tunnel + TLS handshake) exceeded the connect deadline",
                )) as BoxError),
            }
        })
    }
}
