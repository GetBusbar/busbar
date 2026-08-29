// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE'S RESOLVER — where destination pinning actually lives.
//!
//! `HttpConnector` is generic over its resolver, and the pin is a RESOLVER, not a connector
//! rewrite: the `http::Uri` is never touched, so the `Host` header, the SNI hyper-rustls derives
//! from `dst.host()`, and rustls's certificate name check all stay on the HOSTNAME — only the
//! socket address is substituted underneath them. This is the same layering reqwest's
//! `.resolve()` override used, which is what makes the SNI/Host/cert-name preservation a
//! structural fact rather than a property to re-prove per consumer.
//!
//! The pinned arm upholds refuse-second-lookup MORE strongly than the reqwest stack did: there,
//! the `.resolve()` override map answered the pinned host and `RefuseSecondLookup` answered the
//! rest; here ONE enum arm is both — a table lookup that performs no I/O ever, answering exactly
//! one name and refusing every other with the shared doctrine text
//! ([`crate::egress::refuse_second_lookup_message`]), byte-identical to the reqwest resolver's.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiAddrs, GaiFuture, GaiResolver, Name};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A caller-supplied name resolver — the test seam (a counting resolver is how "the engine
/// performed zero lookups of its own" becomes an assertion). Production postures use
/// [`EgressResolver::System`] or the pinned arm; this trait exists so a test can observe.
pub trait ResolveNames: Send + Sync {
    fn resolve(
        &self,
        name: &str,
    ) -> futures::future::BoxFuture<'static, Result<Vec<SocketAddr>, BoxError>>;
}

/// The engine's one resolver type — the per-posture difference is a VALUE in this enum, never a
/// second connector type.
#[derive(Clone)]
pub enum EgressResolver {
    /// `getaddrinfo` — reqwest's default and `HttpConnector`'s default. The LLM lanes (their
    /// destination is operator config, guarded at apply) and cold conveniences.
    System(GaiResolver),
    /// THE PIN. Answers exactly one name with exactly one address; refuses every other name with
    /// the doctrine message, verbatim. Note there is deliberately NO IP-literal special case:
    /// `HttpConnector` short-circuits IP-literal hosts before consulting any resolver, same as
    /// reqwest.
    Pinned { host: Arc<str>, addr: IpAddr },
    /// Caller-supplied (tests).
    Custom(Arc<dyn ResolveNames>),
}

impl EgressResolver {
    /// The system arm, spelled as a constructor so call sites read as the posture they build.
    pub fn system() -> Self {
        EgressResolver::System(GaiResolver::new())
    }
}

/// What a resolution produced, iterated the way `HttpConnector` wants it. The PORT of every
/// address here is advisory at most: `HttpConnector` overwrites it with the URI's explicit port,
/// and treats `0` as "use the scheme default" when the URI carries none — which is why the pinned
/// arm answers port 0 and `PinnedTarget` keeps carrying the judged port on the URI.
pub enum ResolvedAddrs {
    Gai(GaiAddrs),
    One(std::iter::Once<SocketAddr>),
    Listed(std::vec::IntoIter<SocketAddr>),
}

impl Iterator for ResolvedAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        match self {
            ResolvedAddrs::Gai(i) => i.next(),
            ResolvedAddrs::One(i) => i.next(),
            ResolvedAddrs::Listed(i) => i.next(),
        }
    }
}

/// The resolver's future — an enum rather than a box because the System arm runs per fresh
/// connection on the LLM lanes and the pinned arm is always immediate.
pub enum ResolveFuture {
    Gai(GaiFuture),
    Ready(Option<Result<ResolvedAddrs, BoxError>>),
    Custom(futures::future::BoxFuture<'static, Result<Vec<SocketAddr>, BoxError>>),
}

impl Future for ResolveFuture {
    type Output = Result<ResolvedAddrs, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            ResolveFuture::Gai(f) => Pin::new(f)
                .poll(cx)
                .map(|r| r.map(ResolvedAddrs::Gai).map_err(Into::into)),
            ResolveFuture::Ready(slot) => Poll::Ready(
                slot.take()
                    .expect("a resolve future is polled to completion once"),
            ),
            ResolveFuture::Custom(f) => f
                .as_mut()
                .poll(cx)
                .map(|r| r.map(|addrs| ResolvedAddrs::Listed(addrs.into_iter()))),
        }
    }
}

impl tower::Service<Name> for EgressResolver {
    type Response = ResolvedAddrs;
    type Error = BoxError;
    type Future = ResolveFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            EgressResolver::System(g) => tower::Service::poll_ready(g, cx).map_err(Into::into),
            EgressResolver::Pinned { .. } | EgressResolver::Custom(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, name: Name) -> Self::Future {
        match self {
            EgressResolver::System(g) => ResolveFuture::Gai(tower::Service::call(g, name)),
            EgressResolver::Pinned { host, addr } => {
                if name.as_str().eq_ignore_ascii_case(host) {
                    // Port 0: `HttpConnector` overwrites the resolved port with the destination
                    // URI's — matching reqwest's documented `.resolve()` behaviour of ignoring
                    // the override's port. The judged port rides the URI to the socket.
                    ResolveFuture::Ready(Some(Ok(ResolvedAddrs::One(std::iter::once(
                        SocketAddr::new(*addr, 0),
                    )))))
                } else {
                    ResolveFuture::Ready(Some(Err(crate::egress::refuse_second_lookup_message(
                        name.as_str(),
                    )
                    .into())))
                }
            }
            EgressResolver::Custom(r) => ResolveFuture::Custom(r.resolve(name.as_str())),
        }
    }
}
