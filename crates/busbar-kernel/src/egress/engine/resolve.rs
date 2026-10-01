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
//!
//! The pooled posture's arm is [`EgressResolver::Judged`]: the name is resolved once per new
//! connection and EVERY address it answered with is judged by the dial table ([`DialTable`], the
//! configuration-time metadata denylist asked of an address) before `HttpConnector` sees any of
//! them. A refused answer is a resolver error, so the dial fails as a connect failure and nothing
//! is connected; an admitted answer is handed on whole, and the `Uri` keeps the name for SNI, the
//! certificate check and `Host`. A pooled connection was therefore dialled to an address this arm
//! judged, which is what makes reusing it safe.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiAddrs, GaiFuture, GaiResolver, Name};

use crate::net_guard::{AddressRefusal, DialDenylist};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// THE DIAL TABLE every pooled client judges through: one [`DialDenylist`], replaced whole when a
/// configuration is committed ([`DialTable::publish`]) and read by every resolution after it, so a
/// warm client reused across an apply judges under the new lists.
#[derive(Clone)]
pub struct DialTable(Arc<arc_swap::ArcSwap<DialDenylist>>);

impl DialTable {
    /// A table of its own, holding `lists`.
    pub fn new(lists: DialDenylist) -> Self {
        DialTable(Arc::new(arc_swap::ArcSwap::from_pointee(lists)))
    }

    /// The process's table: the one the composition root publishes each committed configuration
    /// into. Before the first commit it holds the built-in metadata list and no carve-outs.
    pub fn process() -> Self {
        static PROCESS: std::sync::OnceLock<DialTable> = std::sync::OnceLock::new();
        PROCESS
            .get_or_init(|| DialTable::new(DialDenylist::default()))
            .clone()
    }

    /// Replace the lists every holder of this table judges by.
    pub fn publish(&self, lists: DialDenylist) {
        self.0.store(Arc::new(lists));
    }

    /// Judge one resolution's answer, refusing it whole.
    fn judge(&self, host: &str, addrs: Vec<SocketAddr>) -> Result<ResolvedAddrs, BoxError> {
        let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
        self.0
            .load()
            .judge(host, &ips)
            .map_err(|refusal| Box::new(DialRefused(refusal)) as BoxError)?;
        Ok(ResolvedAddrs::Listed(addrs.into_iter()))
    }
}

/// The dial posture a pooled client is built with: the process table over the system resolver.
/// A test scopes its own table and names over the clients built inside [`with_scoped_dial`], so a
/// plane's runtime built in that scope judges by the test's lists without touching the process
/// table another test reads.
pub(crate) fn pooled_dial() -> (DialTable, Option<Arc<dyn ResolveNames>>) {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(scoped) = SCOPED_DIAL.with(|s| s.borrow().clone()) {
        return (scoped.0, Some(scoped.1));
    }
    (DialTable::process(), None)
}

/// A test's scoped dial posture: its table and its names.
#[cfg(any(test, feature = "test-support"))]
type ScopedDial = (DialTable, Arc<dyn ResolveNames>);

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static SCOPED_DIAL: std::cell::RefCell<Option<ScopedDial>> =
        const { std::cell::RefCell::new(None) };
}

/// TEST SEAM: every pooled client built by `build` on this thread judges by `table` and resolves
/// through `names`.
#[cfg(any(test, feature = "test-support"))]
pub fn with_scoped_dial<R>(
    table: DialTable,
    names: Arc<dyn ResolveNames>,
    build: impl FnOnce() -> R,
) -> R {
    let prior = SCOPED_DIAL.with(|s| s.replace(Some((table, names))));
    let built = build();
    SCOPED_DIAL.with(|s| *s.borrow_mut() = prior);
    built
}

/// A dial the table refused: the name answered with an address the metadata denylist refuses.
/// `HttpConnector` reports it as a connect failure, which is how a plane classifies it: not a
/// timeout, so it fails over as a refused connection does.
#[derive(Debug)]
pub struct DialRefused(pub AddressRefusal);

impl std::fmt::Display for DialRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dial refused: {}", self.0)
    }
}

impl std::error::Error for DialRefused {}

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
    /// `getaddrinfo` — reqwest's default and `HttpConnector`'s default. The pooled posture reaches
    /// it only inside [`EgressResolver::Judged`].
    System(GaiResolver),
    /// THE PIN. Answers exactly one name with exactly one address; refuses every other name with
    /// the doctrine message, verbatim. Note there is deliberately NO IP-literal special case:
    /// `HttpConnector` short-circuits IP-literal hosts before consulting any resolver, same as
    /// reqwest.
    Pinned { host: Arc<str>, addr: IpAddr },
    /// Caller-supplied (tests).
    Custom(Arc<dyn ResolveNames>),
    /// THE POOLED POSTURE: `names` answers, `table` judges every answered address, and only an
    /// admitted answer reaches the connector. An IP-literal host never reaches a resolver
    /// (`HttpConnector` short-circuits it); a literal cannot resolve elsewhere, and it was judged as
    /// a literal when the configuration was applied.
    Judged {
        names: Box<EgressResolver>,
        table: DialTable,
    },
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
/// connection on the pooled posture and the pinned arm is always immediate.
pub enum ResolveFuture {
    Gai(GaiFuture),
    Ready(Option<Result<ResolvedAddrs, BoxError>>),
    Custom(futures::future::BoxFuture<'static, Result<Vec<SocketAddr>, BoxError>>),
    Judged {
        names: Box<ResolveFuture>,
        host: Box<str>,
        table: DialTable,
    },
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
                    .expect("a resolve future is polled to its end once"),
            ),
            ResolveFuture::Custom(f) => f
                .as_mut()
                .poll(cx)
                .map(|r| r.map(|addrs| ResolvedAddrs::Listed(addrs.into_iter()))),
            ResolveFuture::Judged { names, host, table } => {
                let answered = std::task::ready!(Pin::new(names.as_mut()).poll(cx));
                Poll::Ready(answered.and_then(|addrs| table.judge(host, addrs.collect())))
            }
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
            EgressResolver::Judged { names, .. } => tower::Service::poll_ready(names.as_mut(), cx),
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
            EgressResolver::Judged { names, table } => ResolveFuture::Judged {
                host: name.as_str().into(),
                names: Box::new(tower::Service::call(names.as_mut(), name)),
                table: table.clone(),
            },
        }
    }
}
