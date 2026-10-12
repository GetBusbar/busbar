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
//! connection and EVERY address it answered with is judged by the deployment's one destination
//! guard (OWNER ruling DESTINATION GUARD: the connector's, installed by the root and asked through
//! `plane_host::egress_trust::egress_trust_host`, the root-installed egress-trust seam) before `HttpConnector` sees any of them. A refused answer is a resolver error, so the dial fails as a connect failure and nothing
//! is connected; an admitted answer is handed on whole, and the `Uri` keeps the name for SNI, the
//! certificate check and `Host`. A pooled connection was therefore dialled to an address this arm
//! judged, which is what makes reusing it safe.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiAddrs, GaiFuture, GaiResolver, Name};

use busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER;

use crate::host_services::DestJudge;
use crate::plane_host::egress_trust::{egress_trust_host, EgressTrustHost, PassThroughEgressTrust};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Judge one resolution's answer, refusing it whole, by `judge` (a test's own) or the
/// deployment's destination guard behind the root-installed egress-trust seam. The engine never
/// decides: with no seam installed the answer is refused (fail closed). The refusal is the
/// resolver's error, so `HttpConnector` reports the dial as a connect failure caused by it: not a
/// timeout, so a plane fails it over as it does a refused connection.
fn judged(
    judge: Option<&Arc<dyn DestJudge>>,
    host: &str,
    addrs: Vec<SocketAddr>,
) -> Result<ResolvedAddrs, BoxError> {
    let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
    let answer = match (judge, egress_trust_host()) {
        (Some(j), _) => j.judge_answer(host, &ips, EGRESS_PROVIDER),
        (None, Some(seam)) => seam.judge_answer(host, &ips, EGRESS_PROVIDER),
        (None, None) => PassThroughEgressTrust.judge_answer(host, &ips, EGRESS_PROVIDER),
    };
    answer.map_err(|refusal| Box::new(refusal) as BoxError)?;
    Ok(ResolvedAddrs::Listed(addrs.into_iter()))
}

/// The guard's NAME arm over `host`, before any resolution, by `judge` or the installed guard, fail
/// closed as [`judged`] is. Every unpinned dial asks it: an IP-literal host never reaches a resolver
/// (`HttpConnector` short-circuits it), so this is the judgement a literal gets, as its own answer;
/// a cloud-metadata, operator-blocked or `localhost` name is refused here whatever it resolves to.
pub(crate) fn judged_name(judge: Option<&Arc<dyn DestJudge>>, host: &str) -> Result<(), BoxError> {
    let verdict = match (judge, egress_trust_host()) {
        (Some(j), _) => j.judge_host(host, EGRESS_PROVIDER),
        (None, Some(seam)) => seam.judge_name(host, EGRESS_PROVIDER),
        (None, None) => no_guard_name(host),
    };
    verdict.map_err(|refusal| Box::new(refusal) as BoxError)
}

/// The name arm in a process with no guard behind the seam: every host refused (fail closed).
#[cfg(not(any(test, feature = "test-support")))]
fn no_guard_name(host: &str) -> Result<(), crate::host_services::DestRefusal> {
    PassThroughEgressTrust.judge_name(host, EGRESS_PROVIDER)
}

/// The name arm in a TEST binary no composition root boots: the loopback literal every fixture binds
/// is admitted (as an operator lists it in `advanced.allow_destinations`); every other host is
/// refused, fail closed, as in a shipped process with no guard.
#[cfg(any(test, feature = "test-support"))]
fn no_guard_name(host: &str) -> Result<(), crate::host_services::DestRefusal> {
    crate::egress::fixtures::loopback_literal_listed(host)
}

/// An answer the target's own resolution produced, judged whole as [`judged`] judges one. The
/// tunnelled arm's judgement of a target the proxy will connect to.
pub(crate) fn judged_answer(
    judge: Option<&Arc<dyn DestJudge>>,
    host: &str,
    addrs: Vec<SocketAddr>,
) -> Result<(), BoxError> {
    judged(judge, host, addrs).map(|_| ())
}

/// The judge and the name lookup a pooled client dials by; `None` = the process's own.
type PooledDial = (Option<Arc<dyn DestJudge>>, Option<Arc<dyn ResolveNames>>);

/// The dial posture a pooled client is built with: the installed guard (`None`, read through the
/// egress-trust seam at each dial) over the system resolver. A test scopes its own judge and names over the
/// clients built inside `egress::fixtures::with_scoped_dial`, so a plane's runtime built in that
/// scope judges by the test's judge without touching the process's.
pub(crate) fn pooled_dial() -> PooledDial {
    #[cfg(any(test, feature = "test-support"))]
    if let Some((judge, names)) = crate::egress::fixtures::scoped_dial() {
        return (Some(judge), Some(names));
    }
    (None, None)
}

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
    /// the doctrine message, verbatim. `HttpConnector` short-circuits IP-literal hosts before
    /// consulting any resolver, so the connector above refuses a literal that is not the pin itself
    /// before it dials.
    Pinned { host: Arc<str>, addr: IpAddr },
    /// Caller-supplied (tests).
    Custom(Arc<dyn ResolveNames>),
    /// THE POOLED POSTURE: `names` answers, the destination guard (`judge`, or the process's
    /// installed one when `None`) judges every answered address, and only an admitted answer
    /// reaches the connector. An IP-literal host never reaches a resolver
    /// (`HttpConnector` short-circuits it), so the connector above judges every host by the guard's
    /// name arm ([`judged_name`]) before it dials: a literal is judged there, as its own answer.
    Judged {
        names: Box<EgressResolver>,
        judge: Option<Arc<dyn DestJudge>>,
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
        judge: Option<Arc<dyn DestJudge>>,
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
            ResolveFuture::Judged { names, host, judge } => {
                let answered = std::task::ready!(Pin::new(names.as_mut()).poll(cx));
                Poll::Ready(
                    answered.and_then(|addrs| judged(judge.as_ref(), host, addrs.collect())),
                )
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
            EgressResolver::Judged { names, judge } => ResolveFuture::Judged {
                host: name.as_str().into(),
                names: Box::new(tower::Service::call(names.as_mut(), name)),
                judge: judge.clone(),
            },
        }
    }
}
