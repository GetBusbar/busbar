// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEED JUDGE (IF 13, round 8): on a pool miss only, `judge_name_with`, then `Resolve`, then
//! `judge_answer_with`, then `Guard::not_the_node(class, addr, true)` on every admitted address
//! (the node's own ports are refused in every class), all before one byte is sent.
//!
//! A refusal is audited here with its full reason and reaches the plugin as `NeedErr::Denied` with
//! no text (I2); a failed resolution is `Unavailable`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::proxy::{ProxyChoice, ProxyHop};
use busbar_kernel::config::tls::ProxyResolution;

use busbar_plugin_abi::host_side::needs::NeedErr;
use futures::channel::oneshot;

use crate::guard::{FrozenGuard, Guard, Resolve};

/// The Need judge: the connector's own guard and its resolver (no judge type parameter, IF 13).
#[derive(Debug)]
pub struct Judge<R: Resolve> {
    guard: FrozenGuard,
    resolver: R,
    proxy: Option<Arc<ProxyChoice>>,
    resolution: ProxyResolution,
    observations: Arc<super::observations::Observations>,
}

/// One admitted connection route; proxy hop admission never grants origin authority.
#[derive(Debug)]
pub struct Route {
    /// Pinned socket addresses for the direct destination or selected proxy.
    pub addrs: Vec<SocketAddr>,
    /// The selected proxy tunnel, when configured and not exempt.
    pub tunnel: Option<Tunnel>,
}

/// The proxy handshake selected for one logical destination.
#[derive(Debug)]
pub struct Tunnel {
    /// The exact operator-selected hop; credentials remain confined to CONNECT.
    pub hop: Arc<ProxyHop>,
    /// Original authority in Proxy mode, admitted pinned address in Local mode.
    pub target: String,
}

/// `host` and `port` of a `host:port` dest (a bracketed IPv6 literal loses its brackets).
///
/// # Errors
/// `Invalid` for no port, a port that is not a u16, or an empty host.
pub fn split_dest(dest: &str) -> Result<(&str, u16), NeedErr> {
    let (host, port) = dest.rsplit_once(':').ok_or(NeedErr::Invalid)?;
    let port = port.parse::<u16>().map_err(|_| NeedErr::Invalid)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err(NeedErr::Invalid);
    }
    Ok((host, port))
}

/// The URL of a FETCH need, read the one way the judgement and the exchange both read it: a WHATWG
/// parser reads `https:///x` as host `x`, but a URL whose authority is empty names no host.
///
/// # Errors
/// `Invalid` for text that does not parse or whose authority is empty.
pub(crate) fn parse_fetch_url(url: &str) -> Result<url::Url, NeedErr> {
    let u = url::Url::parse(url).map_err(|_| NeedErr::Invalid)?;
    let rest = url.split_once(':').map_or("", |(_, r)| r);
    if rest
        .as_bytes()
        .iter()
        .take(3)
        .filter(|&&b| matches!(b, b'/' | b'\\'))
        .count()
        == 3
    {
        return Err(NeedErr::Invalid);
    }
    Ok(u)
}

/// `host` and `port` of a FETCH URL (the scheme's default port when it names none).
///
/// # Errors
/// `Invalid` for a URL that does not parse, names no host, or whose scheme is not http or https.
pub fn split_url(url: &str) -> Result<(String, u16), NeedErr> {
    let u = parse_fetch_url(url)?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(NeedErr::Invalid);
    }
    let host = u.host_str().ok_or(NeedErr::Invalid)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = u.port_or_known_default().ok_or(NeedErr::Invalid)?;
    Ok((host.to_owned(), port))
}

impl<R: Resolve> Judge<R> {
    /// A judge over `guard` and `resolver`.
    #[must_use]
    pub fn new(guard: Guard, resolver: R) -> Self {
        Self::from_frozen(guard.freeze(), resolver)
    }

    /// A judge over an already frozen generation's destination policy.
    #[must_use]
    pub fn from_frozen(guard: FrozenGuard, resolver: R) -> Self {
        Self::with_proxy(guard, resolver, None, ProxyResolution::Local)
    }

    /// A frozen network generation's explicit proxy and resolution policy.
    #[must_use]
    pub fn with_proxy(
        guard: FrozenGuard,
        resolver: R,
        proxy: Option<Arc<ProxyChoice>>,
        resolution: ProxyResolution,
    ) -> Self {
        Self::observed(guard, resolver, proxy, resolution, Arc::default())
    }

    /// A frozen network judge writing to its generation's bounded pre-store observations.
    #[must_use]
    pub fn observed(
        guard: FrozenGuard,
        resolver: R,
        proxy: Option<Arc<ProxyChoice>>,
        resolution: ProxyResolution,
        observations: Arc<super::observations::Observations>,
    ) -> Self {
        Judge {
            guard,
            resolver,
            proxy,
            resolution,
            observations,
        }
    }

    /// Record a fixed denial without consulting any process or store singleton.
    pub fn denied(&self, host: &str, owner: u64, class: u32, verdict: u64) {
        self.observations.record(
            host,
            Some(owner),
            Some(class),
            super::observations::Outcome::Denied(verdict),
        );
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NeedErr> {
        let (tx, rx) = oneshot::channel();
        self.resolver.resolve(
            host,
            Box::new(move |answer| {
                // A dropped receiver is a cancelled chain: nobody is waiting for the answer.
                let _ = tx.send(answer);
            }),
        );
        rx.await
            .map_err(|_| NeedErr::Closed)?
            .map_err(|_| NeedErr::Unavailable)
    }

    /// Judge a dial of `host:port` under the judged `class` and return the addresses to connect
    /// to, in answer order. Every address answered is judged; one refusal refuses the dial.
    ///
    /// # Errors
    /// `Denied` for any guard refusal (audited, with the reason, on the core side), `Unavailable`
    /// for a failed resolution.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        class: u32,
        owner: (u64, u32),
    ) -> Result<Vec<SocketAddr>, NeedErr> {
        self.addresses(host, port, class, false, owner, false).await
    }

    /// Plan one direct or proxied dial under already checked instance authority.
    /// Proxy mode delegates only DNS failure/no-address, never a policy refusal or cancellation.
    pub async fn plan(
        &self,
        host: &str,
        port: u16,
        class: u32,
        reach: bool,
        secured: bool,
        owner: (u64, u32),
    ) -> Result<Route, NeedErr> {
        self.guard
            .judge_name_with(host, class, false, reach)
            .map_err(|why| {
                self.denied(host, owner.0, class, why.verdict);
                NeedErr::Denied
            })?;
        let proxy = self
            .proxy
            .as_ref()
            .and_then(|choice| choice.select(secured, host));
        let delegated = proxy.is_some() && self.resolution == ProxyResolution::Proxy;
        let origin = self
            .addresses(host, port, class, reach, owner, delegated)
            .await?;
        let Some(hop) = proxy else {
            return Ok(Route {
                addrs: origin,
                tunnel: None,
            });
        };
        if delegated && origin.is_empty() {
            self.observations.record(
                host,
                Some(owner.0),
                Some(class),
                super::observations::Outcome::Delegated,
            );
        }
        let target = if delegated {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        } else {
            origin.first().ok_or(NeedErr::Unavailable)?.to_string()
        };
        let addrs = self
            .addresses(
                hop.host(),
                hop.port(),
                busbar_plugin_abi::need::egress::OPERATOR_INFRASTRUCTURE,
                false,
                owner,
                false,
            )
            .await?;
        Ok(Route {
            addrs,
            tunnel: Some(Tunnel { hop, target }),
        })
    }

    async fn addresses(
        &self,
        host: &str,
        port: u16,
        class: u32,
        reach: bool,
        owner: (u64, u32),
        delegated: bool,
    ) -> Result<Vec<SocketAddr>, NeedErr> {
        let refused = |why: crate::guard::Refusal| {
            self.denied(host, owner.0, class, why.verdict);
            NeedErr::Denied
        };
        let ips = match self
            .guard
            .judge_name_with(host, class, false, reach)
            .map_err(refused)?
        {
            Some(literal) => vec![literal],
            None => {
                let answer = match self.resolve(host).await {
                    Ok(answer) if delegated && answer.is_empty() => return Ok(Vec::new()),
                    Ok(answer) => answer,
                    Err(NeedErr::Unavailable) if delegated => return Ok(Vec::new()),
                    Err(error) => return Err(error),
                };
                self.guard
                    .judge_answer_with(host, &answer, class, false, reach)
                    .map_err(refused)?;
                answer
            }
        };
        ips.into_iter()
            .map(|ip| {
                let at = SocketAddr::new(ip, port);
                self.guard
                    .not_the_node(class, at)
                    .map(|()| at)
                    .map_err(refused)
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../tests/need_judge_tests.rs"]
mod tests;
