// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE CONNECTOR, AS THE BOOT PATH BUILDS IT (`BUSBAR-1.6.0.md` THE DESIGN, section 5
//! "Connections"; section 8: the connector is the sole holder of TLS trust roots; OWNER ruling
//! DESTINATION GUARD: one destination check, in the connector, for every outbound connection).
//! [`dest_judge`] builds the deployment's one destination judge ([`GuardJudge`]: the one
//! [`Guard`], the system resolver, each egress class's scheme rule); the root hands that same judge
//! to [`build_with_secrets`] (the connector's dial judge, [`judge`]) and to the kernel
//! (`dest.judge` and the kernel's own clients), so every dial of every kind is judged by one guard.
//! The root hands in the deployment's values and holds what it returns; nothing here keeps a
//! second.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB};
use busbar_contract::abi::host::service::{
    DEST_INTERNAL, DEST_NO_HOST, DEST_PLAINTEXT, DEST_SCHEME, DEST_UNRESOLVABLE,
};
use busbar_contract::net::url_host_to_ascii;
use busbar_contract::transport::trust::EgressTrust;
use busbar_kernel::config::Destinations;
use busbar_kernel::host_services::{Admitted, DestJudge, DestRefusal, Refused};

use crate::guard::{is_loopback, names_loopback, Guard, Resolve, SystemResolver};
use crate::pool::PoolPosture;
use crate::registry::{Entry, Transports};
use crate::{Connector, DialJudge, Judged, JudgedAll, Verdict, WakeTicket};

/// THE PROCESS'S CONNECTOR over the framer entries `entries` yields, judging every dial through
/// `dest` ([`judge`], the node's `own_ports` refused to a loopback-allowed need), dialling a framed
/// connection through the proxy the process's environment names ([`crate::proxy`]), securing a
/// connection with the default outbound trust where its target asks for it, waking a plugin's
/// ticket through `wake`, keeping a dialled connection whose exchange finished whole under the
/// deployment's `pool` posture ([`crate::pool`]), and resolving a program's environment references
/// through `spawn_secrets` at config time ([`crate::spawn_env`]). The trust is built before `entries` is asked for,
/// so a boot that cannot secure a connection loads no transport door.
///
/// # Errors
///
/// The default outbound trust will not build, a proxy variable is set and does not parse,
/// `entries` refuses, two entries claim one scheme, or
/// an entry states no claim.
pub fn build_with_secrets(
    entries: impl FnOnce() -> Result<Vec<Entry>, String>,
    dest: Arc<dyn DestJudge>,
    own_ports: &[u16],
    wake: WakeTicket,
    pool: PoolPosture,
    spawn_secrets: crate::spawn_env::SpawnSecretFn,
) -> Result<Arc<Connector>, String> {
    let tls = crate::tls::client::build_client_config(&EgressTrust::default())
        .map_err(|e| format!("its connection security: {e}"))?;
    // THE PROXY ENVIRONMENT, read once (row 130 E5a): a set variable that does not parse refuses
    // the boot, as the kernel engine's install did.
    let proxy = crate::proxy::from_env().map_err(|e| format!("its proxy environment: {e}"))?;
    let view = Transports::new(entries()?).map_err(|e| e.to_string())?;
    Ok(Arc::new(
        Connector::serving(view, judge(dest, own_ports), Some(Arc::new(tls)), wake)
            .pooling(pool)
            .proxying(proxy)
            .resolving_spawn_secrets(spawn_secrets),
    ))
}

// FINAL-REPIN: delete when the pinned door root cells call build_with_secrets
/// THE PINNED DOOR ROOT CELLS' NAME for [`build_with_secrets`], kept until their pin moves: the
/// same connector, its program environment references resolved through the linked secret plugins
/// at config time, as the root's boot resolves them. Never in a shipped build (`test-support`).
///
/// # Errors
///
/// As [`build_with_secrets`].
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn build(
    entries: impl FnOnce() -> Result<Vec<Entry>, String>,
    dest: Arc<dyn DestJudge>,
    own_ports: &[u16],
    wake: WakeTicket,
    pool: PoolPosture,
) -> Result<Arc<Connector>, String> {
    build_with_secrets(
        entries,
        dest,
        own_ports,
        wake,
        pool,
        busbar_kernel::config::secret::resolve_linked_string_at_config,
    )
}

/// THE DEPLOYMENT'S ONE DESTINATION JUDGE: its [`Guard`] over the system resolver.
///
/// # Errors
///
/// An `advanced.allow_destinations` entry the guard refuses (the boot refusal, naming it).
pub fn dest_judge(d: &Destinations) -> Result<Arc<GuardJudge>, String> {
    Ok(Arc::new(GuardJudge::new(
        Guard::from_config(d)?,
        Arc::new(SystemResolver),
    )))
}

/// THE DESTINATION JUDGE (`busbar_kernel::host_services::DestJudge`) over the one [`Guard`]: a
/// destination's scheme under its egress class (open-web secure only; loopback-allowed plaintext
/// to loopback only; every other class takes its target's scheme), then the guard's name arm,
/// then (a name) ONE resolution off the caller's thread and the guard's answer arm, the FIRST
/// address of an admitted answer pinned.
pub struct GuardJudge {
    guard: Guard,
    resolver: Arc<dyn Resolve>,
}

impl GuardJudge {
    /// The judge over `guard`, resolving names through `resolver`.
    #[must_use]
    pub fn new(guard: Guard, resolver: Arc<dyn Resolve>) -> Self {
        GuardJudge { guard, resolver }
    }

    /// The guard it judges by.
    #[must_use]
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// The name and scheme arms: the host, port and scheme to dial, and the literal when the host
    /// is one. The host handed back is the one a URL client dials, the name the guard judged
    /// ([`url_host_to_ascii`]: a non-ASCII name its UTS #46 punycode, `bücher.example` read as
    /// `xn--bcher-kva.example`), so a resolution asks for the name judged and the name 1.5.5's
    /// client resolved, never the spelling as written. An ASCII host is handed back as written.
    fn named(
        &self,
        dest: &str,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(String, u16, bool, Option<IpAddr>), u64> {
        // The classes a need may declare are 0..=4; a destination under any other names none.
        if class > EGRESS_LOOPBACK_ALLOWED {
            return Err(DEST_NO_HOST);
        }
        let (host, port, https) = split(dest)?;
        if !https && class == EGRESS_OPEN_WEB {
            return Err(DEST_PLAINTEXT);
        }
        let literal = self
            .guard
            .judge_name_with(&host, class, strict, reach)
            .map_err(|r| r.verdict)?;
        if literal.is_some() {
            plaintext_to_loopback(class, https, &host)?;
        }
        // The guard admitted the host, so it maps; a host that did not would be unjudgeable.
        let host = match url_host_to_ascii(&host) {
            Ok(dialled) => dialled.into_owned(),
            Err(_) => return Err(DEST_NO_HOST),
        };
        Ok((host, port, https, literal))
    }
}

/// Loopback-allowed's scheme rule, held once the guard admitted the destination: plaintext only
/// to a host WRITTEN as loopback ([`names_loopback`]), as 1.5.5's collector and webrequest guards
/// ruled on the URL's host, never on what a name resolved to (ARCHITECT parity ruling A3).
fn plaintext_to_loopback(class: u32, https: bool, host: &str) -> Result<(), u64> {
    if class == EGRESS_LOOPBACK_ALLOWED && !https && !names_loopback(host) {
        return Err(DEST_PLAINTEXT);
    }
    Ok(())
}

/// A destination as `(host, port, https)`: an `http(s)` URL (any other scheme refused, userinfo
/// refused), or a bare `host[:port]` authority (secure, port 443 unless named). The scheme is read
/// without case, as RFC 3986 reads it and as 1.5.5 read every URL it judged (`scheme_is`: v1.5.5
/// `crates/busbar/src/observability.rs:180-183`, `config_validate/mod.rs:1857`; `HTTP://` and
/// `HTTPS://` were accepted wherever their lower-case spelling was; ARCHITECT parity ruling A3).
fn split(dest: &str) -> Result<(String, u16, bool), u64> {
    if let Some((scheme, rest)) = dest.split_once("://") {
        let lowered = format!("{}://{rest}", scheme.to_ascii_lowercase());
        // The one http(s) URL reader (scheme allowlist, userinfo refused, the scheme's port).
        return match busbar_kernel_egress::trust::net::split_url(&lowered) {
            Ok((https, host, port, _)) => Ok((host, port, https)),
            Err(busbar_kernel_egress::trust::net::AddressRefusal::Scheme { .. }) => {
                Err(DEST_SCHEME)
            }
            Err(_) => Err(DEST_NO_HOST),
        };
    }
    if dest.is_empty() || dest.contains('@') {
        return Err(DEST_NO_HOST);
    }
    let (host, port) = match dest.strip_prefix('[') {
        Some(inner) => {
            let (host, tail) = inner.split_once(']').ok_or(DEST_NO_HOST)?;
            (host, tail.strip_prefix(':'))
        }
        None => match dest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            _ => (dest, None),
        },
    };
    let port = port.map_or(Ok(443), |p| p.parse().map_err(|_| DEST_NO_HOST))?;
    if host.is_empty() {
        return Err(DEST_NO_HOST);
    }
    Ok((host.to_owned(), port, true))
}

impl DestJudge for GuardJudge {
    fn judge_name(&self, dest: &str, class: u32, refuse_private: bool) -> Result<(), u64> {
        self.named(dest, class, refuse_private, false).map(|_| ())
    }

    fn judge(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        self.judged(dest, class, refuse_private, false, done)
    }

    fn judge_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        self.judged(dest, class, false, true, done)
    }

    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal> {
        self.guard
            .judge_answer(host, addrs, class)
            .map_err(|r| DestRefusal {
                verdict: r.verdict,
                reason: r.to_string(),
            })
    }

    /// The guard's name arm over a bare host, with the guard's own sentence ([`Guard::judge_name`]).
    fn judge_host(&self, host: &str, class: u32) -> Result<(), DestRefusal> {
        self.guard
            .judge_name(host, class)
            .map(|_| ())
            .map_err(|r| DestRefusal {
                verdict: r.verdict,
                reason: r.to_string(),
            })
    }

    /// A config commit re-publishes the guard's metadata lists ([`Guard::publish`]).
    fn destinations_applied(&self, d: &Destinations) {
        self.guard.publish(d);
    }
}

impl GuardJudge {
    /// The judgement [`DestJudge::judge`] and [`DestJudge::judge_reaching`] share: `reach`, the
    /// need's private reach to the destination ([`Guard::judge_name_with`]).
    fn judged(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        reach: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let (host, port, https, literal) = match self.named(dest, class, refuse_private, reach) {
            Err(v) => return Some(Err(v.into())),
            Ok(n) => n,
        };
        if let Some(ip) = literal {
            return Some(Ok((SocketAddr::new(ip, port), vec![ip])));
        }
        let guard = self.guard.clone();
        // The mapped name ([`GuardJudge::named`]): the one judged, and the one a URL client resolves.
        let name = host.clone();
        self.resolver.resolve(
            &name,
            Box::new(move |answer| {
                done(match answer {
                    // The resolver's own reason, named.
                    Err(reason) => Err(Refused {
                        verdict: DEST_UNRESOLVABLE,
                        detail: Some(reason),
                    }),
                    Ok(addrs) => guard
                        .judge_answer_with(&host, &addrs, class, refuse_private, reach)
                        .map_err(|r| Refused {
                            verdict: r.verdict,
                            detail: r.addr.map(|a| a.to_string()),
                        })
                        .and_then(|()| {
                            // All admitted, so the first is a choice between equals that keeps
                            // the resolver's own ordering.
                            plaintext_to_loopback(class, https, &host)?;
                            Ok((SocketAddr::new(addrs[0], port), addrs))
                        }),
                });
            }),
        );
        None
    }
}

/// THE DIAL JUDGE the one Connector holds (spec section 5, "Dialing only what the kernel
/// judged"): the deployment's one destination judge, every dial under the need's own egress
/// class, the address it pinned dialled exactly. A loopback-allowed need is held off the node
/// itself: a pinned loopback (or unspecified) address on one of the node's `own_ports` is refused
/// as internal, whether the judgement answered at once or after resolving a name.
#[must_use]
pub fn judge(dest: Arc<dyn DestJudge>, own_ports: &[u16]) -> Arc<dyn DialJudge> {
    Arc::new(OneJudge {
        dest,
        own: own_ports.into(),
    })
}

/// [`judge`]'s dial judge: the one destination judge and the node's own ports.
struct OneJudge {
    dest: Arc<dyn DestJudge>,
    own: Arc<[u16]>,
}

impl OneJudge {
    /// A dial judged by `judging` (the plain judgement or the reaching one), its pin held off the
    /// node itself.
    fn pinned(
        &self,
        class: u32,
        done: Judged,
        judging: impl FnOnce(Box<dyn FnOnce(Admitted) + Send>) -> Option<Admitted>,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let done: JudgedAll = Box::new(move |v, _| done(v));
        self.pinned_all(class, done, judging)
    }

    /// [`Self::pinned`], the pended answer naming the name's other admitted addresses on the same
    /// port, each held off the node as the pin is.
    fn pinned_all(
        &self,
        class: u32,
        done: JudgedAll,
        judging: impl FnOnce(Box<dyn FnOnce(Admitted) + Send>) -> Option<Admitted>,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let later = Arc::clone(&self.own);
        let pin = |v: &Admitted| v.as_ref().map(|(at, _)| *at).map_err(|r| r.verdict);
        let pended: Box<dyn FnOnce(Admitted) + Send> = Box::new(move |v| {
            let also = match &v {
                Ok((at, addrs)) => addrs
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, at.port()))
                    .filter(|a| a != at)
                    .filter(|a| not_the_node(class, &later, Ok(*a)).is_ok())
                    .collect(),
                Err(_) => Vec::new(),
            };
            done(not_the_node(class, &later, pin(&v)), also);
        });
        judging(pended).map(|v| not_the_node(class, &self.own, pin(&v)))
    }
}

impl DialJudge for OneJudge {
    fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self.pinned(class, done, |pended| {
            self.dest.judge(dest, class, false, pended)
        })
    }

    fn judge_dial_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self.pinned(class, done, |pended| {
            self.dest.judge_reaching(dest, class, pended)
        })
    }

    fn judge_dial_all(
        &self,
        dest: &str,
        class: u32,
        reach: bool,
        done: JudgedAll,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self.pinned_all(class, done, |pended| {
            if reach {
                self.dest.judge_reaching(dest, class, pended)
            } else {
                self.dest.judge(dest, class, false, pended)
            }
        })
    }

    /// The guard's name arm, the one every dial's judgement opens with ([`DestJudge::judge_name`]).
    fn judge_static(&self, dest: &str, class: u32) -> Option<Verdict> {
        self.dest.judge_name(dest, class, false).err()
    }
}

/// A loopback-allowed pin on one of the node's own ports, refused (`DEST_INTERNAL`); any other
/// judgement as it was.
fn not_the_node(
    class: u32,
    own: &[u16],
    v: Result<SocketAddr, Verdict>,
) -> Result<SocketAddr, Verdict> {
    match v {
        Ok(at)
            if class == EGRESS_LOOPBACK_ALLOWED
                && (is_loopback(at.ip()) || at.ip().is_unspecified())
                && own.contains(&at.port()) =>
        {
            Err(DEST_INTERNAL)
        }
        v => v,
    }
}

/// The ports the node listens on, read off its listen addresses (`listen`, `admin_listen`): an
/// address without a port names none.
#[must_use]
pub fn own_ports(listens: &[&str]) -> Vec<u16> {
    listens
        .iter()
        .filter_map(|l| l.rsplit_once(':').and_then(|(_, p)| p.parse().ok()))
        .collect()
}

#[cfg(test)]
#[path = "tests/process_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/dest_judge_tests.rs"]
mod dest_judge_tests;

#[cfg(test)]
#[path = "tests/collector_class_tests.rs"]
mod collector_class_tests;
