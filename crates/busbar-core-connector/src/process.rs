// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE CONNECTOR, AS THE BOOT PATH BUILDS IT (`BUSBAR-1.6.0.md` THE DESIGN, section 5

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

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
pub fn build_with_secrets(
    entries: impl FnOnce() -> Result<Vec<Entry>, String>,
    dest: Arc<dyn DestJudge>,
    own_ports: &[u16],
    wake: WakeTicket,
    pool: PoolPosture,
    spawn_secrets: crate::spawn_env::SpawnSecretFn,
) -> Result<Arc<Connector>, String> {
    let proxy = crate::proxy::from_env().map_err(|e| format!("its proxy environment: {e}"))?;
    let view = Transports::new(entries()?).map_err(|e| e.to_string())?;
    Ok(Arc::new(
        Connector::serving_with_trust(view, judge(dest, own_ports), EgressTrust::default(), wake)
            .map_err(|e| format!("its connection security: {e}"))?
            .pooling(pool)
            .proxying(proxy)
            .resolving_spawn_secrets(spawn_secrets),
    ))
}

/// THE DEPLOYMENT'S ONE DESTINATION JUDGE: its [`Guard`] over the system resolver.
pub fn dest_judge(d: &Destinations) -> Result<Arc<GuardJudge>, String> {
    Ok(Arc::new(GuardJudge::new(
        Guard::from_config(d)?,
        Arc::new(SystemResolver),
    )))
}

/// THE DESTINATION JUDGE (`busbar_kernel::host_services::DestJudge`) over the one [`Guard`]: a
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
    fn named(
        &self,
        dest: &str,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(String, u16, bool, Option<IpAddr>), u64> {
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

        let host = match url_host_to_ascii(&host) {
            Ok(dialled) => dialled.into_owned(),
            Err(_) => return Err(DEST_NO_HOST),
        };
        Ok((host, port, https, literal))
    }
}

/// Loopback-allowed's scheme rule, held once the guard admitted the destination: plaintext only to
fn plaintext_to_loopback(class: u32, https: bool, host: &str) -> Result<(), u64> {
    if class == EGRESS_LOOPBACK_ALLOWED && !https && !names_loopback(host) {
        return Err(DEST_PLAINTEXT);
    }
    Ok(())
}

/// A destination as `(host, port, https)`: an `http(s)` URL (any other scheme refused, userinfo
fn split(dest: &str) -> Result<(String, u16, bool), u64> {
    if let Some((scheme, rest)) = dest.split_once("://") {
        let lowered = format!("{}://{rest}", scheme.to_ascii_lowercase());

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

        let name = host.clone();
        self.resolver.resolve(
            &name,
            Box::new(move |answer| {
                done(match answer {
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
#[must_use]
pub fn judge(dest: Arc<dyn DestJudge>, own_ports: &[u16]) -> Arc<dyn DialJudge> {
    Arc::new(OneJudge {
        dest,
        own: Arc::new(RwLock::new(own_ports.into())),
    })
}

/// [`judge`]'s dial judge: the one destination judge and the node's own ports.
struct OneJudge {
    dest: Arc<dyn DestJudge>,
    own: Arc<RwLock<Arc<[u16]>>>,
}

impl OneJudge {
    /// A dial judged by `judging` (the plain judgement or the reaching one), its pin held off the
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
    fn pinned_all(
        &self,
        class: u32,
        done: JudgedAll,
        judging: impl FnOnce(Box<dyn FnOnce(Admitted) + Send>) -> Option<Admitted>,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let later = Arc::clone(&self.own);
        let pin = |v: &Admitted| v.as_ref().map(|(at, _)| *at).map_err(|r| r.verdict);
        let pended: Box<dyn FnOnce(Admitted) + Send> = Box::new(move |v| {
            let own = Arc::clone(&later.read().expect("own ports"));
            let also = match &v {
                Ok((at, addrs)) => addrs
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, at.port()))
                    .filter(|a| a != at)
                    .filter(|a| not_the_node(class, &own, Ok(*a)).is_ok())
                    .collect(),
                Err(_) => Vec::new(),
            };
            done(not_the_node(class, &own, pin(&v)), also);
        });
        judging(pended).map(|v| {
            let own = Arc::clone(&self.own.read().expect("own ports"));
            not_the_node(class, &own, pin(&v))
        })
    }
}

impl DialJudge for OneJudge {
    fn own_ports_applied(&self, ports: &[u16]) {
        let next: Arc<[u16]> = ports.into();
        let previous = std::mem::replace(&mut *self.own.write().expect("own ports"), next);
        drop(previous);
    }

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
