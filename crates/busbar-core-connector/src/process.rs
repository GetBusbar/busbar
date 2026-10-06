// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE CONNECTOR, AS THE BOOT PATH BUILDS IT (`BUSBAR-1.6.0.md` THE DESIGN, section 5
//! "Connections"; section 8: the connector is the sole holder of TLS trust roots; OWNER ruling
//! DESTINATION GUARD: one destination check, in the connector, for every outbound connection).
//! [`dest_judge`] builds the deployment's one destination judge ([`GuardJudge`]: the one
//! [`Guard`], the system resolver, each egress class's scheme rule); the root hands that same judge
//! to [`build`] (the connector's dial judge, [`judge`]) and to the kernel (`dest.judge` and the
//! kernel's own clients), so every dial of every kind is judged by one guard. The root hands in
//! the deployment's values and holds what it returns; nothing here keeps a second.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB};
use busbar_contract::abi::host::service::{
    DEST_INTERNAL, DEST_NO_HOST, DEST_PLAINTEXT, DEST_SCHEME, DEST_UNRESOLVABLE,
};
use busbar_contract::transport::trust::EgressTrust;
use busbar_kernel::config::Destinations;
use busbar_kernel::host_services::{Admitted, DestJudge, DestRefusal};

use crate::guard::{Guard, Resolve, SystemResolver};
use crate::pool::PoolPosture;
use crate::registry::{Entry, Transports};
use crate::{Connector, DialJudge, Judged, Verdict, WakeTicket};

/// THE PROCESS'S CONNECTOR over the framer entries `entries` yields, judging every dial through
/// `dest` ([`judge`], the node's `own_ports` refused to a loopback-allowed need), securing a
/// connection with the default outbound trust where its target asks for it, waking a plugin's
/// ticket through `wake`, and keeping a dialled connection whose exchange finished whole under the
/// deployment's `pool` posture ([`crate::pool`]). The trust is built before `entries` is asked for,
/// so a boot that cannot secure a connection loads no transport door.
///
/// # Errors
///
/// The default outbound trust will not build, `entries` refuses, two entries claim one scheme, or
/// an entry states no claim.
pub fn build(
    entries: impl FnOnce() -> Result<Vec<Entry>, String>,
    dest: Arc<dyn DestJudge>,
    own_ports: &[u16],
    wake: WakeTicket,
    pool: PoolPosture,
) -> Result<Arc<Connector>, String> {
    let tls = crate::tls::client::build_client_config(&EgressTrust::default())
        .map_err(|e| format!("its connection security: {e}"))?;
    let view = Transports::new(entries()?).map_err(|e| e.to_string())?;
    Ok(Arc::new(
        Connector::serving(view, judge(dest, own_ports), Some(Arc::new(tls)), wake).pooling(pool),
    ))
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
    /// is one.
    fn named(&self, dest: &str, class: u32) -> Result<(String, u16, bool, Option<IpAddr>), u64> {
        // The classes a need may declare are 0..=4; a destination under any other names none.
        if class > EGRESS_LOOPBACK_ALLOWED {
            return Err(DEST_NO_HOST);
        }
        let (host, port, https) = split(dest)?;
        if !https && class == EGRESS_OPEN_WEB {
            return Err(DEST_PLAINTEXT);
        }
        let literal = self.guard.judge_name(&host, class).map_err(|r| r.verdict)?;
        if let Some(ip) = literal {
            plaintext_to_loopback(class, https, ip)?;
        }
        Ok((host, port, https, literal))
    }
}

/// Loopback-allowed's scheme rule over a pinned address: plaintext to loopback only.
fn plaintext_to_loopback(class: u32, https: bool, ip: IpAddr) -> Result<(), u64> {
    if class == EGRESS_LOOPBACK_ALLOWED && !https && !ip.is_loopback() {
        return Err(DEST_PLAINTEXT);
    }
    Ok(())
}

/// A destination as `(host, port, https)`: an `http(s)` URL (any other scheme refused, userinfo
/// refused), or a bare `host[:port]` authority (secure, port 443 unless named).
fn split(dest: &str) -> Result<(String, u16, bool), u64> {
    if dest.contains("://") {
        // The one http(s) URL reader (scheme allowlist, userinfo refused, the scheme's port).
        return match busbar_kernel::net_guard::split_url(dest) {
            Ok((https, host, port, _)) => Ok((host, port, https)),
            Err(busbar_kernel::net_guard::AddressRefusal::Scheme { .. }) => Err(DEST_SCHEME),
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
    fn judge_name(&self, dest: &str, class: u32) -> Result<(), u64> {
        self.named(dest, class).map(|_| ())
    }

    fn judge(
        &self,
        dest: &str,
        class: u32,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        let (host, port, https, literal) = match self.named(dest, class) {
            Err(v) => return Some(Err(v)),
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
                    Err(_) => Err(DEST_UNRESOLVABLE),
                    Ok(addrs) => guard
                        .judge_answer(&host, &addrs, class)
                        .map_err(|r| r.verdict)
                        .and_then(|()| {
                            // All admitted, so the first is a choice between equals that keeps
                            // the resolver's own ordering.
                            plaintext_to_loopback(class, https, addrs[0])?;
                            Ok((SocketAddr::new(addrs[0], port), addrs))
                        }),
                });
            }),
        );
        None
    }

    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal> {
        self.guard
            .judge_answer(host, addrs, class)
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

/// THE DIAL JUDGE the one Connector holds (spec section 5, "Dialing only what the kernel
/// judged"): the deployment's one destination judge, every dial under the need's own egress
/// class, the address it pinned dialled exactly. A loopback-allowed need is held off the node
/// itself: a pinned loopback (or unspecified) address on one of the node's `own_ports` is refused
/// as internal, whether the judgement answered at once or after resolving a name.
#[must_use]
pub fn judge(dest: Arc<dyn DestJudge>, own_ports: &[u16]) -> Arc<dyn DialJudge> {
    let own: Arc<[u16]> = own_ports.into();
    Arc::new(move |target: &str, class: u32, done: Judged| {
        let later = Arc::clone(&own);
        let pin = |v: Admitted| v.map(|(at, _)| at);
        let pended: Box<dyn FnOnce(Admitted) + Send> =
            Box::new(move |v| done(not_the_node(class, &later, pin(v))));
        dest.judge(target, class, pended)
            .map(|v| not_the_node(class, &own, pin(v)))
    })
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
                && (at.ip().is_loopback() || at.ip().is_unspecified())
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
