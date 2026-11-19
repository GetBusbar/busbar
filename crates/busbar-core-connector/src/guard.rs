// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DESTINATION GUARD: the one check every outbound connection asks, whatever dials it. It is

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use arc_swap::ArcSwap;

use busbar_contract::conn::codes::connector;
use busbar_contract::net::{
    embedded_ipv4, host_ip, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
    is_link_local_v6, judged_host, IpNet, METADATA_HOSTS,
};
use busbar_contract::services::codes::{
    DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST, DEST_OBFUSCATED,
};

/// THE DEFAULT POLICY, ONE TABLE: the egress classes whose dials the private address refusal holds
pub const PRIVATE_REFUSED_IN: &[u32] = &[
    connector::EGRESS_DEFAULT,
    connector::EGRESS_PROVIDER,
    connector::EGRESS_OPEN_WEB,
];

/// The loopback-allowed class: private addresses refused but loopback, and an alternate IPv4
const LOOPBACK_CLASS: u32 = connector::EGRESS_LOOPBACK_ALLOWED;

/// LOOPBACK AS 1.5.5'S COLLECTOR GUARD READ IT (v1.5.5 `crates/busbar/src/observability.rs:620-633`
#[must_use]
pub fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// A HOST WRITTEN AS LOOPBACK, as 1.5.5's collector and webrequest guards read the URL's host for
#[must_use]
pub fn names_loopback(host: &str) -> bool {
    let Some(name) = norm(host) else {
        return false;
    };
    match host_ip(&name) {
        Some(ip) => is_loopback(ip),
        None => name == "localhost" || name.ends_with(".localhost"),
    }
}

/// The classes a need whose config names its target is lifted out of, to operator infrastructure:
const LIFTED_WHEN_CONFIGURED: &[u32] = &[connector::EGRESS_DEFAULT];

/// The class a dial's address is judged under: a need's own, or (its target named by its config,
#[must_use]
pub fn judged_class(class: u32, configured: bool) -> u32 {
    let trusted = connector::EGRESS_OPERATOR_INFRASTRUCTURE;
    if configured && LIFTED_WHEN_CONFIGURED.contains(&class) {
        trusted
    } else {
        class
    }
}

/// Why the guard refused a destination: the `DEST_*` verdict, the target name, and the address
/// when an answered (or literal) address decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal<'h> {
    /// The `DEST_*` verdict (`busbar_contract::services::codes::service`).
    pub verdict: u64,
    /// The target as judged: the caller's own name, lent (a refusal copies no name).
    pub host: Refused<'h>,
    /// The address that decided it, when one did.
    pub addr: Option<IpAddr>,
}

/// What a [`Refusal`] names: the target name as the caller gave it, or (the node's own front door)
/// the address as judged. It spells exactly what the owned name spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused<'h> {
    /// The target name as judged.
    Name(&'h str),
    /// The node's own front door, by the address as judged.
    Door(SocketAddr),
}

impl<'h> From<&'h str> for Refused<'h> {
    fn from(name: &'h str) -> Self {
        Refused::Name(name)
    }
}

impl std::fmt::Display for Refused<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Name(name) => f.write_str(name),
            Refused::Door(addr) => write!(f, "{addr}"),
        }
    }
}

impl std::fmt::Display for Refusal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = &self.host;
        match (self.verdict, self.addr) {
            (DEST_METADATA, Some(a)) => write!(
                f,
                "host `{h}` resolves to the cloud-metadata address {a}; that is refused \
                 unconditionally"
            ),
            (DEST_METADATA, None) => write!(
                f,
                "host `{h}` is a cloud-metadata name; that is refused unconditionally"
            ),
            (DEST_INTERNAL, Some(a)) => write!(
                f,
                "host `{h}` resolves to the internal address {a}; enable allow_private on its upstream registration to allow it"
            ),
            (DEST_INTERNAL, None) => write!(
                f,
                "host `{h}` is a loopback name; enable allow_private on its upstream registration to allow it"
            ),
            (DEST_NO_HOST, _) => write!(
                f,
                "host `{h}` cannot be judged: it maps to no name or address a URL client would \
                 dial (UTS #46 refuses it, it holds a `%` escape outside an IPv6 zone id, or it \
                 ends in a number the guard does not read as the IPv4 address a URL client \
                 dials), so it is refused"
            ),
            (DEST_OBFUSCATED, _) => write!(
                f,
                "host `{h}` is an alternate IPv4 encoding the resolver expands; write the address \
                 in dotted-quad form so it can be checked"
            ),
            _ => write!(
                f,
                "host `{h}` resolved to no addresses at all; there is nothing to connect to and \
                 nothing to have judged"
            ),
        }
    }
}

impl std::error::Error for Refusal<'_> {}

/// One configured metadata refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entry {
    /// An exact host, lowercased, no trailing dot.
    Host(String),
    /// An IP network (a bare IP is host-length): the shared [`IpNet`] reader and matcher.
    Net(IpNet),
}

impl Entry {
    fn names(&self, host: &str) -> bool {
        match self {
            Entry::Host(h) => h == host,
            Entry::Net(..) => false,
        }
    }

    fn covers(&self, addr: IpAddr) -> bool {
        let Entry::Net(net) = self else {
            return false;
        };
        net.covers(addr)
    }
}

/// An IPv4-mapped, -compatible or NAT64 IPv6 address is its IPv4 address. The IPv6 loopback `::1`
/// is itself, not the IPv4-compatible `0.0.0.1` it would read as.
pub(crate) fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) if v6.is_loopback() => addr,
        IpAddr::V6(v6) => embedded_ipv4(&v6).map_or(addr, IpAddr::V4),
        v4 => v4,
    }
}

/// THE ONE MAPPING every name the guard compares goes through, a target's and a configured
pub(crate) fn norm(host: &str) -> Option<String> {
    judged_host(host).ok()
}

/// The 1.5.5 metadata lists one config commit states: the carve-outs (read in the provider class
/// only) and the extra refusals.
#[derive(Debug, Default)]
pub(crate) struct Metadata {
    /// `security.blocked_metadata_hosts`.
    pub(crate) blocked: Vec<Entry>,
}

/// THE GUARD, built at boot from a deployment's [`Destinations`](busbar_kernel::config::Destinations); its metadata lists are
/// re-published at every config commit ([`Guard::publish`]), and every clone reads the lists in
/// force now.
#[derive(Debug, Clone)]
pub struct Guard {
    pub(crate) block_private: bool,
    /// The 1.5.5 metadata lists in force, replaced whole at a commit.
    pub(crate) metadata: Arc<RwLock<Arc<Metadata>>>,
    /// The node's own listen ports and bound addresses, replaced whole when the boot metadata is
    /// finalised ([`Guard::publish_own`]); every clone reads the set in force now.
    pub(crate) node: Arc<ArcSwap<OwnNode>>,
}

/// A destination-policy snapshot with no mutation or publication surface.
/// The captured metadata and own-listener values cannot follow a later generation.
#[derive(Debug, Clone)]
pub struct FrozenGuard(Guard);

impl FrozenGuard {
    /// Judge the logical name using this generation's immutable policy.
    pub fn judge_name_with<'h>(
        &self,
        host: &'h str,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<Option<IpAddr>, Refusal<'h>> {
        self.0.judge_name_with(host, class, strict, reach)
    }

    /// Judge every address using this generation's immutable policy.
    pub fn judge_answer_with<'h>(
        &self,
        host: &'h str,
        addrs: &[IpAddr],
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(), Refusal<'h>> {
        self.0.judge_answer_with(host, addrs, class, strict, reach)
    }

    /// Refuse this generation's own listeners in every egress class.
    pub fn not_the_node(&self, class: u32, addr: SocketAddr) -> Result<(), Refusal<'static>> {
        self.0.not_the_node(class, addr, true)
    }
}

/// The node's own front door: every configured listener's port (`listen`, `admin_listen`, each
/// listener and media listener) and the addresses those listeners are bound to.
#[derive(Debug, Default)]
pub(crate) struct OwnNode {
    pub(crate) ports: Vec<u16>,
    pub(crate) ips: foldhash::HashSet<IpAddr>,
}

impl Default for Guard {
    /// The strict guard: private addresses refused, nothing allowed.
    fn default() -> Self {
        Guard {
            block_private: true,
            metadata: Arc::default(),
            node: Arc::default(),
        }
    }
}

impl Guard {
    /// Freeze the current metadata and own-listener policy into independent publication cells.
    /// Neither this guard nor any of its clones can mutate the returned snapshot.
    #[must_use]
    pub fn freeze(&self) -> FrozenGuard {
        FrozenGuard(Guard {
            block_private: self.block_private,
            metadata: Arc::new(RwLock::new(self.metadata())),
            node: Arc::new(ArcSwap::from(self.node.load_full())),
        })
    }

    /// Publish the node's own listen ports and the addresses its listeners are bound to (boot
    /// metadata, IF 12.1): what [`Guard::not_the_node`] refuses. Replaces the set whole.
    /// [`Guard::from_config`] writes it from the deployment's own listen addresses.
    pub fn publish_own(&self, ports: &[u16], bound: &[IpAddr]) {
        self.node
            .store(Arc::new(crate::off_path::egress::guard::own_node(
                ports, bound,
            )));
    }

    /// The node's own ports (IF 12.1): `addr` is refused `DEST_INTERNAL` when its port is one of
    /// the node's own listen ports and its IP is loopback, unspecified, or one the listeners are
    /// bound to, so no dial reaches a plane route, the admin API or another plugin's listener
    /// through core's front door. A Need dial passes `all_classes = true` (every class); core's own
    /// upstream exchanges and push deliveries pass `false` and keep today's scope, the
    /// loopback-allowed class only. The refusal names no route.
    pub fn not_the_node(
        &self,
        class: u32,
        addr: SocketAddr,
        all_classes: bool,
    ) -> Result<(), Refusal<'static>> {
        if !all_classes && class != LOOPBACK_CLASS {
            return Ok(());
        }
        let node = self.node.load();
        let ip = canonical(addr.ip());
        let own_front_door = node.ports.contains(&addr.port())
            && (is_loopback(ip) || ip.is_unspecified() || node.ips.contains(&ip));
        if own_front_door {
            // The host is the address as judged: named by value, so the refusal builds no text.
            return Err(Refusal {
                verdict: DEST_INTERNAL,
                host: Refused::Door(addr),
                addr: Some(addr.ip()),
            });
        }
        Ok(())
    }

    /// The metadata lists in force now.
    fn metadata(&self) -> Arc<Metadata> {
        Arc::clone(&self.metadata.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether a private address is refused: where `block_private_addresses` holds and the class
    fn refuses_private(&self, class: u32, strict: bool) -> bool {
        strict || (self.block_private && PRIVATE_REFUSED_IN.contains(&class))
    }

    /// Whether private address `addr` is refused in the loopback-allowed class: where
    fn refuses_off_loopback(&self, class: u32, addr: IpAddr) -> bool {
        self.block_private && class == LOOPBACK_CLASS && !is_loopback(addr)
    }

    /// The name arm, before any resolution, under egress class `class`. `Ok(Some(ip))`: the host
    pub fn judge_name<'h>(&self, host: &'h str, class: u32) -> Result<Option<IpAddr>, Refusal<'h>> {
        self.judge_name_as(host, class, false)
    }

    /// [`Guard::judge_name`], private reach refused whatever the deployment says when `strict`.
    pub fn judge_name_as<'h>(
        &self,
        host: &'h str,
        class: u32,
        strict: bool,
    ) -> Result<Option<IpAddr>, Refusal<'h>> {
        self.judge_name_with(host, class, strict, false)
    }

    /// [`Guard::judge_name_as`] for a destination its need holds a PRIVATE REACH to (`reach`, the
    pub fn judge_name_with<'h>(
        &self,
        host: &'h str,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<Option<IpAddr>, Refusal<'h>> {
        let refuse = |verdict| {
            Err(Refusal {
                verdict,
                host: Refused::Name(host),
                addr: None,
            })
        };

        let Some(name) = norm(host) else {
            return refuse(DEST_NO_HOST);
        };
        let m = self.metadata();
        let reach = reach && !strict && class != connector::EGRESS_OPEN_WEB;
        if METADATA_HOSTS.iter().any(|h| name == *h) || m.blocked.iter().any(|e| e.names(&name)) {
            return refuse(DEST_METADATA);
        }

        if is_alternate_ipv4_encoding(&name)
            && !(class == LOOPBACK_CLASS && host_ip(&name).is_some())
        {
            return refuse(DEST_OBFUSCATED);
        }
        if let Some(ip) = host_ip(&name) {
            self.judge_address(host, ip, class, strict, reach)?;
            return Ok(Some(ip));
        }

        let loopback_name = name == "localhost" || name.ends_with(".localhost");
        if loopback_name && self.refuses_private(class, strict) && !reach {
            return refuse(DEST_INTERNAL);
        }
        Ok(None)
    }

    /// The answer arm, after resolution: EVERY address `host` answered with is judged, and one
    pub fn judge_answer<'h>(
        &self,
        host: &'h str,
        addrs: &[IpAddr],
        class: u32,
    ) -> Result<(), Refusal<'h>> {
        self.judge_answer_with(host, addrs, class, false, false)
    }

    /// [`Guard::judge_answer`] for a destination its need holds a private reach to
    pub fn judge_answer_with<'h>(
        &self,
        host: &'h str,
        addrs: &[IpAddr],
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(), Refusal<'h>> {
        if addrs.is_empty() {
            return Err(Refusal {
                verdict: DEST_NO_ADDRESSES,
                host: Refused::Name(host),
                addr: None,
            });
        }
        addrs
            .iter()
            .try_for_each(|a| self.judge_address(host, *a, class, strict, reach))
    }

    /// One address `host` stands for, in the order the module header states.
    fn judge_address<'h>(
        &self,
        host: &'h str,
        addr: IpAddr,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(), Refusal<'h>> {
        let refuse = |verdict| {
            Err(Refusal {
                verdict,
                host: Refused::Name(host),
                addr: Some(addr),
            })
        };
        let Some(name) = norm(host) else {
            return refuse(DEST_NO_HOST);
        };
        let m = self.metadata();
        let metadata = ip_is_cloud_metadata(&addr);

        let link_local = matches!(canonical(addr), IpAddr::V6(v6) if is_link_local_v6(&v6));
        let listed = |l: &[Entry]| l.iter().any(|e| e.covers(addr));

        let denied = metadata
            || listed(&m.blocked)
            || METADATA_HOSTS.contains(&name.as_str())
            || m.blocked.iter().any(|e| e.names(&name));
        let admitted =
            !denied && !link_local && reach && !strict && class != connector::EGRESS_OPEN_WEB;
        if admitted {
            return Ok(());
        }
        if denied || link_local {
            return refuse(DEST_METADATA);
        }
        let refused = self.refuses_private(class, strict) || self.refuses_off_loopback(class, addr);
        if refused && ip_is_internal(&addr) {
            return refuse(DEST_INTERNAL);
        }
        Ok(())
    }
}

/// Where one resolution's answer goes: called once, from any thread. `Err` is a resolution
pub type Resolved = Box<dyn FnOnce(Result<Vec<IpAddr>, String>) + Send>;

/// A resolver that answers off the caller's thread: the guard's one resolution of a name.
pub trait Resolve: Send + Sync {
    /// Resolve `host`, answering through `done` now or later, on any thread; never blocks.
    fn resolve(&self, host: &str, done: Resolved);
}

/// The most name lookups the host keeps in flight at once.
pub const MAX_PENDING_LOOKUPS: usize = 64;

/// The system resolver, one short-lived thread per resolution, so a slow name never holds a
/// worker. Its threads are CAPPED: at most [`MAX_PENDING_LOOKUPS`] resolutions are
/// in flight at once, and one more is answered at once as a resolution failure, no thread started.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, done: Resolved) {
        resolve_capped(
            host,
            done,
            MAX_PENDING_LOOKUPS,
            &RESOLVING,
            crate::off_path::guard::system_lookup,
        );
    }
}

/// The resolutions [`SystemResolver`] has in flight.
static RESOLVING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) use crate::off_path::guard::resolve_capped;

#[cfg(test)]
#[path = "tests/guard_tests.rs"]
mod tests;
