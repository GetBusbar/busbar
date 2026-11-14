// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// busbar:request-path
#![cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]

//! `busbar-core-connector` — THE CONNECTOR (THE DESIGN: connections). The chain is kernel →

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod carrier;
#[expect(
    unsafe_code,
    reason = "the child job's OS calls (process groups, job objects) are FFI"
)]
pub mod child_job;
pub mod compose;
pub mod datagram;
mod dialled;
pub mod doors;
pub mod egress_audit;
pub mod dtls;
pub mod endpoint;
pub mod fetch;
pub mod framed_stream;
pub mod framer;
pub mod guard;
pub mod hostio;
pub mod io;
mod line;
pub mod listen;
pub mod pool;
pub mod process;
mod program;
pub mod proxy;
pub mod proxy_route;
pub mod publication;
pub mod registry;
pub(crate) mod seal;
pub mod secure_vec;
pub mod socket;
pub mod spawn_env;
/// The TLS test kit (far ends, the recording TLS fixture server, a private test CA) for this crate's
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub mod udp;
pub mod wire;

use foldhash::{HashMap, HashMapExt as _, HashSet, HashSetExt as _};
use std::collections::VecDeque;
use std::future::Future as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::host::service::{DEST_NO_ADDRESSES, DEST_UNRESOLVABLE};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};
use busbar_contract::conn::{
    Bytes, ConnCause, ConnError, ConnId, ConnSlab, Conns, DeclaredConns, HeadDefaults, InstanceId,
    NeedId, NeedRefusal, OpenDesc, Piece, PieceKind, PollConns, Ticket, NO_TICKET,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_contract::transport::ConnFacts;

use crate::compose::{
    Connection, Dial, Failure, Hop, Planned, Via, DEFAULT_OPEN_TIMEOUT, EXCHANGE_STREAM,
    WRITE_BUFFER_BYTES,
};
use crate::framer::FramerDoor;
use crate::hostio::HostIo;
use crate::line::{Line, EVERY};
use crate::listen::{AcceptLimits, Listening};
use crate::pool::{PoolKey, PoolPosture, Pools, Same};
use crate::registry::Transports;

/// How the host wakes a caller's ticket, naming the caller that handed it the ticket: the supplier
pub type WakeTicket = busbar_contract::conn::ConnWake;

/// A `DEST_*` verdict (`busbar_contract::abi::host::service`) refusing a dial.
pub type Verdict = u64;

/// Where a pended judgement goes: the address to dial, or the verdict refusing it. Called once,
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, Verdict>) + Send>;

/// Where a pended judgement goes with the name's OTHER admitted addresses, in the resolver's order:
pub type JudgedAll = Box<dyn FnOnce(Result<SocketAddr, Verdict>, Vec<SocketAddr>) + Send>;

/// A need's `egress_class` `0`: the connector's default class (`busbar_contract::abi::host::conn::
pub const DEFAULT_CLASS: u32 = 0;

/// THE KERNEL'S DESTINATION JUDGE, as a dial reaches it (`dest.judge`, R-K): every authority the
pub trait DialJudge: Send + Sync {
    /// Judge a transport-located authority with independent security intent and egress class.
    fn judge_target_all(
        &self,
        target: busbar_kernel::host_services::Destination<'_>,
        reach: bool,
        done: JudgedAll,
    ) -> Option<Result<SocketAddr, Verdict>> {
        if !scheme_admits(target.egress_class, target.secure) {
            return Some(Err(busbar_contract::abi::host::service::DEST_PLAINTEXT));
        }
        self.judge_dial_all(target.authority, target.egress_class, reach, done)
    }

    /// Static policy for an explicit transport destination.
    fn judge_target_static(
        &self,
        target: busbar_kernel::host_services::Destination<'_>,
    ) -> Option<Verdict> {
        if !scheme_admits(target.egress_class, target.secure) {
            return Some(busbar_contract::abi::host::service::DEST_PLAINTEXT);
        }
        self.judge_static(target.authority, target.egress_class)
    }

    /// Replace the bootstrap listener-port metadata before the effective plugins open.
    fn own_ports_applied(&self, _ports: &[u16]) {}

    /// Judge `dest` (`host:port`) under egress class `class`.
    fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>>;

    /// [`DialJudge::judge_dial`] for a destination the dialling need holds a PRIVATE REACH to (the
    fn judge_dial_reaching(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self.judge_dial(dest, class, done)
    }

    /// [`DialJudge::judge_dial`] (with the need's private reach when `reach`) whose pended answer
    fn judge_dial_all(
        &self,
        dest: &str,
        class: u32,
        reach: bool,
        done: JudgedAll,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let done: Judged = Box::new(move |v| done(v, Vec::new()));
        if reach {
            self.judge_dial_reaching(dest, class, done)
        } else {
            self.judge_dial(dest, class, done)
        }
    }

    /// THE STATIC ARM ALONE: the refusal `dest` (`host:port`) meets under class `class` before any
    fn judge_static(&self, dest: &str, class: u32) -> Option<Verdict> {
        let _ = (dest, class);
        None
    }
}

/// Any function of the judge's shape is a judge: [`process::judge`] joins the deployment's one
impl<F> DialJudge for F
where
    F: Fn(&str, u32, Judged) -> Option<Result<SocketAddr, Verdict>> + Send + Sync,
{
    fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        self(dest, class, done)
    }
}

/// The longest text an [`IpAddr`] displays as (an IPv6 address with an embedded IPv4 tail).
pub(crate) const IP_TEXT: usize = 46;

/// The longest text a [`SocketAddr`] displays as (`[` IPv6 `%` scope `]:` port).
pub(crate) const SOCKET_TEXT: usize = 64;

/// A value's display text, written into a fixed buffer on the stack: the text of an address the
/// connector hands on as `&str`, without a `String` per call. Text past `N` bytes is cut short
/// (the address texts it is sized for never are).
#[derive(Clone, Copy)]
pub(crate) struct StackText<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> std::fmt::Debug for StackText<N> {
    /// As the text's own `str` shows.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize> StackText<N> {
    /// `value`'s display text.
    pub(crate) fn of(value: &dyn std::fmt::Display) -> Self {
        use std::fmt::Write as _;
        let mut text = Self {
            buf: [0; N],
            len: 0,
        };
        let _ = write!(text, "{value}");
        text
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
    }
}

impl<const N: usize> std::fmt::Write for StackText<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        let into = self.buf.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        into.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The judge a connector built with none holds: an IP literal is its own address, judged by the
pub(crate) struct LiteralsOnly(pub(crate) guard::Guard);

impl DialJudge for LiteralsOnly {
    fn judge_dial(&self, dest: &str, class: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
        let Some(at) = socket::address_of(dest) else {
            return Some(Err(busbar_contract::abi::host::service::DEST_UNRESOLVABLE));
        };
        let host = StackText::<IP_TEXT>::of(&at.ip());
        Some(
            self.0
                .judge_answer(host.as_str(), &[at.ip()], class)
                .map(|()| at)
                .map_err(|r| r.verdict),
        )
    }

    fn judge_dial_reaching(
        &self,
        dest: &str,
        class: u32,
        _: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let Some(at) = socket::address_of(dest) else {
            return Some(Err(busbar_contract::abi::host::service::DEST_UNRESOLVABLE));
        };
        let host = StackText::<IP_TEXT>::of(&at.ip());
        Some(
            self.0
                .judge_answer_with(host.as_str(), &[at.ip()], class, false, true)
                .map(|()| at)
                .map_err(|r| r.verdict),
        )
    }
}

/// THE SCHEME RULE OF A NEED'S EGRESS CLASS (`abi::host::conn::connector`, `EGRESS_*`), held
fn scheme_admits(egress_class: u32, secure: bool) -> bool {
    egress_class != EGRESS_OPEN_WEB || secure
}

///
/// THE ONE PLAINTEXT RULE (every class): a dial that is not secured from its first byte is admitted
/// only to loopback (by name or by the judged address) or to a destination an exact
/// `advanced.tls.destinations` entry admits plaintext to (`plain_admitted`, which a carrier that
/// upgrades later also carries: its cleartext window is held on the connection instead,
/// [`compose::Connection::hold_clear_window`]). `open-web` never admits plaintext.
fn class_admits(
    egress_class: u32,
    secure: bool,
    plain_admitted: bool,
    within: &[IpAddr],
    authority: &str,
    addr: SocketAddr,
) -> bool {
    (within.is_empty() || within.contains(&addr.ip()))
        && match egress_class {
            EGRESS_OPEN_WEB => secure,
            _ => {
                secure
                    || plain_admitted
                    || addr.ip().is_loopback()
                    || guard::names_loopback(&host_of(authority))
            }
        }
}

/// WHAT A JUDGEMENT THAT PENDED ON A RESOLUTION ANSWERS THE CONNECTION'S CALLER. A name that did
fn pended_verdict(v: Verdict) -> ConnError {
    match v {
        DEST_UNRESOLVABLE | DEST_NO_ADDRESSES => ConnError::Fault,
        _ => ConnError::Refused,
    }
}

/// THE REFUSAL TEXTS (host-only, [`NeedRefusal`]): static, naming no hop (the renderer names it)
/// and only keys the operator can set.
mod refusal_text {
    /// The URL carries userinfo.
    pub(crate) const CREDENTIALED: &str =
        "the URL carries userinfo; busbar never sends credentials embedded in a URL";
    /// No loaded transport serves the need's scheme.
    pub(crate) const UNSERVED: &str = "busbar serves no transport for the URL's scheme";
    /// The target is malformed or not located by its transport.
    pub(crate) const UNLOCATED: &str = "the target is not a host busbar can dial";
    /// The need names a target or trust the configuration does not provide.
    pub(crate) const UNRESOLVED: &str =
        "the need names a target or trust anchors the configuration does not provide";
    /// The operator's trust anchors for the target could not be loaded.
    pub(crate) const TRUST: &str =
        "the trust anchors configured for the target could not be loaded";
    /// Plaintext to a destination whose class asks for connection security.
    pub(crate) const PLAINTEXT: &str = "plaintext is not admitted to this destination";
    /// None of the above.
    pub(crate) const CHECKS: &str = "the connector's own checks refused the target";
}

/// A guard verdict in words (never `guard::Refusal`'s Display: its catch-all and the operator's
/// blocked list would be misnamed).
const fn verdict_text(v: Verdict) -> &'static str {
    use busbar_contract::abi::host::service::{
        DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED, DEST_PLAINTEXT, DEST_SCHEME,
    };
    match v {
        DEST_METADATA => {
            "the destination guard refuses a cloud-metadata host or a host listed in \
             security.blocked_metadata_hosts"
        }
        DEST_INTERNAL => {
            "the destination guard refuses an internal or loopback address (list it in \
             advanced.allow_destinations to allow it)"
        }
        DEST_OBFUSCATED => {
            "the destination guard refuses an alternate IPv4 spelling; write the address in \
             dotted-quad form"
        }
        DEST_NO_HOST => "the destination guard cannot judge the host, so it refuses it",
        DEST_PLAINTEXT => refusal_text::PLAINTEXT,
        DEST_SCHEME => "the destination guard does not admit the scheme",
        DEST_UNRESOLVABLE => "the name did not resolve",
        DEST_NO_ADDRESSES => "the name resolved to no addresses",
        _ => refusal_text::CHECKS,
    }
}

/// A guard verdict on the target (or, with `proxy`, the operator's egress proxy) as a reason: a
/// name that did not resolve is the path, never policy.
fn verdict_reason(v: Verdict, proxy: bool) -> NeedRefusal {
    let text = verdict_text(v);
    match (unresolved_here(v), proxy) {
        (true, false) => NeedRefusal::Unreached(text.to_owned()),
        (true, true) => NeedRefusal::ProxyUnreached(text.to_owned()),
        (false, false) => NeedRefusal::Policy(text),
        (false, true) => NeedRefusal::ProxyPolicy(text),
    }
}

/// A dial's failure on the target (or, with `proxy`, the hop to the operator's egress proxy) as a
/// reason: always the path, whatever the failure says.
fn unreached(f: &Failure, proxy: bool) -> NeedRefusal {
    let text = match f {
        Failure::Refused(t) | Failure::Failed(t) => t.clone(),
        Failure::Timeout => "the dial timed out".to_owned(),
        Failure::Closed | Failure::Pending => "the connection closed during the dial".to_owned(),
    };
    if proxy {
        NeedRefusal::ProxyUnreached(text)
    } else {
        NeedRefusal::Unreached(text)
    }
}

/// Caller-owned request fields cannot set framing or override host-held authority.
fn head_is_refused(desc: &OpenDesc<'_>, authority_held: bool) -> bool {
    const FRAMING: [&str; 2] = ["content-length", "transfer-encoding"];
    const AUTHORITY: &str = "host";
    let breaks = |b: &[u8]| b.iter().any(|c| matches!(c, b'\r' | b'\n' | b'\0'));
    breaks(desc.target.as_bytes())
        || breaks(desc.method)
        || breaks(desc.head_target)
        || desc.fields.iter().any(|(name, value)| {
            let name_is = |f: &str| name.trim().eq_ignore_ascii_case(f);
            breaks(name.as_bytes())
                || breaks(value)
                || FRAMING.iter().any(|f| name_is(f))
                || (authority_held && name_is(AUTHORITY))
        })
}

/// The opening's fields: the head the opener built and moved in ([`Conns::open_owned`]), kept as
/// it is; else a copy of the borrowed head an opener lent.
fn opening_fields(fields: &[(&str, &[u8])], owned: Option<OwnedHead>) -> Vec<(String, Vec<u8>)> {
    if let Some(owned) = owned {
        return owned.into_fields();
    }
    busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::OutboundHead);
    fields
        .iter()
        .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
        .collect()
}

/// Host defaults remain in the signed wire head, but cannot authorize caller framing fields.
fn request_head_is_refused(
    caller: InstanceId,
    need: NeedId,
    desc: &OpenDesc<'_>,
    authority_held: bool,
) -> bool {
    let Some(completed) = desc.completed_head else {
        return head_is_refused(desc, authority_held);
    };
    let Some(count) = completed.caller_field_count(caller, need, desc) else {
        return true;
    };
    let caller_head = OpenDesc {
        fields: &desc.fields[..count],
        completed_head: None,
        ..desc.clone()
    };
    head_is_refused(&caller_head, authority_held)
}

/// What the connector holds for one declared need: the entry serving its transport, resolved once
/// at declare (a need no entry serves is refused there, never at its open).
#[derive(Clone)]
struct DeclaredNeed {
    door: Arc<dyn FramerDoor>,
    /// The protocols the serving entry offers in the TLS handshake.
    alpn: Vec<Vec<u8>>,
    egress_class: u32,
    /// The target the need's `target_from` resolved to; `None` = the plugin names it per open.
    declared_target: Option<Arc<str>>,
    /// The need's own client config, when its `trust_from` named an operator CA: the public roots
    /// with that CA added on top (spec section 5, the host connector: "an extra trusted root added
    /// on top of the public roots, as in 1.5.5"); `None` = the connector's default trust.
    tls: Option<Arc<rustls::ClientConfig>>,
    tls_policy: Option<busbar_contract::transport::trust::EgressTrust>,
    /// The program the need's `target_from` resolved to, its environment references held as its
    /// declaration resolved them: every open spawns it.
    program: Option<(busbar_contract::conn::Program, spawn_env::HeldEnv)>,
    /// A member-program need's members (`busbar_contract::section::MEMBER_PROGRAM`): every open
    /// names one and leases its one long-lived program connection.
    members: Option<Arc<program::Members>>,
    member_spec: Option<ReadNeed>,
}

/// A judgement's answer once it came, and the waker of the read or wait that found none.
type Answer = Arc<
    Mutex<(
        Option<Result<SocketAddr, Verdict>>,
        Option<Waker>,
        Vec<SocketAddr>,
    )>,
>;

/// The trust anchors sealed per destination (the transport pin), by the need's owner, the need and
type Anchored = Mutex<HashMap<(InstanceId, NeedId, String), Arc<tls::client::Sealed>>>;

/// THE REGISTRATIONS' SEALS AT ONE DESTINATION: each registration's seal at its authority, by name
/// (`None`: it holds no anchors), in name order. An open naming no registration sealed there is held
/// to the one answer they and the destination's own seal all give, and refused where they disagree:
/// a pin nobody enforces is refused, never dropped, and no registration's anchors are erased by
/// another's.
#[derive(Default)]
struct Registered {
    members: std::collections::BTreeMap<String, Option<Arc<tls::client::Sealed>>>,
}

impl Registered {
    /// What an open naming no registration is held to, with the destination's `own` seal: the one
    fn held(
        &self,
        own: Option<&Arc<tls::client::Sealed>>,
    ) -> Result<Option<Arc<tls::client::Sealed>>, ConnError> {
        let mut seals = own
            .into_iter()
            .map(Some)
            .chain(self.members.values().map(Option::as_ref));
        let Some(first) = seals.next() else {
            return Ok(None);
        };
        if seals.all(|other| same_anchors(first, other)) {
            Ok(first.cloned())
        } else {
            Err(ConnError::Refused)
        }
    }
}

/// Whether two seals hold a connection to the same: the same key pin and the same client identity
fn same_anchors(
    a: Option<&Arc<tls::client::Sealed>>,
    b: Option<&Arc<tls::client::Sealed>>,
) -> bool {
    let pins = a.and_then(|s| s.key_pin.as_deref()) == b.and_then(|s| s.key_pin.as_deref());
    let identities = match (
        a.and_then(|s| s.identity.as_deref()),
        b.and_then(|s| s.identity.as_deref()),
    ) {
        (None, None) => true,
        (Some(x), Some(y)) => x.cert == y.cert,
        _ => false,
    };
    let roots = a.map(|s| s.extra_anchors.as_slice()).unwrap_or_default()
        == b.map(|s| s.extra_anchors.as_slice()).unwrap_or_default();
    pins && identities && roots
}

/// The trust anchors sealed per REGISTRATION, by the need's owner, the need and the registration's
type MemberAnchored = Mutex<ByMember<(String, Option<Arc<tls::client::Sealed>>)>>;

/// What is held per registration: by the need's owner, then the need, then the registration's
/// name, so a lookup borrows the name and an owner's entries go with it in one removal.
struct ByMember<V>(HashMap<InstanceId, HashMap<NeedId, HashMap<String, V>>>);

impl<V> Default for ByMember<V> {
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<V> ByMember<V> {
    fn get(&self, owner: InstanceId, need: NeedId, member: &str) -> Option<&V> {
        self.0.get(&owner)?.get(&need)?.get(member)
    }

    /// Hold `value` for `member` (its name is kept: a registration is sealed at declaration).
    fn insert(&mut self, owner: InstanceId, need: NeedId, member: &str, value: V) -> Option<V> {
        let members = self.0.entry(owner).or_default().entry(need).or_default();
        if let Some(held) = members.get_mut(member) {
            return Some(std::mem::replace(held, value));
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a registration's name is kept once, when it is first sealed"
        )]
        let name = member.to_owned();
        members.insert(name, value)
    }

    fn remove(&mut self, owner: InstanceId, need: NeedId, member: &str) -> Option<V> {
        self.0.get_mut(&owner)?.get_mut(&need)?.remove(member)
    }

    /// Every entry `owner` holds goes.
    fn forget(&mut self, owner: InstanceId) {
        self.0.remove(&owner);
    }
}

/// What a member's auth binding is held under: the need's owner, the need, the registration's
/// key and origin: by owner, then need, then member, then origin, so a lookup borrows its names and
/// an owner's bindings go with it in one removal.
type Auths = HashMap<
    InstanceId,
    HashMap<NeedId, HashMap<String, HashMap<String, busbar_contract::conn::ConnAuth>>>,
>;

/// The listeners, one per inbound need, by the need's owner and need.
type Listeners = Mutex<HashMap<(InstanceId, NeedId), Arc<Accepting>>>;

/// ONE INBOUND LISTENER, driven under no lock (`BUSBAR-1.6.0.md` §11: no plugin code runs under a
/// host lock): an accept takes the listener out, crosses the carrier's `accept` (and closes a
/// connection past the cap) with nothing held, and puts it back. An accept that finds it out
/// (another accept has it, or its bind is still crossing) answers PENDING, woken when it is back.
#[derive(Default)]
struct Accepting {
    /// The listener while no accept has it out, and the accepts that found it out.
    slot: Mutex<(Option<Listening>, Vec<Waker>)>,
}

impl Accepting {
    /// Take the listener out; `None` (with `waker` woken once it is back) while it is out.
    fn take(&self, waker: &Waker) -> Option<Listening> {
        let mut slot = self.slot.lock().expect("listener");
        let taken = slot.0.take();
        if taken.is_none() && !slot.1.iter().any(|w| w.will_wake(waker)) {
            slot.1.push(waker.clone());
        }
        taken
    }

    /// Put `listening` back (`None`: it is gone), waking every accept that found it out.
    fn put(&self, listening: Option<Listening>) {
        let waiting = {
            let mut slot = self.slot.lock().expect("listener");
            slot.0 = listening;
            std::mem::take(&mut slot.1)
        };
        for w in waiting {
            w.wake();
        }
    }
}

/// A listener an accept has out: put back however the accept ends, an unwind included.
struct AcceptingOut<'a> {
    home: &'a Accepting,
    listening: Option<Listening>,
}

impl Drop for AcceptingOut<'_> {
    fn drop(&mut self) {
        if let Some(l) = self.listening.take() {
            self.home.put(Some(l));
        }
    }
}

/// The address set a pended dial's pinned address must be in, held inline for the usual few.
type Within = smallvec::SmallVec<[IpAddr; 4]>;

/// A dial whose judgement pended, retained until its accepted writes reach the line. `planned`
struct Judging {
    planned: Option<Planned>,
    /// A spent dial or replay's terminal error, retained for every poll until close.
    failed: Option<ConnError>,
    /// The need's egress class, whose scheme rule the pinned address is held to.
    egress_class: u32,
    /// The address set the pinned address must be in (`OpenDesc::within`); empty = any.
    within: Within,
    /// Writes the caller made before the dial, in order.
    early: VecDeque<(Bytes, bool, bool)>,
    answer: Answer,
    /// A dial through a proxy ([`proxy`]): the proxy, and whether the target's own judgement has
    proxied: Option<Proxied>,
}

/// A dial through a proxy, judged in two steps: the target (its name arm, and its own resolution
struct Proxied {
    spec: Arc<proxy::ProxyHop>,
    target_judged: bool,
    /// The address the guard judged for the target, when it resolved here: under
    /// `advanced.proxy_resolution: local` (the default) the CONNECT names it, so what the guard
    /// judged is what the proxy dials.
    target_at: Option<SocketAddr>,
}

/// Whether a target judgement's refusal is only that the name does not resolve HERE: behind a
fn unresolved_here(verdict: Verdict) -> bool {
    verdict == DEST_UNRESOLVABLE || verdict == DEST_NO_ADDRESSES
}

/// What an exchange lent a pooled line keeps to redial it ONCE on a fresh connection when that line
struct Redial {
    door: Arc<dyn FramerDoor>,
    dial: Dial,
    egress_class: u32,
    judged_class: u32,
    require_secure: bool,
    /// The need's private reach to the destination ([`DialJudge::judge_dial_reaching`]).
    reach: bool,
    /// The bytes the line's socket had taken when the exchange was lent it.
    mark: u64,
}

/// A HELD CONNECTION'S DIAL OR REPLAY, CROSSING WITH NO LOCK HELD (`BUSBAR-1.6.0.md` §11: no plugin code
struct Crossing<'h> {
    held: &'h Held,
}

impl<'h> Crossing<'h> {
    /// The dial of `held` begins crossing; `judging` (its spent judgement's lock) is let go.
    fn begin(held: &'h Held, judging: std::sync::MutexGuard<'_, Option<Judging>>) -> Self {
        *held.crossing.lock().expect("crossing") = Some(Vec::new());
        drop(judging);
        Self { held }
    }

    /// Keep the crossing's failure before releasing its callers to read it. A consumed plan
    fn finish(self, result: Result<bool, ConnError>) -> Result<bool, ConnError> {
        if let Err(error) = result {
            if error != ConnError::Pending {
                self.held
                    .fail(self.held.judging.lock().expect("judging"), error);
            }
        }
        result
    }
}

impl Drop for Crossing<'_> {
    fn drop(&mut self) {
        let waiting = self
            .held
            .crossing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap_or_default();
        for w in waiting {
            w.wake();
        }
    }
}

/// A piece a short caller buffer left, and its unread bytes.
type Left = (Piece, Vec<u8>);

/// What a short caller buffer left of a piece (the piece and its unread bytes), and whether the
/// end was answered.
#[derive(Default)]
struct Rest {
    piece: Option<Left>,
    ended: bool,
    /// A read (or an upgrade) has the rest out.
    reading: bool,
    /// The reads that found it out, woken when it is back.
    missed: Vec<Waker>,
}

/// ONE READ HAS THE REST (`BUSBAR-1.6.0.md` §11: no plugin code runs under a host lock): taken
struct Reading<'h> {
    rest: &'h Mutex<Rest>,
    /// The end was answered.
    ended: bool,
    /// What a short buffer left, for the next read.
    left: Option<Left>,
}

impl<'h> Reading<'h> {
    /// Take the rest for one read: what a short buffer left, and whether the end was answered.
    fn begin(rest: &'h Mutex<Rest>, waker: &Waker) -> Option<(Self, Option<Left>)> {
        let incoming = waker.clone();
        let mut r = rest.lock().expect("rest");
        if r.reading {
            if !r.missed.iter().any(|w| w.will_wake(waker)) {
                r.missed.push(incoming);
            }
            return None;
        }
        r.reading = true;
        let kept = r.piece.take();
        let ended = r.ended;
        Some((
            Self {
                rest,
                ended,
                left: None,
            },
            kept,
        ))
    }
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        let missed = {
            let mut r = self
                .rest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            r.reading = false;
            r.ended |= self.ended;
            if let Some(left) = self.left.take() {
                r.piece = Some(left);
            }
            std::mem::take(&mut r.missed)
        };
        for w in missed {
            w.wake();
        }
    }
}

/// One connection the connector holds for its owner: the line it rides and the stream it reads
struct Held {
    /// A request reserved on this connection but not yet committed.
    prepared: Mutex<Option<(String, String, std::time::Instant)>>,
    /// Blocks application I/O until the prepared request has committed successfully.
    uncommitted: AtomicBool,
    line: Mutex<Option<(Arc<Line>, u64)>>,
    /// Closed while a dial or replay may still have this state out. Published with `line` locked.
    retired: AtomicBool,
    /// The judgement the dial waits on; `None` once dialled.
    judging: Mutex<Option<Judging>>,
    /// THE DIAL IS CROSSING (`Some`, with the callers waiting on it): its judgement is spent and
    crossing: Mutex<Option<Vec<Waker>>>,
    /// The piece a short caller buffer left, and whether the end was answered: the reading
    rest: Mutex<Rest>,
    /// The far end's reason phrase, held until its head's last piece is read.
    reason: Mutex<Option<Vec<u8>>>,
    /// Where a dialled connection goes back to when its exchange finished whole: its pool shard
    pooled: Option<(usize, PoolKey)>,
    /// The dialled exchange ended WHOLE (its stream's end was read).
    whole: AtomicBool,
    /// The one redial an exchange lent a pooled line keeps.
    redial: Mutex<Option<Redial>>,
    /// A LEASE on a member's long-lived program connection, in place of a connection of its own.
    lease: Option<(Arc<program::Member>, u64)>,
    /// THE REQUEST'S WHOLE BOUND until its answer (`OpenDesc::timeout_ms`; `None` = unbounded
    due: Mutex<Option<Due>>,
    /// The dial's original bound, including a pended judgement, independent of the request.
    dial_due: Mutex<Option<Due>>,
    /// The caller-selected dial bound, also used for a later security handshake.
    open_timeout: Duration,
    /// A held session's UPSTREAM LEG over a datagram framer's need ([`dialled`]): its exchange
    dialled: Option<dialled::Dialled>,
    /// WHY THE CONNECTION FAILED BEFORE A LINE EXISTED (host-only, [`NeedRefusal`]): the first
    /// terminal reason its judgement or dial met.
    why: std::sync::OnceLock<NeedRefusal>,
}

/// The instant a request's `timeout_ms` (the plugin's own number, unclamped: `RequestPiece` and
fn due_at(now: std::time::Instant, timeout_ms: u64) -> Option<std::time::Instant> {
    if timeout_ms == 0 {
        return None;
    }
    now.checked_add(Duration::from_millis(timeout_ms))
}

/// THE WHOLE REQUEST'S BOUND (`RequestPiece::timeout_ms`, BUSBAR-1.6.0.md:4890 "timeout clamped to
/// the deadline class"; the `call` class, :3496-3505): from the open, through the dial, the
/// judgement, the handshake and the send, until the far end's FIRST piece of its answer. Past it a
/// read is answered [`ConnError::Timeout`], and a reader waiting on the connection is woken to read
/// it. Once an answer has begun the bound is spent: what bounds a streamed answer is its own class,
/// as its reader keeps it, never this one (an answer cut mid-stream by a time-to-answer bound would
/// be a different outcome from the one the reader chose).
#[derive(Clone)]
struct Due {
    at: std::time::Instant,
    timer: Arc<std::sync::OnceLock<Mutex<Option<DeadlineTimer>>>>,
    wake: Arc<DeadlineWake>,
}

type DeadlineTimer = std::pin::Pin<Box<tokio::time::Sleep>>;

#[derive(Clone, Copy)]
enum DeadlineInterest {
    Ticket(Ticket),
    Task,
}

#[derive(Default)]
struct DeadlineWaiters {
    tickets: HashMap<Ticket, Waker>,
    tasks: Vec<Waker>,
}

#[derive(Default)]
struct DeadlineWake {
    cancelled: AtomicBool,
    waiters: Mutex<DeadlineWaiters>,
}

impl DeadlineWake {
    fn register(&self, interest: DeadlineInterest, waker: &Waker) {
        if matches!(interest, DeadlineInterest::Ticket(NO_TICKET)) {
            return;
        }

        let mut fresh = Some(waker.clone());
        let previous = {
            let mut waiters = self.waiters.lock().expect("deadline waiters");
            if self.cancelled.load(Ordering::Acquire) {
                None
            } else {
                match interest {
                    DeadlineInterest::Ticket(ticket) => {
                        waiters.tickets.insert(ticket, fresh.take().unwrap())
                    }
                    DeadlineInterest::Task => {
                        if !waiters.tasks.iter().any(|old| old.will_wake(waker)) {
                            waiters.tasks.push(fresh.take().unwrap());
                        }
                        None
                    }
                }
            }
        };
        drop(previous);
        drop(fresh);
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let waiters = std::mem::take(&mut *self.waiters.lock().expect("deadline waiters"));
        drop(waiters);
    }
}

impl Wake for DeadlineWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.waiters.lock().expect("deadline waiters"));
        for waker in waiters.tickets.into_values().chain(waiters.tasks) {
            waker.wake();
        }
    }
}

impl Due {
    fn new(at: std::time::Instant) -> Self {
        Self {
            at,
            timer: Arc::default(),
            wake: Arc::default(),
        }
    }

    fn cancel(&self) {
        self.wake.cancel();
        let timer = self
            .timer
            .get()
            .and_then(|slot| slot.lock().expect("deadline timer").take());
        drop(timer);
    }

    /// Poll the one timer outside every host guard. Copies retain one clock across polls.
    fn check(&self) -> Result<(), ConnError> {
        if self.wake.cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        if framer::now() >= self.at {
            return Err(ConnError::Timeout);
        }
        let _entered = crate::io::enter_process_runtime();
        if tokio::runtime::Handle::try_current().is_ok() {
            let slot = self.timer.get_or_init(|| {
                Mutex::new(Some(Box::pin(tokio::time::sleep_until(
                    tokio::time::Instant::from_std(self.at),
                ))))
            });
            let timer = slot.lock().expect("deadline timer").take();
            let Some(mut timer) = timer else {
                return Ok(());
            };
            let waker = Waker::from(self.wake.clone());
            let ready = std::pin::Pin::new(&mut timer)
                .poll(&mut Context::from_waker(&waker))
                .is_ready();
            let mut timer = Some(timer);
            let previous = {
                let mut slot = slot.lock().expect("deadline timer");
                if !self.wake.cancelled.load(Ordering::Acquire) {
                    slot.replace(timer.take().expect("the polled timer"))
                } else {
                    None
                }
            };
            drop(previous);
            drop(timer);
            if ready {
                return Err(ConnError::Timeout);
            }
        }
        Ok(())
    }
}

impl Held {
    fn over(
        line: Option<(Arc<Line>, u64)>,
        judging: Option<Judging>,
        pooled: Option<(usize, PoolKey)>,
    ) -> Self {
        Held {
            prepared: Mutex::new(None),
            uncommitted: AtomicBool::new(false),
            line: Mutex::new(line),
            retired: AtomicBool::new(false),
            judging: Mutex::new(judging),
            crossing: Mutex::new(None),
            rest: Mutex::new(Rest::default()),
            reason: Mutex::new(None),
            pooled,
            whole: AtomicBool::new(false),
            redial: Mutex::new(None),
            lease: None,
            due: Mutex::new(None),
            dial_due: Mutex::new(None),
            open_timeout: DEFAULT_OPEN_TIMEOUT,
            dialled: None,
            why: std::sync::OnceLock::new(),
        }
    }

    /// Hold `why` as the reason this connection failed before a line existed (the first wins).
    fn refused(&self, why: NeedRefusal) {
        let _ = self.why.set(why);
    }

    /// This connection carries a held session's upstream leg (`d`).
    fn dialling(mut self, d: dialled::Dialled) -> Self {
        self.dialled = Some(d);
        self
    }

    fn line(&self) -> Option<(Arc<Line>, u64)> {
        self.line.lock().expect("line").clone()
    }

    /// Bounded by `timeout_ms` from `now` (the op's one clock reading) until its answer begins;
    /// `0`, or a bound no instant can
    fn bounded(self, now: std::time::Instant, timeout_ms: u64) -> Self {
        if let Some(at) = due_at(now, timeout_ms) {
            *self.due.lock().expect("due") = Some(Due::new(at));
        }
        self
    }

    fn watch_deadlines(&self, interest: DeadlineInterest, waker: &Waker) {
        let due = self.due.lock().expect("due").clone();
        let dial_due = self.dial_due.lock().expect("dial due").clone();
        let now = framer::now();
        for due in due.into_iter().chain(dial_due) {
            if now < due.at {
                due.wake.register(interest, waker);
            }
        }
    }

    /// [`ConnError::Timeout`] once the bound has passed; subscribers are woken when it passes.
    fn within_due(&self) -> Result<(), ConnError> {
        let due = self.due.lock().expect("due").clone();
        due.map_or(Ok(()), |d| d.check())
    }

    /// Its dial bounded by `timeout` from `now` (the op's one clock reading).
    fn dial_bounded(mut self, now: std::time::Instant, timeout: Duration) -> Self {
        self.open_timeout = timeout;
        if let Some(at) = now.checked_add(timeout) {
            *self.dial_due.lock().expect("dial due") = Some(Due::new(at));
        }
        self
    }

    fn within_dial_due(&self) -> Result<(), ConnError> {
        let due = self.dial_due.lock().expect("dial due").clone();
        due.map_or(Ok(()), |d| d.check())
    }

    fn landed(&self) {
        let due = self.dial_due.lock().expect("dial due").take();
        if let Some(due) = &due {
            due.cancel();
        }
        drop(due);
    }

    /// The answer began: the bound is spent.
    fn answered(&self) {
        let due = self.due.lock().expect("due").take();
        if let Some(due) = &due {
            due.cancel();
        }
        drop(due);
        self.landed();
    }

    /// A terminal judgement, dial or replay spends the bound too: a later deadline cannot
    fn fail(
        &self,
        mut judging: std::sync::MutexGuard<'_, Option<Judging>>,
        error: ConnError,
    ) -> ConnError {
        if let Some(j) = judging.as_mut() {
            j.failed = Some(error);
        }
        drop(judging);
        self.answered();
        error
    }
}

impl Drop for Held {
    /// A lease no one closed (its owner dropped it) is closed as it goes: the member's program does
    fn drop(&mut self) {
        if let Some((member, lease)) = self.lease.take() {
            member.close(lease);
        }

        if let Some(d) = &self.dialled {
            d.close();
        }
    }
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").finish_non_exhaustive()
    }
}

/// A need as an instance declared it, whole, the answer its declaration got, and why its latest
/// `declare` or `open` failed before any connection existed (host-only, [`NeedRefusal`]).
type Declared = (ReadNeed, Result<(), ConnError>, Option<NeedRefusal>);

type TlsPolicy = (
    Arc<rustls::ClientConfig>,
    busbar_contract::transport::trust::EgressTrust,
);

/// THE CONNECTOR: the host side of the connection table.
pub struct Connector {
    slab: ConnSlab<Held>,
    /// The transport each declared need names, the egress class its dials are judged under, and
    over: Mutex<HashMap<(InstanceId, NeedId), DeclaredNeed>>,
    /// Every need an instance declared through [`DeclaredConns::declare`], whole, and the answer
    declared: Mutex<HashMap<(InstanceId, NeedId), Declared>>,
    transports: RwLock<Transports>,
    tls: Option<Arc<rustls::ClientConfig>>,
    tls_policy: Option<busbar_contract::transport::trust::EgressTrust>,
    wake: WakeTicket,
    judge: Arc<dyn DialJudge>,
    /// One listener per inbound need.
    listeners: Listeners,
    /// The per-worker pools of dialled connections.
    pools: Pools,
    /// The trust anchors each sealed destination's connections are held to.
    anchored: Anchored,
    /// The trust anchors each sealed REGISTRATION's own connections are held to: two registrations
    member_anchored: MemberAnchored,
    /// The registrations' seals at each destination, by the need's owner, the need and the
    registered: Mutex<HashMap<(InstanceId, NeedId, String), Registered>>,
    /// The REGISTRATIONS holding a PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`), by the need's
    reaching: Mutex<ByMember<String>>,
    /// Each member's auth binding: what a plugin's own request naming that member is authenticated
    auths: Mutex<Auths>,
    /// The instances whose connections' authority the host writes
    authority_held: Mutex<HashSet<InstanceId>>,
    /// THE ABI RULES FLAGGED, once per instance and code ([`Connector::flag_once`]): BUSBAR-6013 (a
    /// retired need shape), 6014 (a refused call) and 6015 (an honoured deprecated value), each
    /// logged and audited the first time an instance meets it.
    flagged: Mutex<HashSet<(InstanceId, u16)>>,
    /// THE HOST'S I/O every carrier is served from ([`hostio`]): the one holder of OS handles.
    io: Arc<HostIo>,
    /// THE PROXY ENVIRONMENT every framed dial honours ([`proxy`]); `None` = every dial direct.
    proxy: Option<Arc<proxy::ProxyChoice>>,
    /// THE SESSION BOOK: each held session's [`datagram::Pairing`], by its kernel-minted unit key
    pairs: Mutex<HashMap<u64, Arc<datagram::Pairing>>>,
    /// HOW A PROGRAM'S ENVIRONMENT REFERENCES RESOLVE ([`spawn_env`]): the resolver the composition
    spawn_secrets: Option<spawn_env::SpawnSecretFn>,
    /// THE OUTBOUND TLS TRUST STORE (`advanced.tls`), selected by the guard-judged dial host;
    /// empty = the connector's own config (`tls`) for every dial.
    trust: arc_swap::ArcSwapOption<tls::store::TrustStore>,
    /// `advanced.proxy_resolution: local` (the default, `true`): behind a proxy the target must
    /// resolve here, every address it answers is judged, and the CONNECT names the judged
    /// address; `proxy` (`false`): a name that does not resolve here is CONNECTed by name and its
    /// address check is the proxy's (BUSBAR-3149 at boot).
    proxy_by_address: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector").finish_non_exhaustive()
    }
}

impl Default for Connector {
    fn default() -> Self {
        Self {
            slab: ConnSlab::default(),
            over: Mutex::new(HashMap::new()),
            declared: Mutex::new(HashMap::new()),
            transports: RwLock::new(Transports::default()),
            tls: None,
            tls_policy: None,
            wake: Arc::new(|_, _| {}),
            judge: Arc::new(LiteralsOnly(guard::Guard::default())),
            listeners: Mutex::new(HashMap::new()),
            pools: Pools::new(PoolPosture::NONE),
            anchored: Mutex::new(HashMap::new()),
            member_anchored: Mutex::default(),
            registered: Mutex::new(HashMap::new()),
            reaching: Mutex::default(),
            auths: Mutex::new(HashMap::new()),
            authority_held: Mutex::new(HashSet::new()),
            flagged: Mutex::new(HashSet::new()),
            io: hostio::process(),
            proxy: None,
            pairs: Mutex::new(HashMap::new()),
            spawn_secrets: None,
            trust: arc_swap::ArcSwapOption::empty(),
            proxy_by_address: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

struct TicketWake {
    wake: WakeTicket,
    /// The caller whose ticket this is.
    owner: InstanceId,
    ticket: Ticket,
}

impl Wake for TicketWake {
    fn wake(self: Arc<Self>) {
        (self.wake)(self.owner, self.ticket);
    }
}

pub(crate) fn map(f: &Failure) -> ConnError {
    match f {
        Failure::Pending => ConnError::Pending,
        Failure::Refused(_) => ConnError::Refused,
        Failure::Timeout => ConnError::Timeout,
        Failure::Closed => ConnError::Closed,
        Failure::Failed(_) => ConnError::Fault,
    }
}

fn class(code: u8) -> Option<WireStatusClass> {
    use busbar_contract::abi::transport::{
        STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
    };
    match code {
        STATUS_SUCCESS => Some(WireStatusClass::Success),
        STATUS_CALLER_FAULT => Some(WireStatusClass::CallerFault),
        STATUS_FAR_END_FAULT => Some(WireStatusClass::FarEndFault),
        STATUS_OTHER => Some(WireStatusClass::Other),
        _ => None,
    }
}

impl Connector {
    /// A connector holding no connection, no declared need and no transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same connector serving `transports`, judging every dial's address through `judge`,
    #[must_use]
    pub fn serving(
        transports: Transports,
        judge: Arc<dyn DialJudge>,
        tls: Option<Arc<rustls::ClientConfig>>,
        wake: WakeTicket,
    ) -> Self {
        Self {
            transports: RwLock::new(transports),
            tls,
            wake,
            judge,
            ..Self::default()
        }
    }

    /// A connector with explicit TLS policy provenance, permitting member-local CA additions.
    pub fn serving_with_trust(
        transports: Transports,
        judge: Arc<dyn DialJudge>,
        trust: busbar_contract::transport::trust::EgressTrust,
        wake: WakeTicket,
    ) -> Result<Self, tls::client::BadClientIdentity> {
        let config = Arc::new(tls::client::build_client_config(&trust)?);
        let mut connector = Self::serving(transports, judge, Some(config), wake);
        connector.tls_policy = Some(trust);
        Ok(connector)
    }

    /// The same connector resolving its programs' environment references through `secrets`, at
    #[must_use]
    pub fn resolving_spawn_secrets(mut self, secrets: spawn_env::SpawnSecretFn) -> Self {
        self.spawn_secrets = Some(secrets);
        self
    }

    /// INSTALL THE TRUST STORE every later dial selects its TLS configuration from (boot-time; a
    /// second install replaces the first, as the effective configuration replaces the bootstrap
    /// one).
    pub fn install_trust_store(&self, store: Arc<tls::store::TrustStore>) {
        egress_audit::install_store(Arc::clone(&store));
        self.trust.store(Some(store));
    }

    /// THE CLIENT TLS CONFIG for a dial of `target` (the guard-judged target, `host:port` or a
    /// URL): the trust store's selection for its host, else the connector's own. A destination no
    /// anchor applies to is refused, coded and audited.
    fn tls_for(&self, target: &str) -> Result<Option<Arc<rustls::ClientConfig>>, ConnError> {
        let Some(store) = self.trust.load_full() else {
            return Ok(self.tls.clone());
        };
        match store.config_for(&host_of(target)) {
            Ok(Some(config)) => Ok(Some(config)),
            Ok(None) => Ok(self.tls.clone()),
            Err(refusal) => {
                egress_audit::dial_refused(target, None, &refusal.to_string(), None);
                Err(ConnError::Refused)
            }
        }
    }

    /// Set `advanced.proxy_resolution`: `true` = `local` (judge and CONNECT by address), `false`
    /// = `proxy` (CONNECT by name; the proxy resolves a name busbar cannot).
    pub fn set_proxy_by_address(&self, by_address: bool) {
        self.proxy_by_address.store(by_address, Ordering::Relaxed);
    }

    fn proxy_delegated(&self) -> bool {
        !self.proxy_by_address.load(Ordering::Relaxed)
    }

    /// What a CONNECT names for `planned`: the judged address under `proxy_resolution: local`,
    /// else the target's own authority.
    fn connect_target(&self, planned: &Planned, target_at: Option<SocketAddr>) -> String {
        match target_at {
            Some(at) if !self.proxy_delegated() => at.to_string(),
            _ => planned.authority().to_owned(),
        }
    }

    /// Whether an exact `advanced.tls.destinations` entry admits plaintext to `authority`'s host.
    fn plaintext_admitted(&self, authority: &str) -> bool {
        self.trust
            .load()
            .as_ref()
            .is_some_and(|s| s.plaintext_admitted(&host_of(authority)))
    }

    /// Whether a dial of `planned` at `addr` is a carrier that must be secured before it carries
    /// application bytes: not framed, not secure from its first byte, not to loopback, and not
    /// to a destination plaintext is admitted to.
    fn holds_clear_window(&self, planned: &Planned, addr: SocketAddr) -> bool {
        !planned.framed()
            && !planned.secure()
            && !addr.ip().is_loopback()
            && !guard::names_loopback(&host_of(planned.authority()))
            && !self.plaintext_admitted(planned.authority())
    }

    /// Whether plaintext is admitted for `planned` beyond loopback: a carrier (held to its
    /// cleartext window instead) or an exact plaintext entry.
    fn plain_admitted(&self, planned: &Planned) -> bool {
        !planned.framed() || self.plaintext_admitted(planned.authority())
    }

    /// The host I/O this connector's carriers are served from.
    #[must_use]
    pub fn io(&self) -> &Arc<HostIo> {
        &self.io
    }

    /// THE CARRIER OF A NETWORK ADDRESS, as a connection rides it: the first loaded carrier whose
    #[must_use]
    pub fn address_via(&self) -> Option<Via> {
        let view = self.transports.read().expect("transports");
        view.address_carrier().map(|e| Via {
            door: Arc::clone(&e.door),
            io: Arc::clone(&self.io),
        })
    }

    /// What a need served by `door` rides: a CARRIER is carried as itself (no framer); a FRAMER
    fn ride_on(&self, door: &Arc<dyn FramerDoor>) -> Option<(Option<Arc<dyn FramerDoor>>, Via)> {
        if door.facts().role == ROLE_CARRIER {
            return Some((
                None,
                Via {
                    door: Arc::clone(door),
                    io: Arc::clone(&self.io),
                },
            ));
        }
        self.address_via().map(|via| (Some(Arc::clone(door)), via))
    }

    /// A dial of `dial` over the entry `door` serves, located: the framer's `locate`, or a carrier
    fn plan(&self, door: &Arc<dyn FramerDoor>, dial: Dial) -> Result<Planned, Failure> {
        self.plan_carried(door, dial, None)
    }

    /// [`Connector::plan`], dialling `carried` (the answer this attempt's head was completed
    /// with, already matched to the dial's caller, need and target) instead of locating again.
    fn plan_carried(
        &self,
        door: &Arc<dyn FramerDoor>,
        dial: Dial,
        carried: Option<framer::Located>,
    ) -> Result<Planned, Failure> {
        match self.ride_on(door) {
            Some((Some(framer), via)) => Planned::locate_carried(framer, via, dial, carried),
            Some((None, via)) => Planned::carried(via, dial),
            None => Err(Failure::Refused(
                "no carrier is loaded to reach an address".into(),
            )),
        }
    }

    /// The framer `owner`'s `need` rides, located at `target` (empty = the need's own, as an open
    fn framer_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        self.framer_located(owner, need, target, timeout_ms)
            .map(|(head, _)| head)
    }

    /// [`Connector::framer_head`], keeping the framer's whole locate answer for the open that
    /// dials it ([`Conns::open_located`]). Only a framer's own locate is carried: a carrier's
    /// answer and a datagram's rendezvous are worked out again at the open, as before.
    fn framer_located(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<(HeadDefaults, Option<Arc<LocatedTarget>>), ConnError> {
        let (door, declared, members) = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|n| {
                (
                    Arc::clone(&n.door),
                    n.declared_target.clone().filter(|_| target.is_empty()),
                    n.members.clone(),
                )
            })
            .ok_or(ConnError::Refused)?;
        // A member-program target names a host-declared child, not a socket authority.
        // Its pipe framing contributes no request-head defaults. Match the same member
        // selection used by open_timed; only the later open can lease or spawn it.
        if let Some(members) = members {
            if !members.contains_key(program::member_of(target)) {
                return Err(ConnError::Refused);
            }
            return Ok((
                HeadDefaults {
                    lines: Vec::new(),
                    states_length: false,
                },
                None,
            ));
        }
        let target = declared.as_deref().unwrap_or(target);
        // A datagram association obtains its peer description over a separately
        // framed exchange. Its own door has no request-head locate operation.
        let datagram = door.facts().datagram;
        let door = if datagram {
            self.rendezvous_exchange(target)?.door
        } else {
            door
        };
        if door.facts().role == ROLE_CARRIER {
            return self
                .located(&door, target)
                .ok_or(ConnError::Refused)
                .map(|located| {
                    (
                        HeadDefaults {
                            lines: located.defaults,
                            states_length: located.states_length,
                        },
                        None,
                    )
                });
        }
        let located = framer::locate_request(door.as_ref(), target, timeout_ms)
            .map_err(|_| ConnError::Refused)?;
        let head = HeadDefaults {
            lines: located.defaults.clone(),
            states_length: located.states_length,
        };
        let carried = (!datagram).then(|| {
            Arc::new(LocatedTarget::new(
                owner,
                need,
                target.to_owned(),
                located.authority,
                located.name,
                located.secure,
                located.offer,
                located.defaults,
                located.states_length,
            ))
        });
        Ok((head, carried))
    }

    /// The ordinary exchange carrying a datagram association's peer description.
    /// Both head completion and opening resolve the same target-selected framer.
    fn rendezvous_exchange(&self, target: &str) -> Result<registry::Entry, ConnError> {
        let scheme = target
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .ok_or(ConnError::Refused)?;
        let view = self.transports.read().expect("transports");
        let served = view.dialing(scheme).ok_or(ConnError::Refused)?;
        if served.entry.door.facts().datagram {
            return Err(ConnError::Refused);
        }
        Ok(served.entry.clone())
    }

    /// Where `target` goes, per the entry `door` serves: its authority, security and name.
    fn located(&self, door: &Arc<dyn FramerDoor>, target: &str) -> Option<framer::Located> {
        if door.facts().role == ROLE_CARRIER {
            let claim = door.facts().claims.first().copied().unwrap_or_default();
            return compose::carried_at(claim, target).ok();
        }
        framer::locate(door.as_ref(), target).ok()
    }

    /// The same connector dialling every framed connection through the proxy `config` selects for
    #[must_use]
    pub fn proxying(mut self, config: Option<Arc<proxy::ProxyChoice>>) -> Self {
        self.proxy = config;
        self
    }

    /// Publish the effective boot's validated transport view, listener ports and pool posture
    pub fn finalize_boot_metadata(
        &self,
        transports: Transports,
        own_ports: &[u16],
        posture: PoolPosture,
    ) {
        self.judge.own_ports_applied(own_ports);
        self.pools.reconfigure(posture);
        let previous = std::mem::replace(
            &mut *self.transports.write().expect("transports"),
            transports,
        );
        drop(previous);
    }

    /// The proxy a dial of `planned` goes through: a framed dial (never a carrier carried as
    fn tunnel_for(&self, planned: &Planned, within: &[IpAddr]) -> Option<Arc<proxy::ProxyHop>> {
        if !planned.framed() || !within.is_empty() {
            return None;
        }
        self.proxy
            .as_ref()?
            .select(planned.secure(), proxy::host_of(planned.authority()))
    }

    /// Judge `dest` under `class` (with the need's private reach when `reach`), the pended answer
    fn judge_into(
        &self,
        dest: &str,
        secure: bool,
        class: u32,
        reach: bool,
        answer: &Answer,
    ) -> Option<Result<SocketAddr, Verdict>> {
        let answering = Arc::clone(answer);
        let done: JudgedAll = Box::new(move |v, also| {
            let waiting = {
                let mut a = answering.lock().expect("judgement");
                a.0 = Some(v);
                a.2 = also;
                a.1.take()
            };
            if let Some(w) = waiting {
                w.wake();
            }
        });
        self.judge.judge_target_all(
            busbar_kernel::host_services::Destination {
                authority: dest,
                secure,
                egress_class: class,
            },
            reach,
            done,
        )
    }

    /// The same connector keeping dialled connections under `posture` (the deployment's
    #[must_use]
    pub fn pooling(mut self, posture: PoolPosture) -> Self {
        self.pools = Pools::new(posture);
        self
    }

    /// The need `owner` declared as `need`, whole, as [`DeclaredConns::declare`] received it.
    #[must_use]
    pub fn declared_spec(&self, owner: InstanceId, need: NeedId) -> Option<ReadNeed> {
        let declared = self.declared.lock().expect("declared needs");
        declared
            .get(&(owner, need))
            .map(|(spec, _, _)| spec.clone())
    }

    /// Record that `owner` declared `need` — the only needs it may open. A need declared without a
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.slab.declare(owner, need);
    }

    /// Whether a loaded transport entry serves `transport` (a scheme).
    #[must_use]
    pub fn serves_scheme(&self, transport: &str) -> bool {
        self.transports
            .read()
            .expect("transports")
            .serving(transport)
            .is_some()
    }

    /// Whether `transport` is served by a FRAMER (`http`, `grpc`, ...), not a carrier (`tcp`,
    /// `unix`, ...) carried as itself.
    fn framed_transport(&self, transport: &str) -> bool {
        self.transports
            .read()
            .expect("transports")
            .dialing(transport)
            .is_some_and(|served| served.entry.door.facts().role != ROLE_CARRIER)
    }

    /// Flag `diag` for `owner` once: the first time an instance meets an ABI rule, one coded line
    /// and one audit record; `false` (nothing written) every time after.
    fn flag_once(
        &self,
        owner: InstanceId,
        diag: &busbar_contract::diagnostic::Diagnostic,
        refusal: busbar_kernel::audit::auditlog::PluginRefusal,
        what: &str,
    ) -> bool {
        let first = self
            .flagged
            .lock()
            .expect("flagged")
            .insert((owner, diag.code));
        if first {
            busbar_kernel::diagnostics::diag_warn!(diag, instance = owner.0, "{what}");
            busbar_kernel::audit::auditlog::record_plugin_refusal(
                refusal,
                "plugin",
                &format!("instance-{}", owner.0),
                &diag.banner().to_string(),
            );
        }
        first
    }

    /// The ABI rules flagged so far, by instance and code, in order.
    #[cfg(test)]
    pub(crate) fn abi_flags(&self) -> Vec<(InstanceId, u16)> {
        let mut flags: Vec<_> = self
            .flagged
            .lock()
            .expect("flagged")
            .iter()
            .copied()
            .collect();
        flags.sort_by_key(|(owner, code)| (owner.0, *code));
        flags
    }

    /// The framer entry that answers `scheme`, where a loaded one does: what frames a stream that
    #[must_use]
    pub fn framer_for(&self, scheme: &str) -> Option<Arc<dyn framer::FramerDoor>> {
        self.transports
            .read()
            .expect("transports")
            .serving(scheme)
            .map(|s| Arc::clone(&s.entry.door))
    }

    /// Record that `owner` declared `need` over `transport` (a scheme the registry view serves), in
    pub fn declare_over(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
    ) -> Result<(), ConnError> {
        self.declare_need(owner, need, transport, DEFAULT_CLASS)
    }

    /// Record that `owner` declared `need` over `transport`, its dials judged under the need's own
    pub fn declare_need(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
    ) -> Result<(), ConnError> {
        self.record(owner, need, transport, egress_class, None, None)
    }

    /// Record that `owner` declared `need` over `transport` in `egress_class`, its target named by
    pub fn declare_need_to(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: &str,
    ) -> Result<(), ConnError> {
        self.record(
            owner,
            need,
            transport,
            egress_class,
            Some(declared_target),
            None,
        )
    }

    /// THE SCHEME MATCH: the need is recorded over the entry serving `transport`, resolved here
    fn record(
        &self,
        owner: InstanceId,
        need: NeedId,
        transport: &str,
        egress_class: u32,
        declared_target: Option<&str>,
        security: Option<TlsPolicy>,
    ) -> Result<(), ConnError> {
        let (tls, tls_policy) = security.map_or((None, None), |(config, policy)| {
            (Some(config), Some(policy))
        });
        let served = {
            let view = self.transports.read().expect("transports");
            // busbar:expect(bp::clone_alloc, reason = "config: a need's declaration keeps its own copy of the entry's protocol list")
            view.dialing(transport)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let Some((door, alpn)) = served else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        self.slab.declare(owner, need);
        // Made once at declaration and shared by every open (an `Arc` clone, not a copy).
        let declared_target: Option<Arc<str>> = declared_target.map(Arc::from);
        self.set_need(
            owner,
            need,
            Some(DeclaredNeed {
                door,
                alpn,
                egress_class,
                declared_target,
                tls,
                tls_policy,
                program: None,
                members: None,
                member_spec: None,
            }),
        );
        Ok(())
    }

    /// THE ADMISSION OF A PINNED TARGET (FAIL-CLOSED: the verdict `need_admit` reports is the one
    fn admits_pinned(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        egress_class: u32,
    ) -> Result<(), NeedRefusal> {
        let door = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|n| Arc::clone(&n.door))
            .ok_or(NeedRefusal::Policy(refusal_text::CHECKS))?;
        let unlocated = |_| NeedRefusal::Policy(refusal_text::UNLOCATED);
        endpoint::named(target).map_err(unlocated)?;
        let located = self
            .located(&door, target)
            .ok_or(NeedRefusal::Policy(refusal_text::UNLOCATED))?;
        endpoint::named(&located.authority).map_err(unlocated)?;
        if !scheme_admits(egress_class, located.secure) {
            return Err(NeedRefusal::Policy(refusal_text::PLAINTEXT));
        }
        let judged_class = guard::judged_class(egress_class, true);
        if let Some(v) = self
            .judge
            .judge_target_static(busbar_kernel::host_services::Destination {
                authority: &located.authority,
                secure: located.secure,
                egress_class: judged_class,
            })
        {
            return Err(verdict_reason(v, false));
        }
        if socket::address_of(&located.authority).is_some() {
            match self.judge.judge_target_all(
                busbar_kernel::host_services::Destination {
                    authority: &located.authority,
                    secure: located.secure,
                    egress_class: judged_class,
                },
                false,
                Box::new(|_, _| {}),
            ) {
                Some(Ok(addr))
                    if class_admits(
                        egress_class,
                        located.secure,
                        door.facts().role == ROLE_CARRIER
                            || self.plaintext_admitted(&located.authority),
                        &[],
                        &located.authority,
                        addr,
                    ) => {}
                Some(Ok(_)) => {
                    egress_audit::dial_refused(
                        &located.authority,
                        Some(egress_class),
                        "plaintext",
                        Some((u64::from(owner.0), need.0)),
                    );
                    return Err(ConnError::Refused);
                }
                Some(Err(v)) => {
                    egress_audit::dial_refused(
                        &located.authority,
                        Some(egress_class),
                        egress_audit::verdict_name(v),
                        Some((u64::from(owner.0), need.0)),
                    );
                    return Err(ConnError::Refused);
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Record (or, with `None`, drop) what the connector holds for `owner`'s `need`: a member of an
    fn set_need(&self, owner: InstanceId, need: NeedId, record: Option<DeclaredNeed>) {
        let before = {
            let mut over = self.over.lock().expect("needs");
            match record {
                Some(r) => over.insert((owner, need), r),
                None => over.remove(&(owner, need)),
            }
        };

        drop(before);
    }

    /// THE MEMBER-PROGRAM NEED (`busbar_contract::section::MEMBER_PROGRAM`): `owner`'s outbound
    fn record_members(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
        scope: &busbar_contract::config_time::ConfigScope,
        predecessor: Option<InstanceId>,
    ) -> Result<(), ConnError> {
        let served = {
            let view = self.transports.read().expect("transports");
            // busbar:expect(bp::clone_alloc, reason = "config: a need's declaration keeps its own copy of the entry's protocol list")
            view.dialing(&spec.transport)
                .filter(|served| served.entry.door.facts().role == ROLE_CARRIER)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let carried = spec.direction == DIRECTION_OUTBOUND
            && spec.egress_class == EGRESS_OPERATOR_INFRASTRUCTURE
            && spec.auth.is_empty()
            && busbar_contract::section::member_program(&spec.target_from)
            && programs
                .iter()
                .all(|(_, p)| std::path::Path::new(&p.command).is_absolute());
        let Some((door, alpn)) = served.filter(|_| carried) else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        let before = {
            let over = self.over.lock().expect("needs");

            let source = over.get(&(owner, need)).or_else(|| {
                predecessor
                    .filter(|previous| *previous != owner)
                    .and_then(|previous| over.get(&(previous, need)))
            });
            source
                .filter(|d| d.member_spec.as_ref() == Some(spec))
                .and_then(|d| d.members.clone())
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a member-program need's members are declared once"
        )]
        let members: program::Members = programs
            .iter()
            .map(|(name, p)| {
                let kept = before
                    .as_ref()
                    .and_then(|b| b.get(name))
                    .filter(|m| m.program() == p)
                    .cloned();

                if let Some(kept) = &kept {
                    kept.env().reload(scope);
                }
                let member = match kept {
                    Some(kept) => kept,
                    None => Arc::new(program::Declaration::new(program::Member::new(
                        p.clone(),
                        spawn_env::HeldEnv::load(&p.env_refs, self.spawn_secrets, scope),
                        Via {
                            door: Arc::clone(&door),
                            io: Arc::clone(&self.io),
                        },
                        alpn.clone(),
                    )?)),
                };
                Ok((name.clone(), member))
            })
            .collect::<Result<_, ConnError>>()?;
        self.slab.declare(owner, need);
        self.set_need(
            owner,
            need,
            Some(DeclaredNeed {
                door,
                alpn,
                egress_class: spec.egress_class,
                declared_target: None,
                tls: None,
                tls_policy: None,
                program: None,
                members: Some(Arc::new(members)),
                member_spec: Some(spec.clone()),
            }),
        );
        Ok(())
    }

    /// THE PROGRAM NEED: `owner`'s outbound `need` dials `program` (its pipes, framed by the entry
    fn record_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &busbar_contract::conn::Program,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<(), ConnError> {
        let served = {
            let view = self.transports.read().expect("transports");
            // busbar:expect(bp::clone_alloc, reason = "config: a need's declaration keeps its own copy of the entry's protocol list")
            view.dialing(&spec.transport)
                .filter(|served| served.entry.door.facts().role == ROLE_CARRIER)
                .map(|served| (Arc::clone(&served.entry.door), served.entry.alpn.clone()))
        };
        let carried = spec.direction == DIRECTION_OUTBOUND
            && spec.egress_class == EGRESS_OPERATOR_INFRASTRUCTURE
            && spec.auth.is_empty()
            && std::path::Path::new(&program.command).is_absolute();
        let Some((door, alpn)) = served.filter(|_| carried) else {
            self.set_need(owner, need, None);
            return Err(ConnError::Refused);
        };
        self.slab.declare(owner, need);
        self.set_need(
            owner,
            need,
            Some(DeclaredNeed {
                door,
                alpn,
                egress_class: spec.egress_class,
                declared_target: None,
                tls: None,
                tls_policy: None,
                program: Some((
                    program.clone(),
                    spawn_env::HeldEnv::load(&program.env_refs, self.spawn_secrets, scope),
                )),
                members: None,
                member_spec: None,
            }),
        );
        Ok(())
    }

    /// Bind the one listener for `owner`'s INBOUND `need` on `bind` (`ip:port`), over the transport
    pub fn listen(
        &self,
        owner: InstanceId,
        need: NeedId,
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
        limits: AcceptLimits,
    ) -> Result<SocketAddr, ConnError> {
        self.slab.check_need(owner, need)?;

        // busbar:expect(bp::clone_alloc, reason = "config: a listener is bound once, with its own copy of the protocol list")
        let (door, registered) = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| (Arc::clone(&d.door), d.alpn.clone()))
            .ok_or(ConnError::Refused)?;

        let alpn = match framer::accept_offer(door.as_ref()) {
            Ok(offer) if !offer.is_empty() => offer,
            Ok(_) => registered,
            Err(refused) => {
                tracing::warn!(
                    owner = owner.0,
                    need = need.0,
                    error = %refused,
                    "inbound listener: the entry's locate refused the accepting-side protocol \
                     offer; the listener binds with the transport's registered protocol list"
                );
                registered
            }
        };

        let held = Arc::new(Accepting::default());
        {
            let mut listeners = self.listeners.lock().expect("listeners");
            if listeners.contains_key(&(owner, need)) {
                return Err(ConnError::Refused);
            }
            listeners.insert((owner, need), Arc::clone(&held));
        }
        let bound = self
            .ride_on(&door)
            .ok_or(ConnError::Refused)
            .and_then(|(framer, via)| {
                Listening::bind(framer, &via, bind, tls, alpn, limits).map_err(|error| {
                    tracing::warn!(
                        owner = owner.0,
                        need = need.0,
                        kind = ?error.kind(),
                        "inbound listener bind failed"
                    );
                    ConnError::Fault
                })
            });
        match bound {
            Ok(l) => {
                let addr = l.local_addr();
                held.put(Some(l));
                Ok(addr)
            }
            Err(e) => {
                let gone = {
                    let mut listeners = self.listeners.lock().expect("listeners");
                    let ours = listeners
                        .get(&(owner, need))
                        .is_some_and(|a| Arc::ptr_eq(a, &held));
                    ours.then(|| listeners.remove(&(owner, need))).flatten()
                };
                drop(gone);
                held.put(None);
                Err(e)
            }
        }
    }

    /// The next connection `owner`'s inbound `need` admitted, held for `owner` like one it
    pub fn accept(
        &self,
        owner: InstanceId,
        need: NeedId,
        ticket: Ticket,
    ) -> Result<(ConnId, SocketAddr), ConnError> {
        self.slab.check_need(owner, need)?;
        let l = self
            .listeners
            .lock()
            .expect("listeners")
            .get(&(owner, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        let waker = self.waker(owner, ticket);
        let Some(listening) = l.take(&waker) else {
            return Err(ConnError::Pending);
        };
        let mut out = AcceptingOut {
            home: &l,
            listening: Some(listening),
        };
        let got = out
            .listening
            .as_mut()
            .expect("the listener is out")
            .poll_accept(&mut Context::from_waker(&waker));
        drop(out);
        match got {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Ready(Ok(a)) => {
                let line = Line::new(a.conn);
                let id =
                    self.slab
                        .insert(owner, need, Held::over(Some((line, EVERY)), None, None))?;
                Ok((id, a.peer))
            }
        }
    }

    /// Offer `bytes` on `stream` of `caller`'s connection `conn` (`end` = the stream's message is
    pub fn emit(
        &self,
        caller: InstanceId,
        conn: ConnId,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if !self.settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        line.emit(stream, bytes, end, text).map_err(|f| map(&f))
    }

    /// Dial a held connection whose judgement has answered and replay its accepted writes.
    fn settle(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        let ready = self.settle_dial(held, waker)?;

        if self.observe_landing(held, waker.unwrap_or_else(|| Waker::noop()))? && !ready {
            if let Some(waker) = waker {
                waker.wake_by_ref();
            }
        }
        Ok(ready)
    }

    fn settle_dial(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        if held.retired.load(Ordering::Acquire) {
            return Err(ConnError::Closed);
        }
        held.within_dial_due()?;
        let mut wake = waker.cloned();
        let mut judging = held.judging.lock().expect("judging");
        if held.retired.load(Ordering::Acquire) {
            return Err(ConnError::Closed);
        }
        {
            let mut crossing = held.crossing.lock().expect("crossing");
            if let Some(waiting) = crossing.as_mut() {
                if wake
                    .as_ref()
                    .is_some_and(|w| !waiting.iter().any(|x| x.will_wake(w)))
                {
                    waiting.push(wake.take().expect("the waiting caller"));
                }
                return Ok(false);
            }
        }
        let Some(j) = judging.as_mut() else {
            return Ok(true);
        };
        if let Some(error) = j.failed {
            return Err(error);
        }
        if j.planned.is_none() {
            let crossing = Crossing::begin(held, judging);
            return crossing.finish(self.replay_early(held, waker));
        }
        let (got, also) = {
            let mut a = j.answer.lock().expect("judgement");
            match a.0 {
                None => {
                    let previous = if wake.is_some() {
                        std::mem::replace(&mut a.1, wake.take())
                    } else {
                        None
                    };
                    drop(a);
                    drop(judging);
                    drop(previous);
                    return Ok(false);
                }
                Some(got) => (got, std::mem::take(&mut a.2)),
            }
        };
        let secure = j.planned.as_ref().is_some_and(Planned::secure);
        let target = j
            .planned
            .as_ref()
            .map_or_else(String::new, |p| p.authority().to_owned());
        let plain = j.planned.as_ref().is_some_and(|p| self.plain_admitted(p));
        if let Some(p) = j.proxied.as_mut() {
            if !p.target_judged {
                let delegated = !self.proxy_by_address.load(Ordering::Relaxed);
                match got {
                    Err(v) if !(delegated && unresolved_here(v)) => {
                        egress_audit::dial_refused(
                            &target,
                            Some(j.egress_class),
                            egress_audit::verdict_name(v),
                            None,
                        );
                        return Err(held.fail(judging, pended_verdict(v)));
                    }
                    Ok(at) if !class_admits(j.egress_class, secure, plain, &[], &target, at) => {
                        egress_audit::dial_refused(&target, Some(j.egress_class), "plaintext", None);
                        return Err(held.fail(judging, ConnError::Refused));
                    }
                    _ => {}
                }
                p.target_judged = true;
                p.target_at = got.ok();
                let spec = Arc::clone(&p.spec);
                let answer = Arc::clone(&j.answer);
                let previous = {
                    let mut a = j.answer.lock().expect("judgement");
                    a.0 = None;
                    if wake.is_some() {
                        std::mem::replace(&mut a.1, wake.take())
                    } else {
                        None
                    }
                };
                let crossing = Crossing::begin(held, judging);
                return crossing.finish((|| {
                    drop(previous);
                    if held.retired.load(Ordering::Acquire) {
                        return Err(ConnError::Closed);
                    }
                    // This hop comes only from the operator's parsed proxy configuration. The
                    // application's target already passed its own class and security checks.
                    let proxy_judged = self.judge_into(
                        spec.endpoint(),
                        false,
                        EGRESS_OPERATOR_INFRASTRUCTURE,
                        true,
                        &answer,
                    );
                    if held.retired.load(Ordering::Acquire) {
                        return Err(ConnError::Closed);
                    }
                    let proxy_addr = match proxy_judged {
                        None => return Ok(false),
                        Some(Err(v)) => {
                            held.refused(verdict_reason(v, true));
                            return Err(pended_verdict(v));
                        }
                        Some(Ok(at)) => at,
                    };
                    let planned = {
                        let mut judging = held.judging.lock().expect("judging");
                        if held.retired.load(Ordering::Acquire) {
                            return Err(ConnError::Closed);
                        }
                        judging
                            .as_mut()
                            .and_then(|j| j.planned.take())
                            .ok_or(ConnError::Closed)?
                    };
                    let target_at = held
                        .judging
                        .lock()
                        .expect("judging")
                        .as_ref()
                        .and_then(|j| j.proxied.as_ref())
                        .and_then(|p| p.target_at);
                    self.settle_proxy(held, planned, &spec, proxy_addr, target_at, waker)
                })());
            }
            let proxy_addr = match got {
                Ok(at) => at,
                Err(v) => {
                    held.refused(verdict_reason(v, true));
                    return Err(held.fail(judging, pended_verdict(v)));
                }
            };
            let spec = Arc::clone(&p.spec);
            let target_at = p.target_at;
            let planned = j.planned.take().ok_or(ConnError::Refused)?;
            let crossing = Crossing::begin(held, judging);
            return crossing.finish(self.settle_proxy(
                held, planned, &spec, proxy_addr, target_at, waker,
            ));
        }
        let addr = match got {
            Ok(at) => at,
            Err(v) => {
                egress_audit::dial_refused(
                    &target,
                    Some(j.egress_class),
                    egress_audit::verdict_name(v),
                    None,
                );
                return Err(held.fail(judging, pended_verdict(v)));
            }
        };
        if !class_admits(j.egress_class, secure, plain, &j.within, &target, addr) {
            egress_audit::dial_refused(&target, Some(j.egress_class), "plaintext", None);
            return Err(held.fail(judging, ConnError::Refused));
        }

        let also: Vec<SocketAddr> = also
            .into_iter()
            .filter(|&at| class_admits(j.egress_class, secure, plain, &j.within, &target, at))
            .collect();
        let planned = j.planned.take().ok_or(ConnError::Refused)?;
        let clear_window = self.holds_clear_window(&planned, addr);
        let crossing = Crossing::begin(held, judging);
        crossing.finish((|| {
            let mut conn = planned.dial_at_any(addr, also).map_err(|f| map(&f))?;
            if clear_window {
                conn.hold_clear_window();
            }
            self.ride(held, conn)?;
            self.replay_early(held, waker)
        })())
    }

    /// Complete a proxy dial while the crossing owns its plan and no judgement guard is held.
    fn settle_proxy(
        &self,
        held: &Held,
        planned: Planned,
        spec: &proxy::ProxyHop,
        proxy_addr: SocketAddr,
        target_at: Option<SocketAddr>,
        waker: Option<&Waker>,
    ) -> Result<bool, ConnError> {
        let connect = proxy::connect_request(&self.connect_target(&planned, target_at), spec);
        let conn = planned
            .dial_through(proxy_addr, connect)
            .map_err(|(hop, f)| {
                held.refused(unreached(&f, hop == Hop::Proxy));
                map(&f)
            })?;
        self.ride(held, conn)?;
        self.replay_early(held, waker)
    }

    /// Replay accepted writes in order, retaining each unaccepted suffix across backpressure.
    fn replay_early(&self, held: &Held, waker: Option<&Waker>) -> Result<bool, ConnError> {
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        let mut remaining = held
            .judging
            .lock()
            .expect("judging")
            .as_ref()
            .map_or(0, |j| j.early.len());
        loop {
            if held.retired.load(Ordering::Acquire) {
                return Err(ConnError::Closed);
            }
            if remaining == 0 {
                let mut judging = held.judging.lock().expect("judging");
                if judging.as_ref().is_none_or(|j| j.early.is_empty()) {
                    let finished = judging.take();
                    drop(judging);
                    drop(finished);
                    return Ok(true);
                }

                drop(judging);
                if let Some(waker) = waker {
                    waker.wake_by_ref();
                }
                return Ok(false);
            }
            let next = {
                let mut judging = held.judging.lock().expect("judging");
                let Some(j) = judging.as_ref() else {
                    return Ok(true);
                };
                match j.early.front().cloned() {
                    Some(next) => next,
                    None => {
                        let finished = judging.take();
                        drop(judging);
                        drop(finished);
                        return Ok(true);
                    }
                }
            };
            let (bytes, end, text) = next;
            let emitted = line.emit_waking(stream, &bytes, end, text, waker);
            if held.retired.load(Ordering::Acquire) {
                return Err(ConnError::Closed);
            }
            let took = match emitted {
                Err(Failure::Pending) => return Ok(false),
                Err(f) => return Err(map(&f)),
                Ok(0) if !bytes.is_empty() => return Ok(false),
                Ok(took) => took,
            };
            let mut judging = held.judging.lock().expect("judging");
            let j = judging.as_mut().expect("the crossing owns replay");
            if took == bytes.len() {
                j.early.pop_front();
                remaining -= 1;
            } else {
                j.early.front_mut().expect("the replayed write").0 = bytes.slice(took..);
            }
        }
    }

    /// `held` rides `conn`, just dialled, as its first exchange; a pooled exchange's line is held
    fn ride(&self, held: &Held, mut conn: Connection) -> Result<Arc<Line>, ConnError> {
        let at = held
            .dial_due
            .lock()
            .expect("dial due")
            .as_ref()
            .map(|due| due.at);
        if let Some(at) = at {
            conn.bound_open(at);
        }
        let line = Line::new(conn);
        let mut home = held.line.lock().expect("line");
        if held.retired.load(Ordering::Acquire) {
            drop(home);
            line.close();
            return Err(ConnError::Closed);
        }
        if let Some((shard, key)) = &held.pooled {
            self.pools.hold(*shard, key.clone(), &line);
        }
        *home = Some((Arc::clone(&line), EXCHANGE_STREAM));
        Ok(line)
    }

    /// Judge `planned`'s authority under `judged_class` and dial the pinned address, held to the
    fn dial_judged(
        &self,
        planned: Planned,
        egress_class: u32,
        judged_class: u32,
        within: &[IpAddr],
        reach: bool,
        why: &mut Option<NeedRefusal>,
    ) -> Result<(Option<Connection>, Option<Judging>), ConnError> {
        let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));

        let judged = self.judge_into(
            planned.authority(),
            planned.secure(),
            judged_class,
            reach,
            &answer,
        );

        if let Some(spec) = self.tunnel_for(&planned, within) {
            let mut proxied = Proxied {
                spec,
                target_judged: false,
                target_at: None,
            };
            match judged {
                None => {
                    return Ok((
                        None,
                        Some(Judging {
                            planned: Some(planned),
                            failed: None,
                            egress_class,
                            within: Within::new(),
                            early: VecDeque::new(),
                            answer,
                            proxied: Some(proxied),
                        }),
                    ));
                }
                Some(Err(v)) if !(self.proxy_delegated() && unresolved_here(v)) => {
                    egress_audit::dial_refused(
                        planned.authority(),
                        Some(egress_class),
                        egress_audit::verdict_name(v),
                        None,
                    );
                    return Err(ConnError::Refused);
                }
                Some(Ok(at))
                    if !class_admits(
                        egress_class,
                        planned.secure(),
                        self.plain_admitted(&planned),
                        &[],
                        planned.authority(),
                        at,
                    ) =>
                {
                    egress_audit::dial_refused(
                        planned.authority(),
                        Some(egress_class),
                        "plaintext",
                        None,
                    );
                    return Err(ConnError::Refused);
                }
                Some(_) => {}
            }
            proxied.target_judged = true;
            proxied.target_at = judged.and_then(Result::ok);
            let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));
            let proxy_authority = proxied.spec.endpoint();
            // The configured CONNECT hop is operator infrastructure; its plaintext socket does
            // not change the separately judged application's TLS requirement.
            return match self.judge_into(
                proxy_authority,
                false,
                EGRESS_OPERATOR_INFRASTRUCTURE,
                true,
                &answer,
            ) {
                None => Ok((
                    None,
                    Some(Judging {
                        planned: Some(planned),
                        failed: None,
                        egress_class,
                        within: Within::new(),
                        early: VecDeque::new(),
                        answer,
                        proxied: Some(proxied),
                    }),
                )),
                Some(Err(v)) => {
                    *why = Some(verdict_reason(v, true));
                    Err(ConnError::Refused)
                }
                Some(Ok(at)) => {
                    let connect = proxy::connect_request(
                        &self.connect_target(&planned, proxied.target_at),
                        &proxied.spec,
                    );
                    let conn = planned.dial_through(at, connect).map_err(|f| map(&f))?;
                    Ok((Some(conn), None))
                }
            };
        }
        Ok(match judged {
            Some(Err(v)) => {
                egress_audit::dial_refused(
                    planned.authority(),
                    Some(egress_class),
                    egress_audit::verdict_name(v),
                    None,
                );
                return Err(ConnError::Refused);
            }
            Some(Ok(addr))
                if !class_admits(
                    egress_class,
                    planned.secure(),
                    self.plain_admitted(&planned),
                    within,
                    planned.authority(),
                    addr,
                ) =>
            {
                egress_audit::dial_refused(
                    planned.authority(),
                    Some(egress_class),
                    "plaintext",
                    None,
                );
                return Err(ConnError::Refused);
            }
            Some(Ok(addr)) => {
                let clear_window = self.holds_clear_window(&planned, addr);
                let mut conn = planned.dial_at(addr).map_err(|f| map(&f))?;
                if clear_window {
                    conn.hold_clear_window();
                }
                (Some(conn), None)
            }
            None => (
                None,
                Some(Judging {
                    planned: Some(planned),
                    failed: None,
                    egress_class,
                    within: Within::from_slice(within),
                    early: VecDeque::new(),
                    answer,
                    proxied: None,
                }),
            ),
        })
    }

    /// THE ONE REDIAL: `held` was lent a pooled line that failed before any byte of its exchange
    fn redial(&self, held: &Held) -> Result<bool, ConnError> {
        let mut kept = held.redial.lock().expect("redial");
        let mut home = held.line.lock().expect("line");
        if held.retired.load(Ordering::Acquire) {
            return Err(ConnError::Closed);
        }
        let Some((line, _)) = home.as_ref() else {
            return Ok(false);
        };
        if kept.as_ref().is_none_or(|r| line.flushed() != r.mark) {
            let spent = kept.take();
            drop(home);
            drop(kept);
            drop(spent);
            return Ok(false);
        }
        let Some(r) = kept.take() else {
            return Ok(false);
        };
        let (line, stream) = home.take().expect("the redial takes its old line once");
        drop(home);
        drop(kept);
        self.let_go(held, &line, stream, false);
        let at = framer::now().checked_add(r.dial.open_timeout).map(Due::new);
        let previous = std::mem::replace(&mut *held.dial_due.lock().expect("dial due"), at);
        drop(previous);
        let planned = self.plan(&r.door, r.dial).map_err(|f| map(&f))?;
        if r.require_secure && !planned.secure() {
            return Err(ConnError::AuthRefused);
        }
        let mut why = None;
        let dialled = self.dial_judged(
            planned,
            r.egress_class,
            r.judged_class,
            &[],
            r.reach,
            &mut why,
        );
        if let Some(why) = why {
            held.refused(why);
        }
        match dialled? {
            (Some(conn), _) => {
                self.ride(held, conn)?;
            }
            (None, judging) => *held.judging.lock().expect("judging") = judging,
        }
        Ok(true)
    }

    /// `held`'s exchange leaves `line` (`whole` = its answer was read to its end): the line goes
    fn let_go(&self, held: &Held, line: &Arc<Line>, stream: u64, whole: bool) {
        let left = line.leave(stream, whole);
        if left > 0 {
            return;
        }
        match &held.pooled {
            Some((shard, key)) if whole => self.pools.release(*shard, key, line),
            Some((shard, key)) => self.pools.drop_line(*shard, key, line),
            None => line.close(),
        }
    }

    /// One read of `conn`, waking `waker` when nothing is ready yet: the body [`Conns::read`] (a
    fn read_waking(
        &self,
        caller: InstanceId,
        conn: ConnId,
        waker: &Waker,
        interest: DeadlineInterest,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        held.watch_deadlines(interest, waker);

        held.within_due()?;
        if held.uncommitted.load(Ordering::Acquire) {
            self.settle(&held, Some(waker))?;
            return Err(ConnError::Pending);
        }
        let mut read = match &held.dialled {
            Some(d) => self.read_dialled(&held, d, waker, buf),
            None => self.read_held(&held, waker, buf),
        };
        if matches!(read, Err(ConnError::Pending)) {
            match self.observe_landing(&held, waker) {
                Ok(true) => waker.wake_by_ref(),
                Ok(false) => {}
                Err(error) => read = Err(error),
            }
        }

        if read
            .as_ref()
            .is_ok_and(|p| held.lease.is_none() || p.kind != PieceKind::Fields)
        {
            held.answered();
        }
        read
    }

    /// A read may finish the connect before any reply arrives. Retire its dial bound then,
    fn observe_landing(&self, held: &Held, waker: &Waker) -> Result<bool, ConnError> {
        if held.dial_due.lock().expect("dial due").is_none() {
            return Ok(false);
        }
        let Some((line, stream)) = held.line() else {
            return Ok(false);
        };
        let mut cx = Context::from_waker(waker);
        let landed = if held.uncommitted.load(Ordering::Acquire) {
            line.poll_prepared(stream, &mut cx)
        } else {
            line.poll_landed(stream, &mut cx)
        };
        match landed {
            Poll::Ready(Ok(())) => {
                held.landed();
                Ok(true)
            }
            Poll::Ready(Err(f)) => {
                held.answered();
                Err(map(&f))
            }
            Poll::Pending => Ok(false),
        }
    }

    /// One read of a held session's upstream leg: its exchange's pieces, judged (the far end's
    fn read_dialled(
        &self,
        held: &Held,
        d: &dialled::Dialled,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        while d.exchanging() {
            let piece = self.read_held(held, waker, buf)?;
            let len = piece.len.min(buf.len());
            if let Some(piece) = d.exchanged(piece, &buf[..len])? {
                return Ok(piece);
            }
        }
        d.read(waker, buf)
    }

    /// One read of `held`'s answer (see [`Self::read_waking`]).
    fn read_held(&self, held: &Held, waker: &Waker, buf: &mut [u8]) -> Result<Piece, ConnError> {
        if let Some((member, lease)) = &held.lease {
            return member.read(*lease, waker, buf);
        }
        let Some((mut reading, kept)) = Reading::begin(&held.rest, waker) else {
            return Err(ConnError::Pending);
        };
        let (piece, bytes) = match kept {
            Some(kept) => kept,
            None => {
                if reading.ended {
                    return Err(ConnError::Closed);
                }
                let got = loop {
                    if !self.settle(held, Some(waker))? {
                        return Err(ConnError::Pending);
                    }
                    let (line, stream) = held.line().ok_or(ConnError::Closed)?;
                    match line.poll_piece(stream, &mut Context::from_waker(waker)) {
                        Poll::Pending => return Err(ConnError::Pending),

                        Poll::Ready(Err(_) | Ok(None)) if self.redial(held)? => {}
                        Poll::Ready(Err(f)) => return Err(map(&f)),
                        Poll::Ready(Ok(None)) => {
                            reading.ended = true;
                            return Ok(completion(0));
                        }
                        Poll::Ready(Ok(Some(got))) => break (got, stream),
                    }
                };
                let (got, stream) = got;
                let dialled = stream != EVERY;

                *held.redial.lock().expect("redial") = None;
                if dialled && got.stream == stream && got.ends_stream() {
                    reading.ended = true;
                    held.whole.store(true, Ordering::Release);
                    return Ok(completion(got.stream));
                }
                if dialled && got.stream == stream && got.failed {
                    reading.ended = true;
                    return Err(ConnError::Fault);
                }

                if got.reason.is_some() {
                    held.reason.lock().expect("reason").clone_from(&got.reason);
                }
                (
                    Piece {
                        kind: if got.fields {
                            PieceKind::Fields
                        } else {
                            PieceKind::Body
                        },
                        stream: StreamId(got.stream),
                        len: 0,
                        end: got.end_of_frame,
                        status: class(got.status_class),
                        status_code: got.status_code,

                        status_namespace: got.status_namespace.as_deref().map(str::to_owned),
                        retry_after_secs: got.retry_after_secs,
                        fault: WireFault::from_code(got.fault),
                        reason: None,
                        declared_len: got.declared_len,
                    },
                    got.bytes,
                )
            }
        };
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        let mut out = piece.clone();
        out.len = n;
        if n < bytes.len() {
            out.end = false;
            // What the caller's buffer did not take stays in the piece's own buffer.
            let mut rest = bytes;
            rest.drain(..n);
            reading.left = Some((piece, rest));
        } else if out.kind == PieceKind::Fields && out.end {
            if let Some(reason) = held.reason.lock().expect("reason").take() {
                if let Some(to) = buf.get_mut(n..n + reason.len()) {
                    to.copy_from_slice(&reason);
                    out.reason = Some(n..n + reason.len());
                }
            }
        }
        Ok(out)
    }

    /// The waker of `owner`'s `ticket`: it names `owner` when it wakes.
    fn waker(&self, owner: InstanceId, ticket: Ticket) -> Waker {
        if ticket == NO_TICKET {
            return Waker::noop().clone();
        }
        Waker::from(Arc::new(TicketWake {
            wake: Arc::clone(&self.wake),
            owner,
            ticket,
        }))
    }
}

/// THE OFFERED-NAME RULE (`UpgradeIn::offered_name`, BUSBAR-6014): the name offered (SNI, and the
/// name verified) must be the dialled host when the dial names a host, compared as the guard maps
/// names (case, a trailing dot, IDNA); a dial to an IP literal may offer any DNS name (libpq
/// `hostaddr` + `host`). Trust is never selected by the offered name.
pub(crate) fn offered_name_admitted(target: &str, offered: &str) -> bool {
    use busbar_contract::net::{host_ip, judged_host};
    let mapped = |h: &str| {
        judged_host(h)
            .ok()
            .map(|m| m.trim_start_matches('[').trim_end_matches(']').to_owned())
            .filter(|m| !m.is_empty())
    };
    let Some(offered) = mapped(offered) else {
        return false;
    };
    let Some(dialled) = mapped(&host_of(target)) else {
        return false;
    };
    host_ip(&dialled).is_some() || dialled == offered
}

/// CA via `trust_from` (deprecated, refused from 1.7.0 once the core trust store exists): one info
/// line naming the SHA-256 of each operator anchor a need was declared with. No operator warning:
/// there is nothing the operator can move it to yet.
fn log_operator_anchors(owner: InstanceId, need: NeedId, trust_from: &str, roots: &[Vec<u8>]) {
    for der in roots {
        let digest = ring::digest::digest(&ring::digest::SHA256, der);
        let sha256: String = digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        tracing::info!(
            instance = owner.0,
            need = need.0,
            trust_from,
            sha256 = %sha256,
            "an outbound need trusts an operator CA from its plugin settings (deprecated: the core \
             trust store replaces it)"
        );
    }
}

/// The host name a dial target names: a URL's host, or a bare `host:port`'s host, unbracketed.
fn host_of(target: &str) -> std::borrow::Cow<'_, str> {
    if target.contains("://") {
        if let Ok(parts) = busbar_contract::net::parse_url(target) {
            return std::borrow::Cow::Owned(parts.host);
        }
    }
    let authority = target.split(['/', '?', '#']).next().unwrap_or(target);
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.contains(']') => h,
        _ => authority,
    };
    std::borrow::Cow::Borrowed(host.trim_start_matches('[').trim_end_matches(']'))
}

/// The piece that says the exchange finished.
fn completion(stream: u64) -> Piece {
    Piece {
        kind: PieceKind::Completion,
        stream: StreamId(stream),
        len: 0,
        end: true,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

/// Whether a dial target carries a userinfo (`user:pass@`): a URL by the contract's one reader, a
fn carries_userinfo(target: &str) -> bool {
    match busbar_contract::net::parse_url(target) {
        Ok(parts) => parts.userinfo,
        Err(_) => target
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@')),
    }
}

/// Whether a need's `target_from` reads its target from the plugin's OWN settings: one
fn settings_derived(target_from: &str) -> bool {
    target_from
        .strip_prefix("settings.")
        .is_some_and(|keys| keys.split('.').all(|k| !k.is_empty() && k != "*"))
}

/// `target` without its userinfo: the authority's text up to and including its last `@` left out,
fn without_userinfo(target: &str) -> Option<String> {
    let parts = busbar_contract::net::url_authority(target);
    parts.userinfo?;
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a declared target is cleared of its userinfo once, at declaration"
    )]
    let cleared = format!(
        "{}{}{}{}",
        parts.scheme.unwrap_or_default(),
        if parts.scheme.is_some() { "://" } else { "" },
        parts.host_port,
        parts.tail
    );
    Some(cleared)
}

impl DeclaredConns for Connector {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            require_secure,
            Some(dial_timeout_ms),
            false,
            (None, None),
        )
    }

    fn prepare_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            false,
            Some(dial_timeout_ms),
            true,
            (None, None),
        )
    }

    fn commit_request(
        &self,
        caller: InstanceId,
        conn: ConnId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), ConnError> {
        let (need, held) = self.slab.get(caller, conn)?;
        held.within_due()?;
        let authority_held = self
            .authority_held
            .lock()
            .expect("authority held")
            .contains(&caller);
        if request_head_is_refused(caller, need, desc, authority_held) {
            return Err(ConnError::Refused);
        }
        {
            let prepared = held.prepared.lock().expect("prepared");
            let (target, member, started) = prepared.as_ref().ok_or(ConnError::Refused)?;
            if target != desc.target || member != desc.member {
                return Err(ConnError::Refused);
            }
            if let Some(at) = due_at(*started, desc.timeout_ms) {
                let mut due = held.due.lock().expect("due");
                if due.as_ref().is_none_or(|previous| at < previous.at) {
                    let mut tighter = Due::new(at);
                    if let Some(previous) = due.as_ref() {
                        // Keep every registered deadline waiter when the HEAD adds a tighter bound.
                        tighter.wake = Arc::clone(&previous.wake);
                    }
                    *due = Some(tighter);
                }
            }
        }
        held.within_due()?;
        if !self.settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        match line.poll_prepared(stream, &mut Context::from_waker(Waker::noop())) {
            Poll::Pending => return Err(ConnError::Pending),
            Poll::Ready(result) => result.map_err(|f| map(&f))?,
        }
        held.landed();
        if require_secure && !line.secured() {
            return Err(ConnError::AuthRefused);
        }
        let declared = self
            .over
            .lock()
            .expect("needs")
            .get(&(caller, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        if desc
            .fields
            .iter()
            .any(|(name, _)| program::is_expected_field(name))
        {
            return Err(ConnError::Refused);
        }
        let target = line.target().ok_or(ConnError::Closed)?;
        let planned = self
            .plan(
                &declared.door,
                Dial {
                    tls: match declared.tls {
                        Some(own) => Some(own),
                        None => self.tls_for(&target)?,
                    },
                    target,
                    alpn: declared.alpn,
                    open_timeout: held.open_timeout,
                    anchors: None,
                    opening: Some((opening_fields(desc.fields, None), desc.body.clone())),
                    head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
                },
            )
            .map_err(|f| map(&f))?;
        // Consume once, before crossing plugin code and without holding a host lock.
        if held.prepared.lock().expect("prepared").take().is_none() {
            return Err(ConnError::Refused);
        }
        held.within_due()?;
        let (opening, words) = planned.into_opening();
        line.commit(stream, opening, words).map_err(|f| map(&f))?;
        held.uncommitted.store(false, Ordering::Release);
        Ok(())
    }

    fn hold_authority(&self, owner: InstanceId) {
        self.authority_held
            .lock()
            .expect("authority held")
            .insert(owner);
    }

    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let outbound = spec.direction == DIRECTION_OUTBOUND;

        let per_member = |path: &str| busbar_contract::section::member_target(path).is_some();

        let optional_trust = busbar_contract::section::owned_path(&spec.trust_from).is_some()
            || spec.trust_from.starts_with("settings.");
        let unresolved =
            (!spec.target_from.is_empty() && !per_member(&spec.target_from) && target.is_none())
                || (!spec.trust_from.is_empty()
                    && !per_member(&spec.trust_from)
                    && !optional_trust
                    && trust.is_none());

        let cleared = target
            .filter(|t| settings_derived(&spec.target_from) && carries_userinfo(t))
            .and_then(without_userinfo);
        let target = cleared.as_deref().or(target);
        let credentialed = target.is_some_and(carries_userinfo);
        let untargeted_infrastructure = outbound
            && spec.egress_class == EGRESS_OPERATOR_INFRASTRUCTURE
            && spec.target_from.is_empty()
            && self.framed_transport(&spec.transport);
        let anchored = match trust.filter(|_| outbound) {
            None => Ok(None),
            Some(pem) => tls::client::operator_ca_anchors(pem.as_bytes()).and_then(|roots| {
                log_operator_anchors(owner, need, &spec.trust_from, &roots);
                let policy = busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: roots,
                    ..Default::default()
                };
                tls::client::build_client_config(&policy)
                    .map(|config| Some((Arc::new(config), policy)))
                    .map_err(|e| e.to_string())
            }),
        };
        let untrusted = anchored.is_err();
        let mut why = None;
        let answer = match anchored {
            Ok(_) if !outbound => {
                if !spec.transport.is_empty() && !self.serves_scheme(&spec.transport) {
                    why = Some(NeedRefusal::Policy(refusal_text::UNSERVED));
                    Err(ConnError::Refused)
                } else {
                    self.slab.declare(owner, need);
                    Ok(())
                }
            }
            Ok(_) if untargeted_infrastructure => {
                self.flag_once(
                    owner,
                    &busbar_kernel::diagnostics::PLUGIN_DECLARES_RETIRED_ABI_VALUE,
                    busbar_kernel::audit::auditlog::PluginRefusal::Need,
                    &format!(
                        "an operator-infrastructure need over the framed transport `{}` names no \
                         config-declared target (`target_from`); the class is a property of a \
                         target the operator configured, never a plugin's choice, so the need is \
                         refused",
                        spec.transport
                    ),
                );
                self.set_need(owner, need, None);
                Err(ConnError::Refused)
            }
            Ok(tls) if !(spec.transport.is_empty() || unresolved || credentialed) => self
                .record(owner, need, &spec.transport, spec.egress_class, target, tls)
                .inspect_err(|_| {
                    why = Some(NeedRefusal::Policy(
                        if self.serves_scheme(&spec.transport) {
                            refusal_text::CHECKS
                        } else {
                            refusal_text::UNSERVED
                        },
                    ));
                })
                .and_then(|()| match target {
                    Some(pinned) => self
                        .admits_pinned(owner, need, pinned, spec.egress_class)
                        .map_err(|refused| {
                            self.set_need(owner, need, None);
                            why = Some(refused);
                            ConnError::Refused
                        }),
                    None => Ok(()),
                }),
            _ => {
                self.set_need(owner, need, None);
                why = Some(NeedRefusal::Policy(if credentialed {
                    refusal_text::CREDENTIALED
                } else if unresolved {
                    refusal_text::UNRESOLVED
                } else if untrusted {
                    refusal_text::TRUST
                } else {
                    refusal_text::CHECKS
                }));
                Err(ConnError::Refused)
            }
        };
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer, why));
        answer
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        let declared = self.declared.lock().expect("declared needs");
        declared.get(&(owner, need)).map(|(_, answer, _)| *answer)
    }

    /// THE MID-STREAM UPGRADE: the connection, once dialled, is secured with the need's own client
    fn upgrade_secure(
        &self,
        caller: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        ticket: Ticket,
    ) -> Result<(), ConnError> {
        let (need, held) = self.slab.get(caller, conn)?;
        if self.framed(caller, need) {
            return Err(ConnError::Refused);
        }
        let config = if verify_off {
            let class = self
                .over
                .lock()
                .expect("needs")
                .get(&(caller, need))
                .map(|d| d.egress_class);
            if class != Some(EGRESS_OPERATOR_INFRASTRUCTURE) {
                return Err(ConnError::Refused);
            }
            self.flag_once(
                caller,
                &busbar_kernel::diagnostics::PLUGIN_USES_DEPRECATED_ABI_VALUE,
                busbar_kernel::audit::auditlog::PluginRefusal::Open,
                "an operator-infrastructure connection was secured with UPGRADE_VERIFY_OFF: the far \
                 end's certificate is NOT verified. The flag is deprecated and refused from busbar \
                 1.7.0; configure the server's CA instead of disabling verification",
            );
            Arc::new(crate::tls::client::unverified_client_config())
        } else {
            let declared = self.declared.lock().expect("declared needs");
            let trust_from = declared
                .get(&(caller, need))
                .map(|(spec, _, _)| spec.trust_from.as_str());
            if trust.is_some_and(|t| Some(t) != trust_from) {
                return Err(ConnError::Refused);
            }
            // The need's own (deprecated) CA config, when it declared one; otherwise the trust
            // store selects by the guard-judged dial target below, never by the offered name.
            let over = self.over.lock().expect("needs");
            over.get(&(caller, need)).and_then(|d| d.tls.clone())
        };
        let waker = self.waker(caller, ticket);
        held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);
        held.within_due()?;
        if !self.settle(&held, Some(&waker))? {
            return Err(ConnError::Pending);
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        let target = line.target().ok_or(ConnError::Closed)?;
        let name = match name {
            Some(n) if !offered_name_admitted(&target, n) => {
                self.flag_once(
                    caller,
                    &busbar_kernel::diagnostics::PLUGIN_CALL_REFUSED_ABI_RULE,
                    busbar_kernel::audit::auditlog::PluginRefusal::Op,
                    &format!(
                        "upgrade_secure offered the name `{n}` for a dial to `{}`; the offered \
                         name must be the dialled host (any name only for a dial to an IP \
                         literal), so the upgrade is refused",
                        host_of(&target)
                    ),
                );
                return Err(ConnError::Refused);
            }
            Some(n) => n.to_owned(),
            None => host_of(&target),
        };

        let Some((mut reading, kept)) = Reading::begin(&held.rest, &waker) else {
            return Err(ConnError::Pending);
        };
        let answer = line.upgrade_secure(
            &config,
            &name,
            held.open_timeout,
            kept.is_some(),
            &mut Context::from_waker(&waker),
        );
        let over_clear = matches!(
            &answer,
            Poll::Ready(Err(Failure::Refused(t))) if t == compose::UPGRADE_OVER_CLEAR_BYTES
        );
        if !over_clear {
            reading.left = kept;
        }
        match answer {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Pending => Err(ConnError::Pending),
        }
    }

    /// THE DIAL HAS LANDED: its judgement answered and the far end took the connect (a name's
    fn landed(&self, caller: InstanceId, conn: ConnId, ticket: Ticket) -> Result<(), ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if held.lease.is_some() || held.dialled.is_some() {
            return Ok(());
        }
        let waker = self.waker(caller, ticket);
        held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);
        if !self.settle(&held, Some(&waker))? {
            return Err(ConnError::Pending);
        }
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        let mut cx = Context::from_waker(&waker);
        let landed = if held.uncommitted.load(Ordering::Acquire) {
            line.poll_prepared(stream, &mut cx)
        } else {
            line.poll_landed(stream, &mut cx)
        };
        match landed {
            Poll::Ready(Ok(())) => {
                held.landed();
                Ok(())
            }
            Poll::Ready(Err(f)) => Err(map(&f)),
            Poll::Pending => Err(ConnError::Pending),
        }
    }

    /// A need is framed when the entry serving its transport is a FRAMER (http's kind, over the
    fn request_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        self.framer_head(owner, need, target, timeout_ms)
    }

    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .is_some_and(|d| d.door.facts().role == ROLE_FRAMER)
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        Connector::serves_scheme(self, transport)
    }

    fn declare_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        program: &busbar_contract::conn::Program,
    ) -> Result<(), ConnError> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let answer = self.record_program(owner, need, spec, program, &scope);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer, None));
        answer
    }

    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        let (_, held) = self.slab.get(owner, conn).ok()?;
        let (line, _) = held.line()?;
        line.cause()
    }

    fn refusal(&self, owner: InstanceId, need: NeedId) -> Option<NeedRefusal> {
        let declared = self.declared.lock().expect("declared needs");
        declared
            .get(&(owner, need))
            .and_then(|(_, _, why)| why.clone())
    }

    fn conn_refusal(&self, owner: InstanceId, conn: ConnId) -> Option<NeedRefusal> {
        let (_, held) = self.slab.get(owner, conn).ok()?;
        if let Some(why) = held.why.get() {
            return Some(why.clone());
        }
        let (line, _) = held.line()?;
        if !line.failed_at_proxy() {
            return None;
        }
        let text = match line.cause() {
            Some(c) if c.stage == busbar_contract::abi::host::conn::connector::CAUSE_DEADLINE => {
                "the deadline passed before the proxy opened the tunnel".to_owned()
            }
            Some(c) if !c.text.is_empty() => c.text,
            _ => "the connection closed during the dial".to_owned(),
        };
        Some(NeedRefusal::ProxyUnreached(text))
    }

    fn bind_auth(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        origin: &str,
        binding: busbar_contract::conn::ConnAuth,
    ) {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a member's auth binding is bound once, keeping its names"
        )]
        self.auths
            .lock()
            .expect("auth bindings")
            .entry(owner)
            .or_default()
            .entry(need)
            .or_default()
            .entry(member.to_string())
            .or_default()
            .insert(origin.to_string(), binding);
    }

    fn auth_of(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
    ) -> Option<busbar_contract::conn::ConnAuth> {
        if member.is_empty() {
            return None;
        }
        let origin = busbar_contract::conn::origin_of(target);
        self.auths
            .lock()
            .expect("auth bindings")
            .get(&owner)
            .and_then(|needs| needs.get(&need))
            .and_then(|members| members.get(member))
            .and_then(|origins| origins.get(origin))
            .cloned()
    }

    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let answer = self.record_members(owner, need, spec, programs, &scope, None);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer, None));
        answer
    }

    fn declare_member_programs_from(
        &self,
        predecessor: InstanceId,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let fresh = !self
            .declared
            .lock()
            .expect("declared needs")
            .contains_key(&(owner, need));
        let previous = (fresh && predecessor != owner).then_some(predecessor);
        let answer = self.record_members(owner, need, spec, programs, &scope, previous);
        self.declared
            .lock()
            .expect("declared needs")
            .insert((owner, need), (spec.clone(), answer, None));
        answer
    }

    /// THE INSTANCE IS GONE: its connections close (a member lease among them ends), then every
    fn forget(&self, owner: InstanceId) {
        for conn in self.slab.forget(owner) {
            let _ = self.close(owner, conn);
        }
        self.pools.forget(owner);

        #[expect(
            clippy::disallowed_methods,
            reason = "config: an instance's retirement lets go of every listener it bound, once"
        )]
        let gone: Vec<Arc<Accepting>> = {
            let mut listeners = self.listeners.lock().expect("listeners");
            // busbar:expect(bp::state_scan, reason = "config: an instance's retirement finds every listener it bound, once")
            let keys: Vec<(InstanceId, NeedId)> = listeners
                .keys()
                .filter(|(o, _)| *o == owner)
                .copied()
                .collect();
            keys.iter().filter_map(|k| listeners.remove(k)).collect()
        };
        drop(gone);
        // busbar:expect(bp::state_scan, reason = "config: an instance's retirement finds every need it declared, once")
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an instance's retirement lets go of every need it declared, once"
        )]
        let needs: Vec<NeedId> = self
            .over
            .lock()
            .expect("needs")
            .keys()
            .filter(|(o, _)| *o == owner)
            .map(|(_, n)| *n)
            .collect();
        for need in needs {
            self.set_need(owner, need, None);
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an instance's retirement lets go of its declarations, once"
        )]
        self.declared
            .lock()
            .expect("declared needs")
            .retain(|(o, _), _| *o != owner);
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an instance's retirement lets go of its sealed anchors, once"
        )]
        self.anchored
            .lock()
            .expect("anchored")
            .retain(|(o, _, _), _| *o != owner);
        self.member_anchored
            .lock()
            .expect("member anchored")
            .forget(owner);
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an instance's retirement lets go of its registrations, once"
        )]
        self.registered
            .lock()
            .expect("registered")
            .retain(|(o, _, _), _| *o != owner);
        self.reaching.lock().expect("reaching").forget(owner);
        self.auths.lock().expect("auths").remove(&owner);
        self.authority_held
            .lock()
            .expect("authority held")
            .remove(&owner);
    }
}

impl Connector {
    /// Register a held session's `pairing` under its kernel-minted `unit` key, before the session
    pub fn pair(&self, unit: u64, pairing: Arc<datagram::Pairing>) -> Result<(), ConnError> {
        if unit == 0 {
            return Err(ConnError::Refused);
        }
        let mut pairs = self.pairs.lock().expect("pairs");
        if pairs.contains_key(&unit) {
            return Err(ConnError::Refused);
        }
        pairs.insert(unit, pairing);
        Ok(())
    }

    /// THE SESSION'S CLEANUP (once): its pairing leaves the book and closes, both legs with it, so
    pub fn unpair(&self, unit: u64) {
        let gone = self.pairs.lock().expect("pairs").remove(&unit);
        if let Some(p) = gone {
            p.close();
        }
    }

    /// A session's upstream offer mirrors metadata learned from its actual caller association.
    pub async fn wait_session_opening(&self, unit: u64) -> Result<(), ConnError> {
        let pairing = self.pairs.lock().expect("pairs").get(&unit).cloned();
        match pairing {
            Some(pairing) => pairing.wait_opening().await,
            None => Ok(()),
        }
    }

    /// THE COMPOSED OPEN of a held session's upstream leg over a datagram framer's need ([`dialled`]):
    #[expect(
        clippy::too_many_arguments,
        reason = "the composed open carries the open's every input to the exchange it dials"
    )]
    fn open_dialled(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        door: &Arc<dyn FramerDoor>,
        target: &str,
        open_timeout: Duration,
        (egress_class, declared_target, tls): (
            u32,
            Option<&str>,
            Option<Arc<rustls::ClientConfig>>,
        ),
        require_secure: bool,
        why: &mut Option<NeedRefusal>,
    ) -> Result<Held, ConnError> {
        if desc.unit == 0 {
            return Err(ConnError::Refused);
        }
        let pairing = self
            .pairs
            .lock()
            .expect("pairs")
            .get(&desc.unit)
            .cloned()
            .ok_or(ConnError::Refused)?;
        if pairing.closed() {
            return Err(ConnError::Refused);
        }
        let registry::Entry {
            door: exchange,
            alpn,
        } = self.rendezvous_exchange(target)?;

        let port = udp::bind(
            StackText::<SOCKET_TEXT>::of(&SocketAddr::new(pairing.local().ip(), 0)).as_str(),
        )
        .and_then(udp::ReadyPort::open)
        .map_err(|_| ConnError::Fault)?;
        let cert = Arc::new(dtls::SessionCert::mint().map_err(|_| ConnError::Fault)?);
        let judged_class = guard::judged_class(egress_class, declared_target.is_some());
        let (framing, began) = datagram::DatagramFraming::dial(
            Arc::clone(door),
            cert,
            port.local_addr(),
            &pairing.opening(),
            Arc::clone(&self.judge),
            judged_class,
        )
        .map_err(|_| ConnError::Refused)?;
        let description = began
            .pieces
            .iter()
            .find(|g| g.stream == 0 && !g.fields)
            .map(|g| g.bytes.as_slice())
            .ok_or(ConnError::Fault)?;
        let now = framer::now();
        let due = due_at(now, desc.timeout_ms);

        let body = dialled::composed_body(desc.fields, &desc.body, description)?;
        let held = self.dial_exchange(
            caller,
            need,
            &OpenDesc {
                body: body.into(),
                ..desc.clone()
            },
            (exchange, alpn),
            target,
            (now, open_timeout),
            (egress_class, declared_target, tls),
            false,
            require_secure,
            false,
            why,
        )?;
        let dialled = dialled::Dialled::new(framing, port, pairing, due).begun(began)?;
        Ok(held.dialling(dialled))
    }

    /// THE DIALLED EXCHANGE over `door` (a framer of a stream, or a carrier carried as itself):
    #[expect(
        clippy::too_many_arguments,
        reason = "the dialled exchange takes the open's every input as its callers resolved them"
    )]
    fn dial_exchange(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        (door, alpn): (Arc<dyn FramerDoor>, Vec<Vec<u8>>),
        target: &str,
        (now, open_timeout): (std::time::Instant, Duration),
        (egress_class, declared_target, tls): (
            u32,
            Option<&str>,
            Option<Arc<rustls::ClientConfig>>,
        ),
        poolable: bool,
        require_secure: bool,
        prepare: bool,
        why: &mut Option<NeedRefusal>,
    ) -> Result<Held, ConnError> {
        endpoint::named(target).map_err(|_| ConnError::Refused)?;
        // The answer the attempt's head was completed with, when it was located for this very
        // caller, need and target; any other is never trusted and the entry is asked afresh.
        let carried = located
            .filter(|located| located.answers(caller, need, target))
            .map(|located| framer::Located {
                authority: located.authority().to_owned(),
                name: located.name().map(str::to_owned),
                secure: located.secure(),
                offer: located.offer().to_vec(),
                defaults: located.defaults().to_vec(),
                states_length: located.states_length(),
            });
        let dial = Dial {
            target: target.to_owned(),
            tls: match tls {
                Some(own) => Some(own),
                None => self.tls_for(target)?,
            },
            alpn,
            open_timeout,
            opening: (!prepare).then(|| (opening_fields(desc.fields, owned), desc.body.clone())),
            head_words: if prepare {
                (Vec::new(), Vec::new())
            } else {
                (desc.method.to_vec(), desc.head_target.to_vec())
            },
            anchors: None,
        };

        let trust = dial.tls.clone().map(Same);
        let planned = self
            .plan_carried(&door, dial, carried)
            .map_err(|f| map(&f))?;
        if require_secure && !planned.secure() {
            return Err(ConnError::AuthRefused);
        }

        let authority = planned.authority().to_ascii_lowercase();
        let own = (!desc.member.is_empty())
            .then(|| {
                self.member_anchored
                    .lock()
                    .expect("anchors")
                    .get(caller, need, desc.member)
                    .filter(|(at, _)| *at == authority)
                    .map(|(_, sealed)| sealed.clone())
            })
            .flatten();

        let anchored_as = own.is_some().then(|| desc.member.to_owned());

        let anchors = match own {
            Some(sealed) => sealed,
            None => {
                let at = (caller, need, authority);
                let anchored = self.anchored.lock().expect("anchors");
                let own = anchored.get(&at);
                match self.registered.lock().expect("anchors").get(&at) {
                    Some(registered) => registered.held(own)?,
                    None => own.cloned(),
                }
            }
        };

        let anchors = if let Some(sealed) = anchors.as_ref().filter(|s| !s.extra_anchors.is_empty())
        {
            let needs = self.over.lock().expect("needs");
            let current = match needs.get(&(caller, need)) {
                Some(d) if d.tls.is_some() => d.tls_policy.as_ref(),
                _ => self.tls_policy.as_ref(),
            };
            if sealed.policy.as_ref() != current {
                Some(tls::client::rebase(sealed, current).map_err(|_| ConnError::Refused)?)
            } else {
                anchors
            }
        } else {
            anchors
        };

        let sealed = anchors.clone().map(Same);
        if anchors.as_ref().is_some_and(|a| {
            (a.key_pin.is_some() || !a.extra_anchors.is_empty()) && !planned.secure()
        }) {
            return Err(ConnError::Refused);
        }
        let planned = planned.anchored(anchors);

        let reach = !desc.member.is_empty()
            && self
                .reaching
                .lock()
                .expect("reach")
                .get(caller, need, desc.member)
                .is_some_and(|at| at.eq_ignore_ascii_case(planned.authority()));

        let judged_class = guard::judged_class(egress_class, declared_target.is_some());

        if let Some(declared) = declared_target {
            let located = self.located(&door, declared).ok_or(ConnError::Refused)?;
            if !located.authority.eq_ignore_ascii_case(planned.authority())
                || located.secure != planned.secure()
            {
                return Err(ConnError::Refused);
            }
        }

        if !scheme_admits(egress_class, planned.secure()) {
            return Err(ConnError::Refused);
        }

        let pooled = (poolable && self.pools.keeps() && desc.within.is_empty()).then(|| {
            (
                self.pools.shard(),
                self.pools.keyed(PoolKey {
                    owner: caller,
                    need,
                    door: Arc::as_ptr(&door).cast::<()>() as usize,
                    authority: planned.authority().to_ascii_lowercase(),
                    secure: planned.secure(),
                    name: planned.name().map(str::to_owned),
                    class: (judged_class, egress_class),
                    reach,
                    anchored_as,
                    trust,
                    sealed,
                    hash: 0,
                }),
            )
        });
        let mut planned = planned;
        if let Some((shard, key)) = &pooled {
            if let Some(line) = self.pools.lend(*shard, key) {
                let redial = Redial {
                    door: Arc::clone(&door),
                    dial: planned.dial().clone(),
                    egress_class,
                    judged_class,
                    require_secure,
                    reach,
                    mark: line.flushed(),
                };
                let (opening, words) = planned.into_opening();
                match line.attach(opening, words) {
                    Ok(stream) => {
                        let held = Held::over(Some((line, stream)), None, pooled)
                            .bounded(now, desc.timeout_ms);
                        *held.redial.lock().expect("redial") = Some(redial);
                        return Ok(held);
                    }

                    Err((stream, _)) if line.flushed() != redial.mark => {
                        let held = Held::over(Some((line, stream)), None, pooled)
                            .bounded(now, desc.timeout_ms);
                        return Ok(held);
                    }

                    Err((stream, _)) => {
                        line.leave(stream, false);
                        self.pools.drop_line(*shard, key, &line);
                        planned = self.plan(&redial.door, redial.dial).map_err(|f| map(&f))?;
                    }
                }
            }
        }
        if require_secure && !planned.secure() {
            return Err(ConnError::AuthRefused);
        }
        let (conn, judging) =
            self.dial_judged(planned, egress_class, judged_class, desc.within, reach, why)?;
        let held = Held::over(None, judging, pooled)
            .bounded(now, desc.timeout_ms)
            .dial_bounded(now, open_timeout);
        if let Some(conn) = conn {
            self.ride(&held, conn)?;
        }
        Ok(held)
    }
}

impl Connector {
    /// Open `desc` on `caller`'s `need`, holding why the open failed before any connection existed
    /// as the need's refusal ([`DeclaredConns::refusal`]); an open that succeeds clears it.
    fn open_timed(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: Option<u64>,
        prepare: bool,
        (located, owned): (Option<&LocatedTarget>, Option<OwnedHead>),
    ) -> Result<ConnId, ConnError> {
        let started = framer::now();
        self.slab.check_need(caller, need)?;
        let declared_timeout_ms = self
            .declared
            .lock()
            .expect("declared needs")
            .get(&(caller, need))
            .map_or(0, |(spec, _, _)| spec.timeout_ms);
        let dial_timeout_ms = dial_timeout_ms.unwrap_or(desc.timeout_ms);
        let dial_timeout_ms = if dial_timeout_ms == 0 {
            declared_timeout_ms
        } else {
            dial_timeout_ms
        };
        let open_timeout = if dial_timeout_ms == 0 {
            DEFAULT_OPEN_TIMEOUT
        } else {
            Duration::from_millis(dial_timeout_ms)
        };
        let authority_held = self
            .authority_held
            .lock()
            .expect("authority held")
            .contains(&caller);
        // The head the opener built and moved in, where it did: every check below reads it as the
        // borrowed fields an opener lending it would have passed, and the dial keeps it uncopied.
        let lent = owned.as_ref().map(OwnedHead::view);
        let viewed = lent.as_deref().map(|fields| OpenDesc {
            fields,
            ..desc.clone()
        });
        let read = viewed.as_ref().unwrap_or(desc);
        if request_head_is_refused(caller, need, read, authority_held) {
            return Err(ConnError::Refused);
        }

        let DeclaredNeed {
            door,
            alpn,
            egress_class,
            declared_target,
            tls,
            tls_policy: _,
            program,
            members,
            member_spec: _,
        } = self
            .over
            .lock()
            .expect("needs")
            .get(&(caller, need))
            .cloned()
            .ok_or(ConnError::Refused)?;
        if members.is_none()
            && read
                .fields
                .iter()
                .any(|(name, _)| program::is_expected_field(name))
        {
            return Err(ConnError::Refused);
        }

        if prepare && (members.is_some() || program.is_some() || door.facts().datagram) {
            return Err(ConnError::Refused);
        }

        if let Some(members) = members {
            if require_secure {
                return Err(ConnError::AuthRefused);
            }
            let expected = program::Expected::of(read.fields)?;
            let member = members
                .get(program::member_of(desc.target))
                .map(|declaration| declaration.member())
                .ok_or(ConnError::Refused)?;

            drop(members);
            let lease = member.lease(&desc.body, expected)?;
            let mut held = Held::over(None, None, None).bounded(started, desc.timeout_ms);
            held.lease = Some((member, lease));

            return self.slab.insert(caller, need, held);
        }

        if let Some((program, env)) = program {
            if require_secure {
                return Err(ConnError::AuthRefused);
            }
            if !desc.target.is_empty() {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                target: program.command.clone(),
                tls: None,
                alpn,
                open_timeout,
                opening: Some((opening_fields(desc.fields, owned), desc.body.clone())),
                head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            };
            let via = Via {
                door,
                io: Arc::clone(&self.io),
            };

            let conn = Connection::spawn(&via, &program, &env, dial, 0).map_err(|f| map(&f))?;

            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None)
                    .bounded(started, desc.timeout_ms)
                    .dial_bounded(started, open_timeout),
            );
        }

        let declared_target = declared_target.as_deref();
        let target = match (desc.target, declared_target) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        };

        if door.facts().datagram {
            let held = self.open_dialled(
                caller,
                need,
                read,
                &door,
                target,
                open_timeout,
                (egress_class, declared_target, tls),
                require_secure,
                why,
            )?;
            return self.slab.insert(caller, need, held);
        }

        if let Some(path) = socket::unix_path(target) {
            if prepare {
                return Err(ConnError::Refused);
            }
            if require_secure {
                return Err(ConnError::AuthRefused);
            }
            if egress_class != EGRESS_OPERATOR_INFRASTRUCTURE
                || declared_target.is_some_and(|d| d != target)
            {
                return Err(ConnError::Refused);
            }
            let dial = Dial {
                anchors: None,
                target: target.to_owned(),
                tls: None,
                alpn,
                open_timeout,
                opening: Some((opening_fields(desc.fields, owned), desc.body.clone())),
                head_words: (desc.method.to_vec(), desc.head_target.to_vec()),
            };
            let (framer, via) = self.ride_on(&door).ok_or(ConnError::Refused)?;
            let conn = Connection::dial_unix(framer, &via, dial, path).map_err(|f| map(&f))?;

            let line = Line::new(conn);
            return self.slab.insert(
                caller,
                need,
                Held::over(Some((line, EXCHANGE_STREAM)), None, None)
                    .bounded(started, desc.timeout_ms)
                    .dial_bounded(started, open_timeout),
            );
        }
        let held = self.dial_exchange(
            caller,
            need,
            desc,
            (door, alpn),
            target,
            (started, open_timeout),
            (egress_class, declared_target, tls),
            !prepare,
            require_secure,
            prepare,
            why,
        )?;
        if prepare {
            *held.prepared.lock().expect("prepared") =
                Some((desc.target.to_owned(), desc.member.to_owned(), started));
            held.uncommitted.store(true, Ordering::Release);
        }
        let rejected = held
            .line()
            .map(|(line, stream)| (line, stream, held.pooled.clone()));
        let inserted = self.slab.insert(caller, need, held);
        if inserted.is_err() {
            if let Some((line, stream, pooled)) = rejected {
                line.leave(stream, false);
                match pooled {
                    Some((shard, key)) => self.pools.drop_line(shard, &key, &line),
                    None => line.close(),
                }
            }
        }
        inserted
    }
}

impl Conns for Connector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.open_with_security(caller, need, desc, false)
    }

    fn open_with_security(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            require_secure,
            None,
            false,
            (None, None),
        )
    }

    fn open_located(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        located: Option<&LocatedTarget>,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            require_secure,
            None,
            false,
            (located, None),
        )
    }

    fn open_owned(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        head: OwnedHead,
        require_secure: bool,
        located: Option<&LocatedTarget>,
    ) -> Result<ConnId, ConnError> {
        self.open_timed(
            caller,
            need,
            desc,
            require_secure,
            None,
            false,
            (located, Some(head)),
        )
    }

    /// A write is taken whole, short, or (no room under
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        if held.uncommitted.load(Ordering::Acquire) {
            return Err(ConnError::Pending);
        }
        if let Some((member, lease)) = &held.lease {
            return member.write(*lease, bytes);
        }
        if let Some(d) = held.dialled.as_ref() {
            return d.write(bytes, end, text);
        }
        if !self.settle(&held, None)? {
            let mut judging = held.judging.lock().expect("judging");

            if held.crossing.lock().expect("crossing").is_some() {
                return Err(ConnError::Pending);
            }
            if let Some(j) = judging.as_mut() {
                if let Some(error) = j.failed {
                    return Err(error);
                }

                if j.early.back().is_some_and(|(bytes, _, _)| bytes.is_empty()) {
                    return Err(ConnError::Pending);
                }
                let held_bytes: usize = j.early.iter().map(|(b, _, _)| b.len()).sum();
                let take = bytes
                    .len()
                    .min(WRITE_BUFFER_BYTES.saturating_sub(held_bytes));
                if take == 0 && !bytes.is_empty() {
                    return Err(ConnError::Pending);
                }
                j.early.push_back((
                    Bytes::copy_from_slice(&bytes[..take]),
                    end && take == bytes.len(),
                    text,
                ));
                return Ok(take);
            }

            return Err(ConnError::Pending);
        }
        let (line, stream) = held.line().ok_or(ConnError::Closed)?;
        let got = line.emit(stream, bytes, end, text);
        if got.is_ok() {
            let _ = self.observe_landing(&held, Waker::noop());
        }
        match got {
            Ok(0) if !bytes.is_empty() => Err(ConnError::Pending),
            got => got.map_err(|f| map(&f)),
        }
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.read_waking(
            caller,
            conn,
            &self.waker(caller, ticket),
            DeadlineInterest::Ticket(ticket),
            buf,
        )
    }

    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        let waker = self.waker(caller, ticket);
        let mut cx = Context::from_waker(&waker);
        for (at, conn) in set.iter().enumerate() {
            let (_, held) = self.slab.get(caller, *conn)?;
            held.watch_deadlines(DeadlineInterest::Ticket(ticket), &waker);

            if held.within_due().is_err() {
                return Ok(at);
            }
            if let Some((member, lease)) = &held.lease {
                match member.ready(*lease, &waker) {
                    Ok(false) => continue,
                    _ => return Ok(at),
                }
            }
            if let Some(d) = held.dialled.as_ref().filter(|d| !d.exchanging()) {
                if d.ready(&waker) {
                    return Ok(at);
                }
                continue;
            }
            if held.rest.lock().expect("rest").piece.is_some() {
                return Ok(at);
            }
            match self.settle(&held, Some(&waker)) {
                Ok(false) => continue,
                Err(_) => return Ok(at),
                Ok(true) => {}
            }
            let Some((line, stream)) = held.line() else {
                return Ok(at);
            };
            if line.poll_ready(stream, &mut cx).is_ready() {
                let _ = self.observe_landing(&held, &waker);
                return Ok(at);
            }
            match self.observe_landing(&held, &waker) {
                Ok(true) => waker.wake_by_ref(),
                Err(_) => return Ok(at),
                Ok(false) => {}
            }
        }
        Err(ConnError::Pending)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let (_, held) = self.slab.get(caller, conn)?;
        held.within_due()?;
        if let Some((member, lease)) = &held.lease {
            return member.facts(*lease);
        }
        if !self.settle(&held, None)? {
            return Err(ConnError::Pending);
        }
        if held.uncommitted.load(Ordering::Acquire) {
            let (line, stream) = held.line().ok_or(ConnError::Closed)?;
            match line.poll_prepared(stream, &mut Context::from_waker(Waker::noop())) {
                Poll::Pending => return Err(ConnError::Pending),
                Poll::Ready(result) => result.map_err(|f| map(&f))?,
            }
            held.landed();
        }
        let (line, _) = held.line().ok_or(ConnError::Closed)?;
        let e = line.established().ok_or(ConnError::Closed)?;
        Ok(ConnFacts {
            sni: e.offered_name.clone(),
            alpn: e
                .agreed_protocol
                .as_ref()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            peer_cert: line.peer_cert_hash().map(|fingerprint| {
                busbar_contract::transport::wire::CertFacts {
                    subject: String::new(),
                    issuer: String::new(),
                    fingerprint,
                }
            }),
            claim: e.claim.clone(),
            peer_key_pin: e.peer_key_pin.clone(),
            client_identity: e.client_identity,
        })
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let held = self.slab.remove(caller, conn)?;
        let line = {
            let mut home = held.line.lock().expect("line");
            held.retired.store(true, Ordering::Release);
            home.take()
        };
        held.answered();
        if let Some((member, lease)) = &held.lease {
            member.close(*lease);
        }
        if let Some(d) = &held.dialled {
            d.close();
        }
        if let Some((line, stream)) = line {
            self.let_go(&held, &line, stream, held.whole.load(Ordering::Acquire));
        }
        Ok(())
    }
}

impl PollConns for Connector {
    fn failure_cause(&self, caller: InstanceId, conn: ConnId) -> Option<ConnCause> {
        DeclaredConns::cause(self, caller, conn)
    }

    /// The framer the need rides, located at `target`: its own head lines, and whether its head
    fn head_defaults(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        self.framer_head(owner, need, target, timeout_ms)
    }

    fn locate_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<(HeadDefaults, Option<Arc<LocatedTarget>>), ConnError> {
        self.framer_located(owner, need, target, timeout_ms)
    }

    fn poll_read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        match self.read_waking(caller, conn, cx.waker(), DeadlineInterest::Task, buf) {
            Err(ConnError::Pending) => Poll::Pending,
            done => Poll::Ready(done),
        }
    }

    /// The anchors are sealed against the authority the need's own entry locates `target` at, the
    fn anchor(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
        anchors: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), ConnError> {
        let declared = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .cloned();
        let door = declared.as_ref().map(|d| Arc::clone(&d.door));
        let base = declared
            .as_ref()
            .and_then(|d| d.tls.as_deref())
            .or(self.tls.as_deref());
        let policy = match declared.as_ref() {
            Some(d) if d.tls.is_some() => d.tls_policy.as_ref(),
            _ => self.tls_policy.as_ref(),
        };
        let located = door.as_ref().and_then(|door| self.located(door, target));
        let at = located.map(|mut l| {
            l.authority.make_ascii_lowercase();
            (owner, need, l.authority)
        });
        let sealed = match (&at, anchors.is_empty()) {
            (_, true) => None,
            (None, false) => return Err(ConnError::Refused),
            (Some(_), false) => Some(Arc::new(
                tls::client::seal_with_policy(base, policy, anchors)
                    .map_err(|_| ConnError::Refused)?,
            )),
        };

        if member.is_empty() {
            let Some(at) = at else {
                return Ok(());
            };
            let mut anchored = self.anchored.lock().expect("anchors");
            match sealed {
                Some(sealed) => {
                    anchored.insert(at, sealed);
                }

                None => {
                    anchored.remove(&at);
                }
            }
            return Ok(());
        }
        let mut by_member = self.member_anchored.lock().expect("anchors");
        let mut registered = self.registered.lock().expect("anchors");
        let before = match &at {
            Some((_, _, authority)) => {
                by_member.insert(owner, need, member, (authority.clone(), sealed.clone()))
            }
            None => by_member.remove(owner, need, member),
        };
        if let Some((was, _)) = before {
            let was = (owner, need, was);
            if let Some(at_was) = registered.get_mut(&was) {
                at_was.members.remove(member);
                if at_was.members.is_empty() {
                    registered.remove(&was);
                }
            }
        }
        if let Some(at) = at {
            #[expect(
                clippy::disallowed_methods,
                reason = "config: a registration's seal is recorded at its destination once, at declaration"
            )]
            registered
                .entry(at)
                .or_default()
                .members
                .insert(member.to_owned(), sealed);
        }
        Ok(())
    }

    /// The registration's own target's authority is read by the need's entry, as a dial reads it;
    fn seal_reach(
        &self,
        owner: InstanceId,
        need: NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), ConnError> {
        if !reach {
            self.reaching
                .lock()
                .expect("reach")
                .remove(owner, need, member);
            return Ok(());
        }
        let door = self
            .over
            .lock()
            .expect("needs")
            .get(&(owner, need))
            .map(|d| Arc::clone(&d.door))
            .ok_or(ConnError::Refused)?;
        let mut located = self.located(&door, target).ok_or(ConnError::Refused)?;
        if member.is_empty() {
            return Err(ConnError::Refused);
        }
        located.authority.make_ascii_lowercase();
        self.reaching
            .lock()
            .expect("reach")
            .insert(owner, need, member, located.authority);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/connector_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/real_tcp_tests.rs"]
mod real_tcp_tests;

#[cfg(test)]
#[path = "tests/callback_waker.rs"]
#[allow(unsafe_code)]
mod callback_waker;

#[cfg(test)]
#[path = "tests/rest_callback_tests.rs"]
mod rest_callback_tests;

#[cfg(test)]
#[path = "tests/settled_dial_error_tests.rs"]
mod settled_dial_error_tests;

#[cfg(test)]
#[path = "tests/trust_from_tests.rs"]
mod trust_from_tests;

#[cfg(test)]
#[path = "tests/explain_tests.rs"]
mod explain_tests;

#[cfg(test)]
#[path = "tests/upgrade_tests.rs"]
mod upgrade_tests;

#[cfg(test)]
#[path = "tests/unix_target_tests.rs"]
mod unix_target_tests;

#[cfg(test)]
#[allow(unsafe_code, dead_code)]
#[path = "tests/support.rs"]
mod support;

#[cfg(test)]
#[path = "tests/refresh_binding_tests.rs"]
mod refresh_binding_tests;

#[cfg(test)]
#[path = "tests/lease_release_tests.rs"]
mod lease_release_tests;

#[cfg(test)]
#[path = "tests/completed_head_tests.rs"]
mod completed_head_tests;
