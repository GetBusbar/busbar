// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE MEDIA RENDEZVOUS, ONE SESSION (IF §8.7, §12.13, §13): the connector's side of a datagram transport's
//! `TransportSession`. The transport parses and writes SDP and decides which pair to nominate; every packet
//! decision is core's, and this is where it is made, with no socket in it (the port driver in `carrier` feeds
//! it datagrams and sends what it queues).
//!
//! What the session does, in the order a call goes:
//! * `begin` hands the transport the host DTLS certificate's fingerprint (`ConnIn.local_fingerprint`) and, for a
//!   dial, the opening. The answer must carry ICE_TERMS: a session no check can be routed to is refused.
//! * ICE_TERMS register the local ufrag (the port's demux key, see [`Session::take_ufrag_move`]) and give the
//!   [`Association`] its credentials. An inbound check is verified (USERNAME, MESSAGE-INTEGRITY with the local
//!   pwd) by the association before its source becomes a path (`EV_PATH` `PATH_NEW | PATH_VERIFIED`).
//! * ICE_CANDIDATE is judged by the destination judge before a path id exists for it or a check goes to it
//!   (refused: `PATH_DENIED`, audited `ice_candidate_denied`).
//! * PATH_BIND / PATH_REBIND ask the association to make a verified path the bound one (`PATH_BOUND`, else
//!   `PATH_REJECTED`). A secured SEND_TO goes only to the bound path; a clear one only where the association
//!   allows it; the rest are dropped and counted.
//! * SECURE gives the far end's role and certificate digest. DTLS runs through the association on the bound
//!   path, compares the far end's certificate with that digest after the handshake and before exporting keys,
//!   and a mismatch yields no `EV_KEYING`, `PATH_REJECTED` and the audit `dtls_fingerprint_mismatch`.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use busbar_kernel::media::Lines;
use busbar_kernel::plugin_records::RecordsDenied;
use busbar_plugin_abi::kinds::transport::transport as wire;
use busbar_plugin_abi::records::{tag, Records};
use busbar_ports::transport::{
    ConnIn, TransportEvent, TransportOut, TransportPort, TransportSession,
};
use busbar_ports::PortError;
use foldhash::HashMap;

use super::{Association, Failure, IceCredentials, Role, SessionCert, SrtpKeying, Up, Verdict};
use crate::DialJudge;

/// The most paths (heard sources and judged candidates) one session numbers.
const MAX_PATHS: usize = 64;
/// The most lines and channels one session records.
const MAX_LINES: usize = 64;

/// Where the audit record of a media-session refusal goes: `dtls_fingerprint_mismatch` and
/// `ice_candidate_denied`. The detail never carries a credential, a digest or an address of the caller.
pub trait MediaAudit: Send + Sync + 'static {
    /// One audit record named `event`.
    fn record(&self, event: &'static str, detail: &str);
}

/// A live transport session: the four calls a datagram session takes, with its handle inside. The one
/// production form is [`Ported`]; a test supplies a scripted one.
pub(crate) trait Live: Send {
    /// `TransportPort::event`.
    fn event(
        &mut self,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
    /// `TransportPort::datagram`.
    fn datagram(
        &mut self,
        path: u32,
        secured: bool,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError>;
    /// `TransportPort::timer`.
    fn timer(&mut self, sink: &mut dyn FnMut(TransportOut<'_>)) -> Result<(), PortError>;
}

/// Begins live transport sessions.
pub(crate) trait Opener: Send + Sync + 'static {
    /// `TransportPort::begin`.
    fn begin(
        &self,
        conn: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<Box<dyn Live>, PortError>;
}

/// A datagram transport instance's port, as an [`Opener`].
pub(crate) struct Ported(pub(crate) Arc<dyn TransportPort>);

/// One session of a [`Ported`] transport: dropping it drops the transport's session.
struct PortedSession {
    port: Arc<dyn TransportPort>,
    handle: TransportSession,
}

impl Opener for Ported {
    fn begin(
        &self,
        conn: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<Box<dyn Live>, PortError> {
        let handle = self.0.begin(conn, sink)?;
        Ok(Box::new(PortedSession {
            port: Arc::clone(&self.0),
            handle,
        }))
    }
}

impl Live for PortedSession {
    fn event(
        &mut self,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.port.event(&mut self.handle, ev, sink)
    }

    fn datagram(
        &mut self,
        path: u32,
        secured: bool,
        bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        self.port
            .datagram(&mut self.handle, path, secured, bytes, sink)
    }

    fn timer(&mut self, sink: &mut dyn FnMut(TransportOut<'_>)) -> Result<(), PortError> {
        self.port.timer(&mut self.handle, sink)
    }
}

/// What opens a session.
pub(crate) struct Params {
    /// `CONN_DIAL` (the connector reaches out: its candidates are admitted and probed) rather than `CONN_ACCEPT`.
    pub(crate) dial: bool,
    /// The media port's bound address, as `ConnIn.local` states it.
    pub(crate) local: SocketAddr,
    /// A dial's opening (`ConnInfo.head`), empty for an accept.
    pub(crate) opening: Vec<u8>,
    /// The destination judge and egress class the session's candidates are judged under; none refuses them all.
    pub(crate) judge: Option<(Arc<dyn DialJudge>, u32)>,
}

/// What the transport answered, owned: a `TransportOut` borrows the transport's buffer, and the session
/// acts on it only after the call returned.
enum Act {
    Send {
        path: u32,
        secured: bool,
        bytes: Vec<u8>,
    },
    Close,
    Wake(u64),
    Line(Line),
    Secure {
        path: u32,
        role: u32,
        alg: u32,
        digest: Vec<u8>,
    },
    Rendezvous(Box<str>),
    Terms {
        controlling: bool,
        local: IceCredentials,
        remote: IceCredentials,
    },
    Candidate(Box<str>),
    Bind {
        path: u32,
        from: Option<u32>,
    },
}

/// A line (media kind) or a data channel (label) a stream head names.
enum Line {
    Media(Box<str>),
    Channel(Box<str>),
}

/// What the session owes the transport next, in order.
enum Ev {
    Path {
        path: u32,
        flags: u32,
        addr: Box<str>,
    },
    Keying {
        path: u32,
        keying: SrtpKeying,
    },
    Datagram {
        path: u32,
        secured: bool,
        bytes: Vec<u8>,
    },
}

/// One numbered far-end address.
struct Slot {
    addr: SocketAddr,
    /// `PATH_VERIFIED` has been told.
    told_verified: bool,
    /// The candidate was refused by the judge: nothing is ever sent to it.
    denied: bool,
}

/// The session's numbering of far-end addresses (`path` ids start at 1; 0 means "none").
#[derive(Default)]
struct Paths {
    by_addr: HashMap<SocketAddr, u32>,
    by_id: HashMap<u32, Slot>,
    last: u32,
}

impl Paths {
    fn id(&self, addr: SocketAddr) -> Option<u32> {
        self.by_addr.get(&addr).copied()
    }

    fn slot(&self, id: u32) -> Option<&Slot> {
        self.by_id.get(&id)
    }

    /// The id of `addr`, numbering it when new (`true`); `None` at the cap.
    fn number(&mut self, addr: SocketAddr) -> Option<(u32, bool)> {
        if let Some(id) = self.id(addr) {
            return Some((id, false));
        }
        if self.by_id.len() >= MAX_PATHS {
            return None;
        }
        self.last += 1;
        let id = self.last;
        self.by_addr.insert(addr, id);
        self.by_id.insert(
            id,
            Slot {
                addr,
                told_verified: false,
                denied: false,
            },
        );
        Some((id, true))
    }
}

/// One media session: the transport's session, the association that carries its ICE and DTLS, and the
/// numbering between them.
pub(crate) struct Session {
    handle: Option<Box<dyn Live>>,
    cert: Arc<SessionCert>,
    assoc: Option<Association>,
    dialling: bool,
    judge: Option<(Arc<dyn DialJudge>, u32)>,
    audit: Arc<dyn MediaAudit>,
    paths: Paths,
    events: VecDeque<Ev>,
    out: VecDeque<(SocketAddr, Vec<u8>)>,
    /// The transport's WAKE_AT, in the host clock's nanoseconds.
    wake: Option<u64>,
    lines: Lines,
    rendezvous: Option<Box<str>>,
    /// The local ufrag now registered as this session's demux key.
    ufrag: Option<Box<str>>,
    /// A ufrag change not yet taken: (the old key, the new one).
    ufrag_moved: Option<(Option<Box<str>>, Box<str>)>,
    /// Addresses numbered since the port last took them (its by-address routes).
    new_addrs: Vec<SocketAddr>,
    bound_told: Option<u32>,
    failure_told: bool,
    closed: bool,
    ended: bool,
    dropped: u64,
    denied: u64,
}

/// `fp`'s SDP form, `sha-256 AA:BB:...` (the `a=fingerprint` value the transport writes into its answer).
pub(crate) fn sdp_fingerprint(fp: [u8; 32]) -> String {
    let mut text = String::from("sha-256 ");
    for (i, b) in fp.iter().enumerate() {
        if i > 0 {
            text.push(':');
        }
        let _ = write!(text, "{b:02X}");
    }
    text
}

fn creds(ufrag: &str, pwd: &[u8]) -> IceCredentials {
    IceCredentials {
        ufrag: String::from(ufrag),
        pwd: std::str::from_utf8(pwd)
            .map(String::from)
            .unwrap_or_default(),
    }
}

/// The line or channel a stream head names: `kind` makes it a media line, `label` a data channel (today's
/// `stream_head`, kept).
fn line_of(head: Records<'_>) -> Option<Line> {
    let mut label = None;
    for rec in head {
        let Ok(rec) = rec else {
            return None;
        };
        if rec.tag != tag::PAIR {
            continue;
        }
        let Ok((name, value)) = rec.pair() else {
            continue;
        };
        let Ok(value) = std::str::from_utf8(value) else {
            continue;
        };
        match name {
            "kind" => return Some(Line::Media(Box::from(value.trim()))),
            "label" => label = Some(value),
            _ => {}
        }
    }
    label.map(|l| Line::Channel(Box::from(l.trim())))
}

fn capture(out: &TransportOut<'_>, into: &mut Vec<Act>) {
    match *out {
        TransportOut::SendTo {
            path,
            secured,
            bytes,
        } => into.push(Act::Send {
            path,
            secured,
            bytes: Vec::from(bytes),
        }),
        TransportOut::Close { .. } => into.push(Act::Close),
        TransportOut::WakeAt(ns) => into.push(Act::Wake(ns)),
        TransportOut::StreamHead { head, .. } => {
            if let Some(line) = line_of(head) {
                into.push(Act::Line(line));
            }
        }
        TransportOut::Secure {
            path,
            role,
            alg,
            peer_fingerprint,
        } => into.push(Act::Secure {
            path,
            role,
            alg,
            digest: Vec::from(peer_fingerprint),
        }),
        TransportOut::Rendezvous(text) => into.push(Act::Rendezvous(Box::from(text))),
        TransportOut::IceTerms {
            controlling,
            local_ufrag,
            local_pwd,
            remote_ufrag,
            remote_pwd,
        } => into.push(Act::Terms {
            controlling,
            local: creds(local_ufrag, local_pwd),
            remote: creds(remote_ufrag, remote_pwd),
        }),
        TransportOut::IceCandidate(text) => into.push(Act::Candidate(Box::from(text))),
        TransportOut::PathBind { path, from } => into.push(Act::Bind { path, from }),
        _ => {}
    }
}

/// What an ICE_CANDIDATE line names.
enum Candidate {
    /// A UDP candidate at this address.
    Udp(SocketAddr),
    /// Not UDP (a TCP candidate): never used, never refused.
    Skip,
    /// A candidate whose address is not an IP literal or does not parse: it cannot be judged.
    Unjudgeable,
}

/// One RFC 8839 `candidate:` attribute value: `foundation component transport priority address port typ ...`.
fn parse_candidate(line: &str) -> Candidate {
    let line = line.trim();
    let line = line.strip_prefix("candidate:").unwrap_or(line);
    let mut fields = line.split_whitespace();
    let (_, _, transport, _, address, port) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    );
    let (Some(transport), Some(address), Some(port)) = (transport, address, port) else {
        return Candidate::Unjudgeable;
    };
    if !transport.eq_ignore_ascii_case("udp") {
        return Candidate::Skip;
    }
    match (address.parse::<IpAddr>(), port.parse::<u16>()) {
        (Ok(ip), Ok(port)) => Candidate::Udp(SocketAddr::new(ip, port)),
        _ => Candidate::Unjudgeable,
    }
}

impl Session {
    /// Begin the transport's session and take its first answer. The answer must carry ICE_TERMS.
    pub(crate) fn begin(
        opener: &dyn Opener,
        cert: Arc<SessionCert>,
        audit: Arc<dyn MediaAudit>,
        params: Params,
        now: Instant,
    ) -> Result<Session, RecordsDenied> {
        let fingerprint = sdp_fingerprint(cert.fingerprint());
        let local = crate::StackText::<{ crate::SOCKET_TEXT }>::of(&params.local);
        let conn = ConnIn {
            role: wire::ROLE_DATAGRAM,
            flags: if params.dial {
                wire::CONN_DIAL
            } else {
                wire::CONN_ACCEPT
            },
            alpn: "",
            sni: "",
            peer: "",
            local: local.as_str(),
            tls_peer_cert: &[],
            leftover: &[],
            head: &params.opening,
            local_fingerprint: &fingerprint,
            mono_ns: crate::framer::now_ns(),
        };
        let mut acts = Vec::new();
        let handle = opener
            .begin(&conn, &mut |out| capture(&out, &mut acts))
            .map_err(|e| refused(&e))?;
        let mut session = Session {
            handle: Some(handle),
            cert,
            assoc: None,
            dialling: params.dial,
            judge: params.judge,
            audit,
            paths: Paths::default(),
            events: VecDeque::new(),
            out: VecDeque::new(),
            wake: None,
            lines: Lines::default(),
            rendezvous: None,
            ufrag: None,
            ufrag_moved: None,
            new_addrs: Vec::new(),
            bound_told: None,
            failure_told: false,
            closed: false,
            ended: false,
            dropped: 0,
            denied: 0,
        };
        session.apply(acts, now);
        session.settle(now);
        if session.assoc.is_none() || session.closed {
            // ICE_TERMS are required: core cannot route a check to a session without its local ufrag.
            session.close();
            return Err(RecordsDenied::Invalid);
        }
        Ok(session)
    }

    /// The far end's description (`EV_RENDEZVOUS`): an accepted session's offer, a dialled one's answer.
    /// `false` when the transport refused it (the session is closed).
    pub(crate) fn rendezvous(&mut self, description: &str, now: Instant) -> bool {
        let done = self.with(now, |live, sink| {
            live.event(TransportEvent::Rendezvous(description), sink)
        });
        self.settle(now);
        done.is_some()
    }

    /// The transport's RENDEZVOUS text, once, as `accept`/`dial` return it.
    pub(crate) fn take_rendezvous(&mut self) -> Option<Box<str>> {
        self.rendezvous.take()
    }

    /// The lines and channels the transport has named so far.
    pub(crate) fn lines(&self) -> &Lines {
        &self.lines
    }

    /// Whether the session has ended (closed by core, by the transport, or by its far end).
    pub(crate) fn is_closed(&self) -> bool {
        self.closed || self.ended
    }

    /// A ufrag change not yet taken: (the old demux key, the new one). The port re-keys with it and refuses a
    /// key already live there.
    pub(crate) fn take_ufrag_move(&mut self) -> Option<(Option<Box<str>>, Box<str>)> {
        self.ufrag_moved.take()
    }

    /// Addresses numbered since the last call: the port routes non-STUN datagrams from them to this session.
    pub(crate) fn take_new_addrs(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.new_addrs)
    }

    /// The datagram core owes the wire next (DTLS, probes, the transport's clear SEND_TO).
    pub(crate) fn take_out(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.out.pop_front()
    }

    /// (SEND_TOs dropped: unverified path, unbound secured path, unknown or denied path; candidates the judge
    /// refused).
    pub(crate) fn counts(&self) -> (u64, u64) {
        (self.dropped, self.denied)
    }

    /// The path id of `addr`, if numbered.
    #[cfg(test)]
    pub(crate) fn path_of(&self, addr: SocketAddr) -> Option<u32> {
        self.paths.id(addr)
    }

    /// Close the session: the transport's session is dropped, nothing more is sent.
    pub(crate) fn close(&mut self) {
        self.handle = None;
        self.closed = true;
        self.assoc = None;
        self.out.clear();
        self.events.clear();
    }

    /// The next instant [`Self::on_timer`] is owed.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        let wake = self.wake.map(crate::framer::instant_of);
        let assoc = self.assoc.as_ref().and_then(Association::next_timeout);
        [wake, assoc].into_iter().flatten().min()
    }

    /// One datagram from `from`: the association demuxes it (STUN, DTLS, media); what it keeps for the clear
    /// lane goes to the transport on a numbered path, and a verified source is numbered and told first.
    pub(crate) fn on_datagram(&mut self, from: SocketAddr, bytes: &[u8], now: Instant) {
        if self.closed {
            return;
        }
        let Some(assoc) = self.assoc.as_mut() else {
            return;
        };
        let verdict = assoc.ingest(from, bytes, now);
        self.announce(from);
        if verdict == Verdict::Raw {
            if let Some(path) = self.paths.id(from) {
                if self.paths.slot(path).is_some_and(|s| !s.denied) {
                    self.with(now, |live, sink| live.datagram(path, false, bytes, sink));
                }
            }
        }
        self.settle(now);
    }

    /// The deadline passed: DTLS retransmission, probe retries and consent, then the transport's own timer.
    pub(crate) fn on_timer(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        if let Some(assoc) = self.assoc.as_mut() {
            assoc.handle_timeout(now);
        }
        if self
            .wake
            .is_some_and(|ns| crate::framer::instant_of(ns) <= now)
        {
            self.wake = None;
            self.with(now, |live, sink| live.timer(sink));
        }
        self.settle(now);
    }

    /// Call the transport once and apply its answer. `None` when the session is closed or the call failed
    /// (a failed call ends the session).
    fn with<R>(
        &mut self,
        now: Instant,
        call: impl FnOnce(&mut dyn Live, &mut dyn FnMut(TransportOut<'_>)) -> Result<R, PortError>,
    ) -> Option<R> {
        let mut handle = self.handle.take()?;
        let mut acts = Vec::new();
        let result = call(&mut *handle, &mut |out| {
            capture(&out, &mut acts);
        });
        self.handle = Some(handle);
        match result {
            Ok(value) => {
                self.apply(acts, now);
                Some(value)
            }
            Err(_) => {
                self.close();
                None
            }
        }
    }

    fn apply(&mut self, acts: Vec<Act>, now: Instant) {
        for act in acts {
            match act {
                Act::Send {
                    path,
                    secured,
                    bytes,
                } => self.send_to(path, secured, bytes),
                Act::Close => self.close(),
                Act::Wake(ns) => self.wake = Some(ns),
                Act::Line(Line::Media(kind)) => {
                    if self.lines.media.len() < MAX_LINES {
                        self.lines.media.push(kind);
                    }
                }
                Act::Line(Line::Channel(label)) => {
                    if self.lines.channels.len() < MAX_LINES {
                        self.lines.channels.push(label);
                    }
                }
                Act::Rendezvous(text) => self.rendezvous = Some(text),
                Act::Terms {
                    controlling,
                    local,
                    remote,
                } => self.terms(controlling, &local, &remote),
                Act::Secure {
                    path,
                    role,
                    alg,
                    digest,
                } => self.secure(path, role, alg, &digest, now),
                Act::Candidate(text) => self.candidate(&text, now),
                Act::Bind { path, from } => self.bind(path, from, now),
            }
        }
    }

    /// ICE_TERMS: the association's credentials, and the demux key when the local ufrag is new.
    fn terms(&mut self, controlling: bool, local: &IceCredentials, remote: &IceCredentials) {
        if local.ufrag.is_empty() || local.pwd.is_empty() {
            // A session no check can be verified for is a faulted one.
            self.close();
            return;
        }
        let assoc = self
            .assoc
            .get_or_insert_with(|| Association::pending(Arc::clone(&self.cert), local));
        assoc.set_credentials(local, remote);
        if self.dialling {
            assoc.set_dialling();
        }
        assoc.set_controlling(controlling || self.dialling);
        if self.ufrag.as_deref() != Some(local.ufrag.as_str()) {
            let new: Box<str> = Box::from(local.ufrag.as_str());
            let old = self.ufrag.replace(Box::clone(&new));
            self.ufrag_moved = Some((old, new));
        }
    }

    /// SECURE: the far end's DTLS role and certificate digest. A path to run it on that is not known, a role or
    /// algorithm this host does not check, or a different answer after the handshake began, is `PATH_REJECTED`.
    fn secure(&mut self, path: u32, role: u32, alg: u32, digest: &[u8], now: Instant) {
        let role = match role {
            wire::DTLS_CLIENT => Role::Client,
            wire::DTLS_SERVER => Role::Server,
            _ => return self.reject(path),
        };
        let addr = self.paths.slot(path).filter(|s| !s.denied).map(|s| s.addr);
        let (Some(addr), Some(assoc)) = (addr, self.assoc.as_mut()) else {
            return self.reject(path);
        };
        let mut ok = assoc.set_peer(role, alg, digest, now);
        if ok && assoc.bound_path().is_none() {
            ok = assoc.bind_path(addr, now).is_ok();
        }
        if !ok {
            self.reject(path);
        }
    }

    /// ICE_CANDIDATE: judged before a path id exists for it or a check goes to it.
    fn candidate(&mut self, text: &str, now: Instant) {
        let addr = match parse_candidate(text) {
            Candidate::Skip => return,
            Candidate::Udp(addr) => addr,
            Candidate::Unjudgeable => return self.deny(SocketAddr::from(([0, 0, 0, 0], 0))),
        };
        if !self.judged(addr) {
            return self.deny(addr);
        }
        let Some((path, new)) = self.paths.number(addr) else {
            return;
        };
        if new {
            self.new_addrs.push(addr);
            let text = crate::StackText::<{ crate::SOCKET_TEXT }>::of(&addr);
            self.events.push_back(Ev::Path {
                path,
                flags: wire::PATH_NEW,
                addr: Box::from(text.as_str()),
            });
        }
        if self.dialling {
            if let Some(assoc) = self.assoc.as_mut() {
                if !assoc.admit_candidate(addr, now) {
                    self.dropped += 1;
                }
            }
        }
    }

    /// The destination judge's one admission test: the candidate resolves to exactly itself under the
    /// session's egress class. With no judge nothing is admitted.
    fn judged(&self, addr: SocketAddr) -> bool {
        let Some((judge, class)) = self.judge.as_ref() else {
            return false;
        };
        matches!(
            judge.judge_target_all(
                busbar_kernel::host_services::Destination {
                    authority: crate::StackText::<{ crate::SOCKET_TEXT }>::of(&addr).as_str(),
                    // The host owns DTLS for this association, whatever the plugin claims.
                    secure: true,
                    egress_class: *class,
                },
                false,
                Box::new(|_, _| {}),
            ),
            Some(Ok(pinned)) if pinned == addr
        )
    }

    /// A refused candidate: a path id to say so with, `PATH_DENIED`, the audit record. Nothing is sent to it.
    fn deny(&mut self, addr: SocketAddr) {
        self.denied += 1;
        self.audit
            .record("ice_candidate_denied", "a candidate was refused by egress");
        let Some((path, _)) = self.paths.number(addr) else {
            return;
        };
        if let Some(slot) = self.paths.by_id.get_mut(&path) {
            slot.denied = true;
        }
        let text = crate::StackText::<{ crate::SOCKET_TEXT }>::of(&addr);
        self.events.push_back(Ev::Path {
            path,
            flags: wire::PATH_DENIED,
            addr: Box::from(text.as_str()),
        });
    }

    /// PATH_BIND (`from` = none) / PATH_REBIND: the association binds a verified, admitted path or refuses it.
    /// `PATH_BOUND` is told by [`Self::drain`] when the association's bound path becomes this one (at once, or
    /// when core's probe of it is answered).
    fn bind(&mut self, path: u32, from: Option<u32>, now: Instant) {
        let addr = |paths: &Paths, id: u32| paths.slot(id).filter(|s| !s.denied).map(|s| s.addr);
        let to = addr(&self.paths, path);
        let old = from.map(|id| addr(&self.paths, id));
        let (Some(to), Some(assoc)) = (to, self.assoc.as_mut()) else {
            return self.reject(path);
        };
        let accepted = match old {
            None => assoc.bind_path(to, now).is_ok(),
            Some(Some(old)) => assoc.rebind_path(old, to, now).is_ok(),
            Some(None) => false,
        };
        if !accepted {
            self.reject(path);
        }
    }

    fn reject(&mut self, path: u32) {
        let addr = self
            .paths
            .slot(path)
            .map(|s| crate::StackText::<{ crate::SOCKET_TEXT }>::of(&s.addr));
        self.events.push_back(Ev::Path {
            path,
            flags: wire::PATH_REJECTED,
            addr: Box::from(addr.as_ref().map_or("", crate::StackText::as_str)),
        });
    }

    /// SEND_TO: a clear datagram goes where the association allows it (a check to an admitted candidate, an
    /// answer to a heard path, anything to the bound path); a secured one is sealed only toward the bound path.
    /// Anything else is dropped and counted.
    fn send_to(&mut self, path: u32, secured: bool, bytes: Vec<u8>) {
        let addr = self.paths.slot(path).filter(|s| !s.denied).map(|s| s.addr);
        let (Some(addr), Some(assoc)) = (addr, self.assoc.as_mut()) else {
            self.dropped += 1;
            return;
        };
        let sent = if secured {
            assoc.bound_path() == Some(addr) && assoc.seal(&bytes).is_ok()
        } else if assoc.may_send_clear(addr, &bytes) {
            self.out.push_back((addr, bytes));
            true
        } else {
            false
        };
        if !sent {
            self.dropped += 1;
        }
    }

    /// A datagram arrived from `addr`: when the association now holds it verified (a checked connectivity
    /// check, or core's own probe answered) and it was not told so yet, it is numbered and `EV_PATH` says so.
    fn announce(&mut self, addr: SocketAddr) {
        let Some(assoc) = self.assoc.as_ref() else {
            return;
        };
        if !(assoc.heard.contains_key(&addr) || assoc.proven.contains_key(&addr)) {
            return;
        }
        let Some((path, new)) = self.paths.number(addr) else {
            return;
        };
        if new {
            self.new_addrs.push(addr);
        }
        let Some(slot) = self.paths.by_id.get_mut(&path) else {
            return;
        };
        if slot.denied || slot.told_verified {
            return;
        }
        slot.told_verified = true;
        let text = crate::StackText::<{ crate::SOCKET_TEXT }>::of(&addr);
        self.events.push_back(Ev::Path {
            path,
            flags: wire::PATH_VERIFIED | if new { wire::PATH_NEW } else { 0 },
            addr: Box::from(text.as_str()),
        });
    }

    /// Run the queue dry: the association's wire output, what it hands up (keying, DTLS data), its bound
    /// path and its failure, then each event to the transport (whose answers may queue more).
    fn settle(&mut self, now: Instant) {
        loop {
            self.drain();
            let Some(event) = self.events.pop_front() else {
                break;
            };
            match event {
                Ev::Path { path, flags, addr } => {
                    self.with(now, |live, sink| {
                        live.event(
                            TransportEvent::Path {
                                path,
                                flags,
                                addr: &addr,
                            },
                            sink,
                        )
                    });
                }
                Ev::Keying { path, keying } => {
                    self.with(now, |live, sink| {
                        live.event(
                            TransportEvent::Keying {
                                path,
                                profile: keying.profile.code(),
                                material: keying.material(),
                            },
                            sink,
                        )
                    });
                }
                Ev::Datagram {
                    path,
                    secured,
                    bytes,
                } => {
                    self.with(now, |live, sink| live.datagram(path, secured, &bytes, sink));
                }
            }
            if self.closed {
                break;
            }
        }
    }

    fn drain(&mut self) {
        let Some(assoc) = self.assoc.as_mut() else {
            return;
        };
        while let Some(wire_out) = assoc.poll_wire() {
            self.out.push_back(wire_out);
        }
        let mut ups = Vec::new();
        while let Some(up) = assoc.poll_up() {
            ups.push(up);
        }
        let bound = assoc.bound_path();
        let failed_on = assoc.bound.or(assoc.wanted);
        let failure = assoc.failure().cloned();
        if let Some(id) = bound.and_then(|b| self.paths.id(b)) {
            if self.bound_told != Some(id) {
                self.bound_told = Some(id);
                let text = crate::StackText::<{ crate::SOCKET_TEXT }>::of(
                    &self
                        .paths
                        .slot(id)
                        .map_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)), |s| s.addr),
                );
                self.events.push_back(Ev::Path {
                    path: id,
                    flags: wire::PATH_BOUND,
                    addr: Box::from(text.as_str()),
                });
            }
        }
        let bound_id = bound.and_then(|b| self.paths.id(b));
        for up in ups {
            match up {
                Up::Keyed(keying) => {
                    if let Some(path) = bound_id {
                        self.events.push_back(Ev::Keying { path, keying });
                    }
                }
                Up::Plaintext(bytes) => {
                    if let Some(path) = bound_id {
                        self.events.push_back(Ev::Datagram {
                            path,
                            secured: true,
                            bytes,
                        });
                    }
                }
                Up::Connected => {}
                Up::Closed => self.ended = true,
            }
        }
        if let Some(failure) = failure {
            if !self.failure_told {
                self.failure_told = true;
                let mismatch = failure == Failure::Fingerprint;
                if mismatch {
                    self.audit.record(
                        "dtls_fingerprint_mismatch",
                        "the far end's certificate does not match the digest its description gave",
                    );
                }
                if let Some(id) = failed_on.and_then(|a| self.paths.id(a)) {
                    let flags = if mismatch {
                        wire::PATH_REJECTED
                    } else {
                        wire::PATH_GONE
                    };
                    let text = crate::StackText::<{ crate::SOCKET_TEXT }>::of(
                        &failed_on.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
                    );
                    self.events.push_back(Ev::Path {
                        path: id,
                        flags,
                        addr: Box::from(text.as_str()),
                    });
                }
            }
        }
    }
}

/// A transport that refused or failed `begin`.
fn refused(error: &PortError) -> RecordsDenied {
    match error {
        PortError::Failed { .. } | PortError::Call(_) => RecordsDenied::Unavailable,
        PortError::Refused { .. } => RecordsDenied::Invalid,
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
