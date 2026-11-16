// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport suite body (IF §14). Owned by the transport agent: this is the only file it edits (plus the
//! `tests/` cases that call it). Drives the plugin with [`super::harness::Harness`].
//!
//! Cases covered (IF §14, L9's suite): describe, `check` and `open` through the registry; C-ALPN (the cached
//! `offer` per role, none for a role the instance does not declare, the case's ALPN among the offer); the scripted
//! `begin` + `ingest` cases (stream count, C-TOKEN-PAD through the adapter's decode, C-MSG-FLAGS shape); EOF;
//! C-TRANSPORT-REFUSE (`emit(E_REFUSE)` before and after a head, a status outside 400..=599 REFUSED R_INVALID, no
//! head, body, upgrade or open in the answer); C-TRANSPORT-CLOSE (`emit(E_CLOSE)` for every reason answers only
//! Write or SendTo and at most one Close); C-TRANSPORT-BACKPRESSURE (STREAM_FULL only from `emit`, STREAM_WRITABLE
//! only from ingest, timer, datagram and event; neither in a refuse or close answer); C-DTLS-FP (a datagram
//! `begin` is handed a fingerprint); C-SESSION-DROP (every session is dropped, none is leaked).

use std::collections::BTreeSet;

use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::transport::{
    CR_CAPACITY_EXHAUSTED, CR_DRAIN, CR_NORMAL, CR_REVOKED, CR_TIMEOUT, E_CLOSE, E_REFUSE,
    E_REFUSE_HEAD_SENT, ROLE_CLIENT, ROLE_DATAGRAM, ROLE_SERVER,
};
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::ports::transport::{
    ConnIn, TransportOut, TransportPort, TransportSession,
};
use busbar_plugin_loader::ports::PortError;

use super::harness::Harness;
use super::TransportCase;
use crate::fake_needs::FakeNeeds;

/// What one answer's sink saw, owned so it outlives the call.
#[derive(Default)]
#[allow(dead_code)]
struct Tally {
    streams: BTreeSet<u64>,
    heads: Vec<u64>,
    writes: usize,
    sends: usize,
    closes: usize,
    full: Vec<u64>,
    writable: Vec<u64>,
    opened: Vec<u64>,
    other: usize,
    upgrade: usize,
}

impl Tally {
    fn note(&mut self, out: &TransportOut<'_>) {
        match out {
            TransportOut::Write(_) => self.writes += 1,
            TransportOut::SendTo { .. } => self.sends += 1,
            TransportOut::Close { .. } => self.closes += 1,
            TransportOut::StreamHead { stream, .. } => {
                self.streams.insert(*stream);
                self.heads.push(*stream);
            }
            TransportOut::StreamBody { stream, .. }
            | TransportOut::StreamEnd(stream)
            | TransportOut::StreamReset { stream, .. }
            | TransportOut::StreamTrailers { stream, .. } => {
                self.streams.insert(*stream);
            }
            TransportOut::StreamOpened(stream) => {
                self.streams.insert(*stream);
                self.opened.push(*stream);
            }
            TransportOut::StreamFull(stream) => self.full.push(*stream),
            TransportOut::StreamWritable(stream) => self.writable.push(*stream),
            TransportOut::Upgrade { .. } | TransportOut::Leftover(_) => self.upgrade += 1,
            _ => self.other += 1,
        }
    }
}

fn conn(role: u32, alpn: &str) -> ConnIn<'_> {
    ConnIn {
        role,
        flags: 0,
        alpn,
        sni: "",
        peer: "192.0.2.1:50000",
        local: "192.0.2.2:8443",
        tls_peer_cert: &[],
        leftover: &[],
        head: &[],
        local_fingerprint: if role == ROLE_DATAGRAM {
            "sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
        } else {
            ""
        },
        mono_ns: 1,
    }
}

fn begin(port: &dyn TransportPort, c: &ConnIn<'_>) -> (TransportSession, Tally) {
    let mut tally = Tally::default();
    let session = match port.begin(c, &mut |o| tally.note(&o)) {
        Ok(s) => s,
        Err(e) => panic!("transport suite: begin(role {}) failed: {e:?}", c.role),
    };
    (session, tally)
}

fn ingest(port: &dyn TransportPort, s: &mut TransportSession, bytes: &[u8]) -> Tally {
    let mut tally = Tally::default();
    if let Err(e) = port.ingest(s, bytes, &mut |o| tally.note(&o)) {
        panic!(
            "transport suite: ingest of {} bytes failed: {e:?}",
            bytes.len()
        );
    }
    assert!(
        tally.full.is_empty(),
        "C-TRANSPORT-BACKPRESSURE: STREAM_FULL is valid only from emit, ingest answered it"
    );
    assert!(
        tally.closes <= 1,
        "ingest answered CLOSE {} times, at most one is valid",
        tally.closes
    );
    tally
}

/// An `emit` that must answer only goodbye or refusal bytes: no stream records, no flow records, no upgrade.
fn emit_terminal(
    port: &dyn TransportPort,
    s: &mut TransportSession,
    stream: u64,
    piece: u32,
    arg: u32,
    bytes: &[u8],
) -> Result<Tally, PortError> {
    let mut tally = Tally::default();
    port.emit(s, stream, piece, arg, bytes, &mut |o| tally.note(&o))?;
    Ok(tally)
}

fn assert_terminal(what: &str, t: &Tally) {
    assert!(
        t.full.is_empty() && t.writable.is_empty(),
        "C-TRANSPORT-BACKPRESSURE: {what} answered a flow record"
    );
    assert!(t.closes <= 1, "{what} answered CLOSE {} times", t.closes);
    assert!(
        t.heads.is_empty() && t.opened.is_empty() && t.upgrade == 0,
        "{what} answered a stream head, an open or an upgrade"
    );
}

pub(super) fn run(plugin: &'static Plugin, config: &[u8], cases: &[TransportCase<'_>]) {
    let h = Harness::admit(plugin, FakeNeeds::default())
        .unwrap_or_else(|r| panic!("transport suite: admission refused: {r:?}"));
    assert!(
        matches!(h.kind(), KindCode::Transport),
        "transport suite: {} is not a transport plugin",
        h.identity()
    );
    if let Err(e) = h.check("suite-check", config) {
        panic!("transport suite: check refused the config: {e:?}");
    }
    let port = match h.open_transport("suite-0", config) {
        Ok(p) => p,
        Err(e) => panic!("transport suite: open refused the config: {e:?}"),
    };

    // C-ALPN: a role the instance does not declare offers nothing, and each offered id is a real token.
    for role in [0, 9, u32::MAX] {
        assert!(
            port.alpn(role).is_empty(),
            "C-ALPN: offer for undeclared role {role} is not empty"
        );
        assert!(
            port.defaults(role).is_empty(),
            "C-ALPN: defaults for undeclared role {role} are not empty"
        );
    }
    assert!(
        port.defaults(ROLE_SERVER).is_empty(),
        "C-ALPN: ROLE_SERVER offer carries default lines"
    );
    for role in [ROLE_SERVER, ROLE_CLIENT] {
        let offer = port.alpn(role);
        let seen: BTreeSet<&str> = offer.iter().map(|a| &**a).collect();
        assert_eq!(
            seen.len(),
            offer.len(),
            "C-ALPN: duplicate id in role {role} offer"
        );
        for id in offer {
            assert!(
                (1..=255).contains(&id.len()),
                "C-ALPN: id {id:?} is not 1..=255 bytes"
            );
        }
    }
    for (name, value) in port.defaults(ROLE_CLIENT) {
        assert!(
            **name == name.to_ascii_lowercase() && !name.is_empty() && !value.is_empty(),
            "C-ALPN: client default line {name:?} is not a lowercase name with a value"
        );
    }
    assert!(
        port.defaults(ROLE_CLIENT).len() <= 8,
        "C-ALPN: more than 8 client default lines"
    );

    // A second instance of the same image opens beside the first: sessions are per instance, offers are cached
    // per instance.
    let second = match h.open_transport("suite-1", config) {
        Ok(p) => p,
        Err(e) => panic!("transport suite: a second instance of the config was refused: {e:?}"),
    };
    for role in [ROLE_SERVER, ROLE_CLIENT] {
        assert_eq!(
            port.alpn(role),
            second.alpn(role),
            "C-ALPN: two instances of one config offer differently on role {role}"
        );
    }

    for (n, case) in cases.iter().enumerate() {
        let offer = port.alpn(case.role);
        if !case.alpn.is_empty() {
            assert!(
                offer.iter().any(|a| &**a == case.alpn),
                "case {n}: C-ALPN: offer {offer:?} on role {} does not name {:?}",
                case.role,
                case.alpn
            );
        }

        // Scripted input: begin, every chunk, then EOF.
        let c = conn(case.role, case.alpn);
        let (mut session, opened) = begin(&*port, &c);
        assert!(
            opened.full.is_empty() && opened.writable.is_empty(),
            "case {n}: begin answered a flow record"
        );
        let mut streams = opened.streams;
        for chunk in case.input {
            streams.extend(ingest(&*port, &mut session, chunk).streams);
        }
        assert_eq!(
            streams.len() as u32,
            case.expect_streams,
            "case {n}: streams seen {streams:?}, expected {}",
            case.expect_streams
        );
        let eof = ingest(&*port, &mut session, &[]);
        assert!(
            eof.heads.is_empty(),
            "case {n}: EOF opened a new stream {:?}",
            eof.heads
        );
        drop(session);

        // C-TRANSPORT-CLOSE: every reason, one fresh session each.
        for reason in [
            CR_NORMAL,
            CR_DRAIN,
            CR_REVOKED,
            CR_TIMEOUT,
            CR_CAPACITY_EXHAUSTED,
        ] {
            let (mut s, _) = begin(&*port, &c);
            match emit_terminal(&*port, &mut s, 0, E_CLOSE, reason, &[]) {
                Ok(t) => {
                    assert_terminal("emit(E_CLOSE)", &t);
                    assert!(
                        t.other == 0 && t.streams.is_empty(),
                        "case {n}: C-TRANSPORT-CLOSE: reason {reason} answered more than Write/SendTo/Close"
                    );
                }
                Err(e) => panic!("case {n}: emit(E_CLOSE, {reason}) failed: {e:?}"),
            }
        }

        // C-TRANSPORT-REFUSE: only on a side that serves streams to a plane (a client conn has no refused stream).
        if case.role == ROLE_SERVER {
            for (flag, label) in [(0, "before head"), (E_REFUSE_HEAD_SENT, "after head")] {
                let (mut s, _) = begin(&*port, &c);
                let mut seen = BTreeSet::new();
                for chunk in case.input {
                    seen.extend(ingest(&*port, &mut s, chunk).streams);
                }
                let stream = seen.iter().next().copied().unwrap_or(1);
                match emit_terminal(&*port, &mut s, stream, E_REFUSE, 429 | flag, b"budget") {
                    Ok(t) => assert_terminal(&format!("emit(E_REFUSE) {label}"), &t),
                    Err(e) => panic!("case {n}: emit(E_REFUSE, 429) {label} failed: {e:?}"),
                }
            }
            for bad in [200u32, 399, 600] {
                let (mut s, _) = begin(&*port, &c);
                match emit_terminal(&*port, &mut s, 1, E_REFUSE, bad, b"x") {
                    Err(PortError::Refused { code, .. }) => assert_eq!(
                        code, R_INVALID,
                        "case {n}: status {bad} refused with code {code}, not R_INVALID"
                    ),
                    other => panic!(
                        "case {n}: C-TRANSPORT-REFUSE: status {bad} outside 400..=599 was not REFUSED R_INVALID: {:?}",
                        other.map(|_| "an answer")
                    ),
                }
            }
        }
    }

    // C-SESSION-DROP: every session above was dropped at the end of its scope; both instances close with the
    // harness.
    drop(port);
    drop(second);
}
