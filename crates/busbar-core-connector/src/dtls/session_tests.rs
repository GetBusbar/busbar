// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The media session over a scripted transport: what core decides on ICE and DTLS, with no socket and no
//! plugin image (C-DTLS-FP, C-ICE's per-session arms).

use super::*;
use crate::dtls::tests::{answer, check, creds, is_probe, p};
use busbar_plugin_abi::records::{Reply, Writer};
use std::sync::Mutex;
use std::time::Duration;

const LOCAL: (&str, &str) = ("lfrag", "local-password-0123456789");
const REMOTE: (&str, &str) = ("rfrag", "remote-password-0123456789");
const KIND: u32 = 0;

/// What a scripted transport answers.
#[derive(Clone)]
enum Out {
    Terms,
    Offer(&'static str),
    Cand(&'static str),
    /// PATH_BIND on the path the call is about.
    BindThis,
    /// PATH_BIND of `path`, moving it from `from`.
    Rebind {
        path: u32,
        from: u32,
    },
    /// SECURE on the path the call is about: the far end's role and digest.
    SecureThis {
        role: u32,
        digest: Vec<u8>,
    },
    SendTo {
        path: u32,
        secured: bool,
    },
    Head(&'static str, &'static str),
}

/// What the scripted transport saw, in order.
#[derive(Debug, PartialEq)]
enum Seen {
    Path { path: u32, flags: u32 },
    Keying { path: u32 },
    Datagram { path: u32, secured: bool },
}

#[derive(Default)]
struct Script {
    on_begin: Vec<Out>,
    on_offer: Vec<Out>,
    on_verified: Vec<Out>,
    on_datagram: Vec<Out>,
    seen: Vec<Seen>,
    began: Option<(u32, u32, String, Vec<u8>)>,
}

type Shared = Arc<Mutex<Script>>;

fn emit(out: &Out, path: u32, sink: &mut dyn FnMut(TransportOut<'_>)) {
    match out {
        Out::Terms => sink(TransportOut::IceTerms {
            controlling: false,
            local_ufrag: LOCAL.0,
            local_pwd: LOCAL.1.as_bytes(),
            remote_ufrag: REMOTE.0,
            remote_pwd: REMOTE.1.as_bytes(),
        }),
        Out::Offer(text) => sink(TransportOut::Rendezvous(text)),
        Out::Cand(text) => sink(TransportOut::IceCandidate(text)),
        Out::BindThis => sink(TransportOut::PathBind { path, from: None }),
        Out::Rebind { path, from } => sink(TransportOut::PathBind {
            path: *path,
            from: Some(*from),
        }),
        Out::SecureThis { role, digest } => sink(TransportOut::Secure {
            path,
            role: *role,
            alg: wire::FP_SHA256,
            peer_fingerprint: digest,
        }),
        Out::SendTo { path, secured } => sink(TransportOut::SendTo {
            path: *path,
            secured: *secured,
            bytes: b"to the far end",
        }),
        Out::Head(name, value) => {
            let mut head = Reply::new();
            head.put_pair(tag::PAIR, name, value.as_bytes()).unwrap();
            sink(TransportOut::StreamHead {
                stream: 1,
                end_stream: false,
                head: Records::new(head.as_bytes()),
            });
        }
    }
}

struct Fake(Shared);
struct FakeLive(Shared);

impl Opener for Fake {
    fn begin(
        &self,
        conn: &ConnIn<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<Box<dyn Live>, PortError> {
        let mut script = self.0.lock().unwrap();
        script.began = Some((
            conn.role,
            conn.flags,
            String::from(conn.local_fingerprint),
            Vec::from(conn.head),
        ));
        for out in &script.on_begin {
            emit(out, 0, sink);
        }
        Ok(Box::new(FakeLive(Arc::clone(&self.0))))
    }
}

impl Live for FakeLive {
    fn event(
        &mut self,
        ev: TransportEvent<'_>,
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        let mut script = self.0.lock().unwrap();
        match ev {
            TransportEvent::Rendezvous(_) => {
                for out in &script.on_offer {
                    emit(out, 0, sink);
                }
            }
            TransportEvent::Path { path, flags, .. } => {
                script.seen.push(Seen::Path { path, flags });
                if flags & wire::PATH_VERIFIED != 0 {
                    for out in &script.on_verified {
                        emit(out, path, sink);
                    }
                }
            }
            TransportEvent::Keying { path, .. } => script.seen.push(Seen::Keying { path }),
        }
        Ok(())
    }

    fn datagram(
        &mut self,
        path: u32,
        secured: bool,
        _bytes: &[u8],
        sink: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        let mut script = self.0.lock().unwrap();
        script.seen.push(Seen::Datagram { path, secured });
        let outs = std::mem::take(&mut script.on_datagram);
        for out in &outs {
            emit(out, path, sink);
        }
        Ok(())
    }

    fn timer(&mut self, _sink: &mut dyn FnMut(TransportOut<'_>)) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default)]
struct Audited(Mutex<Vec<&'static str>>);

impl MediaAudit for Audited {
    fn record(&self, event: &'static str, _detail: &str) {
        self.0.lock().unwrap().push(event);
    }
}

fn permissive() -> Option<(Arc<dyn DialJudge>, u32)> {
    let judge =
        |dest: &str, _class: u32, _done: crate::Judged| -> Option<Result<SocketAddr, u64>> {
            let addr: SocketAddr = dest.parse().ok()?;
            if addr.ip() == IpAddr::from([169, 254, 169, 254]) {
                return Some(Err(busbar_contract::abi::host::service::DEST_METADATA));
            }
            Some(Ok(addr))
        };
    let judge: Arc<dyn DialJudge> = Arc::new(judge);
    Some((judge, KIND))
}

struct Rig {
    session: Session,
    script: Shared,
    audit: Arc<Audited>,
    cert: Arc<SessionCert>,
    peer: Association,
    peer_addr: SocketAddr,
    our_addr: SocketAddr,
    now: Instant,
}

/// An accepted session whose far end (`peer`, a real association with its own certificate) sits at
/// `203.0.113.9:50000`. `digest` is the certificate digest the transport states in SECURE.
fn accepted(script: Script, tamper: bool) -> Rig {
    let cert = Arc::new(SessionCert::mint().unwrap());
    let peer_cert = Arc::new(SessionCert::mint().unwrap());
    let mut digest = Vec::from(peer_cert.fingerprint());
    if tamper {
        digest[0] ^= 1;
    }
    let mut script = script;
    script.on_begin.push(Out::Terms);
    script.on_verified.push(Out::SecureThis {
        role: wire::DTLS_SERVER,
        digest,
    });
    script.on_verified.push(Out::BindThis);
    let script: Shared = Arc::new(Mutex::new(script));
    let audit = Arc::new(Audited::default());
    let now_ns = crate::framer::now_ns();
    let now = crate::framer::instant_of(now_ns);
    let our_addr = p("198.51.100.1:3478");
    let session = Session::begin(
        &Fake(Arc::clone(&script)),
        Arc::clone(&cert),
        audit.clone(),
        Params {
            dial: false,
            local: our_addr,
            opening: &[],
            judge: permissive(),
        },
        now_ns,
    )
    .unwrap();
    let peer = Association::new(
        peer_cert,
        Role::Client,
        &creds(REMOTE.0, REMOTE.1),
        &creds(LOCAL.0, LOCAL.1),
        cert.fingerprint(),
    );
    Rig {
        session,
        script,
        audit,
        cert,
        peer,
        peer_addr: p("203.0.113.9:50000"),
        our_addr,
        now,
    }
}

impl Rig {
    /// The far end's honest connectivity check, as it reaches the media port.
    fn honest_check(&self) -> Vec<u8> {
        check(&creds(LOCAL.0, LOCAL.1), REMOTE.0, LOCAL.1)
    }

    /// Both ends hear an honest check; the far end binds the path to us.
    fn start(&mut self) {
        let honest = self.honest_check();
        self.session.on_datagram(self.peer_addr, &honest, self.now);
        let to_peer = check(&creds(REMOTE.0, REMOTE.1), LOCAL.0, REMOTE.1);
        self.peer.ingest(self.our_addr, &to_peer, self.now);
        self.peer.bind_path(self.our_addr, self.now).unwrap();
    }

    /// Carry what each side owes the wire to the other, answering probes as a full ICE agent would.
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.now += Duration::from_millis(10);
            self.peer.handle_timeout(self.now);
            self.session.on_timer(self.now);
            while let Some((to, bytes)) = self.session.take_out() {
                assert_eq!(to, self.peer_addr);
                if is_probe(&bytes) {
                    let reply = answer(&bytes, REMOTE.1);
                    self.session.on_datagram(self.peer_addr, &reply, self.now);
                } else {
                    self.peer.ingest(self.our_addr, &bytes, self.now);
                }
            }
            while let Some((_, bytes)) = self.peer.poll_wire() {
                if is_probe(&bytes) {
                    let reply = answer(&bytes, LOCAL.1);
                    self.peer.ingest(self.our_addr, &reply, self.now);
                } else {
                    self.session.on_datagram(self.peer_addr, &bytes, self.now);
                }
            }
            while self.peer.poll_up().is_some() {}
        }
    }

    fn seen(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().unwrap()
    }

    fn told(&self, flags: u32) -> bool {
        self.seen()
            .seen
            .iter()
            .any(|s| matches!(s, Seen::Path { flags: f, .. } if f & flags != 0))
    }

    fn keyed(&self) -> bool {
        self.seen()
            .seen
            .iter()
            .any(|s| matches!(s, Seen::Keying { .. }))
    }
}

#[test]
fn a_datagram_begin_gets_the_host_fingerprint_and_a_dial_gets_its_opening() {
    let rig = accepted(Script::default(), false);
    let (role, flags, fingerprint, head) = rig.seen().began.clone().unwrap();
    assert_eq!(role, wire::ROLE_DATAGRAM);
    assert_eq!(flags, wire::CONN_ACCEPT);
    assert_eq!(
        fingerprint,
        sdp_fingerprint(rig.cert.fingerprint()).as_str()
    );
    assert!(fingerprint.starts_with("sha-256 ") && fingerprint.len() > 8);
    assert!(head.is_empty());

    let script: Shared = Arc::new(Mutex::new(Script {
        on_begin: vec![Out::Terms, Out::Offer("v=0 offer")],
        ..Script::default()
    }));
    let mut dialled = Session::begin(
        &Fake(Arc::clone(&script)),
        Arc::new(SessionCert::mint().unwrap()),
        Arc::new(Audited::default()),
        Params {
            dial: true,
            local: p("198.51.100.1:40000"),
            opening: b"opening",
            judge: permissive(),
        },
        crate::framer::now_ns(),
    )
    .unwrap();
    let (role, flags, _, head) = script.lock().unwrap().began.clone().unwrap();
    assert_eq!((role, flags), (wire::ROLE_DATAGRAM, wire::CONN_DIAL));
    assert_eq!(head, b"opening");
    assert_eq!(dialled.take_rendezvous().as_deref(), Some("v=0 offer"));
}

#[test]
fn a_session_whose_answer_has_no_ice_terms_is_refused() {
    let script: Shared = Arc::new(Mutex::new(Script::default()));
    let refused = Session::begin(
        &Fake(script),
        Arc::new(SessionCert::mint().unwrap()),
        Arc::new(Audited::default()),
        Params {
            dial: false,
            local: p("198.51.100.1:3478"),
            opening: &[],
            judge: None,
        },
        crate::framer::now_ns(),
    );
    assert!(matches!(refused, Err(RecordsDenied::Invalid)));
}

#[test]
fn a_matching_certificate_keys_the_bound_path() {
    let mut rig = accepted(Script::default(), false);
    rig.start();
    rig.pump(60);
    assert!(rig.told(wire::PATH_VERIFIED), "the checked source was told");
    assert!(rig.told(wire::PATH_BOUND), "the bind answered PATH_BOUND");
    assert!(rig.keyed(), "keying was exported once the digest matched");
    assert!(!rig.told(wire::PATH_REJECTED));
    assert!(rig.audit.0.lock().unwrap().is_empty());
}

#[test]
fn a_fingerprint_mismatch_is_path_rejected_with_no_keying() {
    let mut rig = accepted(Script::default(), true);
    rig.start();
    rig.pump(60);
    assert!(rig.told(wire::PATH_REJECTED), "the path was rejected");
    assert!(!rig.keyed(), "no EV_KEYING for a mismatching certificate");
    assert_eq!(
        *rig.audit.0.lock().unwrap(),
        vec!["dtls_fingerprint_mismatch"]
    );
}

#[test]
fn a_check_with_a_bad_message_integrity_never_becomes_a_path() {
    let mut rig = accepted(Script::default(), false);
    let forged = check(&creds(LOCAL.0, LOCAL.1), REMOTE.0, "not-the-local-password");
    rig.session.on_datagram(rig.peer_addr, &forged, rig.now);
    assert!(rig.seen().seen.is_empty(), "nothing was told");
    assert_eq!(rig.session.path_of(rig.peer_addr), None);
    // The honest one still is.
    let honest = rig.honest_check();
    rig.session.on_datagram(rig.peer_addr, &honest, rig.now);
    assert_eq!(rig.session.path_of(rig.peer_addr), Some(1));
}

#[test]
fn a_dial_candidate_at_a_metadata_address_is_denied_and_nothing_is_sent() {
    let script: Shared = Arc::new(Mutex::new(Script {
        on_begin: vec![
            Out::Terms,
            Out::Offer("v=0 offer"),
            Out::Cand("1 1 udp 2130706431 169.254.169.254 3478 typ host"),
            Out::Cand("2 1 udp 2130706430 203.0.113.9 50000 typ host"),
        ],
        ..Script::default()
    }));
    let audit = Arc::new(Audited::default());
    let mut session = Session::begin(
        &Fake(Arc::clone(&script)),
        Arc::new(SessionCert::mint().unwrap()),
        audit.clone(),
        Params {
            dial: true,
            local: p("198.51.100.1:40000"),
            opening: b"opening",
            judge: permissive(),
        },
        crate::framer::now_ns(),
    )
    .unwrap();
    let guard = script.lock().unwrap();
    let seen = &guard.seen;
    assert!(
        seen.iter()
            .any(|s| matches!(s, Seen::Path { path: 1, flags } if flags & wire::PATH_DENIED != 0)),
        "the metadata candidate was denied"
    );
    assert!(
        seen.iter()
            .any(|s| matches!(s, Seen::Path { path: 2, flags } if flags & wire::PATH_NEW != 0)),
        "the other candidate was admitted"
    );
    assert_eq!(session.counts().1, 1);
    assert_eq!(*audit.0.lock().unwrap(), vec!["ice_candidate_denied"]);
    // Every datagram owed goes to the admitted candidate; none to the metadata address.
    let metadata = p("169.254.169.254:3478");
    while let Some((to, _)) = session.take_out() {
        assert_ne!(to, metadata);
    }
}

#[test]
fn a_secured_send_to_an_unbound_path_is_dropped_and_counted() {
    let mut rig = accepted(
        Script {
            on_datagram: vec![Out::SendTo {
                path: 1,
                secured: true,
            }],
            ..Script::default()
        },
        false,
    );
    // The honest check numbers path 1; the transport answers its datagram with a secured SEND_TO.
    let honest = rig.honest_check();
    rig.session.on_datagram(rig.peer_addr, &honest, rig.now);
    assert!(rig.told(wire::PATH_VERIFIED));
    assert_eq!(rig.session.counts().0, 1, "the secured SEND_TO was dropped");
    assert!(
        rig.session
            .take_out()
            .is_none_or(|(_, bytes)| is_probe(&bytes)),
        "only core's own probe may be on the wire"
    );
}

#[test]
fn a_path_rebind_moves_the_binding_and_yields_path_bound() {
    let mut rig = accepted(Script::default(), false);
    rig.start();
    rig.pump(5);
    assert!(rig.told(wire::PATH_BOUND));
    let first_bound = rig
        .seen()
        .seen
        .iter()
        .filter(|s| matches!(s, Seen::Path { flags, .. } if flags & wire::PATH_BOUND != 0))
        .count();
    assert_eq!(first_bound, 1);

    // A second verified source; the transport then moves the binding to it.
    rig.script.lock().unwrap().on_datagram = vec![Out::Rebind { path: 2, from: 1 }];
    let second = p("203.0.113.10:50001");
    let honest = rig.honest_check();
    rig.session.on_datagram(second, &honest, rig.now);
    assert_eq!(rig.session.path_of(second), Some(2));
    // Core probed the new path; its answer completes the rebind.
    let mut probe = None;
    while let Some((to, bytes)) = rig.session.take_out() {
        if to == second && is_probe(&bytes) {
            probe = Some(bytes);
        }
    }
    let probe = probe.expect("core probes the new path before binding it");
    let reply = answer(&probe, REMOTE.1);
    rig.session.on_datagram(second, &reply, rig.now);
    assert!(
        rig.seen()
            .seen
            .iter()
            .any(|s| matches!(s, Seen::Path { path: 2, flags } if flags & wire::PATH_BOUND != 0)),
        "PATH_BOUND on the new path"
    );
}

#[test]
fn stream_heads_become_the_sessions_lines_and_channels() {
    let script: Shared = Arc::new(Mutex::new(Script {
        on_begin: vec![
            Out::Terms,
            Out::Head("kind", "audio"),
            Out::Head("kind", "video"),
            Out::Head("label", "events"),
        ],
        ..Script::default()
    }));
    let session = Session::begin(
        &Fake(script),
        Arc::new(SessionCert::mint().unwrap()),
        Arc::new(Audited::default()),
        Params {
            dial: false,
            local: p("198.51.100.1:3478"),
            opening: &[],
            judge: None,
        },
        crate::framer::now_ns(),
    )
    .unwrap();
    let lines = session.lines();
    assert_eq!(lines.media, [Box::<str>::from("audio"), Box::from("video")]);
    assert_eq!(lines.channels, [Box::<str>::from("events")]);
}
