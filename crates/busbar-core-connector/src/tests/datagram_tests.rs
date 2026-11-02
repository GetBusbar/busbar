// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM DRIVER, end to end over a real handshake: a scripted datagram framer behind the

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    DatagramLane, DatagramRoute, FramePiece, FrameSpan, FramerOut, FramerSink, RendezvousTerms,
    HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES, LANE_CLEAR, LANE_RENDEZVOUS, LANE_SECURED,
    PATH_REQUEST_BIND, PATH_REQUEST_REBIND, PIECE_END_OF_FRAME, ROLE_FRAMER,
};

use super::DatagramFraming;
use crate::dtls::{Association, IceCredentials, Role, SessionCert, SrtpKeying, Up, Verdict};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use crate::{DialJudge, Judged};

const HOST_UFRAG: &str = "hostfrag";
const HOST_PWD: &str = "host-password-0123456789";
const FAR_UFRAG: &str = "farfrag";
const FAR_PWD: &str = "far-password-0123456789";

#[path = "datagram_turn_tests.rs"]
mod turn_tests;

#[path = "datagram_emission_close_tests.rs"]
mod emission_close_tests;

#[path = "datagram_secure_credit_tests.rs"]
mod secure_credit_tests;

fn p(s: &str) -> SocketAddr {
    s.parse().expect("addr")
}

fn creds(ufrag: &str, pwd: &str) -> IceCredentials {
    IceCredentials {
        ufrag: ufrag.into(),
        pwd: pwd.into(),
    }
}

/// A Binding request to the owner of `to`: USERNAME "to.ufrag:from_ufrag", MESSAGE-INTEGRITY under
fn check(to_ufrag: &str, from_ufrag: &str, key: &str, txid: u8) -> Vec<u8> {
    let username = format!("{to_ufrag}:{from_ufrag}").into_bytes();
    let padded = username.len().div_ceil(4) * 4;
    let mut m = vec![0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    m.extend_from_slice(&[txid; 12]);
    m.extend_from_slice(&0x0006_u16.to_be_bytes());
    m.extend_from_slice(&u16::try_from(username.len()).unwrap().to_be_bytes());
    m.extend_from_slice(&username);
    m.resize(20 + 4 + padded, 0);
    let covered_len = u16::try_from(m.len() - 20 + 24).unwrap();
    m[2..4].copy_from_slice(&covered_len.to_be_bytes());
    sign(m, key)
}

/// The success response to the request `req`: same transaction id, MESSAGE-INTEGRITY under `pwd`
fn answer(req: &[u8], pwd: &str) -> Vec<u8> {
    let mut m = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    m.extend_from_slice(&req[8..20]);
    let covered_len = u16::try_from(m.len() - 20 + 24).unwrap();
    m[2..4].copy_from_slice(&covered_len.to_be_bytes());
    sign(m, pwd)
}

fn sign(mut m: Vec<u8>, key: &str) -> Vec<u8> {
    let key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let tag = ::ring::hmac::sign(&key, &m);
    m.extend_from_slice(&0x0008_u16.to_be_bytes());
    m.extend_from_slice(&20_u16.to_be_bytes());
    m.extend_from_slice(tag.as_ref());
    m
}

fn is_request(d: &[u8]) -> bool {
    d.len() >= 20 && d[0..2] == [0x00, 0x01]
}

/// One call the framer saw: the lane's host state as it arrived.
#[derive(Debug, Clone, Default)]
struct Seen {
    lane: u32,
    path: u32,
    bound: u32,
    verified: bool,
    keying: Option<(u32, Vec<u8>)>,
    local: String,
    routes_cap: usize,
    size: u32,
    told: Vec<(u32, String)>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Knobs {
    /// Answer the rendezvous with a zero-length route.
    bad_route: bool,
    /// On a check from a path other than the bound one: ask to move there, and route it a clear
    /// datagram that is not a check's answer.
    rebind_new: bool,
    /// A dialling framing: it offers at begin, settles terms that initiate and carry the far end's
    /// candidates, and checks every path it is told of, asking to bind the first.
    dial: bool,
    /// The framer fails (`Outcome::Failed`) the first clear-lane datagram it is handed.
    fail_clear: bool,
}

#[derive(Default)]
struct St {
    seen: Vec<Seen>,
    finished: Vec<Option<Seen>>,
    addrs: HashMap<u32, String>,
    remote: Option<(String, String, Vec<u8>)>,
    secured: Vec<Vec<u8>>,
    routes: Vec<(u32, u32, Vec<u8>)>,
    pieces: Vec<(u64, Vec<u8>)>,
    /// Flags for the next scripted batch of pieces; ordinary messages use zero.
    piece_flags: u16,
    /// Channel messages the framer was asked to emit, before secure routing.
    emitted: Vec<Vec<u8>>,
    terms: bool,
    request: (u32, u32, u32),
    candidates: String,
    txid: u8,
    /// This framing's own check credentials.
    local: (&'static str, &'static str),
}

struct Scripted {
    facts: DoorFacts,
    knobs: Knobs,
    st: Mutex<St>,
    /// A crossing parked once: the call it parks, said when it is in, and held until released.
    park: Mutex<Option<Park>>,
}

/// Which crossing a [`Park`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parks {
    Ingest,
    Emit,
    Finish,
}

struct Park {
    call: Parks,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

fn scripted(knobs: Knobs) -> Arc<Scripted> {
    scripted_as(knobs, (HOST_UFRAG, HOST_PWD))
}

fn scripted_as(knobs: Knobs, local: (&'static str, &'static str)) -> Arc<Scripted> {
    Arc::new(Scripted {
        facts: DoorFacts {
            name: "scripted".into(),
            claims: vec!["scripted"],
            role: ROLE_FRAMER,
            composes_over: Vec::new(),
            ported: false,
            status_rows: Vec::new(),
            duplex: Vec::new(),
            datagram: true,
        },
        knobs,
        st: Mutex::new(St {
            local,
            ..St::default()
        }),
        park: Mutex::new(None),
    })
}

fn raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: host-lent bytes, valid for the call.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// Read the lane: what arrived on it and the host's state.
fn read_lane(st: &mut St, lane: *const DatagramLane) -> Option<&'static DatagramLane> {
    if lane.is_null() {
        return None;
    }
    // SAFETY: host-lent lane, valid for the call; the test reads it only during the call.
    let l: &'static DatagramLane = unsafe { &*lane };
    let mut seen = Seen {
        lane: l.lane,
        path: l.path,
        bound: l.bound,
        verified: l.verified == 1,
        local: String::from_utf8_lossy(raw(l.local_addr.ptr, l.local_addr.len)).into_owned(),
        routes_cap: l.routes_cap,
        size: l.size,
        ..Seen::default()
    };
    if !l.keying.is_null() {
        // SAFETY: as above.
        let k = unsafe { &*l.keying };
        seen.keying = Some((k.profile, raw(k.bytes, k.len).to_vec()));
    }
    if !l.paths.is_null() {
        // SAFETY: as above, `paths_len` of them.
        let paths = unsafe { std::slice::from_raw_parts(l.paths, l.paths_len) };
        for path in paths {
            let addr = String::from_utf8_lossy(raw(path.addr.ptr, path.addr.len)).into_owned();
            st.addrs.insert(path.path, addr.clone());
            seen.told.push((path.path, addr));
        }
    }
    st.seen.push(seen);
    Some(l)
}

/// Write what the framer owes into the sink and the lane's routes.
fn write_answer(st: &mut St, sink: &FramerSink, lane: Option<&DatagramLane>, o: &mut FramerOut) {
    let mut wire_at = 0_usize;
    let mut frame_at = 0_usize;
    let mut frame = |b: &[u8]| -> FrameSpan {
        assert!(frame_at + b.len() <= sink.frame_cap);
        // SAFETY: the host's frame buffer, bounded above.
        unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), sink.frame.add(frame_at), b.len()) };
        let s = FrameSpan {
            offset: frame_at as u64,
            len: b.len() as u64,
        };
        frame_at += b.len();
        s
    };
    if let Some(lane) = lane {
        let mut n = 0_usize;
        for (path, l, bytes) in st.routes.drain(..) {
            assert!(n < lane.routes_cap && wire_at + bytes.len() <= sink.wire_cap);
            // SAFETY: the host's wire buffer and route buffer, bounded above.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), sink.wire.add(wire_at), bytes.len());
                lane.routes.add(n).write(DatagramRoute {
                    offset: wire_at as u64,
                    len: bytes.len() as u64,
                    path,
                    lane: l,
                });
            }
            wire_at += bytes.len();
            n += 1;
        }
        o.datagram.routes_len = n as u32;
        (
            o.datagram.request,
            o.datagram.request_from,
            o.datagram.request_to,
        ) = std::mem::take(&mut st.request);
    }
    if std::mem::take(&mut st.terms) {
        let (ru, rp, fp) = st.remote.clone().expect("terms after a rendezvous");
        let (lu, lp) = st.local;
        let candidates = std::mem::take(&mut st.candidates);
        o.datagram.terms = RendezvousTerms {
            role: if candidates.is_empty() {
                HANDSHAKE_ANSWERS
            } else {
                HANDSHAKE_INITIATES
            },
            _reserved: 0,
            local_user: frame(lu.as_bytes()),
            local_secret: frame(lp.as_bytes()),
            remote_user: frame(ru.as_bytes()),
            remote_secret: frame(rp.as_bytes()),
            peer_fingerprint: frame(&fp),
            candidates: if candidates.is_empty() {
                FrameSpan::default()
            } else {
                frame(candidates.as_bytes())
            },
        };
    }
    let mut n = 0_usize;
    for (stream, bytes) in st.pieces.drain(..) {
        let s = frame(&bytes);
        assert!(n < sink.pieces_cap);
        // SAFETY: the host's piece buffer, bounded above. A `FramePiece` is plain integers, so the
        // all-zero piece is valid: every field not named here (the status, the fault reading, the
        // retry) is zero, whatever the piece grows to.
        unsafe {
            sink.pieces.add(n).write(FramePiece {
                stream,
                offset: s.offset,
                len: s.len,

                flags: PIECE_END_OF_FRAME | if stream == 0 { 0 } else { st.piece_flags },
                ..std::mem::zeroed()
            });
        }
        n += 1;
    }
    st.piece_flags = 0;
    o.yielded.wire_len = wire_at as u64;
    o.yielded.frame_len = frame_at as u64;
    o.yielded.pieces_len = n as u32;
    o.yielded.flags = 0;
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

impl Scripted {
    /// Dialling: a check to every path this call told, and a bind request for the first while
    fn check_told(&self, st: &mut St, lane: &DatagramLane) {
        if !self.knobs.dial {
            return;
        }
        let told = st.seen.last().map(|s| s.told.clone()).unwrap_or_default();
        for (path, _) in told {
            st.txid = st.txid.wrapping_add(1);
            let c = check(FAR_UFRAG, HOST_UFRAG, FAR_PWD, 0x40 | st.txid);
            st.routes.push((path, LANE_CLEAR, c));
            if lane.bound == 0 && st.request.0 == 0 {
                st.request = (PATH_REQUEST_BIND, 0, path);
            }
        }
    }
}

impl FramerDoor for Scripted {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let parks = match call {
            Call::Ingest(..) => Some(Parks::Ingest),
            Call::Emit(..) => Some(Parks::Emit),
            Call::Finish(..) => Some(Parks::Finish),
            _ => None,
        };
        let mut park = self.park.lock().unwrap();
        if park.as_ref().is_some_and(|p| Some(p.call) == parks) {
            let p = park.take().unwrap();
            drop(park);
            let _ = p.entered.send(());
            let _ = p.release.recv();
        } else {
            drop(park);
        }
        let ok = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        let mut st = self.st.lock().unwrap();
        match call {
            Call::Begin(i, o) => {
                let lane = read_lane(&mut st, i.lane);
                o.framing = 7;
                if self.knobs.dial {
                    st.pieces.push((0, b"offer".to_vec()));
                }
                write_answer(&mut st, &i.sink, lane, o);
            }
            Call::Ingest(i, o) => {
                let lane = read_lane(&mut st, i.lane).expect("a datagram framer reads its lane");
                let bytes = raw(i.bytes, i.len).to_vec();
                if self.knobs.fail_clear && lane.lane == LANE_CLEAR {
                    return Crossed {
                        outcome: Outcome::Failed,
                        error: None,
                    };
                }
                match lane.lane {
                    LANE_RENDEZVOUS => {
                        let text = String::from_utf8(bytes).unwrap();
                        let mut w = text.split(' ');
                        let (u, pw, fp) = (w.next().unwrap(), w.next().unwrap(), w.next().unwrap());
                        st.remote = Some((u.into(), pw.into(), unhex(fp)));
                        if let Some(c) = w.next() {
                            st.candidates = c.split(',').map(|a| format!("{a}\n")).collect();
                        }
                        st.terms = true;
                        st.pieces.push((0, b"description".to_vec()));
                        if self.knobs.bad_route {
                            st.routes.push((1, LANE_CLEAR, Vec::new()));
                        }
                    }
                    LANE_CLEAR if is_request(&bytes) => {
                        let pwd = st.local.1;
                        st.routes.push((lane.path, LANE_CLEAR, answer(&bytes, pwd)));
                        if lane.bound == 0 {
                            st.request = (PATH_REQUEST_BIND, 0, lane.path);
                        } else if self.knobs.rebind_new && lane.path != lane.bound {
                            st.request = (PATH_REQUEST_REBIND, lane.bound, lane.path);
                            st.routes.push((lane.path, LANE_CLEAR, vec![0x80, 0, 0, 1]));
                        }
                    }
                    LANE_SECURED => {
                        st.secured.push(bytes.clone());
                        st.pieces.push((1, bytes));
                    }
                    _ => {}
                }
                self.check_told(&mut st, lane);
                write_answer(&mut st, &i.sink, Some(lane), o);
            }
            Call::Emit(i, o) => {
                let lane = read_lane(&mut st, i.lane).expect("a datagram framer reads its lane");
                let bytes = raw(i.bytes, i.len).to_vec();
                st.emitted.push(bytes.clone());
                if !bytes.is_empty() {
                    st.routes.push((lane.bound.max(1), LANE_SECURED, bytes));
                }
                write_answer(&mut st, &i.sink, Some(lane), o);
            }
            Call::Timer(i, o) => {
                let lane = read_lane(&mut st, i.lane);
                if let Some(l) = lane {
                    self.check_told(&mut st, l);
                }
                write_answer(&mut st, &i.sink, lane, o);
            }
            Call::Finish(i, o) => {
                let lane = read_lane(&mut st, i.lane);
                let seen = lane.and_then(|_| st.seen.pop());
                st.finished.push(seen);
                write_answer(&mut st, &i.sink, lane, o);
            }
            _ => {
                return Crossed {
                    outcome: Outcome::Refused,
                    error: None,
                }
            }
        }
        ok
    }
}

struct Far {
    a: Association,
    addr: SocketAddr,
    ups: Vec<Up>,
}

struct Rig {
    door: Arc<Scripted>,
    host: DatagramFraming,
    host_addr: SocketAddr,
    far: Far,
    now: Instant,
    /// Pieces the host handed up, in order.
    got: Vec<(u64, Vec<u8>)>,
    /// Datagrams the host sent anywhere but the far end.
    elsewhere: Vec<(SocketAddr, Vec<u8>)>,
    /// The far end's ICE agent answers the requests it is sent.
    answers: bool,
    /// Requests the far end was sent and did not answer.
    unanswered: Vec<Vec<u8>>,
    /// Every destination the judge was asked about.
    judged: Arc<Mutex<Vec<String>>>,
}

const METADATA: &str = "169.254.169.254:3478";

/// The destination judge: the link-local metadata range refused, any other literal admitted as
fn judge(asked: Arc<Mutex<Vec<String>>>) -> Arc<dyn DialJudge> {
    Arc::new(move |dest: &str, _class: u32, _done: Judged| {
        asked.lock().unwrap().push(dest.to_owned());
        let addr: SocketAddr = dest.parse().ok()?;
        match addr.ip() {
            std::net::IpAddr::V4(v4) if v4.is_link_local() => Some(Err(7_u64)),
            _ => Some(Ok(addr)),
        }
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rig(knobs: Knobs) -> Rig {
    let door = scripted(knobs);
    let host_cert = Arc::new(SessionCert::mint().unwrap());
    let far_cert = Arc::new(SessionCert::mint().unwrap());
    let host_addr = p("198.51.100.1:3478");
    let judged = Arc::new(Mutex::new(Vec::new()));
    let host = if knobs.dial {
        let opening = [("media".to_owned(), b"audio".to_vec())];
        let (host, y) = DatagramFraming::dial(
            door.clone(),
            Arc::clone(&host_cert),
            host_addr,
            &opening,
            judge(Arc::clone(&judged)),
            0,
        )
        .expect("the framing begins");
        assert_eq!(y.pieces.len(), 1, "the dialling framing offers at once");
        host
    } else {
        DatagramFraming::accept(door.clone(), Arc::clone(&host_cert), host_addr)
            .expect("the framing begins")
            .0
    };
    let far = Far {
        a: Association::new(
            Arc::clone(&far_cert),
            if knobs.dial {
                Role::Server
            } else {
                Role::Client
            },
            &creds(FAR_UFRAG, FAR_PWD),
            &creds(HOST_UFRAG, HOST_PWD),
            host_cert.fingerprint(),
        ),
        addr: p("203.0.113.9:50000"),
        ups: Vec::new(),
    };
    let mut r = Rig {
        door,
        host,
        host_addr,
        far,
        now: Instant::now(),
        got: Vec::new(),
        elsewhere: Vec::new(),
        answers: true,
        unanswered: Vec::new(),
        judged,
    };
    let mut description = format!("{FAR_UFRAG} {FAR_PWD} {}", hex(&far_cert.fingerprint()));
    if knobs.dial {
        description.push_str(&format!(" {},{METADATA},not-an-address", r.far.addr));
    }
    let mut y = r
        .host
        .rendezvous(description.as_bytes(), r.now)
        .expect("the rendezvous settles terms");
    r.got.extend(
        std::mem::take(&mut y.pieces)
            .into_iter()
            .map(|g| (g.stream, g.bytes)),
    );
    r
}

impl Rig {
    fn deliver(&mut self, from: SocketAddr, d: &[u8]) {
        let mut y = self
            .host
            .datagram(from, d, self.now)
            .expect("the host takes it");
        self.got.extend(
            std::mem::take(&mut y.pieces)
                .into_iter()
                .map(|g| (g.stream, g.bytes)),
        );
    }

    /// The far end's first check, then `rounds` of the clock with every datagram delivered.
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.now += Duration::from_millis(10);
            self.far.a.handle_timeout(self.now);
            let mut y = self.host.timeout(self.now).expect("the host's clock");
            self.got.extend(
                std::mem::take(&mut y.pieces)
                    .into_iter()
                    .map(|g| (g.stream, g.bytes)),
            );
            while let Some((to, d)) = self.host.poll_send() {
                if to != self.far.addr {
                    self.elsewhere.push((to, d));
                    continue;
                }
                let v = self.far.a.ingest(self.host_addr, &d, self.now);
                if v == Verdict::Raw && is_request(&d) && !self.answers {
                    self.unanswered.push(d);
                } else if v == Verdict::Raw && is_request(&d) {
                    let a = answer(&d, FAR_PWD);
                    let from = self.far.addr;
                    self.deliver(from, &a);
                }
            }
            let _ = self.far.a.bind_path(self.host_addr, self.now);
            while let Some((to, d)) = self.far.a.poll_wire() {
                assert_eq!(to, self.host_addr);
                let from = self.far.addr;
                self.deliver(from, &d);
            }
            while let Some(u) = self.far.a.poll_up() {
                self.far.ups.push(u);
            }
        }
    }

    fn first_check(&mut self) {
        let c = check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1);
        let from = self.far.addr;
        self.deliver(from, &c);
    }

    fn seen(&self) -> Vec<Seen> {
        self.door.st.lock().unwrap().seen.clone()
    }

    fn far_keying(&self) -> &SrtpKeying {
        self.far
            .ups
            .iter()
            .find_map(|u| match u {
                Up::Keyed(k) => Some(k),
                _ => None,
            })
            .expect("the far end exported keying material")
    }
}

#[test]
fn the_keying_material_item_is_presented_once_verified_and_equal_to_the_far_ends_export() {
    let mut r = rig(Knobs::default());
    assert_eq!(r.got, vec![(0, b"description".to_vec())]);
    r.first_check();
    r.pump(200);
    assert!(r.host.presented(), "the item was presented");
    assert_eq!(
        r.host.bound(),
        Some(r.far.addr),
        "the far end's path is bound"
    );

    let seen = r.seen();
    let keyed: Vec<&Seen> = seen.iter().filter(|s| s.keying.is_some()).collect();

    assert_eq!(keyed.len(), 1, "the item crosses exactly once: {seen:?}");
    let (profile, bytes) = keyed[0].keying.clone().unwrap();
    assert!(
        keyed[0].verified,
        "the item crosses only with the far end verified"
    );
    let far = r.far_keying();
    assert_eq!(
        profile,
        far.profile.code(),
        "the profile is the negotiated one"
    );
    assert!(profile == 0x0007 || profile == 0x0008, "AEAD-AES-GCM only");
    assert_eq!(
        bytes,
        far.material(),
        "the item is the exporter's output, both ends"
    );

    let first_verified = seen.iter().position(|s| s.verified).expect("verified once");
    assert!(seen[..first_verified].iter().all(|s| s.keying.is_none()));

    r.far.a.seal(b"ping").unwrap();
    r.pump(5);
    assert!(r.got.contains(&(1, b"ping".to_vec())), "{:?}", r.got);
    r.host.emit(1, b"pong", true, false, r.now).unwrap();
    r.pump(5);
    assert!(r
        .far
        .ups
        .iter()
        .any(|u| matches!(u, Up::Plaintext(p) if p == b"pong")));
    assert_eq!(r.host.refused_routes(), 0);
    assert!(r.elsewhere.is_empty());
}

#[test]
fn a_source_that_sent_no_verified_check_never_reaches_the_framer() {
    let mut r = rig(Knobs::default());
    let spoof = p("192.0.2.66:4444");
    let before = r.seen().len();

    r.deliver(
        spoof,
        &check(HOST_UFRAG, FAR_UFRAG, "wrong-password-012345", 2),
    );
    r.deliver(spoof, &[0x80, 0, 0, 1, 2, 3]);
    let seen = r.seen();
    assert_eq!(seen.len(), before, "nothing crossed for the spoofed source");
    assert!(seen
        .iter()
        .all(|s| s.told.iter().all(|(_, a)| a != &spoof.to_string())));

    r.first_check();
    let seen = r.seen();
    assert!(seen.len() > before);
    assert!(seen
        .iter()
        .any(|s| s.told.contains(&(1, r.far.addr.to_string()))));

    assert!(seen.iter().any(|s| s.lane == LANE_CLEAR && s.path == 1));
}

#[test]
fn a_rebind_to_a_path_that_never_answered_the_probe_is_not_applied() {
    let mut r = rig(Knobs {
        rebind_new: true,
        ..Knobs::default()
    });
    r.first_check();
    r.pump(200);
    assert_eq!(r.host.bound(), Some(r.far.addr));

    let spoof = p("192.0.2.77:5555");
    r.deliver(spoof, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 3));
    r.pump(100);
    assert_eq!(
        r.host.bound(),
        Some(r.far.addr),
        "the bound path did not move"
    );
    let last = r.seen().last().cloned().unwrap();
    assert_eq!(last.bound, 1, "the framer is still told the first path");

    assert!(r
        .elsewhere
        .iter()
        .all(|(to, d)| *to == spoof && d.len() >= 20 && (d[0..2] == [0, 1] || d[0..2] == [1, 1])));
    assert!(r.elsewhere.iter().any(|(_, d)| d[0..2] == [1, 1]));
    assert_eq!(r.host.refused_routes(), 1);

    let probe = r
        .elsewhere
        .iter()
        .rev()
        .find(|(_, d)| d[0..2] == [0, 1])
        .map(|(_, d)| d.clone())
        .expect("core probed the new path");
    r.deliver(spoof, &answer(&probe, FAR_PWD));
    assert_eq!(r.host.bound(), Some(spoof), "a proven path is bound");
}

#[test]
fn a_framer_answer_that_breaks_the_lane_is_a_fault_before_any_byte_is_used() {
    let door = scripted(Knobs {
        bad_route: true,
        ..Knobs::default()
    });
    let cert = Arc::new(SessionCert::mint().unwrap());
    let (mut host, _) =
        DatagramFraming::accept(door, cert, p("198.51.100.1:3478")).expect("begins");
    let e = host
        .rendezvous(b"farfrag far-password-0123456789 00", Instant::now())
        .expect_err("a zero-length route is refused");
    assert_eq!(e.outcome, Outcome::Fault, "{e}");
    assert!(host.poll_send().is_none());
}

#[test]
fn nothing_on_the_port_is_the_associations_before_the_rendezvous() {
    let door = scripted(Knobs::default());
    let cert = Arc::new(SessionCert::mint().unwrap());
    let (mut host, _) =
        DatagramFraming::accept(door.clone(), cert, p("198.51.100.1:3478")).expect("begins");
    let before = door.st.lock().unwrap().seen.len();
    let y = host
        .datagram(
            p("203.0.113.9:50000"),
            &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 4),
            Instant::now(),
        )
        .unwrap();
    assert!(y.pieces.is_empty());
    assert_eq!(door.st.lock().unwrap().seen.len(), before);

    let seen = door.st.lock().unwrap().seen.clone();
    assert!(seen.iter().all(|s| s.keying.is_none() && !s.verified));
}

fn dialling() -> Knobs {
    Knobs {
        dial: true,
        ..Knobs::default()
    }
}

#[test]
fn dialling_every_candidate_meets_the_judge_and_a_refused_one_is_never_sent_a_byte() {
    let mut r = rig(dialling());
    r.pump(200);

    let judged = r.judged.lock().unwrap().clone();
    assert!(judged.contains(&r.far.addr.to_string()), "{judged:?}");
    assert!(judged.contains(&METADATA.to_owned()), "{judged:?}");
    assert_eq!(
        r.host.refused_candidates(),
        2,
        "the metadata address and the non-address"
    );

    assert!(
        r.elsewhere.is_empty(),
        "nothing left for any other address: {:?}",
        r.elsewhere
    );
    assert!(r
        .seen()
        .iter()
        .all(|s| s.told.iter().all(|(_, a)| a != METADATA)));

    assert_eq!(r.host.bound(), Some(r.far.addr));
    assert!(r.host.presented());
    let keyed: Vec<Seen> = r
        .seen()
        .into_iter()
        .filter(|s| s.keying.is_some())
        .collect();
    assert_eq!(keyed.len(), 1);
    assert!(keyed[0].verified);
    assert_eq!(
        keyed[0].keying.as_ref().unwrap().1,
        r.far_keying().material()
    );
    r.host.emit(1, b"hello", true, false, r.now).unwrap();
    r.pump(5);
    assert!(r
        .far
        .ups
        .iter()
        .any(|u| matches!(u, Up::Plaintext(p) if p == b"hello")));
}

#[test]
fn dialling_an_admitted_candidate_never_binds_unverified() {
    let mut r = rig(dialling());
    r.answers = false;
    r.pump(200);

    assert!(!r.unanswered.is_empty(), "core probed the candidate");
    assert_eq!(r.host.bound(), None, "an unproven candidate is not bound");
    assert!(!r.host.presented());

    let unanswered = std::mem::take(&mut r.unanswered);
    for d in &unanswered {
        r.deliver(p("192.0.2.88:6666"), &answer(d, FAR_PWD));
    }
    assert_eq!(r.host.bound(), None, "an answer from elsewhere is no proof");

    let from = r.far.addr;
    for d in &unanswered {
        r.deliver(from, &answer(d, FAR_PWD));
    }
    r.answers = true;
    r.pump(200);
    assert_eq!(r.host.bound(), Some(r.far.addr));
    assert!(r.host.presented());
}

/// The core probes `r` sent to `to` (Binding requests).
fn probes_to(r: &Rig, to: SocketAddr) -> Vec<Vec<u8>> {
    r.elsewhere
        .iter()
        .filter(|(at, d)| *at == to && is_request(d))
        .map(|(_, d)| d.clone())
        .collect()
}

#[test]
fn dialling_a_check_from_a_path_the_judge_refuses_is_never_probed_handed_up_or_bound() {
    let mut r = rig(Knobs {
        dial: true,
        rebind_new: true,
        ..Knobs::default()
    });
    r.pump(200);
    assert_eq!(r.host.bound(), Some(r.far.addr));
    assert!(r.elsewhere.is_empty(), "{:?}", r.elsewhere);

    let refused = p("169.254.10.20:4000");
    r.deliver(refused, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 0x21));
    r.pump(20);
    assert!(
        r.judged.lock().unwrap().contains(&refused.to_string()),
        "the heard path met the judge"
    );

    for probe in probes_to(&r, refused) {
        r.deliver(refused, &answer(&probe, FAR_PWD));
    }
    r.pump(20);
    assert_eq!(
        r.host.bound(),
        Some(r.far.addr),
        "a refused path is never bound"
    );
    assert!(
        r.elsewhere.iter().all(|(to, _)| *to != refused),
        "a refused path is sent no byte: {:?}",
        r.elsewhere
    );
    assert!(
        !r.host.owns(refused),
        "a refused path is not the association's"
    );
    assert!(
        r.seen()
            .iter()
            .all(|s| s.told.iter().all(|(_, a)| a != &refused.to_string())),
        "a refused path is never numbered or told to the framer"
    );

    let admitted = p("192.0.2.50:7000");
    r.deliver(admitted, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 0x22));
    r.pump(1);
    assert!(r.judged.lock().unwrap().contains(&admitted.to_string()));
    assert!(r.host.owns(admitted));
    assert!(r
        .seen()
        .iter()
        .any(|s| s.told.iter().any(|(_, a)| a == &admitted.to_string())));
    let probe = probes_to(&r, admitted)
        .pop()
        .expect("core probed the admitted path");
    r.deliver(admitted, &answer(&probe, FAR_PWD));
    assert_eq!(
        r.host.bound(),
        Some(admitted),
        "an admitted, proven path binds"
    );
}

const B_UFRAG: &str = "bfrag";
const B_PWD: &str = "b-password-0123456789";

/// An accepted association on `door`, its rendezvous settled.
fn settled(door: Arc<Scripted>) -> DatagramFraming {
    let cert = Arc::new(SessionCert::mint().unwrap());
    let (mut f, _) = DatagramFraming::accept(door, cert, p("198.51.100.1:3478")).unwrap();
    let fp = hex(&SessionCert::mint().unwrap().fingerprint());
    f.rendezvous(
        format!("{FAR_UFRAG} {FAR_PWD} {fp}").as_bytes(),
        Instant::now(),
    )
    .unwrap();
    f
}

fn lanes(door: &Scripted) -> Vec<u32> {
    door.st
        .lock()
        .unwrap()
        .seen
        .iter()
        .map(|s| s.lane)
        .collect()
}

#[test]
fn one_port_finds_each_datagram_its_association_by_user_name_then_by_path() {
    let (da, db) = (
        scripted(Knobs::default()),
        scripted_as(Knobs::default(), (B_UFRAG, B_PWD)),
    );
    let mut port = super::Associations::new();
    let a = port.add(settled(da.clone())).unwrap();
    let b = port.add(settled(db.clone())).unwrap();
    assert_ne!(a, b);
    let (pa, pb, stranger) = (
        p("203.0.113.1:1000"),
        p("203.0.113.2:2000"),
        p("192.0.2.3:3000"),
    );
    let now = Instant::now();
    let (before_a, before_b) = (lanes(&da).len(), lanes(&db).len());

    let (id, y) = port
        .datagram(pa, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1), now)
        .unwrap();
    assert_eq!(id, a);
    y.unwrap();
    let (id, y) = port
        .datagram(pb, &check(B_UFRAG, FAR_UFRAG, B_PWD, 2), now)
        .unwrap();
    assert_eq!(id, b);
    y.unwrap();
    assert_eq!(
        lanes(&da)[before_a..],
        [LANE_CLEAR],
        "a saw its own check only"
    );
    assert_eq!(
        lanes(&db)[before_b..],
        [LANE_CLEAR],
        "b saw its own check only"
    );

    let (id, _) = port.datagram(pb, &[0x80, 0x6f, 0, 1], now).unwrap();
    assert_eq!(id, b);

    assert!(port
        .datagram(stranger, &check("nobody", FAR_UFRAG, HOST_PWD, 3), now)
        .is_none());
    assert!(port.datagram(stranger, &[0x80, 0x6f, 0, 2], now).is_none());

    let (id, _) = port
        .datagram(
            stranger,
            &check(HOST_UFRAG, FAR_UFRAG, "wrong-password-012345", 4),
            now,
        )
        .unwrap();
    assert_eq!(id, a);
    assert!(port.datagram(stranger, &[0x80, 0x6f, 0, 3], now).is_none());

    assert_eq!(
        port.add(settled(scripted(Knobs::default()))),
        Err(super::NotAdded::UserTaken)
    );
    let unsettled = DatagramFraming::accept(
        scripted(Knobs::default()),
        Arc::new(SessionCert::mint().unwrap()),
        p("198.51.100.1:3478"),
    )
    .unwrap()
    .0;
    assert_eq!(port.add(unsettled), Err(super::NotAdded::NoTerms));

    assert!(port.remove(b).is_some());
    assert!(port.datagram(pb, &[0x80, 0x6f, 0, 4], now).is_none());
    assert_eq!(port.len(), 1);
}

#[test]
fn a_dialled_association_is_found_by_its_admitted_candidates_before_they_speak() {
    let mut r = rig(dialling());
    let mut port = super::Associations::new();
    let host = std::mem::replace(
        &mut r.host,
        settled(scripted_as(Knobs::default(), (B_UFRAG, B_PWD))),
    );
    let id = port.add(host).unwrap();

    let (got, _) = port
        .datagram(r.far.addr, &[0x80, 0x6f, 0, 1], r.now)
        .unwrap();
    assert_eq!(got, id);

    assert!(port
        .datagram(p(METADATA), &[0x80, 0x6f, 0, 1], r.now)
        .is_none());
}

#[test]
fn only_a_datagram_framer_is_driven_over_the_port() {
    let stream_framer = scripted(Knobs::default());

    let not = Arc::new(Scripted {
        facts: DoorFacts {
            datagram: false,
            ..stream_framer.facts.clone()
        },
        knobs: Knobs::default(),
        st: Mutex::new(St::default()),
        park: Mutex::new(None),
    });
    let cert = Arc::new(SessionCert::mint().unwrap());
    let e = DatagramFraming::accept(not.clone(), Arc::clone(&cert), p("198.51.100.1:3478"))
        .expect_err("not a datagram framer");
    assert_eq!(e.outcome, Outcome::Refused);
    assert!(not.st.lock().unwrap().seen.is_empty(), "nothing crossed");
    assert!(DatagramFraming::accept(stream_framer, cert, p("198.51.100.1:3478")).is_ok());
}

fn got(stream: u64, bytes: &[u8], fields: bool) -> crate::framer::Got {
    crate::framer::Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

#[test]
fn a_head_block_names_a_line_by_kind_and_a_channel_by_label() {
    use super::{stream_head, StreamHead};
    assert_eq!(
        stream_head(b"kind: audio\r\ncodec: opus\r\n"),
        Some(StreamHead::Line {
            kind: "audio".into()
        })
    );
    assert_eq!(
        stream_head(b"label: events\r\n"),
        Some(StreamHead::Channel {
            label: "events".into()
        })
    );
    assert_eq!(stream_head(b"other: x\r\n"), None);
}

#[test]
fn the_bridge_carries_line_frames_unread_line_for_line_and_hands_channels_to_the_session() {
    use super::{Across, Bridge, Leg};
    let mut b = Bridge::new();
    let (session, across) = b.sort(
        Leg::Caller,
        vec![
            got(0, b"description", false),
            got(1 << 32, b"kind: audio\r\ncodec: opus\r\n", true),
            got(1, b"label: events\r\n", true),
            got(1 << 32, b"frame-before-upstream", false),
        ],
    );

    assert!(across.is_empty());
    assert_eq!(
        session.iter().map(|g| g.stream).collect::<Vec<_>>(),
        vec![0, 1],
        "the description and the channel's head are the session's"
    );

    assert_eq!(
        b.opening(&["events"]),
        vec![
            ("media".to_owned(), b"audio".to_vec()),
            ("channel".to_owned(), b"events".to_vec())
        ]
    );
    let _ = b.sort(Leg::Upstream, vec![got(7 << 32, b"kind: audio\r\n", true)]);
    assert_eq!(b.mirrored(), Ok(()));
    let (session, across) = b.sort(
        Leg::Caller,
        vec![got(1 << 32, b"\x01\x02", false), got(1, b"{}", false)],
    );
    assert_eq!(
        across,
        vec![Across {
            stream: 7 << 32,
            bytes: b"\x01\x02".to_vec(),
            end_of_frame: true
        }]
    );
    assert_eq!(session.len(), 1, "the channel's message is the session's");
    let (_, back) = b.sort(Leg::Upstream, vec![got(7 << 32, b"\x03", false)]);
    assert_eq!(back[0].stream, 1 << 32);

    b.stop();
    let (_, a) = b.sort(Leg::Caller, vec![got(1 << 32, b"\x04", false)]);
    let (_, z) = b.sort(Leg::Upstream, vec![got(7 << 32, b"\x05", false)]);
    assert!(a.is_empty() && z.is_empty());
}

#[test]
fn legs_that_do_not_mirror_never_half_bridge() {
    use super::{Bridge, Leg};
    let mut b = Bridge::new();
    let _ = b.sort(
        Leg::Caller,
        vec![
            got(10, b"kind: audio\r\n", true),
            got(11, b"kind: audio\r\n", true),
        ],
    );
    let _ = b.sort(Leg::Upstream, vec![got(20, b"kind: audio\r\n", true)]);
    assert!(b.mirrored().is_err(), "two lines against one");

    assert_eq!(b.across(Leg::Caller, 10), None);
    let (_, a) = b.sort(Leg::Caller, vec![got(10, b"\x01", false)]);
    assert!(a.is_empty());
    let mut k = Bridge::new();
    let _ = k.sort(Leg::Caller, vec![got(10, b"kind: audio\r\n", true)]);
    let _ = k.sort(Leg::Upstream, vec![got(20, b"kind: video\r\n", true)]);
    assert!(k.mirrored().is_err(), "a kind mismatch");
}

/// A leg as a test sees it: the frames that crossed into it, and how often it was closed.
#[derive(Default)]
struct Sink {
    lines: Mutex<Vec<super::Across>>,
    closed: std::sync::atomic::AtomicU32,
}

impl super::LegSink for Sink {
    fn line(&self, across: super::Across, _now: Instant) {
        self.lines.lock().unwrap().push(across);
    }
    fn close(&self) {
        self.closed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn closes(s: &Sink) -> u32 {
    s.closed.load(std::sync::atomic::Ordering::SeqCst)
}

/// A connector serving the scripted dialling framer under `dg` and the identity framer under
fn book() -> crate::Connector {
    let dg = Arc::new(Scripted {
        facts: DoorFacts {
            name: "dg".into(),
            claims: vec!["dg"],
            ..scripted(dialling()).facts.clone()
        },
        knobs: dialling(),
        st: Mutex::new(St {
            local: (HOST_UFRAG, HOST_PWD),
            ..St::default()
        }),
        park: Mutex::new(None),
    });
    let view = crate::registry::Transports::new(vec![
        crate::registry::Entry {
            door: dg,
            alpn: Vec::new(),
        },
        crate::registry::Entry {
            door: Arc::new(crate::support::TestDoor::identity("bytes")),
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let c = crate::Connector::serving(
        view,
        crate::tests::loopback_literals(),
        None,
        Arc::new(|_, _| {}),
    );
    c.declare_over(
        busbar_contract::conn::InstanceId(1),
        busbar_contract::conn::NeedId(0),
        "dg",
    )
    .expect("a served scheme declares");
    c
}

fn open_unit(
    c: &crate::Connector,
    unit: u64,
) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
    use busbar_contract::conn::Conns as _;
    c.open(
        busbar_contract::conn::InstanceId(1),
        busbar_contract::conn::NeedId(0),
        &busbar_contract::conn::OpenDesc {
            target: "bytes://127.0.0.1:9",
            unit,
            ..busbar_contract::conn::OpenDesc::default()
        },
    )
}

/// RED arms of the session book: an open over a datagram framer's need serving no unit, or a unit
#[test]
fn the_session_book_refuses_no_unit_and_an_unregistered_unit_and_forgets_a_closed_one() {
    use busbar_contract::conn::ConnError;
    let c = book();
    assert_eq!(open_unit(&c, 0), Err(ConnError::Refused), "no unit");
    assert_eq!(open_unit(&c, 7), Err(ConnError::Refused), "no registration");
    let sink = Arc::new(Sink::default());
    let pairing = super::Pairing::new(sink.clone(), p("127.0.0.1:3478"));
    assert_eq!(c.pair(0, Arc::clone(&pairing)), Err(ConnError::Refused));
    c.pair(7, Arc::clone(&pairing)).unwrap();
    assert_eq!(
        c.pair(
            7,
            super::Pairing::new(Arc::new(Sink::default()), p("127.0.0.1:3478"))
        ),
        Err(ConnError::Refused),
        "one session per unit"
    );
    c.unpair(7);
    assert!(pairing.closed());
    assert_eq!(closes(&sink), 1, "the caller leg closed once");
    c.unpair(7);
    assert_eq!(closes(&sink), 1, "a second cleanup closes nothing");
    assert_eq!(
        open_unit(&c, 7),
        Err(ConnError::Refused),
        "the stale leg is gone"
    );
}

/// Two sessions' pairings never cross: a frame sorted on one reaches only its own other leg; and a
#[test]
fn two_sessions_never_cross_and_a_close_closes_both_legs_once() {
    use super::{Leg, Pairing};
    let now = Instant::now();
    let (ca, ua, cb, ub) = (
        Arc::new(Sink::default()),
        Arc::new(Sink::default()),
        Arc::new(Sink::default()),
        Arc::new(Sink::default()),
    );
    let a = Pairing::new(ca.clone(), p("127.0.0.1:1"));
    let b = Pairing::new(cb.clone(), p("127.0.0.1:2"));
    for (pairing, up) in [(&a, &ua), (&b, &ub)] {
        pairing.sort(Leg::Caller, vec![got(10, b"kind: audio\r\n", true)], now);
        pairing.sort(Leg::Upstream, vec![got(20, b"kind: audio\r\n", true)], now);
        pairing.attach(up.clone()).unwrap();
    }
    a.sort(Leg::Caller, vec![got(10, b"A", false)], now);
    b.sort(Leg::Upstream, vec![got(20, b"B", false)], now);
    assert_eq!(ua.lines.lock().unwrap().len(), 1);
    assert_eq!(ua.lines.lock().unwrap()[0].bytes, b"A");
    assert_eq!(cb.lines.lock().unwrap()[0].bytes, b"B");
    assert!(ub.lines.lock().unwrap().is_empty() && ca.lines.lock().unwrap().is_empty());
    a.close();
    a.close();
    assert_eq!((closes(&ca), closes(&ua)), (1, 1), "both legs, once");
    assert_eq!(
        (closes(&cb), closes(&ub)),
        (0, 0),
        "the other session runs on"
    );
    a.sort(Leg::Caller, vec![got(10, b"late", false)], now);
    assert_eq!(ua.lines.lock().unwrap().len(), 1, "nothing after the close");
    assert!(
        a.attach(ua.clone()).is_err(),
        "a closed pairing attaches nothing"
    );
}

fn head(status: busbar_contract::transport::wire::WireStatusClass) -> busbar_contract::conn::Piece {
    busbar_contract::conn::Piece {
        kind: busbar_contract::conn::PieceKind::Fields,
        stream: busbar_contract::ids::StreamId(0),
        len: 0,
        end: true,
        status: Some(status),
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

fn piece(kind: busbar_contract::conn::PieceKind) -> busbar_contract::conn::Piece {
    busbar_contract::conn::Piece {
        kind,
        status: None,
        ..head(busbar_contract::transport::wire::WireStatusClass::Other)
    }
}

/// An upstream leg dialled by the scripted framer for `pairing`, on a real port.
fn leg(pairing: &Arc<super::Pairing>) -> crate::dialled::Dialled {
    let cert = Arc::new(SessionCert::mint().unwrap());
    let port = crate::udp::ReadyPort::open(crate::udp::bind("127.0.0.1:0").unwrap()).unwrap();
    let (framing, _) = DatagramFraming::dial(
        scripted(dialling()),
        cert,
        port.local_addr(),
        &pairing.opening(),
        judge(Arc::new(Mutex::new(Vec::new()))),
        0,
    )
    .unwrap();
    crate::dialled::Dialled::new(framing, port, Arc::clone(pairing), None)
}

/// A far end that refuses the exchange is relayed whole (its head, its body, its end) and nothing
#[test]
fn a_refused_exchange_is_relayed_whole_and_leaves_no_bridge_and_an_answered_one_runs() {
    use busbar_contract::conn::PieceKind;
    use busbar_contract::transport::wire::WireStatusClass;
    crate::support::worker().block_on(async {
        let sink = Arc::new(Sink::default());
        let pairing = super::Pairing::new(sink.clone(), p("127.0.0.1:3478"));
        let d = leg(&pairing);
        let h = d
            .exchanged(head(WireStatusClass::FarEndFault), b"")
            .unwrap();
        assert!(h.is_some(), "the far end's head is the reader's");
        let body = d
            .exchanged(piece(PieceKind::Body), b"{\"error\":{}}")
            .unwrap();
        assert!(body.is_some(), "a refusal's body is the reader's");
        let end = d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        assert!(end.is_some());
        assert!(!d.exchanging());
        assert!(pairing.closed(), "nothing half-bridges");
        assert_eq!(closes(&sink), 1);

        let sink = Arc::new(Sink::default());
        let pairing = super::Pairing::new(sink.clone(), p("127.0.0.1:3478"));
        let d = leg(&pairing);
        assert!(d
            .exchanged(head(WireStatusClass::Success), b"")
            .unwrap()
            .is_some());
        let fp = hex(&SessionCert::mint().unwrap().fingerprint());
        let answer = format!("{FAR_UFRAG} {FAR_PWD} {fp} 203.0.113.9:50000");
        assert!(d
            .exchanged(piece(PieceKind::Body), answer.as_bytes())
            .unwrap()
            .is_none());
        assert!(d
            .exchanged(piece(PieceKind::Completion), b"")
            .unwrap()
            .is_none());
        assert!(!d.exchanging());
        assert!(!pairing.closed(), "the mirrored leg is attached and runs");
        d.close();
        assert!(pairing.closed());
        assert_eq!(closes(&sink), 1);
    });
}

/// Lines that do not mirror refuse the open: the description settles nothing attached, and the
#[test]
fn an_answer_whose_lines_do_not_mirror_refuses_the_open() {
    use busbar_contract::conn::{ConnError, PieceKind};
    use busbar_contract::transport::wire::WireStatusClass;
    crate::support::worker().block_on(async {
        let sink = Arc::new(Sink::default());
        let pairing = super::Pairing::new(sink.clone(), p("127.0.0.1:3478"));
        pairing.sort(
            super::Leg::Caller,
            vec![got(10, b"kind: audio\r\n", true)],
            Instant::now(),
        );
        let d = leg(&pairing);
        d.exchanged(head(WireStatusClass::Success), b"").unwrap();
        let fp = hex(&SessionCert::mint().unwrap().fingerprint());
        let answer = format!("{FAR_UFRAG} {FAR_PWD} {fp} 203.0.113.9:50000");
        d.exchanged(piece(PieceKind::Body), answer.as_bytes())
            .unwrap();
        assert_eq!(
            d.exchanged(piece(PieceKind::Completion), b""),
            Err(ConnError::Refused)
        );
        assert!(pairing.closed());
        assert_eq!(closes(&sink), 1);
    });
}

/// A path one association holds is never taken by a check another hears from it.
#[test]
fn a_path_one_association_holds_is_never_taken_by_a_check_another_hears_from_it() {
    let (da, db) = (
        scripted(Knobs::default()),
        scripted_as(Knobs::default(), (B_UFRAG, B_PWD)),
    );
    let mut port = super::Associations::new();
    let a = port.add(settled(da.clone())).unwrap();
    let b = port.add(settled(db.clone())).unwrap();
    let pa = p("203.0.113.1:1000");
    let now = Instant::now();
    let (id, y) = port
        .datagram(pa, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1), now)
        .unwrap();
    assert_eq!(id, a);
    y.unwrap();
    let (id, _) = port.datagram(pa, &[0x80, 0x6f, 0, 1], now).unwrap();
    assert_eq!(id, a, "control: a's path finds a");

    let (id, y) = port
        .datagram(pa, &check(B_UFRAG, FAR_UFRAG, B_PWD, 2), now)
        .unwrap();
    assert_eq!(id, b);
    y.unwrap();
    let (id, _) = port.datagram(pa, &[0x80, 0x6f, 0, 2], now).unwrap();
    assert_eq!(id, a, "a's path is still a's");
}

/// A port keeps no path for an association that no longer owns it.
#[test]
fn a_port_keeps_no_path_for_an_association_that_no_longer_owns_it() {
    let da = scripted(Knobs::default());
    let mut port = super::Associations::new();
    let a = port.add(settled(da.clone())).unwrap();
    let now = Instant::now();
    for i in 0..64_u16 {
        let from = SocketAddr::from(([203, 0, 113, 1], 1000 + i));
        let txid = u8::try_from(i % 250).unwrap() + 1;
        let (id, y) = port
            .datagram(from, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, txid), now)
            .unwrap();
        assert_eq!(id, a);
        y.unwrap();
    }
    let routed = port.by_path.values().filter(|id| **id == a).count();
    assert!(
        routed <= 16,
        "the port routes {routed} paths to an association that heard at most 16 of them"
    );
}

/// A far end description past its bound fails the open.
#[test]
fn a_far_end_description_past_its_bound_fails_the_open() {
    use busbar_contract::conn::{ConnError, PieceKind};
    use busbar_contract::transport::wire::WireStatusClass;
    crate::support::worker().block_on(async {
        let sink = Arc::new(Sink::default());
        let pairing = super::Pairing::new(sink.clone(), p("127.0.0.1:3478"));
        let d = leg(&pairing);
        d.exchanged(head(WireStatusClass::Success), b"").unwrap();
        let chunk = vec![b'a'; 16 * 1024];
        let mut answered = Ok(None);
        for _ in 0..64 {
            answered = d.exchanged(piece(PieceKind::Body), &chunk);
            if answered.is_err() {
                break;
            }
        }
        assert_eq!(
            answered,
            Err(ConnError::Refused),
            "1 MiB of description is refused"
        );
        assert!(pairing.closed(), "nothing half-bridges");
    });
}

/// A message written in parts past its bound is refused.
#[test]
fn a_message_written_in_parts_past_its_bound_is_refused() {
    use busbar_contract::conn::{ConnError, PieceKind};
    use busbar_contract::transport::wire::WireStatusClass;
    crate::support::worker().block_on(async {
        let sink = Arc::new(Sink::default());
        let pairing = super::Pairing::new(sink.clone(), p("127.0.0.1:3478"));
        let d = leg(&pairing);
        d.exchanged(head(WireStatusClass::Success), b"").unwrap();
        let fp = hex(&SessionCert::mint().unwrap().fingerprint());
        let answer = format!("{FAR_UFRAG} {FAR_PWD} {fp} 203.0.113.9:50000");
        d.exchanged(piece(PieceKind::Body), answer.as_bytes())
            .unwrap();
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        assert!(!pairing.closed(), "the leg runs");
        let chunk = vec![b'a'; 16 * 1024];
        let mut wrote = Ok(0);
        for _ in 0..64 {
            wrote = d.write(&chunk, false, false);
            if wrote.is_err() {
                break;
            }
        }
        assert_eq!(wrote, Err(ConnError::Refused), "1 MiB unended is refused");
        d.close();
    });
}

const C_UFRAG: &str = "cfrag";
const C_PWD: &str = "c-password-0123456789";

/// The existing scripted dialler, retained so tests can deliver later channel heads or failures.
fn observed_dialled() -> (
    Arc<crate::dialled::Dialled>,
    Arc<Scripted>,
    Arc<super::Pairing>,
    SocketAddr,
) {
    let pairing = super::Pairing::new(Arc::new(Sink::default()), p("127.0.0.1:3478"));
    observed_dialled_for(pairing)
}

fn observed_dialled_for(
    pairing: Arc<super::Pairing>,
) -> (
    Arc<crate::dialled::Dialled>,
    Arc<Scripted>,
    Arc<super::Pairing>,
    SocketAddr,
) {
    let door = scripted(dialling());
    let port = crate::udp::ReadyPort::open(crate::udp::bind("127.0.0.1:0").unwrap()).unwrap();
    let at = port.local_addr();
    let (framing, _) = DatagramFraming::dial(
        door.clone(),
        Arc::new(SessionCert::mint().unwrap()),
        at,
        &pairing.opening(),
        judge(Arc::new(Mutex::new(Vec::new()))),
        0,
    )
    .unwrap();
    let d = Arc::new(crate::dialled::Dialled::new(
        framing,
        port,
        pairing.clone(),
        None,
    ));
    d.exchanged(
        head(busbar_contract::transport::wire::WireStatusClass::Success),
        b"",
    )
    .unwrap();
    let fp = hex(&SessionCert::mint().unwrap().fingerprint());
    let answer = format!("{FAR_UFRAG} {FAR_PWD} {fp}");
    d.exchanged(
        piece(busbar_contract::conn::PieceKind::Body),
        answer.as_bytes(),
    )
    .unwrap();
    (d, door, pairing, at)
}

/// A verified peer check drives the scripted batch through the real port and association.
async fn deliver_dialled(d: &crate::dialled::Dialled, door: &Scripted, at: SocketAddr) -> bool {
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(&check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1), at)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ready = d.ready(std::task::Waker::noop());
            if door.st.lock().unwrap().pieces.is_empty() {
                return ready;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the peer check drives the scripted channel piece")
}

#[test]
fn a_pending_final_write_preserves_accepted_parts_until_the_channel_is_named() {
    use busbar_contract::conn::{ConnError, PieceKind};
    crate::support::worker().block_on(async {
        let (d, door, pairing, at) = observed_dialled();
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        assert!(!pairing.closed());
        assert_eq!(d.write(b"accepted-", false, false), Ok(9));
        assert_eq!(d.write(b"tail", true, false), Err(ConnError::Pending));
        assert_eq!(d.write(b"tail", true, false), Err(ConnError::Pending));
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((3, b"label: events\r\n".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_FIELDS;
        }
        assert!(!deliver_dialled(&d, &door, at).await);
        assert!(pairing.published().await.failure.is_none());
        assert_eq!(d.write(b"tail", true, false), Ok(4));
        assert_eq!(d.write(b"next", true, false), Err(ConnError::Pending));
        assert!(pairing.published().await.failure.is_none());
        assert_eq!(d.write(b"next", true, false), Ok(4));
        assert!(pairing.published().await.failure.is_none());
        assert_eq!(
            door.st.lock().unwrap().emitted,
            vec![b"accepted-tail".to_vec(), b"next".to_vec()],
            "only rejected final bytes are re-offered; the accepted prefix appears once"
        );
        d.close();
    });
}

#[test]
fn wait_readiness_keeps_a_consumed_channel_failure_as_the_next_reads_answer() {
    use busbar_contract::conn::{ConnError, PieceKind};
    crate::support::worker().block_on(async {
        let (d, door, pairing, at) = observed_dialled();
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((3, b"channel failed".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_STREAM_FAILED;
        }
        assert!(deliver_dialled(&d, &door, at).await);
        let mut buf = [0; 32];
        assert_eq!(
            d.read(std::task::Waker::noop(), &mut buf),
            Err(ConnError::Fault)
        );
        assert!(pairing.closed(), "the failed association closes both legs");
        assert!(d.ready(std::task::Waker::noop()));
        assert_eq!(
            d.read(std::task::Waker::noop(), &mut buf),
            Err(ConnError::Fault)
        );
        d.close();
    });
}

#[test]
fn a_channel_failure_yielded_by_a_write_stays_terminal_for_the_reader() {
    use busbar_contract::conn::{ConnError, PieceKind};
    crate::support::worker().block_on(async {
        let (d, door, pairing, at) = observed_dialled();
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((3, b"label: events\r\n".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_FIELDS;
        }
        assert!(!deliver_dialled(&d, &door, at).await);
        assert!(pairing.published().await.failure.is_none());
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((3, b"channel failed".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_STREAM_FAILED;
        }
        assert_eq!(d.write(b"message", true, false), Ok(7));
        let publication = pairing.published().await;
        assert!(
            publication.failure.is_some(),
            "the actual crossing retains its terminal failure"
        );
        assert_eq!(publication.original_bytes, 7);
        assert_eq!(publication.original_handed_bytes, 7);
        assert!(pairing.closed());
        assert!(d.ready(std::task::Waker::noop()));
        assert_eq!(
            d.read(std::task::Waker::noop(), &mut [0; 8]),
            Err(ConnError::Fault)
        );
        assert_eq!(d.write(b"message", true, false), Err(ConnError::Fault));
        assert_eq!(
            door.st.lock().unwrap().emitted,
            vec![b"message".to_vec()],
            "accepted input was crossed once and is never replayed after failure"
        );
        d.close();
    });
}

#[derive(Default)]
struct SettledWake(std::sync::atomic::AtomicBool);

impl std::task::Wake for SettledWake {
    fn wake(self: Arc<Self>) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn a_settling_exchange_is_pending_and_wakes_readers_after_the_crossing() {
    use busbar_contract::conn::{ConnError, PieceKind};
    let rt = crate::support::worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (d, door, pairing, _) = observed_dialled();
        let (entered, release) = park(&door, Parks::Ingest);
        let settling = d.clone();
        let crossing = std::thread::spawn(move || {
            let _rt = handle.enter();
            settling.exchanged(piece(PieceKind::Completion), b"")
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let woke = Arc::new(SettledWake::default());
        let waker = std::task::Waker::from(woke.clone());
        let wrote = d.write(b"later", true, false);
        let read = d.read(&waker, &mut [0; 8]);
        let ready = d.ready(&waker);
        release.send(()).unwrap();
        let settled = crossing.join().unwrap();
        assert_eq!(wrote, Err(ConnError::Pending));
        assert_eq!(read, Err(ConnError::Pending));
        assert!(!ready, "settlement has not closed a healthy session");
        assert_eq!(settled, Ok(None));
        assert!(woke.0.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!pairing.closed());
        d.close();
    });
}

#[test]
fn a_close_during_settlement_stays_closed_after_the_crossing_returns() {
    use busbar_contract::conn::{ConnError, PieceKind};
    let rt = crate::support::worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (d, door, pairing, _) = observed_dialled();
        let (entered, release) = park(&door, Parks::Ingest);
        let settling = d.clone();
        let crossing = std::thread::spawn(move || {
            let _rt = handle.enter();
            settling.exchanged(piece(PieceKind::Completion), b"")
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let woke = Arc::new(SettledWake::default());
        let waker = std::task::Waker::from(woke.clone());
        let _ = d.ready(&waker);
        d.close();
        release.send(()).unwrap();
        assert_eq!(crossing.join().unwrap(), Err(ConnError::Closed));
        assert!(woke.0.load(std::sync::atomic::Ordering::SeqCst));
        assert!(pairing.closed());
        assert_eq!(d.write(b"late", false, false), Err(ConnError::Closed));
        assert_eq!(d.read(&waker, &mut [0; 8]), Err(ConnError::Closed));
    });
}

struct LineGate {
    gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    pairing: Mutex<std::sync::Weak<super::Pairing>>,
}

impl super::LegSink for LineGate {
    fn line(&self, _: super::Across, _: Instant) {
        let gate = self.gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
    }

    fn close(&self) {}

    fn pairing(&self) -> Option<Arc<super::Pairing>> {
        self.pairing.lock().unwrap().upgrade()
    }
}

/// Release even if an inspector or its observation panics. Assertions follow release/join.
struct Unpark(std::sync::mpsc::Sender<()>);

impl Drop for Unpark {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct PortWake(tokio::sync::mpsc::UnboundedSender<()>);

struct RetryWrite {
    dialled: Arc<crate::dialled::Dialled>,
    result: Mutex<Option<Result<usize, busbar_contract::conn::ConnError>>>,
}

impl std::task::Wake for RetryWrite {
    fn wake(self: Arc<Self>) {
        *self.result.lock().unwrap() = Some(self.dialled.write(b"next-", false, false));
    }
}

#[test]
fn a_woken_writer_can_accept_bytes_as_soon_as_the_association_comes_home() {
    use busbar_contract::conn::{ConnError, PieceKind};
    let rt = crate::support::worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (d, door, pairing, at) = observed_dialled();
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((3, b"label: events\r\n".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_FIELDS;
        }
        assert!(!deliver_dialled(&d, &door, at).await);
        assert!(pairing.published().await.failure.is_none());
        let (entered, release) = park(&door, Parks::Emit);
        let unpark = Unpark(release);
        let writing = d.clone();
        let on = handle.clone();
        let first = std::thread::spawn(move || {
            let _rt = on.enter();
            writing.write(b"first", true, false)
        });
        let retry = Arc::new(RetryWrite {
            dialled: d.clone(),
            result: Mutex::new(None),
        });
        let inspecting = d.clone();
        let interest = retry.clone();
        let inspector = std::thread::spawn(move || {
            let _rt = handle.enter();
            let ready = entered.recv_timeout(Duration::from_secs(5)).map(|()| {
                let waker = std::task::Waker::from(interest);
                inspecting.ready(&waker)
            });
            drop(unpark);
            ready
        });

        let wrote = first.join().unwrap();
        let blocked = d.write(b"unaccepted", false, false);
        let publication = tokio::time::timeout(Duration::from_secs(10), pairing.published()).await;
        let ready = inspector.join().unwrap();
        let accepted = retry.result.lock().unwrap().take();
        assert!(publication.unwrap().failure.is_none());
        assert_eq!(
            ready,
            Ok(false),
            "the actual Emit was out when interest was registered"
        );
        assert_eq!(wrote, Ok(5));
        assert_eq!(
            blocked,
            Err(ConnError::Pending),
            "one accepted write keeps bounded source admission"
        );
        assert_eq!(
            accepted,
            Some(Ok(5)),
            "publication makes write ownership available before waking"
        );
        let final_part = d.write(b"tail", true, false);
        let publication = pairing.published().await;
        d.close();
        assert_eq!(final_part, Ok(4));
        assert!(publication.failure.is_none());
        assert_eq!(
            door.st.lock().unwrap().emitted,
            vec![b"first".to_vec(), b"next-tail".to_vec()]
        );
    });
}

impl std::task::Wake for PortWake {
    fn wake(self: Arc<Self>) {
        let _ = self.0.send(());
    }
}

#[test]
fn a_pending_final_write_never_overwrites_another_writers_accepted_part() {
    use busbar_contract::conn::{ConnError, PieceKind};
    let rt = crate::support::worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (d, door, pairing, at) = observed_dialled();
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((3, b"label: events\r\n".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_FIELDS;
        }
        assert!(!deliver_dialled(&d, &door, at).await);
        assert!(pairing.published().await.failure.is_none());
        assert_eq!(d.write(b"accepted-", false, false), Ok(9));
        let (wake_tx, mut wake_rx) = tokio::sync::mpsc::unbounded_channel();
        let waker = std::task::Waker::from(Arc::new(PortWake(wake_tx)));
        assert!(!d.ready(&waker));
        let (entered, release) = park(&door, Parks::Ingest);
        let unpark = Unpark(release);
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(&check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 2), at)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), wake_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let driving = d.clone();
        let drive = std::thread::spawn(move || {
            let _rt = handle.enter();
            driving.ready(&waker)
        });
        let entered = entered.recv_timeout(Duration::from_secs(5));
        let other = d.clone();
        let result = Arc::new(Mutex::new(None));
        let observed = result.clone();
        crate::dialled::after_next_write_take(move || {
            let writing = std::thread::spawn(move || other.write(b"middle-", false, false));
            *observed.lock().unwrap() = Some(writing.join().unwrap());
        });
        let final_part = d.write(b"tail", true, false);
        drop(unpark);
        let driven = drive.join();
        assert!(
            entered.is_ok(),
            "the ordinary crossing must own the real framing"
        );
        driven.unwrap();
        assert!(pairing.published().await.failure.is_none());
        let concurrent = result.lock().unwrap().take().unwrap();
        assert_eq!(final_part, Err(ConnError::Pending));
        assert_eq!(
            concurrent,
            Err(ConnError::Pending),
            "the first final write owns its prefix"
        );
        assert_eq!(d.write(b"middle-", false, false), Ok(7));
        assert_eq!(d.write(b"tail", true, false), Ok(4));
        assert_eq!(
            d.write(b"unaccepted", false, false),
            Err(ConnError::Pending)
        );
        let publication = pairing.published().await;
        d.close();
        assert!(publication.failure.is_none());
        assert_eq!(
            door.st.lock().unwrap().emitted,
            vec![b"accepted-middle-tail".to_vec()]
        );
    });
}

#[test]
fn a_read_cannot_overtake_the_older_channel_message_a_wait_is_publishing() {
    use busbar_contract::conn::{ConnError, PieceKind};
    let rt = crate::support::worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let caller = Arc::new(LineGate {
            gate: Mutex::new(None),
            pairing: Mutex::new(std::sync::Weak::new()),
        });
        let pairing = super::Pairing::new(caller.clone(), p("127.0.0.1:3478"));
        *caller.pairing.lock().unwrap() = Arc::downgrade(&pairing);
        pairing.sort(
            super::Leg::Caller,
            vec![got(10, b"kind: audio\r\n", true)],
            Instant::now(),
        );
        let (d, door, _, at) = observed_dialled_for(pairing.clone());
        {
            let mut st = door.st.lock().unwrap();
            st.pieces.push((20, b"kind: audio\r\n".to_vec()));
            st.piece_flags = busbar_contract::abi::transport::PIECE_FIELDS;
        }
        d.exchanged(piece(PieceKind::Completion), b"").unwrap();
        let (wake_tx, mut wake_rx) = tokio::sync::mpsc::unbounded_channel();
        let waker = std::task::Waker::from(Arc::new(PortWake(wake_tx)));
        assert!(!d.ready(&waker), "register the port's pending read");
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        {
            let mut st = door.st.lock().unwrap();
            st.pieces
                .extend([(3, b"older".to_vec()), (20, b"line".to_vec())]);
        }
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, held_back) = std::sync::mpsc::channel();
        let unpark = Unpark(release);
        *caller.gate.lock().unwrap() = Some((entered_tx, held_back));
        peer.send_to(&check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1), at)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), wake_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let waiting = d.clone();
        let wait_waker = waker.clone();
        let on = handle.clone();
        let wait = std::thread::spawn(move || {
            let _rt = on.enter();
            waiting.ready(&wait_waker)
        });
        let inspecting = d.clone();
        let scripted = door.clone();
        let read_waker = waker.clone();

        let peer = peer.into_std().unwrap();
        let inspector = std::thread::spawn(move || {
            let _rt = handle.enter();
            let observed = entered.recv_timeout(Duration::from_secs(5)).map(|()| {
                let ready = inspecting.ready(&read_waker);
                let mut prefix = [0; 2];
                let first = inspecting.read(&read_waker, &mut prefix);
                let prefix = first
                    .as_ref()
                    .ok()
                    .map(|piece| prefix[..piece.len].to_vec());
                let mut buf = [0; 16];
                let second = inspecting.read(&read_waker, &mut buf);
                let suffix = second.as_ref().ok().map(|piece| buf[..piece.len].to_vec());
                scripted
                    .st
                    .lock()
                    .unwrap()
                    .pieces
                    .push((3, b"newer".to_vec()));
                let sent = peer.send_to(&check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 2), at);
                let later = inspecting.read(&read_waker, &mut buf);
                let newer = later.as_ref().ok().map(|piece| buf[..piece.len].to_vec());
                (ready, first, prefix, second, suffix, sent, later, newer)
            });
            drop(unpark);
            (observed, peer)
        });

        let waited = wait.join();
        let publication = tokio::time::timeout(Duration::from_secs(10), pairing.published()).await;
        let (observed, _peer) = inspector.join().unwrap();
        let observed = observed.unwrap();
        let (ready, first, prefix, second, suffix, sent, later, newer) = observed;
        assert!(waited.unwrap());
        assert!(publication.unwrap().failure.is_none());
        assert!(
            ready,
            "the older CHANNEL is readable while LINE delivery is parked"
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.kind, PieceKind::Body);
        assert_eq!(second.kind, PieceKind::Body);
        assert!(!first.end);
        assert!(second.end);
        assert_eq!(prefix.unwrap(), b"ol");
        assert_eq!(suffix.unwrap(), b"der");
        assert_eq!(
            sent.unwrap(),
            check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 2).len()
        );
        let mut messages = vec![b"older".to_vec()];
        match later {
            Ok(piece) => {
                assert_eq!(piece.kind, PieceKind::Body);
                assert!(piece.end);
                messages.push(newer.unwrap());
            }
            Err(error) => assert_eq!(error, ConnError::Pending),
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = [0; 16];
            while messages.len() < 2 {
                let piece = futures::future::poll_fn(|cx| match d.read(cx.waker(), &mut buf) {
                    Err(ConnError::Pending) => std::task::Poll::Pending,
                    answer => std::task::Poll::Ready(answer),
                })
                .await
                .unwrap();
                assert_eq!(piece.kind, PieceKind::Body);
                assert!(piece.end);
                messages.push(buf[..piece.len].to_vec());
            }
        })
        .await
        .expect("the newer CHANNEL follows the already consumed older message");
        assert!(pairing.published().await.failure.is_none());
        let extra = d.read(std::task::Waker::noop(), &mut [0; 16]);
        let publication = pairing.published().await;
        d.close();
        assert!(publication.failure.is_none());
        assert_eq!(messages, vec![b"older".to_vec(), b"newer".to_vec()]);
        assert_eq!(
            extra,
            Err(ConnError::Pending),
            "neither message is replayed after publication"
        );
    });
}

/// Arm `door` to park its next `call` crossing: told when it is in, held until released.
fn park(
    door: &Scripted,
    call: Parks,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (entered, in_) = std::sync::mpsc::channel();
    let (out, release) = std::sync::mpsc::channel();
    *door.park.lock().unwrap() = Some(Park {
        call,
        entered,
        release,
    });
    (in_, out)
}

/// §11.13 M1: no plugin code runs under the port's lock. While `parked` holds association a's
fn others_complete_while_parked(
    call: Parks,
    arm: impl FnOnce(&Arc<Scripted>) -> Arc<Scripted>,
    parked: impl FnOnce(&super::PortAssociations, u64) + Send + 'static,
) {
    let (da, db) = (
        scripted(Knobs::default()),
        scripted_as(Knobs::default(), (B_UFRAG, B_PWD)),
    );
    let port = Arc::new(super::PortAssociations::new());
    let a = port.add(settled(da.clone())).unwrap();
    let b = port.add(settled(db.clone())).unwrap();
    let pb = p("203.0.113.2:2000");
    let none = |_: SocketAddr, _: &[u8]| {};
    let now = Instant::now();
    let answered = port.datagram(pb, &check(B_UFRAG, FAR_UFRAG, B_PWD, 2), now, &none);
    assert!(matches!(answered.as_slice(), [(id, Ok(_))] if *id == b));

    let (entered, release) = park(&arm(&da), call);
    let holder = {
        let port = Arc::clone(&port);
        std::thread::spawn(move || parked(&port, a))
    };
    entered
        .recv_timeout(Duration::from_secs(5))
        .expect("the parked crossing is in");

    let (done, finished) = std::sync::mpsc::channel();
    let other = {
        let port = Arc::clone(&port);
        std::thread::spawn(move || {
            let none = |_: SocketAddr, _: &[u8]| {};
            let now = Instant::now();
            let (ok, _) = port.emit(b, 1, b"m", true, false, now, &none);
            let _ = done.send(("emit", ok));
            let c = port.add(settled(scripted_as(Knobs::default(), (C_UFRAG, C_PWD))));
            let _ = done.send(("admit", c.is_ok()));
            let routed = port.datagram(pb, &[0x80, 0x6f, 0, 1], now, &none);
            let _ = done.send((
                "datagram",
                matches!(routed.as_slice(), [(id, _)] if *id == b),
            ));
            port.remove(b);
            let _ = done.send(("teardown", true));
        })
    };
    let mut seen = Vec::new();
    while let Ok(step) = finished.recv_timeout(Duration::from_secs(2)) {
        seen.push(step);
        if seen.len() == 4 {
            break;
        }
    }
    let _ = release.send(());
    holder.join().unwrap();
    other.join().unwrap();
    assert_eq!(
        seen,
        [
            ("emit", true),
            ("admit", true),
            ("datagram", true),
            ("teardown", true)
        ],
        "another association's callers waited on a framer parked in {call:?}"
    );
}

#[test]
fn a_framer_parked_in_ingest_holds_no_other_caller_of_its_port() {
    others_complete_while_parked(Parks::Ingest, Arc::clone, |port, a| {
        let pa = p("203.0.113.1:1000");
        let none = |_: SocketAddr, _: &[u8]| {};
        let check = check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1);
        let _ = port.datagram(pa, &check, Instant::now(), &none);
        let _ = a;
    });
}

#[test]
fn a_framer_parked_in_emit_holds_no_other_caller_of_its_port() {
    others_complete_while_parked(Parks::Emit, Arc::clone, |port, a| {
        let none = |_: SocketAddr, _: &[u8]| {};
        let _ = port.emit(a, 1, b"m", true, false, Instant::now(), &none);
    });
}

/// A refused admission's framing finishes as it is handed back: never under the port's lock.
#[test]
fn a_refused_framing_parked_in_finish_holds_no_other_caller_of_its_port() {
    let dup = scripted(Knobs::default());
    let refused = settled(dup.clone());
    others_complete_while_parked(
        Parks::Finish,
        move |_| dup,
        move |port, _| {
            assert_eq!(port.add(refused), Err(super::NotAdded::UserTaken));
        },
    );
}

/// What a caller owes an association out on another caller's crossing does not wait for it: it is
#[test]
fn what_an_association_out_on_a_crossing_is_owed_its_holder_runs_in_order() {
    let da = scripted(Knobs::default());
    let port = Arc::new(super::PortAssociations::new());
    let a = port.add(settled(da.clone())).unwrap();
    let none = |_: SocketAddr, _: &[u8]| {};
    let parked = |port: &Arc<super::PortAssociations>| {
        let (entered, release) = park(&da, Parks::Emit);
        let holder = {
            let port = Arc::clone(port);
            std::thread::spawn(move || {
                let none = |_: SocketAddr, _: &[u8]| {};
                port.emit(a, 1, b"first", true, false, Instant::now(), &none)
            })
        };
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the parked crossing is in");
        (holder, release)
    };

    let (holder, release) = parked(&port);
    let before = lanes(&da).len();
    let check = check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1);
    let pa = p("203.0.113.1:1000");
    assert!(
        port.datagram(pa, &check, Instant::now(), &none).is_empty(),
        "queued for the holder"
    );
    let (ok, ran) = port.emit(a, 1, b"second", true, false, Instant::now(), &none);
    assert!(ok && ran.is_empty(), "queued for the holder");
    let _ = release.send(());
    let (ok, answered) = holder.join().unwrap();
    assert!(ok);
    assert!(
        matches!(
            answered.as_slice(),
            [(first, Ok(_)), (datagram, Ok(_)), (second, Ok(_))]
                if *first == a && *datagram == a && *second == a
        ),
        "both Emits and the intervening datagram retain their answers in order"
    );
    assert_eq!(
        lanes(&da)[before..],
        [0, LANE_CLEAR, 0],
        "the parked emit, then what was owed, in order"
    );
    assert_eq!(port.len(), 1, "put back");

    let (holder, release) = parked(&port);
    let before = lanes(&da).len();
    port.remove(a);
    let _ = port.emit(a, 1, b"late", true, false, Instant::now(), &none);
    let _ = release.send(());
    let _ = holder.join().unwrap();
    assert_eq!(lanes(&da).len(), before + 1, "only the parked call crossed");
    assert!(port.is_empty(), "removed while out, finished by its holder");
}

/// Host registration is completed before the association becomes available to port callers.
#[test]
fn association_admission_publishes_host_routing_before_unlocking() {
    let port = super::PortAssociations::new();
    let published = std::cell::Cell::new(None);
    let id = port
        .add_with(settled(scripted(Knobs::default())), |id| {
            assert!(matches!(
                port.assocs.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            published.set(Some(id));
        })
        .unwrap();
    assert_eq!(published.get(), Some(id));
    assert_eq!(port.len(), 1);
    let (accepted, _) = port.emit(
        id,
        1,
        b"after registration",
        true,
        false,
        Instant::now(),
        &|_, _| {},
    );
    assert!(accepted);
    port.remove(id);
}

/// Even an unwinding host publisher must finish its unregistered framing outside the map lock.
#[test]
fn unwinding_association_publication_finishes_after_unlocking() {
    let port = Arc::new(super::PortAssociations::new());
    let door = scripted(Knobs::default());
    let framing = settled(Arc::clone(&door));
    let (entered, release) = park(&door, Parks::Finish);
    let owner = {
        let port = Arc::clone(&port);
        std::thread::spawn(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = port.add_with(framing, |_| panic!("publisher unwinds"));
            }))
        })
    };
    let reached_finish = entered.recv_timeout(Duration::from_secs(5)).is_ok();
    let unlocked = match port.assocs.try_lock() {
        Ok(_) | Err(std::sync::TryLockError::Poisoned(_)) => true,
        Err(std::sync::TryLockError::WouldBlock) => false,
    };
    let _ = release.send(());
    let unwound = owner.join().unwrap().is_err();
    assert!(reached_finish && unlocked && unwound);
    assert!(port.is_empty(), "a failed publisher exposes no association");
}

#[test]
fn datagram_finish_lends_the_current_lane_and_retires_once() {
    for connected in [false, true] {
        let mut rig = rig(Knobs::default());
        if connected {
            rig.first_check();
            rig.pump(200);
            assert!(rig.host.presented());
        }
        let bound = rig.host.bound_path();
        let verified = rig.host.verified();
        let door = Arc::clone(&rig.door);
        if connected {
            door.st
                .lock()
                .unwrap()
                .routes
                .push((bound, LANE_SECURED, b"terminal".to_vec()));
        }
        drop(rig.host);
        let st = door.st.lock().unwrap();
        assert_eq!(st.finished.len(), 1);
        let lane = st.finished[0]
            .as_ref()
            .expect("Finish receives a datagram lane");
        assert_eq!(lane.size as usize, std::mem::size_of::<DatagramLane>());
        assert_eq!(lane.lane, 0);
        assert_eq!(lane.path, 0);
        assert_eq!(lane.bound, bound);
        assert_eq!(lane.verified, verified);
        assert_eq!(lane.local, rig.host_addr.to_string());
        assert!(lane.routes_cap > 0);
        assert!(
            st.routes.is_empty(),
            "the final route fits the lent output buffers"
        );
    }
}
