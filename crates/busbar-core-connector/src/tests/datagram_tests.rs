// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM DRIVER, end to end over a real handshake: a scripted datagram framer behind the
//! [`FramerDoor`] seam (an ICE-lite agent: it answers checks, asks to bind the path a check came
//! from, and hands secured plaintext up on stream `1`), driven by [`DatagramFraming`] over the
//! host's dtls engine, against a far end that is a second dtls engine plus the test acting as its
//! full ICE agent.
//!
//! What is proven, each with its RED arm:
//! * the keying-material item reaches the framer exactly ONCE, on a call whose lane says the far end
//!   is verified, and its bytes are what the far end's own exporter produced;
//! * a datagram from a source that sent no verified check never reaches the framer, and no path
//!   number is told for it;
//! * a rebind to a path that never answered core's probe is not applied, and a clear route to a
//!   heard but unbound path that is not a check's answer is dropped and counted;
//! * a framer answer that breaks the datagram lane's rules is a FAULT before any byte is used;
//! * DIALLING: every advertised candidate meets the destination judge before any byte goes there;
//!   a refused one is never told to the framer and never sent a byte, and an admitted one binds
//!   only once core's probe is answered from it (RED arms: unanswered, or answered from another
//!   source, it never binds).

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
/// `key` (the receiver's password when honest).
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
/// (the answering agent's own password).
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
}

#[derive(Default)]
struct St {
    seen: Vec<Seen>,
    addrs: HashMap<u32, String>,
    remote: Option<(String, String, Vec<u8>)>,
    secured: Vec<Vec<u8>>,
    routes: Vec<(u32, u32, Vec<u8>)>,
    pieces: Vec<(u64, Vec<u8>)>,
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
                flags: PIECE_END_OF_FRAME,
                ..std::mem::zeroed()
            });
        }
        n += 1;
    }
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
    /// nothing is bound.
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
                match lane.lane {
                    LANE_RENDEZVOUS => {
                        // "ufrag pwd fingerprint-hex": the far end's terms.
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
            Call::Finish(..) => {}
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
/// itself.
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
    let y = r
        .host
        .rendezvous(description.as_bytes(), r.now)
        .expect("the rendezvous settles terms");
    r.got
        .extend(y.pieces.into_iter().map(|g| (g.stream, g.bytes)));
    r
}

impl Rig {
    fn deliver(&mut self, from: SocketAddr, d: &[u8]) {
        let y = self
            .host
            .datagram(from, d, self.now)
            .expect("the host takes it");
        self.got
            .extend(y.pieces.into_iter().map(|g| (g.stream, g.bytes)));
    }

    /// The far end's first check, then `rounds` of the clock with every datagram delivered.
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.now += Duration::from_millis(10);
            self.far.a.handle_timeout(self.now);
            let y = self.host.timeout(self.now).expect("the host's clock");
            self.got
                .extend(y.pieces.into_iter().map(|g| (g.stream, g.bytes)));
            while let Some((to, d)) = self.host.poll_send() {
                if to != self.far.addr {
                    self.elsewhere.push((to, d));
                    continue;
                }
                let v = self.far.a.ingest(self.host_addr, &d, self.now);
                if v == Verdict::Raw && is_request(&d) && !self.answers {
                    self.unanswered.push(d);
                } else if v == Verdict::Raw && is_request(&d) {
                    // The far end's ICE agent answers the host's probe under its own password.
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
    // RED arm: a host that presents the item on every call, or never, fails here.
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
    // No call before the far end was verified saw the verified bit.
    let first_verified = seen.iter().position(|s| s.verified).expect("verified once");
    assert!(seen[..first_verified].iter().all(|s| s.keying.is_none()));

    // Plaintext both ways over the bound path, sealed and opened by the host's secure layer.
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
    // A check under the wrong password, and media, from a source the far end never was.
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
    // RED arm: the honest check does cross, with its path told.
    r.first_check();
    let seen = r.seen();
    assert!(seen.len() > before);
    assert!(seen
        .iter()
        .any(|s| s.told.contains(&(1, r.far.addr.to_string()))));
    // The check itself crossed on the clear lane, carrying the path number it was told under.
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
    // A verified check from a new source that never answers core's probe (the password leaked; the
    // address is not the far end's).
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
    // Core probed the new source (the round trip that would prove it), sent it the check's answer,
    // and nothing else: the clear datagram that was no answer was dropped and counted.
    assert!(r
        .elsewhere
        .iter()
        .all(|(to, d)| *to == spoof && d.len() >= 20 && (d[0..2] == [0, 1] || d[0..2] == [1, 1])));
    assert!(r.elsewhere.iter().any(|(_, d)| d[0..2] == [1, 1]));
    assert_eq!(r.host.refused_routes(), 1);
    // RED arm: once the new path answers the probe, the move applies.
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
    // The begin told the framer the host port, and no secret.
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
    // Every advertised literal was asked about; the unparsable one never reached the judge.
    let judged = r.judged.lock().unwrap().clone();
    assert!(judged.contains(&r.far.addr.to_string()), "{judged:?}");
    assert!(judged.contains(&METADATA.to_owned()), "{judged:?}");
    assert_eq!(
        r.host.refused_candidates(),
        2,
        "the metadata address and the non-address"
    );
    // RED: the refused candidate got no byte and was never told to the framer.
    assert!(
        r.elsewhere.is_empty(),
        "nothing left for any other address: {:?}",
        r.elsewhere
    );
    assert!(r
        .seen()
        .iter()
        .all(|s| s.told.iter().all(|(_, a)| a != METADATA)));
    // The admitted one binds once proven, the handshake runs and the item crosses once, verified.
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
    // The framer asked to bind it and the far end saw core's probes, but none was answered.
    assert!(!r.unanswered.is_empty(), "core probed the candidate");
    assert_eq!(r.host.bound(), None, "an unproven candidate is not bound");
    assert!(!r.host.presented());
    // Answers to every request it was sent, from ANOTHER source, prove nothing.
    let unanswered = std::mem::take(&mut r.unanswered);
    for d in &unanswered {
        r.deliver(p("192.0.2.88:6666"), &answer(d, FAR_PWD));
    }
    assert_eq!(r.host.bound(), None, "an answer from elsewhere is no proof");
    // RED arm: answered from the candidate itself, the bind applies.
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
    // The framer asks to move to any path a check comes from that is not the bound one.
    let mut r = rig(Knobs {
        dial: true,
        rebind_new: true,
        ..Knobs::default()
    });
    r.pump(200);
    assert_eq!(r.host.bound(), Some(r.far.addr));
    assert!(r.elsewhere.is_empty(), "{:?}", r.elsewhere);

    // A verified check (the far end knows the host's password) from an address the destination
    // judge refuses, never advertised as a candidate.
    let refused = p("169.254.10.20:4000");
    r.deliver(refused, &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 0x21));
    r.pump(20);
    assert!(
        r.judged.lock().unwrap().contains(&refused.to_string()),
        "the heard path met the judge"
    );
    // Were core to have probed it, the far end answering from there would prove and bind it.
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

    // RED arm: a check from an address the judge admits is probed, told, and binds once proven.
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

    // Each check finds the association its user name names.
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

    // Anything else finds the association by the path a verified check claimed.
    let (id, _) = port.datagram(pb, &[0x80, 0x6f, 0, 1], now).unwrap();
    assert_eq!(id, b);
    // RED: a user name nobody holds, and a path nobody claimed, reach no association.
    assert!(port
        .datagram(stranger, &check("nobody", FAR_UFRAG, HOST_PWD, 3), now)
        .is_none());
    assert!(port.datagram(stranger, &[0x80, 0x6f, 0, 2], now).is_none());
    // A check that names a but fails its integrity claims no path for a.
    let (id, _) = port
        .datagram(
            stranger,
            &check(HOST_UFRAG, FAR_UFRAG, "wrong-password-012345", 4),
            now,
        )
        .unwrap();
    assert_eq!(id, a);
    assert!(port.datagram(stranger, &[0x80, 0x6f, 0, 3], now).is_none());

    // A user name is one association's; one with no terms is refused.
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
    // Removed, its user name and paths go with it.
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
    // The candidate's first datagram is an answer, not a check: found by its path.
    let (got, _) = port
        .datagram(r.far.addr, &[0x80, 0x6f, 0, 1], r.now)
        .unwrap();
    assert_eq!(got, id);
    // RED: the refused candidate's address finds nothing.
    assert!(port
        .datagram(p(METADATA), &[0x80, 0x6f, 0, 1], r.now)
        .is_none());
}

#[test]
fn only_a_datagram_framer_is_driven_over_the_port() {
    let stream_framer = scripted(Knobs::default());
    // RED: a framer whose tail states no datagram framing is refused before any call crosses.
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
    // A line frame before the upstream leg named its lines is dropped, never queued.
    assert!(across.is_empty());
    assert_eq!(
        session.iter().map(|g| g.stream).collect::<Vec<_>>(),
        vec![0, 1],
        "the description and the channel's head are the session's"
    );
    // The upstream dial mirrors the caller's lines, then names the session's channels.
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
    // RED: after the session's close nothing crosses, either way.
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
    // RED: line 0 exists on both legs, yet nothing crosses while the whole set does not mirror.
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
/// `bytes`, its need 0 declared over `dg`.
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
/// no session registered, is refused before anything is bound or sent; a unit is registered once;
/// a closed session's unit is forgotten (its pairing closed once), so the key given again never
/// finds the stale leg.
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
/// close stops the bridge and closes both legs exactly once (RED: nothing crosses after it).
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
/// is attached: the pairing closes, the caller's leg with it (RED: no partial bridge survives).
/// A success answer's body is the host's: it settles the leg, which runs once attached.
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

        // RED arm: a success answer's body is the far end's description, never the reader's.
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
/// pairing closes (RED: one caller line against none upstream never half-bridges).
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

/// RED (THE DESIGN §5, datagram media: "ICE path migration rebinds only on a verified round-trip
/// check (a spoof is a RED)"): a path one accepted association already holds on a shared port stays
/// its own when ANOTHER association hears a check from it. A check proves only that its sender
/// knows that other association's password, never that it owns the source address, so a caller
/// sending its own valid checks from a spoofed source took over another caller's media.
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
    // b's own valid check, from a's address.
    let (id, y) = port
        .datagram(pa, &check(B_UFRAG, FAR_UFRAG, B_PWD, 2), now)
        .unwrap();
    assert_eq!(id, b);
    y.unwrap();
    let (id, _) = port.datagram(pa, &[0x80, 0x6f, 0, 2], now).unwrap();
    assert_eq!(id, a, "a's path is still a's");
}

/// RED (resource bounds): the paths a port routes to one association are only those it still
/// owns. An association holds at most a bounded set of heard paths; the port kept every address it
/// ever routed for the association, so valid checks from ever-new sources grew it without limit.
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

/// RED (resource bounds): the far end's description is bounded. Buffered whole until the
/// exchange's end with no cap, a far end that answered without end grew host memory without limit.
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

/// RED (resource bounds; THE DESIGN §5 "Writes are back-pressured"): a message a plugin writes in
/// parts on the upstream leg is bounded. Gathered until its end with no cap, a write that never
/// ended grew host memory without limit.
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
/// framer (or a refused framing's) in a `call` crossing on its own thread, every other caller of
/// the port completes within a bounded wait: another association's emit, an admission, a datagram
/// to another association, and a teardown. The park is released before anything is asserted, so a
/// failure never hangs.
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
/// queued, and the holder runs it, in order, before putting the association back (one crossing
/// per association at a time). Removed while out, the holder finishes it on the way back and runs
/// nothing more on it.
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
    assert!(matches!(answered.as_slice(), [(id, Ok(_))] if *id == a));
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
