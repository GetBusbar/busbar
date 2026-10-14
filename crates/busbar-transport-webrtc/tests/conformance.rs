// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FRAMER, BOTH DOORS, ONE TABLE** — the `webrtc` framer compiled in (`linked::door`, the
//! `linked` row) and dropped in (this crate's `cdylib` with its `dropped-in` door, `busbar_plugin_door`),
//! each admitted by the ONE loader against the same Statement rendering and bound to a dispatcher
//! of its own (Part 2 #2: a plugin is a plugin; THE DESIGN §11.4: compiled in or dropped in, the
//! same table). The pattern is `plugin-loader`'s export both-ways proof
//! (`src/tests/export_conformance_tests.rs`): one script, two doors, equal transcripts.
//!
//! The published suite's transport script drives a STREAM framer (its `begin` carries no lane, its
//! `emit` becomes wire bytes); a DATAGRAM framer's every call reads its lane, so the script here is
//! the datagram one: the Statement's tail, the lifecycle, the carrier ops it does not play, the
//! framer ops it refuses, a `begin` without a lane refused, a dialled `begin` over a lane answering
//! its session description, a rendezvous that is no description failing the framing, an accepted
//! framing finished, and the instance closed.
//!
//! THE RED ARM, kept: the dropped-in library admitted against a Statement rendering that is not its
//! own is refused, so the equality the witness asserts is between two admitted doors.

use busbar_contract::abi::mechanism::call::{AbiStr, Field};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, DatagramLane, DatagramRoute, EncodeIn, FinishIn, FramePiece,
    FramerOut, FramerSink, IngestIn, ListenIn, ListenOut, LocateIn, LocateOut, LANE_RENDEZVOUS,
    PIECE_END_OF_FRAME, PIECE_TEXT, ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_MORE,
};
use busbar_plugin_loader::conformance::{self as conf, Leg, Subject};
use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
use busbar_plugin_loader::dispatch::{load_dropped, Frame, InFrame, LinkedRow, OutFrame, Plugin};

/// The crate whose cdylib is the dropped-in door.
const CDYLIB: &str = "busbar_transport_webrtc";
/// The host port's address, the one candidate the framer advertises.
const LOCAL: &str = "198.51.100.1:40000";
/// The host's public certificate (the framer states its SHA-256; nothing else reads it).
const CERT: &[u8] = b"the host's public certificate, DER";

fn subject() -> Subject {
    Subject::new(busbar_transport_webrtc::linked::door, CDYLIB, "{}")
}

const fn abi(s: &[u8]) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The host's buffers for one framer op.
struct Host {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    routes: Vec<DatagramRoute>,
}

impl Host {
    fn new() -> Self {
        let piece = FramePiece {
            stream: 0,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            _reserved: 0,
            flags: 0,
            retry_after_secs: 0,
        };
        Self {
            wire: vec![0; 16 * 1024],
            frame: vec![0; 16 * 1024],
            pieces: vec![piece; 16],
            routes: vec![DatagramRoute::default(); 16],
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// The lane of a call ingesting on `lane` (`0`: nothing), nothing bound or verified yet.
    fn lane(&mut self, lane: u32) -> DatagramLane {
        DatagramLane {
            size: std::mem::size_of::<DatagramLane>() as u32,
            lane,
            path: 0,
            bound: 0,
            path_addr: NONE,
            local_addr: abi(LOCAL.as_bytes()),
            verified: 0,
            _reserved: 0,
            keying: std::ptr::null(),
            routes: self.routes.as_mut_ptr(),
            routes_cap: self.routes.len(),
            paths: std::ptr::null(),
            paths_len: 0,
        }
    }

    /// What the last answer yielded, as one deterministic line: the pieces (stream, flags, and for
    /// the description the facts a host reads of it), never the random credentials.
    fn yielded(&self, o: &FramerOut) -> String {
        let n = (o.yielded.pieces_len as usize).min(self.pieces.len());
        let pieces: Vec<String> = self.pieces[..n]
            .iter()
            .map(|p| {
                let at = p.offset as usize;
                let bytes = &self.frame[at..at + p.len as usize];
                let text = String::from_utf8_lossy(bytes);
                let described = p.stream == 0
                    && text.starts_with("v=0")
                    && text.contains("a=fingerprint:sha-256 ")
                    && text.contains("198.51.100.1 40000 typ host")
                    && text.contains("m=application");
                format!(
                    "stream={} flags={} described={described}",
                    p.stream, p.flags
                )
            })
            .collect();
        format!(
            "pieces={pieces:?} routes={} flags={}",
            o.datagram.routes_len,
            o.yielded.flags & (YIELD_ENDED | YIELD_MORE)
        )
    }
}

fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (String, O) {
    let mut f = Frame::new(i, conf::output::<O>());
    let c = p.call(s, &mut f);
    (conf::called(&c), f.out)
}

/// `begin` on `side`, with the host's certificate and (when `lane`) a lane: its line and token.
fn begin(p: &Plugin<Transport>, side: u32, lane: bool) -> (String, u64) {
    let mut host = Host::new();
    let facts = ConnFacts {
        size: std::mem::size_of::<ConnFacts>() as u32,
        _reserved: 0,
        offered_name: NONE,
        agreed_protocol: NONE,
        peer_subject: NONE,
        peer_issuer: NONE,
        peer_fingerprint: NONE,
        claim: NONE,
        local_certificate: abi(CERT),
    };
    let fields = [Field {
        name: abi(b"channel"),
        value: abi(b"events"),
    }];
    let l = host.lane(0);
    let mut i: BeginIn = conf::input();
    i.side = side;
    i.facts = &facts;
    i.sink = host.sink();
    if side == SIDE_DIAL {
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
    }
    if lane {
        i.lane = &l;
    }
    let (called, o): (String, FramerOut) = go(p, slot::BEGIN, i);
    (
        format!("{called} framing={} {}", o.framing != 0, host.yielded(&o)),
        o.framing,
    )
}

/// One leg's transcript.
fn fold(s: &Subject, leg: Leg) -> Vec<String> {
    let d = conf::dispatcher();
    let p = conf::load::<Transport>(s, leg, s.bind(&d, "webrtc")).expect("the door loads");
    let facts = p
        .context::<TransportFacts>()
        .cloned()
        .expect("a transport states its tail");
    let mut t = vec![format!(
        "role={} claims={:?} composes_over={:?}",
        facts.role, facts.claims, facts.composes_over
    )];
    let settings = s.settings();
    t.push(format!(
        "validate {}",
        conf::called(&conf::validate(&p, &settings))
    ));
    t.push(format!("open {}", conf::called(&conf::open(&p, &settings))));

    // The role it does not play, and the framer ops it has no use for.
    t.push(format!(
        "listen {}",
        go::<ListenIn, ListenOut>(&p, slot::LISTEN, conf::input()).0
    ));
    t.push(format!(
        "locate {}",
        go::<LocateIn, LocateOut>(&p, slot::LOCATE, conf::input()).0
    ));
    let mut host = Host::new();
    let mut e: EncodeIn = conf::input();
    e.sink = host.sink();
    t.push(format!(
        "encode {}",
        go::<EncodeIn, FramerOut>(&p, slot::ENCODE, e).0
    ));

    // A datagram framer reads its lane.
    t.push(format!(
        "begin without a lane {}",
        begin(&p, SIDE_DIAL, false).0
    ));

    // Dialled over a lane: the offer, at once, on stream 0.
    let (line, token) = begin(&p, SIDE_DIAL, true);
    t.push(format!("begin dial {line}"));

    // A rendezvous that is no description fails the framing, which is then forgotten.
    let mut host = Host::new();
    let junk = b"not a session description";
    for step in ["rendezvous junk", "rendezvous after failure"] {
        let l = host.lane(LANE_RENDEZVOUS);
        let mut i: IngestIn = conf::input();
        (i.framing, i.bytes, i.len, i.sink, i.lane) =
            (token, junk.as_ptr(), junk.len(), host.sink(), &l);
        t.push(format!(
            "{step} {}",
            go::<IngestIn, FramerOut>(&p, slot::INGEST, i).0
        ));
    }

    // Accepted: it waits for the offer; finished, it ends, and is forgotten.
    let (line, token) = begin(&p, SIDE_ACCEPT, true);
    t.push(format!("begin accept {line}"));
    for step in ["finish", "finish again"] {
        let mut host = Host::new();
        let l = host.lane(0);
        let mut i: FinishIn = conf::input();
        (i.framing, i.sink, i.lane) = (token, host.sink(), &l);
        let (called, o): (String, FramerOut) = go(&p, slot::FINISH, i);
        t.push(format!("{step} {called} {}", host.yielded(&o)));
    }
    t.push(format!("close {}", conf::called(&conf::close(&p))));
    t
}

/// What the contract requires of each line, by its start.
fn expected() -> Vec<String> {
    let piece = PIECE_END_OF_FRAME | PIECE_TEXT;
    vec![
        format!("role={ROLE_FRAMER} claims=[\"webrtc\"] composes_over=[]"),
        "validate Ready lease=false ".into(),
        "open Ready lease=false ".into(),
        "listen Refused".into(),
        "locate Failed".into(),
        "encode Failed".into(),
        "begin without a lane Failed lease=false begin: a datagram framer reads its lane".into(),
        format!(
            "begin dial Ready lease=false  framing=true pieces=[\"stream=0 flags={piece} described=true\"] routes=0 flags=0"
        ),
        "rendezvous junk Failed".into(),
        "rendezvous after failure Failed lease=false no such framing".into(),
        "begin accept Ready lease=false  framing=true pieces=[] routes=0 flags=0".into(),
        format!("finish Ready lease=false  pieces=[] routes=0 flags={YIELD_ENDED}"),
        "finish again Failed lease=false finish: no such framing".into(),
        "close Ready lease=false ".into(),
    ]
}

/// THE WITNESS: the dropped-in library states exactly the linked door's Statement, and the two
/// doors run the script to the same transcript, the one the contract requires.
#[test]
fn the_linked_and_the_dropped_in_framer_are_one_plugin_on_one_table() {
    let s = subject();
    let linked_row = LinkedRow::of(s.door).expect("the linked door is admitted");
    assert_eq!(
        linked_row.statement,
        s.stated(),
        "the dropped-in library states exactly the linked door's Statement"
    );
    let linked = fold(&s, Leg::Linked);
    let dropped = fold(&s, Leg::Dropped);
    assert_eq!(linked, dropped, "the two doors part");
    let want = expected();
    assert_eq!(linked.len(), want.len(), "{linked:#?}");
    for (got, want) in linked.iter().zip(&want) {
        assert!(got.starts_with(want.as_str()), "got:  {got}\nwant: {want}…");
    }
}

/// THE RED ARM: the dropped-in library admitted against a rendering that is not its own (one byte
/// of its Statement moved) is refused; its own is admitted.
#[test]
fn red_arm_a_dropped_in_library_stating_another_statement_is_refused() {
    let s = subject();
    let d = conf::dispatcher();
    let own = s.stated();
    let mut other = own.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    assert!(
        load_dropped::<Transport>(&s.cdylib(), &other, s.bind(&d, "webrtc-other")).is_err(),
        "a library admitted against another Statement must be refused"
    );
    assert!(load_dropped::<Transport>(&s.cdylib(), &own, s.bind(&d, "webrtc-own")).is_ok());
    assert!(conf::load::<Transport>(&s, Leg::Linked, s.bind(&d, "webrtc-linked")).is_ok());
}
