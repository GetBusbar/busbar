// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM FRAMER'S SCRIPT: the transport kind's script for a framer whose tail states
//! `FRAMING_DATAGRAM` (`busbar_contract::abi::transport::datagram`). Such a framer reads the
//! host's DATAGRAM LANE on every call (`begin`, `ingest`, `emit`, `finish`, `timer`), answers no
//! stream, and is begun dialled with its opening description as a piece or accepted waiting for the
//! far end's. The stream framer script (`super::transport`) cannot drive it: its `begin` carries no
//! lane, and its `emit` becomes wire bytes. `super::transport::script_for` picks this script by the
//! tail's framing.
//!
//! The steps are driven as the host drives a datagram framer (one crossing each, over an ample sink
//! and a lane with room for routes) and every answer is judged by the lane's own rules
//! (`busbar_contract::abi::transport::check::check_datagram`) before it is read: a framer that
//! routes on a FAILED answer, names a path the lane does not allow, or states half its rendezvous
//! terms fails the script whatever else it answered. Inputs (`conformance.json`), under
//! `transport.datagram`:
//!
//! A byte input is a JSON string (its UTF-8 bytes) or `{ "hex": "<bytes>" }`.
//!
//! ```json
//! { "transport": { "datagram": {
//!     "local":       "<the host port's address the lane carries>",  /* optional, default 198.51.100.1:40000 */
//!     "certificate": "<the host's public certificate, as begin presents it>", /* optional */
//!     "locate": "refused" | "failed",           /* what locate answers: a datagram framer has no target */
//!     "encode": "refused" | "failed",           /* what encode answers */
//!     "opening": [["<name>", "<value>"], ...],  /* optional: the fields a dialled begin offers */
//!     "offer": null | { "text": true,           /* what a dialled begin yields: nothing, or ONE
//!                       "contains": ["...", ...] }   end-of-frame piece on stream 0 (a text piece
//!                                                     when "text") containing every listed string */
//!     "junk": "<bytes that are no description>", /* a rendezvous the dialled framing fails on */
//!     "rendezvous": {                           /* optional: a far end's description the ACCEPTED
//!         "description": "<bytes>",                framing answers with its own (one end-of-frame
//!         "text": true,                            piece on stream 0) and its terms */
//!         "terms": "initiates" | "answers" } } } }
//! ```
//!
//! THE PINS (M6/contract): `facts`, `ready` without a stated `ready`, `begin unopened` and `begin
//! after close` cross 0 times (the dispatcher answers those without a crossing); the eight carrier
//! ops 8; every other step exactly 1.

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome};
use busbar_contract::abi::transport::check::check_datagram;
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, DatagramLane, DatagramRoute, EncodeIn, FinishIn, FramerOut,
    FramerSink, IngestIn, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES, HANDSHAKE_NONE, LANE_RENDEZVOUS,
    PIECE_END_OF_FRAME, PIECE_TEXT, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_MORE,
};

use super::transport::{facts_line, framer_closed, framer_opened, go, loaded, locate, text, Sink};
use super::{crossings, dispatcher, input, Fold, Leg, Script, Subject, Want};
use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::{Called, Plugin};

/// Each buffer of the host's sink, and the routes the lane has room for.
const AMPLE: usize = 16 * 1024;
/// The pieces the sink has room for.
const PIECES: usize = 16;
/// The routes the lane has room for.
const ROUTES: usize = 16;
/// The host port's address when the inputs name none (a documentation address).
const LOCAL: &str = "198.51.100.1:40000";
/// The host's public certificate when the inputs name none: a framer states a digest of it and
/// reads nothing else of it.
const CERTIFICATE: &[u8] = b"the host's public certificate, DER";

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

fn abi(s: &[u8]) -> AbiStr {
    if s.is_empty() {
        return NONE;
    }
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The host's buffers (the stream script's [`Sink`], ample) and lane for one framer op.
struct Host {
    sink: Sink,
    routes: Vec<DatagramRoute>,
}

impl Host {
    fn new() -> Self {
        Self {
            sink: Sink::new(AMPLE, AMPLE, PIECES),
            routes: vec![DatagramRoute::default(); ROUTES],
        }
    }

    fn sink(&mut self) -> FramerSink {
        self.sink.raw()
    }

    /// The lane of a call carrying bytes on `lane` (`0`: none), nothing heard, bound or verified.
    fn lane(&mut self, lane: u32, local: &[u8]) -> DatagramLane {
        DatagramLane {
            size: u32::try_from(std::mem::size_of::<DatagramLane>()).unwrap_or(u32::MAX),
            lane,
            path: 0,
            bound: 0,
            path_addr: NONE,
            local_addr: abi(local),
            verified: 0,
            _reserved: 0,
            keying: std::ptr::null(),
            routes: self.routes.as_mut_ptr(),
            routes_cap: self.routes.len(),
            paths: std::ptr::null(),
            paths_len: 0,
        }
    }

    /// What one answer yielded, as one deterministic line (never a credential a framer minted):
    /// the lane's judgement, each piece's stream, flags and whether it holds every `contains`
    /// string, the routes, the end and re-call flags, and the terms' role.
    fn yielded(&self, c: &Called, o: &FramerOut, contains: &[Vec<u8>]) -> String {
        let judged = match check_datagram(c.outcome, o, &self.routes, self.routes.len() as u64) {
            Ok(()) => "ok".to_owned(),
            Err(f) => format!("{:?} at {}", f.rule, f.field),
        };
        let n = (o.yielded.pieces_len as usize).min(self.sink.pieces.len());
        let pieces: Vec<String> = self.sink.pieces[..n]
            .iter()
            .map(|p| {
                let at = usize::try_from(p.offset).unwrap_or(usize::MAX);
                let len = usize::try_from(p.len).unwrap_or(usize::MAX);
                let bytes = self
                    .sink
                    .frame
                    .get(at..at.saturating_add(len))
                    .unwrap_or_default();
                let holds = contains.iter().all(|want| {
                    !want.is_empty() && bytes.windows(want.len()).any(|w| w == want.as_slice())
                });
                format!("stream={} flags={} holds={holds}", p.stream, p.flags)
            })
            .collect();
        format!(
            "lane={judged} pieces={pieces:?} routes={} flags={} terms={}",
            o.datagram.routes_len,
            o.yielded.flags & (YIELD_ENDED | YIELD_MORE),
            o.datagram.terms.role
        )
    }
}

/// What the inputs state, read once.
struct Inputs {
    local: Vec<u8>,
    certificate: Vec<u8>,
    locate: Outcome,
    encode: Outcome,
    opening: Vec<(Vec<u8>, Vec<u8>)>,
    /// `None`: a dialled begin yields nothing; `Some((flags, contains))`: one piece.
    offer: Option<(u16, Vec<Vec<u8>>)>,
    junk: Vec<u8>,
    /// The far end's description, its answer's piece flags, and the terms' role.
    rendezvous: Option<(Vec<u8>, u16, u32)>,
}

/// `"refused"` or `"failed"`.
fn refusal(v: &serde_json::Value, what: &str) -> Outcome {
    match v.as_str() {
        Some("refused") => Outcome::Refused,
        Some("failed") => Outcome::Failed,
        _ => {
            panic!("conformance.json: transport.datagram.{what} must be \"refused\" or \"failed\"")
        }
    }
}

/// The flags of an end-of-frame piece, a text piece when `v["text"]` is true.
fn piece_flags(v: &serde_json::Value) -> u16 {
    if v["text"].as_bool().unwrap_or(false) {
        PIECE_END_OF_FRAME | PIECE_TEXT
    } else {
        PIECE_END_OF_FRAME
    }
}

impl Inputs {
    fn read(k: &serde_json::Value) -> Self {
        let g = &k["datagram"];
        assert!(
            g.is_object(),
            "conformance.json: a datagram framer's inputs are `transport.datagram`"
        );
        let or = |v: &serde_json::Value, what: &str, default: &[u8]| {
            if v.is_null() {
                default.to_vec()
            } else {
                text(v, what)
            }
        };
        let opening = g["opening"]
            .as_array()
            .map(|fs| {
                fs.iter()
                    .map(|f| {
                        (
                            text(&f[0], "datagram.opening name"),
                            text(&f[1], "datagram.opening value"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let offer = match &g["offer"] {
            serde_json::Value::Null => None,
            o => Some((
                piece_flags(o),
                o["contains"]
                    .as_array()
                    .map(|c| {
                        c.iter()
                            .map(|v| text(v, "datagram.offer.contains"))
                            .collect()
                    })
                    .unwrap_or_default(),
            )),
        };
        let rendezvous = match &g["rendezvous"] {
            serde_json::Value::Null => None,
            r => Some((
                text(&r["description"], "datagram.rendezvous.description"),
                piece_flags(r),
                match r["terms"].as_str() {
                    Some("initiates") => HANDSHAKE_INITIATES,
                    Some("answers") => HANDSHAKE_ANSWERS,
                    _ => panic!(
                        "conformance.json: transport.datagram.rendezvous.terms must be \
                         \"initiates\" or \"answers\""
                    ),
                },
            )),
        };
        Self {
            local: or(&g["local"], "datagram.local", LOCAL.as_bytes()),
            certificate: or(&g["certificate"], "datagram.certificate", CERTIFICATE),
            locate: refusal(&g["locate"], "locate"),
            encode: refusal(&g["encode"], "encode"),
            opening,
            offer,
            junk: text(&g["junk"], "datagram.junk"),
            rendezvous,
        }
    }
}

/// `begin` on `side` with the host's certificate, the dialled side's opening fields and (when
/// `lane`) the lane: its line, judged against `contains`, and the framing it minted.
fn begin(
    p: &Plugin<Transport>,
    inputs: &Inputs,
    side: u32,
    lane: bool,
    contains: &[Vec<u8>],
) -> (String, u64) {
    let mut host = Host::new();
    let facts = ConnFacts {
        size: u32::try_from(std::mem::size_of::<ConnFacts>()).unwrap_or(u32::MAX),
        _reserved: 0,
        offered_name: NONE,
        agreed_protocol: NONE,
        peer_subject: NONE,
        peer_issuer: NONE,
        peer_fingerprint: NONE,
        claim: NONE,
        local_certificate: abi(&inputs.certificate),
    };
    let fields: Vec<Field> = inputs
        .opening
        .iter()
        .map(|(n, v)| Field {
            name: abi(n),
            value: abi(v),
        })
        .collect();
    let l = host.lane(0, &inputs.local);
    let mut i: BeginIn = input();
    i.side = side;
    // A datagram lane rides the host's secure layer, as the connector's does.
    i.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    i.facts = &facts;
    i.sink = host.sink();
    if side == SIDE_DIAL && !fields.is_empty() {
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
    }
    if lane {
        i.lane = &l;
    }
    let (c, o): (Called, FramerOut) = go(p, slot::BEGIN, i);
    (
        format!(
            "{} framing={} {}",
            super::called(&c),
            o.framing != 0,
            host.yielded(&c, &o, contains)
        ),
        o.framing,
    )
}

/// `ingest` of `bytes` on `lane` into `framing`: its line, judged against `contains`.
fn ingest(
    p: &Plugin<Transport>,
    inputs: &Inputs,
    framing: u64,
    lane: u32,
    bytes: &[u8],
    contains: &[Vec<u8>],
) -> String {
    let mut host = Host::new();
    let l = host.lane(lane, &inputs.local);
    let mut i: IngestIn = input();
    (i.framing, i.bytes, i.len, i.sink, i.lane) =
        (framing, bytes.as_ptr(), bytes.len(), host.sink(), &l);
    let (c, o): (Called, FramerOut) = go(p, slot::INGEST, i);
    format!("{} {}", super::called(&c), host.yielded(&c, &o, contains))
}

/// `finish` of `framing`: its line.
fn finish(p: &Plugin<Transport>, inputs: &Inputs, framing: u64) -> String {
    let mut host = Host::new();
    let l = host.lane(0, &inputs.local);
    let mut i: FinishIn = input();
    (i.framing, i.sink, i.lane) = (framing, host.sink(), &l);
    let (c, o): (Called, FramerOut) = go(p, slot::FINISH, i);
    format!("{} {}", super::called(&c), host.yielded(&c, &o, &[]))
}

/// The line of a READY answer that judged clean and yielded `pieces`, `flags` and `terms`.
fn ready_line(framing: Option<bool>, pieces: &[String], flags: u32, terms: u32) -> String {
    let minted = framing.map(|m| format!(" framing={m}")).unwrap_or_default();
    format!(
        "Ready lease=false {minted} lane=ok pieces={pieces:?} routes=0 flags={flags} terms={terms}"
    )
}

/// One end-of-frame piece on stream `0` with `flags`, holding what it must.
fn described(flags: u16) -> String {
    format!("stream=0 flags={flags} holds=true")
}

/// The datagram framer's fold.
pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let inputs = Inputs::read(s.kind_inputs("transport"));
    let settings = leg.settings(s);
    let d = dispatcher();
    let (p, facts) = loaded(s, leg, s.bind(&d, "transport"));
    let mut sc = Script::new(crossings(&p));
    let begin_dial = || begin(&p, &inputs, SIDE_DIAL, true, &[]).0;

    // ── the Statement, an op before `open`, the lifecycle, `ready`, the role it does not play ──
    let line = format!("{} datagram={}", facts_line(&p, &facts), facts.datagram);
    framer_opened(&mut sc, (s, &p, &d), &settings, line, &begin_dial);

    // ── the framer ops a datagram framer has no use for ──
    sc.judged("locate", 1, Want::Starts(starts(inputs.locate)), || {
        locate(&p, b"conformance", AMPLE).0
    });
    sc.judged("encode", 1, Want::Starts(starts(inputs.encode)), || {
        let mut host = Host::new();
        let mut e: EncodeIn = input();
        e.sink = host.sink();
        super::called(&go::<EncodeIn, FramerOut>(&p, slot::ENCODE, e).0)
    });

    // ── a datagram framer reads its lane ──
    sc.judged("begin without a lane", 1, Want::Starts("Failed "), || {
        begin(&p, &inputs, SIDE_DIAL, false, &[]).0
    });

    // ── dialled over a lane: its opening, at once; a rendezvous that is no description fails the
    //    framing, which is then forgotten ──
    let offered: Vec<Vec<u8>> = inputs
        .offer
        .as_ref()
        .map(|(_, c)| c.clone())
        .unwrap_or_default();
    let pieces: Vec<String> = inputs
        .offer
        .as_ref()
        .map(|(flags, _)| vec![described(*flags)])
        .unwrap_or_default();
    let want = Want::Is(ready_line(Some(true), &pieces, 0, HANDSHAKE_NONE));
    let dialled = sc.step_judged("begin dial", 1, want, || {
        begin(&p, &inputs, SIDE_DIAL, true, &offered)
    });
    for step in ["rendezvous junk", "rendezvous after failure"] {
        sc.judged(step, 1, Want::Starts("Failed "), || {
            ingest(&p, &inputs, dialled, LANE_RENDEZVOUS, &inputs.junk, &[])
        });
    }

    // ── accepted: it waits for the far end's description, answers it when the inputs give one,
    //    and ends when finished ──
    let want = Want::Is(ready_line(Some(true), &[], 0, HANDSHAKE_NONE));
    let accepted = sc.step_judged("begin accept", 1, want, || {
        begin(&p, &inputs, SIDE_ACCEPT, true, &[])
    });
    if let Some((description, flags, role)) = &inputs.rendezvous {
        let want = Want::Is(ready_line(None, &[described(*flags)], 0, *role));
        sc.judged("rendezvous", 1, want, || {
            ingest(&p, &inputs, accepted, LANE_RENDEZVOUS, description, &[])
        });
    }
    let want = Want::Is(ready_line(None, &[], YIELD_ENDED, HANDSHAKE_NONE));
    sc.judged("finish", 1, want, || finish(&p, &inputs, accepted));
    sc.judged("finish again", 1, Want::Starts("Failed "), || {
        finish(&p, &inputs, accepted)
    });
    sc.judged("ingest on no framing", 1, Want::Starts("Failed "), || {
        ingest(&p, &inputs, u64::MAX, LANE_RENDEZVOUS, &inputs.junk, &[])
    });

    // ── the rest of the lifecycle; a closed instance serves nothing ──
    framer_closed(&mut sc, &p, &settings, &begin_dial);
    sc.fold()
}

/// The start of a refusal's line.
fn starts(o: Outcome) -> &'static str {
    if o == Outcome::Refused {
        "Refused "
    } else {
        "Failed "
    }
}

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_datagram_tests.rs"]
mod tests;
