// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::plugin::{AbiVersion, Kind};

/// The role is derived from the declaration, never stated beside it: nothing under a transport makes
/// it a carrier, anything under it makes it a framer.
#[test]
fn the_role_is_what_the_transport_composes_over() {
    assert_eq!(role_of(&[]), Role::Carrier);
    assert_eq!(role_of(&["a"]), Role::Framer);
    assert_eq!(role_of(&["a", "b"]), Role::Framer);
}

/// A rendering sink keeps every byte, in order.
#[test]
fn a_byte_sink_keeps_what_it_is_given_in_order() {
    let mut out = Vec::new();
    BytesOut::put(&mut out, b"ab");
    BytesOut::put(&mut out, b"");
    BytesOut::put(&mut out, b"c");
    assert_eq!(out, b"abc");
}

/// A plain piece reports no status, and the constructor keeps what it was given.
#[test]
fn a_plain_piece_carries_no_status() {
    let piece = Framed::plain(StreamId(3), b"xy", true);
    assert_eq!(
        (piece.stream, piece.bytes, piece.end_of_frame),
        (StreamId(3), &b"xy"[..], true)
    );
    assert_eq!(
        (piece.status, piece.status_code, piece.retry_after_secs),
        (None, None, None)
    );
}

// ── both roles are object-safe and drivable through the trait object ─────────────────────────────

struct Echo;

impl Plugin for Echo {
    fn key(&self) -> &'static str {
        "echo"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        crate::transport::TRANSPORT_ABI
    }
}

impl Carrier for Echo {
    fn listen(&self, bind: &str) -> Result<(u64, String), TransportError> {
        Ok((1, bind.to_string()))
    }
    fn poll_accept(&self, _: u64, _: &mut Context<'_>) -> CarrierPoll<(u64, String)> {
        Poll::Pending
    }
    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError> {
        match dest {
            Dest::Authority(_) => Ok(7),
            Dest::Program { .. } => Err(TransportError::AddressRefused),
        }
    }
    fn poll_read(&self, _: u64, _: &mut Context<'_>, _: &mut [u8]) -> CarrierPoll<Chunk> {
        Poll::Ready(Ok(Chunk::stream(0)))
    }
    fn poll_write(&self, _: u64, _: &mut Context<'_>, bytes: &[u8], _: bool) -> CarrierPoll<usize> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(&self, _: u64, _: &mut Context<'_>) -> CarrierPoll<()> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(&self, _: u64, _: &mut Context<'_>, _: CloseReason) -> CarrierPoll<()> {
        Poll::Ready(Ok(()))
    }
    fn arrival(&self, conn: u64) -> Option<CarrierFacts> {
        (conn == 7).then(|| CarrierFacts {
            peer: "far".into(),
            local_port: 0,
        })
    }
}

/// A framer whose frame is one line: what it ingests comes back a line at a time, and what it emits
/// goes out with the line's end.
struct Lines(std::sync::Mutex<Vec<u8>>);

#[derive(Default)]
struct Collected {
    sent: Vec<u8>,
    frames: Vec<(Vec<u8>, bool)>,
    ended: bool,
}

impl FramerOut for Collected {
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        self.frames.push((piece.bytes.to_vec(), piece.end_of_frame));
    }
    fn end(&mut self) {
        self.ended = true;
    }
    fn now(&self) -> crate::transport::HostTime {
        crate::transport::HostTime::default()
    }
    fn wake_at(&mut self, _: Option<u64>) {}
}

impl Plugin for Lines {
    fn key(&self) -> &'static str {
        "lines"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        crate::transport::TRANSPORT_ABI
    }
}

impl Framer for Lines {
    fn locate(&self, target: &str) -> Result<Located, TransportError> {
        Ok(Located {
            authority: target.to_string(),
            secure: false,
            server_name: None,
        })
    }
    fn open(
        &self,
        _: Side,
        _: &str,
        _: &ConnFacts,
        _: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        Ok(1)
    }
    fn ingest(
        &self,
        _: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let mut held = self.0.lock().unwrap();
        held.extend_from_slice(bytes);
        while let Some(at) = held.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = held.drain(..=at).collect();
            out.frame(Framed::plain(StreamId(0), &line[..at], true));
        }
        if end {
            out.end();
        }
        Ok(())
    }
    fn emit(
        &self,
        _: u64,
        _: StreamId,
        bytes: &[u8],
        end_of_frame: bool,
        _text: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        out.send(bytes);
        if end_of_frame {
            out.send(b"\n");
        }
        Ok(())
    }
    fn encode_envelope(
        &self,
        _: &[(&str, &[u8])],
        body: &[u8],
        out: &mut dyn BytesOut,
    ) -> Result<(), Encode> {
        out.put(body);
        Ok(())
    }
    fn refusal(
        &self,
        state: u64,
        _: Option<StreamId>,
        bytes: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        self.emit(state, StreamId(0), bytes, true, false, out)
    }
    fn close(&self, _: u64, _: CloseReason, _: &mut dyn FramerOut) {}
    fn detach(&self, _: u64, out: &mut dyn BytesOut) -> Result<(), TransportError> {
        out.put(&std::mem::take(&mut *self.0.lock().unwrap()));
        Ok(())
    }
    fn tick(&self, _: u64, _: &mut dyn FramerOut) -> Result<(), TransportError> {
        Ok(())
    }
    fn adopt(
        &self,
        _: Side,
        _: &ConnFacts,
        leftover: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        self.ingest(1, leftover, false, out)?;
        Ok(1)
    }
}

#[test]
fn a_carrier_is_driven_through_its_trait_object() {
    let carrier: &dyn Carrier = &Echo;
    assert_eq!(carrier.listen("here").unwrap(), (1, "here".to_string()));
    assert_eq!(carrier.dial(&Dest::Authority("h:1")).unwrap(), 7);
    assert_eq!(
        carrier.dial(&Dest::Program {
            program: "/bin/x",
            args: &["-v"],
            env: &[("K", "V")],
        }),
        Err(TransportError::AddressRefused)
    );
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert_eq!(carrier.poll_write(7, &mut cx, b"abc", true), Poll::Ready(Ok(3)));
    assert!(carrier.poll_accept(1, &mut cx).is_pending());
    assert_eq!(carrier.arrival(7).unwrap().peer, "far");
    assert_eq!(carrier.arrival(8), None);
}

#[test]
fn a_framer_is_driven_through_its_trait_object_and_hands_its_stream_on() {
    let framer: &dyn Framer = &Lines(std::sync::Mutex::new(Vec::new()));
    let mut out = Collected::default();
    let state = framer
        .open(Side::Accept, "", &ConnFacts::default(), &mut out)
        .unwrap();
    framer.ingest(state, b"one\ntw", false, &mut out).unwrap();
    assert_eq!(out.frames, vec![(b"one".to_vec(), true)]);
    framer
        .emit(state, StreamId(0), b"hi", true, false, &mut out)
        .unwrap();
    assert_eq!(out.sent, b"hi\n");
    // The unconsumed half line moves with the stream, and the adopter frames it where it stopped.
    let mut leftover = Vec::new();
    framer.detach(state, &mut leftover).unwrap();
    assert_eq!(leftover, b"tw");
    let mut moved = Collected::default();
    let adopted = framer
        .adopt(Side::Accept, &ConnFacts::default(), &leftover, &mut moved)
        .unwrap();
    framer.ingest(adopted, b"o\n", true, &mut moved).unwrap();
    assert_eq!(moved.frames, vec![(b"two".to_vec(), true)]);
    assert!(moved.ended);
}

// ── the row: every constant a transport declares, as one value ───────────────────────────────────

struct Declared;

impl crate::transport::TransportMeta for Declared {
    const KEY: &'static str = "declared";
    const SELECTOR_FORMS: &'static [crate::grammar::SelectorForm] =
        &[crate::grammar::SelectorForm::ExactPath];
    const EGRESS_SELECTOR_FORMS: &'static [crate::grammar::SelectorForm] =
        &[crate::grammar::SelectorForm::Port];
    const COMPOSES_OVER: &'static [&'static str] = &["below"];
    const HANDOFF: Option<crate::transport::wire::Handoff> =
        Some(crate::transport::wire::Handoff {
            from: "a",
            to: "b",
            binding_fact: "c",
        });
    const FRAMING: crate::transport::wire::Framing = crate::transport::wire::Framing::Datagram;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<crate::transport::wire::Unit0Trigger> =
        Some(crate::transport::wire::Unit0Trigger::FirstLine);
    const UPGRADES_TO: &'static [&'static str] = &["up"];
    const HANDSHAKE_TRIGGER: Option<crate::transport::wire::HandshakeTrigger> =
        Some(crate::transport::wire::HandshakeTrigger {
            frame_kind: "k",
            max_steps: 3,
        });
    const TRANSPORT_FACTS: &'static [&'static str] = &["fact"];
    const DECODES_PAYLOAD: bool = true;
    const STATUS_CLASS: Option<crate::transport::wire::StatusAt> =
        Some(crate::transport::wire::StatusAt::Terminal);
    const STATUS_NAMESPACE: Option<&'static str> = Some("numbering");
}

/// The row is the declaration, constant for constant — a field left behind or crossed with its
/// neighbour is a difference here, because every constant above is distinct from its default.
#[test]
fn a_row_is_its_declaration_constant_for_constant() {
    use crate::transport::TransportMeta as M;
    let row = TransportRow::of::<Declared>();
    assert_eq!(row.key, <Declared as M>::KEY);
    assert_eq!(row.composes_over, <Declared as M>::COMPOSES_OVER);
    assert_eq!(row.selector_forms, <Declared as M>::SELECTOR_FORMS);
    assert_eq!(
        row.egress_selector_forms,
        <Declared as M>::EGRESS_SELECTOR_FORMS
    );
    assert_eq!(row.handoff, <Declared as M>::HANDOFF);
    assert_eq!(row.framing, <Declared as M>::FRAMING);
    assert_eq!(
        (row.session, row.session_bound, row.decodes_payload),
        (true, false, true)
    );
    assert_eq!(row.unit0_trigger, <Declared as M>::UNIT0_TRIGGER);
    assert_eq!(row.upgrades_to, <Declared as M>::UPGRADES_TO);
    assert_eq!(row.handshake_trigger, <Declared as M>::HANDSHAKE_TRIGGER);
    assert_eq!(row.transport_facts, <Declared as M>::TRANSPORT_FACTS);
    assert_eq!(row.status_at, <Declared as M>::STATUS_CLASS);
    assert_eq!(row.status_namespace, <Declared as M>::STATUS_NAMESPACE);
    assert_eq!(row.role(), Role::Framer);
}

/// A transport that answers for its own key alone makes ONE claim, and that claim is its declared
/// per-scheme constants, field for field.
#[test]
fn a_single_wire_transport_claims_its_own_key_with_its_own_constants() {
    use crate::transport::TransportMeta as M;
    let row = TransportRow::of::<Declared>();
    assert_eq!(
        row.claims,
        [crate::transport::Claim {
            key: "declared",
            session: true,
            session_bound: false,
            unit0_trigger: <Declared as M>::UNIT0_TRIGGER,
            status_at: <Declared as M>::STATUS_CLASS,
            status_namespace: Some("numbering"),
            transport_facts: &["fact"],
            selector_forms: <Declared as M>::SELECTOR_FORMS,
        }]
    );
}

/// An entry that frames several wires states one claim per wire, each with its OWN status leg — the
/// row carries them as stated, never folded into the entry's.
#[test]
fn an_entry_states_one_claim_per_wire_each_with_its_own_status_leg() {
    use crate::transport::wire::StatusAt;
    struct Several;
    impl crate::transport::TransportMeta for Several {
        const KEY: &'static str = "first";
        const SELECTOR_FORMS: &'static [crate::grammar::SelectorForm] = &[];
        const EGRESS_SELECTOR_FORMS: &'static [crate::grammar::SelectorForm] = &[];
        const COMPOSES_OVER: &'static [&'static str] = &["below"];
        const HANDOFF: Option<crate::transport::wire::Handoff> = None;
        const FRAMING: crate::transport::wire::Framing = crate::transport::wire::Framing::Stream;
        const SESSION: bool = false;
        const SESSION_BOUND: bool = false;
        const UNIT0_TRIGGER: Option<crate::transport::wire::Unit0Trigger> = None;
        const UPGRADES_TO: &'static [&'static str] = &[];
        const HANDSHAKE_TRIGGER: Option<crate::transport::wire::HandshakeTrigger> = None;
        const TRANSPORT_FACTS: &'static [&'static str] = &[];
        const DECODES_PAYLOAD: bool = false;
        const STATUS_CLASS: Option<StatusAt> = Some(StatusAt::FirstFrame);
        const STATUS_NAMESPACE: Option<&'static str> = Some("one");
        const CLAIMS: &'static [crate::transport::Claim] = &[
            crate::transport::Claim {
                key: "first",
                session: false,
                session_bound: false,
                unit0_trigger: None,
                status_at: Some(StatusAt::FirstFrame),
                status_namespace: Some("one"),
                transport_facts: &[],
                selector_forms: &[],
            },
            crate::transport::Claim {
                key: "second",
                session: true,
                session_bound: true,
                unit0_trigger: None,
                status_at: Some(StatusAt::Terminal),
                status_namespace: Some("two"),
                transport_facts: &[],
                selector_forms: &[],
            },
        ];
    }
    let row = TransportRow::of::<Several>();
    let legs: Vec<_> = row.claims.iter().map(|c| (c.key, c.status_at)).collect();
    assert_eq!(
        legs,
        [
            ("first", Some(StatusAt::FirstFrame)),
            ("second", Some(StatusAt::Terminal))
        ]
    );
    assert_eq!(row.role(), Role::Framer, "the role stays the entry's");
}
