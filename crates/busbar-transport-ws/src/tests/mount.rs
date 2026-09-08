// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DUPLEX MOUNT, PROVED AGAINST A SURFACE AND A DRIVER THAT ARE NOT ANY PLANE'S.
//!
//! ## Why the fakes are fakes
//!
//! Everything the mount decides is decided against a declaration it did not write and a driver it
//! cannot see inside. A battery that drove a real protocol through it would prove that the mount
//! works for that protocol, which is the one claim the mount does not make — and it would put a
//! plane's name in a transport's source, which the scan beside this file refuses outright.
//!
//! So the surface here declares a binding called `duplex` with one mount, and the driver here is a
//! script: it answers frame *n* with whatever the test queued, records what it was handed, and
//! counts its own closes. Every rule below is then checkable at the seam rather than through a
//! socket — the ordering the pump guarantees, the backpressure posture, which end cut, and the
//! number this wire spells for each reason.

use std::collections::VecDeque;
use std::sync::Mutex;

use busbar_contract::TransportMeta;
use busbar_contract_transport::driver::Outcome;
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::session::{
    Cut, DetachedSession, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen,
    SessionReply,
};
use busbar_contract_transport::surface::{
    check_surface, Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};
use busbar_contract_transport::wire::{CloseReason, TransportError};

use super::{
    address, close_code, open_session, published_facts, pump, reason_for, FrameSink, FrameSource,
    Upgrade, SESSION_FACTS,
};
use crate::WsTransport;

// ── a declaration that is nobody's ──────────────────────────────────────────────────────────────

/// Two bindings over two different wires, at two different mounts.
///
/// The second one is the point of the pair: it is carried by another transport entirely, and a mount
/// that addressed on the target alone would open sessions on it.
const BINDINGS: &[BindingDecl] = &[
    BindingDecl {
        name: "duplex",
        transport: "ws",
        mounts: &["/session", "/session/"],
    },
    BindingDecl {
        name: "elsewhere",
        transport: "http",
        mounts: &["/elsewhere"],
    },
];

const OPERATIONS: &[Operation] = &[
    Operation {
        op: "start",
        dispatch: &[Dispatch::Document {
            binding: "duplex",
            method: "GET",
            member: "kind",
            name: "start",
            bar: Bar::Credential,
        }],
        answering: Answering::Stream,
        request_media: "application/octet-stream",
        response_media: "application/octet-stream",
    },
    Operation {
        op: "look",
        dispatch: &[Dispatch::Document {
            binding: "elsewhere",
            method: "POST",
            member: "kind",
            name: "look",
            bar: Bar::Open,
        }],
        answering: Answering::Unary,
        request_media: "application/octet-stream",
        response_media: "application/octet-stream",
    },
];

const SURFACE: WireSurface = WireSurface {
    bindings: BINDINGS,
    operations: OPERATIONS,
};

const CHAIN: &[&str] = &["tcp", "http", "ws"];

// ── a driver that is nobody's ───────────────────────────────────────────────────────────────────

/// What one `open` was handed, flattened to what a test can assert on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Opened {
    path: String,
    peer: String,
    binding: String,
    transport: String,
    chain: Vec<String>,
    bar: Bar,
}

/// A session driver that answers from a script and records everything it was handed.
struct FakeDriver {
    answer: Result<SessionHandle, Outcome>,
    script: Mutex<VecDeque<SessionReply>>,
    opened: Mutex<Vec<Opened>>,
    seen: Mutex<Vec<(u64, Vec<u8>)>>,
    closed: Mutex<Vec<(SessionHandle, SessionEnd)>>,
}

impl FakeDriver {
    fn new(script: Vec<SessionReply>) -> Self {
        Self {
            answer: Ok(SessionHandle(7)),
            script: Mutex::new(script.into()),
            opened: Mutex::new(Vec::new()),
            seen: Mutex::new(Vec::new()),
            closed: Mutex::new(Vec::new()),
        }
    }

    fn refusing(outcome: Outcome) -> Self {
        Self {
            answer: Err(outcome),
            ..Self::new(Vec::new())
        }
    }

    fn seen(&self) -> Vec<(u64, Vec<u8>)> {
        self.seen.lock().expect("the fake driver's log").clone()
    }

    fn closes(&self) -> Vec<(SessionHandle, SessionEnd)> {
        self.closed.lock().expect("the fake driver's log").clone()
    }
}

impl SessionDriver for FakeDriver {
    fn open(&self, open: SessionOpen<'_>, surface: &WireSurface) -> Result<SessionHandle, Outcome> {
        assert_eq!(*surface, SURFACE, "the surface travels with the open");
        self.opened
            .lock()
            .expect("the fake driver's log")
            .push(Opened {
                path: open.fact(tfacts::PATH).unwrap_or_default().to_string(),
                peer: open.fact(tfacts::PEER).unwrap_or_default().to_string(),
                binding: open.binding.to_string(),
                transport: open.transport.to_string(),
                chain: open.chain.iter().map(|l| (*l).to_string()).collect(),
                bar: open.bar,
            });
        self.answer
    }

    fn drive(&self, session: SessionHandle, frame: SessionFrame<'_>) -> SessionReply {
        assert_eq!(session, SessionHandle(7), "the handle comes back unchanged");
        self.seen
            .lock()
            .expect("the fake driver's log")
            .push((frame.seq, frame.payload.to_vec()));
        self.script
            .lock()
            .expect("the fake driver's script")
            .pop_front()
            .unwrap_or_else(|| SessionReply::quiet(Outcome::Completed))
    }

    fn close(&self, session: SessionHandle, end: SessionEnd) {
        self.closed
            .lock()
            .expect("the fake driver's log")
            .push((session, end));
    }
}

// ── a socket that is nobody's ───────────────────────────────────────────────────────────────────

/// An inbound stream of scripted frames. Ends orderly when the script runs out, unless the script
/// ends in a failure.
struct FakeSource {
    frames: VecDeque<Result<Vec<u8>, TransportError>>,
}

impl FakeSource {
    fn of(frames: &[&str]) -> Self {
        Self {
            frames: frames.iter().map(|f| Ok(f.as_bytes().to_vec())).collect(),
        }
    }

    /// How many frames the pump never asked for. Zero is a pump that drained the peer; anything else
    /// is a pump that stopped reading, which is what backpressure looks like from this side.
    fn unread(&self) -> usize {
        self.frames.len()
    }
}

impl FrameSource for FakeSource {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        self.frames.pop_front()
    }
}

/// The same source by reference, for the tests that read what the pump LEFT BEHIND. A pump that
/// consumed its source could not be asked what it never asked for, and "what it never asked for" is
/// the whole evidence for the backpressure posture.
impl FrameSource for &mut FakeSource {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        self.frames.pop_front()
    }
}

/// An outbound sink that accepts a fixed number of frames and then reports it is full.
struct FakeSink {
    accepts: usize,
    written: Vec<(Vec<u8>, String)>,
    closes: Vec<u16>,
}

impl FakeSink {
    fn accepting(accepts: usize) -> Self {
        Self {
            accepts,
            written: Vec::new(),
            closes: Vec::new(),
        }
    }

    fn open() -> Self {
        Self::accepting(usize::MAX)
    }

    fn frames(&self) -> Vec<String> {
        self.written
            .iter()
            .map(|(bytes, _)| String::from_utf8_lossy(bytes).into_owned())
            .collect()
    }
}

impl FrameSink for &mut FakeSink {
    async fn write_frame(&mut self, frame: &[u8], media: &str) -> Result<(), TransportError> {
        if self.accepts == 0 {
            return Err(TransportError::Backpressure);
        }
        self.accepts -= 1;
        self.written.push((frame.to_vec(), media.to_string()));
        Ok(())
    }

    async fn write_close(&mut self, code: u16) {
        self.closes.push(code);
    }
}

/// The mount every test below opens.
fn mounted() -> super::Mount<'static> {
    address(&SURFACE, "ws", CHAIN, &upgrade("/session")).expect("the declared mount addresses")
}

fn upgrade(target: &str) -> Upgrade<'_> {
    Upgrade {
        target,
        peer: "198.51.100.7:44311",
    }
}

fn reply(frames: &[&str], outcome: Outcome) -> SessionReply {
    SessionReply::frames(
        frames.iter().map(|f| f.as_bytes().to_vec()).collect(),
        "application/octet-stream",
        outcome,
    )
}

// ── the declaration this mount is built on holds ────────────────────────────────────────────────

/// The fixture is a surface the boot check accepts, so nothing below is proved against a
/// declaration the tree would refuse at startup.
#[test]
fn the_fixture_surface_is_one_the_boot_check_admits() {
    check_surface(&SURFACE).expect("the fixture declares a surface the boot check admits");
}

// ── addressing ──────────────────────────────────────────────────────────────────────────────────

/// A declared mount of THIS transport's binding addresses, and carries the binding's own bar.
#[test]
fn a_declared_mount_addresses_and_carries_its_bar() {
    let mount = mounted();
    assert_eq!(mount.binding.name, "duplex");
    assert_eq!(mount.bar, Bar::Credential);
    assert_eq!(mount.key, "ws");
    assert_eq!(mount.chain, CHAIN);
}

/// Both declared spellings of one mount address, and a query does not stop them.
#[test]
fn every_declared_spelling_of_a_mount_addresses() {
    for target in ["/session", "/session/", "/session?since=4"] {
        let mount = address(&SURFACE, "ws", CHAIN, &upgrade(target))
            .unwrap_or_else(|_| panic!("`{target}` is a declared spelling of the mount"));
        assert_eq!(mount.binding.name, "duplex");
    }
}

/// A target another wire's binding declares does NOT open a session here.
///
/// The rule the target-only reading gets wrong: a surface declares several bindings over several
/// wires, and a session opened on another wire's binding would run under that binding's credential
/// bar on a wire nobody declared it for.
#[test]
fn another_wires_binding_does_not_address_here() {
    assert!(address(&SURFACE, "ws", CHAIN, &upgrade("/elsewhere")).is_err());
    assert!(address(&SURFACE, "ws", CHAIN, &upgrade("/nothing")).is_err());
}

/// The facts a session publishes are the two this transport declares, path first.
#[test]
fn the_published_facts_are_the_declared_ones_in_order() {
    let up = upgrade("/session?since=4");
    let facts = published_facts(&up);
    assert_eq!(
        facts,
        vec![
            (tfacts::PATH, "/session?since=4"),
            (tfacts::PEER, "198.51.100.7:44311")
        ]
    );
    assert!(
        tfacts::undeclared(
            <WsTransport as TransportMeta>::TRANSPORT_FACTS,
            SESSION_FACTS
        )
        .is_none(),
        "this mount may publish no reserved key its transport did not declare"
    );
    for (key, _) in &facts {
        assert!(
            SESSION_FACTS.contains(key),
            "the published list and the declared list are one list: `{key}` is not in both"
        );
    }
}

// ── opening ─────────────────────────────────────────────────────────────────────────────────────

/// The open hands the driver the facts, the binding, the stack and the bar, and takes back a handle.
#[test]
fn the_open_hands_over_what_the_transport_knows() {
    let driver = FakeDriver::new(Vec::new());
    let mount = mounted();
    let handle = open_session(&driver, &SURFACE, &mount, &upgrade("/session"))
        .expect("the fake driver opens");
    assert_eq!(handle, SessionHandle(7));
    assert_eq!(
        driver.opened.lock().expect("the log").as_slice(),
        [Opened {
            path: "/session".into(),
            peer: "198.51.100.7:44311".into(),
            binding: "duplex".into(),
            transport: "ws".into(),
            chain: vec!["tcp".into(), "http".into(), "ws".into()],
            bar: Bar::Credential,
        }]
    );
}

/// A driver that will not open one refuses in the eight words, BEFORE the protocol changes.
///
/// Which is the whole reason `open_session` is a separate call: the caller still holds a leg with a
/// status line on it, and answers there rather than upgrading and then closing.
#[test]
fn a_refused_open_answers_in_the_closed_vocabulary() {
    let driver = FakeDriver::refusing(Outcome::Unauthenticated);
    let refused = open_session(&driver, &SURFACE, &mounted(), &upgrade("/session"));
    assert_eq!(refused, Err(Outcome::Unauthenticated));
    assert!(
        driver.closes().is_empty(),
        "a session that never opened is never closed"
    );
}

/// A mount composed before its driver exists opens nothing, and says so honestly.
#[test]
fn a_detached_mount_opens_nothing() {
    let refused = open_session(&DetachedSession, &SURFACE, &mounted(), &upgrade("/session"));
    assert_eq!(refused, Err(Outcome::Unavailable));
}

// ── frames, in order ────────────────────────────────────────────────────────────────────────────

/// Inbound frames reach the driver in arrival order and numbered from zero; outbound frames leave in
/// the order the driver wrote them, across several inbound frames.
#[tokio::test]
async fn frames_travel_in_order_in_both_directions() {
    let driver = FakeDriver::new(vec![
        reply(&["a1", "a2", "a3"], Outcome::Completed),
        reply(&[], Outcome::Completed),
        reply(&["c1"], Outcome::Completed),
    ]);
    let mut sink = FakeSink::open();
    let end = pump(
        &driver,
        SessionHandle(7),
        FakeSource::of(&["one", "two", "three"]),
        &mut sink,
    )
    .await;

    assert_eq!(
        driver.seen(),
        vec![
            (0, b"one".to_vec()),
            (1, b"two".to_vec()),
            (2, b"three".to_vec())
        ]
    );
    assert_eq!(sink.frames(), vec!["a1", "a2", "a3", "c1"]);
    assert_eq!(
        sink.written[0].1, "application/octet-stream",
        "the media type on a frame is the declaration's, carried through"
    );
    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Client,
            reason: CloseReason::PeerClosed
        }
    );
}

/// A refused frame does not end the session: the plane wrote its refusal, and the peer carries on.
#[tokio::test]
async fn a_refused_frame_does_not_end_the_session() {
    let driver = FakeDriver::new(vec![
        reply(&["no"], Outcome::Forbidden),
        reply(&["yes"], Outcome::Completed),
    ]);
    let mut sink = FakeSink::open();
    let end = pump(
        &driver,
        SessionHandle(7),
        FakeSource::of(&["one", "two"]),
        &mut sink,
    )
    .await;
    assert_eq!(driver.seen().len(), 2, "the second frame was still served");
    assert_eq!(sink.frames(), vec!["no", "yes"]);
    assert_eq!(end.cut, Cut::Client);
}

// ── backpressure ────────────────────────────────────────────────────────────────────────────────

/// A sink that will not take a frame ends the session as THIS side's cut, and the pump stops reading.
///
/// Both halves matter. The end is the node's because this end stopped serving, whatever the
/// proximate cause was; and the frames still queued on the source were never read, which is the
/// posture the module's header describes — no queue, so the inbound rate is the outbound wire's.
#[tokio::test]
async fn a_full_sink_ends_the_session_and_stops_the_reading() {
    let driver = FakeDriver::new(vec![
        reply(&["a1", "a2"], Outcome::Completed),
        reply(&["b1"], Outcome::Completed),
    ]);
    let mut sink = FakeSink::accepting(2);
    let mut source = FakeSource::of(&["one", "two", "three", "four"]);
    let end = pump(&driver, SessionHandle(7), &mut source, &mut sink).await;

    assert_eq!(sink.frames(), vec!["a1", "a2"], "no frame was dropped");
    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Upstream,
            reason: CloseReason::TransportFailed
        }
    );
    assert_eq!(
        source.unread(),
        2,
        "the pump stopped reading rather than buffering what it could not write"
    );
}

// ── cuts, in both directions ────────────────────────────────────────────────────────────────────

/// The peer closing is the client's cut, and it is owed the courtesy close its protocol defines.
#[tokio::test]
async fn a_peer_that_closes_is_the_clients_cut() {
    let driver = FakeDriver::new(Vec::new());
    let mut sink = FakeSink::open();
    let end = pump(&driver, SessionHandle(7), FakeSource::of(&[]), &mut sink).await;
    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Client,
            reason: CloseReason::PeerClosed
        }
    );
    assert_eq!(sink.closes, vec![1000]);
}

/// A carrier that fails under the read is still the client's cut, and gets no close frame.
#[tokio::test]
async fn a_failed_read_is_the_clients_cut_with_nothing_written_back() {
    let driver = FakeDriver::new(Vec::new());
    let mut sink = FakeSink::open();
    let mut source = FakeSource::of(&["one"]);
    source.frames.push_back(Err(TransportError::Reset));
    let end = pump(&driver, SessionHandle(7), &mut source, &mut sink).await;
    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Client,
            reason: CloseReason::TransportFailed
        }
    );
    assert!(
        sink.closes.is_empty(),
        "there is nothing on the other end to read a close"
    );
}

/// The driver ending it is this side's cut, after its last frames are written, with its own code.
#[tokio::test]
async fn a_driver_that_ends_it_is_the_upstream_cut() {
    let mut ending = reply(&["last"], Outcome::Completed);
    ending.close = Some(CloseReason::Drain);
    let driver = FakeDriver::new(vec![ending]);
    let mut sink = FakeSink::open();
    let mut source = FakeSource::of(&["one", "two"]);
    let end = pump(&driver, SessionHandle(7), &mut source, &mut sink).await;

    assert_eq!(
        sink.frames(),
        vec!["last"],
        "the last frames went out first"
    );
    assert_eq!(sink.closes, vec![1001]);
    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Upstream,
            reason: CloseReason::Drain
        }
    );
    assert_eq!(source.unread(), 1, "nothing was served after the close");
}

/// Every ending closes the session with the driver exactly once — including the ugly ones.
#[tokio::test]
async fn every_ending_closes_the_session_exactly_once() {
    let endings: Vec<(FakeDriver, FakeSource, usize)> = vec![
        (FakeDriver::new(Vec::new()), FakeSource::of(&[]), usize::MAX),
        (
            FakeDriver::new(vec![reply(&["a"], Outcome::Completed)]),
            FakeSource::of(&["one"]),
            0,
        ),
        (
            FakeDriver::new(vec![SessionReply::ending(
                Outcome::Completed,
                CloseReason::Revoked,
            )]),
            FakeSource::of(&["one"]),
            usize::MAX,
        ),
    ];
    for (driver, source, accepts) in endings {
        let mut sink = FakeSink::accepting(accepts);
        let end = pump(&driver, SessionHandle(7), source, &mut sink).await;
        let closes = driver.closes();
        assert_eq!(closes.len(), 1, "one ending, one close");
        assert_eq!(closes[0], (SessionHandle(7), end));
    }
}

// ── the numbers this wire spells ────────────────────────────────────────────────────────────────

/// Every reason has a code, and each code is the one this wire's own numbering means by it.
#[test]
fn every_close_reason_spells_a_code_of_this_wire() {
    let table = [
        (CloseReason::Normal, 1000),
        (CloseReason::PeerClosed, 1000),
        (CloseReason::Drain, 1001),
        (CloseReason::Revoked, 1008),
        (CloseReason::Timeout, 1011),
        (CloseReason::Poisoned, 1011),
        (CloseReason::TransportFailed, 1011),
        (CloseReason::CapacityExhausted, 1013),
    ];
    for (reason, code) in table {
        assert_eq!(close_code(reason), code, "the code for {reason:?}");
    }
    for (reason, code) in table {
        assert!(
            (1000..=1015).contains(&code),
            "{reason:?} spells {code}, which is outside the codes this wire defines"
        );
    }
}

/// A carrier failure maps to a reason that does not blame the wrong end.
#[test]
fn a_carrier_failure_maps_to_an_honest_reason() {
    assert_eq!(reason_for(TransportError::Timeout), CloseReason::Timeout);
    assert_eq!(reason_for(TransportError::Closed), CloseReason::PeerClosed);
    for error in [
        TransportError::Reset,
        TransportError::Backpressure,
        TransportError::Framing,
        TransportError::Refused,
    ] {
        assert_eq!(reason_for(error), CloseReason::TransportFailed);
    }
}
