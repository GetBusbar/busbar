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
    Cut, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen, SessionReply,
};
use busbar_contract_transport::surface::{
    check_surface, Answering, Bar, BindingDecl, Capture, Dispatch, Operation, WireSurface,
};
use busbar_contract_transport::wire::{CloseReason, TransportError};

use super::{
    address, close_code, open_session, published_facts, pump, reason_for, FrameSink, FrameSource,
    SessionBudgets, Upgrade, SESSION_FACTS,
};
use crate::WsTransport;

// ── a declaration that is nobody's ──────────────────────────────────────────────────────────────

/// Three bindings, and each of the last two is a way of being addressable that is NOT a session.
///
/// * `duplex` is the session mount: this wire, and a duplex row declaring it.
/// * `elsewhere` is carried by another transport entirely. A mount that addressed on the target
///   alone would open sessions on it.
/// * `posted` is the harder one, and the reason the declaration needs a duplex KIND rather than a
///   duplex-shaped document row. It is on THIS wire, at a mount of its own, and it is an ordinary
///   posted-envelope endpoint — a deployment is perfectly entitled to declare one over a wire that
///   can also carry sessions. A mount that asked only "my transport?" and "a declared mount?" would
///   upgrade a caller here and hand them a session on a surface whose own declaration says it
///   answers one document with one answer.
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
    BindingDecl {
        name: "posted",
        transport: "ws",
        mounts: &["/posted"],
    },
    // A session mount whose declared PATTERN carries an identifier. A published URL with a key in
    // it is the ordinary shape of a session that is ABOUT something, and it is the one shape a
    // vocabulary of literals could not declare: a session has no target template to read a capture
    // off, because after the upgrade this wire has no target at all.
    BindingDecl {
        name: "keyed",
        transport: "ws",
        mounts: &["/session/leg/{leg_id}"],
    },
];

const OPERATIONS: &[Operation] = &[
    Operation {
        op: "start",
        // THE DUPLEX KIND. The binding, the upgrade's method, the bar — the three facts this mount
        // has before the protocol changes, and nothing it could not have afterwards. Declared as a
        // document row instead, it would carry a member and a name that nothing here resolves and
        // nothing here could resolve: after the upgrade there is no document to read either from.
        dispatch: &[
            Dispatch::Duplex {
                binding: "keyed",
                method: "GET",
                bar: Bar::Credential,
            },
            Dispatch::Duplex {
                binding: "duplex",
                method: "GET",
                bar: Bar::Credential,
            },
        ],
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
    Operation {
        op: "post",
        dispatch: &[Dispatch::Document {
            binding: "posted",
            method: "POST",
            member: "kind",
            name: "post",
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
    credential: Option<String>,
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
                credential: open.fact(tfacts::CREDENTIAL).map(str::to_string),
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
        credential: None,
    }
}

fn upgrade_presenting<'u>(target: &'u str, credential: &'u str) -> Upgrade<'u> {
    Upgrade {
        credential: Some(credential),
        ..upgrade(target)
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

/// A BINDING OF THIS VERY WIRE THAT DECLARED NO SESSION IS NOT A PLACE ONE MAY BE OPENED.
///
/// The cell the duplex kind exists for, and the one a transport-key-and-path reading gets wrong.
/// `posted` is on `ws`, at a declared mount, and it is an ordinary posted-envelope endpoint: its
/// only row answers one document with one answer. Nothing about the transport key or the path says
/// so — the only thing that does is that the declarer wrote no duplex row for it.
///
/// Upgrading here would hand a stranger an open session on an endpoint whose declaration never
/// offered one, and would then run it under a bar read off document rows, which are rows about
/// requests this session will never carry.
#[test]
fn a_request_answer_binding_of_this_wire_is_not_a_session_mount() {
    assert!(address(&SURFACE, "ws", CHAIN, &upgrade("/posted")).is_err());
}

/// The facts a session publishes are the ones this transport declares, path first.
#[test]
fn the_published_facts_are_the_declared_ones_in_order() {
    let up = upgrade("/session?since=4");
    let facts = published_facts(&up, &[]);
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

/// A KEYED MOUNT PUBLISHES WHAT ITS PATTERN CAPTURED, under the declarer's own name and LAST.
///
/// Two halves. The capture reaches the driver at all — it is the only account a session gets of
/// where it was opened beyond the raw path, because a session declares no target template to read
/// one off. And it comes after the reserved keys, which is the precedence rather than a tidiness: a
/// declaration is free to name a capture `credential`, and a session authenticated against a segment
/// of its own URL instead of against what the caller presented would be a door opened by whoever
/// wrote the mount.
#[test]
fn a_keyed_mount_publishes_its_capture_under_the_declared_name_and_after_the_reserved_keys() {
    let up = upgrade_presenting("/session/leg/7f3a", "Bearer sk-1");
    let mounted = address(&SURFACE, "ws", CHAIN, &up).expect("a keyed pattern is a session mount");
    assert_eq!(mounted.binding.name, "keyed");
    assert_eq!(
        mounted.captures,
        vec![Capture {
            name: "leg_id",
            value: "7f3a"
        }]
    );
    assert_eq!(
        published_facts(&up, &mounted.captures),
        vec![
            (tfacts::PATH, "/session/leg/7f3a"),
            (tfacts::PEER, "198.51.100.7:44311"),
            (tfacts::CREDENTIAL, "Bearer sk-1"),
            ("leg_id", "7f3a"),
        ]
    );
}

/// A CAPTURE MAY NOT SHADOW A RESERVED KEY, because the reserved key is pushed first and the first
/// match is the answer.
///
/// Named `path` on purpose: every location resolved further in is resolved against these facts, and
/// a session whose `path` fact was a segment of its own URL rather than the URL would be a session
/// answered about somewhere else.
#[test]
fn a_capture_named_like_a_reserved_key_is_never_reached() {
    let up = upgrade("/session");
    let facts = published_facts(
        &up,
        &[Capture {
            name: tfacts::PATH,
            value: "not-the-path",
        }],
    );
    assert_eq!(
        facts.iter().find(|(k, _)| *k == tfacts::PATH),
        Some(&(tfacts::PATH, "/session")),
        "reserved first, first match wins"
    );
}

/// An upgrade that presented a credential publishes it, WHOLE, and an upgrade that presented none
/// publishes no such fact at all.
///
/// The absent/empty distinction is the cell rather than a detail of it: a driver handed
/// `("credential", "")` is being told one was presented and is blank, and a caller that presented
/// none did not present a blank one. And the scheme word travels, because deciding what a scheme
/// means is the authentication chain's — a transport that stripped a prefix would be interpreting a
/// credential it may not read.
#[test]
fn a_presented_credential_is_published_whole_and_an_absent_one_is_absent() {
    let presented = upgrade_presenting("/session", "Bearer sk-44401");
    assert_eq!(
        published_facts(&presented, &[]),
        vec![
            (tfacts::PATH, "/session"),
            (tfacts::PEER, "198.51.100.7:44311"),
            (tfacts::CREDENTIAL, "Bearer sk-44401"),
        ]
    );

    let anonymous = upgrade("/session");
    assert!(
        published_facts(&anonymous, &[])
            .iter()
            .all(|(k, _)| *k != tfacts::CREDENTIAL),
        "an upgrade that presented nothing publishes no credential fact, not an empty one"
    );

    let blank = upgrade_presenting("/session", "");
    assert_eq!(
        published_facts(&blank, &[])
            .iter()
            .find(|(k, _)| *k == tfacts::CREDENTIAL),
        Some(&(tfacts::CREDENTIAL, "")),
        "a credential that WAS presented and is blank is a different statement, and is made"
    );
}

/// The credential is the ONLY one this session ever gets, and it reaches the driver's `open`.
///
/// Which is the whole reason it is on the upgrade rather than on a frame: after the upgrade the
/// protocol has changed and there is no request left to carry one, so a mount that dropped it would
/// leave a declared credential bar with nothing to resolve for the life of the session.
#[test]
fn the_upgrades_credential_reaches_the_open() {
    let driver = FakeDriver::new(Vec::new());
    let up = upgrade_presenting("/session", "Bearer sk-44401");
    let mount = address(&SURFACE, "ws", CHAIN, &up).expect("the declared mount addresses");
    open_session(&driver, &SURFACE, &mount, &up).expect("the fake driver opens");
    assert_eq!(
        driver.opened.lock().expect("the log")[0]
            .credential
            .as_deref(),
        Some("Bearer sk-44401")
    );
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
            credential: None,
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

/// A session driver that opens nothing, for a mount composed before its driver exists.
///
/// The duplex twin of the one-shot seam's `Detached` driver, and there for the same reason: a mount is handed a
/// driver at listen, and a deployment that has mounted a surface it cannot yet run has to answer
/// SOMETHING. Refusing the upgrade with the word that means "this node cannot serve it" is the only
/// answer that is true, and it is refused BEFORE the protocol changes, so the caller gets it on a
/// wire that still has somewhere to put it.
#[derive(Clone, Copy, Debug, Default)]
struct DetachedSession;

impl SessionDriver for DetachedSession {
    fn open(
        &self,
        _open: SessionOpen<'_>,
        _surface: &WireSurface,
    ) -> Result<SessionHandle, Outcome> {
        Err(Outcome::Unavailable)
    }

    fn drive(&self, _session: SessionHandle, _frame: SessionFrame<'_>) -> SessionReply {
        SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed)
    }

    fn close(&self, _session: SessionHandle, _end: SessionEnd) {}
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
        SessionBudgets::default(),
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
        SessionBudgets::default(),
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
    let end = pump(
        &driver,
        SessionHandle(7),
        &mut source,
        &mut sink,
        SessionBudgets::default(),
    )
    .await;

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
    let end = pump(
        &driver,
        SessionHandle(7),
        FakeSource::of(&[]),
        &mut sink,
        SessionBudgets::default(),
    )
    .await;
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
    let end = pump(
        &driver,
        SessionHandle(7),
        &mut source,
        &mut sink,
        SessionBudgets::default(),
    )
    .await;
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
    let end = pump(
        &driver,
        SessionHandle(7),
        &mut source,
        &mut sink,
        SessionBudgets::default(),
    )
    .await;

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
        let end = pump(
            &driver,
            SessionHandle(7),
            source,
            &mut sink,
            SessionBudgets::default(),
        )
        .await;
        let closes = driver.closes();
        assert_eq!(closes.len(), 1, "one ending, one close");
        assert_eq!(closes[0], (SessionHandle(7), end));
    }
}

// ── the whole-session deadline ──────────────────────────────────────────────────────────────────

/// A source that never yields anything and never ends: the peer that connected and then said
/// nothing, which is the cheapest way to hold a slot on this node.
struct SilentSource;

impl FrameSource for SilentSource {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        std::future::pending().await
    }
}

/// A source that always has another frame: the peer that never stops talking, which a read-scoped
/// timeout would never bound at all.
struct EndlessSource {
    served: u64,
}

impl FrameSource for &mut EndlessSource {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        self.served += 1;
        // A frame per simulated millisecond. Under a paused clock this is what makes the exchange
        // consume the budget rather than spin: without it the loop would never yield to the timer.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        Some(Ok(b"more".to_vec()))
    }
}

/// A peer that connected and then said nothing is cut by THIS side when the budget runs out.
///
/// All three halves are the cell: the reason is `Timeout` rather than a carrier failure, the cut is
/// this node's because the deadline was this node's, and the driver is still closed exactly once —
/// the expiry is a fifth way out of the loop and the one most likely to be the one that leaks.
#[tokio::test(start_paused = true)]
async fn a_session_that_outruns_its_deadline_is_cut_by_this_side() {
    let driver = FakeDriver::new(Vec::new());
    let mut sink = FakeSink::open();
    let end = pump(
        &driver,
        SessionHandle(7),
        SilentSource,
        &mut sink,
        SessionBudgets {
            deadline: Some(std::time::Duration::from_secs(30)),
        },
    )
    .await;

    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Upstream,
            reason: CloseReason::Timeout
        }
    );
    assert_eq!(
        sink.closes,
        vec![1011],
        "a deadline this node was waiting on is this node's own fault to report"
    );
    let closes = driver.closes();
    assert_eq!(closes.len(), 1, "one ending, one close");
    assert_eq!(closes[0], (SessionHandle(7), end));
}

/// A peer that never stops talking is cut by the SAME budget.
///
/// The property a read-scoped timeout does not have: every individual read here completes well
/// inside the deadline, and the session still ends at it, because the budget is the session's rather
/// than any one frame's.
#[tokio::test(start_paused = true)]
async fn a_peer_that_never_stops_talking_still_meets_the_deadline() {
    let driver = FakeDriver::new(Vec::new());
    let mut sink = FakeSink::open();
    let mut source = EndlessSource { served: 0 };
    let end = pump(
        &driver,
        SessionHandle(7),
        &mut source,
        &mut sink,
        SessionBudgets {
            deadline: Some(std::time::Duration::from_secs(30)),
        },
    )
    .await;

    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Upstream,
            reason: CloseReason::Timeout
        }
    );
    assert!(
        source.served > 1,
        "the peer was served frames before the budget ran out, not cut on its first read"
    );
}

/// A session that finishes inside its budget ends the way it would have with no budget at all.
///
/// The other half of the cell above: a deadline that cut a healthy exchange would be indistinguishable
/// from one that never fired, if only the firing were asserted.
#[tokio::test(start_paused = true)]
async fn a_session_inside_its_deadline_ends_on_its_own_terms() {
    let driver = FakeDriver::new(vec![reply(&["a"], Outcome::Completed)]);
    let mut sink = FakeSink::open();
    let end = pump(
        &driver,
        SessionHandle(7),
        FakeSource::of(&["one"]),
        &mut sink,
        SessionBudgets {
            deadline: Some(std::time::Duration::from_secs(30)),
        },
    )
    .await;

    assert_eq!(
        end,
        SessionEnd {
            cut: Cut::Client,
            reason: CloseReason::PeerClosed
        }
    );
    assert_eq!(sink.frames(), vec!["a"]);
    assert_eq!(sink.closes, vec![1000]);
}

/// The unbounded budget is the default, and it is what an embedder driving a pair it owns gets.
#[test]
fn the_default_budget_bounds_nothing() {
    assert_eq!(SessionBudgets::default().deadline, None);
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
