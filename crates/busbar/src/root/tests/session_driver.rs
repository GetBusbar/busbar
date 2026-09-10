// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERIC SESSION DRIVER, PROVED AGAINST A PLANE THAT DOES NOT EXIST.
//!
//! Every fixture here is invented. The surfaces below are made-up planes', declared in the ordinary
//! vocabulary with the ordinary duplex kind; the PLANE is a made-up one too, reached through the
//! contract's own `SessionPlane` face, whose reader knows three words and whose refusal encoder
//! writes the reason and nothing else; and the units are a stub that records what it was asked and
//! either proceeds through every step or refuses at the first. There is no dialect, no protocol and
//! no plane name anywhere in this file, and that is the claim under test rather than a stylistic
//! preference: what the driver does, it does for ANY plane, and a battery driving a real one
//! through it would prove only that it works for that one.
//!
//! The questions:
//!
//! * a declared credential bar with nothing to satisfy it refuses BEFORE anything is allocated —
//!   and a blank credential is nothing;
//! * a binding no declared operation dispatches over is refused rather than given a default shape;
//! * whether there is a session here to run at all is the plane's ROW's answer and not this
//!   driver's — and the reason there is only ever ONE shape is the contract's own boot check;
//! * THE OPENING UNIT runs at the upgrade, carries the session's identity, and its ending is the
//!   upgrade's answer — a session whose opening unit did not complete is not in the table;
//! * every unit a frame opens carries THAT session's identity, which is what links its postings
//!   and its audit records to the session rather than to nobody;
//! * what goes back is the PLANE's: a refusal rendered by its own encoder under the declared media,
//!   a frame it could not read answered the same way, and a frame that opens no unit consumed
//!   quietly with no media on the reply;
//! * a frame delivered out of ordinal stops the session rather than being read against the wrong
//!   state;
//! * a handle that was never minted, and one already closed, are the same answer;
//! * close releases exactly once, tells the units exactly once, and a second close does neither;
//! * the root's own unit set, with no session units composed, refuses a declared run as unclaimed.

use std::sync::Mutex;

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Authenticated, Decision, Decode, Encode, Meter, OpClassId, PrincipalId, ReasonCode, Refusal,
    Route, RoutePlan, ScopeFacts, TrustToken, UnitToken, Usage, UsageToken, VerifiedDestination,
    Verify,
};
use busbar_contract::bounded::{ArenaBytes, Facts, Ir};
use busbar_contract::dest::{DestinationFacts, EgressBody};
use busbar_contract::plane::{
    Ingress, Plane, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use busbar_contract::transport::facts as tfacts;
use busbar_contract::transport::session::{
    Cut, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen, SessionReply,
};
use busbar_contract::transport::surface::{
    check_surface, Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};
use busbar_contract::transport::Outcome;
use busbar_contract::unit::{ConfigView, Ctx, Refusal as PlaneRefusal, Unit, UnitEnd};
use busbar_contract::wire::{CloseReason, Frame, FrameCursor};
use busbar_kernel::slice::{ConcurrencyGauge, GroupLeaseSlip};
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};

use super::{declared_run, declares_a_run, SessionLoopDriver, SessionRead, SessionUnits};

// ── two planes that do not exist ────────────────────────────────────────────────────────────────

/// The made-up run plane's one duplex binding, carried on the `ws` registry key.
///
/// The key is the only string here that is not invented, and it is not a plane's: it is a wire's own
/// registry entry, and the declaration names it as DATA exactly as a real plane's does.
const RUN_BINDING: &str = "made-up-run";

/// The media the made-up declaration names for its frames. Invented, like everything else here.
const MADE_UP_MEDIA: &str = "application/made-up";

/// A binding declared under a bar and dispatched over by a STREAM operation: a session that is a run
/// of units.
const RUN_SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: RUN_BINDING,
        transport: "ws",
        mounts: &["/made/up/run"],
    }],
    operations: &[Operation {
        op: "open",
        dispatch: &[Dispatch::Duplex {
            binding: RUN_BINDING,
            method: "GET",
            bar: Bar::Credential,
        }],
        answering: Answering::Stream,
        request_media: MADE_UP_MEDIA,
        response_media: MADE_UP_MEDIA,
    }],
};

/// The made-up open plane's binding.
const OPEN_BINDING: &str = "made-up-open";

/// The same declaration with ONE word changed — the bar — so the cells that turn on the credential
/// and the cells that turn on the session's own bookkeeping are not the same cells.
const OPEN_SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: OPEN_BINDING,
        transport: "ws",
        mounts: &["/made/up/open"],
    }],
    operations: &[Operation {
        op: "open",
        dispatch: &[Dispatch::Duplex {
            binding: OPEN_BINDING,
            method: "GET",
            bar: Bar::Open,
        }],
        answering: Answering::Stream,
        request_media: MADE_UP_MEDIA,
        response_media: MADE_UP_MEDIA,
    }],
};

/// The SAME open declaration with its answering word changed to the other one — a fixture that
/// exists to be REFUSED.
const UNARY_SURFACE: WireSurface = WireSurface {
    bindings: OPEN_SURFACE.bindings,
    operations: &[Operation {
        op: "open",
        dispatch: &[Dispatch::Duplex {
            binding: OPEN_BINDING,
            method: "GET",
            bar: Bar::Open,
        }],
        answering: Answering::Unary,
        request_media: MADE_UP_MEDIA,
        response_media: MADE_UP_MEDIA,
    }],
};

/// A binding declared and dispatched over by NOTHING: a mount with no session behaviour on its row.
const UNDECLARED_BINDING: &str = "made-up-undeclared";

/// Both declarations this battery stands on are ones the boot check admits.
///
/// A fixture the tree would refuse at startup would make every green cell below a statement about a
/// surface that could never be mounted.
#[test]
fn the_fixture_planes_declare_surfaces_the_boot_check_admits() {
    assert_eq!(check_surface(&RUN_SURFACE), Ok(()));
    assert_eq!(check_surface(&OPEN_SURFACE), Ok(()));
}

// ── the plane, and it is nobody's ───────────────────────────────────────────────────────────────

/// The operation class every unit the made-up plane reads is.
const MADE_UP_OP: OpClassId = OpClassId::new("made-up");

/// The three words the made-up reader knows.
const OPENS_A_UNIT: &[u8] = b"open";
const NOT_YET_A_UNIT: &[u8] = b"noise";

/// A plane whose reader knows three words and whose refusal encoder writes the reason.
///
/// Reached only through the contract's `SessionPlane` face, which is the point: the driver is handed
/// `dyn`, and a cell that asserted a frame's bytes is asserting that the bytes the PLANE wrote are
/// the bytes that went out — not that the driver spelled anything itself.
struct MadeUpPlane;

/// What the made-up plane keeps per session: how many frames it has read.
struct Opened {
    frames: u32,
}

impl Plugin for MadeUpPlane {
    fn key(&self) -> &'static str {
        "made-up"
    }
    fn kind(&self) -> Kind {
        Kind::Plane
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

impl Plane for MadeUpPlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, busbar_contract::wire::Decode> {
        // The state the driver handed back is the one this plane opened, and it is the session's:
        // a reader that got a fresh one per frame would be a driver that kept none.
        let opened = st
            .and_then(|s| s.get_mut::<Opened>())
            .ok_or(busbar_contract::wire::Decode::MissingDeclaredFact)?;
        opened.frames += 1;
        let frame = frames
            .next_frame()
            .ok_or(busbar_contract::wire::Decode::MissingDeclaredFact)?;
        match frame.bytes.as_slice() {
            OPENS_A_UNIT => Ok(Ingress::Open(Box::new(UnitDraft {
                op: MADE_UP_OP,
                body_ir: Ir::empty(),
                correlates: None,
                correlation_out: None,
                facts: Facts::new(),
            }))),
            NOT_YET_A_UNIT => Ok(Ingress::NeedMore),
            _ => Err(busbar_contract::wire::Decode::UnsupportedOperation),
        }
    }

    fn encode_egress<'u>(
        &self,
        _u: &Unit<'u>,
        _dest: &busbar_contract::dest::VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, busbar_contract::wire::Encode> {
        Err(busbar_contract::wire::Encode::Unrepresentable)
    }

    fn encode_ingress_frame<'u>(
        &self,
        _u: &Unit<'u>,
        _f: &Frame,
        _dest: &busbar_contract::dest::VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, busbar_contract::wire::Encode> {
        Ok(None)
    }

    fn decode_response<'u>(
        &self,
        _frames: &mut FrameCursor<'u>,
        _dest: &busbar_contract::dest::VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, busbar_contract::wire::Decode> {
        Ok(Progress::NeedMore)
    }

    fn encode_response<'u>(
        &self,
        _r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, busbar_contract::wire::Encode> {
        Err(busbar_contract::wire::Encode::Unrepresentable)
    }

    /// The reason, spelled, ON THE ARENA the driver opened: a cell that reads it back is reading a
    /// borrow of the driver's own stack, copied out before the space dropped.
    fn encode_refusal<'u>(
        &self,
        refusal: &PlaneRefusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, busbar_contract::wire::Encode> {
        let spelled = format!("refused:{:?}@{:?}", refusal.reason, refusal.step);
        ctx.arena()
            .alloc_bytes(spelled.as_bytes())
            .map_err(|_| busbar_contract::wire::Encode::ArenaExhausted)
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, busbar_contract::wire::Encode> {
        Ok(None)
    }

    fn authenticate<'u>(
        &self,
        _u: &Unit<'u>,
        _ctx: &Ctx<'u>,
    ) -> busbar_contract::kinds::CredentialLocator {
        busbar_contract::kinds::CredentialLocator::default()
    }

    fn verify<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        DestinationFacts::KernelVerb { verb: "made-up" }
    }

    fn approve<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> busbar_contract::unit::ScopeFacts {
        busbar_contract::unit::ScopeFacts::default()
    }

    fn admit<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> busbar_contract::unit::AdmitFacts {
        busbar_contract::unit::AdmitFacts::default()
    }

    fn route<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> busbar_contract::dest::RoutePlan {
        busbar_contract::dest::RoutePlan::default()
    }

    fn meter<'u>(
        &self,
        _u: &Unit<'u>,
        _r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> busbar_contract::unit::UsageLocators {
        busbar_contract::unit::UsageLocators::default()
    }

    fn audit<'u>(
        &self,
        _u: &Unit<'u>,
        _out: &UnitEnd,
        _ctx: &Ctx<'u>,
    ) -> busbar_contract::unit::AuditFacts {
        busbar_contract::unit::AuditFacts {
            op_class: MADE_UP_OP,
            finish: busbar_contract::FinishClass::Complete,
        }
    }

    fn plane_facts<'u>(
        &self,
        _verb: busbar_contract::ids::AdminVerbId,
        _subject: Option<&'u str>,
        _ctx: &Ctx<'u>,
    ) -> Result<busbar_contract::kinds::PlaneFacts<'u>, busbar_contract::wire::Decode> {
        Err(busbar_contract::wire::Decode::UnsupportedOperation)
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        _r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> busbar_contract::kinds::ContentFacts<'u> {
        busbar_contract::kinds::ContentFacts::default()
    }
}

impl SessionPlane for MadeUpPlane {
    fn open_session<'u>(&self, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Opened { frames: 0 })
    }

    fn open_upstream<'u>(
        &self,
        _dest: &busbar_contract::dest::VerifiedDestination,
        _ctx: &Ctx<'u>,
    ) -> PlaneSessionState {
        PlaneSessionState::new(Opened { frames: 0 })
    }
}

/// The made-up plane's configuration block, which has nothing in it.
struct NoConfig;

impl ConfigView for NoConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

// ── the units, and they are nobody's ────────────────────────────────────────────────────────────

/// One moment the driver asked for a unit for: the session, and whether a draft came with it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Moment {
    session: u64,
    op: Option<OpClassId>,
}

/// A unit set that records what it was asked and either proceeds through every step or refuses at
/// the first.
///
/// What the battery is asking of the loop is not what the steps decide — that is the kernel's own
/// batteries' question — but WHICH UNIT the driver opened, WHAT IDENTITY it carried, and WHAT the
/// plane was handed back to render. The proceeding arm answers every step with the emptiest value
/// the step accepts, so a unit that completes did so on the loop's own ordering and nothing here.
#[derive(Default)]
struct RecordingUnits {
    /// Refuse every unit at Arrival, including the opening one.
    refuse: bool,
    /// Refuse the units frames open, and let the opening one through.
    refuse_after_open: bool,
    /// The moments the driver asked for a unit for, in order.
    moments: Mutex<Vec<Moment>>,
    /// One entry per unit the loop opened, in order: the session identity it carried.
    seen: Mutex<Vec<Option<busbar_caps::SessionId>>>,
    /// How many times the driver said a session was over.
    closed: Mutex<Vec<u64>>,
}

impl RecordingUnits {
    fn refusing() -> Self {
        RecordingUnits {
            refuse: true,
            ..RecordingUnits::default()
        }
    }

    fn refusing_frames() -> Self {
        RecordingUnits {
            refuse_after_open: true,
            ..RecordingUnits::default()
        }
    }

    fn moments(&self) -> Vec<Moment> {
        self.moments.lock().expect("the log").clone()
    }

    /// The session identity each unit carried, in the order the units ran.
    fn sessions(&self) -> Vec<Option<busbar_caps::SessionId>> {
        self.seen.lock().expect("the log").clone()
    }

    fn closed(&self) -> Vec<u64> {
        self.closed.lock().expect("the log").clone()
    }
}

/// The unit one moment runs as: the recorder, told whether to refuse.
struct OneMoment<'a> {
    log: &'a RecordingUnits,
    refuse: bool,
}

impl SessionUnits for RecordingUnits {
    fn unit<'f>(&'f self, read: &SessionRead<'_, '_>) -> Box<dyn Units + 'f> {
        self.moments.lock().expect("the log").push(Moment {
            session: read.session,
            op: read.draft.map(|d| d.op),
        });
        Box::new(OneMoment {
            log: self,
            refuse: self.refuse || (self.refuse_after_open && read.draft.is_some()),
        })
    }

    fn closed(&self, session: u64) {
        self.closed.lock().expect("the log").push(session);
    }
}

impl Units for OneMoment<'_> {
    fn arrival(&self, token: &UnitToken<Arrival>, ctx: &UnitCtx) -> Decision<Arrival> {
        self.log.seen.lock().expect("the log").push(ctx.session);
        if self.refuse {
            // NoDestination, because it is the one reason code that maps to a word of its own
            // (`NotFound`) rather than into the catch-all: a cell that asserted `Unavailable` would
            // be asserting the same value the loop answers when nothing ran at all.
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }
        Decision::proceed(
            token,
            ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: vec!["ws"],
            },
        )
    }

    fn decode(&self, token: &UnitToken<Decode>, _c: &UnitCtx) -> Decision<Decode> {
        Decision::proceed(token, MADE_UP_OP)
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _c: &UnitCtx,
    ) -> Decision<Authenticate> {
        Decision::proceed(token, Authenticated::Principal(PrincipalId::new("made-up")))
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        _trust: &TrustToken,
        _c: &UnitCtx,
        _p: &PrincipalId,
    ) -> Decision<Verify> {
        Decision::proceed(token, Vec::new())
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        _c: &UnitCtx,
        _p: &PrincipalId,
        _d: &[VerifiedDestination],
    ) -> Decision<Approve> {
        Decision::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        _a: &AdmitToken<Admit>,
        _c: &UnitCtx,
        _p: &PrincipalId,
        _d: &[VerifiedDestination],
        _l: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        Decision::proceed(token, Admission::ZeroHold)
    }

    fn route(&self, token: &UnitToken<Route>, _c: &UnitCtx, _m: &AccrualMeter) -> Decision<Route> {
        Decision::proceed(token, RoutePlan::default())
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _c: &UnitCtx,
        _p: &busbar_caps::Outcome,
    ) -> Decision<Meter> {
        match Usage::report(usage, Vec::new()) {
            Ok(report) => Decision::proceed(token, report),
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::ArenaBudget)),
        }
    }

    fn audit(
        &self,
        token: &UnitToken<Audit>,
        _c: &UnitCtx,
        _o: &busbar_caps::Outcome,
    ) -> Decision<Audit> {
        Decision::proceed(
            token,
            AuditFacts {
                op_class: MADE_UP_OP,
                finish: busbar_contract::FinishClass::Complete,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        Decision::proceed(
            token,
            AuditFacts {
                op_class: MADE_UP_OP,
                finish: busbar_contract::FinishClass::Error,
            },
        )
    }

    /// The bytes that leave, and a REFUSED unit has some: this is the door the loop renders a
    /// refusal through. The fixture answers with an empty frame, because what a refusal LOOKS like
    /// is the plane's — and the driver asks the plane, not this step.
    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _c: &UnitCtx,
        _o: &busbar_caps::Outcome,
    ) -> Decision<Encode> {
        Decision::proceed(
            token,
            busbar_contract::wire::Frame {
                direction: busbar_contract::wire::Direction::Outbound,
                stream: busbar_contract::ids::StreamId(0),
                bytes: busbar_contract::bounded::SlabBytes::new(std::sync::Arc::from(
                    [].as_slice(),
                )),
                meta: busbar_contract::wire::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

/// Everything one driver is composed over, held together so a cell can borrow all of it at once.
struct Node {
    kernel: busbar_kernel::teller::Kernel,
    units: RecordingUnits,
    plane: MadeUpPlane,
    config: NoConfig,
    gauge: ConcurrencyGauge,
    canary: busbar_caps::Canary,
}

impl Node {
    fn new() -> Self {
        Node::over(RecordingUnits::default())
    }

    fn over(units: RecordingUnits) -> Self {
        Node {
            kernel: crate::root::kernel::new_kernel(),
            units,
            plane: MadeUpPlane,
            config: NoConfig,
            gauge: ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
        }
    }

    fn driver(&self) -> SessionLoopDriver<'_, RecordingUnits> {
        SessionLoopDriver::new(
            &self.kernel,
            &self.units,
            &self.plane,
            &self.config,
            &self.gauge,
            &self.canary,
        )
    }

    /// The moments the driver asked for, as (session, had a draft).
    fn moments(&self) -> Vec<(u64, bool)> {
        self.units
            .moments()
            .into_iter()
            .map(|m| (m.session, m.op.is_some()))
            .collect()
    }
}

/// The upgrade one made-up caller arrives with.
fn upgrade<'a>(
    binding: &'static str,
    bar: Bar,
    facts: &'a [(&'a str, &'a str)],
) -> SessionOpen<'a> {
    SessionOpen {
        facts,
        transport: "ws",
        chain: &["tcp", "ws"],
        binding,
        bar,
    }
}

/// One inbound frame, at an ordinal, carrying a word the made-up reader knows.
fn frame(seq: u64, payload: &'static [u8]) -> SessionFrame<'static> {
    SessionFrame { payload, seq }
}

/// An ending the far side caused.
const CLIENT_WENT: SessionEnd = SessionEnd {
    cut: Cut::Client,
    reason: CloseReason::PeerClosed,
};

/// The credentialed upgrade on the run binding, opened.
fn open_run(driver: &SessionLoopDriver<'_, RecordingUnits>) -> SessionHandle {
    driver
        .open(
            upgrade(
                RUN_BINDING,
                Bar::Credential,
                &[(tfacts::CREDENTIAL, "token")],
            ),
            &RUN_SURFACE,
        )
        .expect("the credential satisfies the declared bar and the opening unit completes")
}

// ── the bar, and what it costs to refuse ────────────────────────────────────────────────────────

/// A DECLARED BAR WITH NOTHING TO SATISFY IT IS REFUSED, AND NOTHING IS ALLOCATED.
///
/// The ordering is the security property rather than an optimisation: a stranger who can make this
/// node carve out a session's state before presenting anything is a stranger choosing how much of
/// this node's memory an unauthenticated upgrade occupies. So the cell asks the count as well as the
/// answer — "nothing was allocated" asserted against the absence of a crash is not asserted at all —
/// and asks the units too: not even the opening unit ran.
#[test]
fn a_declared_bar_with_no_credential_refuses_before_anything_is_allocated() {
    let node = Node::new();
    let driver = node.driver();

    let refused = driver.open(upgrade(RUN_BINDING, Bar::Credential, &[]), &RUN_SURFACE);

    assert_eq!(refused, Err(Outcome::Unauthenticated));
    assert_eq!(driver.open_sessions(), 0);
    assert!(
        node.moments().is_empty(),
        "no unit was asked for, not even the opening one"
    );
}

/// A BLANK CREDENTIAL DOES NOT SATISFY THE BAR.
///
/// The mount publishes the key only where the upgrade actually presented one, so an empty value
/// means a credential was presented and is blank — which no chain can resolve. Admitting it would
/// open the session and then refuse every unit on it, which is a worse answer arrived at later on a
/// wire with nowhere left to put it.
#[test]
fn a_blank_credential_does_not_satisfy_a_declared_bar() {
    let node = Node::new();
    let driver = node.driver();

    let refused = driver.open(
        upgrade(RUN_BINDING, Bar::Credential, &[(tfacts::CREDENTIAL, "")]),
        &RUN_SURFACE,
    );

    assert_eq!(refused, Err(Outcome::Unauthenticated));
    assert_eq!(driver.open_sessions(), 0);
    assert!(node.moments().is_empty());
}

/// A DECLARED OPEN BINDING OPENS WITHOUT ONE, because "open" is a declaration and not an omission —
/// and what opened it is THE OPENING UNIT, run at the upgrade, carrying the session's identity and
/// no draft, because no frame carries an upgrade.
#[test]
fn a_declared_open_binding_opens_with_no_credential_on_its_opening_unit() {
    let node = Node::new();
    let driver = node.driver();

    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the binding is declared open");

    assert_eq!(driver.open_sessions(), 1);
    assert_eq!(
        node.moments(),
        vec![(session.0, false)],
        "one moment, and it had no draft"
    );
    assert_eq!(
        node.units.sessions(),
        vec![Some(node.kernel.session_id(session.0))],
        "the opening unit carried the session's identity"
    );
}

/// AN OPENING UNIT THAT DOES NOT COMPLETE IS THE UPGRADE'S REFUSAL, in the loop's own word, and the
/// session is not in the table — the plane's client half was opened on the stack and dropped there.
///
/// The one moment a refusal is still answerable on the wire, and the loop is what answers it: the
/// stub refuses at Arrival with the one reason that has a word of its own, and that word is what the
/// upgrade gets. The units are told the session is over exactly as they would be for a close, so a
/// wait the opening unit entered does not outlive an upgrade that was never answered yes.
#[test]
fn an_opening_unit_that_does_not_complete_refuses_the_upgrade_and_leaves_nothing() {
    let node = Node::over(RecordingUnits::refusing());
    let driver = node.driver();

    let refused = driver.open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE);

    assert_eq!(
        refused,
        Err(Outcome::NotFound),
        "the loop's own ending is the answer"
    );
    assert_eq!(driver.open_sessions(), 0, "nothing was left in the table");
    assert_eq!(
        node.moments().len(),
        1,
        "the opening unit was asked for, once"
    );
    assert_eq!(
        node.units.closed().len(),
        1,
        "and the units were told it was over, once"
    );
}

// ── the shape is the PLANE'S ROW'S answer ───────────────────────────────────────────────────────

/// WHAT THE DRIVER READS OFF THE ROW, and it is the plane's answer rather than this driver's.
///
/// A run and its declared media for a binding a declared streaming duplex operation dispatches
/// over; nothing for a binding nothing dispatches over. That is the whole of what this driver knows
/// about any plane.
#[test]
fn whether_a_binding_declares_a_run_and_its_media_is_read_off_the_row() {
    assert_eq!(declared_run(&RUN_SURFACE, RUN_BINDING), Some(MADE_UP_MEDIA));
    assert!(declares_a_run(&OPEN_SURFACE, OPEN_BINDING));
    assert_eq!(declared_run(&RUN_SURFACE, UNDECLARED_BINDING), None);
}

/// THERE IS ONLY EVER ONE SHAPE, AND THIS IS WHY: the boot check refuses the other one.
///
/// The reason the driver has no `match` over the answering word, quoted from the contract rather
/// than re-derived here. A duplex row that declared its answer unary would be a session cut at its
/// first answer, and [`check_surface`] refuses the whole surface before any listener binds — so
/// there is no mountable binding a second arm could ever serve, and `declared_run` reads the word
/// as a CONDITION rather than as a switch.
#[test]
fn a_duplex_row_that_is_not_a_run_never_reaches_a_mount_at_all() {
    assert!(
        check_surface(&UNARY_SURFACE).is_err(),
        "the boot check refuses it"
    );
    assert!(
        !declares_a_run(&UNARY_SURFACE, OPEN_BINDING),
        "and this driver would not run it either"
    );
}

/// AN UPGRADE ON A BINDING WITH NO DECLARED BEHAVIOUR IS REFUSED, on the leg that can still carry a
/// refusal, rather than opened onto a shape the composition root picked — and before any unit runs.
#[test]
fn an_upgrade_on_a_binding_nothing_dispatches_over_is_refused() {
    let node = Node::new();
    let driver = node.driver();

    let refused = driver.open(
        upgrade(
            UNDECLARED_BINDING,
            Bar::Credential,
            &[(tfacts::CREDENTIAL, "token")],
        ),
        &RUN_SURFACE,
    );

    assert_eq!(refused, Err(Outcome::NotFound));
    assert_eq!(driver.open_sessions(), 0);
    assert!(
        node.moments().is_empty(),
        "the row said no before any unit was asked for"
    );
}

// ── the plane call ──────────────────────────────────────────────────────────────────────────────

/// A DECLARED RUN OPENS ONE UNIT PER FRAME THE PLANE READS AS ONE, AND EVERY ONE CARRIES THIS
/// SESSION'S IDENTITY AND THE PLANE'S DRAFT.
///
/// The money half of the seam, and the reason the identity is asserted rather than the count alone:
/// a posting and an audit link filed under `None` is a frame of a session attributed to nobody, and
/// a session's records that do not share an identity are not a chain. The draft is asserted too,
/// because it is what makes the unit the PLANE's reading of the frame rather than the driver's.
#[test]
fn a_declared_run_opens_one_unit_per_frame_under_one_session_identity() {
    let node = Node::new();
    let driver = node.driver();
    let session = open_run(&driver);

    for seq in 0..3 {
        let reply = driver.drive(session, frame(seq, OPENS_A_UNIT));
        assert_eq!(
            reply.outcome,
            Outcome::Completed,
            "the loop ran the unit to its end"
        );
        assert!(
            reply.frames.is_empty(),
            "a completed unit on this path has no reply to relay"
        );
        assert_eq!(reply.media, "", "and no media beside no frame");
        assert_eq!(reply.close, None, "a frame does not end the session");
    }

    assert_eq!(
        node.moments(),
        vec![
            (session.0, false),
            (session.0, true),
            (session.0, true),
            (session.0, true)
        ],
        "the opening unit, then one unit per frame, each with the plane's draft"
    );
    assert_eq!(
        node.units.sessions(),
        vec![Some(node.kernel.session_id(session.0)); 4],
        "four units, one session identity"
    );
}

/// A REFUSED UNIT'S ANSWER IS THE PLANE'S OWN RENDERING, UNDER THE DECLARED MEDIA.
///
/// The loop refused, and what went out is what the PLANE wrote for that refusal — the reason and
/// the step, in the fixture's spelling, allocated on the arena this driver opened for the frame —
/// labelled with the media the declaration named. A driver that spelled a refusal itself would have
/// a wire shape of its own, which is the one thing a driver with no plane's name in it cannot have.
#[test]
fn a_refused_units_answer_is_the_planes_own_rendering_under_the_declared_media() {
    let node = Node::over(RecordingUnits::refusing_frames());
    let driver = node.driver();
    let session = open_run(&driver);

    let reply = driver.drive(session, frame(0, OPENS_A_UNIT));

    assert_eq!(
        reply.outcome,
        Outcome::NotFound,
        "the loop's ending, in the eight words"
    );
    assert_eq!(
        reply.frames,
        vec![b"refused:NoDestination@Arrival".to_vec()],
        "the plane's rendering of the loop's refusal, copied off the frame's arena"
    );
    assert_eq!(
        reply.media, MADE_UP_MEDIA,
        "under the media the row declares"
    );
    assert_eq!(reply.close, None);
}

/// A FRAME THE PLANE CANNOT READ IS ANSWERED WITH THE PLANE'S DECODE REFUSAL, AND RUNS NO UNIT.
///
/// There is nothing to run: the reading is the unit's whole content and there is none. The codec
/// state is lent immutably for the rendering, which is the contract's rule — a refusal never
/// advances codec state — and the session carries on.
#[test]
fn a_frame_the_plane_cannot_read_is_refused_in_the_planes_dialect_and_runs_no_unit() {
    let node = Node::new();
    let driver = node.driver();
    let session = open_run(&driver);

    let reply = driver.drive(session, frame(0, b"gibberish"));

    assert_eq!(reply.outcome, Outcome::Unavailable);
    assert_eq!(reply.frames, vec![b"refused:DecodeFailed@Decode".to_vec()]);
    assert_eq!(reply.media, MADE_UP_MEDIA);
    assert_eq!(reply.close, None, "the session carries on");
    assert_eq!(node.moments().len(), 1, "only the opening unit ever ran");

    // And the next frame is read against the SAME session, in order.
    let next = driver.drive(session, frame(1, OPENS_A_UNIT));
    assert_eq!(next.outcome, Outcome::Completed);
}

/// A FRAME THAT OPENS NO UNIT IS CONSUMED QUIETLY: no unit, no frame back, and NO MEDIA — a media
/// type beside an empty run would be this driver saying what the answer is when there is none.
#[test]
fn a_frame_that_opens_no_unit_is_consumed_with_no_unit_and_no_media() {
    let node = Node::new();
    let driver = node.driver();
    let session = open_run(&driver);

    let reply = driver.drive(session, frame(0, NOT_YET_A_UNIT));

    assert_eq!(reply, SessionReply::quiet(Outcome::Completed));
    assert_eq!(node.moments().len(), 1, "only the opening unit ran");
}

/// THE CODEC STATE THE PLANE OPENED IS THE SESSION'S, AND EVERY FRAME READS AGAINST IT.
///
/// The made-up plane counts the frames it has read in the state it opened at the upgrade, and a
/// reader handed a fresh state per frame would refuse the fourth read exactly as it refused the
/// first — which is to say, not at all. So the cell drives past the point the plane's own state
/// makes a difference: the state is opened once, handed back on every frame, and the plane's count
/// is what makes the session's frames a session rather than four arrivals.
#[test]
fn the_planes_codec_state_is_held_across_the_sessions_frames() {
    let node = Node::new();
    let driver = node.driver();
    let session = open_run(&driver);

    for seq in 0..4 {
        assert_eq!(
            driver.drive(session, frame(seq, NOT_YET_A_UNIT)),
            SessionReply::quiet(Outcome::Completed)
        );
    }
    // The plane's reader refuses a frame with no state at all — so four quiet reads are four reads
    // against a state that was there every time.
    assert_eq!(node.moments().len(), 1);
}

// ── the ordinal, and the handle ─────────────────────────────────────────────────────────────────

/// A FRAME OUT OF ORDER STOPS THE SESSION rather than being read against the wrong state.
///
/// The violation that is otherwise SILENT: a duplex plane reads frame *n* against what frame *n-1*
/// left behind, so an out-of-order delivery produces a different, quietly wrong reading rather than
/// an error — for the rest of the session, in both directions. `Poisoned` is this node saying the
/// fault was its own, which it is: the transport made a claim about its own delivery and it was
/// wrong.
#[test]
fn a_frame_out_of_order_ends_the_session_and_runs_no_unit() {
    let node = Node::new();
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the binding is declared open");

    let jumped = driver.drive(session, frame(7, OPENS_A_UNIT));

    assert_eq!(jumped.outcome, Outcome::Unavailable);
    assert_eq!(jumped.close, Some(CloseReason::Poisoned));
    assert_eq!(
        node.moments().len(),
        1,
        "the frame was never read, so no unit was opened for it — only the opening unit ran"
    );
}

/// A HANDLE NEVER MINTED AND ONE ALREADY CLOSED ARE THE SAME ANSWER, and neither runs a unit.
///
/// They should be: a frame for a session that is over is a frame with nothing to read it against,
/// and so is a frame for one that never began. Carrying on would mean inventing a session.
#[test]
fn a_handle_this_driver_does_not_hold_is_not_a_session() {
    let node = Node::new();
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the binding is declared open");

    let never_minted = driver.drive(SessionHandle(9_999), frame(0, OPENS_A_UNIT));
    driver.close(session, CLIENT_WENT);
    let after_close = driver.drive(session, frame(0, OPENS_A_UNIT));

    for reply in [&never_minted, &after_close] {
        assert_eq!(reply.outcome, Outcome::NotFound);
        assert_eq!(reply.close, Some(CloseReason::TransportFailed));
    }
    assert_eq!(node.moments().len(), 1, "neither ran a unit");
}

/// CLOSE RELEASES EXACTLY ONCE, TELLS THE UNITS EXACTLY ONCE, and the "exactly" is enforced rather
/// than assumed of the caller.
///
/// The slot is removed under the table's lock, so the second caller of a double close finds nothing
/// and releases nothing. A transport that called it twice on the ugly endings would otherwise
/// double-release precisely the sessions that failed — and tell the units twice that a session
/// whose waits they already ended was over.
#[test]
fn close_releases_exactly_once_and_a_second_close_releases_nothing() {
    let node = Node::new();
    let driver = node.driver();
    let a = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the binding is declared open");
    let b = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the binding is declared open");
    assert_ne!(a, b, "two upgrades are two sessions");
    assert_eq!(driver.open_sessions(), 2);

    driver.close(a, CLIENT_WENT);
    assert_eq!(driver.open_sessions(), 1);
    driver.close(a, CLIENT_WENT);
    assert_eq!(
        driver.open_sessions(),
        1,
        "the second close released nothing"
    );
    driver.close(b, CLIENT_WENT);
    assert_eq!(driver.open_sessions(), 0);
    assert_eq!(
        node.units.closed(),
        vec![a.0, b.0],
        "each session's units told once"
    );
}

/// TWO OPEN SESSIONS KEEP THEIR OWN ORDINALS, THEIR OWN CODEC STATE AND THEIR OWN IDENTITIES.
///
/// One driver serves every session a listener accepts, so a table keyed wrongly would let one
/// caller's frame advance another caller's sequence — which is the out-of-order failure above,
/// arrived at from the inside and attributed to the wrong session.
#[test]
fn two_sessions_do_not_share_an_ordinal_or_an_identity() {
    let node = Node::new();
    let driver = node.driver();
    let a = open_run(&driver);
    let b = open_run(&driver);

    // Interleaved, which is how they really arrive: a's first, b's first, a's second.
    let replies: Vec<SessionReply> = vec![
        driver.drive(a, frame(0, OPENS_A_UNIT)),
        driver.drive(b, frame(0, OPENS_A_UNIT)),
        driver.drive(a, frame(1, OPENS_A_UNIT)),
    ];

    for reply in &replies {
        assert_eq!(reply.close, None, "every ordinal was the one expected");
    }
    let a_id = Some(node.kernel.session_id(a.0));
    let b_id = Some(node.kernel.session_id(b.0));
    assert_eq!(
        node.units.sessions(),
        vec![a_id, b_id, a_id, b_id, a_id],
        "two opening units, then each frame's unit under its own session's identity"
    );
}

/// THE DRIVER NAMES NO PLANE, and this file is where that is checkable.
///
/// Every cell above drove a surface no plane in this tree declares, through a plane that does not
/// exist, over units that are nobody's. The one string in the fixtures that is not invented is a
/// wire's registry key, which the declaration carries as DATA. A driver that had a plane's name in
/// it could not have served any of them.
#[test]
fn the_driver_serves_a_surface_no_plane_in_this_tree_declares() {
    let node = Node::new();
    let driver = node.driver();
    assert_eq!(
        format!("{driver:?}"),
        "SessionLoopDriver",
        "it could not say whose sessions it just ran, because it has no way to ask"
    );
    assert!(driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .is_ok());
}

/// THE ROOT'S OWN UNIT SET, WITH NO SESSION UNITS COMPOSED, REFUSES A DECLARED RUN AS UNCLAIMED.
///
/// `ProductionUnits` carries the composed session units as data, and a node that composed none is
/// a node that mounted no duplex plane: its opening unit is judged by the root's own steps, which
/// refuse a unit no plane claimed — the same answer the one-shot driver gets from the same struct.
/// That is the composition gate the arena note named, closed from the honest side: nothing runs
/// until something is composed, and what is composed is a value.
#[cfg(feature = "root-admin")]
#[test]
fn the_roots_own_units_with_nothing_composed_refuse_a_declared_run() {
    let units = crate::root::kernel::ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ));
    let kernel = crate::root::kernel::new_kernel();
    let gauge = ConcurrencyGauge::new();
    let canary = busbar_caps::Canary::new();
    let driver = SessionLoopDriver::new(&kernel, &units, &MadeUpPlane, &NoConfig, &gauge, &canary);

    let refused = driver.open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE);

    assert_eq!(
        refused,
        Err(Outcome::NotFound),
        "the root's arrival step refuses a unit no plane claimed, and that is the upgrade's answer"
    );
    assert_eq!(driver.open_sessions(), 0);
}
