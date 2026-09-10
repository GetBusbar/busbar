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

use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Authenticated, Decision, Decode, Encode, Meter, OpClassId, PrincipalId, ReasonCode, Refusal,
    Route, RoutePlan, ScopeFacts, TrustToken, UnitToken, Usage, UsageToken, VerifiedDestination,
    Verify,
};
use busbar_contract::bounded::{ArenaBytes, Facts, Ir};
use busbar_contract::dest::{
    DestinationFacts, EgressBody, VerifiedDestination as PlaneDestination,
};
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
/// A frame of an already-open unit: not a new unit, a WRITE on the leg the open one sealed.
const RELAYS_A_FRAME: &[u8] = b"relay";
/// The end of the open unit, which is what finishes the leg.
const ENDS_THE_UNIT: &[u8] = b"end";
/// What a made-up PROVIDER says back down the leg: one response frame of the open exchange.
const A_PROVIDER_REPLY: &[u8] = b"reply";

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
            RELAYS_A_FRAME => Ok(Ingress::Frame {
                for_: None,
                relay: ArenaBytes::new(RELAYS_A_FRAME),
                facts: Box::new(Facts::new()),
            }),
            ENDS_THE_UNIT => Ok(Ingress::Close {
                for_: None,
                facts: Box::new(Facts::new()),
            }),
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

    /// The relay, as this made-up plane spells it: the unit's key and the bytes it was handed.
    ///
    /// The KEY is in the output on purpose. What the cells beside this are holding is that the view
    /// the driver builds carries the identity of the unit that SEALED the leg — not a fresh one
    /// minted at write time — and the only way to observe that from outside the kernel is to have
    /// the plane write it down.
    fn encode_ingress_frame<'u>(
        &self,
        u: &Unit<'u>,
        f: &Frame,
        _dest: &busbar_contract::dest::VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, busbar_contract::wire::Encode> {
        // The upstream half's state is the leg's own, and a plane handed a fresh one per frame
        // would be a composition that kept none.
        let opened = st
            .and_then(|s| s.get_mut::<Opened>())
            .ok_or(busbar_contract::wire::Encode::Unrepresentable)?;
        opened.frames += 1;
        let spelled = format!(
            "up:{}:{}:{}",
            u.key().get(),
            opened.frames,
            String::from_utf8_lossy(f.bytes.as_slice())
        );
        ctx.arena()
            .alloc_bytes(spelled.as_bytes())
            .map(Some)
            .map_err(|_| busbar_contract::wire::Encode::ArenaExhausted)
    }

    /// What the made-up provider said, read against the LEG's own codec state.
    ///
    /// The state is required rather than optional, for the reason the client reader requires one: a
    /// half of a session that was handed a fresh state per frame would be a composition that kept
    /// none, and the cell that reads the counter back out is what holds that.
    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _dest: &busbar_contract::dest::VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, busbar_contract::wire::Decode> {
        let opened = st
            .and_then(|s| s.get_mut::<Opened>())
            .ok_or(busbar_contract::wire::Decode::MissingDeclaredFact)?;
        opened.frames += 1;
        let frame = frames
            .next_frame()
            .ok_or(busbar_contract::wire::Decode::MissingDeclaredFact)?;
        match frame.bytes.as_slice() {
            A_PROVIDER_REPLY => Ok(Progress::Frame {
                for_: None,
                r: Box::new(Response {
                    ir: Ir::new(A_PROVIDER_REPLY, &[]),
                    finish: busbar_contract::FinishClass::Complete,
                    facts: Facts::new(),
                }),
            }),
            NOT_YET_A_UNIT => Ok(Progress::NeedMore),
            _ => Err(busbar_contract::wire::Decode::UnsupportedOperation),
        }
    }

    /// The reply as it goes back to the CLIENT, written against the client half's state.
    ///
    /// The counter is in the output for the same reason the unit key is in the relay's: it is the
    /// only way to observe from outside that the state this was written against is the one the
    /// session accumulated on its client half, rather than the leg's or a fresh one.
    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, busbar_contract::wire::Encode> {
        let opened = st
            .and_then(|s| s.get_mut::<Opened>())
            .ok_or(busbar_contract::wire::Encode::Unrepresentable)?;
        opened.frames += 1;
        let spelled = format!(
            "down:{}:{}",
            opened.frames,
            String::from_utf8_lossy(r.ir.body())
        );
        ctx.arena()
            .alloc_bytes(spelled.as_bytes())
            .map_err(|_| busbar_contract::wire::Encode::ArenaExhausted)
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
        u: &Unit<'u>,
        end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, busbar_contract::wire::Encode> {
        let spelled = format!("end:{}:{end:?}", u.key().get());
        ctx.arena()
            .alloc_bytes(spelled.as_bytes())
            .map(Some)
            .map_err(|_| busbar_contract::wire::Encode::ArenaExhausted)
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
    /// Where this session's units seal their leg to, once a unit has completed. `None` is a session
    /// that relays nothing, which is every session the driver served before this line.
    dest: Option<PlaneDestination>,
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

    fn destination(&self, _session: u64) -> Option<PlaneDestination> {
        self.dest.clone()
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

// ── the upstream leg: relayed under the open unit's view, refused, and never dialled ─────────────

/// A lease that is nobody's: it records what it was offered and answers what it was told to.
struct FakeLease {
    offers: Arc<Mutex<Vec<Vec<u8>>>>,
    finished: Arc<Mutex<bool>>,
    answer: Option<busbar_contract::TransportError>,
}

impl busbar_contract::transport::session::EgressLease for FakeLease {
    fn offer(&mut self, frame: &[u8]) -> Result<(), busbar_contract::TransportError> {
        if let Some(error) = self.answer {
            return Err(error);
        }
        self.offers.lock().expect("the log").push(frame.to_vec());
        Ok(())
    }

    fn finish(&mut self) {
        *self.finished.lock().expect("the log") = true;
    }
}

/// A dialler that is nobody's: it hands back the lease it was built with, or refuses.
struct FakeDialler {
    offers: Arc<Mutex<Vec<Vec<u8>>>>,
    finished: Arc<Mutex<bool>>,
    /// What the LEASE answers an offer with, once it is attached.
    lease_answer: Option<busbar_contract::TransportError>,
    /// What the DIAL itself answers, where it refuses.
    dial_answer: Option<busbar_contract::TransportError>,
    dials: Arc<Mutex<usize>>,
}

impl crate::root::leg_dial::LegDialer for FakeDialler {
    fn dial<'a>(
        &'a self,
        _dest: &'a PlaneDestination,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        crate::root::leg_dial::DialledLeg,
                        busbar_contract::TransportError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            *self.dials.lock().expect("the log") += 1;
            if let Some(error) = self.dial_answer {
                return Err(error);
            }
            let lease = FakeLease {
                offers: Arc::clone(&self.offers),
                finished: Arc::clone(&self.finished),
                answer: self.lease_answer,
            };
            let drain: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
                Box::pin(async {});
            Ok((
                Box::new(lease) as Box<dyn busbar_contract::transport::session::EgressLease>,
                drain,
            ))
        })
    }
}

/// A source that is nobody's: the frames a client would have sent, then the orderly end.
struct Scripted(std::collections::VecDeque<&'static [u8]>);

impl busbar_transport_ws::mount::FrameSource for Scripted {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, busbar_contract::TransportError>> {
        self.0.pop_front().map(|f| Ok(f.to_vec()))
    }
}

/// A destination sealed by the node's own kernel, which is the only thing that may seal one.
///
/// Through `transport_key_token`, a token this kernel already mints for the composition, rather
/// than through a forged seal of this file's own: the construction gate counts every crate that
/// implements the contract's sealing marker, and a battery that added one would be adding to the
/// exact number that rule exists to hold down.
fn sealed_leg(kernel: &busbar_kernel::teller::Kernel) -> PlaneDestination {
    PlaneDestination::seal(
        &kernel.transport_key_token(),
        DestinationFacts::Upstream {
            transport: "ws",
            address: busbar_contract::dest::UpstreamAddress::socket("ws://made.up/leg"),
            lane: busbar_contract::LaneId::new("made-up-lane"),
        },
        "ws",
        None,
    )
}

/// THE RELAY: a frame of an already-open unit is a WRITE on the leg, under the unit's own view.
///
/// Everything the line exists for is in this one cell. A relay frame opens NO unit — the exchange
/// was priced when it opened, and walking the steps again would price it twice — so the moments the
/// units saw are the opening one and nothing more. What happens instead is that the plane is handed
/// the unit as the KERNEL seals it and asked what goes upstream, and what it writes reaches the
/// lease. The key in the plane's output is the key of the unit that SEALED the leg, which is the
/// half of the identity no composition may write for itself.
///
/// The ending is the other half: the plane is handed the sealed end, writes it, and the lease is
/// FINISHED — a leg left un-finished would hold its drain, its socket and its task for the life of
/// the process.
#[tokio::test]
async fn a_relayed_frame_goes_out_under_the_open_units_own_view() {
    let mut node = Node::new();
    node.units.dest = Some(sealed_leg(&node.kernel));
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the declared mount opens");

    let offers = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(Mutex::new(false));
    let dialler = FakeDialler {
        offers: Arc::clone(&offers),
        finished: Arc::clone(&finished),
        lease_answer: None,
        dial_answer: None,
        dials: Arc::new(Mutex::new(0)),
    };

    // The unit that seals the leg.
    assert_eq!(
        driver.drive(session, frame(0, OPENS_A_UNIT)).outcome,
        Outcome::Completed
    );

    // BETWEEN FRAMES: the decorator dials what the unit parked, before the next read.
    let mut source = crate::root::leg_dial::LegDialing::new(
        Scripted(
            [RELAYS_A_FRAME, ENDS_THE_UNIT]
                .into_iter()
                .collect::<std::collections::VecDeque<_>>(),
        ),
        &driver,
        session,
        &dialler,
    );
    let relayed = busbar_transport_ws::mount::FrameSource::next_frame(&mut source)
        .await
        .expect("the client spoke")
        .expect("the read did not fail");
    assert_eq!(
        driver.drive(session, frame(1, RELAYS_A_FRAME)).outcome,
        Outcome::Completed,
        "a relay is not an ending"
    );
    assert_eq!(relayed, RELAYS_A_FRAME.to_vec());

    assert_eq!(
        node.moments(),
        vec![(1, false), (1, true)],
        "the opening unit at the upgrade and the unit the client's first frame opened, and NOTHING \
         for the relay: a relayed frame belongs to a unit that was already priced, and walking the \
         steps again would price one exchange twice"
    );
    let written = offers.lock().expect("the log").clone();
    assert_eq!(
        written,
        vec![b"up:2:1:relay".to_vec()],
        "the plane wrote the relay against the view of the unit that SEALED the leg — key 2, the \
         unit the client's first frame opened (key 1 was the opening unit at the upgrade) — and \
         not a key minted at write time"
    );

    // The ending: the plane writes the sealed end and the leg finishes.
    let _ = busbar_transport_ws::mount::FrameSource::next_frame(&mut source).await;
    let reply = driver.drive(session, frame(2, ENDS_THE_UNIT));
    assert_eq!(reply.outcome, Outcome::Completed);
    let written = offers.lock().expect("the log").clone();
    assert_eq!(written.len(), 2, "the ending went out too");
    assert!(
        written[1].starts_with(b"end:2:"),
        "the ending is encoded against the OPEN unit's view: {}",
        String::from_utf8_lossy(&written[1])
    );
    assert!(
        *finished.lock().expect("the log"),
        "the leg is finished, so its drain, its socket and its task can end with the exchange"
    );
}

/// A LEASE THAT REFUSES ENDS THE SESSION, and the word says which refusal it was.
///
/// At depth the leg has fallen behind and nothing is wrong with the caller, so the answer is
/// `CapacityExhausted` — the same session opened later may well run. Carrying on instead would be a
/// relayed session that silently stopped relaying, for as long as the client kept talking, which is
/// the one outcome worse than an ending.
#[tokio::test]
async fn a_refusing_lease_ends_the_session() {
    let mut node = Node::new();
    node.units.dest = Some(sealed_leg(&node.kernel));
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the declared mount opens");
    let dialler = FakeDialler {
        offers: Arc::new(Mutex::new(Vec::new())),
        finished: Arc::new(Mutex::new(false)),
        lease_answer: Some(busbar_contract::TransportError::Backpressure),
        dial_answer: None,
        dials: Arc::new(Mutex::new(0)),
    };
    driver.drive(session, frame(0, OPENS_A_UNIT));

    let mut source = crate::root::leg_dial::LegDialing::new(
        Scripted([RELAYS_A_FRAME].into_iter().collect()),
        &driver,
        session,
        &dialler,
    );
    let _ = busbar_transport_ws::mount::FrameSource::next_frame(&mut source).await;

    let reply = driver.drive(session, frame(1, RELAYS_A_FRAME));
    assert_eq!(reply.outcome, Outcome::Unavailable);
    assert_eq!(
        reply.close,
        Some(CloseReason::CapacityExhausted),
        "a leg at depth is 'try again later' and not the caller's fault"
    );
}

/// A DIAL THAT FAILS ENDS THE SESSION, and it ends it on the READ rather than on a later frame.
///
/// The pump reads the decorator's `Err` as the session's end, which is the earliest moment the
/// failure can be answered at all. The alternative is what a composition without this decorator
/// would do: read the next frame, find no leg, relay nothing, and carry on — a session that stopped
/// relaying and told nobody.
#[tokio::test]
async fn a_failed_dial_ends_the_session_before_the_next_frame_is_read() {
    let mut node = Node::new();
    node.units.dest = Some(sealed_leg(&node.kernel));
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the declared mount opens");
    let dials = Arc::new(Mutex::new(0));
    let dialler = FakeDialler {
        offers: Arc::new(Mutex::new(Vec::new())),
        finished: Arc::new(Mutex::new(false)),
        lease_answer: None,
        dial_answer: Some(busbar_contract::TransportError::AddressRefused),
        dials: Arc::clone(&dials),
    };
    driver.drive(session, frame(0, OPENS_A_UNIT));

    let mut source = crate::root::leg_dial::LegDialing::new(
        Scripted([RELAYS_A_FRAME].into_iter().collect()),
        &driver,
        session,
        &dialler,
    );
    let read = busbar_transport_ws::mount::FrameSource::next_frame(&mut source).await;
    assert_eq!(
        read,
        Some(Err(busbar_contract::TransportError::AddressRefused)),
        "the read is where a failed dial is answered, and the pump ends the session on it"
    );
    assert_eq!(*dials.lock().expect("the log"), 1, "dialled once, not spun");
}

// ── the leg's inbound half: what the provider says, on its way back to the client ────────────────

/// Attach a dialled leg and a client offering end to an open session, the way the composition does.
///
/// The leg goes on through the DECORATOR rather than by calling `attach_leg` directly, because that
/// is the only path the composition has: a cell that attached one by hand would be proving the
/// driver's half of an arrangement whose other half nothing exercised.
async fn relayed(
    driver: &SessionLoopDriver<'_, RecordingUnits>,
    session: SessionHandle,
    client: FakeLease,
) {
    let dialler = FakeDialler {
        offers: Arc::new(Mutex::new(Vec::new())),
        finished: Arc::new(Mutex::new(false)),
        lease_answer: None,
        dial_answer: None,
        dials: Arc::new(Mutex::new(0)),
    };
    assert_eq!(
        driver.drive(session, frame(0, OPENS_A_UNIT)).outcome,
        Outcome::Completed,
        "the unit that seals the leg"
    );
    let mut source = crate::root::leg_dial::LegDialing::new(
        Scripted(Default::default()),
        driver,
        session,
        &dialler,
    );
    let ended = busbar_transport_ws::mount::FrameSource::next_frame(&mut source).await;
    assert!(
        ended.is_none(),
        "the client said nothing more; the dial ran anyway"
    );
    assert!(
        driver.attach_client(session, Box::new(client)),
        "the session takes its client's offering end"
    );
}

/// A MADE-UP PROVIDER'S REPLY REACHES THE CLIENT, and it reaches it as the PLANE wrote it.
///
/// The whole of the inbound half is in this cell. Bytes arrive off a leg nobody's, the plane reads
/// them against the LEG's codec state, writes them against the CLIENT's, and what it wrote is what
/// the client's offering end was handed. Nothing here spelled a byte and nothing walked a unit: the
/// exchange those bytes answer was priced when it opened, and pricing it again on the way back
/// would price one exchange twice.
///
/// The counter in the plane's output is what makes "against the CLIENT's state" checkable: the
/// client half had already read the frame that opened the unit, so its second write is `2`. A
/// composition that handed the reply the leg's state, or a fresh one, could not produce that number.
#[tokio::test]
async fn a_made_up_providers_reply_reaches_the_client() {
    let mut node = Node::new();
    node.units.dest = Some(sealed_leg(&node.kernel));
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the declared mount opens");

    let downstream = Arc::new(Mutex::new(Vec::new()));
    let finished = Arc::new(Mutex::new(false));
    relayed(
        &driver,
        session,
        FakeLease {
            offers: Arc::clone(&downstream),
            finished: Arc::clone(&finished),
            answer: None,
        },
    )
    .await;

    let end = crate::root::leg_pump::pump_leg(
        &driver,
        session,
        Scripted([A_PROVIDER_REPLY].into_iter().collect()),
    )
    .await;

    assert_eq!(
        downstream.lock().expect("the log").clone(),
        vec![b"down:2:reply".to_vec()],
        "the plane's own rendering of the provider's reply, written against the client half's own \
         codec state, on the client's offering end"
    );
    assert_eq!(
        node.moments(),
        vec![(1, false), (1, true)],
        "the opening unit and the unit the client's frame opened, and NOTHING for the reply"
    );
    assert_eq!(
        end.reason,
        CloseReason::Normal,
        "the provider then finished, which is orderly"
    );
}

/// A PROVIDER THAT CLOSES ENDS THE SESSION, and ends it EXACTLY ONCE.
///
/// A leg with nothing left on it is a relayed session with nothing left to relay, and a node that
/// carried on would be answering a talking client with silence. The "once" is the other half and it
/// is the same "once" a double close is: the client's own pump closes the session it was serving
/// when its read ends, and finding nothing is the answer it should get.
#[tokio::test]
async fn a_provider_close_ends_the_session_once() {
    let mut node = Node::new();
    node.units.dest = Some(sealed_leg(&node.kernel));
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the declared mount opens");
    relayed(
        &driver,
        session,
        FakeLease {
            offers: Arc::new(Mutex::new(Vec::new())),
            finished: Arc::new(Mutex::new(false)),
            answer: None,
        },
    )
    .await;
    assert_eq!(driver.open_sessions(), 1);

    let end = crate::root::leg_pump::pump_leg(&driver, session, Scripted(Default::default())).await;

    assert_eq!(end.cut, Cut::Upstream, "the leg is the end that went");
    assert_eq!(end.reason, CloseReason::Normal);
    assert_eq!(driver.open_sessions(), 0, "the session was released");
    // The client's pump, arriving at the same session a moment later.
    driver.close(session, CLIENT_WENT);
    assert_eq!(
        node.units.closed(),
        vec![session.0],
        "told once, by whichever pump got there first"
    );
    assert_eq!(
        driver.drive(session, frame(1, OPENS_A_UNIT)).close,
        Some(CloseReason::TransportFailed),
        "a frame for a session that is over has nothing to be read against"
    );
}

/// A REPLY THAT CANNOT BE WRITTEN ENDS THE SESSION, in the words the relay ends it in.
///
/// The same posture in both directions, and for the same reason: a client at depth has fallen
/// behind and `CapacityExhausted` says so — nothing is wrong with anybody and the same session
/// opened later may well run. Dropping the reply instead would leave the client waiting on an
/// answer this node had already thrown away.
#[tokio::test]
async fn a_providers_reply_that_cannot_be_written_ends_the_session() {
    let mut node = Node::new();
    node.units.dest = Some(sealed_leg(&node.kernel));
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the declared mount opens");
    relayed(
        &driver,
        session,
        FakeLease {
            offers: Arc::new(Mutex::new(Vec::new())),
            finished: Arc::new(Mutex::new(false)),
            answer: Some(busbar_contract::TransportError::Backpressure),
        },
    )
    .await;

    let end = crate::root::leg_pump::pump_leg(
        &driver,
        session,
        // Two replies, and the cell is that the SECOND is never read: the first ended the session.
        Scripted([A_PROVIDER_REPLY, A_PROVIDER_REPLY].into_iter().collect()),
    )
    .await;

    assert_eq!(
        end.reason,
        CloseReason::CapacityExhausted,
        "a client at depth is 'try again later' and not anybody's fault"
    );
    assert_eq!(driver.open_sessions(), 0);
}
