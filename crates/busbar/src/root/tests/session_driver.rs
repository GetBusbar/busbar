// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERIC SESSION DRIVER, PROVED AGAINST A PLANE THAT DOES NOT EXIST.
//!
//! Every fixture here is invented. Two surfaces below are made-up planes', declared in the ordinary
//! vocabulary with the ordinary duplex kind — one that declares its sessions a RUN and one that
//! declares them a single answer — and the units are a stub that refuses at the first step. There is
//! no dialect, no protocol and no plane name anywhere in this file, and that is the claim under test
//! rather than a stylistic preference: what the driver does, it does for ANY plane, and a battery
//! driving a real one through it would prove only that it works for that one.
//!
//! The questions:
//!
//! * a declared credential bar with nothing to satisfy it refuses BEFORE anything is allocated —
//!   and a blank credential is nothing;
//! * a binding no declared operation dispatches over is refused rather than given a default shape;
//! * whether there is a session here to run at all is the plane's ROW's answer and not this
//!   driver's — and the reason there is only ever ONE shape is the contract's own boot check;
//! * every one of a session's units carries THAT session's identity, which is what links its
//!   postings and its audit records to the session rather than to nobody;
//! * a frame delivered out of ordinal stops the session rather than being read against the wrong
//!   state;
//! * a handle that was never minted, and one already closed, are the same answer;
//! * close releases exactly once, and a second close releases nothing.

use std::sync::Mutex;

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, Audit, AuditFacts, Authenticate, Decision, Decode, Encode,
    Meter, PrincipalId, ReasonCode, Refusal, Route, TrustToken, UnitToken, UsageToken,
    VerifiedDestination, Verify,
};
use busbar_contract::transport::facts as tfacts;
use busbar_contract::transport::session::{
    Cut, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen, SessionReply,
};
use busbar_contract::transport::surface::{
    check_surface, Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};
use busbar_contract::transport::Outcome;
use busbar_contract::wire::CloseReason;
use busbar_kernel::slice::{ConcurrencyGauge, GroupLeaseSlip};
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};

use super::{declares_a_run, SessionLoopDriver};

// ── two planes that do not exist ────────────────────────────────────────────────────────────────

/// The made-up run plane's one duplex binding, carried on the `ws` registry key.
///
/// The key is the only string here that is not invented, and it is not a plane's: it is a wire's own
/// registry entry, and the declaration names it as DATA exactly as a real plane's does.
const RUN_BINDING: &str = "made-up-run";

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
        request_media: "application/json",
        response_media: "application/json",
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
        request_media: "application/json",
        response_media: "application/json",
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
        request_media: "application/json",
        response_media: "application/json",
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

// ── the units, and they are nobody's ────────────────────────────────────────────────────────────

/// A unit set that refuses at the FIRST step and records the context it was asked with.
///
/// Refusing at Arrival is what keeps this file to one screen of double rather than fourteen: a unit
/// refused at Arrival never reaches Decode, so no later step can be reached and none needs a body.
/// What the battery is asking of the loop is not what the steps decide — that is the kernel's own
/// batteries' question — but WHICH UNIT the driver opened and WHAT IDENTITY it carried, and the
/// first step sees both.
#[derive(Default)]
struct RecordingUnits {
    /// One entry per unit the loop opened, in order: the session identity it carried.
    seen: Mutex<Vec<Option<busbar_caps::SessionId>>>,
}

impl RecordingUnits {
    /// The session identity each unit carried, in the order the units ran.
    fn sessions(&self) -> Vec<Option<busbar_caps::SessionId>> {
        self.seen.lock().expect("the log").clone()
    }
}

impl Units for RecordingUnits {
    fn arrival(&self, token: &UnitToken<Arrival>, ctx: &UnitCtx) -> Decision<Arrival> {
        self.seen.lock().expect("the log").push(ctx.session);
        // NoDestination, because it is the one reason code that maps to a word of its own
        // (`NotFound`) rather than into the catch-all: a cell that asserted `Unavailable` would be
        // asserting the same value the loop answers when nothing ran at all.
        Decision::refuse(token, Refusal::new(ReasonCode::NoDestination))
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
                op_class: busbar_caps::OpClassId::new("made-up"),
                finish: busbar_contract::FinishClass::Error,
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }

    // THE STEPS A UNIT REFUSED AT ARRIVAL NEVER REACHES. `unreachable!` rather than a plausible
    // answer, because a body here would be a fixture quietly deciding something the loop's own
    // ordering says cannot happen — and if the ordering ever changed, a plausible answer would hide
    // it and this panics.
    fn decode(&self, _t: &UnitToken<Decode>, _c: &UnitCtx) -> Decision<Decode> {
        unreachable!("a unit refused at Arrival never reaches Decode")
    }

    fn authenticate(&self, _t: &UnitToken<Authenticate>, _c: &UnitCtx) -> Decision<Authenticate> {
        unreachable!("a unit refused at Arrival never reaches Authenticate")
    }

    fn verify(
        &self,
        _t: &UnitToken<Verify>,
        _trust: &TrustToken,
        _c: &UnitCtx,
        _p: &PrincipalId,
    ) -> Decision<Verify> {
        unreachable!("a unit refused at Arrival never reaches Verify")
    }

    fn approve(
        &self,
        _t: &UnitToken<Approve>,
        _c: &UnitCtx,
        _p: &PrincipalId,
        _d: &[VerifiedDestination],
    ) -> Decision<Approve> {
        unreachable!("a unit refused at Arrival never reaches Approve")
    }

    fn admit(
        &self,
        _t: &UnitToken<Admit>,
        _a: &AdmitToken<Admit>,
        _c: &UnitCtx,
        _p: &PrincipalId,
        _d: &[VerifiedDestination],
        _l: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        unreachable!("a unit refused at Arrival never reaches Admit")
    }

    fn route(&self, _t: &UnitToken<Route>, _c: &UnitCtx, _m: &AccrualMeter) -> Decision<Route> {
        unreachable!("a unit refused at Arrival never reaches Route")
    }

    fn meter(
        &self,
        _t: &UnitToken<Meter>,
        _u: &UsageToken,
        _c: &UnitCtx,
        _p: &busbar_caps::Outcome,
    ) -> Decision<Meter> {
        unreachable!("a unit refused at Arrival never reaches Meter")
    }

    fn audit(
        &self,
        _t: &UnitToken<Audit>,
        _c: &UnitCtx,
        _o: &busbar_caps::Outcome,
    ) -> Decision<Audit> {
        unreachable!("a unit refused at Arrival leaves through audit_refused")
    }

    /// The bytes that leave, and a REFUSED unit has some: this is the door the loop renders a
    /// refusal through, which is why it is the one step after Arrival that a refusal really does
    /// reach. The fixture answers with an empty frame, because what a refusal LOOKS like is the
    /// plane's and there is no plane here.
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
}

/// Everything one driver is composed over, held together so a cell can borrow all of it at once.
struct Node {
    kernel: busbar_kernel::teller::Kernel,
    units: RecordingUnits,
    gauge: ConcurrencyGauge,
    canary: busbar_caps::Canary,
}

impl Node {
    fn new() -> Self {
        Node {
            kernel: crate::root::kernel::new_kernel(),
            units: RecordingUnits::default(),
            gauge: ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
        }
    }

    fn driver(&self) -> SessionLoopDriver<'_, RecordingUnits> {
        SessionLoopDriver::new(&self.kernel, &self.units, &self.gauge, &self.canary)
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

/// One inbound frame, at an ordinal.
fn frame(seq: u64) -> SessionFrame<'static> {
    SessionFrame {
        payload: b"{\"made\":\"up\"}",
        seq,
    }
}

/// An ending the far side caused.
const CLIENT_WENT: SessionEnd = SessionEnd {
    cut: Cut::Client,
    reason: CloseReason::PeerClosed,
};

// ── the bar, and what it costs to refuse ────────────────────────────────────────────────────────

/// A DECLARED BAR WITH NOTHING TO SATISFY IT IS REFUSED, AND NOTHING IS ALLOCATED.
///
/// The ordering is the security property rather than an optimisation: a stranger who can make this
/// node carve out a session's state before presenting anything is a stranger choosing how much of
/// this node's memory an unauthenticated upgrade occupies. So the cell asks the count as well as the
/// answer — "nothing was allocated" asserted against the absence of a crash is not asserted at all.
#[test]
fn a_declared_bar_with_no_credential_refuses_before_anything_is_allocated() {
    let node = Node::new();
    let driver = node.driver();

    let refused = driver.open(upgrade(RUN_BINDING, Bar::Credential, &[]), &RUN_SURFACE);

    assert_eq!(refused, Err(Outcome::Unauthenticated));
    assert_eq!(driver.open_sessions(), 0);
    assert!(node.units.sessions().is_empty(), "no unit was opened");
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
}

/// A DECLARED OPEN BINDING OPENS WITHOUT ONE, because "open" is a declaration and not an omission.
#[test]
fn a_declared_open_binding_opens_with_no_credential() {
    let node = Node::new();
    let driver = node.driver();

    assert!(driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .is_ok());
    assert_eq!(driver.open_sessions(), 1);
}

// ── the shape is the PLANE'S ROW'S answer ───────────────────────────────────────────────────────

/// WHAT THE DRIVER READS OFF THE ROW, and it is the plane's answer rather than this driver's.
///
/// True for a binding a declared streaming duplex operation dispatches over, false for a binding
/// nothing dispatches over. That is the whole of what this driver knows about any plane.
#[test]
fn whether_a_binding_declares_a_run_is_read_off_the_row() {
    assert!(declares_a_run(&RUN_SURFACE, RUN_BINDING));
    assert!(declares_a_run(&OPEN_SURFACE, OPEN_BINDING));
    assert!(!declares_a_run(&RUN_SURFACE, UNDECLARED_BINDING));
}

/// THERE IS ONLY EVER ONE SHAPE, AND THIS IS WHY: the boot check refuses the other one.
///
/// The reason the driver has no `match` over the answering word, quoted from the contract rather
/// than re-derived here. A duplex row that declared its answer unary would be a session cut at its
/// first answer, and [`check_surface`] refuses the whole surface before any listener binds — so
/// there is no mountable binding a second arm could ever serve, and `declares_a_run` reads the word
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
/// refusal, rather than opened onto a shape the composition root picked.
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
}

/// A DECLARED RUN OPENS ONE UNIT PER FRAME, AND EVERY ONE CARRIES THIS SESSION'S IDENTITY.
///
/// The money half of the seam, and the reason the identity is asserted rather than the count alone:
/// a posting and an audit link filed under `None` is a frame of a session attributed to nobody, and
/// a session's records that do not share an identity are not a chain.
#[test]
fn a_declared_run_opens_one_unit_per_frame_under_one_session_identity() {
    let node = Node::new();
    let driver = node.driver();
    let session = driver
        .open(
            upgrade(
                RUN_BINDING,
                Bar::Credential,
                &[(tfacts::CREDENTIAL, "token")],
            ),
            &RUN_SURFACE,
        )
        .expect("the credential satisfies the declared bar");

    for seq in 0..3 {
        let reply = driver.drive(session, frame(seq));
        // The ending is the LOOP's, carried out rather than invented: the stub refuses at Arrival
        // with the one reason code that has a word of its own.
        assert_eq!(reply.outcome, Outcome::NotFound);
        assert!(reply.frames.is_empty(), "no plane was asked");
        assert_eq!(reply.close, None, "a bad frame does not end the session");
    }

    assert_eq!(
        node.units.sessions(),
        vec![Some(node.kernel.session_id(session.0)); 3],
        "three frames, three units, one session identity"
    );
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

    let jumped = driver.drive(session, frame(7));

    assert_eq!(jumped.outcome, Outcome::Unavailable);
    assert_eq!(jumped.close, Some(CloseReason::Poisoned));
    assert!(
        node.units.sessions().is_empty(),
        "the frame was never read, so no unit was opened for it"
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

    let never_minted = driver.drive(SessionHandle(9_999), frame(0));
    driver.close(session, CLIENT_WENT);
    let after_close = driver.drive(session, frame(0));

    for reply in [&never_minted, &after_close] {
        assert_eq!(reply.outcome, Outcome::NotFound);
        assert_eq!(reply.close, Some(CloseReason::TransportFailed));
    }
    assert!(node.units.sessions().is_empty(), "neither ran a unit");
}

/// CLOSE RELEASES EXACTLY ONCE, and the "exactly" is enforced rather than assumed of the caller.
///
/// The slot is removed under the table's lock, so the second caller of a double close finds nothing
/// and releases nothing. A transport that called it twice on the ugly endings would otherwise
/// double-release precisely the sessions that failed.
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
}

/// TWO OPEN SESSIONS KEEP THEIR OWN ORDINALS AND THEIR OWN IDENTITIES.
///
/// One driver serves every session a listener accepts, so a table keyed wrongly would let one
/// caller's frame advance another caller's sequence — which is the out-of-order failure above,
/// arrived at from the inside and attributed to the wrong session.
#[test]
fn two_sessions_do_not_share_an_ordinal_or_an_identity() {
    let node = Node::new();
    let driver = node.driver();
    let a = driver
        .open(
            upgrade(
                RUN_BINDING,
                Bar::Credential,
                &[(tfacts::CREDENTIAL, "token")],
            ),
            &RUN_SURFACE,
        )
        .expect("the credential satisfies the declared bar");
    let b = driver
        .open(
            upgrade(
                RUN_BINDING,
                Bar::Credential,
                &[(tfacts::CREDENTIAL, "token")],
            ),
            &RUN_SURFACE,
        )
        .expect("the credential satisfies the declared bar");

    // Interleaved, which is how they really arrive: a's first, b's first, a's second.
    let replies: Vec<SessionReply> = vec![
        driver.drive(a, frame(0)),
        driver.drive(b, frame(0)),
        driver.drive(a, frame(1)),
    ];

    for reply in &replies {
        assert_eq!(reply.close, None, "every ordinal was the one expected");
    }
    assert_eq!(
        node.units.sessions(),
        vec![
            Some(node.kernel.session_id(a.0)),
            Some(node.kernel.session_id(b.0)),
            Some(node.kernel.session_id(a.0))
        ],
        "each frame's unit carried its own session's identity"
    );
}

/// THE DRIVER NAMES NO PLANE, and this file is where that is checkable.
///
/// Every cell above drove a surface no plane in this tree declares, over units that are nobody's.
/// The one string in the fixtures that is not invented is a wire's registry key, which the
/// declaration carries as DATA. A driver that had a plane's name in it could not have served either.
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
    // Refused at Arrival by units that know nothing of any plane either.
    assert_eq!(
        driver.drive(SessionHandle(1), frame(0)).outcome,
        Outcome::NotFound
    );
}

/// THE STEPS the frames' units are judged by are the NODE'S OWN, and the double proves the loop ran
/// rather than that this driver answered.
///
/// Read together with the cell above: `RecordingUnits` refuses at the loop's first step, so a reply
/// carrying that refusal's word is a reply the LOOP produced. A driver that had answered on its own
/// account would answer the same way with no units at all.
#[test]
fn the_reply_carries_the_loops_own_ending_and_not_this_drivers() {
    let node = Node::new();
    let driver = node.driver();
    let session = driver
        .open(upgrade(OPEN_BINDING, Bar::Open, &[]), &OPEN_SURFACE)
        .expect("the binding is declared open");

    let reply = driver.drive(session, frame(0));

    assert_eq!(node.units.sessions().len(), 1, "the loop ran");
    assert_eq!(
        reply.outcome,
        Outcome::NotFound,
        "and its ending is what came back"
    );
}

// ── THROWAWAY RIG (slot A1): a frame reaches a PLANE's unit over the shipping arena ─────────────
//
// NOT FOR LANDING. Everything above this line names no plane and must stay that way; the module
// below is a rig on the arena tip proving ONE thing: with a real per-unit arena, a driver-shaped
// path can build the contract `Ctx` around an inbound frame, hand the frame to a plane, get the
// plane's UNIT back, run the loop for that frame, and hand back an answer the plane rendered out of
// the same arena. `drive` still answers an empty frame on its own; the rig makes the two calls
// around it that the plane-call commit will fold in, and the arena is the only new thing between
// the two.
#[cfg(feature = "plane-voice")]
mod rig {
    use super::*;
    use busbar_contract::bounded::{Arena as _, Labels, SlabBytes};
    use busbar_contract::ids::{LaneId, StreamId};
    use busbar_contract::plane::{Ingress, Plane, PlaneSessionState};
    use busbar_contract::unit::{Clock, ConfigView, Ctx, RefusalReason, Step, TransportView};
    use busbar_contract::wire::{Direction, Frame, FrameCursor, FrameMeta};
    use busbar_plane_voice::claims::Dialect;
    use busbar_plane_voice::session::VoiceSessionState;
    use busbar_plane_voice::{Upstream, VoicePlane};

    use crate::root::arena::{ArenaSpace, UnitArena, ARENA_BYTES};

    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("voice-realtime"),
        host: "api.openai.com",
        dialect: Dialect::OpenaiRealtime,
    }];

    /// A plugin's own block, for a call not told which plugin it is for: every key answers `None`.
    struct NoConfig;

    impl ConfigView for NoConfig {
        fn get_str(&self, _: &str) -> Option<&str> {
            None
        }
        fn get_int(&self, _: &str) -> Option<i64> {
            None
        }
        fn get_bool(&self, _: &str) -> Option<bool> {
            None
        }
    }

    /// The stack under the rig's upgrade, as the plane reads it.
    struct RigTransport;

    impl TransportView for RigTransport {
        fn key(&self) -> &'static str {
            "ws"
        }
        fn chain(&self) -> &[&'static str] {
            &["tcp", "ws"]
        }
        fn fact(&self, _: &str) -> Option<&str> {
            None
        }
    }

    /// ONE FRAME IN, THE PLANE'S UNIT OUT, THE LOOP RUN, THE PLANE'S ANSWER BACK — over one
    /// `ArenaSpace` on this task's stack, opened for this unit and dropped at its end.
    #[test]
    fn a_frame_reaches_the_planes_unit_and_the_planes_answer_comes_back_over_the_shipping_arena() {
        let node = Node::new();
        let driver = node.driver();
        let facts = [(tfacts::CREDENTIAL, "sk-rig")];
        let handle = driver
            .open(upgrade(RUN_BINDING, Bar::Credential, &facts), &RUN_SURFACE)
            .expect("a declared run opens");

        let payload: &[u8] = br#"{"type":"session.update","session":{}}"#;

        // THE PLANE CALL, over the arena that ships.
        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        let config = NoConfig;
        let transport = RigTransport;
        let labels = Labels::new();
        let clock = Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        };
        let ctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
        let plane = VoicePlane::new(UPSTREAMS);
        let mut state =
            PlaneSessionState::new(VoiceSessionState::for_dialect(Dialect::OpenaiRealtime));
        let frames = vec![Frame {
            direction: Direction::Inbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(std::sync::Arc::from(payload)),
            meta: FrameMeta::default(),
        }];
        let mut cursor = FrameCursor::new(&frames);
        let ingress = plane
            .decode_ingress(&mut cursor, Some(&mut state), &ctx)
            .expect("the plane reads its own client event");
        let Ingress::Open(draft) = ingress else {
            panic!("the first client event opens the plane's unit, got {ingress:?}");
        };
        // The unit's draft borrows the frame's own slab bytes, so reading it costs the arena
        // nothing: the arena is spent by what the plane WRITES, below, and the number is exact.
        assert_eq!(arena.remaining(), ARENA_BYTES);

        // THE LOOP, for that frame, on the driver as it stands.
        let reply = driver.drive(handle, SessionFrame { payload, seq: 0 });
        assert_eq!(
            node.units.sessions().len(),
            1,
            "one frame, one unit, on this session"
        );
        assert_eq!(
            reply.outcome,
            Outcome::NotFound,
            "the rig's units refuse at Arrival"
        );
        assert!(
            reply.frames.is_empty(),
            "what `drive` still answers on its own: nothing — the plane-call commit folds the two \
             calls around it into it"
        );

        // THE ANSWER: the plane's own rendering of the loop's ending, out of the SAME arena.
        let refusal = busbar_contract::unit::Refusal {
            step: Step::Arrival,
            reason: RefusalReason::NoDestination,
            retry_after_secs: None,
            stream: None,
            correlates: None,
        };
        let answer = plane
            .encode_refusal(&refusal, Some(&draft), Some(&state), &ctx)
            .expect("the plane renders the ending");
        let text = std::str::from_utf8(answer.as_slice()).expect("the plane's frames are JSON");
        assert!(
            text.contains("\"error\""),
            "the plane's own rendering, not the driver's prose: {text}"
        );
        assert_eq!(
            arena.remaining(),
            ARENA_BYTES - answer.len(),
            "the answer came out of the shipping arena, byte for byte, and out of nothing else"
        );

        driver.close(handle, CLIENT_WENT);
        // `space` drops here. Every borrow the plane took — the draft, the answer — died first, or
        // this function would not compile: that is the reset at unit end.
    }
}
