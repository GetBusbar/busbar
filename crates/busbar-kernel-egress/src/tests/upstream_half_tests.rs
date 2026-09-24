// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upstream half: the plane's codec state for one dialed upstream, opened by the attempt and
//! carried from the egress encode through every frame's decode (item 451).
//!
//! A plane that keeps codec state decides at `encode_egress`, from the request's own operation,
//! whether the exchange answers incrementally, and reads that decision back at `decode_response`.
//! It has to: a whole answer that opens an incremental exchange looks exactly like a one-shot
//! answer on the wire. When the attempt handed both calls `None`, the decision was never recorded,
//! every incremental answer read as one-shot, and it ended on its FIRST answering frame — the
//! remaining events were never relayed and the unit closed on event one.
//!
//! The fixture plane below has exactly that shape and nothing else: an operation table saying
//! which operations answer incrementally, an encode that records the answer on the upstream half,
//! and a decode that ends a one-shot answer on its first frame and an incremental one only on the
//! frame that says it is the last.

use std::sync::{Arc, Mutex};

use busbar_contract::transport::wire::{Decode, Encode, WireStatusClass};
use busbar_contract::{
    AdmitFacts, AuditFacts, ContentFacts, CredentialLocator, Ctx, DestinationFacts, EgressBody,
    FinishClass, Frame, Ingress, Ir, Kind, Plane, PlaneFacts, PlaneSessionState, Plugin, Progress,
    Refusal, RoutePlan, ScopeFacts, ScratchBytes, SessionPlane, Unit, UnitEnd, UsageLocators,
    VerifiedDestination,
};

use super::harness::{frame, Script, TestPlane};
use super::{member, Node};
use crate::ports::{DestinationId, Outcome};
use crate::wire::RouteOutcome;

/// The body of the frame an incremental answer ends on.
const LAST: &[u8] = b"last";

/// The operation the harness's unit carries.
const HARNESS_OP: &str = "test-op";

/// One upstream half of the fixture's codec state.
#[derive(Debug, Default)]
struct Half {
    /// Whether the request this half carries is answered incrementally. Written at the encode.
    incremental: bool,
    /// How many answering frames this half has read.
    read: u32,
}

/// A plane that keeps codec state per upstream, the way an event-answering dialect must.
#[derive(Debug, Default)]
struct HalfPlane {
    /// Everything the egress path does not call is the harness plane's.
    inner: TestPlane,
    /// The operations this dialect answers incrementally.
    incremental_ops: Vec<&'static str>,
    /// How many answering frames each decode saw, by what the half said at that frame.
    reads: Mutex<Vec<u32>>,
}

impl HalfPlane {
    fn answering_incrementally(ops: &[&'static str]) -> Self {
        Self {
            incremental_ops: ops.to_vec(),
            ..Self::default()
        }
    }
}

impl Plugin for HalfPlane {
    fn key(&self) -> &'static str {
        "half-plane"
    }

    fn kind(&self) -> Kind {
        Kind::Plane
    }

    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        busbar_contract::transport::AbiVersion(1)
    }
}

impl Plane for HalfPlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut busbar_contract::FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        self.inner.decode_ingress(frames, st, ctx)
    }

    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        // The one decision this half exists to carry, taken from the request's own operation.
        if let Some(half) = st.and_then(|state| state.get_mut::<Half>()) {
            half.incremental = self.incremental_ops.contains(&u.op().as_str());
        }
        self.inner.encode_egress(u, dest, None, ctx)
    }

    fn encode_ingress_frame<'u>(
        &self,
        u: &Unit<'u>,
        f: &Frame,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode> {
        self.inner.encode_ingress_frame(u, f, dest, st, ctx)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut busbar_contract::FrameCursor<'u>,
        _dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        let Some(frame) = frames.next_frame() else {
            return Ok(Progress::NeedMore);
        };
        let half = st.and_then(|state| state.get_mut::<Half>());
        let incremental = half.as_ref().is_some_and(|h| h.incremental);
        if let Some(half) = half {
            half.read = half.read.saturating_add(1);
            self.reads
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(half.read);
        }
        // A one-shot answer ends on its one answer; an incremental one only on its last frame.
        let terminal = !incremental || frame.bytes.as_slice() == LAST;
        let r = Box::new(busbar_contract::Response {
            ir: Ir::new(&[], &[]),
            finish: if terminal {
                FinishClass::Complete
            } else {
                FinishClass::TurnComplete
            },
            facts: busbar_contract::Facts::new(),
        });
        Ok(if terminal {
            Progress::Terminal { for_: None, r }
        } else {
            Progress::Frame { for_: None, r }
        })
    }

    fn encode_response<'u>(
        &self,
        r: &busbar_contract::Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode> {
        self.inner.encode_response(r, st, ctx)
    }

    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        draft: Option<&busbar_contract::UnitDraft<'u>>,
        st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode> {
        self.inner.encode_refusal(refusal, draft, st, ctx)
    }

    fn encode_end<'u>(
        &self,
        u: &Unit<'u>,
        end: &UnitEnd,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode> {
        self.inner.encode_end(u, end, st, ctx)
    }

    fn authenticate<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> CredentialLocator {
        self.inner.authenticate(u, ctx)
    }

    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> DestinationFacts {
        self.inner.verify(u, ctx)
    }

    fn approve<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> ScopeFacts {
        self.inner.approve(u, ctx)
    }

    fn admit<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> AdmitFacts {
        self.inner.admit(u, ctx)
    }

    fn route<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> RoutePlan {
        self.inner.route(u, ctx)
    }

    fn meter<'u>(
        &self,
        u: &Unit<'u>,
        r: &busbar_contract::Response<'u>,
        ctx: &Ctx<'u>,
    ) -> UsageLocators {
        self.inner.meter(u, r, ctx)
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, ctx: &Ctx<'u>) -> AuditFacts {
        self.inner.audit(u, out, ctx)
    }

    fn plane_facts<'u>(
        &self,
        verb: busbar_contract::AdminVerbId,
        subject: Option<&'u str>,
        ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        self.inner.plane_facts(verb, subject, ctx)
    }

    fn content_facts<'u>(
        &self,
        u: &Unit<'u>,
        r: &busbar_contract::Response<'u>,
        ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        self.inner.content_facts(u, r, ctx)
    }
}

impl SessionPlane for HalfPlane {
    fn open_session<'u>(&self, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Half::default())
    }

    fn open_upstream<'u>(&self, _dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Half::default())
    }
}

/// An answer of `events` event frames, the last of which says it is the last. Every frame is a
/// whole answer in its own right — which is exactly why the wire alone cannot end it.
fn events(count: usize) -> Script {
    let mut frames: Vec<_> = (1..count)
        .map(|_| frame(Some(WireStatusClass::Success), "event"))
        .collect();
    frames.push(frame(Some(WireStatusClass::Success), "last"));
    Script::Frames(frames)
}

fn node_over(plane: &Arc<HalfPlane>, script: Script) -> Node {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.wants_stream = true;
    let session: Arc<dyn SessionPlane> = plane.clone();
    node.session_plane = Some(session);
    node.transport.script("a", script);
    node
}

/// Item 451. An incremental answer of N events is relayed to its terminal and the attempt hands
/// the meter all N — not cut at event one.
#[test]
fn an_incremental_answer_of_n_events_is_relayed_and_metered_to_its_terminal() {
    const N: usize = 4;
    let plane = Arc::new(HalfPlane::answering_incrementally(&[HARNESS_OP]));
    let node = node_over(&plane, events(N));

    let outcome = node.route("primary");
    let RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("a whole answer is delivered: {outcome:?}");
    };
    assert_eq!(
        delivered.frames, N,
        "every event of the answer is relayed, up to and including the terminal one"
    );
    assert_eq!(
        delivered.finish,
        Some(FinishClass::Complete),
        "the answer ends on its own terminal frame"
    );
    assert_eq!(
        *plane.reads.lock().unwrap(),
        (1..=u32::try_from(N).unwrap()).collect::<Vec<_>>(),
        "ONE upstream half carried the encode's decision through every frame's decode"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success],
        "an answer that arrived whole records one success and no compensating failure"
    );
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "and keeps the budget unit it spent"
    );
}

/// The control: the same half, for an operation the dialect answers in one shot, ends on the first
/// answer — the half carries the decision both ways rather than forcing every answer long.
#[test]
fn a_one_shot_answer_still_ends_on_its_first_answer_with_the_half_threaded() {
    let plane = Arc::new(HalfPlane::answering_incrementally(&[]));
    let node = node_over(&plane, events(4));

    let outcome = node.route("primary");
    let RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("a whole answer is delivered: {outcome:?}");
    };
    assert_eq!(delivered.frames, 1, "a one-shot answer ends on its answer");
    assert_eq!(delivered.finish, Some(FinishClass::Complete));
    assert_eq!(*plane.reads.lock().unwrap(), vec![1]);
}
