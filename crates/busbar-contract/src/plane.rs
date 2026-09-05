//! The plane kind: what bytes mean. A plane names a transport only as a claim, never holds a
//! connection, names no unit or other plane except through a nested destination, and returns
//! facts and locators only — never an amount, a decision, a credential, a price or a scheme
//! outside its claim. Pure over its inputs; no default bodies (see `docs/design/contract-notes.md`).

use crate::bounded::{ArenaBytes, Facts, Ir};
use crate::dest::{EgressBody, RoutePlan, VerifiedDestination};
use crate::grammar::Claim;
use crate::ids::{AdminVerbId, CorrelationRef, MeterClassDecl, OpClassId, RecordSchemaId};
use crate::plugin::Plugin;
use crate::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, ScopeFacts, Unit, UnitEnd, UsageLocators,
};
use crate::wire::{Decode, DiscardCode, Encode, Frame, FrameCursor};
use std::any::Any;

/// Everything a plane declares about itself.
///
/// All of it is a constant, because all of it is read at registration and sealed into policy. A
/// plane cannot vary its own declarations at run time; if it could, the claims a boot proved
/// non-overlapping would stop being the claims that are in force.
pub trait PlaneMeta {
    /// The plane's registry key.
    const KEY: &'static str;
    /// The claims this plane makes over arriving bytes.
    const CLAIMS: &'static [Claim];
    /// The operation classes this plane's units can be.
    const OP_CLASSES: &'static [OpClassId];
    /// The meter classes this plane meters, each with its family, direction and default divisor.
    const METER_CLASSES: &'static [MeterClassDecl];
    /// The session fact keys this plane writes.
    const SESSION_FACTS: &'static [&'static str];
    /// The content fact keys this plane produces.
    const CONTENT_FACTS: &'static [&'static str];
    /// The record schemas this plane keeps kernel-held durable records under.
    const RECORD_SCHEMAS: &'static [RecordSchemaId];
    /// The read-only introspection verbs this plane answers.
    const ADMIN_VERBS: &'static [AdminVerbId];
    /// The fact key that means "this frame supersedes the open one", where the dialect has one.
    const INTERRUPT_FACT: Option<&'static str>;
    /// The fact key that paces the kernel's outbound write path, where the dialect has one.
    const EGRESS_PACING_FACT: Option<&'static str>;
    /// The schema of this plane's own configuration block.
    const CONFIG_SCHEMA: &'static str;
}

/// A plane's codec state for one connection.
///
/// One half per connection: the client half comes from opening the session, and one more half per
/// dialed upstream. It is bounded per half with a ceiling on halves per session. It may own a drop
/// implementation and foreign resources, it is cleared on upgrade, and it is poisoned and dropped
/// on a panic. This is the *only* place cross-frame codec state may live; a plane that keeps state
/// in its own fields is red under the interior-mutability scan.
pub struct PlaneSessionState {
    inner: Box<dyn Any + Send>,
}

impl PlaneSessionState {
    /// Wrap a plane's own state value.
    #[must_use]
    pub fn new<T: Any + Send>(state: T) -> Self {
        Self {
            inner: Box::new(state),
        }
    }

    /// Read the state back as the plane's own type.
    #[must_use]
    pub fn get<T: Any + Send>(&self) -> Option<&T> {
        self.inner.downcast_ref::<T>()
    }

    /// Read the state back mutably as the plane's own type.
    pub fn get_mut<T: Any + Send>(&mut self) -> Option<&mut T> {
        self.inner.downcast_mut::<T>()
    }
}

impl core::fmt::Debug for PlaneSessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlaneSessionState(..)")
    }
}

/// The draft of a unit, before the kernel constructs it.
///
/// A draft carries what the plane read; the kernel writes the identity. The operation class here
/// is the one that prices the unit, which is why a differing class at the audit step is a dispute
/// rather than a re-price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitDraft<'u> {
    /// Which operation class this unit is.
    pub op: OpClassId,
    /// The decoded body and its resolved pointer spans.
    pub body_ir: Ir<'u>,
    /// Which earlier request this unit answers, where it answers one.
    pub correlates: Option<CorrelationRef<'u>>,
    /// The correlation an answer to this unit must carry.
    pub correlation_out: Option<CorrelationRef<'u>>,
    /// The facts the plane read off the bytes.
    pub facts: Facts<'u>,
}

/// One decoded response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'u> {
    /// The decoded body and its resolved pointer spans.
    pub ir: Ir<'u>,
    /// How the plane says it ended.
    pub finish: FinishClass,
    /// The facts the plane read off it.
    pub facts: Facts<'u>,
}

/// What a plane makes of inbound bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress<'u> {
    /// Not yet a whole anything; hand me the next frame.
    NeedMore,
    /// A unit that stays open across frames.
    Open(UnitDraft<'u>),
    /// A unit that is complete in one frame.
    OneShot(UnitDraft<'u>),
    /// A challenge-response exchange.
    Handshake(UnitDraft<'u>),
    /// A frame belonging to an already-open unit, to be relayed under its hold.
    Frame {
        /// Which unit it belongs to.
        for_: Option<CorrelationRef<'u>>,
        /// The bytes to relay.
        relay: ArenaBytes<'u>,
        /// The facts the plane read off it.
        facts: Facts<'u>,
    },
    /// The end of an open unit.
    Close {
        /// Which unit ends.
        for_: Option<CorrelationRef<'u>>,
        /// The facts the plane read off the ending.
        facts: Facts<'u>,
    },
    /// Nothing; drop the frame, change no state.
    Discard {
        /// Why.
        reason: DiscardCode,
    },
}

/// What a plane makes of bytes coming back from an upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress<'u> {
    /// Not yet a whole anything; hand me the next frame.
    NeedMore,
    /// An upstream pushed something that opens a unit of its own.
    Open(UnitDraft<'u>),
    /// An upstream pushed something complete in one frame.
    OneShot(UnitDraft<'u>),
    /// One response frame of an open unit.
    Frame {
        /// Which request it answers.
        for_: Option<CorrelationRef<'u>>,
        /// The decoded response.
        r: Response<'u>,
    },
    /// The last response frame.
    Terminal {
        /// Which request it answers.
        for_: Option<CorrelationRef<'u>>,
        /// The decoded response.
        r: Response<'u>,
    },
    /// Nothing; drop the frame, change no state.
    Discard {
        /// Why.
        reason: DiscardCode,
    },
}

/// What bytes mean.
///
/// Seven codec methods, seven fact methods and two introspection methods. Every one of them is
/// pure over its inputs, and none of them may perform input or output.
///
/// # Errors
/// Every codec method returns [`Decode`] or [`Encode`] when the bytes, or the unit, cannot be
/// expressed in this dialect's shape; the kernel then falls back to its own minimal rendering. A
/// decode error is not itself a refusal — a refusal is rendered through the refusal encoder.
pub trait Plane: Plugin + Send + Sync + 'static {
    /// Read inbound bytes.
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode>;

    /// Write the outbound request for one verified destination.
    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode>;

    /// Write one inbound frame of an open unit onward to its destination. Returning nothing means
    /// the frame is consumed and nothing goes out for it.
    fn encode_ingress_frame<'u>(
        &self,
        u: &Unit<'u>,
        f: &Frame,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode>;

    /// Read bytes coming back from an upstream.
    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode>;

    /// Write one response frame back to the client.
    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;

    /// Write a refusal in this dialect's shape. The codec state is borrowed immutably on purpose:
    /// a refusal must not advance codec state, or a sequence-numbered protocol that incremented
    /// its counter on one would desynchronise against a client that never saw the numbered message.
    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        draft: Option<&UnitDraft<'u>>,
        st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode>;

    /// Write the end of a unit, where the dialect has one to write.
    fn encode_end<'u>(
        &self,
        u: &Unit<'u>,
        end: &UnitEnd,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode>;

    /// Say where the credential is, and narrow the claim's scheme if the dialect narrows it.
    ///
    /// A plane may only narrow within the alternatives its claim declares. Anything else is
    /// refused at the authenticate step; the plane never sees the credential either way.
    fn authenticate<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> crate::kinds::CredentialLocator;

    /// Say where this unit wants to go.
    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> crate::dest::DestinationFacts;

    /// Say what resources this unit touches.
    fn approve<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> ScopeFacts;

    /// Say where the lane name, the response ceiling and the priced input span are.
    fn admit<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> AdmitFacts;

    /// Say which legs this unit needs.
    fn route<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> RoutePlan;

    /// Say where the metered quantities are in a response.
    fn meter<'u>(&self, u: &Unit<'u>, r: &Response<'u>, ctx: &Ctx<'u>) -> UsageLocators;

    /// Say what this unit was and how it ended.
    ///
    /// Called at the metering step's entry with the provisional ending. An operation class here
    /// that differs from the draft's is a dispute; the draft's class is what priced the unit.
    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, ctx: &Ctx<'u>) -> AuditFacts;

    /// Answer one of this plane's declared read-only introspection verbs. Errors when the verb
    /// is not one this plane declares.
    fn plane_facts<'u>(
        &self,
        verb: AdminVerbId,
        ctx: &Ctx<'u>,
    ) -> Result<crate::kinds::PlaneFacts<'u>, Decode>;

    /// Say what the response contained, for the record and the export path.
    fn content_facts<'u>(
        &self,
        u: &Unit<'u>,
        r: &Response<'u>,
        ctx: &Ctx<'u>,
    ) -> crate::kinds::ContentFacts<'u>;
}

/// A plane that can run over a session transport.
///
/// The registry requires this trait exactly when any transport the plane claims declares itself a
/// session transport. The two methods are where the plane's per-connection codec state comes from:
/// one half for the client connection, one per upstream the session dials.
pub trait SessionPlane: Plane {
    /// Open the client half of this session's codec state.
    fn open_session<'u>(&self, ctx: &Ctx<'u>) -> PlaneSessionState;

    /// Open one upstream half of this session's codec state.
    fn open_upstream<'u>(&self, dest: &VerifiedDestination, ctx: &Ctx<'u>) -> PlaneSessionState;
}
