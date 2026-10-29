//! One object-safety fixture per kind trait, and a working implementation of the plane.
//!
//! The honesty table of the design lists object safety as a compile-time property proven by a
//! fixture per kind. That is what the assertions below are: each one only compiles if the trait
//! can be used behind a pointer, which is how the registry holds every plugin.
//!
//! Some of the kinds get a full implementation as well. That proves something the assertions cannot
//! — that the signatures are actually implementable, lifetimes and all — and it proves the
//! no-default-bodies rule the same way a reviewer would: the fixture below names every method,
//! because leaving one out does not compile.

use busbar_contract::bounded::{
    Facts, Ir, Labels, PlaneAlloc, PlaneAllocBudget, ScratchBytes, Span,
};
use busbar_contract::dest::{
    AuthDecoration, DestinationFacts, EgressBody, RoutePlan, VerifiedDestination,
};
use busbar_contract::ids::{
    AdminVerbId, LaneId, MeterClassDecl, OpClassId, RecordSchemaId, SchemeKey,
};
use busbar_contract::kinds::{
    Ack, Challenge, ChallengeState, ContentFacts, CredentialLocator, Head, PlaneFacts, SecretRef,
    StoreError,
};
use busbar_contract::plane::{
    Ingress, Plane, PlaneMeta, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use busbar_contract::unit::{
    AuditFacts, Clock, ConfigView, Ctx, FinishClass, Refusal, SessionView, TransportView, Unit,
    UnitEnd, UsageLocators,
};
use busbar_contract::wire::{Decode, DiscardCode, Encode, Frame, FrameCursor};

/// The codec host every context this fixture builds hands its plane: a fixed, non-zero entropy fill
/// and no clock of its own (the context carries the clock). A context cannot be built without one.
pub struct FixtureCodecHost;

impl busbar_contract::codec::CodecHost for FixtureCodecHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        out.fill(0x5A);
        true
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

/// The handle every context here is built with.
pub const CODEC_HOST: &dyn busbar_contract::codec::CodecHost = &FixtureCodecHost;

// ── the fixture per kind: each of these only compiles if the trait is object-safe ─────────────

const _PLANE: Option<&dyn Plane> = None;
const _SESSION_PLANE: Option<&dyn SessionPlane> = None;
const _PLUGIN: Option<&dyn Plugin> = None;
const _PLANE_ALLOC: Option<&dyn PlaneAlloc> = None;
const _CONFIG: Option<&dyn ConfigView> = None;
const _SESSION_VIEW: Option<&dyn SessionView> = None;
const _TRANSPORT_VIEW: Option<&dyn TransportView> = None;

// ── the borrowed views a call needs, in their smallest honest form ────────────────────────────

/// An allocator that never has room. Enough to build a context; nothing here allocates.
struct NoPlaneAlloc;

impl PlaneAlloc for NoPlaneAlloc {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, PlaneAllocBudget> {
        Err(PlaneAllocBudget {
            wanted: src.len(),
            remaining: 0,
        })
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, PlaneAllocBudget> {
        Err(PlaneAllocBudget {
            wanted: src.len(),
            remaining: 0,
        })
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], PlaneAllocBudget> {
        Err(PlaneAllocBudget {
            wanted: std::mem::size_of_val(src),
            remaining: 0,
        })
    }

    fn remaining(&self) -> usize {
        0
    }
}

/// A configuration block with nothing in it.
struct EmptyConfig;

impl ConfigView for EmptyConfig {
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

/// A one-shot transport stack.
struct OneShotStack;

impl TransportView for OneShotStack {
    fn key(&self) -> &'static str {
        "fixture"
    }
    fn chain(&self) -> &[&'static str] {
        &["fixture"]
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

// ── a plane, implemented in full ──────────────────────────────────────────────────────────────

/// The smallest plane that answers every question the loop asks.
struct FixturePlane;

impl Plugin for FixturePlane {
    fn key(&self) -> &'static str {
        <Self as PlaneMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Plane
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

impl PlaneMeta for FixturePlane {
    const KEY: &'static str = "fixture";
    const CLAIMS: &'static [busbar_contract::grammar::Claim] = &[];
    const OP_CLASSES: &'static [OpClassId] = &[OpClassId::new("echo")];
    const METER_CLASSES: &'static [MeterClassDecl] = &[];
    const SESSION_FACTS: &'static [&'static str] = &[];
    const CONTENT_FACTS: &'static [&'static str] = &[];
    const RECORD_SCHEMAS: &'static [RecordSchemaId] = &[];
    const INTROSPECTION_VERBS: &'static [AdminVerbId] = &[];
    const INTERRUPT_FACT: Option<&'static str> = None;
    const EGRESS_PACING_FACT: Option<&'static str> = None;
    const CONFIG_SCHEMA: &'static str = "{}";
}

impl Plane for FixturePlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        match frames.next_frame() {
            None => Ok(Ingress::NeedMore),
            Some(_) => Ok(Ingress::OneShot(Box::new(UnitDraft {
                op: OpClassId::new("echo"),
                body_ir: Ir::new(&[], &[]),
                correlates: None,
                correlation_out: None,
                facts: Facts::new(),
            }))),
        }
    }

    fn encode_egress<'u>(
        &self,
        _u: &Unit<'u>,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        Ok(EgressBody {
            envelope: busbar_contract::wire::TransportEnvelope::default(),
            body: ScratchBytes::new(&[]),
            auth: SchemeKey::new("none"),
        })
    }

    fn encode_ingress_frame<'u>(
        &self,
        _u: &Unit<'u>,
        _f: &Frame,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode> {
        Ok(None)
    }

    fn decode_response<'u>(
        &self,
        _frames: &mut FrameCursor<'u>,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        Ok(Progress::Discard {
            reason: DiscardCode::Unsupported,
        })
    }

    fn encode_response<'u>(
        &self,
        _r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode> {
        Ok(ScratchBytes::new(&[]))
    }

    fn encode_refusal<'u>(
        &self,
        _refusal: &Refusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode> {
        Ok(ScratchBytes::new(b"refused"))
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode> {
        Ok(None)
    }

    fn authenticate<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> CredentialLocator {
        CredentialLocator::default()
    }

    fn verify<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        DestinationFacts::Upstream {
            transport: "fixture",
            address: busbar_contract::UpstreamAddress::socket("example"),
            lane: LaneId::new("fixture-lane"),
        }
    }

    fn route<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> RoutePlan {
        RoutePlan::default()
    }

    fn meter<'u>(&self, _u: &Unit<'u>, _r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        UsageLocators::default()
    }

    fn audit<'u>(&self, _u: &Unit<'u>, _out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        AuditFacts {
            op_class: OpClassId::new("echo"),
            finish: FinishClass::Complete,
        }
    }

    fn plane_facts<'u>(
        &self,
        _verb: AdminVerbId,
        _subject: Option<&'u str>,
        _ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        Ok(PlaneFacts::default())
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        _r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        ContentFacts::default()
    }
}

impl SessionPlane for FixturePlane {
    fn open_session<'u>(&self, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(0u8)
    }

    fn open_upstream<'u>(&self, _dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(0u8)
    }
}

// ── a transport's declarations ────────────────────────────────────────────────────────────────

/// A transport's declarations. A transport is a memory-ABI framer door, not a trait object (step
/// 36), so what a fixture can state of one is its kind and its declared facts.
struct FixtureTransport;

impl Plugin for FixtureTransport {
    fn key(&self) -> &'static str {
        "fixture"
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

// ── the tests ─────────────────────────────────────────────────────────────────────────────────

/// Every kind can be held behind a pointer, which is how the registry holds one.
#[test]
fn every_kind_is_object_safe() {
    let plane: &dyn Plane = &FixturePlane;
    let session_plane: &dyn SessionPlane = &FixturePlane;

    assert_eq!(plane.kind(), Kind::Plane);
    assert_eq!(session_plane.key(), "fixture");
}

/// A plane call runs, with a real context, and the borrow story holds.
#[test]
fn a_plane_call_runs_under_a_context() {
    let arena = NoPlaneAlloc;
    let config = EmptyConfig;
    let stack = OneShotStack;
    let labels = Labels::new();
    let ctx = Ctx::new(
        Clock {
            unix_secs: 0,
            monotonic_nanos: 0,
        },
        &config,
        None,
        &stack,
        &labels,
        &arena,
        CODEC_HOST,
    );

    let plane = FixturePlane;
    let frames: [Frame; 0] = [];
    let mut cursor = FrameCursor::new(&frames);
    let out = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("a plane with no frames answers, it does not fail");
    assert!(matches!(out, Ingress::NeedMore));
}

/// The kind a plugin reports matches the kind of the trait it implements.
#[test]
fn a_plugin_reports_the_kind_of_the_trait_it_implements() {
    assert_eq!(
        FixturePlane.kind(),
        Kind::of::<busbar_contract::plugin::markers::PlaneKind>()
    );
    assert_eq!(
        FixtureTransport.kind(),
        Kind::of::<busbar_contract::plugin::markers::TransportKind>()
    );
}

/// The shapes the other kinds hand back exist and are constructible.
#[test]
fn the_remaining_kinds_shapes_are_constructible() {
    let _ = Challenge {
        bytes: vec![1],
        state: ChallengeState(vec![2]),
        rounds_left: 1,
    };
    let _ = SecretRef::file("fixture://key");
    let _: Result<Head, StoreError> = Err(StoreError::Unavailable);
    let _ = Ack::Durable;
    let _: Option<AuthDecoration<'static>> = None;
}
