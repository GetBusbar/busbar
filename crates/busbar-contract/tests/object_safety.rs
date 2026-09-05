//! One object-safety fixture per plugin kind, and a working implementation of the two largest.
//!
//! The honesty table of the design lists object safety as a compile-time property proven by a
//! fixture per kind. That is what the assertions below are: each one only compiles if the trait
//! can be used behind a pointer, which is how the registry holds every plugin.
//!
//! Two of the kinds get a full implementation as well. That proves something the assertions cannot
//! — that the signatures are actually implementable, lifetimes and all — and it proves the
//! no-default-bodies rule the same way a reviewer would: the fixture below names every method,
//! because leaving one out does not compile.

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Facts, Ir, Labels};
use busbar_contract::dest::{
    AuthDecoration, DestinationFacts, EgressBody, RoutePlan, TransportKeyHandle,
    VerifiedDestination,
};
use busbar_contract::grammar::ArrivalLocation;
use busbar_contract::ids::{
    AdminVerbId, LaneId, MeterClassDecl, OpClassId, PrincipalId, RecordSchemaId, SchemeKey,
    StreamId,
};
use busbar_contract::kinds::{
    Ack, Anchor, AuthOutcome, AuthScheme, Challenge, ChallengeState, ContentFacts, Credential,
    CredentialFacts, CredentialLocator, EgressAuthScheme, Export, ExportItem, Head, Hook,
    HookFacts, HookKindDecl, HookView, KeyMaterial, OnFailure, PlaneFacts, Seat, Secret,
    SecretError, SecretRef, SecretValue, Signer, Store, StoreError,
};
use busbar_contract::plane::{
    Ingress, Plane, PlaneMeta, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use busbar_contract::transport::{FrameStream, Fut, Transport, TransportConfigView, TransportMeta};
use busbar_contract::unit::{
    AdmitFacts, AuditFacts, Clock, ConfigView, Ctx, FinishClass, Refusal, ScopeFacts, SessionView,
    Step, TransportView, Unit, UnitEnd, UsageLocators,
};
use busbar_contract::wire::{
    ArrivalRecord, CloseReason, Conn, Decode, DiscardCode, Encode, Frame, FrameCursor, Listener,
    StatusAt, TransportError, Unit0Trigger,
};

// ── the fixture per kind: each of these only compiles if the trait is object-safe ─────────────

const _PLANE: Option<&dyn Plane> = None;
const _SESSION_PLANE: Option<&dyn SessionPlane> = None;
const _TRANSPORT: Option<&dyn Transport> = None;
const _AUTH: Option<&dyn AuthScheme> = None;
const _EGRESS_AUTH: Option<&dyn EgressAuthScheme> = None;
const _STORE: Option<&dyn Store> = None;
const _SECRET: Option<&dyn Secret> = None;
const _HOOK: Option<&dyn Hook> = None;
const _EXPORT: Option<&dyn Export> = None;
const _ANCHOR: Option<&dyn Anchor> = None;
const _PLUGIN: Option<&dyn Plugin> = None;
const _SIGNER: Option<&dyn Signer> = None;
const _ARENA: Option<&dyn Arena> = None;
const _CONFIG: Option<&dyn ConfigView> = None;
const _SESSION_VIEW: Option<&dyn SessionView> = None;
const _TRANSPORT_VIEW: Option<&dyn TransportView> = None;

// ── the borrowed views a call needs, in their smallest honest form ────────────────────────────

/// An arena that never has room. Enough to build a context; nothing here allocates.
struct NoArena;

impl Arena for NoArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        Err(ArenaBudget {
            wanted: src.len(),
            remaining: 0,
        })
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        Err(ArenaBudget {
            wanted: src.len(),
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

impl TransportConfigView for EmptyConfig {
    fn bind(&self) -> Option<&str> {
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
    const ADMIN_VERBS: &'static [AdminVerbId] = &[];
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
            Some(_) => Ok(Ingress::OneShot(UnitDraft {
                op: OpClassId::new("echo"),
                body_ir: Ir::new(&[], &[]),
                correlates: None,
                correlation_out: None,
                facts: Facts::new(),
            })),
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
            body: ArenaBytes::new(&[]),
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
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
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
    ) -> Result<ArenaBytes<'u>, Encode> {
        Ok(ArenaBytes::new(&[]))
    }

    fn encode_refusal<'u>(
        &self,
        _refusal: &Refusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        Ok(ArenaBytes::new(b"refused"))
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
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

    fn approve<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        ScopeFacts::default()
    }

    fn admit<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        AdmitFacts::default()
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

// ── a transport, implemented in full ──────────────────────────────────────────────────────────

/// The smallest transport that answers every call the pump makes.
struct FixtureTransport;

impl Plugin for FixtureTransport {
    fn key(&self) -> &'static str {
        <Self as TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

impl TransportMeta for FixtureTransport {
    const KEY: &'static str = "fixture";
    const SELECTOR_FORMS: &'static [busbar_contract::grammar::SelectorForm] = &[];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::grammar::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &[];
    const HANDOFF: Option<busbar_contract::wire::Handoff> = None;
    const FRAMING: busbar_contract::Framing = busbar_contract::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstBytes);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<StatusAt> = Some(StatusAt::FirstFrame);
}

impl Transport for FixtureTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["fixture"],
        }
    }

    fn listen<'a>(
        &'a self,
        _cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async { Err(TransportError::Refused) })
    }

    fn accept<'a>(&'a self, _l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async { Err(TransportError::Closed) })
    }

    fn dial<'a>(
        &'a self,
        _dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async { Err(TransportError::Refused) })
    }

    fn frames(&self, _conn: Conn) -> FrameStream {
        Box::pin(futures::stream::empty())
    }

    fn write<'a>(
        &'a self,
        _conn: &'a Conn,
        _stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        let n = bytes.len();
        Box::pin(async move { Ok(n) })
    }

    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn Arena,
    ) -> Result<ArenaBytes<'a>, Encode> {
        arena.alloc_bytes(body).map_err(|_| Encode::ArenaExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async { Err(TransportError::HandoffMismatch) })
    }

    fn close(&self, _conn: Conn, _reason: CloseReason) {}

    fn unit0_refusal<'a>(
        &'a self,
        _conn: Conn,
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        _bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

// ── a hook and an auth scheme, implemented in full ────────────────────────────────────────────

/// A hook that observes and never gates.
struct FixtureHook;

impl Plugin for FixtureHook {
    fn key(&self) -> &'static str {
        "fixture-hook"
    }
    fn kind(&self) -> Kind {
        Kind::Hook
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

impl Hook for FixtureHook {
    fn hook_kind(&self) -> HookKindDecl {
        HookKindDecl::Tap
    }
    fn seats(&self) -> &'static [Seat] {
        &[Seat::After(Step::Route)]
    }
    fn hook_facts(&self) -> &'static [&'static str] {
        &[]
    }
    fn on_failure(&self) -> OnFailure {
        OnFailure::Closed
    }
    fn max_priced_delta(&self) -> u64 {
        0
    }
    fn may_change_destination(&self) -> bool {
        false
    }
    fn may_rewrite(&self) -> bool {
        false
    }
    fn observe<'u, 'a>(&self, _seat: Seat, _view: &HookView<'u, 'a>) -> HookFacts<'u> {
        HookFacts::default()
    }
}

/// An auth scheme that abstains on everything.
struct FixtureAuth;

impl Plugin for FixtureAuth {
    fn key(&self) -> &'static str {
        "fixture-auth"
    }
    fn kind(&self) -> Kind {
        Kind::Auth
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

impl AuthScheme for FixtureAuth {
    fn locations(&self) -> &'static [ArrivalLocation] {
        &[ArrivalLocation::Header("authorization")]
    }
    fn does_io(&self) -> bool {
        false
    }
    fn verify(
        &self,
        _credential: &Credential,
        _arrival: &ArrivalRecord,
        _clock: Clock,
        _prior: Option<&ChallengeState>,
    ) -> AuthOutcome {
        AuthOutcome::Pass
    }
    fn refresh(&self, clock: Clock) -> KeyMaterial {
        KeyMaterial {
            bytes: Vec::new(),
            fetched_at: clock.unix_secs,
        }
    }
}

// ── the tests ─────────────────────────────────────────────────────────────────────────────────

/// Every kind can be held behind a pointer, which is how the registry holds one.
#[test]
fn every_kind_is_object_safe() {
    let plane: &dyn Plane = &FixturePlane;
    let session_plane: &dyn SessionPlane = &FixturePlane;
    let transport: &dyn Transport = &FixtureTransport;
    let hook: &dyn Hook = &FixtureHook;
    let auth: &dyn AuthScheme = &FixtureAuth;

    assert_eq!(plane.kind(), Kind::Plane);
    assert_eq!(session_plane.key(), "fixture");
    assert_eq!(transport.kind(), Kind::Transport);
    assert_eq!(hook.on_failure(), OnFailure::Closed);
    assert!(!auth.does_io());
}

/// A plane call runs, with a real context, and the borrow story holds.
#[test]
fn a_plane_call_runs_under_a_context() {
    let arena = NoArena;
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
    assert_eq!(
        FixtureHook.kind(),
        Kind::of::<busbar_contract::plugin::markers::HookKind>()
    );
    assert_eq!(
        FixtureAuth.kind(),
        Kind::of::<busbar_contract::plugin::markers::AuthKind>()
    );
}

/// The shapes the other kinds hand back exist and are constructible.
#[test]
fn the_remaining_kinds_shapes_are_constructible() {
    let _ = AuthOutcome::Challenge(Challenge {
        bytes: vec![1],
        state: ChallengeState(vec![2]),
        rounds_left: 1,
    });
    let _ = AuthOutcome::Facts(CredentialFacts {
        principal: PrincipalId::new("someone"),
        issuer: None,
        expiry: None,
        session_bindable: true,
    });
    let _: Result<SecretValue, SecretError> = Err(SecretError::Unknown);
    let _ = SecretRef("fixture://key".into());
    let _: Result<Head, StoreError> = Err(StoreError::Unavailable);
    let _ = ExportItem::Segment {
        stream: "journal",
        from: 0,
        to: 1,
        bytes: ArenaBytes::new(&[]),
    };
    let _ = Ack::Durable;
    let _: Option<AuthDecoration<'static>> = None;
}
