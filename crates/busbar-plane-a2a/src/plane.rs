//! The plane itself: seventeen methods, each of them a few lines over the codec's own vocabulary.
//!
//! Every method here returns FACTS AND LOCATORS. Not an amount, not a decision, not a credential,
//! not a price. Nothing in this file opens a connection, reads a file, reads a clock other than the
//! one the context hands it, or keeps a byte across a call.
//!
//! ## The one shape worth reading before the code
//!
//! The intermediate representation the contract asks a plane to build carries the body AND the
//! resolved pointer spans. The arena a plane is handed allocates bytes and strings, and nothing
//! else, so a plane cannot put a table of spans into it and hand back a borrow that lives as long as
//! the unit. Every draft below therefore carries the body with an EMPTY span table, and everything
//! this plane read is reported as a fact or as a span on the admit facts, both of which are
//! by-value. The kernel's own scanner is what resolves pointers over the body. That is a finding
//! about the contract's allocator, not a decision taken here, and it is written down in the crate's
//! notes.

use busbar_contract::bounded::{ArenaBytes, BoundedVec, FactValue, Facts, Ir, Span};
use busbar_contract::dest::{DestinationFacts, EgressBody, Leg, RoutePlan, VerifiedDestination};
use busbar_contract::ids::{AdminVerbId, LaneId, SchemeAlt};
use busbar_contract::kinds::{ContentFacts, CredentialLocator, PlaneFacts};
use busbar_contract::plane::{
    Ingress, Plane, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::unit::{
    AbortBy, AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, RefusalReason, ResourceLocator,
    ScopeFacts, Unit, UnitEnd, UsageLocator, UsageLocators,
};
use busbar_contract::wire::{Decode, Encode, Frame, FrameCursor, TransportEnvelope};

use crate::facts as f;
use crate::jsonrpc;
use crate::meta::CLASS_BYTES;
use crate::ops;
use crate::records as rec;
use crate::A2aPlane;

/// The per-connection codec state this plane keeps.
///
/// It holds a COUNT and nothing else. This protocol's framing is one document per frame, so there
/// is no partial document to carry across a call; what a connection does need to remember is how far
/// into a streamed answer it is, because a stream's last event is the one that ends the unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Codec {
    /// How many event frames of a streamed answer this half has read.
    pub events_read: u32,
}

/// The fact key the per-name projection reports the agent's own name under.
const SUBJECT_FACT_NAME: &str = "name";

/// The fact key the per-name projection reports the priced lane under.
const SUBJECT_FACT_LANE: &str = "lane";

/// The fact key the per-name projection reports the dialling transport under.
const SUBJECT_FACT_TRANSPORT: &str = "transport";

/// The credential scheme the outbound hop is decorated under.
///
/// The plane NAMES the scheme and never holds what is behind it. Which secret the scheme resolves,
/// and whether the caller may use it at all, is the egress-auth unit's answer.
const EGRESS_SCHEME: &str = "a2a-egress";

/// The envelope member naming the document type of an outbound body.
const FIELD_CONTENT_TYPE: &str = "content-type";

/// The document type every body of this protocol is.
const CONTENT_TYPE_JSON: &[u8] = b"application/json";

/// The envelope member naming which revision the hop is made under.
const FIELD_VERSION: &str = "a2a-version";

/// A fact a record leg reports back when the agent minted its own identifier for a task.
pub const LEG_FACT_BACKEND_TASK_ID: &str = "backend_task_id";

impl A2aPlane {
    /// A leg reaching one of this plane's own records.
    fn record_leg(schema: busbar_contract::ids::RecordSchemaId, op: &'static str) -> Leg {
        Leg {
            destination: DestinationFacts::PlaneRecord { schema, op },
        }
    }

    /// A leg reaching the configured agent, or an unreachable one when none is configured.
    ///
    /// A plane with nothing configured answers honestly rather than panicking or inventing a host:
    /// the empty host is refused by the trust unit against the allow-list, which is the right place
    /// for that refusal to happen.
    fn upstream_leg(&self) -> Leg {
        Leg {
            destination: self.upstream_destination(),
        }
    }

    /// Where a hop to the configured agent goes.
    fn upstream_destination(&self) -> DestinationFacts {
        match self.agents().first() {
            Some(agent) => DestinationFacts::Upstream {
                transport: agent.transport,
                address: busbar_contract::UpstreamAddress::socket(agent.host),
                lane: agent.lane,
            },
            None => DestinationFacts::Upstream {
                transport: crate::claims::TRANSPORT_HTTP,
                address: busbar_contract::UpstreamAddress::socket(""),
                lane: LaneId::new(""),
            },
        }
    }

    /// Which method row a unit's operation class came from, where the class names one.
    fn row_for_op(op: busbar_contract::ids::OpClassId) -> Option<&'static ops::MethodRow> {
        ops::METHODS.iter().find(|r| r.op == op)
    }
}

/// The facts a request body yields, read once.
fn request_facts<'u>(body: &'u [u8], envelope: &jsonrpc::Envelope) -> Facts<'u> {
    let mut facts = Facts::new();
    if let Some(method) = envelope.method_str(body) {
        let _ = facts.set(f::FACT_METHOD, FactValue::Str(method));
        if let Some(row) = ops::row_for(method) {
            let _ = facts.set(f::FACT_WORDING, FactValue::Str(row.wording.as_str()));
            let _ = facts.set(f::FACT_STREAMING, FactValue::Bool(row.streaming));
        }
    }
    if let Some(raw) = envelope.id_bytes(body) {
        if let Ok(text) = core::str::from_utf8(raw) {
            let _ = facts.set(f::FACT_RPC_ID, FactValue::Str(text));
        }
    }
    if let Some(task) = read_str(body, jsonrpc::PTR_PARAMS_ID) {
        let _ = facts.set(f::FACT_TASK_ID, FactValue::Str(task));
    }
    facts
}

/// The span view of a body, built from the pointers this plane declared.
///
/// One scan of one closed grammar, into the unit's own arena, so the loop reads the spans the plane
/// resolved instead of walking the same bytes a second time. The arena refusing is a decode
/// failure at the step that asked for the bytes, which is what the arena's budget means.
fn view<'u>(body: &'u [u8], pointers: &[&'u str], ctx: &Ctx<'u>) -> Result<Ir<'u>, Decode> {
    let spans = busbar_contract::spans::resolve(body, pointers, ctx.arena())
        .map_err(|_| Decode::Oversize)?;
    Ok(Ir::new(body, spans))
}

/// The string value at one pointer of a body, with its quotes stripped.
fn read_str<'u>(body: &'u [u8], pointer: &str) -> Option<&'u str> {
    let raw = read_raw(body, pointer)?;
    let inner = raw.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    core::str::from_utf8(inner).ok()
}

/// The raw bytes at one pointer of a body.
///
/// Through the contract's own span grammar, which is the kernel's: this plane used to carry a
/// scanner of its own, and a closed grammar with a second reading is two grammars.
fn read_raw<'u>(body: &'u [u8], pointer: &str) -> Option<&'u [u8]> {
    match busbar_contract::spans::resolve_pointer(body, pointer) {
        busbar_contract::spans::Resolved::Found(span) => body.get(span.start..span.end),
        _ => None,
    }
}

/// Whether a body has a member at one pointer at all.
fn has(body: &[u8], pointer: &str) -> bool {
    read_raw(body, pointer).is_some()
}

/// Which code and words this dialect answers one refusal reason with.
///
/// ## What this mapping is, and what it is not
///
/// The existing codec renders a refusal through the shared ingress vocabulary, which is visible to
/// its own crate only, so this table cannot be read off it. What IS pinned is the ENVELOPE — the
/// member order, the typed detail entry and the code table, all asserted byte for byte in the
/// envelope module's own tests. What is NOT pinned is the message TEXT, which the composition root
/// must compare against the rig's recorded answers on the day it switches this plane on. That is
/// stated here rather than left for someone to discover.
fn refusal_render(reason: RefusalReason) -> (i64, &'static str) {
    match reason {
        // The caller's request was not one this node will take.
        RefusalReason::BodyTooLarge => (jsonrpc::CODE_INVALID_REQUEST, "the request is too large"),
        RefusalReason::SchemeNotDeclared
        | RefusalReason::CredentialRejected
        | RefusalReason::SessionUnbound
        | RefusalReason::CredentialBudget => (
            jsonrpc::CODE_INVALID_REQUEST,
            "the request did not carry usable authority",
        ),
        // The caller is known and may not do this.
        RefusalReason::ScopeMissing | RefusalReason::Vetoed | RefusalReason::Revoked => (
            jsonrpc::CODE_UNSUPPORTED_OPERATION,
            "the caller may not perform this operation",
        ),
        // There is nowhere for it to go.
        RefusalReason::NoDestination => (
            jsonrpc::CODE_INVALID_PARAMS,
            "no agent is reachable for this request",
        ),
        // Everything else is this node saying no for a reason that is this node's own. A caller is
        // told that it failed here, and is told nothing about the money, the buckets or the store.
        _ => (
            jsonrpc::CODE_INTERNAL,
            "the request could not be served at this time",
        ),
    }
}

/// The finish class one unit ending is.
fn finish_of(end: &UnitEnd, streaming: bool) -> FinishClass {
    match end {
        UnitEnd::Completed if streaming => FinishClass::TurnComplete,
        UnitEnd::Completed => FinishClass::Complete,
        UnitEnd::Refused(_) | UnitEnd::Failed { .. } => FinishClass::Error,
        UnitEnd::Aborted(AbortBy::Client) | UnitEnd::Stalled => FinishClass::Partial,
        UnitEnd::Aborted(AbortBy::Kernel { .. }) => FinishClass::Error,
    }
}

impl Plane for A2aPlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        let Some(frame) = frames.next_frame() else {
            return Ok(Ingress::NeedMore);
        };
        let body = frame.bytes.as_slice();
        // An empty frame is not yet a document. This protocol frames one document per frame, so the
        // only reason to see nothing is that nothing has arrived.
        if body.is_empty() {
            return Ok(Ingress::NeedMore);
        }
        let envelope = jsonrpc::read(body)?;
        let method = envelope.method_str(body).ok_or(Decode::Malformed)?;
        let row = ops::row_for(method).ok_or(Decode::UnsupportedOperation)?;
        let facts = request_facts(body, &envelope);
        let correlation_out = envelope
            .id_bytes(body)
            .and_then(|raw| f::correlation_for(raw, ctx.arena()));
        let draft = UnitDraft {
            op: row.op,
            body_ir: view(body, jsonrpc::REQUEST_PTRS, ctx)?,
            // A request answers nothing; it is answered.
            correlates: None,
            correlation_out,
            facts,
        };
        // A request whose answer arrives as a run of events stays OPEN across those events. One
        // whose answer is a single document is complete in this frame.
        if row.streaming {
            Ok(Ingress::Open(draft))
        } else {
            Ok(Ingress::OneShot(draft))
        }
    }

    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        let body = u.body().body();
        // The caller's envelope goes on unchanged unless a record leg came back saying the agent
        // knows this task by a different name. That is the ONE rewrite this protocol performs, and
        // it performs it for one reason: the identifier this node minted is not the identifier the
        // agent minted, and relaying ours would name a task the agent has never heard of.
        let bytes = match backend_task_id(u) {
            Some(backend) => rewrite_task_id(body, backend)?,
            None => body.to_vec(),
        };
        let body = ctx
            .arena()
            .alloc_bytes(&bytes)
            .map_err(|_| Encode::ArenaExhausted)?;
        let mut envelope = TransportEnvelope::default();
        let content_type = ctx
            .arena()
            .alloc_bytes(CONTENT_TYPE_JSON)
            .map_err(|_| Encode::ArenaExhausted)?;
        let _ = envelope.fields.push(busbar_contract::wire::EnvelopeField {
            name: FIELD_CONTENT_TYPE,
            value: content_type,
        });
        if let Some(version) = ctx.session().and_then(|s| s.session_fact(f::FACT_VERSION)) {
            let value = ctx
                .arena()
                .alloc_bytes(version.as_bytes())
                .map_err(|_| Encode::ArenaExhausted)?;
            let _ = envelope.fields.push(busbar_contract::wire::EnvelopeField {
                name: FIELD_VERSION,
                value,
            });
        }
        // A destination this plane cannot express a hop for is an encode failure rather than a
        // silent hop to somewhere else.
        if !matches!(
            dest.facts(),
            DestinationFacts::Upstream { .. } | DestinationFacts::SessionUpstream { .. }
        ) {
            return Err(Encode::Unrepresentable);
        }
        Ok(EgressBody {
            envelope,
            body,
            auth: busbar_contract::ids::SchemeKey::new(EGRESS_SCHEME),
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
        // An OPEN unit of this plane is one whose ANSWER streams; the request itself was complete in
        // the frame that opened it. So an inbound frame arriving under an open unit belongs to no
        // outbound request, and the honest answer is that it is consumed and nothing goes out for
        // it. Relaying it would send the agent a document it never asked for.
        Ok(None)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        let Some(frame) = frames.next_frame() else {
            return Ok(Progress::NeedMore);
        };
        let body = frame.bytes.as_slice();
        if body.is_empty() {
            return Ok(Progress::NeedMore);
        }
        // An answer carries an identifier. A document arriving on an upstream WITHOUT one is not an
        // answer at all: it is the agent pushing something, which opens a unit of its own and runs
        // all seven steps like any other.
        let id = read_raw(body, jsonrpc::PTR_ID);
        let is_error = has(body, jsonrpc::PTR_ERROR);
        let has_result = has(body, jsonrpc::PTR_RESULT);
        if id.is_none() && !is_error && !has_result {
            let mut facts = Facts::new();
            if let Some(task) = read_str(body, "/taskId").or_else(|| read_str(body, "/id")) {
                let _ = facts.set(f::FACT_TASK_ID, FactValue::Str(task));
            }
            return Ok(Progress::OneShot(UnitDraft {
                op: ops::OP_PUSH_EVENT,
                body_ir: view(body, jsonrpc::RESPONSE_PTRS, ctx)?,
                correlates: None,
                correlation_out: None,
                facts,
            }));
        }

        let mut facts = Facts::new();
        if let Some(raw) = id {
            if let Ok(text) = core::str::from_utf8(raw) {
                let _ = facts.set(f::FACT_RPC_ID, FactValue::Str(text));
            }
        }
        if let Some(state) = read_str(body, "/result/status/state") {
            let _ = facts.set(f::FACT_TASK_STATE, FactValue::Str(state));
        }
        if let Some(task) = read_str(body, "/result/id") {
            let _ = facts.set(f::FACT_TASK_ID, FactValue::Str(task));
        }
        if let Some(context) = read_str(body, "/result/contextId") {
            let _ = facts.set(f::FACT_CONTEXT_ID, FactValue::Str(context));
        }
        if let Some(code) = read_raw(body, jsonrpc::PTR_ERROR_CODE) {
            if let Ok(text) = core::str::from_utf8(code) {
                let _ = facts.set(f::FACT_ERROR_CODE, FactValue::Str(text));
            }
        }
        let for_ = id.and_then(|raw| f::correlation_for(raw, ctx.arena()));
        // An answer that says it is the last one is the last one. An answer carrying an error is
        // also the last one, whatever it says about itself: an agent does not keep streaming after
        // it has reported that it failed.
        let final_event = read_raw(body, "/result/final") == Some(b"true".as_slice());
        let terminal = is_error || final_event || !has(body, "/result/kind");
        if let Some(state) = st {
            if let Some(codec) = state.get_mut::<Codec>() {
                codec.events_read = codec.events_read.saturating_add(1);
            }
        }
        let r = Response {
            ir: view(body, jsonrpc::RESPONSE_PTRS, ctx)?,
            finish: if is_error {
                FinishClass::Error
            } else if terminal {
                FinishClass::Complete
            } else {
                FinishClass::TurnComplete
            },
            facts,
        };
        if terminal {
            Ok(Progress::Terminal { for_, r })
        } else {
            Ok(Progress::Frame { for_, r })
        }
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let body = r.ir.body();
        // An answer that already IS an envelope goes back exactly as it arrived. This is the common
        // path and it is byte-identical by construction: the agent answered the caller's own
        // identifier, because the caller's own envelope is what was relayed.
        if has(body, jsonrpc::PTR_VERSION) {
            return ctx
                .arena()
                .alloc_bytes(body)
                .map_err(|_| Encode::ArenaExhausted);
        }
        // An answer this node composed itself — the ones served out of its own records — arrives as
        // a bare result and is wrapped here, with the identifier the decode step recorded.
        let id = match r.facts.get(f::FACT_RPC_ID) {
            Some(FactValue::Str(text)) => jsonrpc::id_value(text.as_bytes())?,
            _ => serde_json::Value::Null,
        };
        let bytes = jsonrpc::success(&id, body)?;
        ctx.arena()
            .alloc_bytes(&bytes)
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let id = match draft.and_then(|d| d.facts.get(f::FACT_RPC_ID)) {
            Some(FactValue::Str(text)) => jsonrpc::id_value(text.as_bytes())?,
            _ => serde_json::Value::Null,
        };
        let (code, message) = refusal_render(refusal.reason);
        let bytes = jsonrpc::error(&id, code, message)?;
        ctx.arena()
            .alloc_bytes(&bytes)
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        // This protocol writes nothing to end a unit. A single answer ends when its document has
        // been written; a streamed answer ends when its last event has. Emitting a closing frame
        // would be a byte on the wire that is not there today.
        Ok(None)
    }

    fn authenticate<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> CredentialLocator {
        // Three of this protocol's surfaces carry no credential by design: the two discovery
        // documents anyone may read, and the callback an agent this node dialled posts back to.
        // Their claims declare no scheme, so there is nothing to narrow WITHIN and this step names
        // nothing — which is a stronger statement than the invented "anonymous" alternative it
        // replaces, because that one was a value a plane could narrow an authenticated claim down
        // to. The rest present a bearer credential.
        let open_surface = matches!(u.op(), ops::OP_PUSH_EVENT);
        CredentialLocator {
            narrowing: if open_surface {
                None
            } else {
                Some(SchemeAlt::new("bearer"))
            },
            // A bound session's principal is the cached one; an unbound session re-authenticates
            // every unit, and a unit the agent pushed is the kernel's own pairing rather than
            // anything on these bytes.
            from_session: ctx
                .session()
                .is_some_and(busbar_contract::unit::SessionView::is_bound),
        }
    }

    fn verify<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        match u.op() {
            // The operations this node answers out of its own records reach a record and no agent.
            ops::OP_TASK_LIST => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_TASK,
                op: rec::OP_SCAN,
            },
            ops::OP_PUSH_CONFIG_GET => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_PUSH_CONFIG,
                op: rec::OP_GET,
            },
            ops::OP_PUSH_CONFIG_LIST => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_PUSH_CONFIG,
                op: rec::OP_SCAN,
            },
            ops::OP_AGENT_CARD => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_PIN,
                op: rec::OP_GET,
            },
            // A push the agent sent reaches this node's own record of the task it is about.
            ops::OP_PUSH_EVENT => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_TASK,
                op: rec::OP_PUT,
            },
            // Everything else is a hop to the agent.
            _ => self.upstream_destination(),
        }
    }

    fn approve<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        let mut facts = ScopeFacts::default();
        // The resource is the agent, under the kind the codec already names it by. The plane says
        // WHAT is being asked for; which scope that requires, and whether this principal holds it,
        // is the scope unit's answer and never this plane's.
        if let Some(agent) = self.agents().first() {
            let _ = facts.resources.push(ResourceLocator {
                kind: "agent",
                name: agent.id,
            });
        }
        facts
    }

    fn admit<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        AdmitFacts {
            // The lane is not in the request. It is a property of the agent the operator
            // configured, and the trust unit re-derives it against the allow-list.
            lane_locator: None,
            // This protocol gives a caller no way to declare a ceiling on the answer, so no
            // place is named for one.
            max_response_ptrs: BoundedVec::new(),
            // The priced input is the whole request document.
            input_span: Some(Span {
                start: 0,
                end: u.body().body().len(),
            }),
        }
    }

    fn route<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> RoutePlan {
        let mut plan = RoutePlan::default();
        let mut leg = |l: Leg| {
            let _ = plan.legs.push(l);
        };
        match u.op() {
            ops::OP_MESSAGE_SEND | ops::OP_MESSAGE_STREAM => {
                // Open the task, record that it opened, then hop.
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_PUT));
                leg(Self::record_leg(rec::SCHEMA_TASK_EVENT, rec::OP_APPEND));
                leg(self.upstream_leg());
            }
            ops::OP_TASK_GET | ops::OP_TASK_SUBSCRIBE => {
                // Read the row first: it is what says whether this caller may see the task at all,
                // and what the agent's own name for it is.
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_GET));
                leg(self.upstream_leg());
            }
            ops::OP_TASK_CANCEL => {
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_GET));
                leg(self.upstream_leg());
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_PUT));
                leg(Self::record_leg(rec::SCHEMA_TASK_EVENT, rec::OP_APPEND));
            }
            ops::OP_TASK_LIST => leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_SCAN)),
            ops::OP_PUSH_CONFIG_CREATE => {
                leg(Self::record_leg(rec::SCHEMA_PUSH_CONFIG, rec::OP_PUT));
                leg(Self::record_leg(rec::SCHEMA_PIN, rec::OP_PUT));
                leg(self.upstream_leg());
            }
            ops::OP_PUSH_CONFIG_GET => leg(Self::record_leg(rec::SCHEMA_PUSH_CONFIG, rec::OP_GET)),
            ops::OP_PUSH_CONFIG_LIST => {
                leg(Self::record_leg(rec::SCHEMA_PUSH_CONFIG, rec::OP_SCAN))
            }
            ops::OP_PUSH_CONFIG_DELETE => {
                leg(Self::record_leg(rec::SCHEMA_PUSH_CONFIG, rec::OP_DELETE));
                leg(Self::record_leg(rec::SCHEMA_PIN, rec::OP_DELETE));
                leg(self.upstream_leg());
            }
            ops::OP_AGENT_CARD => leg(Self::record_leg(rec::SCHEMA_PIN, rec::OP_GET)),
            ops::OP_PUSH_EVENT => {
                // The token the agent presented is spent exactly once, and spending it is what says
                // which task the push is about.
                leg(Self::record_leg(rec::SCHEMA_PUSH_CONFIG, rec::OP_REDEEM));
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_GET));
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_PUT));
                leg(Self::record_leg(rec::SCHEMA_TASK_EVENT, rec::OP_APPEND));
            }
            // An operation class this plane does not carry gets no legs, which is an empty plan and
            // a refusal at the routing step. Not a panic, and not a guess.
            _ => {}
        }
        plan
    }

    fn meter<'u>(&self, _u: &Unit<'u>, r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        let mut locators = UsageLocators::default();
        let _ = locators.lines.push(UsageLocator {
            class: CLASS_BYTES,
            // The quantity is not at a pointer: it is the size of the document the plane just read.
            // So the locator carries the value and no location, which the contract allows precisely
            // for the case where the plane already has the number in front of it.
            location: None,
            quantity: Some(r.ir.body().len() as u64),
            // This protocol's answers do not name a lane. The lane is the agent's, and the trust
            // unit sealed it; a plane naming a second one would be a second opinion.
            lane: None,
        });
        locators
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        let streaming = Self::row_for_op(u.op()).is_some_and(|r| r.streaming);
        AuditFacts {
            // The DRAFT's class is the one that priced the unit, and this is that class read back
            // off the unit. A plane that named a different class here would be disputing its own
            // earlier answer, which is exactly what the loop treats it as.
            op_class: u.op(),
            finish: finish_of(out, streaming),
        }
    }

    fn plane_facts<'u>(
        &self,
        verb: AdminVerbId,
        subject: Option<&'u str>,
        ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        let _ = ctx;
        let mut facts = Facts::new();
        match verb {
            v if v == crate::meta::VERB_AGENTS => {
                let _ = facts.set("count", FactValue::Int(self.agents().len() as i64));
                for agent in self.agents() {
                    // The agent's name is the key and the lane it is priced on is the value.
                    // Nothing here is a credential, a price or an address: an operator reading this
                    // learns which agents are configured and on which lane, which is what an
                    // introspection verb is for.
                    let _ = facts.set(agent.id, FactValue::Str(agent.lane.as_str()));
                }
            }
            v if v == crate::meta::VERB_AGENT => {
                // The projection over ONE agent. A subject that names no agent is an unsupported
                // operation rather than an empty answer: "there is no such agent" and "that agent
                // has nothing to report" are different facts.
                let name = subject.ok_or(Decode::UnsupportedOperation)?;
                let agent = self
                    .agents()
                    .iter()
                    .find(|a| a.id == name)
                    .ok_or(Decode::UnsupportedOperation)?;
                let _ = facts.set(SUBJECT_FACT_NAME, FactValue::Str(agent.id));
                let _ = facts.set(SUBJECT_FACT_LANE, FactValue::Str(agent.lane.as_str()));
                let _ = facts.set(SUBJECT_FACT_TRANSPORT, FactValue::Str(agent.transport));
            }
            _ => return Err(Decode::UnsupportedOperation),
        }
        Ok(PlaneFacts { facts })
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        let body = r.ir.body();
        let mut facts = Facts::new();
        // Only the declared keys, and only what was actually read. The message content itself never
        // appears here, and neither does anything the caller presented as authority.
        for (key, value) in [
            (f::FACT_TASK_ID, read_str(body, "/result/id")),
            (f::FACT_CONTEXT_ID, read_str(body, "/result/contextId")),
            (f::FACT_TASK_STATE, read_str(body, "/result/status/state")),
        ] {
            if let Some(text) = value {
                let _ = facts.set(key, FactValue::Str(text));
            }
        }
        if let Some(code) = read_raw(body, jsonrpc::PTR_ERROR_CODE) {
            if let Ok(text) = core::str::from_utf8(code) {
                let _ = facts.set(f::FACT_ERROR_CODE, FactValue::Str(text));
            }
        }
        ContentFacts { facts }
    }
}

impl SessionPlane for A2aPlane {
    fn open_session<'u>(&self, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Codec::default())
    }

    fn open_upstream<'u>(&self, _dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Codec::default())
    }
}

/// The agent's own name for a task, where a record leg came back carrying one.
fn backend_task_id<'u>(u: &Unit<'u>) -> Option<&'u str> {
    for result in u.leg_results() {
        if let Some(FactValue::Str(text)) = result.facts.get(LEG_FACT_BACKEND_TASK_ID) {
            return Some(text);
        }
    }
    None
}

/// The request with every task-identifier member replaced by the agent's own name for the task.
///
/// The three member names are the ones the codec already looks for, and the rewrite is done by
/// reading the document and writing it again — which is what the codec does too, so the bytes that
/// reach the agent are the bytes that reach it today.
fn rewrite_task_id(body: &[u8], backend: &str) -> Result<Vec<u8>, Encode> {
    /// The members that carry a task's identifier, in the three spellings this protocol uses.
    const MEMBERS: [&str; 3] = ["id", "taskId", "task_id"];
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| Encode::Unrepresentable)?;
    let Some(params) = value.get_mut("params").and_then(|p| p.as_object_mut()) else {
        // Nothing to rewrite is not a failure: the caller sent no parameters, so no identifier of
        // theirs is going anywhere.
        return Ok(body.to_vec());
    };
    for member in MEMBERS {
        if params.contains_key(member) {
            params.insert(member.into(), serde_json::Value::String(backend.into()));
        }
    }
    serde_json::to_vec(&value).map_err(|_| Encode::Unrepresentable)
}

#[cfg(test)]
mod tests {
    use super::{finish_of, refusal_render, rewrite_task_id, Codec};
    use busbar_contract::unit::{AbortBy, FailureReason, RefusalReason, Step, UnitEnd};

    /// Every closed refusal reason has an answer, and every answer is a code this dialect defines.
    ///
    /// Totality is the point: a reason with no row would be a caller who is told nothing, and the
    /// contract's reason list is closed precisely so this can be checked rather than hoped for.
    #[test]
    fn every_refusal_reason_has_an_answer() {
        let reasons = [
            RefusalReason::InFlightCap,
            RefusalReason::CursorBudget,
            RefusalReason::CredentialBudget,
            RefusalReason::SessionBudget,
            RefusalReason::BodyTooLarge,
            RefusalReason::OpenSlotBusy,
            RefusalReason::SchemeNotDeclared,
            RefusalReason::CredentialRejected,
            RefusalReason::SessionUnbound,
            RefusalReason::Revoked,
            RefusalReason::ScopeMissing,
            RefusalReason::Vetoed,
            RefusalReason::NoDestination,
            RefusalReason::OverBudget,
            RefusalReason::GroupFrozen,
            RefusalReason::Unpriced,
            RefusalReason::OverdraftCeiling,
            RefusalReason::StaleSlice,
            RefusalReason::DurabilityUnavailable,
            RefusalReason::TierMismatch,
        ];
        let known: Vec<i64> = crate::jsonrpc::ERRORS
            .iter()
            .map(|(c, _)| *c)
            .chain([
                crate::jsonrpc::CODE_INVALID_REQUEST,
                crate::jsonrpc::CODE_METHOD_NOT_FOUND,
                crate::jsonrpc::CODE_INVALID_PARAMS,
                crate::jsonrpc::CODE_INTERNAL,
            ])
            .collect();
        for reason in reasons {
            let (code, message) = refusal_render(reason);
            assert!(
                known.contains(&code),
                "{reason:?} renders unknown code {code}"
            );
            assert!(!message.is_empty(), "{reason:?} renders no words");
        }
    }

    /// A refusal tells the caller nothing about the money.
    ///
    /// The words a caller sees must not leak which bucket was dry, which group was frozen or which
    /// slice was stale: those are the node's business and a caller learning them learns about other
    /// callers.
    #[test]
    fn a_refusal_leaks_nothing_about_the_money() {
        for reason in [
            RefusalReason::OverBudget,
            RefusalReason::GroupFrozen,
            RefusalReason::Unpriced,
            RefusalReason::OverdraftCeiling,
            RefusalReason::StaleSlice,
        ] {
            let (_, message) = refusal_render(reason);
            for leak in ["budget", "bucket", "frozen", "price", "slice", "overdraft"] {
                assert!(
                    !message.to_ascii_lowercase().contains(leak),
                    "{reason:?} leaks {leak}"
                );
            }
        }
    }

    /// A completed streamed answer ends a turn; a completed single answer is complete.
    #[test]
    fn a_streamed_answer_ends_a_turn() {
        assert_eq!(
            finish_of(&UnitEnd::Completed, true),
            busbar_contract::unit::FinishClass::TurnComplete
        );
        assert_eq!(
            finish_of(&UnitEnd::Completed, false),
            busbar_contract::unit::FinishClass::Complete
        );
    }

    /// A client that went away leaves a partial answer; a kernel that ended it leaves an error.
    #[test]
    fn who_ended_it_decides_how_it_ended() {
        assert_eq!(
            finish_of(&UnitEnd::Aborted(AbortBy::Client), false),
            busbar_contract::unit::FinishClass::Partial
        );
        assert_eq!(
            finish_of(
                &UnitEnd::Aborted(AbortBy::Kernel {
                    reason: RefusalReason::Revoked
                }),
                false
            ),
            busbar_contract::unit::FinishClass::Error
        );
        assert_eq!(
            finish_of(
                &UnitEnd::Failed {
                    step: Step::Route,
                    reason: FailureReason::Transport
                },
                false
            ),
            busbar_contract::unit::FinishClass::Error
        );
    }

    /// The rewrite replaces every spelling of the identifier and leaves everything else alone.
    #[test]
    fn the_rewrite_replaces_every_spelling() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"ours","other":"kept"}}"#;
        let out = rewrite_task_id(body, "theirs").expect("the rewrite writes");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("it is a document");
        assert_eq!(value["params"]["id"], "theirs");
        assert_eq!(value["params"]["other"], "kept");
        // The envelope's own identifier is the CALLER's and is never rewritten: the agent echoes it
        // and the caller is waiting for exactly those bytes back.
        assert_eq!(value["id"], 1);
    }

    /// A request with no parameters is passed through unchanged, byte for byte.
    #[test]
    fn a_request_with_no_parameters_passes_through() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#;
        let out = rewrite_task_id(body, "theirs").expect("the rewrite writes");
        assert_eq!(out, body.to_vec());
    }

    /// The codec state starts at nothing and counts up.
    #[test]
    fn the_codec_state_counts_events() {
        let mut codec = Codec::default();
        assert_eq!(codec.events_read, 0);
        codec.events_read = codec.events_read.saturating_add(1);
        assert_eq!(codec.events_read, 1);
    }
}
