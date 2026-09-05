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
use busbar_contract::wire::{Decode, DiscardCode, Encode, Frame, FrameCursor, TransportEnvelope};

use crate::facts as f;
use crate::jsonrpc;
use crate::meta::{CLASS_BYTES, CLASS_TOOL_CALLS};
use crate::ops;
use crate::records as rec;
use crate::McpPlane;

/// The per-connection codec state this plane keeps.
///
/// It holds two counts and nothing else. This protocol frames one document per frame, so there is no
/// partial document to carry across a call; what a connection does need to remember is how far into
/// a held stream it is, and how many rounds an upstream has asked for during one call — the second
/// because a round cap is only a cap if something counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Codec {
    /// How many event frames of a held stream this half has read.
    pub events_read: u32,
    /// How many times an upstream has asked for something during the call on this half.
    pub rounds_asked: u32,
}

/// The credential scheme the outbound hop is decorated under.
///
/// The plane NAMES the scheme and never holds what is behind it. Which secret the scheme resolves,
/// and whether the caller may use it at all, is the egress-auth unit's answer.
const EGRESS_SCHEME: &str = "mcp-egress";

/// The envelope member naming the document type of an outbound body.
const FIELD_CONTENT_TYPE: &str = "content-type";

/// The document type every body of this protocol is.
const CONTENT_TYPE_JSON: &[u8] = b"application/json";

/// The envelope member naming which revision the hop is made under.
const FIELD_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// The fact key the per-name projection reports the registration's own name under.
const SUBJECT_FACT_NAME: &str = "name";

/// The fact key the per-name projection reports the priced lane under.
const SUBJECT_FACT_LANE: &str = "lane";

/// The fact key the per-name projection reports the dialling transport under.
const SUBJECT_FACT_TRANSPORT: &str = "transport";

/// The fact key the per-name projection reports a locally launched registration under.
const SUBJECT_FACT_LOCAL: &str = "local";

/// The kind of resource a registered server is, in this plane's own vocabulary.
const RESOURCE_KIND_SERVER: &str = "mcp_server";

/// The kind of resource one tool is, in this plane's own vocabulary.
const RESOURCE_KIND_TOOL: &str = "mcp_tool";

impl McpPlane {
    /// A leg reaching one of this plane's own records.
    fn record_leg(schema: busbar_contract::ids::RecordSchemaId, op: &'static str) -> Leg {
        Leg {
            destination: DestinationFacts::PlaneRecord { schema, op },
        }
    }

    /// A leg reaching the configured server, or an unreachable one when none is configured.
    fn upstream_leg(&self) -> Leg {
        Leg {
            destination: self.upstream_destination(),
        }
    }

    /// Where a hop to the configured server goes.
    ///
    /// A plane with nothing configured answers honestly rather than panicking or inventing a host:
    /// the empty host is refused by the trust unit against the allow-list, which is the right place
    /// for that refusal to happen.
    fn upstream_destination(&self) -> DestinationFacts {
        match self.servers().first() {
            Some(server) => DestinationFacts::Upstream {
                transport: server.transport,
                address: busbar_contract::UpstreamAddress::socket(server.host),
                lane: server.lane,
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

/// The facts a request body yields, read once.
fn request_facts<'u>(body: &'u [u8], envelope: &jsonrpc::Envelope) -> Facts<'u> {
    let mut facts = Facts::new();
    if let Some(method) = envelope.method_str(body) {
        let _ = facts.set(f::FACT_METHOD, FactValue::Str(method));
        if let Some(row) = ops::row_for(method) {
            // The subject is what the request is ABOUT, read from where the codec's own table says
            // it lives — never from the request's content.
            if let Some(pointer) = row.name_pointer {
                if let Some(subject) = read_str(body, pointer) {
                    let _ = facts.set(f::FACT_SUBJECT, FactValue::Str(subject));
                }
            }
        }
    }
    if let Some(raw) = envelope.id_bytes(body) {
        if let Ok(text) = core::str::from_utf8(raw) {
            let _ = facts.set(f::FACT_RPC_ID, FactValue::Str(text));
        }
    }
    // The caller's own metadata block, read for the two members the loop needs and no others. The
    // block's keys carry separators, which a pointer would read as levels, so the whole block is
    // located by pointer and its members are read by name out of it.
    if let Some(block) = read_raw(body, "/params/_meta") {
        if let Some(version) = member_of(block, f::META_PROTOCOL_VERSION) {
            let _ = facts.set(f::FACT_PROTOCOL_VERSION, FactValue::Str(version));
        }
        if let Some(token) = member_of(block, f::META_PROGRESS_TOKEN) {
            let _ = facts.set(f::FACT_PROGRESS_TOKEN, FactValue::Str(token));
        }
    }
    facts
}

/// One quoted member of a flat object, by its exact name.
///
/// The metadata block's own keys contain separators, and a pointer reads a separator as a level, so
/// they cannot be reached by pointer at all. This reads the member by name instead, which is the
/// same walk one level down and no more.
fn member_of<'u>(object: &'u [u8], name: &str) -> Option<&'u str> {
    let needle = format!("\"{name}\"");
    let at = find(object, needle.as_bytes())?;
    let mut i = at + needle.len();
    while i < object.len() && matches!(object[i], b' ' | b'\t' | b'\n' | b'\r' | b':') {
        i += 1;
    }
    if object.get(i) != Some(&b'"') {
        return None;
    }
    let start = i + 1;
    let mut j = start;
    while j < object.len() {
        match object[j] {
            b'\\' => j += 2,
            b'"' => return core::str::from_utf8(object.get(start..j)?).ok(),
            _ => j += 1,
        }
    }
    None
}

/// Where a byte run first appears in another, if it does.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Which code and words this dialect answers one refusal reason with.
///
/// ## What this mapping is, and what it is not
///
/// The existing codec renders a refusal through builders that are visible to its own crate only, so
/// this table cannot be read off them. What IS pinned is the ENVELOPE — the member order, the
/// always-written identifier on an error, the omitted one on a success, and the code table, all
/// asserted byte for byte in the envelope module's own tests. What is NOT pinned is the message
/// TEXT, which the composition root must compare against the battery's recorded answers on the day
/// it switches this plane on. That is stated here rather than left for someone to discover.
fn refusal_render(reason: RefusalReason) -> (i64, &'static str) {
    match reason {
        RefusalReason::BodyTooLarge => (jsonrpc::CODE_INVALID_REQUEST, "the request is too large"),
        RefusalReason::SchemeNotDeclared
        | RefusalReason::CredentialRejected
        | RefusalReason::SessionUnbound
        | RefusalReason::CredentialBudget => (
            jsonrpc::CODE_INVALID_REQUEST,
            "the request did not carry usable authority",
        ),
        // The caller is known and may not do this. This protocol has its own code for a policy
        // refusal, and it is outside the range the specification reserves for itself.
        RefusalReason::ScopeMissing | RefusalReason::Vetoed | RefusalReason::Revoked => (
            jsonrpc::CODE_REFUSED,
            "the caller may not perform this operation",
        ),
        // There is nowhere for it to go, which this protocol names specifically.
        RefusalReason::NoDestination => (
            jsonrpc::CODE_UPSTREAM_UNAVAILABLE,
            "no server is reachable for this request",
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

impl Plane for McpPlane {
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
        if body.is_empty() {
            return Ok(Ingress::NeedMore);
        }
        let envelope = jsonrpc::read(body)?;
        let method = envelope.method_str(body).ok_or(Decode::Malformed)?;
        let facts = request_facts(body, &envelope);

        // A message with no identifier is a NOTICE. The specification forbids answering one, so a
        // notice this plane recognises opens a unit that ends without writing anything, and one it
        // does not recognise is DROPPED — never refused, because a refusal is an answer.
        if !envelope.is_request() {
            if !ops::is_known_notification(method) {
                return Ok(Ingress::Discard {
                    reason: DiscardCode::Unsupported,
                });
            }
            return Ok(Ingress::OneShot(UnitDraft {
                op: ops::OP_NOTIFICATION,
                body_ir: view(body, jsonrpc::REQUEST_PTRS, ctx)?,
                correlates: None,
                correlation_out: None,
                facts,
            }));
        }

        let row = ops::row_for(method).ok_or(Decode::UnsupportedOperation)?;
        // A method an UPSTREAM sends is not one a caller may send. Reading it here would let a
        // caller open a unit that only a paired server is allowed to open.
        if row.sender == ops::Sender::Provider {
            return Err(Decode::UnsupportedOperation);
        }
        let draft = UnitDraft {
            op: row.op,
            body_ir: view(body, jsonrpc::REQUEST_PTRS, ctx)?,
            correlates: None,
            correlation_out: envelope
                .id_bytes(body)
                .and_then(|raw| f::correlation_for(raw, ctx.arena())),
            facts,
        };
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
        // The caller's envelope goes on unchanged. This protocol names its operation in the body,
        // so there is nothing in an outbound request that this node rewrites — and rewriting one
        // would be a byte on the wire that is not there today.
        let body = ctx
            .arena()
            .alloc_bytes(u.body().body())
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
        if let Some(version) = ctx
            .session()
            .and_then(|s| s.session_fact(f::FACT_PROTOCOL_VERSION))
        {
            let value = ctx
                .arena()
                .alloc_bytes(version.as_bytes())
                .map_err(|_| Encode::ArenaExhausted)?;
            let _ = envelope.fields.push(busbar_contract::wire::EnvelopeField {
                name: FIELD_PROTOCOL_VERSION,
                value,
            });
        }
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
        // An OPEN unit of this plane is a HELD STREAM: the request that opened it was complete in
        // one frame, and what flows afterwards flows outward. So an inbound frame arriving under an
        // open unit belongs to no outbound request, and the honest answer is that it is consumed and
        // nothing goes out for it.
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

        // A document arriving from a server that names a METHOD is the server ASKING for something,
        // not answering. It opens a unit of its own and runs all seven steps, and what answers it
        // costs money on this node's budget rather than on the server's.
        if has(body, jsonrpc::PTR_METHOD) {
            let envelope = jsonrpc::read(body)?;
            let method = envelope.method_str(body).ok_or(Decode::Malformed)?;
            let mut facts = Facts::new();
            let _ = facts.set(f::FACT_METHOD, FactValue::Str(method));
            if let Some(raw) = envelope.id_bytes(body) {
                if let Ok(text) = core::str::from_utf8(raw) {
                    let _ = facts.set(f::FACT_RPC_ID, FactValue::Str(text));
                }
            }
            if let Some(state) = st {
                if let Some(codec) = state.get_mut::<Codec>() {
                    codec.rounds_asked = codec.rounds_asked.saturating_add(1);
                }
            }
            let Some(row) = ops::row_for(method) else {
                // A notice a server sends is dropped, exactly as one a caller sends is.
                return Ok(Progress::Discard {
                    reason: DiscardCode::Unsupported,
                });
            };
            // The subject is read HERE, at the one step entitled to read the bytes, so the steps
            // after this one read it off the draft rather than scanning the request a second time.
            if let Some(pointer) = row.name_pointer {
                if let Some(subject) = read_str(body, pointer) {
                    let _ = facts.set(f::FACT_SUBJECT, FactValue::Str(subject));
                }
            }
            return Ok(Progress::OneShot(UnitDraft {
                op: row.op,
                body_ir: view(body, jsonrpc::REQUEST_PTRS, ctx)?,
                // A server's own request answers nothing; it is answered.
                correlates: None,
                correlation_out: envelope
                    .id_bytes(body)
                    .and_then(|raw| f::correlation_for(raw, ctx.arena())),
                facts,
            }));
        }

        let id = read_raw(body, jsonrpc::PTR_ID);
        let is_error = has(body, jsonrpc::PTR_ERROR);
        let mut facts = Facts::new();
        if let Some(raw) = id {
            if let Ok(text) = core::str::from_utf8(raw) {
                let _ = facts.set(f::FACT_RPC_ID, FactValue::Str(text));
            }
        }
        if let Some(kind) = read_str(body, jsonrpc::PTR_RESULT_TYPE) {
            let _ = facts.set(f::FACT_RESULT_TYPE, FactValue::Str(kind));
        }
        if let Some(flag) = read_raw(body, jsonrpc::PTR_IS_ERROR) {
            let _ = facts.set(f::FACT_IS_ERROR, FactValue::Bool(flag == b"true"));
        }
        if let Some(code) = read_raw(body, jsonrpc::PTR_ERROR_CODE) {
            if let Ok(text) = core::str::from_utf8(code) {
                let _ = facts.set(f::FACT_ERROR_CODE, FactValue::Str(text));
            }
        }
        if let Some(state) = st {
            if let Some(codec) = state.get_mut::<Codec>() {
                codec.events_read = codec.events_read.saturating_add(1);
            }
        }
        // A result whose discriminator says it is finished IS finished. One that asks the caller for
        // something, or hands back a task, is a turn rather than an ending: the exchange continues.
        let kind = read_str(body, jsonrpc::PTR_RESULT_TYPE);
        let finish = if is_error {
            FinishClass::Error
        } else if matches!(
            kind,
            Some(jsonrpc::RESULT_TYPE_INPUT_REQUIRED | jsonrpc::RESULT_TYPE_TASK)
        ) {
            FinishClass::TurnComplete
        } else {
            FinishClass::Complete
        };
        let r = Response {
            ir: view(body, jsonrpc::RESPONSE_PTRS, ctx)?,
            finish,
            facts,
        };
        // Every answer of this protocol is one document. There is no partial answer to relay: the
        // frame that carries a result carries all of it.
        Ok(Progress::Terminal {
            for_: id.and_then(|raw| f::correlation_for(raw, ctx.arena())),
            r,
        })
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let body = r.ir.body();
        // An answer that already IS an envelope goes back exactly as it arrived. This is the common
        // path and it is byte-identical by construction: the server answered the caller's own
        // identifier, because the caller's own envelope is what was relayed.
        if has(body, jsonrpc::PTR_VERSION) {
            return ctx
                .arena()
                .alloc_bytes(body)
                .map_err(|_| Encode::ArenaExhausted);
        }
        // An answer this node composed itself arrives as a bare result and is wrapped here, with
        // the identifier the decode step recorded and the discriminator this node chose.
        let id = match r.facts.get(f::FACT_RPC_ID) {
            Some(FactValue::Str(text)) => Some(jsonrpc::id_value(text.as_bytes())?),
            _ => None,
        };
        let kind = match r.facts.get(f::FACT_RESULT_TYPE) {
            Some(FactValue::Str(text)) => text,
            _ => jsonrpc::RESULT_TYPE_COMPLETE,
        };
        let bytes = jsonrpc::success(id.as_ref(), body, kind)?;
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
            Some(FactValue::Str(text)) => Some(jsonrpc::id_value(text.as_bytes())?),
            _ => None,
        };
        let (code, message) = refusal_render(refusal.reason);
        // A reason that implies a wait says so, under the member a caller can act on. Nothing else
        // about why is disclosed.
        let data = refusal
            .retry_after_secs
            .map(|secs| serde_json::json!({ "retryAfterSeconds": secs }));
        let bytes = jsonrpc::error(id.as_ref(), code, message, data)?;
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
        // This protocol writes nothing to end a unit. An answer ends when its document has been
        // written; a held stream ends when the connection does. Emitting a closing frame would be a
        // byte on the wire that is not there today.
        Ok(None)
    }

    fn authenticate<'u>(&self, _u: &Unit<'u>, ctx: &Ctx<'u>) -> CredentialLocator {
        // A locally launched server has no request to carry a header on: its credential is handed to
        // it when it starts. Everything on the document transport presents a bearer credential.
        let over_stdio = ctx.transport().key() == crate::claims::TRANSPORT_STDIO;
        let alt = if over_stdio { "environment" } else { "bearer" };
        // A notice asks for nothing, and it used to be narrowed to an invented "anonymous"
        // alternative for that reason. A notice arrives on the SAME claim a request does, though,
        // and that claim declares a scheme; the surface that genuinely carries no credential is the
        // discovery document, and it says so on its own claim. So a notice narrows like everything
        // else on the mount, and what its credential resolves to is the auth unit's answer.
        CredentialLocator {
            narrowing: Some(SchemeAlt::new(alt)),
            from_session: ctx
                .session()
                .is_some_and(busbar_contract::unit::SessionView::is_bound),
        }
    }

    fn verify<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        match u.op() {
            // The listings this node answers out of its own catalogue reach a record, not a server.
            ops::OP_DISCOVER
            | ops::OP_TOOLS_LIST
            | ops::OP_PROMPTS_LIST
            | ops::OP_RESOURCES_LIST
            | ops::OP_RESOURCE_TEMPLATES_LIST => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_CATALOGUE,
                op: rec::OP_SCAN,
            },
            // A held stream delivers back to the caller that opened it.
            ops::OP_SUBSCRIPTIONS_LISTEN => DestinationFacts::Client {
                selector: "opener",
                mode: busbar_contract::dest::ClientMode::Deliver,
            },
            // The task operations are answered out of this node's own task records.
            ops::OP_TASK_GET => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_TASK,
                op: rec::OP_GET,
            },
            ops::OP_TASK_UPDATE | ops::OP_TASK_CANCEL => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_TASK,
                op: rec::OP_PUT,
            },
            // A notice reaches nothing and answers nothing. It is recorded and that is all.
            ops::OP_NOTIFICATION => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_CATALOGUE,
                op: rec::OP_PUT,
            },
            // A server asking for a completion is answered by the OTHER plane, one level down. This
            // is the one nested destination this plane names, and it names it by a key its claim
            // configuration declares rather than by reaching for that plane directly.
            ops::OP_SAMPLING => DestinationFacts::NestedPlane {
                plane: "llm",
                op: busbar_contract::ids::OpClassId::new("chat"),
            },
            // A server asking which roots it may work under is answered from configuration, which
            // this plane reads through its own settings records.
            ops::OP_ROOTS_LIST => DestinationFacts::PlaneRecord {
                schema: rec::SCHEMA_SETTINGS,
                op: rec::OP_GET,
            },
            // A server asking the CALLER for something goes back to the caller.
            ops::OP_ELICITATION => DestinationFacts::Client {
                selector: "opener",
                mode: busbar_contract::dest::ClientMode::Deliver,
            },
            // Everything else is a hop to the server.
            _ => self.upstream_destination(),
        }
    }

    fn approve<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        let mut facts = ScopeFacts::default();
        // The resource is the registered server, under the kind the codec already names it by. The
        // plane says WHAT is being asked for; which scope that requires, and whether this principal
        // holds it, is the scope unit's answer and never this plane's.
        if let Some(server) = self.servers().first() {
            let _ = facts.resources.push(ResourceLocator {
                kind: RESOURCE_KIND_SERVER,
                name: server.id,
            });
            // A call names a second resource: the tool itself. The tool's own name is on the
            // request, which is not a name that outlives the unit, so what is offered here is the
            // configured server's tool namespace and the scope unit reads the request for the rest.
            if u.op() == ops::OP_TOOL_CALL {
                let _ = facts.resources.push(ResourceLocator {
                    kind: RESOURCE_KIND_TOOL,
                    name: server.id,
                });
            }
        }
        facts
    }

    fn admit<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        AdmitFacts {
            // The lane is not in the request. It is a property of the server the operator
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
            // A call is the whole point, and it is the only operation with an approval to spend.
            ops::OP_TOOL_CALL => {
                // Resolve the tool, spend the grant that says this caller may use it, hop, then
                // record what happened. The grant is spent BEFORE the hop, because a grant spent
                // after a hop is a grant a failed hop leaves unspent for a retry to spend again.
                leg(Self::record_leg(rec::SCHEMA_CATALOGUE, rec::OP_GET));
                leg(Self::record_leg(rec::SCHEMA_DEMOTION, rec::OP_GET));
                leg(Self::record_leg(rec::SCHEMA_APPROVAL, rec::OP_REDEEM));
                leg(self.upstream_leg());
                leg(Self::record_leg(rec::SCHEMA_CALL, rec::OP_APPEND));
            }
            ops::OP_DISCOVER
            | ops::OP_TOOLS_LIST
            | ops::OP_PROMPTS_LIST
            | ops::OP_RESOURCES_LIST
            | ops::OP_RESOURCE_TEMPLATES_LIST => {
                // A listing is answered from what was approved, minus what is quarantined.
                leg(Self::record_leg(rec::SCHEMA_CATALOGUE, rec::OP_SCAN));
                leg(Self::record_leg(rec::SCHEMA_DEMOTION, rec::OP_SCAN));
            }
            ops::OP_PROMPT_GET | ops::OP_RESOURCE_READ => {
                leg(Self::record_leg(rec::SCHEMA_CATALOGUE, rec::OP_GET));
                leg(self.upstream_leg());
                leg(Self::record_leg(rec::SCHEMA_CALL, rec::OP_APPEND));
            }
            ops::OP_COMPLETION => leg(Self::record_leg(rec::SCHEMA_CATALOGUE, rec::OP_GET)),
            ops::OP_TASK_GET => leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_GET)),
            ops::OP_TASK_UPDATE | ops::OP_TASK_CANCEL => {
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_GET));
                leg(Self::record_leg(rec::SCHEMA_TASK, rec::OP_PUT));
            }
            ops::OP_SUBSCRIPTIONS_LISTEN => {
                leg(Self::record_leg(rec::SCHEMA_CATALOGUE, rec::OP_SCAN));
                leg(Leg {
                    destination: DestinationFacts::Client {
                        selector: "opener",
                        mode: busbar_contract::dest::ClientMode::Deliver,
                    },
                });
            }
            // A server asking for a completion opens a child unit of the other plane, with its own
            // hold drawn from this node's own budget.
            ops::OP_SAMPLING => {
                leg(Self::record_leg(rec::SCHEMA_APPROVAL, rec::OP_REDEEM));
                leg(Leg {
                    destination: DestinationFacts::NestedPlane {
                        plane: "llm",
                        op: busbar_contract::ids::OpClassId::new("chat"),
                    },
                });
            }
            ops::OP_ROOTS_LIST => leg(Self::record_leg(rec::SCHEMA_SETTINGS, rec::OP_GET)),
            ops::OP_ELICITATION => leg(Leg {
                destination: DestinationFacts::Client {
                    selector: "opener",
                    mode: busbar_contract::dest::ClientMode::Deliver,
                },
            }),
            // A notice is recorded and answered with nothing.
            ops::OP_NOTIFICATION => leg(Self::record_leg(rec::SCHEMA_CATALOGUE, rec::OP_PUT)),
            // An operation class this plane does not carry gets no legs, which is an empty plan and
            // a refusal at the routing step. Not a panic, and not a guess.
            _ => {}
        }
        plan
    }

    fn meter<'u>(&self, u: &Unit<'u>, r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        let mut locators = UsageLocators::default();
        // A call that was answered is a call that was made. This is a count, and it is flat: the
        // codec meters one attributed event per round, and this is the same statement in the
        // contract's own vocabulary.
        if u.op() == ops::OP_TOOL_CALL {
            let _ = locators.lines.push(UsageLocator {
                class: CLASS_TOOL_CALLS,
                location: None,
                quantity: Some(1),
                lane: None,
            });
        }
        let _ = locators.lines.push(UsageLocator {
            class: CLASS_BYTES,
            // The quantity is not at a pointer: it is the size of the document the plane just read.
            // So the locator carries the value and no location, which the contract allows precisely
            // for the case where the plane already has the number in front of it.
            location: None,
            quantity: Some(r.ir.body().len() as u64),
            // This protocol's answers do not name a lane. The lane is the server's, and the trust
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
            v if v == crate::meta::VERB_TOOLS => {
                let _ = facts.set("count", FactValue::Int(self.servers().len() as i64));
                for server in self.servers() {
                    // The server's name is the key and the lane it is priced on is the value.
                    // Nothing here is a credential, a price or an address: an operator reading this
                    // learns which servers are registered and on which lane, which is what an
                    // introspection verb is for.
                    let _ = facts.set(server.id, FactValue::Str(server.lane.as_str()));
                }
            }
            v if v == crate::meta::VERB_SERVER => {
                // The projection over ONE registration. A subject that names no registration is an
                // unsupported operation rather than an empty answer: "there is no such server" and
                // "that server has nothing to report" are different facts.
                let name = subject.ok_or(Decode::UnsupportedOperation)?;
                let server = self
                    .servers()
                    .iter()
                    .find(|s| s.id == name)
                    .ok_or(Decode::UnsupportedOperation)?;
                let _ = facts.set(SUBJECT_FACT_NAME, FactValue::Str(server.id));
                let _ = facts.set(SUBJECT_FACT_LANE, FactValue::Str(server.lane.as_str()));
                let _ = facts.set(SUBJECT_FACT_TRANSPORT, FactValue::Str(server.transport));
                // Whether this node launches the server itself, which is the one structural thing
                // about a registration an operator cannot read off the name. The host itself stays
                // out: an address is not introspection, it is configuration.
                let _ = facts.set(SUBJECT_FACT_LOCAL, FactValue::Bool(server.host.is_empty()));
            }
            _ => return Err(Decode::UnsupportedOperation),
        }
        Ok(PlaneFacts { facts })
    }

    fn content_facts<'u>(
        &self,
        u: &Unit<'u>,
        r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        let body = r.ir.body();
        let mut facts = Facts::new();
        // Only the declared keys, and only what was actually read. The tool's own output never
        // appears here, and neither does anything the caller presented as authority.
        if let Some(kind) = read_str(body, jsonrpc::PTR_RESULT_TYPE) {
            let _ = facts.set(f::FACT_RESULT_TYPE, FactValue::Str(kind));
        }
        if let Some(flag) = read_raw(body, jsonrpc::PTR_IS_ERROR) {
            let _ = facts.set(f::FACT_IS_ERROR, FactValue::Bool(flag == b"true"));
        }
        if let Some(code) = read_raw(body, jsonrpc::PTR_ERROR_CODE) {
            if let Ok(text) = core::str::from_utf8(code) {
                let _ = facts.set(f::FACT_ERROR_CODE, FactValue::Str(text));
            }
        }
        // What the request was FOR travels with what came back, so the record joins them without a
        // second read of the request: decode already found the subject and the unit carries it.
        if let Some(FactValue::Str(subject)) = u.draft_facts().get(f::FACT_SUBJECT) {
            let _ = facts.set(f::FACT_SUBJECT, FactValue::Str(subject));
        }
        if let Some(server) = self.servers().first() {
            let _ = facts.set(f::FACT_SERVER, FactValue::Str(server.id));
        }
        ContentFacts { facts }
    }
}

impl SessionPlane for McpPlane {
    fn open_session<'u>(&self, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Codec::default())
    }

    fn open_upstream<'u>(&self, _dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(Codec::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{finish_of, member_of, refusal_render, Codec};
    use busbar_contract::unit::{AbortBy, FailureReason, RefusalReason, Step, UnitEnd};

    /// Every closed refusal reason has an answer, and every answer is a code this plane may write.
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
        for reason in reasons {
            let (code, message) = refusal_render(reason);
            assert!(
                crate::jsonrpc::CODES.contains(&code),
                "{reason:?} renders unknown code {code}"
            );
            assert!(
                !crate::jsonrpc::RETIRED_CODES.contains(&code),
                "{reason:?} renders the retired code {code}"
            );
            assert!(!message.is_empty(), "{reason:?} renders no words");
        }
    }

    /// A refusal tells the caller nothing about the money.
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

    /// A held stream ends a turn when it completes; a single answer is complete.
    #[test]
    fn a_held_stream_ends_a_turn() {
        assert_eq!(
            finish_of(&UnitEnd::Completed, true),
            busbar_contract::unit::FinishClass::TurnComplete
        );
        assert_eq!(
            finish_of(&UnitEnd::Completed, false),
            busbar_contract::unit::FinishClass::Complete
        );
    }

    /// Who ended it decides how it ended.
    #[test]
    fn who_ended_it_decides_how_it_ended() {
        assert_eq!(
            finish_of(&UnitEnd::Aborted(AbortBy::Client), false),
            busbar_contract::unit::FinishClass::Partial
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

    /// A metadata member whose name carries separators is read by name, not by pointer.
    ///
    /// This is the case a pointer cannot express: the key itself contains the character a pointer
    /// uses to mean "one level down", so a pointer naming it would read it as three levels.
    #[test]
    fn a_member_whose_name_carries_separators_is_read() {
        let block = br#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","other":1}"#;
        assert_eq!(
            member_of(block, "io.modelcontextprotocol/protocolVersion"),
            Some("2026-07-28")
        );
        assert_eq!(member_of(block, "io.modelcontextprotocol/clientInfo"), None);
    }

    /// A member that is present and is not a string reads as absent.
    #[test]
    fn a_member_that_is_not_a_string_reads_as_absent() {
        let block = br#"{"progressToken":42}"#;
        assert_eq!(member_of(block, "progressToken"), None);
    }

    /// The codec state starts at nothing and counts up on both axes.
    #[test]
    fn the_codec_state_counts() {
        let mut codec = Codec::default();
        assert_eq!((codec.events_read, codec.rounds_asked), (0, 0));
        codec.events_read = codec.events_read.saturating_add(1);
        codec.rounds_asked = codec.rounds_asked.saturating_add(1);
        assert_eq!((codec.events_read, codec.rounds_asked), (1, 1));
    }
}
