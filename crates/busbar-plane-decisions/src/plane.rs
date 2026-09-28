//! The plane itself: the seven codec methods and the fact methods, each a few lines over `codec.rs`
//! and `ops.rs`.
//!
//! Every method here returns FACTS AND LOCATORS. Not an amount, not a decision, not a credential,
//! not a price. Nothing in this file opens a connection, reads a file, reads a clock other than the
//! one the context hands it, or keeps a byte across a call.

use busbar_contract::bounded::{FactValue, Facts, Ir, ScratchBytes};
use busbar_contract::dest::{DestinationFacts, EgressBody, Leg, RoutePlan, VerifiedDestination};
use busbar_contract::grammar::{ArrivalLocation, Location};
use busbar_contract::ids::SchemeAlt;
use busbar_contract::kinds::{ContentFacts, CredentialLocator, PlaneFacts};
use busbar_contract::plane::{
    Ingress, Plane, PlaneSessionState, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, RefusalReason, ResourceLocator, ScopeFacts,
    Unit, UnitEnd, UsageLocator, UsageLocators,
};
use busbar_contract::wire::{Decode, Encode, Frame, FrameCursor, TransportEnvelope};

use crate::codec::{
    self, PTR_ERROR, PTR_ID, PTR_REQUEST_ID, PTR_USAGE_UNITS, REQUEST_PTRS, RESPONSE_PTRS,
};
use crate::facts as f;
use crate::meta::CLASS_DECISION;
use crate::ops;
use crate::DecisionPlane;

/// The transport fact key a request target is published under. The kernel's own reserved key.
const FACT_PATH: &str = busbar_contract::transport::facts::PATH;

/// The transport fact key the request's own verb is published under. The kernel's own reserved
/// key. jev needs it because its two operations are told apart by verb+path, never by a body
/// member the way MCP/A2A's JSON-RPC method name is.
const FACT_METHOD: &str = busbar_contract::transport::facts::METHOD;

/// The egress-auth scheme an outbound hop to the provider is decorated under.
///
/// The plane NAMES the scheme and never holds what is behind it. jev's auth is the core gateway's
/// own bearer credential (the signed design: "auth = core gateway credential, plane returns a
/// CredentialLocator, never sees the secret") — the same seam every other plane's egress hop uses.
const EGRESS_SCHEME: &str = "decision-egress";

/// The envelope member naming the document type of an outbound body.
const FIELD_CONTENT_TYPE: &str = "content-type";

/// The document type every body of this protocol is.
const CONTENT_TYPE_JSON: &[u8] = b"application/json";

impl DecisionPlane {
    /// The ONE provider a unit on this plane is dialled against, judged against and named by.
    ///
    /// A jev request names no provider — its body is the caller's `state`, its operation is the
    /// verb and path — so the plane can only answer "which provider" when exactly one is
    /// configured. With none, or with several, there is no provider the request can be said to
    /// target, and every per-unit answer (`verify`, `approve`, the provider fact) is the same
    /// honest one [`DecisionPlane::EMPTY`] gives: no destination the trust unit admits, no provider
    /// named for scope. Picking the first-declared of several would dial, and ask scope for, a
    /// provider the caller never chose.
    fn provider(&self) -> Option<&'static crate::DecisionProvider> {
        match self.providers() {
            [only] => Some(only),
            _ => None,
        }
    }

    /// The draft facts every unit starts with: its operation, and the provider it is dialled
    /// against where one resolves.
    fn draft_facts(&self, row: &ops::MethodRow) -> Facts<'static> {
        let mut facts = Facts::new();
        let _ = facts.set(f::FACT_OP, FactValue::Str(row.op.as_str()));
        if let Some(p) = self.provider() {
            let _ = facts.set(f::FACT_PROVIDER, FactValue::Str(p.id));
        }
        facts
    }

    /// A leg reaching the configured provider, or an unreachable one when none is configured.
    ///
    /// A plane with nothing configured answers honestly rather than panicking or inventing a host:
    /// the empty host is refused by the trust unit against the allow-list.
    fn upstream_leg(&self) -> Leg {
        Leg {
            destination: self.upstream_destination(),
        }
    }

    /// Where a hop to the configured provider goes.
    fn upstream_destination(&self) -> DestinationFacts {
        match self.provider() {
            Some(p) => DestinationFacts::Upstream {
                transport: p.transport,
                address: busbar_contract::UpstreamAddress::socket(p.host),
                lane: p.lane,
            },
            None => DestinationFacts::Upstream {
                transport: crate::claims::TRANSPORT,
                address: busbar_contract::UpstreamAddress::socket(""),
                lane: busbar_contract::ids::LaneId::new(""),
            },
        }
    }
}

/// Which code and words this dialect answers one refusal reason with.
///
/// jev has no error vocabulary of its own to bind against (unlike A2A's JSON-RPC codes) — it is a
/// bare HTTP+JSON passthrough, so every refusal renders as a plain JSON error object with a neutral
/// message. THE MATCH IS TOTAL — no `_` arm — so a reason with no home here is a compile error,
/// never a silent collapse to an internal fault.
fn refusal_render(reason: RefusalReason) -> (&'static str, &'static str) {
    match reason {
        RefusalReason::BodyTooLarge => ("invalid_request", "the request is too large"),
        RefusalReason::DecodeFailed => ("invalid_request", "the request could not be read"),
        RefusalReason::SchemeNotDeclared
        | RefusalReason::CredentialRejected
        | RefusalReason::SessionUnbound
        | RefusalReason::CredentialBudget => (
            "invalid_request",
            "the request did not carry usable authority",
        ),
        RefusalReason::ScopeMissing
        | RefusalReason::Vetoed
        | RefusalReason::Revoked
        | RefusalReason::PoolNotPermitted => (
            "unsupported_operation",
            "the caller may not perform this operation",
        ),
        RefusalReason::NoDestination => (
            "invalid_params",
            "no decision provider is reachable for this request",
        ),
        RefusalReason::InFlightCap
        | RefusalReason::CursorBudget
        | RefusalReason::SessionBudget
        | RefusalReason::OpenSlotBusy
        | RefusalReason::OverBudget
        | RefusalReason::GroupFrozen
        | RefusalReason::Unpriced
        | RefusalReason::OverdraftCeiling
        | RefusalReason::StaleSlice
        | RefusalReason::TierMismatch
        | RefusalReason::SpillBudget
        | RefusalReason::ScratchExhausted
        | RefusalReason::RateLimited
        | RefusalReason::ChallengeExhausted
        | RefusalReason::NoRate
        | RefusalReason::Replayed
        | RefusalReason::InFlight
        | RefusalReason::DestinationBudgetExhausted
        | RefusalReason::BreakerOpen
        | RefusalReason::DestinationUnreachable
        | RefusalReason::Drain
        | RefusalReason::Superseded
        | RefusalReason::ClientGone
        | RefusalReason::DeadlineExceeded
        | RefusalReason::Stalled => (
            "unsupported_operation",
            "the request could not be served at this time",
        ),
        RefusalReason::DurabilityUnavailable
        | RefusalReason::MeterDisputed
        | RefusalReason::HandoffMismatch
        | RefusalReason::PlanePanic
        | RefusalReason::TaskLost
        | RefusalReason::SecretPlaceholder => {
            ("internal", "the request could not be served at this time")
        }
    }
}

/// Build the bare JSON error object jev's refusal/error shape is: `{"error": {"code": ..,
/// "message": ..}}`. Written by hand rather than through `serde_json::json!` so the byte order is
/// pinned and a conformance test can assert the exact bytes.
fn error_body(code: &str, message: &str) -> Vec<u8> {
    format!(
        "{{\"error\":{{\"code\":{},\"message\":{}}}}}",
        serde_json::to_string(code).unwrap_or_else(|_| "\"internal\"".to_string()),
        serde_json::to_string(message).unwrap_or_else(|_| "\"error\"".to_string()),
    )
    .into_bytes()
}

/// Which operation a `(verb, path)` pair on the transport names, decoded into the row.
fn row_of(ctx: &Ctx<'_>) -> Option<&'static ops::MethodRow> {
    let verb = ctx.transport().fact(FACT_METHOD)?;
    let path = ctx.transport().fact(FACT_PATH)?;
    ops::row_for(verb, path)
}

impl Plane for DecisionPlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        let Some(row) = row_of(ctx) else {
            return Err(Decode::UnsupportedOperation);
        };
        if !row.has_request_body {
            // `GET /v1/models` carries no body. It is complete the moment the surface is
            // recognised, exactly as A2A's discovery documents are.
            return Ok(Ingress::OneShot(Box::new(UnitDraft {
                op: row.op,
                body_ir: Ir::empty(),
                correlates: None,
                correlation_out: None,
                facts: self.draft_facts(row),
            })));
        }
        let Some(frame) = frames.next_frame() else {
            return Ok(Ingress::NeedMore);
        };
        let body = frame.bytes.as_slice();
        if body.is_empty() {
            return Ok(Ingress::NeedMore);
        }
        let facts = self.draft_facts(row);
        Ok(Ingress::OneShot(Box::new(UnitDraft {
            op: row.op,
            // The request body is never read for a declared pointer — see `codec::REQUEST_PTRS`'s
            // own note on why that list is empty. The view still carries the WHOLE body, because
            // byte-identity forwarding reads `Ir::body()`, never a pointer.
            body_ir: codec::view(body, REQUEST_PTRS, ctx)?,
            correlates: None,
            correlation_out: None,
            facts,
        })))
    }

    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        if !matches!(
            dest.facts(),
            DestinationFacts::Upstream { .. } | DestinationFacts::SessionUpstream { .. }
        ) {
            return Err(Encode::Unrepresentable);
        }
        // Byte-identity passthrough: the caller's body goes to the provider UNCHANGED. jev performs
        // none of A2A's task-identifier rewrite — there is no busbar-minted identifier in a
        // `systemone` request to swap out.
        let body = ScratchBytes::new(u.body().body());
        let mut envelope = TransportEnvelope::default();
        let content_type = ctx
            .arena()
            .alloc_bytes(CONTENT_TYPE_JSON)
            .map_err(|_| Encode::ScratchExhausted)?;
        let _ = envelope.fields.push(busbar_contract::wire::EnvelopeField {
            name: FIELD_CONTENT_TYPE,
            value: content_type,
        });
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
    ) -> Result<Option<ScratchBytes<'u>>, Encode> {
        // Both of jev's operations are complete in one request/response pair; there is no open
        // unit an extra inbound frame could belong to.
        Ok(None)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        let Some(frame) = frames.next_frame() else {
            return Ok(Progress::NeedMore);
        };
        let body = frame.bytes.as_slice();
        if body.is_empty() {
            return Ok(Progress::NeedMore);
        }
        let ir = codec::view(body, RESPONSE_PTRS, ctx)?;
        let is_error = codec::has(body, PTR_ERROR);
        let mut facts = Facts::new();
        if let Some(id) =
            codec::read_str(body, PTR_REQUEST_ID).or_else(|| codec::read_str(body, PTR_ID))
        {
            let id = ctx.arena().alloc_str(id).map_err(|_| Decode::Oversize)?;
            let _ = facts.set(f::FACT_REQUEST_ID, FactValue::Str(id));
        }
        let _ = facts.set(f::FACT_HAS_ERROR, FactValue::Bool(is_error));
        // The usage figure is read ONLY on a response that did not error — a 4xx has nothing
        // extractable under the billable-decision class (see `meter` below and the signed design's
        // C-3 "billable-success" rule). Only a whole count the fact can hold EXACTLY is set here; a
        // member that is not one (fractional, negative, not a number, past `i64`) is left to
        // `meter`, which locates it rather than letting a cast wrap it or a parse drop it.
        if !is_error {
            if let Some(units) =
                codec::read_u64(body, PTR_USAGE_UNITS).and_then(|u| i64::try_from(u).ok())
            {
                let _ = facts.set(f::FACT_USAGE_UNITS, FactValue::Int(units));
            }
        }
        let r = Response {
            ir,
            finish: if is_error {
                FinishClass::Error
            } else {
                FinishClass::Complete
            },
            facts,
        };
        Ok(Progress::Terminal {
            for_: None,
            r: Box::new(r),
        })
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode> {
        // Byte-identity passthrough on the way back too: the provider's own bytes reach the caller
        // unchanged. jev composes no answer of its own — both operations are always a relay.
        ctx.arena()
            .alloc_bytes(r.ir.body())
            .map_err(|_| Encode::ScratchExhausted)
    }

    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode> {
        let (code, message) = refusal_render(refusal.reason);
        ctx.arena()
            .alloc_bytes(&error_body(code, message))
            .map_err(|_| Encode::ScratchExhausted)
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode> {
        // Neither jev operation writes anything to end a unit: the answer's own document IS the
        // end.
        Ok(None)
    }

    fn authenticate<'u>(&self, _u: &Unit<'u>, ctx: &Ctx<'u>) -> CredentialLocator {
        // The core gateway credential, always: jev has no anonymous surface (unlike A2A's discovery
        // documents), because even `/v1/models` is billed per the provider's own account scoping.
        CredentialLocator {
            narrowing: Some(SchemeAlt::new(crate::claims::ALT_TOKEN)),
            from_session: ctx
                .session()
                .is_some_and(busbar_contract::unit::SessionView::is_bound),
        }
    }

    fn verify<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        // Both operations are provider/account-scoped hops — jev owns no record of its own a unit
        // could resolve against instead (see records.rs's module note).
        self.upstream_destination()
    }

    fn approve<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        let mut facts = ScopeFacts::default();
        if let Some(p) = self.provider() {
            let _ = facts.resources.push(ResourceLocator {
                kind: "decision_provider",
                name: p.id,
            });
        }
        facts
    }

    fn admit<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        AdmitFacts {
            // jev's request carries no lane name of its own; the lane is the configured provider's,
            // and the trust unit re-derives it against the allow-list.
            lane_locator: None,
            // jev's dialect gives a caller no way to declare a ceiling on the answer.
            max_response_ptrs: busbar_contract::bounded::BoundedVec::new(),
            // The priced input is the whole request document.
            input_span: Some(busbar_contract::bounded::Span {
                start: 0,
                end: u.body().body().len(),
            }),
        }
    }

    fn route<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> RoutePlan {
        let mut plan = RoutePlan::default();
        // Both operations are a bare hop to the configured provider — jev owns no record leg (see
        // records.rs's module note): `systemone` mints no busbar-side identifier a later call would
        // need to look back up, and `models` is never cached.
        if u.op() == ops::OP_SYSTEMONE || u.op() == ops::OP_MODELS {
            let _ = plan.legs.push(self.upstream_leg());
        }
        plan
    }

    fn meter<'u>(&self, _u: &Unit<'u>, r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        let mut locators = UsageLocators::default();
        // Billable-success only (signed design C-3): a response that carried an `/error` member has
        // NOTHING extractable under the billable-decision class — this is not "meter zero", it is
        // "meter nothing at all", so a 4xx never posts a usage line.
        if let Some(FactValue::Bool(true)) = r.facts.get(f::FACT_HAS_ERROR) {
            return locators;
        }
        let whole = match r.facts.get(f::FACT_USAGE_UNITS) {
            Some(FactValue::Int(units)) => u64::try_from(units).ok(),
            _ => None,
        };
        let line = match whole {
            // The quantity was already read out of the response by `decode_response`, so the
            // locator carries the value and no location — the same shape A2A's byte-class locator
            // uses when the plane already has the number in hand.
            Some(units) => Some((None, Some(units))),
            // The provider REPORTED a usage member this plane cannot carry as a whole count — `7.5`,
            // `-3`, `"7"`, `null`, a figure past `i64`. That is a measurement, not an absence (#81),
            // and judging it is not this plane's job (#42): the locator names WHERE it is and
            // carries no value, so the step that folds locators reads the exact decimal text or
            // refuses it. Dropping it would record "reported nothing" for an exchange that reported
            // a figure.
            None if codec::has(r.ir.body(), PTR_USAGE_UNITS) => Some((
                Some(Location::Arrival(ArrivalLocation::FirstFrameJsonPointer(
                    PTR_USAGE_UNITS,
                ))),
                None,
            )),
            // No usage member at all: the provider reported nothing, and no line is the record of
            // that — the settlement's "destination reported no usage" row decides what it bills.
            None => None,
        };
        if let Some((location, quantity)) = line {
            let _ = locators.lines.push(UsageLocator {
                class: CLASS_DECISION,
                location,
                quantity,
                // jev's response never names a lane of its own; the lane is the provider's,
                // sealed by the trust unit.
                lane: None,
            });
        }
        locators
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        AuditFacts {
            op_class: u.op(),
            finish: busbar_contract::unit::finish_class_of(out, FinishClass::Complete),
        }
    }

    fn plane_facts<'u>(
        &self,
        _verb: busbar_contract::ids::AdminVerbId,
        _subject: Option<&'u str>,
        _ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        // jev declares no introspection verb (see meta.rs), so any verb asked here is one this
        // plane never claimed.
        Err(Decode::UnsupportedOperation)
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        // Only the declared metadata keys, copied off what `decode_response` already read — never a
        // re-read of the body, and never `state`/`answers`.
        let mut facts = Facts::new();
        for key in [f::FACT_OP, f::FACT_HAS_ERROR, f::FACT_USAGE_UNITS] {
            if let Some(v) = r.facts.get(key) {
                let _ = facts.set(key, v);
            }
        }
        ContentFacts { facts }
    }
}

impl SessionPlane for DecisionPlane {
    fn open_session<'u>(&self, _ctx: &Ctx<'u>) -> PlaneSessionState {
        // jev keeps no per-connection codec state: every exchange is a complete request/response
        // pair with nothing to carry to the next one.
        PlaneSessionState::new(())
    }

    fn open_upstream<'u>(&self, _dest: &VerifiedDestination, _ctx: &Ctx<'u>) -> PlaneSessionState {
        PlaneSessionState::new(())
    }
}

#[cfg(test)]
#[path = "tests/plane.rs"]
mod tests;
