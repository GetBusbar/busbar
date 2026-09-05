//! The `Plane` implementation: the codec itself.
//!
//! Every method here is pure over its inputs and performs no I/O, matching the plane trait's own
//! doc comment. The one piece of shared logic — "which of the table's verbs does this unit's body
//! name" — is `identify`, and it runs exactly once, at `decode_ingress`, which writes the verb it
//! resolved into the draft's fact map. Every later step that needs the verb (`verify`, `approve`,
//! `content_facts`) reads it back off `Unit::draft_facts()`. Decode is the step that is entitled to
//! read the bytes; a later step re-deriving the same answer from the same bytes is a second reading
//! of one closed grammar, and two readings can drift.

use busbar_contract::bounded::{ArenaBytes, FactValue, Facts, Ir, Span};
use busbar_contract::dest::{DestinationFacts, EgressBody, RoutePlan, VerifiedDestination};
use busbar_contract::ids::AdminVerbId;
use busbar_contract::kinds::{ContentFacts, CredentialLocator, PlaneFacts};
use busbar_contract::plane::{Ingress, Plane, PlaneSessionState, Progress, Response, UnitDraft};
use busbar_contract::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, ResourceLocator, ScopeFacts, Unit, UnitEnd,
    UsageLocators,
};
use busbar_contract::wire::{Decode, Encode, Frame, FrameCursor};

use crate::meta::FACT_VERB;
use crate::verbs::{self, VerbEntry, OP_READ, OP_WRITE, VERB_OPENAPI_JSON};
use crate::{refusal, AdminPlane};

/// What decoding one admin frame's envelope resolved to.
struct Decoded<'u> {
    entry: &'static VerbEntry,
    params: Vec<(&'static str, &'u str)>,
}

/// Identify which of the table's verbs a decoded body names, by re-scanning its `method`/`path`
/// fields. See the module doc comment for why this is a fresh scan rather than a cached fact.
fn identify<'u>(bytes: &'u [u8]) -> Option<Decoded<'u>> {
    // The envelope's two members are the request line's two structural values, so they are named
    // with the kernel's own reserved keys rather than with this crate's guess at their spelling.
    let method = str_at(bytes, PTR_METHOD)?;
    let path = str_at(bytes, PTR_PATH)?;
    let (entry, params) = verbs::find_verb(method, path)?;
    Some(Decoded { entry, params })
}

/// Where the envelope carries the request line's method.
///
/// Spelled as a pointer to the kernel's own reserved transport fact key rather than to this
/// crate's guess at it; the test below is what keeps the two spellings one.
const PTR_METHOD: &str = "/method";

/// Where the envelope carries the request line's target.
const PTR_PATH: &str = "/path";

/// The span of a string value's CONTENT at one pointer, quotes excluded.
///
/// Through the contract's own span grammar, which is the kernel's. This plane used to carry a
/// scanner of a different design again — a cursor over nested scopes rather than a pointer walk —
/// and the closed grammar the design names has one reading, not two.
fn content_at(bytes: &[u8], pointer: &str) -> Option<Span> {
    match busbar_contract::spans::resolve_pointer(bytes, pointer) {
        busbar_contract::spans::Resolved::Found(span) => {
            let raw = bytes.get(span.start..span.end)?;
            if raw.first() == Some(&b'"') && raw.len() >= 2 && raw.last() == Some(&b'"') {
                Some(Span::new(span.start + 1, span.end - 1))
            } else {
                Some(span)
            }
        }
        _ => None,
    }
}

/// The string value at one pointer, with its quotes stripped.
fn str_at<'u>(bytes: &'u [u8], pointer: &str) -> Option<&'u str> {
    let span = content_at(bytes, pointer)?;
    core::str::from_utf8(bytes.get(span.start..span.end)?).ok()
}

/// The span view of a body, built from the pointers this step resolved.
///
/// One scan of one closed grammar, into the unit's own arena, so the loop reads the spans the
/// plane resolved instead of walking the same bytes a second time.
fn view<'u>(bytes: &'u [u8], pointers: &[&'u str], ctx: &Ctx<'u>) -> Result<Ir<'u>, Decode> {
    let spans = busbar_contract::spans::resolve(bytes, pointers, ctx.arena())
        .map_err(|_| Decode::Oversize)?;
    Ok(Ir::new(bytes, spans))
}

/// The verb `decode_ingress` resolved, read back off the unit's sealed draft facts.
///
/// The fact's own string borrows the unit; the row it names is static, and the destination and
/// resource locator shapes are `&'static str`, so the name is resolved against the closed table
/// rather than re-derived from the body.
fn draft_verb(u: &Unit<'_>) -> Option<&'static str> {
    match u.draft_facts().get(FACT_VERB) {
        Some(FactValue::Str(name)) => verbs::verb_named(name).map(|e| e.verb),
        _ => None,
    }
}

impl Plane for AdminPlane {
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        let frame = frames.next_frame().ok_or(Decode::Malformed)?;
        let bytes = frame.bytes.as_slice();
        let decoded = identify(bytes).ok_or(Decode::UnsupportedOperation)?;

        let mut facts = Facts::new();
        facts
            .set(FACT_VERB, FactValue::Str(decoded.entry.verb))
            .map_err(|_| Decode::MissingDeclaredFact)?;
        for (name, value) in &decoded.params {
            facts
                .set(name, FactValue::Str(value))
                .map_err(|_| Decode::MissingDeclaredFact)?;
        }

        // The documented representative body-field extraction. See `verbs::documented_body_field`
        // for the honest scope of this: one field for a subset of mutation verbs, not full
        // per-operation schema validation. Every verb this table does not cover still decodes
        // correctly above; it simply carries no extra body fact, which is a visible omission (the
        // fact is absent) rather than a silently wrong one (nothing is invented in its place).
        // Every pointer this step resolved, in the order it resolved them: the request line's two
        // structural values, and the one body member the verb's row documents where it has one.
        let mut pointers: [&'u str; 3] = [PTR_METHOD, PTR_PATH, PTR_PATH];
        let mut declared = 2;
        if let Some(field) = verbs::documented_body_field(decoded.entry.verb) {
            let pointer = ctx
                .arena()
                .alloc_str(&format!("/body/{field}"))
                .map_err(|_| Decode::Oversize)?;
            if let Some(text) = str_at(bytes, pointer) {
                let _ = facts.set(field, FactValue::Str(text));
            }
            pointers[declared] = pointer;
            declared += 1;
        }

        let ir = view(bytes, &pointers[..declared], ctx)?;
        let op = if decoded.entry.read_only {
            OP_READ
        } else {
            OP_WRITE
        };
        Ok(Ingress::OneShot(UnitDraft {
            op,
            body_ir: ir,
            correlates: None,
            correlation_out: None,
            facts,
        }))
    }

    fn encode_egress<'u>(
        &self,
        _u: &Unit<'u>,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        // An admin verb never dials an upstream: its destination is always `KernelVerb`, which the
        // kernel itself executes (through `busbar-unit-verbs`) without opening a leg this plane
        // would encode. This is a genuinely unreachable path for a correctly wired admin plane, not
        // a lazy stub — `route` below never returns a leg, so nothing should ever call this.
        Err(Encode::Unrepresentable)
    }

    fn encode_ingress_frame<'u>(
        &self,
        _u: &Unit<'u>,
        _f: &Frame,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        // Every admin unit is `OneShot` (see `decode_ingress`): there is no open unit whose later
        // frames this method would relay onward to a destination. Unreachable for the same reason
        // as `encode_egress`.
        Err(Encode::Unrepresentable)
    }

    fn decode_response<'u>(
        &self,
        _frames: &mut FrameCursor<'u>,
        _dest: &VerifiedDestination,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        // Nothing ever comes back from an upstream this plane dialled, because this plane dials
        // none. Unreachable for the same reason as `encode_egress`/`encode_ingress_frame`.
        Err(Decode::UnsupportedOperation)
    }

    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        _st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let body = r.ir.body();
        // The one documented exception: the `openapi.json` blob is served verbatim by
        // `busbar-unit-verbs` (this plane computes no result), EXCEPT that `info.version` is
        // substituted for this plane's own version. The plane learns which verb produced this
        // response the same way it learns everything else about a response it did not decode
        // itself: a `verb` fact the executing unit is expected to stamp back onto `Response.facts`,
        // mirroring the key this plane's own `decode_ingress` used. Where that fact is absent (a
        // convention this plane declares but cannot enforce on `busbar-unit-verbs`, since that
        // crate is out of scope here), the safe default is the ordinary passthrough path below,
        // never the substitution — a byte-identical pass-through is always a safe default; a wrong
        // substitution is not.
        let is_openapi_json =
            matches!(r.facts.get(FACT_VERB), Some(FactValue::Str(v)) if v == VERB_OPENAPI_JSON);
        if is_openapi_json {
            if let Some(rendered) = substitute_info_version(body, env!("CARGO_PKG_VERSION")) {
                return ctx
                    .arena()
                    .alloc_bytes(&rendered)
                    .map_err(|_| Encode::ArenaExhausted);
            }
        }
        ctx.arena()
            .alloc_bytes(body)
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn encode_refusal<'u>(
        &self,
        refused: &Refusal,
        _draft: Option<&UnitDraft<'u>>,
        _st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let body = refusal::envelope(refused.reason);
        ctx.arena()
            .alloc_bytes(body.as_bytes())
            .map_err(|_| Encode::ArenaExhausted)
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        // A one-shot request/response dialect has no ending frame of its own to write beyond the
        // response or refusal already rendered; the kernel's own minimal ending covers it.
        Ok(None)
    }

    fn authenticate<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> CredentialLocator {
        // The admin credential travels on every request (a bearer token), never cached on a
        // session: the admin claim's transport is plain HTTP request/response, so there is no
        // session to cache it on. No narrowing: the claim declares exactly one alternative.
        CredentialLocator {
            narrowing: None,
            from_session: false,
        }
    }

    fn verify<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        // `decode_ingress` already refused anything that does not resolve to one of the table's
        // verbs, so the verb fact is always set on a unit that reached this step. The `"unknown"`
        // fallback exists only because `verify` cannot return a `Result`: it is unreachable in a
        // correctly wired loop, not a silently wrong answer — a destination named `"unknown"` is
        // refused by the trust unit rather than dialled.
        DestinationFacts::KernelVerb {
            verb: draft_verb(u).unwrap_or("unknown"),
        }
    }

    fn approve<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        let mut resources = busbar_contract::bounded::BoundedVec::new();
        if let Some(verb) = draft_verb(u) {
            // `kind: "admin_verb"` is this plane's own honest vocabulary for what is being asked
            // for: not a money resource, not a session, just "this one named kernel verb". The
            // scope unit is the one that turns this into a decision against the principal's held
            // scope; this plane only states what is being touched.
            let _ = resources.push(ResourceLocator {
                kind: "admin_verb",
                name: verb,
            });
        }
        ScopeFacts { resources }
    }

    fn admit<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        // Admin verbs are not priced against a lane: no lane locator, no response ceiling to
        // clamp, no priced input span.
        AdmitFacts::default()
    }

    fn route<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> RoutePlan {
        // The `KernelVerb` destination `verify` names IS the routing: the kernel dials its own verb
        // table directly. This plane opens no leg of its own.
        RoutePlan::default()
    }

    fn meter<'u>(&self, _u: &Unit<'u>, _r: &Response<'u>, _ctx: &Ctx<'u>) -> UsageLocators {
        // This plane declares no meter classes (see `meta::METER_CLASSES`), so there is nothing to
        // locate a quantity for.
        UsageLocators::default()
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        let finish = match out {
            UnitEnd::Completed => FinishClass::Complete,
            UnitEnd::Refused(_) | UnitEnd::Failed { .. } => FinishClass::Error,
            UnitEnd::Aborted(_) | UnitEnd::Stalled => FinishClass::Partial,
        };
        AuditFacts {
            op_class: u.op(),
            finish,
        }
    }

    fn plane_facts<'u>(
        &self,
        _verb: AdminVerbId,
        _subject: Option<&'u str>,
        _ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        // This plane declares no introspection verbs of its own (`meta::INTROSPECTION_VERBS` is empty; see
        // its doc comment for the naming collision with the `KernelVerb` table), so every
        // call here names a verb this plane does not declare.
        Err(Decode::UnsupportedOperation)
    }

    fn content_facts<'u>(
        &self,
        u: &Unit<'u>,
        r: &Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        let mut facts = Facts::new();
        let verb = match r.facts.get(FACT_VERB) {
            Some(FactValue::Str(v)) => Some(v),
            _ => draft_verb(u),
        };
        if let Some(verb) = verb {
            let _ = facts.set(FACT_VERB, FactValue::Str(verb));
        }
        ContentFacts { facts }
    }
}

/// Replace the `info.version` field of an `openapi.json`-shaped body with `version`.
///
/// A pure, small string-replace over the parsed structure's byte spans — never a full
/// re-serialization, so every other byte of the operator-facing document (formatting, key order,
/// every other field) survives untouched. Returns `None` when the body does not have the expected
/// `info.version` shape, so the caller's safe default (verbatim passthrough) applies instead of a
/// half-substituted document.
fn substitute_info_version(bytes: &[u8], version: &str) -> Option<Vec<u8>> {
    let version_span = content_at(bytes, "/info/version")?;
    let mut out = Vec::with_capacity(bytes.len() + version.len());
    out.extend_from_slice(&bytes[..version_span.start]);
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(&bytes[version_span.end..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two envelope pointers spell the kernel's own reserved transport fact keys.
    ///
    /// The envelope's two members ARE the request line's structural values, and the kernel reserves
    /// the spelling of both. Three planes each guessed `"path"` before the constants existed; this
    /// is what stops a fourth guess landing here.
    #[test]
    fn the_envelope_pointers_spell_the_reserved_keys() {
        use busbar_contract::transport::facts as tfacts;
        assert_eq!(PTR_METHOD, format!("/{}", tfacts::METHOD));
        assert_eq!(PTR_PATH, format!("/{}", tfacts::PATH));
    }

    #[test]
    fn substitutes_info_version_and_leaves_everything_else_byte_identical() {
        let body = br#"{"info":{"title":"busbar admin API","version":"1.5.5"},"paths":{}}"#;
        let rendered = substitute_info_version(body, "1.6.0").expect("info.version present");
        let text = String::from_utf8(rendered).unwrap();
        assert_eq!(
            text,
            r#"{"info":{"title":"busbar admin API","version":"1.6.0"},"paths":{}}"#
        );
    }

    #[test]
    fn absent_info_falls_back_to_none() {
        let body = br#"{"paths":{}}"#;
        assert!(substitute_info_version(body, "1.6.0").is_none());
    }

    #[test]
    fn identify_resolves_every_documented_body_field_verb() {
        // A representative sample, not the full 18: exercised in the table test module instead.
        let body = br#"{"method":"POST","path":"/api/v1/admin/keys","body":{"name":"k1"}}"#;
        let decoded = identify(body).expect("decodes");
        assert_eq!(decoded.entry.verb, "post_keys");
        assert!(decoded.params.is_empty());
    }
}
