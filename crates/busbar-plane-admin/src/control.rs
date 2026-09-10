//! The `Control` implementation: the four calls this surface answers.
//!
//! Every method here is pure over its inputs and performs no I/O. There is no decode call and that
//! is the point: the surface's route table is DECLARED (`meta::ROUTES`, the one claim), so the loop
//! resolves an arriving request against the declaration and the operation it resolved travels as a
//! fact on the unit. Every step that needs it — `verify`, `answer` — reads it back off
//! `Unit::draft_facts()` rather than re-reading the bytes. One reading of one closed table cannot
//! drift from itself; two can.

use busbar_contract::bounded::{ArenaBytes, FactValue, Span};
use busbar_contract::control::{Control, Rendering};
use busbar_contract::dest::DestinationFacts;
use busbar_contract::unit::{AdmitFacts, AuditFacts, Ctx, FinishClass, Unit, UnitEnd};
use busbar_contract::wire::Encode;

use crate::meta::FACT_VERB;
use crate::verbs::{self, VERB_OPENAPI_JSON};
use crate::{refusal, AdminControl};

/// The span of a string value's CONTENT at one pointer, quotes excluded.
///
/// Through the contract's own span grammar, which is the kernel's. This surface used to carry a
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

/// The operation the loop resolved, read back off the unit's sealed draft facts.
///
/// The fact's own string borrows the unit; the row it names is static, and the destination shape is
/// `&'static str`, so the name is resolved against the declared table rather than re-derived from
/// the body.
fn draft_verb(u: &Unit<'_>) -> Option<&'static str> {
    match u.draft_facts().get(FACT_VERB) {
        Some(FactValue::Str(name)) => verbs::verb_named(name).map(|e| e.operation),
        _ => None,
    }
}

impl Control for AdminControl {
    fn verify<'u>(&self, u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        // The loop already refused anything that does not resolve to one of the declared rows, so
        // the operation fact is always set on a unit that reached this call. The `"unknown"`
        // fallback exists only because `verify` cannot return a `Result`: it is unreachable in a
        // correctly wired loop, not a silently wrong answer — a destination named `"unknown"` is
        // refused by the trust unit rather than dialled.
        DestinationFacts::KernelVerb {
            verb: draft_verb(u).unwrap_or("unknown"),
        }
    }

    fn admit<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        // A control unit is not priced against a lane: no lane locator, no response ceiling to
        // clamp, no priced input span. This surface declares no meter classes at all (`meta`), so
        // there is nothing for the door to hold against.
        AdmitFacts::default()
    }

    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        // One mapping, written once in the contract and read by every kind, because the audit
        // record is the same record whichever door the request came in by.
        let finish = busbar_contract::unit::finish_class_of(out, FinishClass::Complete);
        AuditFacts {
            op_class: u.op(),
            finish,
        }
    }

    fn answer<'u>(
        &self,
        _u: &Unit<'u>,
        rendering: Rendering<'u, '_>,
        ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        let (body, facts) = match rendering {
            Rendering::Refused(refused) => {
                let envelope = refusal::envelope(refused.reason);
                return ctx
                    .arena()
                    .alloc_bytes(envelope.as_bytes())
                    .map_err(|_| Encode::ArenaExhausted);
            }
            Rendering::Served { body, facts } => (body, facts),
        };
        let body = body.as_slice();
        // The one documented exception: the `openapi.json` blob is served verbatim by
        // `busbar-unit-verbs` (this surface computes no result), EXCEPT that `info.version` is
        // substituted for this crate's own version. The surface learns which operation produced a
        // body the same way it learns everything else about one it did not produce itself: the
        // executing unit stamps the operation back onto the rendering's facts, under the key this
        // crate's own declaration uses. Where that fact is absent, the safe default is the ordinary
        // passthrough below, never the substitution — a byte-identical pass-through is always a safe
        // default; a wrong substitution is not.
        //
        // THE PASS-THROUGH DOES NOT GO THROUGH THE ARENA. The arena is 4 KiB per unit and the body
        // already lives for the unit — it is the executing verb's own bytes, not something this
        // surface produced — so borrowing it is both cheaper and the only thing that WORKS: copying
        // meant every admin answer larger than the arena was refused for arena budget, and
        // `openapi.json` alone is over 350 KB. A borrow has no budget to exhaust.
        let is_openapi_json =
            matches!(facts.get(FACT_VERB), Some(FactValue::Str(v)) if v == VERB_OPENAPI_JSON);
        if is_openapi_json {
            // The one exception is the one case that genuinely produces NEW bytes, so it is the one
            // case that has to find somewhere to put them. Where the rendered document does not fit
            // the arena, the safe default the paragraph above states applies — the verbatim
            // borrow — rather than an arena refusal: a document whose `info.version` still reads
            // the executing verb's own value is a document; no document at all is not.
            if let Some(rendered) = substitute_info_version(body, env!("CARGO_PKG_VERSION")) {
                if let Ok(bytes) = ctx.arena().alloc_bytes(&rendered) {
                    return Ok(bytes);
                }
            }
        }
        Ok(ArenaBytes::new(body))
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
#[path = "tests/control.rs"]
mod tests;
