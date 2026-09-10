// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT STEP — the one place a unit of this plane ends.
//!
//! Audit is the last of the unit's seven steps, and it is the only one that returns a finished
//! response. Everything else in the unit answers with a decision and hands the response along; this
//! file turns the last of those into a posted record, a metric, a request-log link and a refund
//! where one is owed, and gives the bytes back to the loop.
//!
//! ## Two doors, one terminal
//!
//! A unit that PASSED the admission door is audited WITH its charge: the caller was charged, the
//! record has to say what for, and a non-2xx outcome refunds the flat fee it actually paid. A unit
//! that never passed is audited WITHOUT one: nothing was charged, so there is nothing to refund, and
//! a refund on that path would be a blind decrement against a different request's spend in the same
//! window. That is the whole difference between [`audit`] and [`audit_refused`] — and it is a
//! difference of evidence, not of destination. Both doors lead to the same terminal, which settles,
//! emits and links exactly once, and there is no third way out of this plane.
//!
//! ## Which pool the record says
//!
//! Both doors name the destination the same way: through [`EngineHost::pool_label`], the host's own
//! bound, so an unconfigured model name can never open a new metric series on either path. A unit
//! that reached routing names the pool the charge landed on. A unit refused before routing names
//! whatever destination it had got as far as reading — a CONFIGURED pool it was not permitted to
//! reach is recorded under that pool's name, exactly as the live pre-admission guard records it —
//! and a unit refused before any destination was read names the reserved unresolved label, which
//! the same bound maps to itself. Both are still counted and still fire the request-log webhook: a
//! pre-routing turn-away that is invisible to the operator is the failure mode this rule exists to
//! prevent, and a raw early return is exactly that failure.
//!
//! ## Why the doors live here and nowhere else
//!
//! The construction gate names this file, and a call to either door anywhere else in this crate is
//! counted against the plane. That is not tidiness: a second call site is a second way for a unit to
//! be posted, and "posted exactly once" is a property of the call graph, not of the intent of
//! whoever wrote the second site.
//!
//! ## Why the RENDERING lives here too
//!
//! A refusal taken at any earlier step is not bytes yet: it is a named outcome — a status, a
//! dialect-neutral code word, the sentence the client reads, and whatever headers the refusal itself
//! carries. [`RefusalOutcome`] is that value, and [`render_refusal`] is the one function in this
//! directory that turns one into a response. An earlier step that could build a response could hand
//! it straight back to the loop and skip the terminal, which is the same hole the two doors close
//! from the other side: the gate forbids a `Response` return anywhere under the step directory but
//! this file, so "every outcome is rendered at the terminal" is a property the compiler and the gate
//! hold jointly rather than a convention.

// BUILT DARK, as the Route step beside it is: the doors below have no production caller until the
// unit's own shell is assembled, and the identity harness at the bottom is what drives them until
// then. The allow is scoped to this file so it retires with the step it covers.
#![allow(dead_code)]

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;

use busbar_caps::{step::Audit, AuditFacts, Decision, OpClassId, UnitToken};
use busbar_contract::FinishClass;
use busbar_substrate::plane_host::EngineHost;

/// BYTES THAT HAVE PASSED THROUGH THIS FILE — the only shape in which a response moves between the
/// steps, and the only shape in which one leaves the plane.
///
/// A newtype, and the point is entirely in where its two halves live. [`Served::of`] and
/// [`Served::into_response`] are written HERE, in the one file the construction gate lets return a
/// `Response`, so every crossing between "a response" and "what a step may hold" happens inside the
/// terminal's own file. A step file can carry one of these from end to end and never name the type
/// it wraps; the loop's driver can unwrap one exactly where it hands the transport its answer. What
/// neither can do is invent a finished response somewhere in the middle of the unit and return it,
/// because there is nowhere else the conversion is spelled.
///
/// This is the compiler's half of the rule the gate states. The gate counts signatures; the type
/// makes the count structural.
pub struct Served(Response);

impl Served {
    /// Take bytes into the sealed shape. Called from the walk when a step renders a refusal, and
    /// from the driver for the node's own last-resort answer.
    #[must_use]
    pub fn of(resp: Response) -> Self {
        Served(resp)
    }

    /// Give the bytes back to the transport. The ONE unwrap, at the ONE place a unit's answer
    /// leaves the plane.
    #[must_use]
    pub fn into_response(self) -> Response {
        self.0
    }

    /// Read the sealed bytes without taking them — what the terminal's own facts are read off.
    #[must_use]
    pub fn as_response(&self) -> &Response {
        &self.0
    }
}

impl std::fmt::Debug for Served {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Served")
            .field("status", &self.0.status())
            .finish_non_exhaustive()
    }
}

/// A REFUSAL AS A VALUE — what an earlier step answers with instead of bytes.
///
/// The three parts are the three a client can observe of a turn-away, and they are deliberately
/// dialect-NEUTRAL: the `status` it wears, the `kind` code word (one of the substrate's shared
/// tokens, not a dialect's spelling of it) and the `message` sentence. Which envelope those are
/// poured into — which member names, which nesting, which synthesized header — is the caller's
/// dialect's business and is decided at the terminal, from the protocol name, by
/// [`render_refusal`]. A step that chose the envelope would be a step that had to know the dialects,
/// and "delete a dialect and the plane is free of it" would stop being true of the step files.
///
/// `headers` is for the refusals that carry one of their OWN — a `Retry-After` on a rate-limit
/// turn-away is the live example. They are stamped onto the rendered response after the envelope, so
/// a refusal that carries none is byte-for-byte what the bare shaper produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalOutcome {
    status: StatusCode,
    kind: &'static str,
    message: Cow<'static, str>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl RefusalOutcome {
    /// Name a refusal: the status, the code word, the sentence. No headers of its own.
    pub fn new(
        status: StatusCode,
        kind: &'static str,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
            headers: Vec::new(),
        }
    }

    /// Add a header this refusal carries in its own right.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// The status this refusal wears on the wire.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The dialect-neutral code word this refusal wears on the wire.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// The sentence the client reads.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The headers the refusal carries in its own right, in the order they were named.
    pub fn headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }
}

/// THE ONE PLACE A NAMED REFUSAL BECOMES BYTES.
///
/// The shaper is the same `ingress_error` the live arms call, given the same three values, so the
/// bytes are the live path's bytes rather than an equivalent set of them. The refusal's own headers
/// are stamped afterwards, which is the order the live arms stamp them in: the envelope first, the
/// refusal's additions over it.
///
/// This does NOT post the unit. Rendering and sealing are two jobs and they are two functions: a
/// refusal is rendered here and then handed to [`audit_refused`], which is what makes the record and
/// the response come from one place without making them one call.
pub fn render_refusal(proto: &str, refusal: &RefusalOutcome) -> Response {
    let mut resp = busbar_substrate::proxy::ingress_error(
        proto,
        refusal.status(),
        refusal.kind(),
        refusal.message(),
    );
    for (name, value) in refusal.headers() {
        resp.headers_mut().insert(name.clone(), value.clone());
    }
    resp
}

/// What the terminal needs that the step shape has nowhere to put.
///
/// The same evidence the two doors always took — who was calling, on what wire, as what operation
/// class, to what destination, since when, and in which charge window — gathered into one value so
/// the step itself can be what every other step is: a token in, a decision out. The destination is
/// the only field either door reads differently, and it does not: both bound it through
/// [`EngineHost::pool_label`], so an unconfigured name can never open a metric series on either
/// path, and a CONFIGURED one is recorded under its own name on both.
pub struct AuditCtx<'a> {
    /// The neutral host seam the terminal is reached through.
    pub host: &'a Arc<dyn EngineHost>,
    /// This request's governance context — the resolved key, or none.
    pub gov: &'a busbar_contract::store::PlaneRequestCtx,
    /// The ingress protocol name, as the record spells the wire.
    pub proto: &'static str,
    /// The operation class the unit was, as the sealed facts name it.
    pub op_class: OpClassId,
    /// The destination the record names. For a unit that reached routing, the pool the charge
    /// landed on — post-downgrade. For one refused before a destination was ever read, the reserved
    /// unresolved label, which the host's own bound maps to itself.
    pub destination: &'a str,
    /// When the request started, for the finish-stage latency observation.
    pub started: Instant,
    /// The pinned header-arrival epoch the refund, where one is owed, lands in.
    pub charged_at: u64,
}

/// The terminal's answer: the sealed step-7 facts, and the bytes the loop gives the client.
///
/// [`Audited::decision`] is exactly what the kernel's `Units::audit` returns. The response rides
/// beside it because this step is the only one in the plane that has one to give, and the loop —
/// not this step — is what hands it back to the transport.
pub struct Audited {
    /// The sealed step-7 answer: what the plane says this unit was, and how it says it ended.
    pub decision: Decision<Audit>,
    /// The posted response, in the sealed shape — the only shape a response moves in outside this
    /// file.
    pub response: Served,
}

impl Audited {
    /// The step's answer on its own, which is what the loop takes.
    pub fn into_decision(self) -> Decision<Audit> {
        self.decision
    }
}

/// The shape of this step, as a value — the `Units::audit` row with the plane's own context.
///
/// The kernel's row takes a `UnitCtx` and a `UnitEnd` the kernel owns and this crate cannot name; a
/// plane is a plugin on the neutral ABI and does not depend on the kernel. So the context is the
/// plane's and the provisional end is the response itself, while the token and the sealed answer
/// are the kernel's own vocabulary, named at `busbar-caps` where a plugin may name it.
pub type AuditStep = for<'a> fn(&UnitToken<Audit>, &AuditCtx<'a>, Served, bool) -> Audited;

/// How the plane says a unit ended.
///
/// TWO SOURCES, and the order between them is the whole of this function. The first is the WALK'S
/// OWN TAP, riding back on the response in the cell the walk handed it: where the tap has reported,
/// it is the only thing that knows the difference between an answer that finished and one that
/// stopped — a stream is served on 2xx headers and can still die mid-body, so the status line says
/// `Complete` and the truth is `Partial`. The second is the client-facing status, which is what a
/// response without a tap can say and all the older release ever said: an upstream that answered 200
/// into a client-facing 502 ended in error, because the end a record seals is the end the CALLER
/// experienced.
///
/// The tap is empty while a response is still in flight, and then this reads the status exactly as
/// it always has — so the terminal's timing and its bytes are unchanged, and what the tap adds is a
/// truer class on every end that has already happened by the time the record is written.
///
/// [`FinishClass::TurnComplete`] is never answered here. It names one turn of a duplex exchange
/// whose session continues, and no dialect this plane speaks has one: a completion's end is the
/// unit's end.
fn finish_of(resp: &Response) -> FinishClass {
    if let Some(finish) = resp
        .extensions()
        .get::<crate::engine::TapCell>()
        .and_then(|cell| cell.get())
        .map(|report| report.finish)
    {
        // THE ONE MAPPING between the engine's own three-class ending and the loop's four. It is
        // written here because this file is the only one on this plane that speaks the loop's
        // vocabulary; the engine spells its own so the default build does not depend on the waist's
        // flag. `TurnComplete` has no source: nothing below can produce it, and nothing on this
        // plane should.
        return match finish {
            crate::engine::TapFinish::Complete => FinishClass::Complete,
            crate::engine::TapFinish::Partial => FinishClass::Partial,
            crate::engine::TapFinish::Error => FinishClass::Error,
        };
    }
    if resp.status().is_success() {
        FinishClass::Complete
    } else {
        FinishClass::Error
    }
}

/// Seal the end of a unit that PASSED the door.
///
/// `charged` is the door's own answer, carried through Route unchanged: an admission that
/// fail-opened without charging must not refund, because the refund is a decrement of a shared
/// window and there is nothing of this unit's in it.
pub fn audit(
    unit_token: &UnitToken<Audit>,
    ctx: &AuditCtx<'_>,
    resp: Served,
    charged: bool,
) -> Audited {
    let facts = AuditFacts {
        op_class: ctx.op_class,
        finish: finish_of(resp.as_response()),
    };
    Audited {
        response: Served::of(ctx.host.finish_admitted(
            ctx.gov,
            ctx.proto,
            ctx.host.pool_label(ctx.destination),
            ctx.started,
            ctx.charged_at,
            resp.into_response(),
            charged,
        )),
        decision: Decision::proceed(unit_token, facts),
    }
}

/// Seal the end of a unit that never passed the door. Nothing was charged, so nothing is refunded.
///
/// The label is the SAME bound the admitted door applies, over the same destination, and that is
/// the whole of the difference this function used to get wrong: it named the reserved unresolved
/// label unconditionally, so a 403 raised against a CONFIGURED pool was recorded as if the pool had
/// never resolved, while the live pre-admission guard recorded it under the pool's own name. The
/// bytes agreed and the record did not. A caller that genuinely has no destination yet — a refusal
/// taken before the model was ever read — passes [`busbar_substrate::proxy::POOL_LABEL_UNRESOLVED`], which
/// the bound maps to itself because no deployment may configure a pool by that name.
pub fn audit_refused(unit_token: &UnitToken<Audit>, ctx: &AuditCtx<'_>, resp: Served) -> Audited {
    // A refusal is never a completion, whatever status it wears.
    let facts = AuditFacts {
        op_class: ctx.op_class,
        finish: FinishClass::Error,
    };
    Audited {
        response: Served::of(ctx.host.finish_rejected(
            ctx.gov,
            ctx.proto,
            ctx.host.pool_label(ctx.destination),
            ctx.started,
            ctx.charged_at,
            resp.into_response(),
        )),
        decision: Decision::proceed(unit_token, facts),
    }
}

/// THE AUDIT-STEP IDENTITY HARNESS: this step against the live terminal it was lifted from.
///
/// Each case drives two governed callers — so each has a request chain of its own and the two can be
/// told apart in a process-wide log — through the live door and through the step, and compares the
/// response the client is given and the record the operator can read back: same protocol, same pool
/// label, same outcome, same status, and EXACTLY ONE link per unit on each chain.
#[cfg(test)]
#[path = "tests/audit.rs"]
mod tests;
