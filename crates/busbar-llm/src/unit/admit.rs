// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 4 — **Admit**: the door, as the LLM plane's own step file.
//!
//! This is the plane half of the kernel's `Units::admit` row. The signature below is that row's,
//! argument for argument — the step's own unit token, the admit token the hold is opened with, the
//! request's context, the principal and the verified set — and it hands back the same sealed
//! answer, `Decision<Admit>`, alongside the plane-side facts the Route, Meter and Audit steps read.
//!
//! # The body is today's door, unchanged
//!
//! One call: `EngineHost::admission_check`, with the same arguments the live path passes to
//! `EngineHost::admission_door` at `native_ingress.rs`'s `drive`, minus the one the door needs only
//! to post its own refusal. Behind that seam is core's `admit_check` →
//! `GovState::try_admit`, which is the check-then-charge at the tag: pass one tests every bucket of
//! the pool-filtered chain and returns on the first blocking one having charged nothing, pass two
//! charges `requests` and `billable_requests` on every bucket under the same shard guards. Nothing
//! here re-implements any part of that, and nothing here may: a request the older release admitted
//! is admitted here, and one it refused is refused here, at the same bucket, on the same metric,
//! with the same retry hint.
//!
//! # Where the money is
//!
//! **The charge point is here and nowhere earlier.** Everything before this step — the pool ACL,
//! the fallback-pool ACL, the no-rate check — turns a request away having charged nothing, and
//! ends through the not-charged terminal. Everything from this step onward has been charged, and
//! ends through the charged terminal. That line is what makes the two refusal doors mean different
//! things, and moving a check across it changes what a caller is billed. In particular candidate
//! resolution and the model-miss 404 stay *after* this call, in the Route step: a 404 for a name
//! that resolved to no lane is a charged 404, and resolving names earlier would silently make it
//! free.
//!
//! **The refusal is free.** A door refusal has charged nothing, so nothing is refunded and nothing
//! may be. The refund is a blind decrement of a shared window counter; issuing one for a request
//! that never charged erodes another request's spend in the same window. The door has already
//! RENDERED the refusal by the time it returns it — those are the bytes the client gets, and this
//! step carries them through untouched rather than re-deriving them from the reason code.
//!
//! **It has not POSTED it.** That is what `admission_check` is for and what `admission_door` is
//! not: the door's own arm finishes its refusal through the not-charged terminal, which for a plane
//! whose terminal is its own Audit step would put a second link on a unit that ends at that step
//! anyway. This step takes the check, carries the unposted bytes out on [`Admitted::refusal`], and
//! the Audit step is the single place any unit of this plane is sealed — the over-budget path
//! included.
//!
//! **The fee is a lookahead, not a posting.** The flat per-request fee enters the budget
//! comparison inside `try_admit` (derived spend plus the fee against the cap) and is *posted* by
//! the billable count this step charges. A non-2xx end refunds that count — the fee base — and
//! never the admission `requests` count, so a caller cannot escape a request cap by failing.
//!
//! # The hold
//!
//! The hold this step opens is accounting. It sizes a reservation; it never refuses a unit the
//! decision admitted, and an under-sized one tops up or posts an overdraft rather than turning
//! anyone away. That is why it is opened at zero here: the pricer that sizes it against the
//! verified set is the ledger phase's, and a hold sized wrong is invisible to a caller, whereas a
//! hold that gated admission would not be. What the hold does carry from this step is the identity
//! it was opened for and the fact that the door said yes — which is what the exit path needs to
//! settle it exactly once.

use std::sync::Arc;

use axum::response::Response;
use busbar_caps::{
    step::Admit, Admission, AdmitToken, Decision, Hold, PrincipalId, ReasonCode, Refusal,
    UnitToken, VerifiedDestination,
};
use busbar_substrate::plane_host::EngineHost;

/// What one destination name resolves to, as the accrual scope has to read it.
///
/// The three arms are the shipped candidate resolution's three answers, and they are kept apart
/// because the accrual scope differs between the first two: a configured pool accrues under its own
/// name, and a bare model lane belongs to no pool and accrues under the DEFAULT (empty) cell, which
/// is the cell the shipped release charges it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// A configured pool. `has_lane` is false for a pool with no member left to route to — which is
    /// admitted rather than refused, and draws a slot, exactly as the shipped release charges it.
    Pool {
        /// Whether the pool has any member to route to.
        has_lane: bool,
    },
    /// A bare model name that names one lane directly.
    Lane,
    /// The name names nothing this node has. The charged model-miss 404 is the Route step's, and it
    /// is charged precisely because this step already ran.
    Miss,
}

impl Resolved {
    /// The cell an accrual on this destination scopes to, given the name that resolved.
    fn cell(self, name: &str) -> &str {
        match self {
            // A bare lane routes on the default cell, exactly as the shipped path opens its sink.
            Resolved::Lane => "",
            Resolved::Pool { .. } | Resolved::Miss => name,
        }
    }

    /// Whether there is an upstream to route to — the fact that makes a client unit draw a request
    /// slot and post the flat fee.
    fn has_lane(self) -> bool {
        match self {
            Resolved::Pool { has_lane } => has_lane,
            Resolved::Lane => true,
            Resolved::Miss => false,
        }
    }
}

/// The deployment, as this step reads it.
pub trait DestinationCells {
    /// What one name resolves to.
    fn resolve(&self, name: &str) -> Resolved;
}

/// THE DEPLOYMENT, as the door reads one on a live node.
///
/// Read through the Route step's own candidate resolution rather than through a second reading of
/// the tables: the cell this answers with is the cell the walk will route on, because it is the same
/// call that produces it.
impl DestinationCells for crate::engine::NativeRuntime {
    fn resolve(&self, name: &str) -> Resolved {
        match crate::unit::route::candidates(self, name) {
            // The pool cell rides back as the destination's own name for a pool and as the empty
            // default cell for a bare lane, which is the one bit that tells the two apart.
            Some((cands, "")) => {
                debug_assert_eq!(cands.len(), 1, "a bare model name names exactly one lane");
                Resolved::Lane
            }
            Some((cands, _)) => Resolved::Pool {
                has_lane: !cands.is_empty(),
            },
            None => Resolved::Miss,
        }
    }
}

/// What the door needs that the step shape has nowhere to put.
///
/// The pinned arrival epoch is the important one: both the flat fee charged here and the token fee
/// charged at stream end are attributed to the window this epoch implies, so a request whose
/// response completes in a later window than its headers arrived cannot split its two charges
/// across two windows.
///
/// There is no start instant here, and that absence is the point: the only thing the door ever
/// needed one for was observing the finish-stage latency of the refusal it posted itself, and it no
/// longer posts one. The instant travels with the step that does.
pub struct AdmitCtx<'a> {
    /// The neutral host seam the door is reached through.
    pub host: &'a Arc<dyn EngineHost>,
    /// The ONE question this step asks of the deployment: what the destination the charge landed on
    /// RESOLVES to. Two answers this step hands on are the resolution's and not the caller's
    /// spelling — the cell the sink accrues under, and whether there is an upstream to route to at
    /// all — and asking here is what keeps them from being read off the pre-downgrade name.
    ///
    /// A view rather than the tables themselves, for the same reason the Verify step's guards take
    /// one: the engine's runtime is this crate's own machinery and a step's context is named by the
    /// composition root, which may not name it.
    pub cells: &'a dyn DestinationCells,
    /// This request's governance context — the resolved key, or none.
    pub gov: &'a busbar_api::PlaneRequestCtx,
    /// The ingress protocol name, for the refusal's native error envelope.
    pub proto: &'static str,
    /// The destination the caller named: a pool, or a model that resolves to one lane.
    pub destination: &'a str,
    /// The pinned header-arrival epoch every charge and every refund lands in.
    pub charged_at: u64,
}

/// The door's answer, plus what the later steps read.
///
/// [`Admitted::decision`] is exactly what the kernel's `Units::admit` returns. The rest is the
/// plane's own: which pool the charge actually landed on, whether it landed at all, the meter half
/// of the hold, and — on a refusal — the bytes the door already rendered.
pub struct Admitted {
    /// The sealed step-4 answer.
    pub decision: Decision<Admit>,
    /// Whether the charge LANDED. `false` means the request was admitted without charging
    /// (governance off, or no key resolved), and a non-2xx end must NOT refund: the refund is a
    /// blind decrement that would erode another request's spend in the same window.
    pub charged: bool,
    /// `Some` when a budget `on_exhaust: downgrade` re-pooled the admission. The charge landed on
    /// THIS pool's buckets, so the dispatch follows it — accounting follows the traffic.
    pub effective_pool: Option<String>,
    /// Whether the verified set offered an upstream to route to, which is what makes a client unit
    /// draw a request slot and post the flat fee.
    pub upstream_candidate: bool,
    /// The stream-end metering sink: the hold's meter half. It carries the admission's in-flight
    /// concurrency gauges, which release when its last clone drops — i.e. when the response stream
    /// completes or the request unwinds — so it is built here, with the admission, and never later.
    ///
    /// Read by the Route step, which carries it to every accrual site, and by Meter — both of which
    /// now exist, so the `allow(dead_code)` this field used to carry has been deleted rather than
    /// left to cover a reader that arrived.
    pub(crate) sink: Option<crate::engine::UsageSink>,
    /// The door's own rendered refusal — bytes, not a posted record. Present exactly when the
    /// decision refuses, and handed to the Audit step's not-charged terminal there and nowhere
    /// else, so this path has the same single terminal every other path has.
    pub refusal: Option<Response>,
}

impl Admitted {
    /// The step's answer on its own, which is what the loop takes.
    pub fn into_decision(self) -> Decision<Admit> {
        self.decision
    }
}

/// The shape of this step, as a value — the `Units::admit` row with the plane's own context.
///
/// The kernel's row takes a `UnitCtx` the kernel owns and this crate cannot name: a plane is a
/// plugin on the neutral ABI and does not depend on the kernel. So the context is the plane's, and
/// everything else — the two tokens, the principal, the verified set, the sealed answer — is the
/// kernel's own vocabulary, named at `busbar-caps` where a plugin is entitled to name it.
pub type AdmitStep = for<'a, 'b> fn(
    &UnitToken<Admit>,
    &AdmitToken<Admit>,
    &AdmitCtx<'a>,
    &PrincipalId,
    &'b [VerifiedDestination],
) -> Admitted;

/// Step 4. Ask the door, and open the hold its yes entitles the unit to.
///
/// Two of the facts this step hands on are about the destination the charge LANDED on, and the door
/// is where that stops being the caller's spelling: a budget `on_exhaust: downgrade` re-pools the
/// admission, and the verified set this step is handed was built over the pre-downgrade name. So
/// "which cell does the accrual scope to" and "is there an upstream to route to" are both asked of
/// the effective name, through the same resolution the Route step walks with.
///
/// The verified set is therefore NOT what says whether there is an upstream: it answers about a pool
/// the charge may no longer be on. Every destination this plane verifies is an upstream lane, so the
/// two agree wherever nothing was downgraded — which is every request that is not re-pooled, and is
/// why the difference is invisible until one is.
pub fn admit(
    unit_token: &UnitToken<Admit>,
    admit_token: &AdmitToken<Admit>,
    ctx: &AdmitCtx<'_>,
    principal: &PrincipalId,
    // The set the Verify step sealed, over the name the caller asked for. It is the loop's row and
    // it is deliberately not read here: see this function's header for why the two facts that used
    // to be read off it are asked of the effective destination instead.
    _destinations: &[VerifiedDestination],
) -> Admitted {
    // THE door, taken without its terminal. Its `Err` is the refusal ALREADY rendered in the
    // ingress protocol's native envelope and NOT yet posted — nothing was charged, so nothing is
    // refunded on the way out, and the one place it is sealed is the Audit step.
    match ctx
        .host
        .admission_check(ctx.gov, ctx.proto, ctx.destination, ctx.charged_at)
    {
        Err(resp) => refused(unit_token, *resp),
        Ok((admit, downgraded)) => {
            // `Some` iff the charge landed. Governance off or no resolved key admits without
            // charging, and that request must finish with `charged = false`.
            let charged = admit.is_some();
            // A budget downgrade re-pooled the admission: the accrual scope is the pool the charge
            // landed on, not the one the caller asked for, so the effective name is the one
            // resolved below.
            let effective = downgraded.as_deref().unwrap_or(ctx.destination);
            // WHAT THE EFFECTIVE NAME RESOLVES TO, asked once and read twice — the same resolution
            // the shipped path runs before it opens its own sink, so the two cannot answer
            // differently about one name.
            //
            // THE ACCRUAL SCOPE IS THE CELL, not the caller's spelling of the destination. Opening
            // the sink on the raw name instead attributes a by-model request's token accrual to a
            // pool bucket named after the model — a bucket the shipped release never charges.
            let resolved = ctx.cells.resolve(effective);
            let sink = crate::native_ingress::usage_sink(
                ctx.host,
                ctx.gov,
                resolved.cell(effective),
                ctx.charged_at,
                admit,
            );
            Admitted {
                // The hold is opened at zero: it is accounting, and sizing it is the ledger
                // phase's. See this module's header for why a small hold cannot refuse anyone.
                decision: Decision::proceed(
                    unit_token,
                    Admission::Own(Hold::open(admit_token, principal.clone(), 0)),
                ),
                charged,
                upstream_candidate: resolved.has_lane(),
                effective_pool: downgraded,
                sink,
                refusal: None,
            }
        }
    }
}

/// A door refusal: no hold, no charge, no refund, no posted link, and the door's own bytes carried
/// through to the one step that posts.
///
/// The reason code is the record's closed vocabulary, and it is READ off the answer rather than
/// assumed: the door stamps which bucket blocked on the refusal it hands back, so an administratively
/// frozen group and a saturated in-flight cap are filed as what they are rather than both as a spent
/// budget. Filing all three under one reason makes a record that cannot tell an operator whether a
/// key was frozen or a caller was simply too fast — and those need different answers.
///
/// NOTHING THE CLIENT SEES MOVES. The stamp rides on the response's extensions, which are dropped
/// when the response is written; the byte-exact refusal — the status, the `kind`, the message and
/// the retry hint an SDK reads — is the response itself, carried through untouched rather than
/// re-derived from the code. The retry hint is lifted onto the refusal so the record carries the
/// same number the wire does.
///
/// A refusal carrying no stamp is filed as over-budget, which is what this step filed before there
/// was a stamp to read and is the honest reading of a door that did not say.
fn refused(unit_token: &UnitToken<Admit>, resp: Response) -> Admitted {
    let reason = match resp
        .extensions()
        .get::<busbar_substrate::plane_host::AdmissionBlock>()
    {
        Some(busbar_substrate::plane_host::AdmissionBlock::GroupFrozen) => ReasonCode::GroupFrozen,
        Some(busbar_substrate::plane_host::AdmissionBlock::RateLimited) => ReasonCode::RateLimited,
        Some(busbar_substrate::plane_host::AdmissionBlock::OverBudget) | None => {
            ReasonCode::OverBudget
        }
    };
    let mut refusal = Refusal::new(reason);
    if let Some(secs) = retry_after_secs(&resp) {
        refusal = refusal.retry_after(secs);
    }
    Admitted {
        decision: Decision::refuse(unit_token, refusal),
        charged: false,
        effective_pool: None,
        upstream_candidate: false,
        sink: None,
        refusal: Some(resp),
    }
}

/// The `Retry-After` the door rendered, in whole seconds.
fn retry_after_secs(resp: &Response) -> Option<u32> {
    resp.headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
}

#[cfg(test)]
#[path = "tests/admit.rs"]
mod tests;
