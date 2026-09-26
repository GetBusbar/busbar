// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 4 — **Admit**: the door, as the LLM plane's own step file.
//!
//! This is the plane half of the kernel's `Units::admit` row. It asks the door and hands back the
//! door's VERDICT — admitted, or the refusal — alongside the plane-side facts the Route, Meter and
//! Audit steps read. It does not hand back the sealed `Decision<Admit>`, because on a yes that
//! decision carries the unit's hold, and the hold is not the plane's to open (see "The hold" below).
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
//! The hold is the KERNEL'S, and this step neither opens nor names one. #43 makes a plane
//! pricing-blind and #83 puts the hold at the kernel's admit and exit (defs 5/6): a reservation is
//! accounting against a money figure, and a plane that opened one would be doing money on its side
//! of the seam. So this step says only what the door said; the composition root that drives the
//! kernel's `Units::admit` row opens the hold on a yes, journals it (item 127), and the loop's exit
//! settles it. The hold never refused a unit the door admitted, so moving where it is opened moves
//! no refusal and no figure.

use std::sync::Arc;

use axum::response::Response;
use busbar_contract::caps::{ReasonCode, Refusal, VerifiedDestination};
use busbar_kernel::plane_host::EngineHost;

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
    /// This request's governance context — the resolved key, or none.
    pub gov: &'a busbar_contract::records::PlaneRequestCtx,
    /// The ingress protocol name, for the refusal's native error envelope.
    pub proto: &'static str,
    /// The destination the caller named: a pool, or a model that resolves to one lane.
    pub destination: &'a str,
    /// The pinned header-arrival epoch every charge and every refund lands in.
    pub charged_at: u64,
}

/// The door's answer, plus what the later steps read.
///
/// [`Admitted::verdict`] is the door's yes or no; the kernel turns it into the sealed step-4
/// answer, opening the hold on a yes. The rest is the plane's own: which pool the charge actually
/// landed on, whether it landed at all, the stream-end metering sink, and — on a refusal — the
/// bytes the door already rendered.
pub struct Admitted {
    /// The door's verdict: `Ok` when it admitted the unit, the refusal when it did not.
    pub verdict: Result<(), Refusal>,
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
    /// The stream-end metering sink. It carries the admission's in-flight
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

/// The shape of this step, as a value — the plane's half of the `Units::admit` row.
///
/// The kernel's row takes a `UnitCtx` the kernel owns and this crate cannot name: a plane is a
/// plugin on the neutral ABI and does not depend on the kernel. So the context is the plane's. The
/// step tokens, the principal and the sealed answer stay with the kernel's row, which opens the
/// hold; the plane reads the verified set and answers with the door's verdict.
pub type AdmitStep = for<'a, 'b> fn(&AdmitCtx<'a>, &'b [VerifiedDestination]) -> Admitted;

/// Step 4. Ask the door, and say what it answered.
///
/// The verified set is read for one fact only: whether there is an upstream to route to. Every
/// destination this plane verifies is an upstream lane, so a non-empty set is that fact; the kind
/// tag that would say so directly is not on a verified destination yet.
pub fn admit(ctx: &AdmitCtx<'_>, destinations: &[VerifiedDestination]) -> Admitted {
    // THE door, taken without its terminal. Its `Err` is the refusal ALREADY rendered in the
    // ingress protocol's native envelope and NOT yet posted — nothing was charged, so nothing is
    // refunded on the way out, and the one place it is sealed is the Audit step.
    match ctx
        .host
        .admission_check(ctx.gov, ctx.proto, ctx.destination, ctx.charged_at)
    {
        Err(resp) => refused(*resp),
        Ok((admit, downgraded)) => {
            // `Some` iff the charge landed. Governance off or no resolved key admits without
            // charging, and that request must finish with `charged = false`.
            let charged = admit.is_some();
            // A budget downgrade re-pooled the admission: the accrual scope is the pool the charge
            // landed on, not the one the caller asked for, so the sink is built against it.
            let pool = downgraded.as_deref().unwrap_or(ctx.destination);
            let sink =
                crate::native_ingress::usage_sink(ctx.host, ctx.gov, pool, ctx.charged_at, admit);
            Admitted {
                // A yes, and nothing more: the hold it entitles the unit to is the kernel's to open.
                verdict: Ok(()),
                charged,
                effective_pool: downgraded,
                upstream_candidate: !destinations.is_empty(),
                sink,
                refusal: None,
            }
        }
    }
}

/// A door refusal: no charge, no refund, no posted link, and the door's own bytes carried through
/// to the one step that posts.
///
/// The reason code is the record's closed vocabulary, and the seam this step reaches the door
/// through hands back a rendered response rather than the blocking bucket, so the code cannot be
/// narrowed past "a budget in the chain had no headroom" from here. The byte-exact refusal — the
/// status, the `kind`, the message and the retry hint an SDK reads — is the response itself, which
/// is why it is carried rather than re-derived. The retry hint is lifted onto the refusal so the
/// record carries the same number the wire does.
fn refused(resp: Response) -> Admitted {
    let mut refusal = Refusal::new(ReasonCode::OverBudget);
    if let Some(secs) = retry_after_secs(&resp) {
        refusal = refusal.retry_after(secs);
    }
    Admitted {
        verdict: Err(refusal),
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
