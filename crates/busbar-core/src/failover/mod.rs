// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAILOVER SEAM — one selection, one admission, one disposition, in core, for every plane that
//! has more than one place to send a request.
//!
//! ## Why this is core and not a plane's
//!
//! Owner's ruling: *"i think mcp and a2a should 100% support failover and reroute — no reason not
//! too"*, and the standing architectural rule *"core needs to be the core. if its used 2x or could
//! be, its core."*
//!
//! Before this module, cause-attributed failure disposition and reroute-before-first-byte were
//! LLM-plane only, and the tree already recorded WHY — and it was never a law about the protocols:
//!
//! > *two servers can expose an equivalent tool and two agents can handle the same task shape, and
//! > busbar simply cannot be told they are interchangeable yet.*
//!
//! That is a missing CONFIG VOCABULARY and a missing SELECTION KEY, not a missing mechanism. The
//! mechanism — [`crate::store::LaneRuntime::try_admit_breaker`], the ONE circuit breaker, keyed by
//! `(pool, lane)` — is good and is not rewritten here. This module is the seam that lets a plane
//! reach it.
//!
//! **What core owns:** what a candidate SET is, the LOOP that walks it, the interchangeability
//! CHECK, the retry-safety RULE, the admission (through the one breaker), and the refusal it
//! produces. **What a plane owns:** what a CANDIDATE is ([`Candidate`]), what makes two of them
//! interchangeable (the pin it hands back from [`Candidate::interchange_key`]), the ORDER they are
//! offered in ([`Order`]) and which admission primitive its dispatch needs — and nothing else.
//! [`crate::egress_auth::gate`] is the precedent this copies rather
//! than a new idea: a plane supplies a grant kind and keeps its refusal wording; it does not keep its
//! own decision. [`crate::audit`] is the nearer one still: core owns the mechanism, a stream supplies
//! one record type.
//!
//! ## WHAT INTERCHANGEABLE MEANS, given that everything here is PINNED
//!
//! This is the hard part and it is not hand-waved. A tool's identity on the MCP plane is pinned by
//! an approved schema digest; an A2A registration is pinned to a verified card at one address. Two
//! DIFFERENT vendors' servers exposing "the same" tool have DIFFERENT fingerprints and different
//! pins, so "interchangeable" cannot be allowed to mean "identical artifact by operator assertion".
//!
//! So it does not mean that. **The canonical case this is built for is THE SAME SERVER, DEPLOYED
//! TWICE** — one image in two regions, a hosted instance beside its self-hosted twin. Same image
//! means the same tool schemas and the same descriptions, and therefore THE SAME FINGERPRINT. That
//! dissolves the problem instead of fighting it:
//!
//! > **Interchangeability is a CHECKABLE FACT, not an operator's assertion. Two candidates are
//! > interchangeable iff the pins busbar already computes AGREE.**
//!
//! [`walk`] enforces exactly that: every failover hop must present the SAME `interchange_key` as the
//! primary, and a candidate that presents `None` (nothing approved yet) or a different key is
//! REFUSED — [`Refusal::NotInterchangeable`] — rather than quietly served. An operator declaring a
//! pool has therefore asserted only *"these two names are the same deployment"*; busbar checks the
//! claim against the digests before it moves a single request, and says so when the claim is false.
//!
//! The honest statement of what is NOT covered: two genuinely different servers offering a similar
//! tool have different pins, so they are refused here. That is deliberate. A call that failed over
//! between them could reach a tool carrying different instructions for the model, which is the
//! confused-deputy shape, and it must never be a default.
//!
//! ## THE SAFETY RULE, which is the reason this module has a `Stage` at all
//!
//! A tool call with side effects is not a chat completion. Retrying `send_email` against a second
//! deployment may send a second email — and the two deployments being the SAME IMAGE makes that
//! worse, not better, because both are wired to the same downstream. So the seam distinguishes two
//! movements that look identical in a log and are not remotely the same act:
//!
//! | movement | has anything been sent? | default |
//! |---|---|---|
//! | [`Stage::BeforeFirstByte`] — REROUTE | no | **ALLOWED** |
//! | [`Stage::AfterDispatch`] — RETRY | yes | **REFUSED** |
//!
//! A reroute is not a retry. When the primary's breaker is Open the request never left busbar, so
//! moving it to an equivalent deployment cannot duplicate anything; that is the case an agent never
//! learns about and it is on by default. An [`Stage::AfterDispatch`] hop is a genuine repeat of a
//! call the upstream may already have executed, and it is refused — [`Refusal::NotRepeatable`] —
//! unless the OPERATION ITSELF is declared [`Repeatable::Yes`]. Read-only work (`search_code`,
//! `read_file`, `run_query`) is the safe half and an operator names it; anything else is refused by
//! default, with no key to turn the rule off wholesale.
//!
//! The two rules COMPOSE, and that composition is the whole safety story: **repeat a call only when
//! the pins match AND the operation is safe to repeat.**
//!
//! ## ADDING A THIRD PLANE COSTS A CANDIDATE TYPE AND NOTHING ELSE
//!
//! That is the acceptance test for this seam, and `tests/failover_tests.rs` declares a candidate type
//! for a plane busbar does not have and shows it selects, admits, trips and reroutes with NO second
//! breaker, NO second walk and NO error type written for it.

// ## ONE SELECTION LOOP, ON ALL THREE PLANES (owner ruling R-I: "Unify now — R-B should be true on
// ## selection too in 1.6.0")
//
// [`walk_with`] is that loop, and it is the only one. R-B was already true of the BREAKER — one FSM,
// one `breaker::classify`, one disposition pipeline, no plane-local state machine — and this is what
// made it true of SELECTION as well. Until it landed the model plane had its OWN admission loop in
// `proxy::select::pick_among`, and this module's own definition of the capability said "the one
// selection loop" while two existed. Both are now the same function.
//
// WHY THIS DIRECTION. The model plane's loop carried SWRR weighting, routing policy, session
// affinity, queueing and `on_exhausted`, and the natural fear was that folding it in would drag all
// of that into core. It did not, because those are not selection:
//
//   * WEIGHTING / ROUTING POLICY / AFFINITY are ORDER — they decide who is ASKED first, never who is
//     ALLOWED. They are now an [`Order`] implementation on the model plane, and nothing they return
//     can admit a candidate the breaker refused, because they perform no admission at all.
//   * QUEUEING and `on_exhausted` (503 / `fallback_pool` / `least_bad` / `queue`) are what that plane
//     does AFTER the loop finds nothing. `proxy::engine::walk`'s own header already said so: the
//     queue wait "lives HERE in on_exhausted dispatch, never inside `pick_among` — selection stays
//     non-blocking". They never moved and they were never a second selection.
//   * The CONCURRENCY PERMIT is the one real difference, and it is a difference of one field:
//     `try_admit` is `try_admit_breaker` plus a permit acquisition, over the same cell, the same
//     verdict decoder and the same single-flight probe CAS. It rides in as the plane's ADMISSION.
//
// The opposite direction — making `pick_among` the one loop and moving MCP and A2A onto it — was
// rejected on the code: it is welded to `App`, to `WeightedLane` and to lane indices into
// `app.lanes`, which MCP servers and A2A agents are not members of (they run on `PlaneBreakers`'
// own runtime); and it has neither the pin check nor the repeat-safety rule, so those two safety
// rules would have had to be bolted onto it or lost on the two planes that need them most.
//
// MOUNTED. The reroute-parity unit (owner ruling R-B: "llm mcp a2a are identical") consumes this
// seam on both non-LLM planes: `mcp::reroute` walks a `tool_pools:` candidate set before every
// `tools/call` leg, and `a2a::receive` walks an `agent_pools:` set at submission admission. Both
// call sites record outcomes through `store::PlaneBreakers::record_signal` — the same Stage-2
// classifier this module's `record_outcome` wraps — rather than through `record_outcome` itself,
// because the plane store's targets share a degenerate lane table and the all-cells hard-down
// write in `record_outcome` would trip every OTHER pool's member at the same position (see
// `store/planes.rs`'s module header for the full argument). `record_outcome`/`record_success`
// remain the LLM-shaped halves, exercised by `tests/failover_tests.rs`, and keep a narrow
// dead-code allow saying so.

use crate::store::LaneRuntime;

// Phase-B B1: the candidate/stage/refusal/admitted/attempt/order/walk_with FAMILY relocated to
// `busbar-substrate`; this glob keeps `crate::failover::X` resolving for every in-core caller. The
// serde config type (`CandidatePoolCfg`) and the LLM-shaped disposition halves (`walk`,
// `record_outcome`, `record_success`) stay here, over `crate::store::LaneRuntime` and
// `crate::breaker`. Glob, so the re-export is never an unused import when a plane consumer is out.
pub use busbar_substrate::failover::*;

/// ONE POOL OF INTERCHANGEABLE UPSTREAMS, as the operator writes it — the ENTIRE config vocabulary
/// this feature adds, and it is CORE's rather than a plane's.
///
/// ```yaml
/// tool_pools:                       # MCP: one server image, deployed twice
///   search:
///     members: [search-eu, search-us]
///     repeatable: [search_code]     # operations safe to perform TWICE. Default: none.
///
/// agent_pools:                      # A2A: one agent, registered twice
///   planner:
///     members: [planner-eu, planner-us]
/// ```
///
/// ## Why it mirrors `pools:` and why it is ONE type for both planes
///
/// The model plane's `pools:` already means *"these members are interchangeable for this request; use
/// whichever is healthy"*. That is the same sentence on all three planes, so an operator learns the
/// concept ONCE — a member list keyed by a pool name, referenced by bare name, never crossing a
/// plane boundary. Two plane-local copies of this struct would be two grammars for one idea and would
/// diverge the first time either grew a key; there is one, in core, and each plane's section merely
/// says which registry the bare names are resolved against.
///
/// ## It is OPT-IN and the default is UNCHANGED
///
/// Owner's steer: *"maybe in a config we dont allow it or maybe we dont suggest it be done."* An
/// absent section is no pools, which is exactly the behaviour of every deployment that exists today:
/// one registration, one destination, no failover, nothing to reason about. Nothing here turns on by
/// itself.
///
/// ## `repeatable:` is a LIST OF OPERATIONS and there is no key that disables the safety rule
///
/// The dangerous half of this feature is repeating a call that already went out, so the declaration
/// is per OPERATION and enumerated by hand. There is deliberately NO `repeatable: all` and no
/// `retry: always`: an operator who wants `send_email` repeated has to write `send_email` down next
/// to the tools they thought about, which is a different act from flipping a switch. See [`Stage`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, not silently un-declare a safety rule.
pub struct CandidatePoolCfg {
    /// The interchangeable registrations, by bare name, resolved against the section's own plane
    /// registry (`tools:` for `tool_pools:`, `agents:` for `agent_pools:`). ORDERED: the first is the
    /// PRIMARY, and its approved fingerprint is the one every other member must match.
    ///
    /// Naming a member is NOT what makes two upstreams interchangeable — busbar checks the pins it
    /// already computed and refuses the pool at dispatch if they disagree. The operator is asserting
    /// *"these names are the same deployment"*, a claim busbar can and does verify.
    #[serde(default)]
    pub members: Vec<String>,
    /// The operations that may be performed TWICE — reads, searches, queries. An operation not named
    /// here is never repeated after a dispatch has gone out.
    ///
    /// EMPTY BY DEFAULT, which is the fail-safe posture: an operator who says nothing gets
    /// reroute-before-first-byte (which duplicates nothing) and no retries at all.
    #[serde(default)]
    pub(crate) repeatable: Vec<String>,
}

impl CandidatePoolCfg {
    /// MAY THIS OPERATION BE PERFORMED TWICE? The one reader of `repeatable:`, so the default can
    /// never be got wrong by a second caller spelling the lookup differently.
    // Read only by the per-call dispatch path a protocol plane drives; a plane whose relay never
    // repeats a dispatch has no caller here. Unconditional allow — the neutral seam names no plane
    // feature.
    #[allow(dead_code)]
    pub fn repeatability(&self, operation: &str) -> Repeatable {
        if self.repeatable.iter().any(|o| o == operation) {
            Repeatable::Yes
        } else {
            Repeatable::No
        }
    }
}

/// THE SEAM'S SPELLING OF [`walk_with`]: the operator's `members:` order, admitted breaker-only.
///
/// The MCP and A2A call sites' entry point. It adds NO selection logic — it names the two things
/// those planes supply ([`InOrder`] and [`LaneRuntime::try_admit_breaker`]) and hands them to the one
/// loop.
// No production caller now: both planes drive [`walk_with`] with the host `breaker_admit` seam
// directly (CLUSTER-1), so the breaker-only spelling survives only for the failover unit tests, which
// drive it under `#[cfg(test)]`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn walk<'a, C: Candidate>(
    store: &dyn LaneRuntime,
    pool: &str,
    members: &'a [C],
    attempt: &Attempt<'_>,
    now: u64,
) -> Result<Admitted<'a, C, Option<u64>>, Refusal> {
    let mut order = InOrder::new(attempt.tried, members.len());
    // These planes render their refusal from `Refusal` itself (which already carries every reason by
    // name), so the positional buffer is local and dropped here.
    let mut passed_over = Vec::new();
    walk_with(
        pool,
        members,
        attempt,
        &mut order,
        &mut passed_over,
        &mut |_position, member| store.try_admit_breaker(pool, member.lane(), now),
    )
}

/// RECORD WHAT THE UPSTREAM DID, through the ONE classifier and onto the ONE breaker cell.
///
/// [`crate::breaker::classify`] is protocol-agnostic already — it consumes a `CanonicalSignal` a
/// per-protocol normalizer produced — so a plane hands its normalized signal here and inherits
/// cause-attributed disposition verbatim: a caller's bad arguments never penalize an upstream, an
/// auth or billing failure is a hard down rather than a slow bleed, and a transient failure is what
/// eventually trips the cell so the NEXT request reroutes before its first byte.
///
/// Returns the [`crate::breaker::Disposition`] taken, so a plane can shape its own answer without
/// re-deciding it.
#[cfg_attr(not(test), allow(dead_code))] // see the module note: the plane call sites record via
                                         // `PlaneBreakers::record_signal` (per-cell hard-down).
pub(crate) fn record_outcome<C: Candidate>(
    store: &dyn LaneRuntime,
    pool: &str,
    candidate: &C,
    signal: &crate::breaker::CanonicalSignal,
    cfg: &crate::store::BreakerCfg,
) -> crate::breaker::Disposition {
    let disposition = crate::breaker::classify(signal);
    let lane = candidate.lane();
    match disposition {
        crate::breaker::Disposition::ClientFault => store.record_client_fault(lane),
        crate::breaker::Disposition::TransientUpstream => {
            // Rate limits carry the upstream's own stated floor, so they go through the arm that
            // honours `Retry-After`; every other transient is the plain transient arm. Same split the
            // model plane makes, because it is a property of the signal and not of the protocol.
            if signal.class == crate::breaker::StatusClass::RateLimit {
                store.record_rate_limit_in(
                    pool,
                    lane,
                    crate::store::now(),
                    cfg,
                    signal.retry_after,
                );
            } else {
                store.record_transient_in(
                    pool,
                    lane,
                    signal.provider_signal.as_deref().unwrap_or("upstream"),
                    cfg,
                    signal.retry_after,
                );
            }
        }
        crate::breaker::Disposition::HardDown => {
            // A hard down is a property of the SHARED upstream, not of one pool fronting it — the
            // same reasoning `record_hard_down_all_cells` carries on the model plane.
            store.record_hard_down_all_cells(
                lane,
                signal.provider_signal.as_deref().unwrap_or("hard_down"),
            );
        }
        // The LANE is healthy and the request was simply wrong for it. Record nothing; the caller
        // fails over WITHOUT penalising anybody.
        crate::breaker::Disposition::ContextLength => {}
    }
    disposition
}

/// The success half of [`record_outcome`], kept separate for the same reason the model plane keeps it
/// separate: a success closes a HalfOpen cell and resets its accumulator, and that is a different
/// write from any failure.
#[cfg_attr(not(test), allow(dead_code))] // twin of `record_outcome`'s allow, same argument.
pub(crate) fn record_success<C: Candidate>(store: &dyn LaneRuntime, pool: &str, candidate: &C) {
    store.record_success_in(pool, candidate.lane());
}

#[cfg(test)]
#[path = "tests/failover_tests.rs"]
mod failover_tests;
