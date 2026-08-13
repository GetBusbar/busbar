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
//! **What core owns:** what a candidate SET is, the ORDER candidates are walked in, the
//! interchangeability CHECK, the retry-safety RULE, the admission (through the one breaker), and the
//! refusal it produces. **What a plane owns:** what a CANDIDATE is ([`Candidate`]) and what makes two
//! of them interchangeable (the pin it hands back from
//! [`Candidate::interchange_key`]). [`crate::egress_auth::gate`] is the precedent this copies rather
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

// NOT MOUNTED ON A DISPATCH PATH YET, deliberately named rather than omitted — the same posture
// `egress_auth/gate.rs` landed under and for the same reason. This unit lands the SEAM, its config
// vocabulary and its proofs; the two call sites that will consume it (`mcp/client/dispatch.rs` and
// `a2a/relay.rs`) are being edited by other units this cycle, and a dispatch-path edit landed blind
// alongside them is a merge conflict wearing a feature's clothes. The seam is here first because the
// VOCABULARY is the part the owner's ruling is about, and a plane that arrives later must find one
// selection loop rather than invent a second. Exercised end-to-end by `tests/failover_tests.rs`.
#![cfg_attr(not(test), allow(dead_code))]

use crate::audit::vocab;
use crate::store::{LaneRuntime, Unavailable};

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
pub(crate) struct CandidatePoolCfg {
    /// The interchangeable registrations, by bare name, resolved against the section's own plane
    /// registry (`tools:` for `tool_pools:`, `agents:` for `agent_pools:`). ORDERED: the first is the
    /// PRIMARY, and its approved fingerprint is the one every other member must match.
    ///
    /// Naming a member is NOT what makes two upstreams interchangeable — busbar checks the pins it
    /// already computed and refuses the pool at dispatch if they disagree. The operator is asserting
    /// *"these names are the same deployment"*, a claim busbar can and does verify.
    #[serde(default)]
    pub(crate) members: Vec<String>,
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
    pub(crate) fn repeatability(&self, operation: &str) -> Repeatable {
        if self.repeatable.iter().any(|o| o == operation) {
            Repeatable::Yes
        } else {
            Repeatable::No
        }
    }
}

/// ONE CANDIDATE: somewhere a request can be sent, on any plane.
///
/// Implementing this is the ENTIRE cost of teaching a plane to fail over. The selection order, the
/// interchangeability check, the retry-safety rule, the breaker admission and the disposition are all
/// inherited from this module, and the circuit breaker itself is
/// [`LaneRuntime::try_admit_breaker`] — the same one the model plane has always used, called from
/// [`walk`] and from nowhere else on these planes.
pub(crate) trait Candidate {
    /// The operator-facing name of this candidate, for refusals and audit rows. A plane spells its own
    /// (`"search-eu"`, `"planner@eu"`); core never parses it.
    fn name(&self) -> &str;

    /// The BREAKER LANE this candidate occupies. The breaker is keyed by `(pool, lane)` and always
    /// has been; a plane candidate is a lane like any other, which is exactly why no second breaker is
    /// needed and none is written.
    fn lane(&self) -> usize;

    /// THE PIN — what makes two candidates interchangeable, as a value busbar ALREADY COMPUTED.
    ///
    /// On the MCP plane this is the approved schema digest of the tool being called on this server;
    /// on the A2A plane it is the approved canonical card fingerprint. It is deliberately NOT an
    /// operator-written equivalence label: a label asserts, a digest CHECKS.
    ///
    /// `None` means NOTHING IS APPROVED YET, which is not a wildcard — it is the one answer that can
    /// never match another candidate, so a pending registration can never be failed over TO or FROM.
    fn interchange_key(&self) -> Option<&str>;
}

/// HAS ANYTHING BEEN SENT YET? The whole safety rule turns on this one distinction — see the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Nothing has left busbar for this request. Moving to an equivalent candidate is a REROUTE and
    /// duplicates nothing.
    BeforeFirstByte,
    /// A previous candidate was dispatched to and the call failed. Moving on is a RETRY of work an
    /// upstream may already have done.
    AfterDispatch,
}

/// MAY THIS OPERATION BE PERFORMED TWICE? A property of the operation the caller named, declared by
/// the operator who vouched for it — never inferred, and never a property of the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Repeatable {
    /// The DEFAULT for everything an operator has not spoken about. A second execution may have a
    /// second effect, so an [`Stage::AfterDispatch`] hop is refused.
    No,
    /// The operator declared this operation safe to perform twice (a read, a search, a query).
    Yes,
}

/// WHY NO FURTHER CANDIDATE MAY BE SELECTED.
///
/// Core's refusal. Every variant carries the pool and enough to name a repair, and every one maps to
/// a token in [`crate::audit::vocab`] via [`Refusal::reason`] — the shared vocabulary, because a
/// refusal spelled one way for MCP and another for A2A is a refusal an auditor cannot read across.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The pool names no candidate at all. An operator error, caught at the seam rather than
    /// presented as an outage.
    Empty { pool: String },
    /// A failover hop's pin does not agree with the primary's, so busbar cannot show the two are the
    /// same deployment. `other_key` is `None` when the candidate has nothing approved yet.
    NotInterchangeable {
        pool: String,
        primary: String,
        primary_key: Option<String>,
        other: String,
        other_key: Option<String>,
    },
    /// THE SAFETY RULE. The call already went out and the operation is not declared repeatable, so it
    /// is not sent a second time.
    NotRepeatable { pool: String, operation: String },
    /// Every interchangeable candidate refused admission. Carries WHY for each, in the shared
    /// [`Unavailable`] taxonomy, so an operator gets the real reasons rather than "unavailable".
    NoneAdmissible {
        pool: String,
        tried: Vec<(String, Unavailable)>,
    },
}

impl Refusal {
    /// The AUDIT WORD for this refusal, from [`crate::audit::vocab`]. Core decides; a plane renders.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            // An empty pool and an all-open pool are both "there is nowhere left to send this",
            // which is one incident with one operator question ("what is up with that pool?").
            Refusal::Empty { .. } | Refusal::NoneAdmissible { .. } => {
                vocab::REASON_NO_UPSTREAM_LEFT
            }
            Refusal::NotInterchangeable { .. } => vocab::REASON_NOT_INTERCHANGEABLE,
            Refusal::NotRepeatable { .. } => vocab::REASON_NOT_REPEATABLE,
        }
    }

    /// The refused pool, for the audit `resource`. Every refusal names one.
    pub(crate) fn pool(&self) -> &str {
        match self {
            Refusal::Empty { pool }
            | Refusal::NotInterchangeable { pool, .. }
            | Refusal::NotRepeatable { pool, .. }
            | Refusal::NoneAdmissible { pool, .. } => pool,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Empty { pool } => write!(
                f,
                "pool `{pool}` names no candidate, so there is nowhere to send this request"
            ),
            Refusal::NotInterchangeable {
                pool,
                primary,
                primary_key,
                other,
                other_key,
            } => write!(
                f,
                "`{other}` is not interchangeable with `{primary}` in pool `{pool}`: their approved \
                 fingerprints differ ({} vs {}), so busbar cannot show they are the same \
                 deployment and will not move a request between them",
                primary_key.as_deref().unwrap_or("<nothing approved>"),
                other_key.as_deref().unwrap_or("<nothing approved>"),
            ),
            Refusal::NotRepeatable { pool, operation } => write!(
                f,
                "`{operation}` already went out and is not declared repeatable, so it is NOT sent \
                 again to another member of pool `{pool}`: a second dispatch of an operation with \
                 effects is a second effect"
            ),
            Refusal::NoneAdmissible { pool, tried } => {
                write!(f, "every candidate in pool `{pool}` refused admission:")?;
                for (name, why) in tried {
                    write!(f, " `{name}` ({why:?});")?;
                }
                Ok(())
            }
        }
    }
}

/// A CANDIDATE THAT MAY BE DISPATCHED TO, and the probe it now owns.
///
/// Only [`walk`] can build one, so a dispatch that skipped the breaker does not compile. `probe_epoch`
/// is the owner token [`LaneRuntime::try_admit_breaker`] handed back — the caller releases it
/// OWNER-CHECKED via `release_probe_owned_in` after recording an outcome, exactly the discipline the
/// model plane's queue dispatch uses.
pub(crate) struct Admitted<'a, C> {
    candidate: &'a C,
    position: usize,
    probe_epoch: u64,
}

/// HAND-WRITTEN so the bound lands on [`Candidate`] and NOT on `Debug`. A derive would make every
/// plane's candidate type `Debug` or lose `expect`/`unwrap` on the result — which is a second thing a
/// third plane has to write, and the acceptance test for this seam is that there is no second thing.
/// It prints the plane's own [`Candidate::name`], which is all an operator wants from it anyway.
impl<C: Candidate> std::fmt::Debug for Admitted<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("candidate", &self.candidate.name())
            .field("position", &self.position)
            .field("probe_epoch", &self.probe_epoch)
            .finish()
    }
}

impl<'a, C: Candidate> Admitted<'a, C> {
    /// The candidate this request may be sent to.
    pub(crate) fn candidate(&self) -> &'a C {
        self.candidate
    }
    /// Its position in the pool. `0` is the primary; anything else means a reroute happened.
    pub(crate) fn position(&self) -> usize {
        self.position
    }
    /// The single-flight probe owner token, for the owner-checked release after the outcome is
    /// recorded.
    pub(crate) fn probe_epoch(&self) -> u64 {
        self.probe_epoch
    }
}

/// WHAT THIS REQUEST HAS ALREADY DONE, and what it is allowed to do next.
///
/// The four facts [`walk`] needs about the REQUEST, as opposed to the pool — bundled because they
/// travel together and are meaningless apart: `stage` and `repeatable` are only ever read against
/// each other, and both are only ever consulted because `tried` is non-empty. A caller building one
/// of these has the whole safety question in front of it in one place, rather than four positional
/// arguments it can transpose.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Attempt<'r> {
    /// Positions in the pool this request has ALREADY been dispatched to (or has already refused).
    /// `walk` never mutates it: a caller records the position it dispatched to and calls again.
    /// EMPTY means this is the request's first selection, which is never a repeat of anything.
    pub(crate) tried: &'r [usize],
    /// Whether anything has left busbar for this request yet. See [`Stage`].
    pub(crate) stage: Stage,
    /// Whether THIS operation may be performed twice, as declared by the operator in the pool's
    /// `repeatable:` list. See [`CandidatePoolCfg::repeatability`].
    pub(crate) repeatable: Repeatable,
    /// The operation being attempted, for the refusal. Named rather than derived so the message an
    /// operator reads says `send_email` and not "a tool call".
    pub(crate) operation: &'r str,
}

/// THE WALK: pick the next candidate in `members` that this request may be sent to, and admit it
/// through THE circuit breaker.
///
/// There is exactly ONE selection loop for these planes and this is it.
///
/// The order of the checks is the contract, because the first failure is what the operator is told:
///
/// 1. **Is there anything here at all?** An empty pool is an operator error, not an outage.
/// 2. **Is this a repeat?** [`Stage::AfterDispatch`] + [`Repeatable::No`] stops here, BEFORE any
///    breaker is consulted, so a non-repeatable call cannot even peek at a second deployment. Asked
///    early on purpose: it is a statement about the REQUEST, and no upstream's health can change it.
/// 3. **Do the pins agree?** Every hop after the primary must present the primary's exact
///    `interchange_key`. Checked before admission so a mismatched candidate is never given a probe.
/// 4. **Will the breaker have it?** [`LaneRuntime::try_admit_breaker`] — the same call the model
///    plane's queue dispatch makes, against the same `(pool, lane)` cell — walked in order until one
///    admits.
pub(crate) fn walk<'a, C: Candidate>(
    store: &dyn LaneRuntime,
    pool: &str,
    members: &'a [C],
    attempt: &Attempt<'_>,
    now: u64,
) -> Result<Admitted<'a, C>, Refusal> {
    // 1. Nothing to select from.
    let Some(primary) = members.first() else {
        return Err(Refusal::Empty {
            pool: pool.to_string(),
        });
    };

    // 2. THE SAFETY RULE, asked before any upstream is consulted. `tried` being empty means this is
    //    the request's FIRST selection, which is never a repeat whatever the stage says.
    if !attempt.tried.is_empty()
        && attempt.stage == Stage::AfterDispatch
        && attempt.repeatable == Repeatable::No
    {
        return Err(Refusal::NotRepeatable {
            pool: pool.to_string(),
            operation: attempt.operation.to_string(),
        });
    }

    let mut refused: Vec<(String, Unavailable)> = Vec::new();
    for (position, member) in members.iter().enumerate() {
        if attempt.tried.contains(&position) {
            continue;
        }
        // 3. THE PIN CHECK. The primary defines the pool's identity; every other member has to prove
        //    it is the same deployment. `None` never matches — not even another `None`, because two
        //    registrations that have each approved nothing are two unknowns, not one fact.
        if position != 0 {
            let ok = match (primary.interchange_key(), member.interchange_key()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            if !ok {
                return Err(Refusal::NotInterchangeable {
                    pool: pool.to_string(),
                    primary: primary.name().to_string(),
                    primary_key: primary.interchange_key().map(str::to_string),
                    other: member.name().to_string(),
                    other_key: member.interchange_key().map(str::to_string),
                });
            }
        }
        // 4. THE ONE BREAKER. Not a second admission path, not a copy of one: this is
        //    `LaneRuntime::try_admit_breaker`, the same method `proxy::engine::walk` calls on the
        //    model plane, against the same per-(pool, lane) cell.
        match store.try_admit_breaker(pool, member.lane(), now) {
            Ok(probe_epoch) => {
                return Ok(Admitted {
                    candidate: member,
                    position,
                    probe_epoch,
                })
            }
            Err(why) => refused.push((member.name().to_string(), why)),
        }
    }

    Err(Refusal::NoneAdmissible {
        pool: pool.to_string(),
        tried: refused,
    })
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
pub(crate) fn record_success<C: Candidate>(store: &dyn LaneRuntime, pool: &str, candidate: &C) {
    store.record_success_in(pool, candidate.lane());
}

#[cfg(test)]
#[path = "tests/failover_tests.rs"]
mod failover_tests;
