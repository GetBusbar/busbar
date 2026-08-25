// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SERVER-INITIATED ASKS — sampling, elicitation and roots — GATED DENY-BY-DEFAULT.
//!
//! ## What the correction changed, and what it did not
//!
//! These were designed as SERVER-INITIATED REQUESTS, gated at the point busbar accepts them. Under
//! revision `2026-07-28` a server cannot initiate a JSON-RPC request at all, so there is no inbound
//! request to refuse. The ask now arrives as an `InputRequiredResult` inside the RESULT of a call
//! **we** made, and the client decides whether to satisfy it by issuing a fresh request (MRTR,
//! SEP-2322).
//!
//! The REQUIREMENT is unchanged and it is the whole reason this module exists:
//!
//! > An upstream MCP server MUST NOT be able to induce busbar to spend busbar's authority — an LLM
//! > completion on busbar's pools and budget, a user prompt, or disclosure of filesystem roots —
//! > that the operator did not explicitly grant that server.
//!
//! Only the direction of the packet changed. Deny-by-default does not move.
//!
//! ## The three parts of the restated mechanism, each of which is a line of code here
//!
//! 1. **The gate is a refusal to ANSWER, not a refusal to accept.** [`drive`] satisfies an ask only
//!    if the server's registry entry carries the matching grant. Ungranted: the ask is not
//!    satisfied, the call FAILS to the caller with the reason, and the ask is audited.
//!
//! 2. **The grant is re-checked on EVERY retry, because there is no handshake to check it once.**
//!    This is the part that is easy to get wrong, and it is why `grants` is a CLOSURE and not a
//!    value: a value captured before the loop is a grant read once, which is exactly the
//!    handshake-era shape that, under on-demand negotiation, is either a per-request check or no
//!    check at all. The closure re-derives the grant from the LIVE registry snapshot each round, so
//!    a revocation bites on the next retry rather than at the end of a conversation with no end.
//!
//! 3. **The loop is BOUNDED and METERED, and this is NEW.** Removing the handshake turns one call
//!    into a SEQUENCE of calls, and a hostile upstream can return `InputRequiredResult` for ever to
//!    amplify cost — every satisfied sampling retry is a real LLM call against real budget. So there
//!    is a hard cap on rounds per logical dispatch (refused past it, not warned), and every round is
//!    metered before it is spent, not after.
//!
//! ## The risk this revision CREATES, which a request/response gate could not have anticipated
//!
//! busbar is a server as well as a client. When busbar's own caller drives a dispatch to an upstream
//! that answers `InputRequiredResult`, busbar must NOT forward that result to its caller. Doing so
//! launders an upstream's request for authority through the party the caller actually trusts, and
//! asks the caller to satisfy, on the upstream's behalf, an ask busbar itself declined.
//!
//! **The rule: an upstream's `InputRequiredResult` TERMINATES AT BUSBAR.** busbar either satisfies
//! it under a grant, or fails the call with a busbar-attributed error. It is never proxied outward.
//! That is enforced by the TYPE: [`Outcome`] has no arm carrying an [`Ask`], so there is no value
//! this function can return that a caller could serialise back onto the wire. A rule enforced by a
//! missing enum variant cannot be forgotten by a later edit in the way a rule enforced by a comment
//! can.
//!
//! ## THE HALF OF THAT CLAIM THAT WAS NOT TRUE, AND WHAT NOW MAKES IT TRUE
//!
//! The sentence above is worth reading twice, because it was correct and it was not enough, and the
//! gap between those two things was a live confused-deputy hole from the day this module was
//! written until the day it was closed.
//!
//! A type with no arm to carry an ask only binds on values that ARRIVE HERE AS ASKS, and that is
//! decided earlier, by a predicate. `client::jsonrpc::input_required_kind` tested
//! `result.type == "input_required"` and read `result.request` as a string. MRTR has neither field:
//! the discriminator is `resultType` and the asks are a MAP at `inputRequests`. So a conformant
//! upstream's ask failed the predicate, was reported as an ordinary result, arrived here as
//! `Round::Done`, left as `Outcome::Completed`, and was written to busbar's own caller VERBATIM.
//! A registered tool server could ask busbar's caller for its password and busbar would deliver the
//! demand under its own name, with its own authentication on it.
//!
//! Nobody caught it because the only tests that exercised the predicate minted busbar's invented
//! shape: the fixture and the parser agreed with each other, and with no server in existence.
//!
//! There are now THREE mechanisms, and they are independent on purpose:
//!
//! 1. the predicate, rewritten against the specification's shape;
//! 2. this type, unchanged — it was always right;
//! 3. a TERMINAL CHECK in `method.rs`, which reads the ask's FIELDS rather than its discriminator at
//!    the last point before the value becomes bytes, and refuses. It exists because mechanism 1 is a
//!    predicate, predicates drift, and this one drifted for its entire life without a single test
//!    noticing.

/// One ask an upstream returned inside its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ask {
    /// `sampling`, `elicitation` or `roots`. An unrecognised kind is refused by
    /// [`super::config::ServerRequestGrants::allows`], which answers `false` for everything it has
    /// not heard of — so a protocol that grows a fourth ask does not grant it by silence.
    pub(crate) kind: String,
    /// The ask's payload, opaque here. Whatever satisfies it reads this; the GATE never does,
    /// because a gate that inspected the payload would be deciding on attacker-controlled content
    /// rather than on the operator's grant.
    pub(crate) payload: serde_json::Value,
}

/// What one upstream round returned.
// Both arms are constructed in production by `super::upstream::call`, which reads the upstream's
// JSON-RPC answer. They are ALSO driven from a deliberately hostile fake upstream in the tests,
// which is the only way to exercise the refusing arms at all — a cooperative real upstream never
// returns an ask it has no grant for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Round {
    /// A finished result. This is the only thing that ever reaches the caller.
    Done(serde_json::Value),
    /// An ask. Never reaches the caller — see the module header's termination rule.
    InputRequired(Ask),
}

/// How the whole logical dispatch ended.
///
/// There is deliberately NO arm carrying an [`Ask`]. That absence is the termination rule
/// expressed as a type: an upstream's `InputRequiredResult` cannot leave this function, because
/// there is nothing to put it in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The upstream finished. The value is the caller's result.
    Completed(serde_json::Value),
    /// BUSBAR refused, with a busbar-attributed reason. A POLICY decision, always.
    Refused(Refusal),
    /// THE UPSTREAM failed. NOT a refusal, and the separation is the whole point of this arm.
    ///
    /// These are two different facts about two different parties. `Refused` says busbar declined to
    /// carry the call — the operator granted nothing, the round cap bit, the caller's budget said
    /// no — and the remedy is always a configuration or quota change. This arm says busbar carried
    /// the call, the call WENT OUT, and the far end did not produce an answer busbar could serve:
    /// it returned a JSON-RPC error, or it stalled past the deadline, or it answered something that
    /// is not a response to this request.
    ///
    /// They were one arm (`Refusal::UpstreamFailed`) until this commit, and the conflation was
    /// visible in three places at once. The caller was told `-32000` / `403 FORBIDDEN` — busbar's
    /// "I refuse" — for a tool that had merely failed, so a model could neither see the failure nor
    /// retry it. The call log recorded `refused`, whose documented meaning is THE CALL DID NOT GO
    /// OUT, for a call that did. And anything reading dispositions to tell "we are being throttled
    /// by policy" from "our upstream is down" could tell neither, because both wore the same word.
    UpstreamFailed(String),
}

/// Why busbar refused to carry a logical dispatch to completion. Every arm is busbar-attributed:
/// the caller is told busbar declined, never handed the upstream's ask to answer itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The operator granted this server nothing for this kind of ask. THE DEFAULT ANSWER.
    Ungranted { server: String, kind: String },
    /// The hard cap on input-required rounds was reached — refused past it, never merely warned.
    RoundCapExceeded { server: String, cap: u32 },
    /// Busbar held the grant and still could not satisfy the ask (an elicitation with nobody to
    /// ask). Kept distinct from `Ungranted` because the operator's remedy is completely different.
    Unsatisfiable {
        server: String,
        kind: String,
        reason: String,
    },
    /// THE RUNAWAY-LOOP COST CAP. The caller's own per-key budget refused to charge this round, so
    /// the round never happened. Per-key budgets ARE the loop cap — the answer to the $2k/2hr
    /// runaway failure mode — and this is the caller's ordinary budget doing its ordinary job.
    /// There is no MCP-specific budget, which is the point.
    BudgetExhausted {
        server: String,
        round: u32,
        reason: String,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Ungranted { server, kind } => write!(
                f,
                "MCP server `{server}` asked busbar to satisfy a `{kind}` request, and that grant \
                 is not held. Server-initiated asks are deny-by-default: set \
                 `tools.{server}.grants.{kind}: true` if the operator intends this server to spend \
                 busbar's authority that way. The ask was not forwarded to you — an upstream's ask \
                 terminates at busbar."
            ),
            Refusal::RoundCapExceeded { server, cap } => write!(
                f,
                "MCP server `{server}` returned more than {cap} input-required rounds for one \
                 dispatch. The cap is hard: an upstream that can ask indefinitely can amplify cost \
                 indefinitely. Raise `tools.{server}.max_input_required_rounds` only if this \
                 exchange genuinely needs more rounds."
            ),
            Refusal::Unsatisfiable {
                server,
                kind,
                reason,
            } => write!(
                f,
                "busbar holds the `{kind}` grant for MCP server `{server}` but could not satisfy \
                 the ask: {reason}"
            ),
            Refusal::BudgetExhausted {
                server,
                round,
                reason,
            } => write!(
                f,
                "round {round} of this dispatch to MCP server `{server}` was refused by your \
                 budget: {reason}. A tool call is charged on the same budget plane as an LLM \
                 request, so a runaway loop stops when the budget stops it."
            ),
        }
    }
}

impl Refusal {
    /// The stable audit reason word. Named once so a new arm cannot land without one.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            Refusal::Ungranted { .. } => "ask_ungranted",
            Refusal::RoundCapExceeded { .. } => "ask_round_cap",
            Refusal::Unsatisfiable { .. } => "ask_unsatisfiable",
            Refusal::BudgetExhausted { .. } => "budget_exhausted",
        }
    }
}

/// What one round of the loop did, for the meter and the audit trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoundRecord {
    /// 0 for the original call, 1.. for each satisfied ask.
    pub(crate) round: u32,
    /// The ask kind this round satisfied, or `None` for the original call.
    pub(crate) satisfied: Option<String>,
}

/// DRIVE one logical dispatch to completion, bounded, metered, and gated on every round.
///
/// The four closures are the seams, and each one is a closure for a reason:
///
/// - `call` is the upstream leg — in production, `super::upstream::call`, which plans the outbound
///   credential under the INBOUND caller's grant and sends the request. Taking it as a parameter is
///   what lets the gate, the bound and the metering be tested against a deliberately hostile
///   upstream without a network.
/// - `grants` RE-READS the live registry each round. A value would be a grant read once, and under
///   on-demand negotiation a check made once and cached is not a check at all.
/// - `satisfy` performs the granted ask — for `sampling`, a real LLM request on busbar's pools and
///   budget. That is the clause deny-by-default was always paired with: when granted, the ask rides
///   the SAME admission/budget/metering/audit plane as any other LLM request, never a free side
///   channel.
/// - `charge` runs BEFORE each round, and its refusal ENDS the dispatch. That ordering is the
///   runaway-loop cost cap: a round that the budget will not admit is a round that never happens,
///   rather than a round that happens and is billed afterwards. Charging after the fact would let a
///   hostile upstream spend past the cap by exactly the amount of one unbounded loop, which is the
///   entire failure mode.
///
/// `call` and `satisfy` are ASYNC and the other two are not, and that split is the honest one:
/// those are the two steps that can reach past this process. `call` is the upstream network leg
/// always; `satisfy` became I/O the day a granted `sampling` ask stopped being refused — satisfying
/// one is a real LLM dispatch through busbar's own governed pipeline, and pretending that is a
/// synchronous table lookup would only have moved the await somewhere a reader cannot see it. The
/// gate (`grants`) and the meter (`charge`) stay synchronous, so the questions a per-round check
/// must not raise — could the grant read or the charge be awaited past? — still cannot arise.
/// The satisfaction and the ask are passed BY VALUE rather than by reference so each returned
/// future borrows nothing from the loop's own state, which is what keeps both closures plain
/// `FnMut`s rather than something only a boxed, higher-ranked signature could express.
pub(crate) async fn drive<C, F, S, SF>(
    server: &str,
    cap: u32,
    mut call: C,
    grants: impl Fn() -> super::config::ServerRequestGrants,
    mut satisfy: S,
    mut charge: impl FnMut(&RoundRecord) -> Result<(), String>,
) -> Outcome
where
    C: FnMut(u32, Option<serde_json::Value>) -> F,
    F: std::future::Future<Output = Result<Round, String>>,
    S: FnMut(Ask) -> SF,
    SF: std::future::Future<Output = Result<serde_json::Value, String>>,
{
    let mut round: u32 = 0;
    let mut satisfaction: Option<serde_json::Value> = None;
    let mut satisfied_kind: Option<String> = None;
    loop {
        // CHARGE FIRST, and refuse on a refusal. See the `charge` note above: this is the same
        // per-key budget an LLM request is admitted against, and it is what stops a loop that
        // nothing else stops.
        if let Err(reason) = charge(&RoundRecord {
            round,
            satisfied: satisfied_kind.take(),
        }) {
            return Outcome::Refused(Refusal::BudgetExhausted {
                server: server.to_string(),
                round,
                reason,
            });
        }
        let result = match call(round, satisfaction.take()).await {
            Ok(r) => r,
            Err(e) => return Outcome::UpstreamFailed(e),
        };
        let ask = match result {
            Round::Done(value) => return Outcome::Completed(value),
            Round::InputRequired(ask) => ask,
        };

        // THE BOUND, checked against the round we would be about to start. `cap` counts SATISFIED
        // asks, not total calls, so `cap: 0` means "never satisfy one" and reads that way.
        if round >= cap {
            return Outcome::Refused(Refusal::RoundCapExceeded {
                server: server.to_string(),
                cap,
            });
        }

        // THE GATE, re-derived from the live registry on THIS round. Deny-by-default: `allows`
        // answers `false` for an unheld grant and for a kind it does not recognise.
        if !grants().allows(&ask.kind) {
            return Outcome::Refused(Refusal::Ungranted {
                server: server.to_string(),
                kind: ask.kind,
            });
        }

        // The kind survives the move: the ask itself is consumed by the satisfier's future (see
        // the by-value note above), and both the refusal and the next round's meter record need to
        // name what was being satisfied.
        let kind = ask.kind.clone();
        match satisfy(ask).await {
            Ok(value) => {
                satisfaction = Some(value);
                satisfied_kind = Some(kind);
                round += 1;
            }
            Err(reason) => {
                return Outcome::Refused(Refusal::Unsatisfiable {
                    server: server.to_string(),
                    kind,
                    reason,
                })
            }
        }
    }
}

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/inputreq_tests.rs"]
mod inputreq_tests;
