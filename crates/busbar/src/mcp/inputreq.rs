// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SERVER-INITIATED ASKS — sampling, elicitation and roots — gated deny-by-default, per §3.10 AS
//! CORRECTED BY §14.3.
//!
//! ## What the correction changed, and what it did not
//!
//! §3.10 designed these as SERVER-INITIATED REQUESTS gated at the point busbar accepts them. Under
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
//!    handshake-era shape §14.4 says is "either a per-request check or nothing at all". The closure
//!    re-derives the grant from the LIVE registry snapshot each round, so a revocation bites on the
//!    next retry rather than at the end of a conversation that has no end.
//!
//! 3. **The loop is BOUNDED and METERED, and this is NEW.** Removing the handshake turns one call
//!    into a SEQUENCE of calls, and a hostile upstream can return `InputRequiredResult` for ever to
//!    amplify cost — every satisfied sampling retry is a real LLM call against real budget. So there
//!    is a hard cap on rounds per logical dispatch (refused past it, not warned), and every round is
//!    metered before it is spent, not after.
//!
//! ## The risk this revision CREATES, which §3.10 could not have anticipated
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
// `Done` and `InputRequired` have no production CONSTRUCTOR in this build, because the only thing
// that could construct one is the upstream reader, and the client direction is not built. The gate,
// the bound and the metering they feed are all real and all tested against a deliberately hostile
// fake upstream — which is the only way to test a gate against an adversary anyway, since a
// cooperative real upstream never exercises the refusing arms.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Round {
    /// A finished result. This is the only thing that ever reaches the caller.
    Done(serde_json::Value),
    /// An ask. Never reaches the caller — see the module header's termination rule.
    InputRequired(Ask),
}

/// How the whole logical dispatch ended.
///
/// There is deliberately NO arm carrying an [`Ask`]. That absence is the §14.3 termination rule
/// expressed as a type: an upstream's `InputRequiredResult` cannot leave this function, because
/// there is nothing to put it in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The upstream finished. The value is the caller's result.
    Completed(serde_json::Value),
    /// busbar refused, with a busbar-attributed reason.
    Refused(Refusal),
}

/// Why busbar refused to carry a logical dispatch to completion. Every arm is busbar-attributed:
/// the caller is told busbar declined, never handed the upstream's ask to answer itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The operator granted this server nothing for this kind of ask. THE DEFAULT ANSWER.
    Ungranted { server: String, kind: String },
    /// The hard cap on input-required rounds was reached. §14.3 part 3: refused past it, not warned.
    RoundCapExceeded { server: String, cap: u32 },
    /// Busbar held the grant and still could not satisfy the ask (an elicitation with nobody to
    /// ask). Kept distinct from `Ungranted` because the operator's remedy is completely different.
    Unsatisfiable {
        server: String,
        kind: String,
        reason: String,
    },
    /// THE RUNAWAY-LOOP COST CAP (§2.2). The caller's own per-key budget refused to charge this
    /// round, so the round never happened. This is the mechanism §1.2 names for the $2k/2hr failure
    /// mode, and it is the caller's ordinary budget doing its ordinary job — there is no
    /// MCP-specific budget, which is the point.
    BudgetExhausted {
        server: String,
        round: u32,
        reason: String,
    },
    /// The upstream leg itself failed.
    UpstreamFailed(String),
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
            Refusal::UpstreamFailed(reason) => {
                write!(f, "the MCP upstream call failed: {reason}")
            }
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
            Refusal::UpstreamFailed(_) => "upstream_failed",
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
/// - `call` is the upstream leg. Taking it as a parameter is what lets the gate, the bound and the
///   metering be tested against a deliberately hostile upstream without a network.
/// - `grants` RE-READS the live registry each round (§14.3 part 2). A value would be a grant read
///   once, which §14.4 says is not a check at all.
/// - `satisfy` performs the granted ask — for `sampling`, a real LLM request on busbar's pools and
///   budget, which is the surviving clause of §3.10: when granted, it rides the SAME
///   admission/budget/metering/audit plane as any other LLM request, never a free side channel.
/// - `charge` runs BEFORE each round, and its refusal ENDS the dispatch. That ordering is the
///   runaway-loop cost cap: a round that the budget will not admit is a round that never happens,
///   rather than a round that happens and is billed afterwards. Charging after the fact would let a
///   hostile upstream spend past the cap by exactly the amount of one unbounded loop, which is the
///   entire failure mode.
pub(crate) fn drive(
    server: &str,
    cap: u32,
    mut call: impl FnMut(u32, Option<&serde_json::Value>) -> Result<Round, String>,
    grants: impl Fn() -> super::config::ServerRequestGrants,
    mut satisfy: impl FnMut(&Ask) -> Result<serde_json::Value, String>,
    mut charge: impl FnMut(&RoundRecord) -> Result<(), String>,
) -> Outcome {
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
        let result = match call(round, satisfaction.as_ref()) {
            Ok(r) => r,
            Err(e) => return Outcome::Refused(Refusal::UpstreamFailed(e)),
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

        match satisfy(&ask) {
            Ok(value) => {
                satisfaction = Some(value);
                satisfied_kind = Some(ask.kind);
                round += 1;
            }
            Err(reason) => {
                return Outcome::Refused(Refusal::Unsatisfiable {
                    server: server.to_string(),
                    kind: ask.kind,
                    reason,
                })
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/inputreq_tests.rs"]
mod inputreq_tests;
