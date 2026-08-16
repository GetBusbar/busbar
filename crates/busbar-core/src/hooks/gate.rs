// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUEST GATE, FIRED FROM ANY PROTOCOL — one function, one projection, one verdict, for a
//! request the shared pipeline knows only through [`crate::ir::facts::IrFacts`].
//!
//! # Why this exists, and why it is not in `proxy/`
//!
//! Hooks were a MODEL-PLANE feature by accident of where they were wired, not by design. Every
//! firing site lived in `proxy/engine`, every projection was built by walking a chat body, and the
//! consequence was written down in five places as though it were a law of the protocol: "hooks do
//! not run on tool calls". It was never a law. It was unfinished wiring — the config grammar for
//! attaching a hook to an MCP server (`tools.hooks:`, `tools.<server>.hooks:`) and to an A2A agent
//! (`agents.hooks:`, `agents.<agent>.hooks:`) already parsed, already validated, already refused a
//! cross-plane reference, and then did nothing, because nothing fired it.
//!
//! A hook is a policy decision about ONE REQUEST. The owner's ruling is the whole design: *"it's 1
//! request object 1 response. llm mcp or agent dont matter."* So the seam takes what every protocol
//! can produce — an `IrFacts` — and knows nothing else. There is no protocol name in a condition
//! here, no plane enum, no `if this is MCP`. The protocol appears exactly twice: as the
//! `ingress_protocol` LABEL a hook is told (data, never a branch) and as the `container` name, and
//! both are supplied by the caller's own arm.
//!
//! # What a hook is sent
//!
//! The SAME [`RoutingRequest`] wire the model plane sends, built from the IR rather than from a
//! body: `pool` is the container the request is addressed to (a pool, an MCP server, an A2A agent),
//! `ingress_protocol` names the dialect, the shape signals come from [`IrFacts::shape`], and — behind
//! the hook's own `prompt:` grant — `messages` carries the content projection, one entry per
//! [`crate::ir::facts::ContentItem`], each rendered by `screenable_text`. A hook therefore screens a
//! tool call's arguments through exactly the field it already screens a prompt through, and a gate
//! written for the model plane works here with no change.
//!
//! **`candidates` is EMPTY, and that is a fact rather than a gap.** These protocols route to one
//! registered upstream chosen by the caller's own grant, not to a ranked set — so there is nothing
//! to rank, and the two verbs that speak about a candidate set (`order`, `restrict`) have nothing to
//! act on. They are IGNORED here, loudly at `debug`, rather than silently: a hook that tries to
//! reorder something that has no order has been told the wrong thing about the request, and the
//! honest answer is that the verb does not apply, not a synthesised candidate list.
//!
//! # The verdict
//!
//! `reject` is the verb that matters, and it is the one this seam exists to deliver: a gate stops
//! the request before anything is dispatched. Gates fire IN PRIORITY ORDER and the FIRST rejection
//! wins — sequentially, and deliberately so, unlike the model plane's concurrent phase-2 reconcile:
//! there is no candidate set for the reconcile to intersect, so concurrency would buy latency on a
//! path where the common answer is "no gates at all" and would spend a deadline on gates whose
//! verdict is already irrelevant. A short-circuit on the first reject is both cheaper and the same
//! answer.
//!
//! A gate that FAILS (errors, times out, panics across the ABI) does not proceed by default: its own
//! `on_error` decides, exactly as on the model plane. `reject` there means a gate an operator
//! declared load-bearing cannot be skipped by being broken.

use crate::hooks::subject::{project, RequestSubject};
use crate::hooks::{Candidate, ResolvedPolicy, RoutingContext, RoutingDecision};

/// The answer a firing site acts on. Deliberately NOT the model plane's `PolicyOutcome`: that type
/// carries `Order`/`Restrict`/`Weighted`, three answers about a candidate set, and a caller here
/// would have to know they cannot happen. A two-armed verdict cannot be misread.
pub(crate) enum GateVerdict {
    /// No gate objected (or none is attached). The request proceeds.
    Proceed,
    /// A gate refused the request. `status` is CLAMPED to the 4xx band and `message` is the hook's
    /// own, already sanitized by the engine's fail-closed reply normalizer — a hook cannot mint a
    /// 5xx, a success, or a header-injecting message through this path.
    Reject {
        status: u16,
        message: String,
        /// The transport/policy name, for the audit row and the log line: "it was refused" is not
        /// an operator-actionable fact unless it says by WHAT.
        hook: &'static str,
    },
}

/// FIRE the gates attached to this container, in priority order, and return the first verdict that
/// stops the request.
///
/// ZERO COST when nothing is attached: an empty slice returns before any projection is built, which
/// is the same shape (and the same guarantee) as the model plane's `global_gates.is_empty()`
/// early-out.
pub(crate) async fn decide(
    gates: &[(u16, ResolvedPolicy)],
    subject: &RequestSubject<'_>,
) -> GateVerdict {
    if gates.is_empty() {
        return GateVerdict::Proceed;
    }
    // The content items are materialised ONCE and borrowed by every gate's projection: the walk is
    // over the IR and cannot differ between gates, and re-walking per gate would be the same answer
    // computed N times.
    let items = subject.facts.content();
    for (
        _,
        ResolvedPolicy::Policy {
            policy,
            on_error,
            timeout,
            send_prompt,
            send_user,
            ..
        },
    ) in gates
    {
        let req = project(subject, &items, *send_prompt, *send_user);
        let ctx = RoutingContext {
            pool: subject.container,
            // No pool-scoped budget signal on these planes: the budget a request here spends is the
            // caller key's, and it is metered by the plane's own admission. A field that carried a
            // number derived from something else would be worse than an absent one.
            budget_remaining: None,
            budget: &[],
        };
        // The candidate set is EMPTY — see the module header for why that is the truth about these
        // protocols rather than a projection that has not been built yet.
        const NO_CANDIDATES: &[Candidate<'static>] = &[];
        let decision = match tokio::time::timeout(
            *timeout,
            policy.decide(&req, NO_CANDIDATES, &ctx, *timeout),
        )
        .await
        {
            Ok(Ok(d)) => d,
            // The gate could not answer. Its OWN `on_error` decides, and `reject` is the arm an
            // operator picks when the gate is load-bearing: a broken security gate must not become
            // an open one.
            Ok(Err(e)) => {
                tracing::warn!(
                    hook = policy.name(),
                    container = subject.container,
                    protocol = subject.ingress_protocol,
                    error = %e,
                    "request gate failed; applying its on_error"
                );
                if let Some(v) = fail_closed(on_error, policy.name()) {
                    return v;
                }
                continue;
            }
            Err(_) => {
                tracing::warn!(
                    hook = policy.name(),
                    container = subject.container,
                    protocol = subject.ingress_protocol,
                    timeout_ms = timeout.as_millis() as u64,
                    "request gate deadline exceeded; applying its on_error"
                );
                if let Some(v) = fail_closed(on_error, policy.name()) {
                    return v;
                }
                continue;
            }
        };
        match decision {
            RoutingDecision::Reject { status, message } => {
                return GateVerdict::Reject {
                    // RE-CLAMPED at the seam that acts on it, not merely at the seam that parsed
                    // it — the same belt-and-braces the model plane's forward site applies, so no
                    // policy implementation, shipped or future, can mint a 5xx or a success here.
                    status: status.clamp(400, 499),
                    message,
                    hook: policy.name(),
                };
            }
            // The two candidate-set verbs. Nothing to act on, and saying so at `debug` is what
            // stops an operator concluding their compliance restrict is in force here.
            RoutingDecision::Prefer(_) | RoutingDecision::Restrict { .. } => {
                tracing::debug!(
                    hook = policy.name(),
                    container = subject.container,
                    protocol = subject.ingress_protocol,
                    "request gate answered with a candidate-set verb on a protocol that routes to \
                     one registered upstream; ignored (only `reject` applies here)"
                );
            }
            RoutingDecision::Abstain => {}
        }
    }
    GateVerdict::Proceed
}

/// A failed gate's terminal, as a verdict. `Some` only for `reject` — the two ranking terminals
/// (`weighted`, `first`) are statements about which candidate to pick, and with no candidates they
/// mean exactly "this gate has no verdict", which is a proceed.
fn fail_closed(on_error: &crate::config::PolicyOnError, hook: &'static str) -> Option<GateVerdict> {
    match on_error {
        crate::config::PolicyOnError::Reject => Some(GateVerdict::Reject {
            status: 403,
            message: "A required gate could not complete, so this request was refused.".to_string(),
            hook,
        }),
        crate::config::PolicyOnError::Weighted | crate::config::PolicyOnError::First => None,
    }
}

#[cfg(test)]
#[path = "tests/gate_tests.rs"]
mod gate_tests;
