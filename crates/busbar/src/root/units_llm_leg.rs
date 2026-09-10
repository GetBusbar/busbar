// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the two legs beside it carry the same line:
// a leg is the SERVING path, and it names items that exist only under this feature. Declared in
// `root/mod.rs` under `root-llm` instead, so a plane-gated module is not named from code under a
// different feature.
#![cfg(feature = "root-llm-serve")]

//! THE LLM PLANE'S LEG: one arrival off a mounted surface, walked through the door the driven path
//! already walks.
//!
//! ## What this leg is, in one sentence
//!
//! It resolves two things off the arrival that only this plane can resolve — WHICH DIALECT sent
//! these bytes, and WHICH OPERATION they name — builds the arrival this plane's walk takes, and
//! hands the walk both halves of what it produced. Everything else about serving one request is
//! already written: the ten steps, the two audit doors, the in-flight table, the exit arm's
//! settlement and the late accrual on the body all belong to [`LlmNode`] and are not repeated here.
//!
//! ## Why it drives the NODE's door and not the mount's kernel
//!
//! The two legs mounted before this one take the mount's kernel, hold cell, leases, gauge and canary
//! and run the ten steps against them. This one does not, and the difference is not an oversight.
//!
//! This plane's walk ALREADY EXISTS ON THE DRIVEN PATH. `LlmNode` owns an in-flight table that
//! bounds how many units this node has open, one gauge, one canary, one admission door, one pinned
//! rate card and one book, and the switched-over ingress tables serve real traffic through them
//! today. A mounted leg that ran the same protocol against a SECOND set of those would give this
//! node two in-flight tables, two canaries and two sets of counters for one plane — and which one a
//! request was counted on would depend on whether the operator had composed a mount. That is a
//! difference in the money and in the admission bound, arrived at silently.
//!
//! So the leg walks [`LlmNode::walk`], which is the door [`LlmNode::answer`] is: the same seats, the
//! same one arrival reading, the same table, the same exit arm. `answer` is that call with the
//! ending dropped. The paired cell in this plane's mount asserts the consequence rather than the
//! intention — one request each way, one journal head, one link on the chain.
//!
//! The mount's `kernel`, `ctx` and `run` are therefore unread, and so is the dispatch seam: this
//! plane's Route step dials its own destination and there is no surface underneath to ask. A leg
//! that reached for the seam anyway would be asking the mounted router to answer a request the
//! engine has already answered.
//!
//! ## Where the arrival's three ingress values come from
//!
//! [`crate::root::mount_ingress`], sealed at mount time. A mount answers in front of the catch-all
//! that resolves them, so they cannot be read off the request the way the driven path reads them —
//! and the alternative, a process-wide static, is refused there for reasons that are about two
//! deployments in one process.

use std::sync::Arc;

use busbar_llm::unit::walk::WalkArrival;

use crate::root::mount_ingress::ArrivalSource;
// The payload the substrate declares, under the ONE spelling this plane's root module already
// carries: the leg reads a sealed context by downcasting to it, as the driven path's readers do.
use crate::root::plane_mount;
use crate::root::units_llm::ArrivalPayload;
use crate::root::units_llm::LlmNode;

/// THE LLM PLANE'S LEG, assembled once.
///
/// Two fields, and both are things a request cannot supply for itself: the node whose door every
/// unit of this plane goes through, and the deployment's ingress source. There is deliberately no
/// third — every other input this plane's walk needs is either on the arrival or already inside the
/// node.
pub struct LlmLeg {
    /// The node this plane's units are walked by. OWNED by the leg rather than borrowed from a
    /// static, for the reason the ingress source is a value: a process with two of these in it is
    /// two deployments, and they must not share a table, a canary or a book.
    node: LlmNode,
    /// What the composition root resolved, asked per arrival. See [`ArrivalSource`].
    ingress: Arc<dyn ArrivalSource>,
}

impl std::fmt::Debug for LlmLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LlmLeg")
    }
}

/// What this plane made of one arrival, before any of it reaches the loop.
///
/// The two answers only this plane can give, resolved TOGETHER because they are one question with
/// two halves: a path whose dialect is known but whose operation is not is not a unit this plane
/// has, and neither is the reverse. Resolving them apart would let the recognition question answer
/// yes where the walk would then have nothing to run.
struct Named {
    /// Which dialect sent these bytes, by the plane's own ladder.
    dialect: &'static str,
    /// Which operation they name, by that dialect's own endpoint resolution.
    operation: busbar_api::operation::Operation,
}

impl LlmLeg {
    /// Assemble the leg over one node and one ingress source.
    ///
    /// No `MissingSource` refusal, and the absence is deliberate rather than an omission: the two
    /// legs beside this one refuse boot field by field because they assemble a dozen boot-resolved
    /// bindings, any of which could be absent on a real deployment and every one of which would
    /// serve traffic looking healthy if it were. This leg assembles NEITHER of those things — the
    /// node's own bindings are the driven path's and were resolved when the node was built, and the
    /// ingress source is one value the caller either has or cannot call this at all.
    #[must_use]
    pub fn assemble(node: LlmNode, ingress: Arc<dyn ArrivalSource>) -> Self {
        LlmLeg { node, ingress }
    }

    /// The node this leg walks, for a caller that has to bind the same book to it.
    #[must_use]
    pub fn node(&self) -> &LlmNode {
        &self.node
    }

    /// **WHAT THIS PLANE MAKES OF ONE ARRIVAL** — the dialect, and the operation.
    ///
    /// ONE resolution, reached by both the recognition question and the walk, for the reason the
    /// mount composes one arrival for both: two would be two chances for the loop to be handed a
    /// request the recognition never saw.
    ///
    /// The dialect is [`busbar_plane_llm::claims::dialect_for`] — the plane's own fourteen-rung
    /// ladder, walked in rung order, over the path and the headers. It is not re-derived here and
    /// there is no list of dialects in this file: the ladder is the declaration, and a rung added to
    /// it is a rung this leg reads for free.
    ///
    /// The HEADERS it walks are the ones the mount published as facts of its own transport, read
    /// back through [`plane_mount::header_of`] so the prefix is spelled in one place. That is the
    /// whole reason the mount publishes them: four of this plane's fourteen rungs name a vendor
    /// header, and a leg that could not see one could be mounted, could be claimed, and could not
    /// tell one dialect from another.
    ///
    /// The OPERATION is the dialect's own `resolve_operation` over its own endpoint — the same call
    /// the driven body-model arrival makes, at the same place in the order, so a path this dialect
    /// names no operation for is not a request at all. On the driven path that answer is a
    /// path-shaped 404 from the surface; here it is the mount's second question answering "not a
    /// unit of this plane", and the request goes to the surface underneath that already answers it.
    fn named(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> Option<Named> {
        let target = path_of(arrival);
        let dialect = busbar_plane_llm::claims::dialect_for(target, &|name| {
            plane_mount::header_of(arrival, name)
        })?;
        let operation = busbar_substrate::handlers::request_handler(dialect)
            .and_then(|rh| rh.resolve_operation(target, arrival.body))?;
        Some(Named { dialect, operation })
    }

    /// Whether these bytes are a unit THIS PLANE has.
    #[must_use]
    pub fn recognises(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool {
        self.named(arrival).is_some()
    }

    /// **WALK ONE MOUNTED ARRIVAL, and hand back the ending AND the plane's own response.**
    ///
    /// The response is the walk's, UNTOUCHED — not rebuilt, not buffered, not re-framed. That is
    /// load-bearing on this plane in a way it is not on the two mounted before it: a streamed answer
    /// here is a body that has not finished, and the cell that fills when it drains rides on the
    /// response as an extension. A leg that read the bytes to hand back three fields would drain the
    /// stream into memory, drop the extension, and with it the money that lands after the terminal.
    ///
    /// The ending is the kernel's own, settled from a lend at the node's exit arm and still carrying
    /// its posting. Never [`busbar_kernel::teller::Ended::AlreadySettled`] on the path where a unit
    /// ran: that would tell the mount the kernel settled this unit at its own exit, which is the one
    /// thing that did not happen.
    pub async fn serve(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
    ) -> (
        busbar_kernel::teller::Ended,
        crate::root::transports::MountedReply,
    ) {
        let Some(named) = self.named(arrival) else {
            // UNREACHABLE THROUGH A MOUNT, because the mount asks `recognises` first and both
            // questions are this one function. It is an answer rather than an unwrap because a path
            // that cannot be taken still has to say something if it is — and the ending it says is
            // `AlreadySettled`, which here is the TRUE statement and not a stand-in: no hold was
            // opened, no unit ran, and there is no posting for anything to settle. The answer beside
            // it is present, so nothing downstream opens the ending at all.
            //
            // The answer is the transport's own "cannot take this", not a dialect's error envelope,
            // for the reason there is nothing to answer: no dialect was named, so there is no native
            // shape to render one in, and picking a dialect to be wrong in would be worse than being
            // plain.
            return (
                busbar_kernel::teller::Ended::AlreadySettled,
                plane_mount::http_response(crate::root::transports::unavailable_answer()),
            );
        };
        let sealed = self
            .ingress
            .arrival(arrival.fact(busbar_contract::transport::facts::CREDENTIAL));
        // The sealed context is read the way the driven path's own readers read theirs: by
        // downcasting to the payload the substrate declares. A context carrying anything else is a
        // wiring bug rather than a runtime input, and it is answered rather than unwrapped — with
        // the transport's own "cannot take this", for the reason the unnamed-dialect arm above
        // gives: no unit ran and there is nothing to settle.
        let Some(payload) = sealed.downcast_ref::<ArrivalPayload>() else {
            return (
                busbar_kernel::teller::Ended::AlreadySettled,
                plane_mount::http_response(crate::root::transports::unavailable_answer()),
            );
        };
        let walk_arrival = WalkArrival {
            host: Arc::clone(&payload.host),
            gov: busbar_api::PlaneRequestCtx {
                key: payload.gov.key.clone(),
            },
            proto: named.dialect,
            operation: named.operation,
            caller_token: payload.caller_token.clone(),
            // THE WHOLE MAP THE CALLER SENT, read back off the facts the mount published. This
            // plane's walk forwards a request's headers to a destination, so a curated subset here
            // would be a request the node made up.
            headers: plane_mount::headers_of(arrival),
            body: axum::body::Bytes::copy_from_slice(arrival.body),
            // A BODY-MODEL ARRIVAL. The two dialects that keep their model in the URL parse their own
            // URL space before the loop, in their own crate, and that parse is not reached from here
            // — a mounted arrival of one of those two is walked as the body-model shape its own
            // `BODY_INGRESS` entry already is. See this file's module note in the mount beside it.
            path: None,
        };
        self.node.walk(walk_arrival, None).await
    }
}

/// The request target one arrival names, without its query.
///
/// The mount publishes the path AND QUERY under the reserved key, because that is what the request
/// line carried and a fact that dropped half of it would be a fact about a request nobody sent. The
/// ladder matches on the PATH — a suffix rung against `/v1/chat/completions?stream=true` would not
/// match, and a contained-literal rung could be made to match by a query string a caller chose,
/// which is a routing decision handed to the client.
///
/// So the query is cut here, at the one place that asks the ladder a question, and the fact stays
/// whole for everything else that reads it.
fn path_of<'a>(arrival: &'a busbar_contract::transport::Arrival<'a>) -> &'a str {
    let target = arrival
        .fact(busbar_contract::transport::facts::PATH)
        .unwrap_or_default();
    target.split_once('?').map_or(target, |(path, _)| path)
}

#[cfg(test)]
#[path = "tests/units_llm_leg.rs"]
mod tests;
