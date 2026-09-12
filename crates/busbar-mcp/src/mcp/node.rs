// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SEAM THE COMPOSITION SERVES A CLASS THROUGH** — and the table of which classes it has
//! taken.
//!
//! ## What changed, and what did not
//!
//! Every one of this protocol's thirteen client classes used to be answered by an arm of
//! [`method::dispatch`]'s `match`: the arm read the catalogue (or the task store, or the upstream)
//! and returned a document. No door was asked, no budget was drawn, no audit row was sealed and no
//! meter moved, because a `match` arm is not a serving path — it is a function call.
//!
//! A class in [`served`]'s table no longer has an arm. It is walked through the composition root's
//! node instead: arrival over the claim the transport named, decode against the plane's own method
//! table, authenticate, verify, approve, admit at the node's door, route over the legs the plane's
//! own plan names, meter, and both audit doors. The BYTES are unchanged and are produced by the
//! same function that produced them before — that is what makes the move provable — and the node
//! invokes it on the one arm where the loop settled.
//!
//! ## Why the byte source is a table here rather than an argument there
//!
//! Because it is temporary. Each of these documents is a byte source that the plan's own lines move
//! plane-side (the catalogue projections, the answer framing, the task-store reads), and when a
//! document leaves this crate its row leaves this table. One table that shrinks is readable; a
//! closure threaded from each of thirteen call sites is thirteen places to get the pairing wrong.
//!
//! ## The one production implementor, and the one double
//!
//! [`install`] is called by the composition root at boot, with the root's own MCP node. Nothing else
//! may call it and nothing else can: a plane crate cannot name the root. This crate's own batteries
//! install an ADMIT-EVERYTHING double, because what they judge is the BYTES a class puts on the wire
//! — which is this crate's half — while what the node adds is the STEPS, which are the root's and
//! are judged by the root's cells and by the end-to-end battery against the real binary. A double
//! that decided anything would be this crate marking its own governance homework.
//!
//! [`method::dispatch`]: super::method::dispatch

use std::sync::OnceLock;

use axum::response::Response;
use busbar_plane_mcp::ops;

/// What the composition already knew about one arriving request, as the seam hands it over.
///
/// Every field is a fact the transport or the neutral ingress reader established before this class
/// was named. The node reads them and asks the plane's own table what the method means; nothing
/// here is a judgement.
pub struct ClassRequest<'a> {
    /// The method name, exactly as the neutral ingress reader read it off the envelope.
    pub method: &'a str,
    /// The whole request document's length, in the bytes it arrived as — never a re-serialisation of
    /// the parsed value, which is a different number and would price a different request.
    pub request_bytes: u64,
    /// The caller's resolved key, or `None` on a deployment with no data-plane chain.
    pub key: Option<&'a busbar_api::VirtualKey>,
    /// The claim that matched, which is how this plane names a transport.
    pub claim_transport: &'static str,
    /// The composed stack the request arrived over, bottom layer first. Its TOP is the claim's
    /// transport, which is the pairing the arrival step checks.
    pub chain: &'static [&'static str],
    /// Whether the principal is a bound session's rather than these bytes'.
    pub from_session: bool,
}

/// **THE COMPOSED STACK THE DOCUMENT SURFACE STANDS ON**, bottom layer first.
///
/// It ends at the claim's own transport, and that is not decoration: `units_mcp::arrival` refuses an
/// arrival record whose chain does not END at the claim that matched, and it reads the top rather
/// than membership precisely because the streamed surface stands on the document one — a chain read
/// by membership would let a stream be matched as a request.
pub const DOCUMENT_CHAIN: &[&str] = &["tcp", "tls", busbar_plane_mcp::claims::TRANSPORT_HTTP];

/// **THE COMPOSED STACK A PIPE STANDS ON**, which is one layer.
///
/// There is no TCP under a pipe and no TLS over it, so a chain that reported either would be a
/// transport describing a connection it does not have.
pub const PIPE_CHAIN: &[&str] = &[busbar_plane_mcp::claims::TRANSPORT_STDIO];

/// **THE TRANSPORT'S OWN HALF of a [`ClassRequest`]**, supplied by each transport at its dispatch.
///
/// Separate from the request because the other half — who is asking, what the method is — is the
/// envelope's and is read once, in one place. This is the part only the carrier can know: which
/// claim it is, what the composed stack under it is, and how many bytes actually arrived.
///
/// There are two constructors and no literal one, because a carrier is a CLAIM and its stack
/// together: a caller free to pair `stdio` with the document chain could hand the arrival step a
/// record from one surface under another surface's claim, and the unit would be refused at step zero
/// for a reason no operator could read.
#[derive(Debug, Clone, Copy)]
pub struct Carrier {
    claim_transport: &'static str,
    chain: &'static [&'static str],
    request_bytes: u64,
}

impl Carrier {
    /// The DOCUMENT surface's carrier — one HTTP request in, one response out.
    #[must_use]
    pub fn document(request_bytes: u64) -> Self {
        Carrier {
            claim_transport: busbar_plane_mcp::claims::TRANSPORT_HTTP,
            chain: DOCUMENT_CHAIN,
            request_bytes,
        }
    }

    /// The PIPE surface's carrier — this process's own stdin and stdout.
    #[must_use]
    pub fn pipe(request_bytes: u64) -> Self {
        Carrier {
            claim_transport: busbar_plane_mcp::claims::TRANSPORT_STDIO,
            chain: PIPE_CHAIN,
            request_bytes,
        }
    }

    /// The claim this carrier's requests arrive under.
    #[must_use]
    pub fn claim_transport(&self) -> &'static str {
        self.claim_transport
    }

    /// The composed stack, bottom layer first, ending at the claim's transport.
    #[must_use]
    pub fn chain(&self) -> &'static [&'static str] {
        self.chain
    }

    /// The length of the frame as it arrived.
    #[must_use]
    pub fn request_bytes(&self) -> u64 {
        self.request_bytes
    }
}

/// Why the node did not serve a class it took.
///
/// The loop's own refusal, in the contract's spelling, or the absence of an answer at all. Both are
/// rendered by this crate, because how a refusal reads on this wire is this protocol's statement and
/// not the root's.
#[derive(Debug)]
pub enum Denied {
    /// The loop stopped the unit at a step.
    Refused(busbar_contract::unit::Refusal<'static>),
    /// The unit ended without an answer and without a refusal.
    Unavailable,
}

/// **THE COMPOSITION'S SERVING PATH**, as this plane reaches it.
///
/// One method, and the shape is the whole of the contract between the two crates: the node is handed
/// what arrived and the document the class already had, it walks the unit, and it invokes the
/// document on the one arm where the loop settled. The node never sees the bytes it returns and this
/// crate never sees the steps it passed.
pub trait ServingNode: Send + Sync {
    /// Walk one class through the loop and answer with `answer`'s document where it settled.
    ///
    /// # Errors
    ///
    /// The loop refused the unit at a step, or the unit ended without an answer.
    fn serve(
        &self,
        request: &ClassRequest<'_>,
        answer: &dyn Fn() -> Response,
    ) -> Result<Response, Denied>;
}

/// The node the composition root installed, if it has.
static NODE: OnceLock<&'static dyn ServingNode> = OnceLock::new();

/// **INSTALL THE COMPOSITION'S NODE.** Called once, at boot, by the composition root and by nothing
/// else.
///
/// A second call is ignored rather than a panic: two nodes is two doors and two books, and the first
/// one is the one every request before the second call was already served through — so the honest
/// answer is to keep it and let the boot that tried twice be the bug it is.
pub fn install(node: &'static dyn ServingNode) {
    let _ = NODE.set(node);
}

/// Whether a node is bound — for a caller reporting what it is running under.
#[must_use]
pub fn installed() -> bool {
    NODE.get().is_some()
}

/// **THE CLASSES THE NODE HAS TAKEN, and the document each of them answers with.**
///
/// One row per class served through the composition. A class with no row here still has its arm in
/// [`method::dispatch`](super::method::dispatch) and is answered the way it always was; a class with
/// a row here has NO arm, and this is where its document is named.
///
/// `tools/list` is the first, and it is first because it is money-free: it reaches two of this
/// plane's own records and no upstream, so nothing is priced, nothing is dialled and no grant is
/// spent. `resources/list` is the second and `prompts/list` the third on the same measurement —
/// one record walk each, no upstream. The order the rest follow is the plan's (§14.3), money-free
/// first and `tools/call` last.
fn document_for(op: busbar_contract::ids::OpClassId) -> Option<super::method::ClassDocument> {
    if op == ops::OP_TOOLS_LIST {
        return Some(super::method::tools_list_document);
    }
    if op == ops::OP_RESOURCES_LIST {
        return Some(super::method::resources_list_document);
    }
    if op == ops::OP_PROMPTS_LIST {
        return Some(super::method::prompts_list_document);
    }
    None
}

/// Serve one class through the composition, where the node has taken it.
///
/// `None` is "this class is not served here", which is every class with an arm still in the dispatch
/// table — so the dispatcher runs after this and is unchanged for them.
///
/// A class the node HAS taken, on a build with no node installed, answers `None` as well, and that
/// is deliberate rather than a fallback: the dispatch arm is gone, so the method reads as
/// unimplemented and says so loudly. Answering it here would be a second serving path beside the
/// node — the exact thing moving the class was for. Every build that carries this plane carries the
/// node (`plane-mcp` enables `root-mcp`), so the only way to reach it is a test binary that has not
/// installed its double.
pub(in crate::mcp) fn served(
    ctx: &super::method::Ctx<'_>,
    method: &str,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Option<Response> {
    let row = ops::row_for(method)?;
    let document = document_for(row.op)?;
    let node = NODE.get()?;
    let carrier = ctx.carrier;
    let request = ClassRequest {
        method,
        request_bytes: carrier.request_bytes,
        key: ctx.gov.key(),
        claim_transport: carrier.claim_transport,
        chain: carrier.chain,
        // Every claim of this plane presents its credential once and carries no second round, so a
        // unit on a session-bound carrier is one whose principal was resolved at the session's open
        // and a unit on the document carrier is one whose credential arrived with these bytes. The
        // carrier is what says which, because the claim is what declares it.
        from_session: busbar_plane_mcp::claims::is_stdio(carrier.claim_transport),
    };
    Some(
        match node.serve(&request, &|| document(ctx, params, id.clone())) {
            Ok(answer) => answer,
            // THE LOOP'S REFUSAL, on this wire. The step and the reason are the loop's; the code,
            // the status and the sentence are this protocol's, which is why the rendering is here.
            Err(Denied::Refused(refusal)) => refused(id, &refusal),
            Err(Denied::Unavailable) => super::envelope::error_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                id,
                busbar_mcp_codec::codec::CODE_INTERNAL,
                "this request opened a unit that ended without an answer. Nothing was charged.",
                None,
            ),
        },
    )
}

/// **A REFUSAL THE LOOP RAISED, on this wire.**
///
/// The STEP is what decides the status, and it decides it because the step is the only thing about a
/// refusal a caller is owed: which gate said no. The reason is deliberately NOT rendered — a reason
/// names a cap, a lane or a rate, and a refusal that told a caller about the deployment's money is
/// exactly the leak the unpriced refusal's own documentation forbids. What goes out is the gate and
/// the fact that nothing was charged.
///
/// `-32000` for all of them: the codec publishes one code for "busbar refused this", and a code per
/// step would be this plane inventing a vocabulary the schema does not carry.
fn refused(
    id: Option<serde_json::Value>,
    refusal: &busbar_contract::unit::Refusal<'_>,
) -> Response {
    use busbar_contract::unit::Step;
    let (status, sentence) = match refusal.step {
        // A body this plane does not carry. The same class of answer the envelope's own `_meta`
        // checks give, because it is the same class of defect.
        Step::Arrival | Step::Decode => (
            axum::http::StatusCode::BAD_REQUEST,
            "this request could not be read as a call on this server.",
        ),
        // No admitted identity. `401` is the door's answer on every transport of this plane.
        Step::Authenticate => (
            axum::http::StatusCode::UNAUTHORIZED,
            "this request carries no credential this server admits.",
        ),
        // An identity that is not permitted what it asked for. Two steps, one answer: whether the
        // destination was refused or the grant was short, the caller may not do this.
        Step::Verify | Step::Approve => (
            axum::http::StatusCode::FORBIDDEN,
            "this credential is not permitted the operation it named.",
        ),
        // The door. `429` and never `402`: what the door says is "not now", and the caller's own
        // retry is the remedy.
        Step::Admit => (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "this request was not admitted. Nothing was charged.",
        ),
        // Everything past the door. The unit ran and stopped, and the caller is owed the fact
        // rather than the internals.
        Step::Route | Step::Meter | Step::Audit | Step::Encode => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "this request was admitted and could not be completed.",
        ),
    };
    super::envelope::error_response(
        status,
        id,
        busbar_mcp_codec::codec::CODE_REFUSED,
        sentence,
        None,
    )
}

/// **THE ADMIT-EVERYTHING DOUBLE** this crate's own batteries are served through.
///
/// Behind `test-support`, which is exactly the feature that puts an engine in the closure for this
/// crate's App-building batteries — so the double exists precisely when there are batteries that
/// need one, and never in a shipped binary.
///
/// It runs the document and nothing else, which is the division of labour the seam exists for: what
/// this crate owns is the BYTES a class puts on the wire, and those are unchanged by the move —
/// that is the whole claim. What the real node adds is the STEPS, and a double that pretended to
/// make step decisions would be this crate marking its own governance homework.
///
/// It is deliberately not configurable. A double with a "refuse" mode would invite a battery here to
/// assert a refusal this crate does not decide; the refusal RENDERING, which this crate does own, is
/// asserted off a refusal value with no node at all.
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod double {
    /// The double itself: every class admitted, every document run.
    struct AdmitEverything;

    impl super::ServingNode for AdmitEverything {
        fn serve(
            &self,
            _request: &super::ClassRequest<'_>,
            answer: &dyn Fn() -> axum::response::Response,
        ) -> Result<axum::response::Response, super::Denied> {
            Ok(answer())
        }
    }

    /// Install it for this test binary. Idempotent, and called from the one place this crate's
    /// batteries build an App.
    pub(crate) fn install_test_node() {
        static DOUBLE: AdmitEverything = AdmitEverything;
        super::install(&DOUBLE);
    }
}

#[cfg(test)]
#[path = "tests/node_tests.rs"]
mod tests;
