// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// COMPILED WHERE SOME PLANE HAS A MOUNT, and not otherwise. It names `tower` and `axum` and the
// per-arrival dispatch seam, none of which a build with no mounted plane carries.
#![cfg(any(
    feature = "root-a2a-serve",
    feature = "root-mcp-serve",
    feature = "root-llm-serve"
))]

//! ONE MOUNT, FOR EVERY PLANE THAT HAS ONE: one HTTP surface, one loop, one answer.
//!
//! ## Why this file exists rather than one per plane
//!
//! It was written for the A2A plane, because that was the first plane whose leg had a surface to
//! reach. Then the MCP leg needed the same thing, and the same thing turned out to be *everything*:
//! the claim walk is over the closed grammar's own selector shapes, the body cap is the operator's,
//! the fact publication is the kernel's reserved keys, the request/answer channel is a property of a
//! synchronous loop meeting an asynchronous router, and the refusal path's rule — a unit refused
//! before Route executes nothing — is the administrative mount's rule and every mount's rule.
//!
//! Not one line of it was about A2A. So rather than a second copy under a second name, the body
//! moved here and the two planes' mounts became what they always were: a claim table, a leg, and a
//! media type. Two files with the same six hundred lines are two things that can drift, and the
//! first thing to drift between them would have been a difference nobody meant.
//!
//! ## What a mount is and what it is not
//!
//! The router that goes in is the one that already answers the protocol — the legacy plugin's, with
//! its own route specifications. The router that comes out answers the same addresses THROUGH THE
//! KERNEL'S LOOP. The seam between them is [`crate::root::transports::MountDispatch`], so the inner
//! router remains the only thing that knows what any of these operations do, and the bytes a caller
//! reads are the ones that surface wrote.
//!
//! It chooses the PATH and never the bytes. That is the whole sentence, and every decision in this
//! file follows from it.
//!
//! ## What is claimed, and why the plane decides rather than a list here
//!
//! A path list in this file would be a second declaration of where a protocol lives, and the one
//! that drifts is the one nobody re-derived. So the claim is asked TWICE, of two things that already
//! know:
//!
//! 1. **The plane's own claim table** says which addresses the protocol occupies. It is walked
//!    generically — an exact path, a segment pattern or a stream name, matched by the grammar's own
//!    shapes — so this file names no route of any protocol and a plane gains one for free when it
//!    declares one.
//! 2. **The plane's own decode** says whether these particular bytes are a unit it has. A body it
//!    does not recognise is not a unit of that plane, and it goes straight to the surface that
//!    already answers it — with the 404, the 405, the `-32601` or the document that release pinned.
//!
//! That second question is what keeps a GET of a discovery document, or a REST route a plane
//! declares and does not name an operation for, byte-for-byte what it was: the loop takes the units
//! it can name and hands back everything else untouched.
//!
//! ## The refusal path executes nothing
//!
//! A unit refused at Verify, Approve or Admit never reaches the seam, so there is no answer to carry
//! out and this file renders the loop's own refusal instead of sending the request back down to be
//! refused a second time. That rule is the administrative mount's and it is the same rule here, for
//! the same reason: a status check afterwards discards an answer, it cannot discard an execution
//! that already happened.
//!
//! The bytes of that refusal are the PLANE's. It has an encoder for exactly this — the one the
//! generic driver already uses — so a caller refused by the loop reads its own protocol's error
//! document, carrying its own request identifier, rather than a sentence this file made up.

use std::sync::Arc;

use busbar_contract::grammar::{Claim, PathSeg, Selector};

use crate::root::transports::{unavailable_answer, MountDispatch, MountedReply, PlaneAnswer};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT A MOUNT NEEDS OF A LEG
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE FOUR THINGS A MOUNT ASKS ITS PLANE, and nothing else.
///
/// One trait rather than one mount per plane, and the four methods are the whole of what a mount
/// cannot answer for itself: which addresses this protocol occupies, whether these particular bytes
/// are a unit it has, what the loop makes of them, and what its refusal document looks like. Every
/// other decision in this file is the mount's own and is identical for every plane, which is exactly
/// why there is one file.
///
/// A leg that wanted to tell the mount anything more would have to widen this, and the widening is
/// the review.
pub trait MountedLeg: Send + Sync + 'static {
    /// The claims this plane declares, walked by [`claims_a_path`] and never restated here.
    fn claims(&self) -> &'static [Claim];

    /// The plane's DECLARED SURFACE, where this protocol has one.
    ///
    /// A second declaration of the same protocol's addresses, and it is asked as well as the claim
    /// table because the two answer different questions: the claim table is what the kernel routes
    /// on, the surface is what a transport serves with. An address either of them names is an
    /// address this protocol owns, so a mount that asked only one would hand away every address the
    /// other had that it did not — silently, with a route answering around the loop while the plane
    /// still said it owned it.
    ///
    /// `None` for a plane that declares no wire surface, which is an honest absence rather than a
    /// default: a protocol whose addresses live only in its claim table is completely described by
    /// the claim table, and inventing a surface for it here would be this file declaring a plane's
    /// addresses on the plane's behalf.
    fn surface(&self) -> Option<&'static busbar_contract::transport::surface::WireSurface> {
        None
    }

    /// Whether these bytes are a unit THIS PLANE has, asked of the plane's own decode.
    fn recognises(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool;

    /// Walk one arrival through the kernel's steps WITH the mount's seam, and hand back both halves.
    ///
    /// **A FUTURE, AND THE PLANE'S OWN RESPONSE.** Two changes with one cause. The mount used to run
    /// this on a blocking worker and take back three fields, which decided two things on every
    /// plane's behalf that are not the mount's to decide: that the walk blocks, and that the answer
    /// is bytes. A plane whose walk is genuinely asynchronous had nowhere to be one, and a plane
    /// whose answer is a run of events had it flattened.
    ///
    /// So the leg says what it is. A synchronous leg wraps its own walk in [`sync_leg`] and steps off
    /// the reactor itself — which is where that decision belongs, because whether a walk blocks is a
    /// property of the walk. An asynchronous one simply awaits. Either way what comes back is the
    /// plane's own [`MountedReply`], and this file does not look inside it.
    fn serve<'a>(
        &'a self,
        arrival: &'a busbar_contract::transport::Arrival<'a>,
        kernel: &'a busbar_kernel::teller::Kernel,
        ctx: &'a busbar_kernel::teller::UnitCtx,
        run: busbar_kernel::teller::Run<'a>,
        dispatch: Option<&'a dyn MountDispatch>,
    ) -> Walked<'a>;

    /// The plane's own refusal document for one ending, where the plane has one.
    fn render_refusal(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        ended: &busbar_kernel::teller::Ended,
    ) -> Option<Vec<u8>>;

    /// The media type this protocol's document answers carry.
    ///
    /// The frame a refusal goes out on is the MOUNT's half and the document inside it is the
    /// PLANE's, so the type has to come from the plane rather than be assumed here — even though
    /// both protocols mounted today answer with the same one.
    fn media_type(&self) -> &'static str;
}

/// ONE LEG'S WALK, AS A FUTURE THE MOUNT AWAITS.
///
/// Boxed because the trait is used as `dyn MountedLeg` — the whole point of the trait is that the
/// mount holds one leg without knowing which plane's it is, and a leg that returned an opaque future
/// type could not be a trait object. The lifetime is one lifetime for every borrow the walk is given,
/// which is what lets the arrival, the kernel and the run live on the mount's own stack frame rather
/// than being cloned into the future.
pub type Walked<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (busbar_kernel::teller::Ended, Option<MountedReply>)>
            + Send
            + 'a,
    >,
>;

/// RUN ONE SYNCHRONOUS WALK OFF THE REACTOR.
///
/// ## Why a leg calls this and the mount does not
///
/// The mount used to put every walk on a blocking worker, which is the right thing to do to a
/// synchronous walk and the wrong thing to assume about all of them. Whether a walk blocks is a
/// property of the WALK: the two legs mounted today step through the kernel's teller synchronously
/// and must not hold a reactor thread while they do it, and a leg that is genuinely asynchronous
/// would have been shipped to a blocking pool to await there for no reason. So the decision moved to
/// the only place that knows the answer, and this is the generic way to spell it — no plane's name
/// appears in it, and a leg opts in by calling it.
///
/// ## Why `block_in_place` and not `spawn_blocking`
///
/// `spawn_blocking` needs `'static`, and a walk borrows: the arrival, the kernel, the run's four
/// counters and the seam are all on the mount's stack. Meeting that with `spawn_blocking` would mean
/// cloning or `Arc`-ing every one of them into the closure — a per-request allocation to satisfy a
/// lifetime rather than a need. `block_in_place` tells the runtime this worker is about to block so
/// it hands the rest of its queue to another, which is the same outcome for everything else on the
/// reactor and costs the borrow nothing.
///
/// **On a single-threaded runtime the walk runs inline**, because `block_in_place` panics there and
/// there is no second worker to hand anything to. The hazard is named rather than hidden: a mount
/// composed on a current-thread runtime serialises its walks against the task that drives the
/// mounted router, so it is a shape for a probe and not for a node. Every mount in this tree — the
/// binary's and every cell that composes one — is on the multi-threaded runtime.
pub fn sync_leg<T>(walk: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::CurrentThread) | Err(_) => walk(),
        Ok(_) => tokio::task::block_in_place(walk),
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT A MOUNT CLAIMS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Whether one path is an address these claims CLAIM.
///
/// The claim table is the PLANE'S and is walked rather than restated. Matched by the grammar's own
/// shapes and nothing else — an exact path is an equality, a pattern is a segment-by-segment walk
/// with one variable segment per `Var`. There is no prefix arm, and its absence is the point:
/// `/mcpx` is somebody else's path, and a `starts_with` would take it.
///
/// **EVERY claim is walked, and the transport each one names is not read.** It would be easy to keep
/// only the ones made over the document carrier, and it would be this file — the axis-agnostic side
/// of the seam — asking the transport axis its identity, which is the thing the whole arrangement
/// exists to prevent. It would also be unnecessary: a claim whose selector is not a path matches no
/// path, and a claim whose selector IS a path is one this listener genuinely carries, because the
/// mounted router below serves it.
///
/// **A TRAILING SLASH IS THE SAME ADDRESS.** `/mcp` and `/mcp/` are one address to every router in
/// this tree and to every client of either protocol, and a mount that took the first and handed the
/// second straight through would run one of them past the loop and the other around it — the same
/// request, gated or not depending on a character. So the path is normalised ONCE, here, by dropping
/// a single trailing slash from a path that is not itself the root. It is not a prefix match: `/mcpx`
/// still belongs to somebody else, and `/mcp/x` is still a different address that only matches if a
/// claim's own pattern says so.
#[must_use]
pub fn claims_a_path(claims: &[Claim], path: &str) -> bool {
    let normalised = normalise(path);
    claims
        .iter()
        .any(|claim| selector_matches(&claim.selector, normalised))
}

/// One path with a single trailing slash dropped, unless the path IS the root.
///
/// `/` stays `/`, because the empty string is not an address.
#[must_use]
pub fn normalise(path: &str) -> &str {
    match path.strip_suffix('/') {
        Some("") | None => path,
        Some(trimmed) => trimmed,
    }
}

/// Whether one selector of the closed grammar matches one path.
///
/// **EVERY PATH-SHAPED FORM, and not the two that happened to be declared first.** The grammar
/// already says which forms read the request target — [`busbar_contract::grammar::SelectorFamily`]
/// puts five of them in the `Path` family — and this walk used to read two of them and answer "not a
/// path" for the other three. That is not a conservative default: a plane that declares its surface
/// as a suffix or a contained literal was mounted and never reached, because every one of its
/// addresses fell to the "does not claim this" arm and went straight to the router underneath. The
/// mount was on and did nothing, and nothing failed to say so.
///
/// So the five are walked, and the arm that answers "no" is written over the forms that genuinely
/// are not addresses — a header, a handshake, a stream, a port. It is spelled as arms rather than a
/// wildcard so a form the grammar gains has to be CONSIDERED here rather than silently answering no,
/// which is exactly the failure above.
///
/// The trailing-slash normalisation is the same one for all five, applied to the declaration as well
/// as to the request, for the reason stated on [`normalise`].
fn selector_matches(selector: &Selector, path: &str) -> bool {
    match selector {
        Selector::ExactPath(exact) => normalise(exact) == path,
        Selector::PathPattern(pattern) => pattern_matches(pattern, path),
        // A prefix ONE SEGMENT DEEP: the declared prefix and at least one non-empty segment after
        // it. Not a string prefix — `/v1x` is somebody else's address and always was.
        Selector::PrefixOneLevel(prefix) => normalise(prefix)
            .strip_suffix('/')
            .or(Some(normalise(prefix)))
            .and_then(|p| path.strip_prefix(p))
            .is_some_and(|rest| rest.strip_prefix('/').is_some_and(|s| !s.is_empty())),
        // A SUFFIX IS AN ADDRESS ENDING, and it ends at a segment boundary: `/v1/embeddings` claims
        // `/openai/v1/embeddings`, which is the same surface behind a deployment prefix, and does
        // not claim `/xv1/embeddings`, which is a different one.
        Selector::PathSuffix(suffix) => {
            let suffix = normalise(suffix);
            path == suffix
                || (suffix.starts_with('/') && path.ends_with(suffix))
                || (!suffix.starts_with('/')
                    && path.ends_with(suffix)
                    && path.len() > suffix.len()
                    && path.as_bytes()[path.len() - suffix.len() - 1] == b'/')
        }
        // AND A CONTAINED LITERAL IS THE DECLARATION AS WRITTEN. The plane said "a path with this in
        // it", so that is what is asked — over the normalised path, so a trailing slash cannot be
        // the difference between claimed and not.
        Selector::PathContains(literal) => path.contains(normalise(literal)),
        // The forms that read something other than the request target: a header, the handshake, a
        // stream name, a local port. None of them is an address, so no path matches one — and a
        // plane that declares one is not thereby unreachable, because a mount walks its WHOLE table
        // and any one claim matching is enough.
        Selector::HeaderExact(..)
        | Selector::HeaderPresent(_)
        | Selector::HeaderPrefix(..)
        | Selector::Sni(_)
        | Selector::ClientCertSubject(_)
        | Selector::Alpn(_)
        | Selector::StreamName(_)
        | Selector::Port(_) => false,
    }
}

/// One segment pattern against one path.
///
/// The path is split on `/` with the leading empty segment dropped, which is the same reading the
/// declaration's own patterns are written against: `PathSeg::Lit("a2a")` is the first segment of
/// `/a2a/agents/x`, not the second.
///
/// A `Var` matches exactly one NON-EMPTY segment. Empty would let `/a2a/agents/` name an agent whose
/// identifier is the empty string, which is an address no router below serves.
///
/// A `Tail` matches every remaining segment and there must be at least one, for the same reason:
/// "every remaining segment" of nothing is not a match, it is the pattern's prefix with the tail
/// absent, and the two are different addresses.
fn pattern_matches(pattern: &[PathSeg], path: &str) -> bool {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let mut got = segments.iter();
    for seg in pattern {
        match seg {
            PathSeg::Lit(lit) => match got.next() {
                Some(actual) if lit == actual => {}
                _ => return false,
            },
            PathSeg::Var => match got.next() {
                Some(actual) if !actual.is_empty() => {}
                _ => return false,
            },
            // The tail swallows the rest, so the pattern is satisfied exactly when there IS a rest.
            PathSeg::Tail => return got.next().is_some_and(|s| !s.is_empty()),
        }
    }
    // Every pattern segment was consumed, so the path matches exactly when nothing is left over: a
    // pattern is an address and not a prefix of one.
    got.next().is_none()
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   ONE ANSWER, ON THE WIRE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// One answer as the response this listener writes.
///
/// The status and the headers reach the wire HERE, which is why the seam carries all three: a frame
/// carries bytes and nothing else, so a mount that read only the frame would serve every operation of
/// a protocol under one status with no headers at all. Written once because two paths reach it —
/// the unit that ran and the one this wrap refused before the loop was entered — and a second builder
/// would be a second chance for the two to differ.
pub(crate) fn http_response(answer: PlaneAnswer) -> MountedReply {
    let mut response = axum::http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        response = response.header(name.as_str(), value.as_str());
    }
    response
        .body(axum::body::Body::from(answer.body))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .expect("an empty 500 always builds")
        })
}

/// What a node that cannot take the unit at all answers with.
///
/// No document, because there is no plane answer to render: the loop produced no ending of its own,
/// so anything in the body would be this file's prose about a unit it did not decide.
fn unavailable_response() -> MountedReply {
    http_response(unavailable_answer())
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE SEAM'S PRODUCTION HALF
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// One operation, handed across the boundary between the loop and the runtime.
///
/// The request goes one way and the answer comes back the other, on a channel the caller owns, so the
/// asynchronous side never has to know which of several outstanding calls it is answering.
///
/// **TWO ERRANDS AND ONE DOOR.** Executing an operation and reading a body to its end are both
/// things a synchronous loop cannot do for itself, for the same reason and with the same remedy: the
/// runtime is on the other side. A plane that wants its answer buffered is asking the same channel
/// for a second favour, not reaching for a second mechanism — so the channel carries a sum of the
/// two rather than only the first, and a plane that never buffers never sends the second.
pub(crate) enum Errand {
    /// One request handed to the mounted router, and the response that router wrote.
    ///
    /// BOXED, because a request carries a method, a target, a header map and a body while the other
    /// errand carries a body alone: unboxed, every buffering errand would be moved through the
    /// channel in a slot sized for the larger one.
    Call(
        Box<axum::http::Request<axum::body::Body>>,
        std::sync::mpsc::SyncSender<MountedReply>,
    ),
    /// One body read to its end on the runtime that owns it.
    Collect(
        axum::body::Body,
        std::sync::mpsc::SyncSender<Option<Vec<u8>>>,
    ),
}

/// The dispatch that hands one operation to the surface it is already mounted on.
///
/// Deliberately the thinnest thing in the file: it hands the request the caller sent to the router
/// the operation is mounted on and returns that router's whole response. No status is computed here,
/// no header is added and no body is touched.
///
/// **A channel and not `Handle::block_on`,** for the reason the administrative seam gives: the loop
/// is synchronous and runs on a blocking worker, the router is asynchronous, and blocking on a
/// runtime handle from inside a blocking worker is legal on some runtime flavours and a panic on
/// others. A channel is flavour-independent — the blocking side waits on a standard-library receiver,
/// which knows nothing about runtimes.
///
/// **Bound to ONE request,** because a unit of a mounted plane is assembled per arrival and so is its
/// seam. That is the shape [`MountDispatch`] has, and the reason it takes no request: the request
/// travelled across when the dispatch was built.
pub(crate) struct RequestDispatch {
    errands: tokio::sync::mpsc::UnboundedSender<Errand>,
    /// The request this dispatch is bound to, taken when the seam is driven.
    ///
    /// A `Mutex<Option<_>>` because the trait takes `&self` and a request is not clonable in the
    /// sense that matters — a body is bytes and could be copied, but a seam that could be driven
    /// twice would let one arrival execute its operation twice. Taking it is what makes the second
    /// drive answer with the node's own unavailability instead.
    request: std::sync::Mutex<Option<axum::http::Request<axum::body::Body>>>,
}

impl RequestDispatch {
    /// Bind one request to the mounted router's driving task.
    pub(crate) fn new(
        errands: tokio::sync::mpsc::UnboundedSender<Errand>,
        request: axum::http::Request<axum::body::Body>,
    ) -> Self {
        RequestDispatch {
            errands,
            request: std::sync::Mutex::new(Some(request)),
        }
    }
}

impl MountDispatch for RequestDispatch {
    fn execute(&self, _op: busbar_contract::ids::OpClassId) -> MountedReply {
        let taken = self
            .request
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let Some(request) = taken else {
            // The seam was driven twice for one arrival. Nothing here can answer that honestly, and
            // executing the operation a second time is the one thing it must not do.
            return unavailable_response();
        };
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        if self
            .errands
            .send(Errand::Call(Box::new(request), reply))
            .is_err()
        {
            // The driving task is gone, which happens only as the node itself goes away.
            return unavailable_response();
        }
        // WHAT COMES BACK IS THE SURFACE'S RESPONSE, and it is handed on as it stands. Nothing here
        // reads its body, adds a header or recomputes its status: the caller asked for the answer
        // and this is the answer.
        answer.recv().unwrap_or_else(|_| unavailable_response())
    }

    fn collect(&self, body: axum::body::Body) -> Option<Vec<u8>> {
        let (reply, bytes) = std::sync::mpsc::sync_channel(1);
        if self.errands.send(Errand::Collect(body, reply)).is_err() {
            return None;
        }
        // A receive that fails is a body that never finished, which is exactly what `None` says. The
        // two failures are the same failure to the caller and are deliberately not distinguished:
        // both mean the node cannot produce the answer.
        bytes.recv().ok().flatten()
    }
}

/// Start the task that drives the mounted router, and hand back the sender the seams post to.
///
/// One task per operation, so a slow verb cannot hold up the one behind it — the surface was
/// concurrent before the switch and stays concurrent through it.
pub(crate) fn drive(
    inner: axum::Router,
    runtime: &tokio::runtime::Handle,
) -> tokio::sync::mpsc::UnboundedSender<Errand> {
    let (errands, mut inbox) = tokio::sync::mpsc::unbounded_channel::<Errand>();
    runtime.spawn(async move {
        while let Some(errand) = inbox.recv().await {
            match errand {
                Errand::Call(request, reply) => {
                    let inner = inner.clone();
                    tokio::spawn(async move {
                        let _ = reply.send(call(inner, *request).await);
                    });
                }
                // A buffering errand runs on its own task for the same reason an executing one does:
                // a body that takes a while to finish must not hold up the operation behind it.
                Errand::Collect(body, reply) => {
                    tokio::spawn(async move {
                        let _ = reply.send(collect(body).await);
                    });
                }
            }
        }
    });
    errands
}

/// Hand one request to the router and take its whole RESPONSE.
///
/// **NOTHING IS READ HERE.** This used to buffer the body and hand back three fields, which made
/// every mounted answer of every plane a `Vec<u8>` assembled inside the mount whether its plane
/// wanted one or not. What that cost is not abstract: a streamed answer arrived complete or not at
/// all, the chunk boundaries the surface chose were gone, and anything the surface attached to its
/// response as an extension had nowhere to survive. The response is the plane's, so it travels.
async fn call(inner: axum::Router, request: axum::http::Request<axum::body::Body>) -> MountedReply {
    use tower::ServiceExt;

    // The router's own error type is uninhabited: a mounted axum router answers, and failing is not
    // among the things it can do. So there is no error arm to write, and writing one anyway would be
    // a branch that can never be taken pretending to be a fallback that could be.
    inner.oneshot(request).await.unwrap_or_else(|e| match e {})
}

/// Read one body to its end, on the runtime that owns it.
///
/// No cap, and the absence is deliberate: the operator's ingress cap is applied to what ARRIVES, in
/// the wrap below, and a surface's own answer is not an untrusted quantity. A limit invented here
/// would be a second, quieter answer to how large this deployment's responses may be.
async fn collect(body: axum::body::Body) -> Option<Vec<u8>> {
    axum::body::to_bytes(body, usize::MAX)
        .await
        .ok()
        .map(|bytes| bytes.to_vec())
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE MOUNT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Wrap a mounted surface so every unit of its plane on it travels through the kernel.
///
/// `request_body_max_bytes` is the operator's own ingress cap, the same figure the mounted router's
/// body limit was built with. It is a parameter rather than a constant because this wrap reads the
/// body BEFORE that limit gets a chance to: a cap written down twice is a cap that can differ, and
/// the one that matters is the one the deployment configured.
pub fn mount(
    inner: axum::Router,
    leg: Arc<dyn MountedLeg>,
    kernel: busbar_kernel::teller::Kernel,
    parts: Arc<crate::root::data_plane::NodeParts>,
    request_body_max_bytes: usize,
) -> axum::Router {
    let runtime = tokio::runtime::Handle::current();
    let errands = drive(inner.clone(), &runtime);
    // THE PLANE'S OTHER DECLARATION, resolved once at composition rather than per request. A chain
    // that could not be composed over the surface is a surface the contract's own check refused, and
    // a mount that answered from a refused declaration would be serving addresses nothing verified —
    // so the claim question falls back to the claim table alone, which is what it always was.
    let chain = leg
        .surface()
        .and_then(|surface| {
            crate::root::data_plane::PlaneChain::over_parts(surface, Arc::clone(&parts)).ok()
        })
        .map(Arc::new);
    let node = Arc::new(MountedNode {
        leg,
        kernel,
        parts,
        chain,
    });

    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let node = Arc::clone(&node);
            let inner = inner.clone();
            let errands = errands.clone();
            async move {
                use tower::ServiceExt;

                // THE PLANE'S CLAIM IS WHAT DECIDES, and it is asked first. This listener carries
                // routes that are deliberately outside it, and walking those through a loop whose
                // decode reads a table they were never in would refuse a route that has always
                // answered.
                if !node.claims(req.uri().path(), req.method().as_str()) {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                // A BODY BIGGER THAN THE OPERATOR'S CAP IS NOT THIS WRAP'S TO ANSWER. The mounted
                // surface carries that cap and the answer release pinned for exceeding it, and this
                // wrap reads the body first — so a request that DECLARES more than the cap goes
                // straight there rather than being buffered into this node's memory on the way to
                // being rejected anyway.
                let declared = req
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok());
                if declared.is_some_and(|len| len > request_body_max_bytes) {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                let (parts, body) = req.into_parts();
                // AND A BODY THAT COULD NOT BE READ IS NOT AN EMPTY ONE. Read to the same cap, so an
                // undeclared length cannot buffer without bound either; where the read does not
                // finish, the request goes to the surface that already has an answer for it rather
                // than being executed as an empty document.
                let Ok(bytes) = axum::body::to_bytes(body, request_body_max_bytes).await else {
                    let rebuilt = axum::http::Request::from_parts(parts, axum::body::Body::empty());
                    return inner.oneshot(rebuilt).await.unwrap_or_else(|e| match e {});
                };

                // AND THE PLANE'S OWN DECODE IS WHAT DECIDES WHICH UNIT. A body this plane cannot
                // name an operation for is not a unit it has — it is a request the surface's own
                // routing already answers, with the document, the 404, the 405 or the `-32601` that
                // release pinned. Manufacturing a status here for bytes this plane never claimed
                // would be the root inventing an answer it has no basis for.
                let facts = mount_facts(&parts);
                let recognised =
                    with_arrival(&facts, &bytes, |arrival| node.leg.recognises(arrival));
                if !recognised {
                    let rebuilt =
                        axum::http::Request::from_parts(parts, axum::body::Body::from(bytes));
                    return inner.oneshot(rebuilt).await.unwrap_or_else(|e| match e {});
                }

                // The request is handed to the seam WHOLE, so what the surface receives is what the
                // caller sent — the same method, the same target, the same headers and the same
                // bytes. A request rebuilt from a subset would be a request the surface answers
                // differently for a reason nobody wrote down.
                let forwarded =
                    axum::http::Request::from_parts(parts, axum::body::Body::from(bytes.clone()));
                let dispatch: Arc<dyn MountDispatch> =
                    Arc::new(RequestDispatch::new(errands, forwarded));

                // AWAITED HERE, ON THE REACTOR, and no longer shipped to a blocking worker. Whether
                // a walk blocks is the LEG's property, and the leg now says so for itself through
                // `sync_leg`. A mount that decided it for every plane decided it wrong for any plane
                // whose walk is asynchronous — and paid for a `'static` closure, with every borrow
                // cloned or `Arc`-ed into it, to express a decision it had no business making.
                //
                // The arrival is composed on THIS frame so it outlives the await. That is what
                // `arrival_over` returning a value rather than lending one to a closure is for.
                let pairs = fact_pairs(&facts);
                let arrival = arrival_over(&pairs, &bytes);
                node.answer(&arrival, dispatch.as_ref()).await
            }
        },
    ))
}

/// The prefix every header this transport publishes as a fact is written under.
///
/// **RESERVED KEYS ARE THE KERNEL'S VOCABULARY AND HEADERS ARE THIS TRANSPORT'S**, and the prefix is
/// what keeps the two from ever being the same string. A header published under its bare name would
/// put `accept` next to `accepts` and `host` next to `authority` — two spellings of one thing, with
/// nothing saying which a plane should read — and a wire that invented a header called `path` would
/// silently overwrite the request target.
///
/// Named `http.` because it is the DOCUMENT TRANSPORT's, not the mount's and not any plane's: a
/// second transport that carried headers would publish its own under its own prefix, and a plane
/// that reads one is reading a fact of the wire it arrived on.
pub const HEADER_FACT_PREFIX: &str = "http.header.";

/// The fact key one header name is published under.
///
/// Lowercased, because `HeaderMap` already normalises on the way in and a fact key that differed by
/// case between two arrivals of the same header would be two facts.
#[must_use]
pub fn header_fact(name: &str) -> String {
    format!("{HEADER_FACT_PREFIX}{}", name.to_ascii_lowercase())
}

/// One header of an arrival, read back off the facts this mount published.
///
/// The read half of [`header_fact`], so the spelling is decided in one place. A leg that wrote the
/// prefix itself would be a second declaration of this transport's vocabulary.
#[must_use]
pub fn header_of<'a>(
    arrival: &'a busbar_contract::transport::Arrival<'a>,
    name: &str,
) -> Option<&'a str> {
    arrival.fact(&header_fact(name))
}

/// EVERY header of one arrival, read back off the facts this mount published.
///
/// The plural of [`header_of`], and the inverse of what [`mount_facts`] wrote. A leg whose plane's
/// own walk takes a header MAP rather than a fact reader needs the whole of what arrived, and
/// rebuilding it from the facts is the only honest way to get it: the request itself was handed to
/// the seam whole and is no longer this side's to read, so the facts are what a mounted unit knows
/// about the wire.
///
/// **NOT a filter and not a curation.** Every fact under [`HEADER_FACT_PREFIX`] goes back, in the
/// order it was published, which is the order it arrived — including a name that arrived twice,
/// because `HeaderMap::append` keeps repeats exactly as `HeaderMap::iter` yielded them. A subset
/// here would be the transport axis deciding what a plane is allowed to have received.
///
/// A fact whose key or value will not make a header again is left off rather than mangled. It cannot
/// happen for anything this mount published — every one of them came off a `HeaderMap` — and it is
/// written as a conversion rather than an assumption so a fact that some other transport published
/// under this prefix would be visible rather than silently reshaped.
#[must_use]
pub fn headers_of(arrival: &busbar_contract::transport::Arrival<'_>) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    for (key, value) in arrival.facts {
        let Some(name) = key.strip_prefix(HEADER_FACT_PREFIX) else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::try_from(name),
            axum::http::HeaderValue::try_from(*value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

/// EVERY header of one arrival as BORROWED name/value pairs, in the order they were published.
///
/// The same read-back as [`headers_of`] and the same non-curation, for a caller that needs the pairs
/// rather than a `HeaderMap`: the deployment's identity door is asked about the whole arrival, and
/// what it is asked with must be neutral — a door that took this transport's header type would be a
/// door only this transport could knock on.
///
/// BORROWED, so asking the door costs a mounted request no copy of what it already holds. The prefix
/// is stripped here, at the read half of [`header_fact`], so nothing downstream carries this
/// transport's fact vocabulary.
#[must_use]
pub fn header_pairs<'a>(
    arrival: &'a busbar_contract::transport::Arrival<'a>,
) -> Vec<(&'a str, &'a str)> {
    arrival
        .facts
        .iter()
        .filter_map(|(key, value)| Some((key.strip_prefix(HEADER_FACT_PREFIX)?, *value)))
        .collect()
}

/// The facts this mount publishes for one arrival: the kernel's reserved keys, then this
/// transport's own headers.
///
/// ## The reserved keys
///
/// The four a request carries about WHERE it was sent and the one it carries about what it
/// PRESENTED. They are the kernel's reserved keys and never a header name, because a plane reads the
/// fact and never the header — and the credential is published WHOLE, scheme word included, because
/// deciding what a scheme means is the authentication chain's.
///
/// ## And then EVERY header, under this transport's own prefix
///
/// Transport facts are open vocabulary — the contract says so where it names the nine reserved keys,
/// and the reason is exactly this case: a transport's own facts are the transport's. Six reserved
/// readings are the whole of what a request MEANS structurally, and they are not the whole of what
/// arrived. A plane whose surface is identified by a vendor header — and one mounted here declares
/// four of its fourteen rungs that way — could be mounted, could be claimed, and could not tell one
/// dialect from another, because the header it identifies by never crossed the seam.
///
/// So the whole map crosses, under [`HEADER_FACT_PREFIX`], and nothing here decides which headers
/// matter. A mount that published a curated subset would be the transport axis deciding what a plane
/// is allowed to read, which is the one thing an open vocabulary exists to avoid — and the curation
/// would be a list that goes stale the first time a protocol adds a header.
///
/// A header whose bytes are not text is left off rather than lossily rendered: a fact is a string,
/// and a plane matching on a mangled one would be matching on something no caller sent.
fn mount_facts(parts: &axum::http::request::Parts) -> Vec<(String, String)> {
    use busbar_contract::transport::facts;
    let mut out: Vec<(String, String)> = vec![
        (
            facts::PATH.to_string(),
            parts
                .uri
                .path_and_query()
                .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
        ),
        (facts::METHOD.to_string(), parts.method.as_str().to_string()),
    ];
    if let Some(authority) = parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        out.push((facts::AUTHORITY.to_string(), authority.to_string()));
    }
    // ABSENT IS ABSENT, NOT EMPTY. A plane handed an empty credential is being told one was
    // presented and is blank, which is a different — and worse — statement than "none arrived".
    if let Some(credential) = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
    {
        out.push((facts::CREDENTIAL.to_string(), credential.to_string()));
    }
    if let Some(accepts) = parts
        .headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
    {
        out.push((facts::ACCEPTS.to_string(), accepts.to_string()));
    }
    if let Some(media) = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        out.push((facts::MEDIA.to_string(), media.to_string()));
    }
    // AND THE WHOLE MAP, in the order it arrived. `HeaderMap::iter` repeats the name for a header
    // sent more than once, and the repeats are published as they came rather than joined: a fact is
    // one value, and folding two into one comma-separated string would be this file inventing a
    // spelling no caller sent. A plane reading the fact gets the first, which is what a plane
    // reading the header map would have got.
    for (name, value) in &parts.headers {
        if let Ok(text) = value.to_str() {
            out.push((header_fact(name.as_str()), text.to_string()));
        }
    }
    out
}

/// The composed stack this listener is: TCP underneath, the document transport above it.
///
/// Named here because the mount is the one thing that knows how the bytes got in, and the audit
/// record reads it off the arrival.
const CHAIN: [&str; 2] = ["tcp", "http"];

/// The facts of one arrival as the borrowed pairs an arrival reads.
///
/// [`busbar_contract::transport::Arrival`] holds a slice of borrowed pairs and the mount holds owned
/// ones, so somebody has to materialise the borrow and somebody has to own the vector it borrows
/// from. This is the first half; the caller keeps the vector alive for as long as the arrival.
fn fact_pairs(facts: &[(String, String)]) -> Vec<(&str, &str)> {
    facts
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// COMPOSE ONE ARRIVAL OVER these pairs and these bytes.
///
/// ## Why this is a value and no longer a closure
///
/// It was `with_arrival(facts, body, |arrival| …)`, a closure rather than a returned value because
/// an `Arrival` borrows its fact slice and a function cannot hand back one over a vector it built.
/// That reasoning is still true, and the answer is now to build the vector one level up: the caller
/// holds the pairs, this composes an arrival over them, and the arrival lives exactly as long as
/// they do.
///
/// The split is not cosmetic. A closure can only hand its arrival to something SYNCHRONOUS — an
/// arrival composed inside one cannot be borrowed across an `await`, because the closure returns
/// before the future it made is ever polled. The walk is now a future, so the arrival has to outlive
/// the call that made it, and that is exactly what returning it does.
///
/// Still ONE construction for both callers — the recognition question and the walk — because two
/// would be two chances for the loop to be handed something the recognition never saw.
fn arrival_over<'a>(
    pairs: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> busbar_contract::transport::Arrival<'a> {
    busbar_contract::transport::Arrival {
        facts: pairs,
        body,
        transport: "http",
        chain: &CHAIN,
        // The address named no operation: this is a MOUNT, and which operation these bytes are is
        // the plane's to say off the document. Saying otherwise would be the transport axis naming
        // an operation it did not read.
        operation: None,
        bar: busbar_contract::transport::Bar::Open,
    }
}

/// Compose one arrival over these facts and these bytes, for the length of one SYNCHRONOUS call.
///
/// The recognition question is a plain function call and wants the short spelling; the walk is a
/// future and cannot use it. Both compose through [`arrival_over`], so there is still one arrival
/// shape and not two.
/// THE MOUNT'S OWN COMPOSITION OF ONE ARRIVAL, for a cell that has to ask a leg a question the mount
/// would have asked it.
///
/// Test-only and `pub(crate)`, so a plane's own cells reach the mount's composition rather than
/// hand-build a fact set beside it. The alternative is the thing this whole file exists against: a
/// second spelling of what a mounted arrival carries, in a test, drifting away from the one the
/// mount publishes — and a leg asserted against the copy would pass while failing on the wire.
///
/// Three names rather than one closure-taking helper, because the arrival borrows the pairs and the
/// pairs borrow the facts: a caller that has to hold an arrival ACROSS AN AWAIT — which is every
/// caller asking a leg whose walk is asynchronous — needs both to live on its own frame, and a
/// closure's cannot.
#[cfg(test)]
pub(crate) fn test_facts(parts: &axum::http::request::Parts) -> Vec<(String, String)> {
    mount_facts(parts)
}

/// The pairs one arrival borrows, for the caller of [`test_facts`].
#[cfg(test)]
pub(crate) fn test_pairs(facts: &[(String, String)]) -> Vec<(&str, &str)> {
    fact_pairs(facts)
}

/// The arrival itself, over the pairs the caller is holding.
#[cfg(test)]
pub(crate) fn test_arrival<'a>(
    pairs: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> busbar_contract::transport::Arrival<'a> {
    arrival_over(pairs, body)
}

fn with_arrival<T>(
    facts: &[(String, String)],
    body: &[u8],
    f: impl FnOnce(&busbar_contract::transport::Arrival<'_>) -> T,
) -> T {
    let pairs = fact_pairs(facts);
    f(&arrival_over(&pairs, body))
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE NODE ONE UNIT IS WALKED BY
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The node one unit of a mounted plane is answered by.
///
/// Everything a request needs and nothing it does not: the kernel that mints its tokens, the leg its
/// steps run against, and the two node-wide counters. Built once at boot and shared by every request,
/// which is what makes the counts the canary balances node-wide rather than per-request.
struct MountedNode {
    leg: Arc<dyn MountedLeg>,
    kernel: busbar_kernel::teller::Kernel,
    /// THE NODE'S OWN PARTS, and not this mount's. A gauge or a canary made here would count one
    /// plane's traffic against an empty node, and a second plane doing the same would make two
    /// nodes out of one process. Composed once by the boot and lent to every mount on it.
    parts: Arc<crate::root::data_plane::NodeParts>,
    /// This plane's declared surface, over the same parts, where the plane declares one.
    chain: Option<Arc<crate::root::data_plane::PlaneChain>>,
}

impl MountedNode {
    /// **Whether these bytes are addressed to THIS PLANE**, asked of every declaration it has.
    ///
    /// The claim table is what the kernel routes on and is asked first; the declared surface is what
    /// a transport serves with, and is asked as well. Two tables of one protocol's addresses exist
    /// because they answer two different questions, and an address either of them names is an
    /// address this protocol owns — so a request is handed to the surface below only when NEITHER
    /// claims it.
    fn claims(&self, path: &str, method: &str) -> bool {
        claims_a_path(self.leg.claims(), path)
            || self
                .chain
                .as_ref()
                .is_some_and(|chain| chain.claims_the_target(path, method))
    }

    /// Walk one arrival through the loop and answer with what it produced.
    ///
    /// **ASYNC, AND THE LEG'S RESPONSE IS RETURNED UNTOUCHED.** There is no `http_response` on this
    /// path any more, and that absence is the whole change: a response rebuilt from three fields is
    /// a response whose body has been read, whose chunk boundaries are gone and whose extensions
    /// were dropped. The one call to `http_response` left in this file is on the REFUSAL path, where
    /// there is no plane response to carry because the unit never reached the seam — so the frame is
    /// built here, over the plane's own document.
    async fn answer(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        dispatch: &dyn MountDispatch,
    ) -> MountedReply {
        // THE NODE'S PARTS, composed by the thing that owns them. This file supplies the leg and the
        // seam; the unit key, the hold cell, the leases, the meter and the two node-wide counters
        // are the node's, which is what makes one process one node however many planes are mounted
        // on it.
        let cells = self.parts.open(&self.kernel);
        let (ended, answer) = self
            .leg
            .serve(
                arrival,
                &self.kernel,
                &cells.ctx,
                self.parts.lend(&cells),
                Some(dispatch),
            )
            .await;
        // THE ANSWER IS THE SURFACE'S WHERE THERE IS ONE, and it is handed on as it stands. A unit
        // that reached Route carries the response the operation's own surface wrote — its status,
        // its headers, and its body with the boundaries it chose and anything it attached — and this
        // file does not open it.
        match answer {
            Some(reply) => reply,
            // And a unit that did not is rendered by the PLANE, from the ending's own step and
            // reason. Never this file's prose: a refusal document this root wrote would be a status
            // and a body a caller pinned, invented by the one axis with no business deciding either.
            None => refused_response(self.leg.as_ref(), arrival, &ended),
        }
    }
}

/// What a unit that never reached the seam answers with.
///
/// The plane's own refusal document, rendered from the ending's step and reason through the same two
/// helpers the generic driver uses — so a caller refused by a mounted loop and one refused by the
/// driven loop read the same bytes.
///
/// The STATUS is the loop's ending narrowed to the eight words every wire has, and then to the status
/// the document transport spells for each. That narrowing lives in one place for the same reason the
/// document does.
fn refused_response(
    leg: &dyn MountedLeg,
    arrival: &busbar_contract::transport::Arrival<'_>,
    ended: &busbar_kernel::teller::Ended,
) -> MountedReply {
    let status = status_of(crate::root::transports::outcome_of(ended));
    let body = leg.render_refusal(arrival, ended).unwrap_or_default();
    let headers = if body.is_empty() {
        Vec::new()
    } else {
        vec![("content-type".to_string(), leg.media_type().to_string())]
    };
    http_response(PlaneAnswer {
        status,
        headers,
        body,
    })
}

/// The status this document transport spells for one outcome.
///
/// Total over the eight, with no fallback arm: a ninth outcome would not compile, which is the whole
/// value of writing the narrowing down once. Each pair is the status the mounted surfaces already
/// answer the same condition with.
#[must_use]
pub fn status_of(outcome: busbar_contract::transport::Outcome) -> u16 {
    use busbar_contract::transport::Outcome as O;
    match outcome {
        O::Completed => 200,
        O::Unauthenticated => 401,
        O::Forbidden => 403,
        O::NotFound => 404,
        O::Throttled => 429,
        O::TimedOut => 504,
        O::Cancelled => 499,
        O::Unavailable => 503,
    }
}

/// The media type both protocols mounted today answer with.
///
/// A default a leg may return from [`MountedLeg::media_type`], not a constant this file applies: the
/// document is the plane's and so is its type.
pub const MEDIA_JSON: &str = "application/json";

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BOOT'S ONE COMPOSITION STEP
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// WHAT ONE PLANE'S MOUNT DID AT BOOT, so the composition can be read back rather than guessed at.
///
/// The boot reports what it composed for the same reason it refuses a claim overlap out loud: a
/// deployment where a plane's mount silently did not compose serves the surface underneath, looking
/// exactly like a deployment where it did — and the difference is which code answers the money.
#[derive(Debug)]
pub struct Mounted {
    /// The plane, by the key its row carries.
    pub plane: &'static str,
    /// The source that had no boot answer, where this plane's leg did not assemble.
    pub absent: Option<crate::root::registry::MountAbsent>,
}

impl Mounted {
    /// Whether this plane's declared surface is answered by its leg on this node.
    #[must_use]
    pub fn is_mounted(&self) -> bool {
        self.absent.is_none()
    }
}

/// **MOUNT EVERY PLANE THE SEALED REGISTRY CARRIES A ROW FOR, onto one shared listener.**
///
/// This is the whole composition step, and it names no plane. It folds the registry's mount rows —
/// data, one per plane, each declared in that plane's own file — over the router the deployment
/// already composed, so a plane joins the shipped serving path by adding a ROW and never by being
/// named here, in `main.rs`, or in `transports.rs`.
///
/// **THE ORDER IS THE ROWS' ORDER AND IT IS NOT AN ACCIDENT.** Each wrap answers only the paths its
/// own plane claims and hands everything else to what it wrapped, so the fold builds a chain that
/// ends at the router the boot started with. The claims were sealed against each other before any of
/// this ran (`registry::seal` refuses an unresolvable overlap at boot), which is what makes "only the
/// paths its own plane claims" a statement about one plane rather than a race between two.
///
/// **THE LEGACY LEG IS WHAT IS LEFT.** A plane whose row cannot assemble a leg adds no wrap, so its
/// claimed paths fall through to the surface underneath exactly as they did before — the released
/// behaviour, unchanged, for exactly the deployments that cannot mount. The report says which.
pub fn compose_mounts(
    router: axum::Router,
    inputs: &crate::root::registry::MountInputs,
) -> (axum::Router, Vec<Mounted>) {
    let mut composed = router;
    let mut report = Vec::new();
    // THE NODE'S PARTS, COMPOSED ONCE FOR THE PROCESS and lent to every mount this fold builds. One
    // set per mount would be one node per plane: each gauge bounding its own plane's share of the
    // traffic, each canary balancing its own plane's half of the books, and every one of them
    // looking healthy because none of them can see the others.
    let parts = Arc::new(crate::root::data_plane::NodeParts::new());
    for row in crate::root::registry::mount_rows() {
        match (row.compose)(inputs) {
            Ok(leg) => {
                // ONE KERNEL PER MOUNT, minted here rather than shared: a kernel is the authority a
                // leg's tokens are lent from, and two planes lending from one would be two planes
                // holding one process's single seal.
                composed = mount(
                    composed,
                    leg,
                    crate::root::kernel::new_kernel(),
                    Arc::clone(&parts),
                    inputs.request_body_max_bytes,
                );
                report.push(Mounted {
                    plane: row.plane,
                    absent: None,
                });
            }
            Err(absent) => report.push(Mounted {
                plane: row.plane,
                absent: Some(absent),
            }),
        }
    }
    (composed, report)
}

#[cfg(test)]
#[path = "tests/plane_mount.rs"]
mod tests;
