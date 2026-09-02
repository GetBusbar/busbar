// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO SERVE MODE: busbar as an MCP server on ITS OWN stdin/stdout, so a local client
//! (Claude Desktop-class) can run busbar as a child process instead of speaking streamable HTTP.
//!
//! ## ONE PATHWAY — the equality doctrine, applied to a second transport
//!
//! Every line read from stdin is fed to THE SAME serve sequence the HTTP endpoint runs —
//! [`busbar_substrate::ingress::protocol::serve`], with the same [`super::envelope::McpWords`], the same
//! notification observer, and the same [`super::envelope::rpc_dispatch`] behind it. There is no
//! stdio method table, no stdio refusal shaper and no stdio `_meta` reader: a request that the HTTP
//! plane would refuse is refused here with the same code and the same sentence, because it runs the
//! same code.
//!
//! ## THE TRANSPORT IS NEUTRAL: this module owns only MCP SEMANTICS, not the carrier
//!
//! What a stdio-class transport owns — framing (one frame per line), the single write lock, the
//! `CallRef`-keyed correlation table that pairs a server-issued request with its answer, and the
//! EOF-drain session lifecycle — is NOT re-implemented here. It lives in the substrate as
//! [`busbar_substrate::ingress::byte_duplex`], a protocol-blind byte pump, and this module BINDS it
//! by supplying the two callbacks a plane owes: [`DuplexPlane::classify`] ("is this frame a reply,
//! and to which call I issued?") and [`DuplexPlane::handle`] ("dispatch one non-reply frame,
//! writing answers back through the [`DuplexHandle`]"). Every MCP-specific meaning — the JSON-RPC
//! id ⇄ [`CallRef`] spelling, the stdio-era verbs (`initialize`/`ping`/`logging/setLevel`/
//! `resources/subscribe`), `notifications/cancelled`, the live MRTR asks, the SEP-1036 out-of-band
//! elicitation reply, and the server-originated notifications a persistent channel can carry — sits
//! on the PLANE side of those two callbacks. The substrate names none of it; it moves `Vec<u8>`
//! frames and pairs a `u64` call with its answer, and reads nothing of what those bytes mean.
//!
//! The mirrored routing headers (`Mcp-Method`, `Mcp-Name`, `MCP-Protocol-Version`) are an HTTP
//! statement — they exist so an intermediary can route without parsing the body, and a pipe has no
//! intermediary and no header block. They are therefore SYNTHESISED FROM THE BODY, exactly as the
//! conformance battery's own stdio→HTTP adapter (`testing/mcp-conformance/scripts/
//! stdio-http-bridge.mjs`) derives them: nothing the body does not state is stated, so a body
//! defect stays a body defect (`-32602`) instead of being converted into a header defect. On a
//! transport where the two readings cannot exist, the disagreement check is vacuously satisfied
//! rather than skipped — the one dispatch function still runs it.
//!
//! ## GOVERNANCE: a BOOT-TIME credential binds the WHOLE session — the design decision, argued
//!
//! A stdio caller presents no bearer per-request; something has to say who the session is. The
//! choice was between a boot-time credential and an initialize-time exchange, and boot-time won
//! for three reasons:
//!
//! 1. **It is the same admission, made once.** [`ENV_CREDENTIAL`] carries the SAME credential the
//!    HTTP plane accepts, and it is judged by the SAME sequence: the RFC 8707 audience pre-filter
//!    against `mcp.canonical_uri` (routed host-side through
//!    [`identity_audience_binding`](busbar_substrate::plane_host::EngineHost::identity_audience_binding)),
//!    then the configured auth chain and the
//!    one verdict resolution the HTTP middleware itself runs — routed host-side through the
//!    [`identity_admit`](busbar_substrate::plane_host::EngineHost::identity_admit) seam (Seam-B), so this transport
//!    admits an inbound session without naming the auth chain. A credential that the HTTP door would
//!    refuse is refused here; one it would admit binds this session to the same principal, the same
//!    `PlaneRequestCtx`, the same budgets, audit attribution and hooks.
//! 2. **The postures line up with the doctrine "busbar requires authentication to apply budget".**
//!    A CONFIGURED chain with no credential, or a refused one, is a REFUSAL TO SERVE (nonzero
//!    exit, sentence on stderr): fail-closed, exactly as the HTTP door answers `401`. There is no
//!    middle posture in which a governed deployment serves an unattributed stdio session. The
//!    other end of the spectrum does not exist at all: `config_validate` refuses `mcp:` beside an
//!    empty `auth.chain` at BOOT, on every transport, so the empty-chain open-relay posture can
//!    never reach a serving stdio session — the [`session_identity`] `Open` arm survives only as
//!    fail-safe depth (and still warns). The one UNGOVERNED session a production config can
//!    produce is an admitted principal whose module has no `role_bindings` table, and that session
//!    says so on stderr in so many words.
//! 3. **An initialize-time exchange would be session state under a revision that deleted sessions,
//!    guarding a boundary that does not exist here.** The party that launches busbar names its
//!    config file and its environment; per-message re-authentication of one's own parent buys
//!    nothing a boot credential does not, and it would put a second admission pathway beside the
//!    first — the exact parallel-dispatch failure the ingress unification exists to prevent.
//!
//! The credential rides an ENVIRONMENT VARIABLE, not a flag: argv is world-readable on most
//! platforms (`ps`), and the launching client (an MCP host's `env` block) already has exactly this
//! shape for exactly this reason.
//!
//! The identity is FROZEN for the life of the session — the same posture `subscriptions/listen`
//! documents for its stream, with the same bound honestly stated: a key revoked mid-session keeps
//! being honoured until the process ends, where per-poll re-resolution guards the long-lived HTTP
//! stream. The party able to end the session is the party that started it — the supervising client
//! — and killing the child IS the revocation, which no network peer can say of an HTTP stream.
//!
//! ## SERVER-ORIGINATED MESSAGES: the channel exists here, so the messages ride it
//!
//! Streamable HTTP under this revision has no standing stream, so busbar's asks travel as
//! `InputRequiredResult` and its notifications ride a request's own response stream. stdio is ONE
//! full-duplex channel shared by everything, which is why the client leg (`super::client::peer`)
//! already answers a child's `ping` / `roots/list` / `sampling/createMessage` /
//! `elicitation/create` REQUESTS and files its notifications. This module is the mirror image:
//!
//! * an `input_required` result composed by [`super::callerask`] is TRANSLATED into live JSON-RPC
//!   requests on the channel — each `inputRequests` entry is issued as its own request, the
//!   client's answers become `inputResponses`, and the retry (with the sealed `requestState`
//!   echoed) is re-dispatched through the full core sequence. Nothing in the MRTR machinery is
//!   bypassed: the seal, the capability filter, the round budget charge and the epoch checks all
//!   run exactly as they do when an HTTP caller drives the retry itself.
//! * the SSE frames of a response stream — `notifications/message`, `notifications/progress`, the
//!   subscription acknowledgement and the list-changed family — are unwrapped onto stdout, one
//!   JSON-RPC notification per line, tagged with the same `_meta` the stream tagged them with.
//! * the SSE comment keepalive of an idle subscription becomes a server→client `ping` request —
//!   the same liveness statement, in the only vocabulary this framing has for one.
//! * a subscription busbar closes EARLY (a lapsed permission, not the graceful bound) additionally
//!   announces `notifications/cancelled` naming the listen request's id, because on stdio there is
//!   no stream whose closure could say it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::response::Response;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use busbar_substrate::ingress::byte_duplex::{self, CallRef, DuplexHandle, DuplexPlane};

use super::envelope::{
    self, McpWords, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, META_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};

/// The environment variable carrying the session credential. See the module header for why it is
/// an env var and not a flag, and why absence on a governed deployment refuses to serve.
pub(crate) const ENV_CREDENTIAL: &str = "BUSBAR_MCP_STDIO_CREDENTIAL";

/// How long busbar waits for the client to answer ONE live ask before falling back to handing the
/// caller the `input_required` result itself. Bounded for the same reason every exchange in this
/// tree is: a client that stops answering is indistinguishable from a slow one, and the sealed
/// `requestState` makes the fallback restartable rather than lost.
const ASK_TIMEOUT: Duration = Duration::from_secs(30);

/// The cap on live MRTR rounds this binding will drive for one request. Mirrors the operator's
/// per-capability `max_caller_ask_rounds` (which still applies inside dispatch); this is the
/// TRANSPORT's own belt against a composition that never converges.
const MAX_LIVE_ASK_ROUNDS: u32 = 8;

/// How often the session's background watchers re-read the catalogue generation and its tasks —
/// the same cadence `super::subscribe` polls at, for the same reasons.
const WATCH_INTERVAL: Duration = Duration::from_millis(250);

/// THE SESSION IDENTITY, resolved once at boot and frozen. Field-for-field what the HTTP auth
/// middleware inserts as request extensions.
pub(crate) struct SessionIdentity {
    pub(crate) principal: busbar_api::AuthPrincipal,
    pub(crate) gov: busbar_api::PlaneRequestCtx,
}

/// Resolve the session identity from the boot credential — the SAME admission the HTTP door runs,
/// stated step by step in the module header. `Err` is a sentence for stderr and a refusal to serve.
pub(crate) async fn session_identity(
    factory: &busbar_substrate::plane_host::LiveHostFactory,
    credential: Option<&str>,
) -> Result<SessionIdentity, String> {
    let Some(resource) = super::resource_of(&factory()) else {
        return Err(
            "this deployment carries no `mcp:` block, so there is no MCP plane to serve. \
             Presence of the block is what makes busbar an MCP server, on every transport."
                .to_string(),
        );
    };
    // (1) THE AUDIENCE PRE-FILTER, for credentials busbar did not mint — the identical check the
    // HTTP middleware runs before the chain, because a token minted for another resource is not
    // made admissible by arriving on a pipe instead of a socket.
    if let Some(token) = credential {
        use busbar_substrate::plane_host::AudienceBinding as Binding;
        // The binding JUDGEMENT is routed host-side through `identity_audience_binding` (Seam-B), so
        // this transport runs the SAME RFC 8707 pre-filter as the HTTP door without naming the core
        // auth module — only the WORDING of a refusal remains stdio's.
        match factory().identity_audience_binding(token, resource.canonical_uri()) {
            Binding::Deferred | Binding::Bound => {}
            Binding::Mismatch => {
                return Err(format!(
                    "the credential in {ENV_CREDENTIAL} carries an audience that does not \
                     identify this resource. Request a token whose `resource` (RFC 8707) is this \
                     deployment's `mcp.canonical_uri`."
                ));
            }
            Binding::Opaque => {
                return Err(format!(
                    "the credential in {ENV_CREDENTIAL} carries no readable audience, so it \
                     cannot be shown to have been issued for this resource. A busbar-signed key \
                     or a JWT access token bound to `mcp.canonical_uri` is required."
                ));
            }
        }
    }
    // (2)+(3) THE CHAIN + THE ONE VERDICT RESOLUTION, routed through the host `identity_admit` seam
    // (Seam-B): the host runs the SAME chain the HTTP door runs (same audience expectation) and the SAME
    // verdict resolution the middleware runs, over the live governance state, and hands back the resolved
    // `(AuthPrincipal, PlaneRequestCtx)` — or the specific refusal. The plane no longer names the core
    // auth-chain entrypoint (`run_chain_on_request_path`) / `resolve_data_plane_identity`; only the WORDING of a
    // refusal remains stdio's. Byte-identical: the principal and gov context are the exact objects the
    // resolution produced, and the refusal keeps its variant.
    let canonical = resource.canonical_uri().to_string();
    let admitted = factory()
        .identity_admit(credential.map(str::to_string), canonical.clone(), canonical)
        .await;
    match admitted {
        Ok((principal, gov)) => {
            if !gov.is_governed() {
                // The open-relay banner has already fired at boot for the empty chain; this line
                // adds the session-shaped consequence so an operator reading the child's stderr
                // sees what "ungoverned" means HERE: no budget, no attribution, no grant scoping.
                eprintln!(
                    "[warn] mcp stdio session is UNGOVERNED: no enforcement key is bound, so no \
                     budget applies and audit rows attribute to `anonymous`. Configure \
                     `auth.chain` and set {ENV_CREDENTIAL} to bind the session to a key."
                );
            }
            Ok(SessionIdentity { principal, gov })
        }
        Err(busbar_api::IdentityRefusal::Denied) => Err(if credential.is_none() {
            format!(
                "this deployment's `auth.chain` is configured, so an unauthenticated stdio \
                 session is refused exactly as an unauthenticated POST is. Set {ENV_CREDENTIAL} \
                 to a credential the chain admits (audience-bound to `mcp.canonical_uri`)."
            )
        } else {
            format!("the credential in {ENV_CREDENTIAL} was refused by the auth chain.")
        }),
        Err(busbar_api::IdentityRefusal::NoGrant) => Err(format!(
            "the credential in {ENV_CREDENTIAL} authenticated, but its roles earned no \
             enforcement key under `role_bindings`, and an ungoverned admission would widen its \
             access. The same request over HTTP answers `insufficient_scope`."
        )),
    }
}

/// SERVE the process's own stdin/stdout until EOF. The exit code for `main`. (Named for the
/// transport rather than `serve` alone: the plane-coherence lint rightly refuses a second
/// plane-local `serve` beside `a2a::grpc::serve`.) `pub`: called from the thin `busbar` binary's
/// `main.rs`, a different crate after the core split.
pub async fn serve_stdio(factory: busbar_substrate::plane_host::LiveHostFactory) -> i32 {
    let credential = std::env::var(ENV_CREDENTIAL).ok().filter(|c| !c.is_empty());
    let identity = match session_identity(&factory, credential.as_deref()).await {
        Ok(identity) => identity,
        Err(sentence) => {
            eprintln!("busbar: mcp stdio serve refused to start: {sentence}");
            return 1;
        }
    };
    tracing::info!(
        actor = identity.principal.actor_id(),
        governed = identity.gov.is_governed(),
        "mcp stdio serve: session bound; serving on stdin/stdout"
    );
    serve_io(factory, identity, tokio::io::stdin(), tokio::io::stdout()).await;
    0
}

/// SERVE the session over ANY reader/writer pair — generic so the tests drive it over an in-memory
/// duplex with a REAL governed `App`, which is the only way the budget refusal can be watched on an
/// instrument without a network. The pair is handed straight to the neutral byte-duplex pump.
pub(crate) async fn serve_io<R, W>(
    factory: busbar_substrate::plane_host::LiveHostFactory,
    identity: SessionIdentity,
    reader: R,
    writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let session = new_session(factory, identity);
    run_session(session, reader, writer).await;
}

/// Construct one live session (and start its watchers). Split from [`run_session`] so the
/// in-process battery can hold the session while driving the loop — nothing but tests and
/// [`serve_io`] call either. The writer is NOT held here: it belongs to the neutral pump, which
/// hands this session a [`DuplexHandle`] onto it with the first frame ([`Session::out`]).
fn new_session(
    factory: busbar_substrate::plane_host::LiveHostFactory,
    identity: SessionIdentity,
) -> Arc<Session> {
    let session = Arc::new(Session {
        factory,
        principal: identity.principal,
        gov: identity.gov,
        out: OnceLock::new(),
        level: std::sync::Mutex::new(None),
        inflight: std::sync::Mutex::new(HashMap::new()),
        ask_seq: AtomicU64::new(0),
        resource_subs: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        background: std::sync::Mutex::new(Vec::new()),
    });
    session.spawn_resource_watch();
    session
}

/// DRIVE the neutral byte-duplex pump for this session until EOF, then reap the plane's own
/// background watchers. The pump ([`byte_duplex::serve`]) owns framing, the single write lock, the
/// server-issued-call correlation table, and the bounded EOF drain of in-flight [`DuplexPlane::handle`]
/// dispatches; all this module adds after EOF is aborting the session-scoped watchers the pump does
/// not know about (the resource/tasks watchers and keepalive pings the plane spawned).
async fn run_session<R, W>(session: Arc<Session>, reader: R, writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    byte_duplex::serve(reader, writer, session.clone()).await;
    // EOF: the pump has drained its own in-flight handlers; the plane's standing watchers (spawned
    // onto the runtime, unknown to the pump) die here so the loop ends cleanly rather than leaking
    // them past the session.
    for h in session.background.lock().unwrap().drain(..) {
        h.abort();
    }
    for (_, tx) in session.inflight.lock().unwrap().drain() {
        drop(tx); // dropping a cancel sender is harmless: its handler already returned at EOF
    }
}

/// THE TWO CALLBACKS the neutral pump drives. Everything MCP-specific — what a reply looks like,
/// which verbs mean what, the id ⇄ [`CallRef`] spelling — is here, on the plane side of the seam.
#[async_trait::async_trait]
impl DuplexPlane for Session {
    /// Is this inbound frame a REPLY to a request busbar issued on the channel, and to which? Two
    /// shapes answer a busbar ask, and both are MCP semantics the substrate cannot see:
    ///
    /// * a genuine JSON-RPC RESPONSE (no `method`, a `result`/`error`) whose `id` is one busbar
    ///   minted — spelled `busbar:<callref>`, the [`CallRef`] embedded the only way this wire has;
    /// * SEP-1036's OUT-OF-BAND `notifications/elicitation/response`, a NOTIFICATION whose
    ///   `params.requestId` names the elicitation busbar issued — admissible only because this one
    ///   authenticated single-caller channel is the binding HTTP lacks.
    ///
    /// Everything else — a client's own request or notification, a response to no busbar call,
    /// garbage — is not a reply and returns `None`, taking the one dispatch pathway through
    /// [`handle`](Self::handle).
    fn classify(&self, frame: &[u8]) -> Option<CallRef> {
        let value: Value = serde_json::from_slice(frame).ok()?;
        let obj = value.as_object()?;
        match obj.get("method").and_then(Value::as_str) {
            // A response: no method member, a result or error, and an id busbar spells its calls in.
            None => {
                if !(obj.contains_key("result") || obj.contains_key("error")) {
                    return None;
                }
                call_ref_of_id(obj.get("id")?)
            }
            // The out-of-band elicitation reply correlates through `params.requestId`.
            Some("notifications/elicitation/response") => {
                call_ref_of_id(value.pointer("/params/requestId")?)
            }
            // Any other request or notification is the dispatch pathway's business.
            Some(_) => None,
        }
    }

    /// Handle ONE non-reply frame and write its answer(s) back through `out`. The first `out` this
    /// session ever sees is cached ([`Session::out`]) so the standing watchers — spawned before any
    /// frame — can push server-originated notifications onto the SAME channel.
    ///
    /// A frame carrying a caller id is run under a cancellation gate registered by that id, so a
    /// `notifications/cancelled` naming it (processed on its own frame's handler) aborts the work and
    /// suppresses every further message for it (`CANCEL.NO-FURTHER-MESSAGES`). Registering BEFORE the
    /// dispatch begins closes the race the hand-rolled loop documented: a cancel that arrives before
    /// the dispatch starts still fires the gate.
    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        let _ = self.out.set(out);
        let caller_id = envelope_id(&frame);
        match caller_id.as_ref().map(id_key) {
            Some(key) => {
                let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
                self.inflight.lock().unwrap().insert(key.clone(), cancel_tx);
                tokio::select! {
                    () = self.handle_frame(frame, caller_id) => {}
                    _ = cancel_rx => {} // cancelled: the dispatch future is dropped, its answer suppressed
                }
                self.inflight.lock().unwrap().remove(&key);
            }
            // A notification or an id-less frame cannot be cancelled — nothing names it.
            None => self.handle_frame(frame, caller_id).await,
        }
    }
}

/// Read the [`CallRef`] busbar embedded in a JSON-RPC id it minted. busbar spells its own calls
/// `busbar:<n>` (see [`Session::issue_request`]); the bare `n` is the ref the pump minted. A
/// non-string id, or one this plane did not mint, correlates to nothing.
fn call_ref_of_id(id: &Value) -> Option<CallRef> {
    let n: u64 = id.as_str()?.strip_prefix("busbar:")?.parse().ok()?;
    Some(CallRef(n))
}

/// Read the answer out of whichever frame the pump routed back to an [`issue`](DuplexHandle::issue).
/// [`classify`](Session::classify) admits two shapes, so this reads both: the SEP-1036 out-of-band
/// `notifications/elicitation/response` (the answer is `params.response`), and — the ordinary case —
/// a genuine JSON-RPC response read through the shared [`read_response`](busbar_substrate::ingress::jsonrpc::read_response)
/// vocabulary, so a client error or a non-answer becomes the same sentence the HTTP leg would log.
fn interpret_reply(frame: &[u8], sent_id: &Value) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
    if value.get("method").and_then(Value::as_str) == Some("notifications/elicitation/response") {
        return Ok(value
            .pointer("/params/response")
            .cloned()
            .unwrap_or(Value::Null));
    }
    match busbar_substrate::ingress::jsonrpc::read_response(&value, sent_id) {
        Ok(busbar_substrate::ingress::jsonrpc::Reply::Result(result)) => Ok(result),
        Ok(busbar_substrate::ingress::jsonrpc::Reply::Error { code, message }) => Err(format!(
            "the client answered with an error ({code:?}): {message}"
        )),
        Err(not_answer) => Err(not_answer.to_string()),
    }
}

/// The `id` member of one raw frame, when it parses as an object carrying a legible one.
fn envelope_id(line: &[u8]) -> Option<Value> {
    let value: Value = serde_json::from_slice(line).ok()?;
    let id = value.get("id")?;
    (id.is_string() || id.is_number()).then(|| id.clone())
}

/// A stable map key for a JSON-RPC id: type-tagged so the string `"1"` and the number `1` — which
/// never correlate on the wire — never collide in the in-flight table either.
fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => format!("s:{s}"),
        other => format!("n:{other}"),
    }
}

struct Session {
    /// THE NEUTRAL LIVE-HOST FACTORY. Each frame and each watch tick calls it to mint a fresh
    /// live-capable `EngineHost`, whose BOUND snapshot is that frame/tick's current load and whose
    /// `plane_slot_live` re-reads the CURRENT snapshot — so a config swap between frames is seen. The
    /// closure closes over the transport's live handle core-side, so this plane names no core handle.
    factory: busbar_substrate::plane_host::LiveHostFactory,
    principal: busbar_api::AuthPrincipal,
    gov: busbar_api::PlaneRequestCtx,
    /// THE WRITE-AND-CALL HANDLE onto the one channel, handed to this session by the neutral pump
    /// with the FIRST frame it dispatches ([`DuplexPlane::handle`]) and cached here so the standing
    /// watchers — which predate any frame — can emit server-originated notifications too. The pump
    /// owns the single write lock and the correlation table behind it; this session never touches a
    /// raw writer. Unset until the first frame; a real client opens with `initialize`, so every
    /// server-originated push (which can only follow a subscribe/ask/task result) has it by then.
    out: OnceLock<DuplexHandle>,
    /// The session logging floor `logging/setLevel` sets. Injected into a request's `_meta` only
    /// when the request names none of its own — the per-request spelling still wins, so an HTTP
    /// client's semantics are unchanged by the session having a default.
    level: std::sync::Mutex<Option<String>>,
    /// Cancellation gates for in-flight dispatches, keyed by the caller's request id: firing one
    /// (for `notifications/cancelled`) makes that frame's [`DuplexPlane::handle`] select drop its
    /// dispatch and answer nothing further.
    inflight: std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<()>>>,
    /// The internal id sequence for a live-ask RETRY (`busbar:retry:<n>`), an independent request
    /// dispatched in-process and mapped back to the caller's id at delivery — never a wire
    /// correlation (the pump mints those refs), so it keeps its own counter.
    ask_seq: AtomicU64,
    /// URIs the client subscribed to with `resources/subscribe`, each with the LAST fingerprint of
    /// its caller-visible registration — `None` for a subscription whose subject is not (or not
    /// yet) in the caller's catalogue. The baseline is written at subscribe time; the watcher
    /// compares on every generation move.
    resource_subs: std::sync::Mutex<std::collections::BTreeMap<String, Option<u64>>>,
    /// Watcher tasks aborted at EOF.
    background: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Session {
    /// The cached channel handle, once the pump has handed us one. Every emit path runs only after a
    /// frame (an answer to it, or a push that a prior subscribe/ask/task result set in motion), so in
    /// a live session it is always present; a push racing ahead of the first frame is simply dropped.
    fn channel(&self) -> Option<&DuplexHandle> {
        self.out.get()
    }

    /// Write ONE JSON-RPC message as one frame. `serde_json` emits no raw newline, so the framing
    /// MUST (`STDIO.NO-EMBEDDED-NEWLINES`) holds by construction; the pump appends the one line
    /// terminator under its single write lock.
    async fn emit(&self, value: &Value) {
        let Some(out) = self.channel() else { return };
        let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
        out.emit(bytes).await;
    }

    /// Issue ONE busbar-originated request on the channel and await the client's answer, through the
    /// pump's correlation table. The id is spelled `busbar:<callref>` so [`classify`](Self::classify)
    /// can read the pump-minted [`CallRef`] back out of whichever frame answers — a genuine JSON-RPC
    /// response or the out-of-band elicitation notification.
    async fn issue_request(&self, method: &str, params: &Value) -> Result<Value, String> {
        let Some(out) = self.channel() else {
            return Err("the session channel is not open".to_string());
        };
        let call = out.mint();
        let id = Value::from(format!("busbar:{}", call.0));
        let frame = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .unwrap_or_else(|_| b"null".to_vec());
        // The pump registers `call` before writing the frame, so a reply that races back cannot find
        // an empty table; `ASK_TIMEOUT` bounds a client that never answers.
        match tokio::time::timeout(ASK_TIMEOUT, out.issue(call, frame)).await {
            Ok(Some(reply)) => interpret_reply(&reply, &id),
            Ok(None) => Err("the session ended before the client answered".to_string()),
            Err(_) => Err(format!(
                "the client did not answer `{method}` within {}s",
                ASK_TIMEOUT.as_secs()
            )),
        }
    }

    /// ONE FRAME through the ONE pathway, and its answer(s) onto stdout.
    async fn handle_frame(self: &Arc<Self>, line: Vec<u8>, caller_id: Option<Value>) {
        let body = self.body_with_session_level(line);
        let response = self.dispatch_frame(&body).await;
        self.deliver(caller_id, body, response, 0).await;
    }

    /// Inject the session logging floor into `params._meta` when the request names no level of its
    /// own. The transport supplies the SESSION default into the PER-REQUEST slot the revision
    /// defined — which is what a session-scoped `logging/setLevel` can honestly mean on a
    /// revision whose records ride the request that produced them.
    fn body_with_session_level(&self, line: Vec<u8>) -> Vec<u8> {
        let Some(level) = self.level.lock().unwrap().clone() else {
            return line;
        };
        let Ok(mut value) = serde_json::from_slice::<Value>(&line) else {
            return line;
        };
        let Some(meta) = value
            .get_mut("params")
            .and_then(|p| p.get_mut("_meta"))
            .and_then(|m| m.as_object_mut())
        else {
            return line;
        };
        if meta.contains_key(super::sse::META_LOGGING_LEVEL) {
            return line; // the request's own spelling wins
        }
        meta.insert(super::sse::META_LOGGING_LEVEL.to_string(), level.into());
        serde_json::to_vec(&value).unwrap_or(line)
    }

    /// One pass of the CORE SEQUENCE over one frame.
    async fn dispatch_frame(self: &Arc<Self>, body: &[u8]) -> Response {
        // MINT THE NEUTRAL HOST over THIS frame's live snapshot via the factory, so the host is
        // live-capable (its `plane_slot_live` re-reads the CURRENT snapshot for the dispatch-time
        // re-validation and per-round grant re-reads deep in `method`), while its BOUND snapshot is
        // this frame's current load — byte-identical to the former per-frame `app` load, and used
        // for every BOUND read below through the `runtime_of`/`resource_of` funnel.
        let host = (self.factory)();
        let session = self.clone();
        let epochs = super::runtime_of(&host).roots_epochs.clone();
        // The SAME principal name the HTTP observer binds roots epochs under — the authenticated
        // key id, or the one honest constant on an ungoverned deployment.
        let notify_principal = session
            .gov
            .key
            .as_ref()
            .map_or_else(|| "<ungoverned>".to_string(), |k| k.id.clone());
        busbar_substrate::ingress::protocol::serve(
            &McpWords,
            busbar_substrate::ingress::protocol::Request {
                present: super::resource_of(&host).is_some(),
                // A pipe has no Origin: there is no browser and no rebinding surface. `None` takes
                // the same arm an agent's headerless HTTP request takes.
                origin: None,
                allowed_origins: &[],
                wire_refusal: None,
                body,
            },
            // THE NOTIFICATION OBSERVER — the HTTP plane's roots arm, plus the session
            // notifications only a persistent channel can carry.
            {
                let session = session.clone();
                move |method: &str, value: &Value| {
                    if method == super::roots::METHOD_NOTIFY_ROOTS_LIST_CHANGED {
                        epochs.note_change(&notify_principal);
                    }
                    session.observe_notification(method, value);
                }
            },
            {
                let session = self.clone();
                let host = host.clone();
                move |value, id, method| async move {
                    session.stdio_dispatch(&host, value, id, method).await
                }
            },
        )
        .await
    }

    /// Steps 9–12 for this transport: the stdio-era vocabulary first, then the SAME
    /// [`envelope::rpc_dispatch`] the HTTP handler runs, under headers synthesised from the body.
    async fn stdio_dispatch(
        self: &Arc<Self>,
        host: &Arc<dyn busbar_substrate::plane_host::EngineHost>,
        value: Value,
        id: Value,
        method: String,
    ) -> Option<Response> {
        // ── THE STDIO-ERA VOCABULARY ──────────────────────────────────────────────────────────
        // Four verbs and only four, each meaningful ONLY where a persistent connection exists,
        // which is why the HTTP table does not carry them (and the official suite asserts it does
        // not). `initialize` is the dual-era trigger the revision itself names for stdio; the
        // other three are session state a process can honestly hold. They are handled BEFORE the
        // `_meta` gate because a legacy-era client sends them without one — that is what the era
        // negotiation is FOR — and each is a complete answer, not a bypass: nothing here reaches
        // dispatch, the catalogue, or an upstream.
        match method.as_str() {
            "initialize" => return Some(self.initialize_result(id)),
            "ping" => return Some(json_result(id, serde_json::json!({}))),
            "logging/setLevel" => {
                let level = value
                    .get("params")
                    .and_then(|p| p.get("level"))
                    .and_then(|l| l.as_str());
                let Some(level) = level else {
                    return Some(envelope::error_response(
                        axum::http::StatusCode::BAD_REQUEST,
                        Some(id),
                        envelope::code::INVALID_PARAMS,
                        "`params.level` is required: the RFC 5424 severity this session's \
                         `notifications/message` records are filtered at.",
                        None,
                    ));
                };
                *self.level.lock().unwrap() = Some(level.to_string());
                return Some(json_result(id, serde_json::json!({})));
            }
            "resources/subscribe" | "resources/unsubscribe" => {
                let uri = value
                    .get("params")
                    .and_then(|p| p.get("uri"))
                    .and_then(|u| u.as_str());
                let Some(uri) = uri else {
                    return Some(envelope::error_response(
                        axum::http::StatusCode::BAD_REQUEST,
                        Some(id),
                        envelope::code::INVALID_PARAMS,
                        "`params.uri` is required: the resource to watch (or stop watching).",
                        None,
                    ));
                };
                if method.as_str() == "resources/subscribe" {
                    // The BASELINE is taken HERE, synchronously, under the caller's grant: the
                    // subscription's meaning is "tell me when it changes FROM WHAT IT IS NOW", and
                    // a baseline first taken by the watcher's next tick would swallow any change
                    // that lands in between — precisely the change a client subscribes right
                    // before making.
                    let fingerprint = self.visible_resource_fingerprint(host, uri);
                    self.resource_subs
                        .lock()
                        .unwrap()
                        .insert(uri.to_string(), fingerprint);
                } else {
                    self.resource_subs.lock().unwrap().remove(uri);
                }
                // Accepted for ANY uri, and `notifications/resources/updated` then fires only for
                // changes in the catalogue THIS CALLER CAN SEE — so the acceptance leaks nothing
                // about what exists, exactly as `tools/call` on a hidden tool answers the same
                // sentence as on a missing one.
                return Some(json_result(id, serde_json::json!({})));
            }
            _ => {}
        }
        // ── THE ONE DISPATCH ──────────────────────────────────────────────────────────────────
        let headers = synthesized_headers(&value);
        // The neutral host seam (minted `from_handle` in `dispatch_frame`, live-capable) threaded into
        // the SAME `rpc_dispatch` the HTTP handler runs, so the two transports reach the host seams
        // identically — the SOLE engine seam for the data path, live re-reads included.
        envelope::rpc_dispatch(
            host,
            &self.gov,
            &self.principal,
            &headers,
            value,
            id,
            method,
        )
        .await
    }

    /// The `initialize` answer: the dual-era negotiation the revision scopes to stdio. busbar
    /// implements ONE revision, and this result says so — `protocolVersion` names it, so a legacy
    /// client either speaks it from here on (per-request `_meta`) or disconnects, which is the
    /// negotiation completing in either direction. No session is created because the revision has
    /// none to create; `notifications/initialized` is accepted and moves nothing.
    fn initialize_result(&self, id: Value) -> Response {
        json_result(
            id,
            serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": { "listChanged": true },
                    "prompts": { "listChanged": true },
                    "resources": { "listChanged": true, "subscribe": true },
                    "completions": {},
                    "logging": {},
                },
                "serverInfo": {
                    "name": "busbar",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "instructions": format!(
                    "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required, \
                     and every request states its protocol version and client capabilities in \
                     `params._meta`."
                ),
            }),
        )
    }

    /// The session-shaped notifications a persistent channel can carry, observed after the core
    /// reader has established the frame IS a notification. Observation only — the `202`-shaped
    /// silence is core's, and nothing here answers.
    fn observe_notification(self: &Arc<Self>, method: &str, value: &Value) {
        match method {
            // The handshake acknowledgement of a client that sent `initialize`. There is no
            // session for it to arm, so accepting it IS the whole implementation — recorded so the
            // debug trail shows the handshake completing rather than vanishing.
            "notifications/initialized" => {
                tracing::debug!("mcp stdio serve: client completed the initialize handshake");
            }
            // `CANCEL.STDIO-CLIENT-SENDS`: on stdio there is no per-request stream to close, so
            // the notification IS the cancellation. Firing the caller's cancellation gate makes
            // that frame's handler `select` drop its dispatch and suppress its response
            // (`CANCEL.NO-FURTHER-MESSAGES`); a request already answered cleared its gate, which is
            // the race both parties must take gracefully.
            "notifications/cancelled" => {
                let request_id = value
                    .get("params")
                    .and_then(|p| p.get("requestId"))
                    .filter(|i| i.is_string() || i.is_number());
                if let Some(rid) = request_id {
                    if let Some(cancel) = self.inflight.lock().unwrap().remove(&id_key(rid)) {
                        let _ = cancel.send(());
                        tracing::debug!(request = %rid, "mcp stdio serve: request cancelled by the client");
                    }
                }
            }
            // The client's progress on an exchange busbar originated. There is no deadline to
            // extend — busbar's asks are bounded by ASK_TIMEOUT, deliberately — so the honest
            // meaning is the record. The pump owns the correlation table now, so whether the token
            // names a live ask is its business, not a fact this observer reads.
            "notifications/progress" => {
                tracing::debug!("mcp stdio serve: client progress noted");
            }
            // SEP-1036's out-of-band elicitation reply resolves its pending ask through the pump:
            // [`classify`](Session::classify) reads the `params.requestId` as the [`CallRef`] the
            // ask was issued under and the pump routes THIS notification frame straight to the
            // waiting `issue`, so a correlated one never reaches this observer. One that names no
            // (or an unknown) request is the only case that arrives here — nothing to resolve, and
            // dropping it is the whole implementation.
            "notifications/elicitation/response" => {
                tracing::debug!(
                    "mcp stdio serve: elicitation response named no pending ask; dropped"
                );
            }
            _ => {}
        }
    }

    /// DELIVER one dispatch's answer onto the channel: unwrap a stream, drive the live MRTR
    /// exchange, watch a task result, and finally write the caller's response.
    ///
    /// `depth` counts live ask rounds; `original` is the request body the retry re-derives from.
    async fn deliver(
        self: &Arc<Self>,
        caller_id: Option<Value>,
        original: Vec<u8>,
        response: Response,
        depth: u32,
    ) {
        // A notification's acknowledgement is HTTP furniture: the MUST NOT reply has no wire shape
        // on stdio other than silence.
        if response.status() == axum::http::StatusCode::ACCEPTED {
            return;
        }
        let is_stream = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        if is_stream {
            self.pump_stream(caller_id, response).await;
            return;
        }
        // A buffered body: one JSON-RPC envelope (every non-stream answer this plane produces).
        let (_parts, body) = response.into_parts();
        let bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => {
                // Do NOT return silently: the caller sent a request id and is waiting for a frame
                // that names it. Returning here writes nothing, so the CLIENT hangs forever on that
                // id. Log and write an error frame that names the caller's id, so the request is
                // answered and the client's own in-flight entry clears.
                tracing::debug!(error = %e, "mcp stdio serve: a buffered response body could not be read; answering the caller an error frame");
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": caller_id.unwrap_or(Value::Null),
                    "error": {
                        "code": -32603,
                        "message": "the response body could not be read",
                    },
                });
                self.emit(&err).await;
                return;
            }
        };
        let Ok(mut envelope_value) = serde_json::from_slice::<Value>(&bytes) else {
            // Not a JSON-RPC message (unreachable from this plane's own builders). Stderr, exactly
            // as the bridge delivers a body it may not put on stdout.
            // Diagnostic-only snippet, not data-of-record: the parse (over the FULL, unbounded
            // `bytes` above) already failed and the body is being suppressed regardless — this
            // 400-byte cap only bounds what a human sees in the stderr line.
            eprintln!(
                "busbar: mcp stdio serve: a non-JSON-RPC body was produced and suppressed: {}",
                String::from_utf8_lossy(&bytes[..bytes.len().min(400)])
            );
            return;
        };
        // THE LIVE MRTR EXCHANGE. An `input_required` result busbar composed is translated into
        // real requests on the channel; everything the seal protects is protected because the
        // retry re-enters the full sequence.
        let input_required = envelope_value
            .get("result")
            .and_then(|r| r.get("resultType"))
            .and_then(|t| t.as_str())
            == Some("input_required");
        if input_required && depth < MAX_LIVE_ASK_ROUNDS {
            if let Some(retry) = self
                .drive_asks(
                    &original,
                    envelope_value.get("result").unwrap_or(&Value::Null),
                )
                .await
            {
                let body = self.body_with_session_level(retry);
                let response = self.dispatch_frame(&body).await;
                return Box::pin(self.deliver(caller_id, body, response, depth + 1)).await;
            }
            // The client would not (or could not) answer live: hand it the result itself. The
            // sealed `requestState` makes that a continuation, not a dead end.
        }
        // The envelope's id is rewritten to the CALLER's own on the way out: a retry ran under an
        // internal id, and an answer the caller cannot correlate is not an answer.
        if let (Some(id), Some(obj)) = (caller_id.as_ref(), envelope_value.as_object_mut()) {
            if obj.contains_key("id") {
                obj.insert("id".to_string(), id.clone());
            }
        }
        self.emit(&envelope_value).await;
        self.watch_task_result(&envelope_value);
    }

    /// Issue the round's asks as live requests and build the RETRY body, or `None` when the client
    /// did not answer.
    async fn drive_asks(&self, original: &[u8], result: &Value) -> Option<Vec<u8>> {
        let requests = result.get("inputRequests")?.as_object()?;
        let state = result.get("requestState")?.as_str()?;
        let mut responses = serde_json::Map::new();
        for (key, ask) in requests {
            let method = ask.get("method").and_then(|m| m.as_str())?;
            let params = ask.get("params").cloned().unwrap_or(Value::Null);
            match self.issue_request(method, &params).await {
                Ok(answer) => {
                    responses.insert(key.clone(), answer);
                }
                Err(reason) => {
                    tracing::debug!(ask = %key, %reason, "mcp stdio serve: live ask not answered");
                    return None;
                }
            }
        }
        let mut retry: Value = serde_json::from_slice(original).ok()?;
        {
            let params = retry.get_mut("params")?.as_object_mut()?;
            params.insert("inputResponses".to_string(), Value::Object(responses));
            params.insert("requestState".to_string(), Value::from(state));
        }
        // PAT.MRTR.NEW-ID: the retry is an independent request. Internal, and mapped back to the
        // caller's id at delivery.
        retry.as_object_mut()?.insert(
            "id".to_string(),
            Value::from(format!(
                "busbar:retry:{}",
                self.ask_seq.fetch_add(1, Ordering::Relaxed)
            )),
        );
        serde_json::to_vec(&retry).ok()
    }

    /// Unwrap ONE SSE response stream onto the channel, live: each `data:` frame is one line, a
    /// comment keepalive becomes a `ping`, and an EARLY close (a lapsed permission) is announced
    /// with `notifications/cancelled` — the stream vocabulary of a transport that has no stream.
    async fn pump_stream(self: &Arc<Self>, caller_id: Option<Value>, response: Response) {
        use futures::StreamExt as _;
        let (_parts, body) = response.into_parts();
        let mut data = body.into_data_stream();
        let mut pending = String::new();
        let mut sub_meta: Option<Value> = None;
        let mut closed_gracefully = false;
        while let Some(chunk) = data.next().await {
            let Ok(chunk) = chunk else { break };
            pending.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(i) = pending.find('\n') {
                let line: String = pending.drain(..=i).collect();
                let line = line.trim_end_matches(['\n', '\r']);
                if let Some(frame) = line.strip_prefix("data:") {
                    let Ok(mut value) = serde_json::from_str::<Value>(frame.trim_start()) else {
                        continue;
                    };
                    let is_response = value
                        .as_object()
                        .is_some_and(|o| o.contains_key("result") || o.contains_key("error"));
                    if is_response {
                        closed_gracefully = value.get("result").is_some();
                        if let (Some(id), Some(obj)) = (caller_id.as_ref(), value.as_object_mut()) {
                            obj.insert("id".to_string(), id.clone());
                        }
                    } else if sub_meta.is_none() {
                        sub_meta = value.get("params").and_then(|p| p.get("_meta")).cloned();
                    }
                    self.emit(&value).await;
                } else if line.starts_with(':') {
                    // The keepalive of an idle subscription. On HTTP it is bytes on a stream; here
                    // the same liveness statement is a ping, which is what the persistent channel
                    // has for one. Fire-and-forget: the pong resolves the pending entry.
                    let session = self.clone();
                    let handle = tokio::spawn(async move {
                        let _ = session.issue_request("ping", &serde_json::json!({})).await;
                    });
                    self.background.lock().unwrap().push(handle.abort_handle());
                }
            }
        }
        // A stream that ended WITHOUT its graceful result was closed early — a lapsed permission
        // (the error frame preceded this) or a transport failure. On HTTP the closure is the
        // signal; here it is said out loud, in the one vocabulary the revision allows a server to
        // cancel with (`CANCEL.SERVER-ONLY-SUBSCRIPTIONS`: subscriptions, and nothing else).
        if let (Some(id), false) = (caller_id, closed_gracefully) {
            if let Some(meta) = sub_meta {
                self.emit(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {
                        "requestId": id,
                        "reason": "the subscription was closed by the server",
                        "_meta": meta,
                    },
                }))
                .await;
            }
        }
    }

    /// A result whose `resultType` is `task` gets a WATCHER: the task registry's transitions for
    /// it are pushed as `notifications/tasks` — the push the HTTP plane records as impossible
    /// (no stream category to carry it) and the persistent channel simply has.
    fn watch_task_result(self: &Arc<Self>, envelope_value: &Value) {
        let result = envelope_value.get("result");
        let is_task = result
            .and_then(|r| r.get("resultType"))
            .and_then(|t| t.as_str())
            == Some("task");
        if !is_task {
            return;
        }
        let Some(task_id) = result
            .and_then(|r| r.get("taskId"))
            .and_then(|t| t.as_str())
            .map(str::to_string)
        else {
            return;
        };
        let session = self.clone();
        let actor = self.principal.actor_id().to_string();
        // The BASELINE is the status the caller was handed ON the result itself: pushing that
        // again on the first poll would be an echo, and taking the first poll's reading as the
        // baseline instead would swallow any transition that lands before the poll runs — the
        // same subscribe-then-change race the resource watch closes the same way.
        let mut last_status = result
            .and_then(|r| r.get("status"))
            .and_then(|s| s.as_str())
            .map(str::to_string);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(WATCH_INTERVAL).await;
                let Some(task) = super::tasks::TASKS.get(&task_id, &actor) else {
                    return; // expired or swept — the TTL is the registry's statement, not ours
                };
                let detail = task.detailed();
                let status = detail
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                if last_status.as_deref() != Some(status.as_str()) {
                    last_status = Some(status.clone());
                    session
                        .emit(&serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/tasks",
                            "params": detail,
                        }))
                        .await;
                }
                if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
                    return;
                }
            }
        });
        self.background.lock().unwrap().push(handle.abort_handle());
    }

    /// The session's RESOURCE WATCH: the same generation poll `subscriptions/listen` runs, scoped
    /// to the URIs this session subscribed to, emitting `notifications/resources/updated` when a
    /// subscribed resource's REGISTRATION changes in the catalogue this caller can see.
    ///
    /// What busbar can truthfully say here is exactly what it can observe — its own snapshot swap
    /// re-registering the resource (a config apply, an admin edit, a re-observation). A content
    /// change at an upstream busbar is not told about remains unobservable and un-notified, which
    /// is the same honesty line `subscriptions/listen` draws when it narrows
    /// `resourceSubscriptions` away on HTTP; the difference on stdio is that the registration-
    /// level change has a channel it can truthfully ride.
    fn spawn_resource_watch(self: &Arc<Self>) {
        let session = self.clone();
        let handle = tokio::spawn(async move {
            let mut generation = super::runtime_of(&(session.factory)())
                .catalogue
                .generation();
            loop {
                tokio::time::sleep(WATCH_INTERVAL).await;
                // MINT A LIVE-CAPABLE HOST for THIS tick (one live re-read via the factory), and read
                // both the generation gate and every fingerprint below off its BOUND snapshot — so all
                // observe the SAME tick snapshot, byte-identical to the former single load per tick.
                let tick_host = (session.factory)();
                let live = super::runtime_of(&tick_host).catalogue.generation();
                // The generation compare is the cheap gate on the WALK, exactly as it is for
                // `subscriptions/listen`; the baselines were written at subscribe time, so an
                // unmoved generation has nothing to compare against.
                if live == generation {
                    continue;
                }
                generation = live;
                let subs: Vec<String> = {
                    let s = session.resource_subs.lock().unwrap();
                    s.keys().cloned().collect()
                };
                if subs.is_empty() {
                    continue;
                }
                for uri in subs {
                    let fingerprint = session.visible_resource_fingerprint(&tick_host, &uri);
                    let previous = {
                        let mut s = session.resource_subs.lock().unwrap();
                        match s.get_mut(&uri) {
                            // Unsubscribed while this walk ran — nothing to say about it.
                            None => continue,
                            Some(slot) => std::mem::replace(slot, fingerprint),
                        }
                    };
                    // A change is a VISIBLE registration that differs from a VISIBLE baseline. A
                    // resource appearing or vanishing is a LIST change, which is the list-changed
                    // notification's news, not this one's.
                    if let (Some(prev), Some(now)) = (previous, fingerprint) {
                        if prev != now {
                            session
                                .emit(&serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "method": "notifications/resources/updated",
                                    "params": { "uri": uri },
                                }))
                                .await;
                        }
                    }
                }
            }
        });
        self.background.lock().unwrap().push(handle.abort_handle());
    }

    /// The fingerprint of ONE resource as THIS session's caller can currently see it, or `None`
    /// when the caller's catalogue does not carry it.
    fn visible_resource_fingerprint(
        &self,
        host: &Arc<dyn busbar_substrate::plane_host::EngineHost>,
        uri: &str,
    ) -> Option<u64> {
        // BOUND reads off the caller's host — for the frame path the frame snapshot, for the
        // watch tick the tick snapshot; either way the SAME snapshot its caller already loaded.
        let rt = super::runtime_of(host);
        let caller = busbar_substrate::catalogue::Caller {
            key: self.gov.key(),
            // The fingerprint's snapshot instant through the neutral host seam (engine-independent).
            now: host.clock_now_secs(),
            generation: busbar_substrate::trust::validate::Generations::at_admission(
                rt.catalogue.generation(),
            ),
        };
        rt.catalogue
            .resources_for(&caller)
            .iter()
            .find(|r| r.namespaced == uri || r.uri == uri)
            .map(resource_fingerprint)
    }
}

/// The change key of one resource registration — FNV-1a over the row's rendered fields, the same
/// "a different value means re-read, and it is trusted for nothing" contract
/// `subscriptions/listen`'s change key states.
fn resource_fingerprint(r: &&super::catalogue::ResourceEntry) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in [
        r.uri.as_str(),
        r.name.as_deref().unwrap_or(""),
        r.description.as_deref().unwrap_or(""),
        r.mime_type.as_deref().unwrap_or(""),
        r.text.as_deref().unwrap_or(""),
        r.blob.as_deref().unwrap_or(""),
    ] {
        for byte in part.as_bytes().iter().chain(std::iter::once(&0u8)) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// One success envelope. Local to this module for the stdio-era verbs only — the method table's
/// own results are built by `method::result`, which stamps the `resultType` contract these
/// transport-level verbs do not participate in.
fn json_result(id: Value, result: Value) -> Response {
    use axum::response::IntoResponse as _;
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })),
    )
        .into_response()
}

/// The mirrored headers THIS BODY implies — derived, never invented, exactly as the battery's
/// stdio→HTTP adapter derives them (see the module header). The `Accept` preference is the
/// request's own stated asks translated into the framing negotiation's vocabulary: a request that
/// named a logging level or a progress token has asked for the frames only a stream can carry.
fn synthesized_headers(value: &Value) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let meta = value.get("params").and_then(|p| p.get("_meta"));
    let wants_stream = meta.is_some_and(|m| {
        m.get(super::sse::META_LOGGING_LEVEL).is_some()
            || m.get("progressToken").is_some_and(|t| !t.is_null())
    });
    let accept = if wants_stream {
        "text/event-stream, application/json"
    } else {
        "application/json, text/event-stream"
    };
    let _ = headers.insert("accept", axum::http::HeaderValue::from_static(accept));
    let insert = |headers: &mut HeaderMap, name: &'static str, value: &str| {
        if let Ok(v) = axum::http::HeaderValue::from_str(value) {
            headers.insert(name, v);
        }
    };
    if let Some(method) = value.get("method").and_then(|m| m.as_str()) {
        insert(
            &mut headers,
            H_MCP_METHOD,
            &super::client::jsonrpc::encode_sentinel(method),
        );
        if let Some(source) = envelope::name_source_of(method) {
            if let Some(name) = value
                .get("params")
                .and_then(|p| p.get(source))
                .and_then(|n| n.as_str())
            {
                insert(
                    &mut headers,
                    H_MCP_NAME,
                    &super::client::jsonrpc::encode_sentinel(name),
                );
            }
        }
    }
    if let Some(version) = meta
        .and_then(|m| m.get(META_PROTOCOL_VERSION))
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    {
        insert(&mut headers, H_PROTOCOL_VERSION, version);
    }
    headers
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/stdio_serve_tests.rs"]
mod stdio_serve_tests;
