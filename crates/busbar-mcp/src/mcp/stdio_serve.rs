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
//! same code. What this module owns is exactly what a TRANSPORT owns — framing (one JSON-RPC
//! message per line), the carrier for server-originated messages (the same stdout, since stdio has
//! no second channel), and the session lifecycle (EOF on stdin ends the process).
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
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use axum::response::Response;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};

use super::envelope::{
    self, McpWords, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, META_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
use busbar_core::state::AppHandle;

/// A NEUTRAL HOST FACTORY the stdio transport holds: given the session's per-frame LIVE `App`
/// snapshot it mints an `Arc<dyn EngineHost>` over it. Threaded in from the transport's core BOOT
/// boundary (the `busbar` binary's stdio start, or a test) rather than named here, so this plane
/// re-mints the host over each frame's live snapshot — required because the govern/meter/identity
/// reaches `rpc_dispatch` drives read config-derived state that differs per snapshot — WITHOUT ever
/// naming the core host factory itself.
pub(crate) type EngineHostFactory = Arc<
    dyn Fn(&Arc<busbar_core::state::App>) -> Arc<dyn busbar_substrate::plane_host::EngineHost>
        + Send
        + Sync,
>;

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
    handle: &Arc<AppHandle>,
    host_factory: &EngineHostFactory,
    credential: Option<&str>,
) -> Result<SessionIdentity, String> {
    let app = handle.load();
    let Some(resource) = super::resource(&app) else {
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
        match host_factory(&app).identity_audience_binding(token, resource.canonical_uri()) {
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
    let admitted = host_factory(&app)
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
pub async fn serve_stdio(handle: Arc<AppHandle>, host_factory: EngineHostFactory) -> i32 {
    let credential = std::env::var(ENV_CREDENTIAL).ok().filter(|c| !c.is_empty());
    let identity = match session_identity(&handle, &host_factory, credential.as_deref()).await {
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
    serve_io(handle, identity, tokio::io::stdin(), tokio::io::stdout()).await;
    0
}

/// The transport loop over ANY reader/writer pair — generic so the tests drive it over an
/// in-memory duplex with a REAL governed `App`, which is the only way the budget refusal can be
/// watched on an instrument without a network.
pub(crate) async fn serve_io<R, W>(
    handle: Arc<AppHandle>,
    identity: SessionIdentity,
    reader: R,
    writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let session = new_session(handle, identity, writer);
    run_session(session, reader).await;
}

/// Construct one live session (and start its watchers). Split from [`run_session`] so the
/// in-process battery can hold the session while driving the loop — nothing but tests and
/// [`serve_io`] call either.
fn new_session<W>(handle: Arc<AppHandle>, identity: SessionIdentity, writer: W) -> Arc<Session<W>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let session = Arc::new(Session {
        handle,
        principal: identity.principal,
        gov: identity.gov,
        out: tokio::sync::Mutex::new(writer),
        level: std::sync::Mutex::new(None),
        inflight: std::sync::Mutex::new(HashMap::new()),
        pending: std::sync::Mutex::new(HashMap::new()),
        ask_seq: AtomicU64::new(0),
        resource_subs: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        background: std::sync::Mutex::new(Vec::new()),
    });
    session.spawn_resource_watch();
    session
}

/// The read loop: frames in, the one pathway, shutdown on EOF.
async fn run_session<R, W>(session: Arc<Session<W>>, reader: R)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut lines = tokio::io::BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        // One frame per line, split on 0x0A exactly as the client leg reads a child. EOF — zero
        // bytes read — is the shutdown signal (`STDIO.EXIT-ON-EOF`); a final unterminated line is
        // still one frame, matching the battery's own byte-level driver.
        match lines.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                busbar_substrate::diag_debug!(busbar_substrate::diagnostics::MCP_STDIO_READ_ERROR, error = %e, "mcp stdio serve: read error on stdin; shutting down");
                break;
            }
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.iter().all(|b| b.is_ascii_whitespace()) {
            continue; // a blank line is not a frame — same rule the bridge and the client leg apply
        }
        let line = std::mem::take(&mut buf);
        // A RESPONSE is routed to the busbar-originated request awaiting it; it never reaches the
        // serve sequence, whose envelope reader rightly says a response is not a request. Anything
        // else — requests, notifications, garbage — takes the one pathway.
        if session.route_reply(&line) {
            continue;
        }
        let caller_id = envelope_id(&line);
        let key = caller_id.as_ref().map(id_key);
        let task_session = session.clone();
        let task_key = key.clone();
        let handle = tokio::spawn(async move {
            task_session.handle_frame(line, caller_id).await;
            if let Some(k) = task_key {
                task_session.inflight.lock().unwrap().remove(&k);
            }
        });
        // Registered by the caller's OWN id so a `notifications/cancelled` naming it can abort the
        // work and suppress every further message for it (`CANCEL.NO-FURTHER-MESSAGES`). The
        // register-after-spawn window is the cancellation race the specification tells both
        // parties to take gracefully: a cancel that wins it aborts nothing, exactly as a cancel
        // arriving after the answer does.
        if let Some(k) = key {
            session
                .inflight
                .lock()
                .unwrap()
                .insert(k, handle.abort_handle());
        }
    }
    // EOF: DRAIN the in-flight dispatches before exiting, bounded. A client that pipes one request
    // and closes stdin — the ordinary one-shot invocation — has EOF arrive ahead of the answer,
    // and aborting the dispatch there would serve nothing to exactly the caller who asked for
    // exactly one thing. The client-side shutdown sequence is close-then-WAIT-then-kill, so a
    // bounded drain is the shape it expects; a dispatch that outlives the bound (a hung upstream)
    // is abandoned rather than allowed to hold the process open indefinitely.
    let drain_deadline = tokio::time::Instant::now() + EOF_DRAIN;
    while !session.inflight.lock().unwrap().is_empty()
        && tokio::time::Instant::now() < drain_deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The watchers (and any still-running dispatch) die with the loop.
    for h in session.background.lock().unwrap().drain(..) {
        h.abort();
    }
    for (_, h) in session.inflight.lock().unwrap().drain() {
        h.abort();
    }
    let mut out = session.out.lock().await;
    let _ = out.flush().await;
}

/// How long EOF waits for in-flight dispatches to finish before the process exits anyway.
/// "Promptly" (`STDIO.EXIT-ON-EOF`) and "answer what was asked" meet here: enough for the
/// one-shot-pipe invocation (a request whose answer is computed in milliseconds, with EOF already
/// on the pipe), and short enough that a session closed with a subscription or a slow upstream
/// still in flight — dispatches that cannot or will not finish — exits on a bound a supervising
/// client's close-wait-kill sequence reads as prompt.
const EOF_DRAIN: Duration = Duration::from_secs(3);

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

struct Session<W> {
    /// THE LIVE HANDLE. Each frame and each watch tick mints a `from_handle` (live-capable)
    /// `EngineHost` off it (`engine_host_from_handle`), whose BOUND snapshot is that frame/tick's
    /// `handle.load()` and whose `plane_slot_live` re-reads the CURRENT snapshot — replacing the
    /// former per-frame snapshot-only host from the retired `host_factory` field.
    handle: Arc<AppHandle>,
    principal: busbar_api::AuthPrincipal,
    gov: busbar_api::PlaneRequestCtx,
    /// ONE writer, one lock: two concurrent responses interleaving inside a line would be a frame
    /// no reader could parse, which is the transport's one absolute rule.
    out: tokio::sync::Mutex<W>,
    /// The session logging floor `logging/setLevel` sets. Injected into a request's `_meta` only
    /// when the request names none of its own — the per-request spelling still wins, so an HTTP
    /// client's semantics are unchanged by the session having a default.
    level: std::sync::Mutex<Option<String>>,
    /// In-flight dispatches by the caller's request id, for `notifications/cancelled`.
    inflight: std::sync::Mutex<HashMap<String, tokio::task::AbortHandle>>,
    /// Busbar-originated requests awaiting the client's response, by id key.
    pending: std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<Result<Value, String>>>>,
    ask_seq: AtomicU64,
    /// URIs the client subscribed to with `resources/subscribe`, each with the LAST fingerprint of
    /// its caller-visible registration — `None` for a subscription whose subject is not (or not
    /// yet) in the caller's catalogue. The baseline is written at subscribe time; the watcher
    /// compares on every generation move.
    resource_subs: std::sync::Mutex<std::collections::BTreeMap<String, Option<u64>>>,
    /// Watcher tasks aborted at EOF.
    background: std::sync::Mutex<Vec<tokio::task::AbortHandle>>,
}

impl<W: AsyncWrite + Unpin + Send + 'static> Session<W> {
    /// Write ONE JSON-RPC message as one line. `serde_json` emits no raw newline, so the framing
    /// MUST (`STDIO.NO-EMBEDDED-NEWLINES`) holds by construction.
    async fn emit(&self, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
        bytes.push(b'\n');
        let mut out = self.out.lock().await;
        let _ = out.write_all(&bytes).await;
        let _ = out.flush().await;
    }

    /// Route a frame that is a RESPONSE to a busbar-originated request. `true` when consumed.
    fn route_reply(&self, line: &[u8]) -> bool {
        let Ok(value) = serde_json::from_slice::<Value>(line) else {
            return false;
        };
        let Some(obj) = value.as_object() else {
            return false;
        };
        if obj.contains_key("method") {
            return false; // a request or notification — the serve sequence's business
        }
        if !(obj.contains_key("result") || obj.contains_key("error")) {
            return false;
        }
        let Some(id) = obj.get("id").filter(|i| i.is_string() || i.is_number()) else {
            return false;
        };
        let Some(tx) = self.pending.lock().unwrap().remove(&id_key(id)) else {
            // A response to a request nobody sent. Not consumed: the core envelope reader owns the
            // complaint, and answers it in the shared vocabulary.
            return false;
        };
        let outcome = match busbar_substrate::ingress::jsonrpc::read_response(&value, id) {
            Ok(busbar_substrate::ingress::jsonrpc::Reply::Result(result)) => Ok(result),
            Ok(busbar_substrate::ingress::jsonrpc::Reply::Error { code, message }) => Err(format!(
                "the client answered with an error ({code:?}): {message}"
            )),
            Err(not_answer) => Err(not_answer.to_string()),
        };
        let _ = tx.send(outcome);
        true
    }

    /// Issue ONE busbar-originated request on the channel and await the client's answer.
    async fn issue_request(&self, method: &str, params: &Value) -> Result<Value, String> {
        let id = Value::from(format!(
            "busbar:{}",
            self.ask_seq.fetch_add(1, Ordering::Relaxed)
        ));
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().unwrap().insert(id_key(&id), tx);
        self.emit(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .await;
        let outcome = tokio::time::timeout(ASK_TIMEOUT, rx).await;
        self.pending.lock().unwrap().remove(&id_key(&id));
        match outcome {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => Err("the session ended before the client answered".to_string()),
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
        // MINT THE NEUTRAL HOST over THIS frame's live snapshot, `from_handle` so the host is
        // live-capable (its `plane_slot_live` re-reads the CURRENT snapshot for the dispatch-time
        // re-validation and per-round grant re-reads deep in `method`), while its BOUND snapshot is
        // this frame's `handle.load()` — byte-identical to the former per-frame `app` load, and used
        // for every BOUND read below through the `runtime_of`/`resource_of` funnel.
        let host = busbar_core::plane_host::engine_host_from_handle(&self.handle);
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
        // identically. `handle` rides alongside SOLELY for the deferred sampling→ingress leg (still
        // `&Arc<App>`-typed); every other reach goes through `host`.
        envelope::rpc_dispatch(
            &self.handle,
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
            // the notification IS the cancellation. The in-flight dispatch is aborted and its
            // response suppressed with it (`CANCEL.NO-FURTHER-MESSAGES`); a request already
            // answered has nothing to abort, which is the race both parties must take gracefully.
            "notifications/cancelled" => {
                let request_id = value
                    .get("params")
                    .and_then(|p| p.get("requestId"))
                    .filter(|i| i.is_string() || i.is_number());
                if let Some(rid) = request_id {
                    if let Some(handle) = self.inflight.lock().unwrap().remove(&id_key(rid)) {
                        handle.abort();
                        tracing::debug!(request = %rid, "mcp stdio serve: request cancelled by the client");
                    }
                }
            }
            // The client's progress on an exchange busbar originated. There is no deadline to
            // extend — busbar's asks are bounded by ASK_TIMEOUT, deliberately — so the honest
            // meaning is the record: correlated to the pending ask when the token names one.
            "notifications/progress" => {
                let token = value.get("params").and_then(|p| p.get("progressToken"));
                let pending = token
                    .map(id_key)
                    .map(|k| self.pending.lock().unwrap().contains_key(&k))
                    .unwrap_or(false);
                tracing::debug!(
                    correlated = pending,
                    "mcp stdio serve: client progress noted"
                );
            }
            // SEP-1036's out-of-band elicitation reply, admissible HERE and refused over HTTP for
            // a reason worth restating: over HTTP it arrives on no request and could be anyone's;
            // on stdio it arrives on the ONE authenticated single-caller channel, naming the id of
            // an elicitation busbar itself issued on that same channel, so the binding the HTTP
            // waiver said was impossible is exactly what the transport provides. It resolves the
            // pending ask as if the client had answered the request directly.
            "notifications/elicitation/response" => {
                let request_id = value
                    .get("params")
                    .and_then(|p| p.get("requestId"))
                    .filter(|i| i.is_string() || i.is_number());
                let Some(rid) = request_id else {
                    tracing::debug!(
                        "mcp stdio serve: elicitation response named no `params.requestId`; dropped"
                    );
                    return;
                };
                let Some(tx) = self.pending.lock().unwrap().remove(&id_key(rid)) else {
                    tracing::debug!(
                        "mcp stdio serve: elicitation response named no pending ask; dropped"
                    );
                    return;
                };
                let content = value
                    .get("params")
                    .and_then(|p| p.get("response"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let _ = tx.send(Ok(content));
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
        let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
            return;
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
            let mut generation = super::runtime_of(
                &busbar_core::plane_host::engine_host_from_handle(&session.handle),
            )
            .catalogue
            .generation();
            loop {
                tokio::time::sleep(WATCH_INTERVAL).await;
                // MINT A LIVE-CAPABLE HOST for THIS tick (one `handle.load()`, a live re-read), and read both the
                // generation gate and every fingerprint below off its BOUND snapshot — so all observe
                // the SAME tick snapshot, byte-identical to the former single `handle.load()` per tick.
                let tick_host = busbar_core::plane_host::engine_host_from_handle(&session.handle);
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

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/stdio_serve_tests.rs"]
mod stdio_serve_tests;
