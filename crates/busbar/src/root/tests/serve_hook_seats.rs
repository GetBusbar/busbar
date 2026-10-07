// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAT ORDER OF THE REQUEST-STAGE HOOKS, ON THE DOOR (ported from the predev-only `busbar-llm`
//! test `hook_seat_order_tests`, BUSBAR-1.6.0.md Part 5 F25: before any engine deletion every test
//! names its new home). The llm plane served through its door, end to end: a keyed caller behind
//! the data listener's auth gate, admitted and charged by the door's money steps, its unit's hooks
//! bound by the kernel's hook stage (the global rewrite, the request-stage tap, a decision gate and
//! the candidate tap), its far end a real loopback upstream through the process connector. The
//! admission door charges the request first, then the global rewrite runs, then the request-stage
//! tap observes the REWRITTEN request, then the decision gate decides, and only after the gate does
//! the candidate tap fire. A gate reject refunds the billable request (the fee base) but keeps the
//! admission count.
//!
//! Every seat is proven structurally rather than by wall-clock order where the seat is a detached
//! task (taps are fire-and-forget): the rewrite hook reads the ledger AT the moment it runs, the
//! request tap's payload carries the rewritten prompt, and a rejecting gate stops everything seated
//! after it — so a request tap that still arrives was seated before the gate and a candidate tap
//! that never arrives was seated after it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_contract::hooks::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::hooks::ResolvedPolicy;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::{composed_services, Published, PUBLISHING};
use super::{compose_planes, door_routes, DoorEgress, HookStage};
use crate::root::door_steps::{kernel_sections, provider_routes, DoorReach, OutboundAuths};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::root::plane_node::{Node, NodeEndPost};

// The plane the node is handed, as the manifest's linked table names it (the `node` axis): the
// legacy row's test seams the registry rows that own the `pools:`/`models:` sections come from.
include!(concat!(env!("OUT_DIR"), "/node_plane.rs"));

/// THE LINKED DOOR THAT SERVES THE `pools` MAP, found by what its Statement declares (the composition
/// root names no plane): every linked plane door bound on a probe dispatcher of its own, the one
/// whose declaring section is `pools` kept.
fn pools_door() -> busbar_contract::abi::mechanism::door::DoorFn {
    crate::LINKED
        .plane_doors
        .iter()
        .copied()
        .find(|door| {
            let probe = Dispatcher::new(DispatchConfig::default());
            let row = LinkedRow::of(*door).expect("a linked door states itself");
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("pools-door-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: probe.adopter(),
                    conns: None,
                },
            )
            .expect("a linked door binds")
            .served()
            .section
                == busbar_contract::section::RESERVED_POOLS_KEY
        })
        .expect("the fold switch links the door serving the `pools` map")
}

/// The card history the served unit is pinned to at its door: one entry, no price.
static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| {
        let holder = crate::root::kernel::RootHistory::default();
        holder.apply(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                true,
            ),
            1_000,
        );
        holder
    });

/// The marker the rewrite hook plants in the prompt; a tap payload carrying it saw the rewrite.
pub(super) const REWRITTEN: &str = "rewritten-by-the-global-rewrite-seat";

/// The far end's answer: an openai chat completion.
const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// One probe policy playing one seat: it appends its seat name to the shared log when it runs and
/// (for the rewrite seat) samples the key's admission count at that instant.
struct SeatProbe {
    seat: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    /// Rewrite seat only: reads the key's `requests` count when the rewrite runs.
    requests_now: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
    /// Gate seat only: the reject the gate answers with.
    reject: Option<(u16, &'static str)>,
    /// Tap seats: the last delivered projection.
    last_payload: Mutex<Option<Vec<u8>>>,
    /// Gate seat: each candidate the last decide was shown, as one line.
    candidates: Mutex<Vec<String>>,
    /// Gate seat: each candidate's signal bag, as the last decide was shown it.
    bags: Mutex<Vec<busbar_contract::SignalBag>>,
}

impl SeatProbe {
    fn new(seat: &'static str, log: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            seat,
            log: log.clone(),
            requests_now: None,
            reject: None,
            last_payload: Mutex::new(None),
            candidates: Mutex::new(Vec::new()),
            bags: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for SeatProbe {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        self.log.lock().unwrap().push(self.seat.to_string());
        *self.bags.lock().unwrap() = candidates.iter().map(|c| c.signals.clone()).collect();
        *self.candidates.lock().unwrap() = candidates
            .iter()
            .map(|c| {
                format!(
                    "{} tier={:?} tags={:?} latency={} avail={} budget={:?} signals={:?}",
                    c.model,
                    c.tier,
                    c.tags,
                    c.latency_ms.is_some(),
                    c.available_concurrency > 0,
                    c.budget_remaining,
                    c.signals
                        .iter()
                        .map(|(s, v)| format!(
                            "{s:?}={}",
                            match v {
                                busbar_contract::SignalValue::Str(t) => t.to_string(),
                                other => format!(
                                    "{}",
                                    matches!(
                                        other,
                                        busbar_contract::SignalValue::F64(_)
                                            | busbar_contract::SignalValue::U64(_)
                                    )
                                ),
                            }
                        ))
                        .collect::<Vec<_>>()
                )
            })
            .collect();
        Ok(match self.reject {
            Some((status, message)) => RoutingDecision::Reject {
                status,
                message: message.to_string(),
            },
            None => RoutingDecision::Abstain,
        })
    }
    fn name(&self) -> &'static str {
        self.seat
    }
    async fn transform(
        &self,
        _req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> TransformOutcome {
        let requests = self.requests_now.as_ref().map(|f| f());
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:requests={:?}", self.seat, requests));
        TransformOutcome::Rewrite(RewriteReply {
            messages: vec![serde_json::json!({"role": "user", "content": REWRITTEN})],
            tools: vec![],
        })
    }
    async fn notify(
        &self,
        tap: std::sync::Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        _budget: std::time::Duration,
    ) {
        let projection = serde_json::to_vec(&tap.projection_json()).expect("the tap's JSON");
        self.log.lock().unwrap().push(self.seat.to_string());
        *self.last_payload.lock().unwrap() = Some(projection);
    }
}

fn gate(policy: Arc<dyn RoutingPolicy>) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy,
        on_error: busbar_kernel::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_kernel::config::PolicyOnError::Reject,
    }
}

/// Poll a tap probe until its detached delivery lands (bounded), or return `None`.
async fn delivered(tap: &SeatProbe, budget_ms: u64) -> Option<Vec<u8>> {
    for _ in 0..(budget_ms / 10) {
        if let Some(p) = tap.last_payload.lock().unwrap().clone() {
            return Some(p);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    None
}

/// A FAR END ON LOOPBACK: every request it reads is answered with its status and body; it counts
/// the requests it served and keeps each one's `authorization` field.
pub(super) struct FarEnd {
    /// Its port.
    pub port: u16,
    /// The requests it served.
    pub hits: Arc<std::sync::atomic::AtomicUsize>,
    /// Each served request's `authorization` field, as received.
    pub authorizations: Arc<Mutex<Vec<String>>>,
}

impl FarEnd {
    /// The requests it served so far.
    pub fn served(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// What a scripted far end writes for each request it reads: its raw head, then each piece after
/// its delay, then (when `finish` is set) the closing bytes; it then closes the connection, so a
/// script whose head promises more than it writes is a far end that CUT its answer.
#[derive(Clone)]
pub(super) struct Script {
    /// The status line and head fields, through the blank line.
    pub head: String,
    /// Each piece of the body, after its delay in milliseconds.
    pub pieces: Vec<(u64, Vec<u8>)>,
    /// The bytes that complete the body (a chunked body's last chunk); `None` cuts it.
    pub finish: Option<Vec<u8>>,
}

/// One chunk of a chunked body.
pub(super) fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}

/// A far end on loopback answering every request by `script`.
pub(super) async fn far_end_scripted(script: Script) -> FarEnd {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let authorizations = Arc::new(Mutex::new(Vec::new()));
    let (served, seen) = (Arc::clone(&hits), Arc::clone(&authorizations));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (served, seen, script) = (Arc::clone(&served), Arc::clone(&seen), script.clone());
            tokio::spawn(async move {
                let Some(head) = read_request(&mut socket).await else {
                    return;
                };
                served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                seen.lock().unwrap().push(head);
                if socket.write_all(script.head.as_bytes()).await.is_err() {
                    return;
                }
                for (delay, piece) in &script.pieces {
                    tokio::time::sleep(std::time::Duration::from_millis(*delay)).await;
                    if socket.write_all(piece).await.is_err() {
                        return;
                    }
                    let _ = socket.flush().await;
                }
                if let Some(finish) = &script.finish {
                    let _ = socket.write_all(finish).await;
                }
                let _ = socket.shutdown().await;
            });
        }
    });
    FarEnd {
        port,
        hits,
        authorizations,
    }
}

/// Read one request off `socket` through its body; its `authorization` field (empty when none),
/// or `None` when the connection closed first.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut got = Vec::new();
    loop {
        let n = socket.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        got.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&got).to_string();
        if let Some(at) = text.find("\r\n\r\n") {
            let field = |name: &str| {
                text[..at].lines().find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                })
            };
            let length = field("content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            if got.len() >= at + 4 + length {
                return Some(field("authorization").unwrap_or_default());
            }
        }
    }
}

/// A far end on loopback answering every request with `status` and `body` (JSON).
pub(super) async fn far_end_answering(status: u16, body: &'static str) -> FarEnd {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let authorizations = Arc::new(Mutex::new(Vec::new()));
    let (served, seen) = (Arc::clone(&hits), Arc::clone(&authorizations));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (served, seen) = (Arc::clone(&served), Arc::clone(&seen));
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut got = Vec::new();
                let head = loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(at) = text.find("\r\n\r\n") {
                        let field = |name: &str| {
                            text[..at].lines().find_map(|l| {
                                let (n, v) = l.split_once(':')?;
                                n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                            })
                        };
                        let length = field("content-length")
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            break field("authorization").unwrap_or_default();
                        }
                    }
                };
                served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                seen.lock().unwrap().push(head);
                let reason = if status == 200 { "OK" } else { "Error" };
                let reply = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    FarEnd {
        port,
        hits,
        authorizations,
    }
}

/// A far end on loopback answering every request with [`ANSWER`].
async fn far_end() -> u16 {
    far_end_answering(200, ANSWER).await.port
}

/// The key's ledger as the test reads it: (admission count, derived spend in cents, the durable
/// row's admission count, the durable row's billable count).
pub(super) type Ledger = (u64, i64, u64, u64);

/// What a run left: the caller's status, the seat log, the two tap probes and the ledger reader.
struct Ran {
    status: u16,
    log: Arc<Mutex<Vec<String>>>,
    request_tap: Arc<SeatProbe>,
    candidate_tap: Arc<SeatProbe>,
    read: Arc<dyn Fn() -> Ledger + Send + Sync>,
}

/// HOW A RIG IS BUILT: the far ends of its pool `p`'s members (each a model `m<i>` on a provider
/// of its own, at `weight`), the gate's verdict, and the key's all-time budget.
#[derive(Clone, Copy, Default)]
pub(super) struct RigOpts<'a> {
    /// Each member's far-end port and weight, in order.
    pub members: &'a [(u16, u32)],
    /// The global gate rejects with 451.
    pub reject_at_gate: bool,
    /// The key's group holds this many cents a day (a flat 1-cent fee per request).
    pub budget_cents: Option<u64>,
    /// The key's group holds this many tokens a minute.
    pub tokens_per_minute: Option<u64>,
    /// How many of the members (the first ones) pool `p` holds; the rest are models no pool
    /// names. `None`: all of them.
    pub pooled: Option<usize>,
    /// The pools the key may reach (`None`: every pool).
    pub allowed_pools: Option<&'a [&'a str]>,
    /// The members' dialect (`None`: `openai`).
    pub dialect: Option<&'a str>,
    /// Each pool member states a tier `t<i>` and a tag `g<i>`, and the generation declares the
    /// three candidate catalog signals (breaker state, error rate, p95 latency).
    pub described: bool,
    /// Pool `p`'s `failover.timeout_secs` (`None`: the default).
    pub failover_timeout_secs: Option<u64>,
    /// The node's stream ceiling, in seconds (`None`: 600).
    pub stream_ceiling_secs: Option<u64>,
    /// Pool `p`'s `affinity.header_name` (`None`: the pool states no affinity block).
    pub affinity_header: Option<&'a str>,
    /// Each member's lifetime request budget (`None`: unlimited).
    pub lane_budget: Option<i64>,
    /// Pool `p` is ranked by an abstaining policy that is shown the candidates, and the generation
    /// declares exactly these catalog signals (`None`: as [`Self::described`] says).
    pub signals: Option<&'a [busbar_contract::Signal]>,
    /// The plane's owned webhook section configures its `openai` receiver, its callers verified under the
    /// `webhook-signature` scheme by a Standard Webhooks instance holding [`WEBHOOK_SECRET`].
    pub webhook: bool,
    /// Each member's model name (`None`: `m<i>`).
    pub names: Option<&'a [&'a str]>,
    /// Lines written under member `i`'s model entry (the rig indents them as its fields).
    pub model_yaml: &'a [(usize, &'a str)],
    /// Lines written under member `i`'s entry in pool `p` (the rig indents them as its fields).
    pub member_yaml: &'a [(usize, &'a str)],
    /// Lines written under pool `p` (the rig indents them as its fields).
    pub pool_yaml: Option<&'a str>,
    /// Further pools beside `p`: each its name, its members (by index, weight 1) and lines written
    /// under it.
    pub pools: &'a [(&'a str, &'a [usize], &'a str)],
    /// Further limits on the key's group (its all-time `budget_cents` one, when set, first); a
    /// group is made for them when `budget_cents` makes none.
    pub limits: &'a [busbar_kernel::config::groups::LimitCfg],
    /// The deployment's data front door is open (no `keys` chain): an unkeyed caller is admitted
    /// anonymously.
    pub open: bool,
    /// The deployment's `limits.upstream_request_timeout_secs`: the transports' wait for a far
    /// end's head, and (unless `stream_ceiling_secs` says otherwise) the stream ceiling.
    pub upstream_request_timeout_secs: Option<u64>,
    /// No hook is bound: the four probed seats (and a ranker) are left out of the generation.
    pub hookless: bool,
}

/// The Standard Webhooks signing secret the rig's `webhook-signature` instance holds (`whsec_` +
/// base64 of the key [`WEBHOOK_KEY`]).
pub(super) const WEBHOOK_KEY: &[u8] = b"busbar-webhook-test-key-0123456789";

/// [`WEBHOOK_KEY`] as the secret's configured spelling.
pub(super) fn webhook_secret() -> String {
    use base64::Engine as _;
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode(WEBHOOK_KEY)
    )
}

/// THE `webhook-signature` INSTANCE the rig's App serves the scheme with: the linked auth row,
/// opened through the root's auth axis with Standard Webhooks settings and [`webhook_secret`].
fn webhook_schemes() -> busbar_kernel::auth::inbound::InboundSchemes {
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    busbar_kernel::preflight::install_auth_axis(crate::root::dispatch::auth_axis);
    let registry = Arc::new(
        busbar_kernel::preflight::plugins_preflight(
            None,
            None,
            &busbar_kernel::config::IdentityProviders::new(),
            &HashMap::new(),
            &busbar_kernel::config::PluginsCfg::default(),
            &busbar_kernel::config::ExportCfg::default(),
        )
        .expect("the linked rows"),
    );
    let door = crate::root::dispatch::auth_axis(registry)
        .open(
            "busbar-auth-webhook-signature",
            "identity-providers.openai-hooks",
            &serde_json::json!({"variant": "standard-webhooks", "signing-secret": webhook_secret()}),
        )
        .expect("the linked webhook-signature row opens");
    busbar_kernel::auth::inbound::InboundSchemes::opened(HashMap::from([(
        "webhook-signature".to_string(),
        vec![door],
    )]))
}

/// THE LLM DOOR, SERVED END TO END, as production composes it: the data router built with the
/// door's claims, a keyed caller's token, the generation's App and the node's book.
pub(super) struct DoorRig {
    /// The data router.
    pub router: axum::Router,
    /// The caller's bearer token.
    pub token: String,
    /// The generation.
    pub app: Arc<busbar_kernel::state::App>,
    /// The node's book: every unit's line and audit record.
    pub book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    /// The key's id.
    pub key_id: String,
    log: Arc<Mutex<Vec<String>>>,
    request_tap: Arc<SeatProbe>,
    candidate_tap: Arc<SeatProbe>,
    gate_seat: Arc<SeatProbe>,
    read: Arc<dyn Fn() -> Ledger + Send + Sync>,
    tokens: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// The boot's answer to the composed planes' public route schemes (`refuse_unserved`): over no
    /// `identity-providers:` at all, then over one entry serving `webhook-signature`.
    pub scheme_check: (Result<(), String>, Result<(), String>),
    /// The public routes the composed planes state: `(verb, target)`.
    pub public_routes: Vec<(String, String)>,
    /// Every served plane's config apply (`Served::appliers`), kept before the planes moved into
    /// the data routes.
    pub appliers: super::DoorAppliers,
    /// What a config apply re-seals the egress over, as production keeps it from the boot: the
    /// connector, the auth plugins and the journal.
    pub conns: Arc<dyn PollConns>,
    /// The auth plugins.
    pub auths: Arc<OutboundAuths>,
    /// The journal.
    pub journal: Arc<dyn busbar_kernel_egress::ports::Journal>,
}

impl DoorRig {
    /// Each candidate the pool's ranking policy was last shown, one line each.
    pub fn gate_saw(&self) -> Vec<String> {
        self.gate_seat.candidates.lock().unwrap().clone()
    }

    /// Each candidate's signal bag, as the pool's ranking policy was last shown it.
    pub fn ranker_bags(&self) -> Vec<busbar_contract::SignalBag> {
        self.gate_seat.bags.lock().unwrap().clone()
    }

    /// One request through the door as the keyed caller: its status, head and body.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, axum::http::HeaderMap, Vec<u8>) {
        let response = self.open(method, path, body, &[]).await;
        let status = response.status().as_u16();
        let head = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body")
            .to_vec();
        (status, head, bytes)
    }

    /// One request through the door as the keyed caller, with `fields` beside its own: the
    /// response, its body unread.
    pub async fn open(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        fields: &[(&str, &str)],
    ) -> axum::response::Response {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", self.token));
        for (name, value) in fields {
            req = req.header(*name, *value);
        }
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let req = req
            .body(match body {
                Some(b) => axum::body::Body::from(b.to_string()),
                None => axum::body::Body::empty(),
            })
            .expect("a request");
        self.router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers")
    }

    /// The tokens on the key's ledger once they are nonzero or the wait is spent (the accrual is
    /// write-behind).
    pub async fn tokens_after(&self) -> u64 {
        let mut tokens = (self.tokens)();
        for _ in 0..100 {
            if tokens != 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            tokens = (self.tokens)();
        }
        tokens
    }

    /// One chat completion on pool `p`.
    pub async fn chat(&self) -> (u16, axum::http::HeaderMap, Vec<u8>) {
        self.send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "p", "max_tokens": 16,
                "messages": [{"role": "user", "content": "the original prompt"}]})),
        )
        .await
    }

    /// The key's ledger, once its last unit's money settled (bounded).
    pub async fn ledger_after(&self, billable: u64) -> Ledger {
        let mut ledger = (self.read)();
        for _ in 0..200 {
            if ledger.3 >= billable {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            ledger = (self.read)();
        }
        ledger
    }

    /// The audit records the node's book sealed so far.
    pub fn audit_records(&self) -> usize {
        self.book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .audit_records
            .len()
    }
}

/// BUILD THE RIG: the door serving the `pools` map, linked and bound through the loader's one load
/// on the process connector, over `opts`' far ends, its egress the model-serving walk over the
/// kernel's lane cells, its hooks the kernel's stage with the four probed seats installed.
pub(super) async fn rig(instance: &'static str, opts: RigOpts<'_>) -> DoorRig {
    // The registry rows that own the `pools:`/`models:` sections the deployment writes.
    node_plane::testkit::install_test_seams();
    busbar_kernel::metrics::init();
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let transport_settings = {
        let mut s = busbar_contract::transport::TransportSettings::default();
        if let Some(secs) = opts.upstream_request_timeout_secs {
            s.request_timeout_secs = secs;
        }
        s
    };
    let connector = busbar_core_connector::process::build(
        || crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &transport_settings),
        judge,
        &[],
        Arc::new(|_| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
    )
    .expect("the connector builds");

    // THE LLM DOOR, linked, bound through the loader's one load, its needs declared on the
    // connector.
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(pools_door()).expect("the door states itself");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: Some(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
        },
    )
    .expect("the linked door binds");

    // THE DEPLOYMENT: one openai provider per member, one model per provider, pool `p` over them.
    let key_file = std::env::temp_dir().join(format!(
        "busbar-hook-seats-{}-{instance}",
        std::process::id()
    ));
    std::fs::write(&key_file, "sk-seats").expect("the credential file");
    let name = |i: usize| {
        opts.names
            .and_then(|n| n.get(i))
            .map_or_else(|| format!("m{i}"), |n| (*n).to_string())
    };
    let indent = |lines: &str, by: usize| -> String {
        lines
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| format!("{:by$}{l}\n", ""))
            .collect()
    };
    let mut yaml = String::from("providers:\n");
    for (i, _) in opts.members.iter().enumerate() {
        yaml.push_str(&format!(
            "  oai{i}:\n    api_key: {{ file: '{}' }}\n",
            key_file.display()
        ));
    }
    yaml.push_str("models:\n");
    for (i, _) in opts.members.iter().enumerate() {
        yaml.push_str(&format!("  '{}':\n    provider: oai{i}\n", name(i)));
        for (_, lines) in opts.model_yaml.iter().filter(|(at, _)| *at == i) {
            yaml.push_str(&indent(lines, 4));
        }
    }
    yaml.push_str("pools:\n  p:\n    members:\n");
    let pooled = opts.pooled.unwrap_or(opts.members.len());
    for (i, (_, weight)) in opts.members.iter().enumerate().take(pooled) {
        yaml.push_str(&format!(
            "      - model: '{}'\n        weight: {weight}\n",
            name(i)
        ));
        if opts.described {
            yaml.push_str(&format!("        tier: t{i}\n        tags: [g{i}]\n"));
        }
        for (_, lines) in opts.member_yaml.iter().filter(|(at, _)| *at == i) {
            yaml.push_str(&indent(lines, 8));
        }
    }
    if let Some(secs) = opts.failover_timeout_secs {
        yaml.push_str(&format!("    failover:\n      timeout_secs: {secs}\n"));
    }
    if let Some(header) = opts.affinity_header {
        yaml.push_str(&format!(
            "    affinity:\n      mode: session\n      header_name: {header}\n"
        ));
    }
    if let Some(lines) = opts.pool_yaml {
        yaml.push_str(&indent(lines, 4));
    }
    for (pool, members, lines) in opts.pools {
        yaml.push_str(&format!("  {pool}:\n    members:\n"));
        for i in *members {
            yaml.push_str(&format!(
                "      - model: '{}'\n        weight: 1\n",
                name(*i)
            ));
        }
        yaml.push_str(&indent(lines, 4));
    }
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("a deployment");
    let mut defs_yaml = String::new();
    for (i, (port, _)) in opts.members.iter().enumerate() {
        defs_yaml.push_str(&format!(
            "oai{i}:\n  protocol: {}\n  base_url: 'http://127.0.0.1:{port}'\n",
            opts.dialect.unwrap_or("openai")
        ));
    }
    let defs: HashMap<String, busbar_kernel::config::ProviderDef> =
        serde_yaml::from_str(&defs_yaml).expect("the providers");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let providers = provider_routes(&cfg.providers);
    let mut sections = kernel_sections(&cfg);
    if opts.webhook {
        // The plane's one owned section, by the name its Statement states.
        let owned = *plane
            .served()
            .owns
            .first()
            .expect("the door states its webhook section");
        sections.insert(
            owned,
            serde_yaml::from_str("{openai: {style: webhook-signature}}").expect("the section"),
        );
    }
    let model_pools = crate::root::model_egress::ModelPools::of(&cfg);

    // THE MONEY: a signing governance book with one minted key (in a budgeted group when asked),
    // the node's book bound.
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let limit = |metric, amount, per| busbar_kernel::config::groups::LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    let limits: Vec<busbar_kernel::config::groups::LimitCfg> = opts
        .budget_cents
        .map(|amount| {
            limit(
                busbar_kernel::config::groups::LimitMetric::Budget,
                amount,
                busbar_kernel::config::groups::LimitWindow::Day,
            )
        })
        .into_iter()
        .chain(opts.tokens_per_minute.map(|amount| {
            limit(
                busbar_kernel::config::groups::LimitMetric::Tokens,
                amount,
                busbar_kernel::config::groups::LimitWindow::Minute,
            )
        }))
        .chain(opts.limits.iter().cloned())
        .collect();
    let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = (!limits.is_empty())
        .then(|| {
            (
                format!("{instance}-group"),
                busbar_kernel::config::GroupCfg {
                    parent: None,
                    enabled: true,
                    limits,
                    ..Default::default()
                },
            )
        })
        .into_iter()
        .collect();
    let cost = if groups.is_empty() {
        CostModel::flat(1)
    } else {
        CostModel::resolve_parts(None, 1, &groups)
    };
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "seats".to_string(),
                group: groups.keys().next().cloned(),
                allowed_pools: opts
                    .allowed_pools
                    .map(|pools| pools.iter().map(|p| (*p).to_string()).collect()),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book_over(Box::new(|| CARD.pin()));
    node.bind_book(Arc::clone(&book.durability));
    let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
    let site = Arc::clone(&post);
    let book_money = Arc::clone(&gov);
    let plane_money = move || {
        Arc::new(PlaneMoney::new(
            Arc::clone(&book_money),
            Arc::clone(&site) as Arc<dyn EndPost>,
        ))
    };

    // THE GENERATION: the lanes, the pool, the fee, and the four seats.
    let mut builder = busbar_kernel::test_support::TestApp::new()
        .inbound_schemes(if opts.webhook {
            webhook_schemes()
        } else {
            busbar_kernel::auth::inbound::InboundSchemes::none()
        })
        .governance(Arc::clone(&gov))
        .cost(cost);
    if !opts.open {
        builder = builder.keys_chain();
    }
    for (i, (port, _)) in opts.members.iter().enumerate() {
        let lane = busbar_kernel::test_support::LaneSpec::new(
            &name(i),
            match opts.dialect {
                Some("anthropic") => "anthropic",
                _ => "openai",
            },
            &format!("http://127.0.0.1:{port}"),
        );
        builder = builder.lane(match opts.lane_budget {
            Some(n) => lane.budget(n),
            None => lane,
        });
    }
    let weights: Vec<(usize, u32)> = opts
        .members
        .iter()
        .enumerate()
        .take(pooled)
        .map(|(i, (_, w))| (i, *w))
        .collect();
    builder = builder.pool("p", &weights);
    for (pool, members, _) in opts.pools {
        let weights: Vec<(usize, u32)> = members.iter().map(|i| (*i, 1)).collect();
        builder = builder.pool(pool, &weights);
    }
    let mut app = builder.build();
    let log = Arc::new(Mutex::new(Vec::new()));
    let read: Arc<dyn Fn() -> Ledger + Send + Sync> = {
        let (gov, cost, key_id) = (Arc::clone(&gov), app.cost.clone(), key.id.clone());
        Arc::new(move || {
            let u = gov
                .usage_for(cost.as_ref(), &key_id, busbar_kernel::store::now())
                .expect("usage read")
                .expect("the key exists");
            gov.flush_budgets();
            // Window 0 is the key's all-time bucket.
            let row = gov.store().get_usage(&key_id, 0).expect("ledger row");
            (
                u.requests,
                u.spend_cents,
                row.requests,
                row.billable_requests,
            )
        })
    };
    let tokens: Arc<dyn Fn() -> u64 + Send + Sync> = {
        let (gov, cost, key_id) = (Arc::clone(&gov), app.cost.clone(), key.id.clone());
        Arc::new(move || {
            gov.usage_for(cost.as_ref(), &key_id, busbar_kernel::store::now())
                .expect("usage read")
                .map_or(0, |u| u.tokens)
        })
    };
    let mut rewrite = SeatProbe::new("rewrite", &log);
    let read_for_rewrite = Arc::clone(&read);
    rewrite.requests_now = Some(Box::new(move || read_for_rewrite().0));
    let request_tap = Arc::new(SeatProbe::new("request-tap", &log));
    let candidate_tap = Arc::new(SeatProbe::new("candidate-tap", &log));
    let mut gate_probe = SeatProbe::new("gate", &log);
    // The pool's ranking policy, which is shown the candidates (an abstaining ranker).
    let ranker = Arc::new(SeatProbe::new("ranker", &log));
    if opts.reject_at_gate {
        gate_probe.reject = Some((451, "the gate says no"));
    }
    if !opts.hookless {
        let a = Arc::get_mut(&mut app).expect("sole owner");
        a.rewrite_hooks = vec![(std::time::Duration::from_millis(500), Arc::new(rewrite))];
        // The request tap holds the prompt grant so its payload carries the (rewritten) messages.
        let rt: Arc<dyn RoutingPolicy> = request_tap.clone();
        a.tap_hooks = vec![(std::time::Duration::from_millis(500), true, rt, Vec::new())];
        let ct: Arc<dyn RoutingPolicy> = candidate_tap.clone();
        a.tap_hooks_candidate =
            vec![(std::time::Duration::from_millis(500), false, ct, Vec::new())];
        a.global_gates = vec![(0u16, gate(Arc::new(gate_probe)))];
        if opts.described || opts.signals.is_some() {
            let r: Arc<dyn RoutingPolicy> = ranker.clone();
            a.pool_orderings.insert("p".to_string(), gate(r));
            use busbar_contract::Signal;
            let declared = opts.signals.unwrap_or(&[
                Signal::CandidateBreakerState,
                Signal::CandidateErrorRate,
                Signal::CandidateLatencyP95Ms,
            ]);
            for s in declared {
                a.requested_signals.insert(*s);
            }
        }
    }

    // THE COMPOSITION, as production seals it: the door opened with the deployment's sections,
    // its egress the model-serving walk over the kernel's lane cells, its hooks the kernel's stage.
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let auths = Arc::new(OutboundAuths::new(
        Arc::clone(&dispatcher),
        crate::LINKED.auths,
        None,
        None,
    ));
    let models = crate::root::model_egress::ModelServing {
        pools: model_pools,
        lanes: (0..opts.members.len()).map(|i| (name(i), i)).collect(),
        app: {
            let app = Arc::clone(&app);
            Arc::new(move || Arc::clone(&app))
        },
    };
    let reach = DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: Arc::clone(&auths),
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: opts
            .stream_ceiling_secs
            .or(opts.upstream_request_timeout_secs)
            .unwrap_or(600),
        models: Some(&models),
        upgrades: Vec::new(),
    };
    let stage = HookStage {
        host: {
            let app = Arc::clone(&app);
            Arc::new(move || busbar_kernel::plane_host::engine_host(&app))
        },
        gov: Arc::clone(&gov),
    };
    let sections: BTreeMap<&'static str, serde_yaml::Value> = sections;
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        None,
        &plane_money,
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        Some(&stage),
    )
    .expect("the door serving the pools map composes");
    let _ = std::fs::remove_file(&key_file);
    served.post = Some(Arc::clone(&post));
    let public_routes = served
        .planes
        .iter()
        .flat_map(|p| p.snapshot.admin_routes.iter())
        .filter(|r| r.flags & busbar_contract::abi::plane::ROUTE_PUBLIC != 0)
        .map(|r| (r.verb.clone(), r.target.clone()))
        .collect();
    let scheme_check = {
        let none = busbar_kernel::config::IdentityProviders::new();
        let mut one = busbar_kernel::config::IdentityProviders::new();
        one.insert(
            "openai-hooks".to_string(),
            serde_yaml::from_str("{module: busbar-auth-webhook-signature}").expect("an entry"),
        );
        (
            crate::root::public_verify::refuse_unserved(&served, &none),
            crate::root::public_verify::refuse_unserved(&served, &one),
        )
    };
    let appliers = served.appliers();
    let doors = door_routes(
        served,
        || CARD.pin(),
        &[],
        &busbar_kernel::base_data_core_lines(&app),
    )
    .expect("its claims mount");
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);
    DoorRig {
        router,
        token: token.expose_secret().to_string(),
        app,
        book: Arc::clone(&book.durability),
        key_id: key.id.to_string(),
        log,
        request_tap,
        candidate_tap,
        gate_seat: ranker,
        read,
        tokens,
        scheme_check,
        public_routes,
        appliers,
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        auths: Arc::clone(&auths),
        journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
    }
}

/// ONE KEYED REQUEST through the llm door with the four probed seats installed, a rejecting gate
/// when `reject_at_gate`.
async fn run(instance: &'static str, reject_at_gate: bool) -> Ran {
    let port = far_end().await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(port, 1)],
            reject_at_gate,
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, _) = rig.chat().await;
    Ran {
        status,
        log: Arc::clone(&rig.log),
        request_tap: Arc::clone(&rig.request_tap),
        candidate_tap: Arc::clone(&rig.candidate_tap),
        read: Arc::clone(&rig.read),
    }
}

impl DoorRig {
    /// The request-stage tap's last delivered projection (bounded wait).
    pub async fn request_tap_payload(&self, budget_ms: u64) -> Option<Vec<u8>> {
        delivered(&self.request_tap, budget_ms).await
    }

    /// The seat log.
    pub fn seats(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// A rejecting decision gate: the admission charge, the rewrite and the request tap all happened
/// before it; the candidate tap never fires; the billable request is refunded and the admission
/// count is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrated_request_hook_seats_after_admit_before_candidate() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-hook-seats-reject";
    let _published = Published(instance);
    let ran = run(instance, true).await;
    assert_eq!(
        ran.status, 451,
        "the gate's reject is what the caller receives"
    );

    // Admission door before rewrite: the rewrite seat saw the request already counted.
    let log = ran.log.lock().unwrap().clone();
    assert!(
        log.iter().any(|e| e == "rewrite:requests=Some(1)"),
        "the rewrite seat must run AFTER the admission door charged the request; log: {log:?}"
    );
    // Rewrite before the request tap: the tap's payload carries the rewritten prompt, and the tap
    // was delivered at all even though the gate rejected (so it was seated before the gate).
    let payload = delivered(&ran.request_tap, 2_000)
        .await
        .expect("the request-stage tap fires before the gate and is delivered despite the reject");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        text.contains(REWRITTEN),
        "the request tap must observe the REWRITTEN request: {text}"
    );
    assert!(
        !text.contains("the original prompt"),
        "the request tap must not see the pre-rewrite prompt: {text}"
    );
    // The gate ran (it produced the 451) and the candidate tap, seated after the gates, never
    // fires on a rejected request.
    assert!(
        log.iter().any(|e| e == "gate"),
        "the gate seat ran; log: {log:?}"
    );
    assert!(
        delivered(&ran.candidate_tap, 300).await.is_none(),
        "the candidate tap is seated after the gates, so a gate reject must never reach it"
    );
    // The reject consumed the requests slot but refunded the fee base (a flat 1-cent fee per
    // billable request, so derived spend reads the billable count directly).
    let (requests, spend, row_requests, row_billable) = (ran.read)();
    assert_eq!(requests, 1, "the admission count is never refunded");
    assert_eq!(
        spend, 0,
        "the billable request (the fee base) is refunded on a gate reject"
    );
    assert_eq!(
        (row_requests, row_billable),
        (1, 0),
        "the durable ledger row keeps the admission and drops the billable request"
    );
}

/// The positive twin: an abstaining gate lets the request through, the candidate tap fires AFTER
/// the gate decided, and a served request keeps its billable request (one fee).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_tap_fires_after_an_abstaining_gate_and_a_served_request_bills_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-hook-seats-serve";
    let _published = Published(instance);
    let ran = run(instance, false).await;
    assert_eq!(ran.status, 200, "the live lane serves the request");
    assert!(
        delivered(&ran.candidate_tap, 2_000).await.is_some(),
        "the candidate tap fires on a request the gates let through"
    );
    let log = ran.log.lock().unwrap().clone();
    let gate_at = log.iter().position(|e| e == "gate").expect("the gate ran");
    let cand_at = log
        .iter()
        .position(|e| e == "candidate-tap")
        .expect("the candidate tap was delivered");
    let rewrite_at = log
        .iter()
        .position(|e| e.starts_with("rewrite:"))
        .expect("the rewrite ran");
    assert!(
        rewrite_at < gate_at && gate_at < cand_at,
        "seat order must be rewrite, gate, candidate tap; log: {log:?}"
    );
    // The unit's money settles at its end, which the caller's last byte may precede: read the
    // ledger once it has (bounded).
    let mut ledger = (ran.read)();
    for _ in 0..200 {
        if ledger.3 == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        ledger = (ran.read)();
    }
    let (requests, spend, row_requests, row_billable) = ledger;
    assert_eq!((requests, row_requests), (1, 1));
    assert_eq!(
        (spend, row_billable),
        (1, 1),
        "a served request keeps its one billable request (1-cent flat fee)"
    );
}
