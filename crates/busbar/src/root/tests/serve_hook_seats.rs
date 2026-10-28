// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAT ORDER OF THE REQUEST-STAGE HOOKS, ON THE DOOR (ported from the predev-only engine test
//! `hook_seat_order_tests`, BUSBAR-1.6.0.md Part 5 F25: before any engine deletion every test names
//! its new home). The plane serving the `pools` map, served through its door end to end: a keyed
//! caller behind the data listener's auth gate, admitted and charged by the door's money steps, its
//! unit's hooks bound by the kernel's hook stage (the global rewrite, the request-stage tap, a gate
//! and the candidate tap), its far end a real loopback upstream through the process connector. The
//! admission door charges the request first, then the global rewrite runs, then the request-stage
//! tap observes the REWRITTEN request, then the gate decides, and only after the gate does the
//! candidate tap fire. A gate reject refunds the billable request (the fee base) but keeps the
//! admission count.
//!
//! The root names no plane and no dialect: the dialects these cells speak are the plane's own door
//! words (`DRIVER_WORDS`, its `tests/on_driver/words.txt`), read as data through [`word`].
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
use super::{compose_planes_over, door_routes, DoorEgress, HookStage};
use crate::root::door_steps::{kernel_sections, provider_routes, DoorReach, OutboundAuths};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::root::plane_node::{Node, NodeEndPost};

// The words of the plane under proof that these cells read as data (`DRIVER_WORDS`: the plane's own
// `tests/on_driver/words.txt`, from the manifest's driver-proofs row).
include!(concat!(env!("OUT_DIR"), "/driver_words.rs"));

/// One of the plane's door words (`key = value` per line, `#` a comment): what the root's cells
/// would otherwise have to spell, a dialect of the plane under proof.
pub(super) fn word(key: &str) -> &'static str {
    DRIVER_WORDS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("the plane's door words have no `{key}` row"))
}

/// THE LINKED DOOR THAT SERVES THE `pools` MAP, found by what its Statement declares (the composition
/// root names no plane): every linked plane door bound on a probe dispatcher of its own, the one
/// whose declaring section is `pools` kept.
pub(super) fn pools_door() -> busbar_contract::abi::mechanism::door::DoorFn {
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
                    conns: crate::root::loader::dispatch::ConnTable::Probe,
                },
            )
            .expect("a linked door binds")
            .served()
            .section
                == busbar_contract::section::RESERVED_POOLS_KEY
        })
        .expect("the driver-proofs row links the door serving the `pools` map")
}

/// THE REGISTRY ROWS THE DEPLOYMENT WRITES INTO, as the composition root installs them: the linked
/// protocol declarations (the door row's `protocols` axis) and the row the door serving the `pools`
/// map folds to, which owns the `pools:`/`models:` sections. The door is the plane's one
/// registration (DEV-GREEN row 83), so its Statement is the row. Idempotent.
pub(super) fn install_door_seams() {
    static ROW: std::sync::OnceLock<&'static busbar_kernel::plane_driver::registry::PlaneDecl> =
        std::sync::OnceLock::new();
    for decls in crate::LINKED.protocols {
        busbar_kernel::ingress::protocols::register_test_protocols(decls);
    }
    let row = ROW.get_or_init(|| {
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        let reg = registration(linked_probe(pools_door(), "pools-door-row"))
            .expect("the door serving the `pools` map binds");
        busbar_kernel::plane_driver::door::fold(reg).expect("the door folds")
    });
    busbar_kernel::plane_driver::registry::register_test_plane(row);
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

/// [`CARD`]'s pin: the history a rig that names no card of its own pins its units to.
fn card_pin() -> Option<crate::root::kernel::PinnedHistory> {
    CARD.pin()
}

/// The marker the rewrite hook plants in the prompt; a tap payload carrying it saw the rewrite.
pub(super) const REWRITTEN: &str = "rewritten-by-the-global-rewrite-seat";

/// The far end's answer: a chat completion in the door words' `dialect`.
pub(super) const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

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
    /// Gate seat: each candidate's signal bag the last decide was shown, its values as they are
    /// (`<model> <Signal>=<SignalValue>` ...), one line each.
    values: Mutex<Vec<String>>,
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
            values: Mutex::new(Vec::new()),
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
        *self.values.lock().unwrap() = candidates
            .iter()
            .map(|candidate| {
                let bag: Vec<String> = candidate
                    .signals
                    .iter()
                    .map(|(signal, value)| format!("{signal:?}={value:?}"))
                    .collect();
                format!("{} {}", candidate.model, bag.join(" "))
            })
            .collect();
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
pub(crate) struct RigOpts<'a> {
    /// Each member's far-end port and weight, in order.
    pub members: &'a [(u16, u32)],
    /// The global gate rejects with 451.
    pub reject_at_gate: bool,
    /// The key's group holds this many cents a day (a flat 1-cent fee per request).
    pub budget_cents: Option<u64>,
    /// How many of the members (the first ones) pool `p` holds; the rest are models no pool
    /// names. `None`: all of them.
    pub pooled: Option<usize>,
    /// The pools the key may reach (`None`: every pool).
    pub allowed_pools: Option<&'a [&'a str]>,
    /// The members' dialect (`None`: the door words' `dialect`).
    pub dialect: Option<&'static str>,
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
    /// Every provider's `api_key`, a secret reference as written (YAML) (`None`: a credential file
    /// of the rig's own, gone once the door composed).
    pub api_key: Option<&'a str>,
    /// More fields of every provider entry, as written (YAML, one level below the provider's name:
    /// `error_map:`, `health:`).
    pub provider_yaml: &'a str,
    /// More fields of pool `p`, as written (YAML, one level below the pool's name:
    /// `upstream_credentials:`, `on_exhausted:`, `failover:`).
    pub pool_yaml: &'a str,
    /// More fields of each of pool `p`'s members, by member (YAML: `context_max:`).
    pub member_yaml: &'a [&'a str],
    /// More fields of each model entry, by member (YAML: `max_concurrent:`).
    pub model_yaml: &'a [&'a str],
    /// More pools beside `p`: each its name and its members as (member index, weight).
    pub more_pools: &'a [(&'a str, &'a [(usize, u32)])],
    /// The key's group as configured: its name and its limits (replaces `budget_cents`' group).
    pub group: Option<(&'a str, &'a [busbar_kernel::config::groups::LimitCfg])>,
    /// The group the key names, configured or not (`None`: the configured group, if any).
    pub key_group: Option<&'a str>,
    /// Requests already on a bucket's all-time window before the money hydrates: (bucket, count),
    /// each a billable request.
    pub seed: &'a [(&'a str, u64)],
    /// The door asks no caller credential (an open front door).
    pub open_door: bool,
    /// With `described`, the candidate catalog signals the generation declares (`None`: breaker
    /// state, error rate and p95 latency).
    pub declared: Option<&'a [busbar_contract::Signal]>,
    /// The destination judge refuses every private address, so each member's dial is refused
    /// before it leaves.
    pub refuse_private: bool,
    /// No rewrite seat is installed, so the caller's own messages reach the translation (a cell
    /// that reads what the plane does with the caller's parts).
    pub no_rewrite: bool,
    /// The deployment's `limits.request_body_max_bytes` (`None`: the default): the translation cap
    /// the kernel hands the door in its settings, which the plane enforces (row 155).
    pub request_body_max_bytes: Option<usize>,
    /// The node's book keeps its journal in a configured store that refuses, and the lane to it is
    /// full ([`full_journal_book`]): the node fails closed on every new unit (H3).
    pub full_journal: bool,
    /// The deployment's `rate_card:` (`None`: no card, billing off): the governance book prices
    /// the key's counts against it.
    pub rate_card: Option<&'a BTreeMap<String, busbar_kernel::config::RateEntryCfg>>,
    /// The flat request fee, in cents (`None`: 1 cent).
    pub fee_cents: Option<i64>,
    /// The card history a unit is pinned to at its door, which the node's book prices its line
    /// against (`None`: the rig's own priceless card).
    pub pin: Option<fn() -> Option<crate::root::kernel::PinnedHistory>>,
    /// The walk's clock the door plane is composed on, which every generation's walk reads (`None`:
    /// the node's own, [`crate::root::egress_ports::NodeClock`]).
    pub clock: Option<&'a Arc<dyn busbar_kernel_egress::ports::Clock>>,
}

/// A NODE'S BOOK WHOSE JOURNAL CANNOT REACH ITS STORE: the journal is kept by a configured store
/// that refuses every write, the lane to it holds one batch, and three appends have filled it, so
/// the node's `journal_refusal` names the full journal and the store (`test-store`).
pub(crate) fn full_journal_book() -> Arc<std::sync::Mutex<crate::root::durability::Durability>> {
    let slots = crate::root::store_double::RecordSlots::new();
    slots.refuse(true);
    let lane = crate::root::durability::JournalLane::with_capacity(slots.calls(), "test-store", 1)
        .expect("the lane starts");
    let book = Arc::new(std::sync::Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            0,
            lane,
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
            Box::new(|| None),
            None,
        )
        .expect("the store reads back"),
    ));
    let token = busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>();
    for _ in 0..3 {
        let _lost = book.lock().unwrap().journal.append(
            &token,
            busbar_contract::caps::StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                busbar_kernel_wal::RecordClass::Load,
                Vec::new(),
            )],
        );
    }
    book
}

/// `text`, each line indented by `by` spaces (empty lines dropped).
fn indented(text: &str, by: usize) -> String {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| format!("{}{l}\n", " ".repeat(by)))
        .collect()
}

/// THE POOLS DOOR, SERVED END TO END, as production composes it: the data router built with the
/// door's claims, a keyed caller's token, the generation's App and the node's book.
pub(crate) struct DoorRig {
    /// The data router.
    pub router: axum::Router,
    /// Every route the door mounts on that router: `(path, method, auth)`, as built.
    pub door_table: Vec<(
        String,
        String,
        busbar_contract::abi::mechanism::route::RouteAuth,
    )>,
    /// The caller's bearer token.
    pub token: String,
    /// The generation.
    pub app: Arc<busbar_kernel::state::App>,
    /// The node's book: every unit's line and audit record.
    pub book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    /// The key's id.
    pub key_id: String,
    /// The governance book the key was minted on.
    pub gov: Arc<GovState>,
    /// The served door's generations, as a config apply refreshes them.
    appliers: super::DoorAppliers,
    /// A config apply of the same deployment onto the door ([`DoorAppliers::refresh_models`], as
    /// the root's apply hook runs it), its secrets resolved anew.
    reapply: Arc<dyn Fn() + Send + Sync>,
    log: Arc<Mutex<Vec<String>>>,
    request_tap: Arc<SeatProbe>,
    candidate_tap: Arc<SeatProbe>,
    gate_seat: Arc<SeatProbe>,
    read: Arc<dyn Fn() -> Ledger + Send + Sync>,
    tokens: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl DoorRig {
    /// Apply the deployment again, as an operator's config apply does: the door refreshes onto it,
    /// or keeps the generation it serves.
    pub fn apply(&self) {
        (self.reapply)();
    }

    /// The generation the door serves.
    pub fn generation(&self) -> u64 {
        self.appliers
            .0
            .first()
            .expect("one door")
            .current()
            .generation
    }

    /// Each candidate the pool's ranking policy was last shown, one line each.
    pub fn gate_saw(&self) -> Vec<String> {
        self.gate_seat.candidates.lock().unwrap().clone()
    }

    /// Each candidate's signal bag the pool's ranking policy was last shown, its values as they
    /// are: `<model> <Signal>=<SignalValue> ...`, one line each.
    pub fn gate_signals(&self) -> Vec<String> {
        self.gate_seat.values.lock().unwrap().clone()
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

    /// One request through the door carrying only `fields` (no credential of the rig's): its
    /// status, head and body.
    pub async fn send_bare(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        fields: &[(&str, &str)],
    ) -> (u16, axum::http::HeaderMap, Vec<u8>) {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder().method(method).uri(path);
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
        let response = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status().as_u16();
        let head = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body")
            .to_vec();
        (status, head, bytes)
    }

    /// The audit records the node's book sealed so far, oldest first.
    pub fn records(&self) -> Vec<busbar_kernel_audit::AuditRecord> {
        self.book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .audit_records
            .clone()
    }

    /// A bucket's all-time ledger as the money reads it: (admission count, derived spend in
    /// cents), and the durable row's (admission count, billable count).
    pub fn bucket(&self, bucket: &str) -> (u64, i64, u64, u64) {
        let derived = self
            .gov
            .derived_bucket_usage(
                &self.app.cost,
                bucket,
                "total",
                true,
                busbar_kernel::store::now(),
            )
            .expect("usage read");
        self.gov.flush_budgets();
        let row = self.gov.store().get_usage(bucket, 0).expect("ledger row");
        (
            derived.requests,
            derived.spend_cents,
            row.requests,
            row.billable_requests,
        )
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
pub(crate) async fn rig(instance: &'static str, opts: RigOpts<'_>) -> DoorRig {
    try_rig(instance, opts)
        .await
        .unwrap_or_else(|e| panic!("the door serving the pools map composes: {e}"))
}

/// [`rig`], the composition's refusal answered rather than panicked on: what the root's boot dies
/// on.
pub(crate) async fn try_rig(instance: &'static str, opts: RigOpts<'_>) -> Result<DoorRig, String> {
    // The registry rows that own the `pools:`/`models:` sections the deployment writes.
    install_door_seams();
    busbar_kernel::snapshot::init();
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: opts.refuse_private,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build_with_secrets(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &busbar_contract::transport::TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_, _| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
        busbar_kernel::config::secret::resolve_linked_string_at_config,
    )
    .expect("the connector builds");

    // THE POOLS DOOR, linked, bound through the loader's one load, its needs declared on the
    // connector. Its dispatcher is the boot's (`root::dispatch::build`): it serves the composition's
    // host services (the door's codecs draw their entropy and read their clock there, #1028) and is
    // lent the kernel's seal (a caller's or a member's credential is revealed only under it, #1021).
    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::clone(&services) as Arc<dyn busbar_contract::services::HostServices>,
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let row = LinkedRow::of(pools_door()).expect("the door states itself");
    let plane = Arc::new(
        load_linked::<Plane>(
            &row,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&connector) as Arc<dyn DeclaredConns>
                ),
            },
        )
        .expect("the linked door binds"),
    );

    // THE DEPLOYMENT: one provider per member (in the members' dialect), one model per provider,
    // pool `p` over them.
    let key_file = std::env::temp_dir().join(format!(
        "busbar-hook-seats-{}-{instance}",
        std::process::id()
    ));
    let own_key = format!("{{ file: '{}' }}", key_file.display());
    if opts.api_key.is_none() {
        std::fs::write(&key_file, "sk-seats").expect("the credential file");
    }
    let mut yaml = String::from("providers:\n");
    for (i, _) in opts.members.iter().enumerate() {
        yaml.push_str(&format!(
            "  oai{i}:\n    api_key: {}\n",
            opts.api_key.unwrap_or(&own_key)
        ));
        yaml.push_str(&indented(opts.provider_yaml, 4));
    }
    yaml.push_str("models:\n");
    for (i, _) in opts.members.iter().enumerate() {
        yaml.push_str(&format!("  m{i}:\n    provider: oai{i}\n"));
        yaml.push_str(&indented(opts.model_yaml.get(i).copied().unwrap_or(""), 4));
    }
    yaml.push_str("pools:\n  p:\n    members:\n");
    let pooled = opts.pooled.unwrap_or(opts.members.len());
    for (i, (_, weight)) in opts.members.iter().enumerate().take(pooled) {
        yaml.push_str(&format!("      - model: m{i}\n        weight: {weight}\n"));
        if opts.described {
            yaml.push_str(&format!("        tier: t{i}\n        tags: [g{i}]\n"));
        }
        yaml.push_str(&indented(opts.member_yaml.get(i).copied().unwrap_or(""), 8));
    }
    yaml.push_str(&indented(opts.pool_yaml, 4));
    if let Some(secs) = opts.failover_timeout_secs {
        yaml.push_str(&format!("    failover:\n      timeout_secs: {secs}\n"));
    }
    if let Some(header) = opts.affinity_header {
        yaml.push_str(&format!(
            "    affinity:\n      mode: session\n      header_name: {header}\n"
        ));
    }
    for (name, members) in opts.more_pools {
        yaml.push_str(&format!("  {name}:\n    members:\n"));
        for (i, weight) in members.iter() {
            yaml.push_str(&format!("      - model: m{i}\n        weight: {weight}\n"));
        }
    }
    if let Some(cap) = opts.request_body_max_bytes {
        yaml.push_str(&format!("limits:\n  request_body_max_bytes: {cap}\n"));
    }
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).map_err(|e| e.to_string())?;
    let mut defs_yaml = String::new();
    for (i, (port, _)) in opts.members.iter().enumerate() {
        defs_yaml.push_str(&format!(
            "oai{i}:\n  protocol: {}\n  base_url: 'http://127.0.0.1:{port}'\n",
            opts.dialect.unwrap_or(word("dialect"))
        ));
    }
    let defs: HashMap<String, busbar_kernel::config::ProviderDef> =
        serde_yaml::from_str(&defs_yaml).expect("the providers");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).map_err(|e| e.join("; "))?;
    let providers = provider_routes(
        &cfg.providers,
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let sections = kernel_sections(&cfg);
    let model_pools = crate::root::model_egress::ModelPools::of(&cfg);

    // THE MONEY: a signing governance book with one minted key (in a budgeted group when asked),
    // the node's book bound.
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let configured = opts.group.map(|(name, limits)| {
        (
            name.to_string(),
            busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: limits.to_vec(),
                ..Default::default()
            },
        )
    });
    let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = opts
        .budget_cents
        .filter(|_| configured.is_none())
        .map(|amount| {
            let limit = busbar_kernel::config::groups::LimitCfg {
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount,
                per: Some(busbar_kernel::config::groups::LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            };
            (
                format!("{instance}-group"),
                busbar_kernel::config::GroupCfg {
                    parent: None,
                    enabled: true,
                    limits: vec![limit],
                    ..Default::default()
                },
            )
        })
        .into_iter()
        .chain(configured)
        .collect();
    let fee = opts.fee_cents.unwrap_or(1);
    let cost = if groups.is_empty() && opts.rate_card.is_none() {
        CostModel::flat(fee)
    } else {
        CostModel::resolve_parts(opts.rate_card, fee, &groups)
    };
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "seats".to_string(),
                group: opts
                    .key_group
                    .map(str::to_string)
                    .or_else(|| groups.keys().next().cloned()),
                allowed_pools: opts
                    .allowed_pools
                    .map(|pools| pools.iter().map(|p| (*p).to_string()).collect()),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
    for (bucket, requests) in opts.seed {
        gov.store()
            .put_usage(
                bucket,
                0,
                &busbar_contract::records::UsageLedger {
                    requests: *requests,
                    billable_requests: *requests,
                    models: Vec::new(),
                },
            )
            .expect("seed the bucket");
    }
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let node = Arc::new(Node::new());
    let pin = opts.pin.unwrap_or(card_pin);
    let book = crate::root::durability::node_book_over(Box::new(pin));
    let durability = if opts.full_journal {
        full_journal_book()
    } else {
        Arc::clone(&book.durability)
    };
    node.bind_book(Arc::clone(&durability));
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
    let mut builder = busbar_kernel::test_support::TestApp::new();
    if !opts.open_door {
        builder = builder.keys_chain();
    }
    let mut builder = builder.governance(Arc::clone(&gov)).cost(cost);
    for (i, (port, _)) in opts.members.iter().enumerate() {
        let lane = busbar_kernel::test_support::LaneSpec::new(
            &format!("m{i}"),
            opts.dialect.unwrap_or(word("dialect")),
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
    for (name, members) in opts.more_pools {
        builder = builder.pool(name, members);
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
    {
        let a = Arc::get_mut(&mut app).expect("sole owner");
        a.rewrite_hooks = if opts.no_rewrite {
            Vec::new()
        } else {
            vec![(std::time::Duration::from_millis(500), Arc::new(rewrite))]
        };
        // The request tap holds the prompt grant so its payload carries the (rewritten) messages.
        let rt: Arc<dyn RoutingPolicy> = request_tap.clone();
        a.tap_hooks = vec![(std::time::Duration::from_millis(500), true, rt, Vec::new())];
        let ct: Arc<dyn RoutingPolicy> = candidate_tap.clone();
        a.tap_hooks_candidate =
            vec![(std::time::Duration::from_millis(500), false, ct, Vec::new())];
        a.global_gates = vec![(0u16, gate(Arc::new(gate_probe)))];
        if opts.described {
            let r: Arc<dyn RoutingPolicy> = ranker.clone();
            a.pool_orderings.insert("p".to_string(), gate(r));
            use busbar_contract::Signal;
            let all = [
                Signal::CandidateBreakerState,
                Signal::CandidateErrorRate,
                Signal::CandidateLatencyP95Ms,
            ];
            for signal in opts.declared.unwrap_or(&all) {
                a.requested_signals.insert(*signal);
            }
        }
    }

    // THE COMPOSITION, as production seals it: the door opened with the deployment's sections,
    // its egress the model-serving walk over the kernel's lane cells, its hooks the kernel's stage.
    let secrets: Arc<dyn busbar_contract::secret::SecretResolve> =
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let auths = Arc::new(OutboundAuths::new(
        Arc::clone(&dispatcher),
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    ));
    let models = crate::root::model_egress::ModelServing {
        pools: model_pools.clone(),
        lanes: (0..opts.members.len())
            .map(|i| (format!("m{i}"), i))
            .collect(),
        app: {
            let app = Arc::clone(&app);
            Arc::new(move || Arc::clone(&app))
        },
    };
    let clock: Arc<dyn busbar_kernel_egress::ports::Clock> = match opts.clock {
        Some(clock) => Arc::clone(clock),
        None => Arc::new(crate::root::egress_ports::NodeClock::new()),
    };
    let reach = DoorReach {
        providers: &providers,
        secrets: Arc::clone(&secrets),
        auths: Arc::clone(&auths),
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: opts.stream_ceiling_secs.unwrap_or(600),
        models: Some(&models),
        catalog: None,
        upgrades: Vec::new(),
    };
    let stage = HookStage {
        host: {
            let app = Arc::clone(&app);
            Arc::new(move || busbar_kernel::plane_driver::engine_host(&app))
        },
        gov: Arc::clone(&gov),
        journal: None,
    };
    let sections: BTreeMap<&'static str, serde_yaml::Value> = sections;
    // As [`compose_planes`] composes, on the rig's walk clock.
    let served = compose_planes_over(
        &crate::LINKED,
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        None,
        &plane_money,
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        Some(&stage),
        &clock,
        &busbar_contract::config_time::ConfigScope::config_time(),
    );
    let _ = std::fs::remove_file(&key_file);
    let mut served = served?;
    served.post = Some(Arc::clone(&post));
    let appliers = served.appliers();
    // THE APPLY, as the root's apply hook runs it: the same deployment's sections, the pools and
    // lanes, the door's egress resealed over the providers with their secrets resolved anew.
    let reapply: Arc<dyn Fn() + Send + Sync> = {
        let (appliers, app, post) = (appliers.clone(), Arc::clone(&app), Arc::clone(&post));
        let (connector, auths) = (Arc::clone(&connector), Arc::clone(&auths));
        let lanes = opts.members.len();
        let stream_ceiling_secs = opts.stream_ceiling_secs.unwrap_or(600);
        let (sections, providers) = (sections.clone(), providers.clone());
        Arc::new(move || {
            let secrets: Arc<dyn busbar_contract::secret::SecretResolve> =
                Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
            let models = crate::root::model_egress::ModelServing {
                pools: model_pools.clone(),
                lanes: (0..lanes).map(|i| (format!("m{i}"), i)).collect(),
                app: {
                    let app = Arc::clone(&app);
                    Arc::new(move || Arc::clone(&app))
                },
            };
            let reach = DoorReach {
                providers: &providers,
                secrets: Arc::clone(&secrets),
                auths: Arc::clone(&auths),
                conns: Arc::clone(&connector) as Arc<dyn PollConns>,
                stream_ceiling_secs,
                models: Some(&models),
                catalog: None,
                upgrades: Vec::new(),
            };
            appliers.refresh_models(
                &sections,
                &DoorEgress {
                    reach: &reach,
                    journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
                },
            );
        })
    };
    let doors = door_routes(served, pin, &[], &busbar_kernel::base_data_core_lines(&app))
        .expect("its claims mount");
    let door_table = doors
        .iter()
        .map(|d| (d.path.clone(), d.method.as_str().to_string(), d.auth))
        .collect();
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);
    Ok(DoorRig {
        router,
        door_table,
        token: token.expose(&busbar_kernel::seal::lend()).to_string(),
        app,
        book: durability,
        key_id: key.id.to_string(),
        gov,
        appliers,
        reapply,
        log,
        request_tap,
        candidate_tap,
        gate_seat: ranker,
        read,
        tokens,
    })
}

/// ONE KEYED REQUEST through the pools door with the four probed seats installed, a rejecting gate
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

/// A rejecting gate: the admission charge, the rewrite and the request tap all happened
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

// ── ONE ACCRUAL PER SERVED UNIT (coverage map rows 694 and 722, F25 REHOME) ────────────────────

/// The token figures the far end reports on a delivered answer: eleven input, seven output.
const SPLIT_INPUT: u64 = 11;
const SPLIT_OUTPUT: u64 = 7;

/// The far end's whole answer, in the door words' `dialect`, reporting [`SPLIT_INPUT`] and
/// [`SPLIT_OUTPUT`].
const SPLIT_ANSWER: &str = r#"{"id":"chatcmpl-split","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#;

/// The same answer streamed: a delta, the stop, the usage, the end.
const SPLIT_FRAMES: [&str; 4] = [
    r#"{"id":"chatcmpl-split","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}"#,
    r#"{"id":"chatcmpl-split","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    r#"{"id":"chatcmpl-split","object":"chat.completion.chunk","created":0,"model":"m0","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#,
    "[DONE]",
];

/// A far end on loopback answering [`SPLIT_FRAMES`] as one chunked stream, to its end.
async fn far_end_with_the_split_streamed() -> FarEnd {
    far_end_scripted(Script {
        head: "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
               transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
            .to_string(),
        pieces: SPLIT_FRAMES
            .iter()
            .map(|frame| (0, chunk(format!("data: {frame}\n\n").as_bytes())))
            .collect(),
        finish: Some(b"0\r\n\r\n".to_vec()),
    })
    .await
}

/// What a served unit left on the key's books, once its money settled: the admissions on the
/// key's bucket, the tokens it accrued, the durable ledger row's per-class counts for `m0`, and
/// every metering row the key holds (`model in= out= cr= cw= req= billable=`; the provider column
/// is the rig's own provider name and is not pinned here).
struct Accrued {
    requests: u64,
    tokens: u64,
    durable: BTreeMap<String, u64>,
    metering: Vec<String>,
}

/// Read [`Accrued`] off `rig` once its last unit's money settled (bounded).
async fn accrued(rig: &DoorRig) -> Accrued {
    let (requests, _, _, _) = rig.ledger_after(1).await;
    let tokens = rig.tokens_after().await;
    let gov = rig
        .app
        .governance
        .clone()
        .expect("the rig keeps a governance book");
    gov.flush_budgets();
    gov.flush_metering();
    let durable = gov
        .store()
        .get_usage(&rig.key_id, 0)
        .expect("the durable ledger row")
        .models
        .iter()
        .find(|row| row.model == "m0")
        .map(|row| {
            row.usage_units
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(class, count)| (class.clone(), *count))
                .collect()
        })
        .unwrap_or_default();
    let metering = gov
        .metering_for(busbar_kernel::governance::metering_bucket(
            busbar_kernel::store::now(),
        ))
        .expect("metering read")
        .into_iter()
        .filter(|row| row.key_id == rig.key_id)
        .map(|row| {
            format!(
                "{} in={} out={} cr={} cw={} req={} billable={}",
                row.model,
                row.tokens_input,
                row.tokens_output,
                row.tokens_cache_read,
                row.tokens_cache_write,
                row.requests,
                row.billable_requests
            )
        })
        .collect();
    Accrued {
        requests,
        tokens,
        durable,
        metering,
    }
}

/// THE WALK'S TAP AND THE METER STEP MAKE ONE POSTING BETWEEN THEM, BUFFERED AND STREAMED.
///
/// Legacy: the retiring engine crate's `src/unit/tests/chain.rs::the_walks_tap_and_the_meter_step_make_one_posting_between_them`
/// (coverage map row 694, REHOME). 1.5.5 behaviour pinned, for BOTH the buffered and the streamed
/// answer through the door serving the `pools` map: the unit's consumption is posted exactly once —
/// one metering row `m0 in=11 out=7 cr=0 cw=0 req=1 billable=1`, one admission on the key's bucket,
/// and the key's tokens accrued once (11 + 7 = 18), however the answer was delivered. The old home
/// pinned one buffered request's requests, billable count and spend.
///
/// RED: a second posting of the unit (two metering rows, req=2, or 36 tokens), a streamed answer
/// whose usage frame is never accrued (0 tokens, no row), or a split posted under the wrong tiers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_walks_tap_and_the_meter_step_make_one_posting_between_them() {
    let _one = PUBLISHING.lock().await;
    let row = format!("m0 in={SPLIT_INPUT} out={SPLIT_OUTPUT} cr=0 cw=0 req=1 billable=1");
    for (instance, streamed) in [
        ("serve-hook-seats-one-posting-buffered", false),
        ("serve-hook-seats-one-posting-streamed", true),
    ] {
        let _published = Published(instance);
        let far = if streamed {
            far_end_with_the_split_streamed().await
        } else {
            far_end_answering(200, SPLIT_ANSWER).await
        };
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send(
                "POST",
                "/v1/chat/completions",
                Some(
                    serde_json::json!({"model": "p", "stream": streamed, "max_tokens": 16,
                    "messages": [{"role": "user", "content": "hi"}]}),
                ),
            )
            .await;
        assert_eq!(
            status,
            200,
            "{instance}: served: {}",
            String::from_utf8_lossy(&body)
        );
        let books = accrued(&rig).await;
        assert_eq!(books.requests, 1, "{instance}: one admission");
        assert_eq!(
            books.tokens,
            SPLIT_INPUT + SPLIT_OUTPUT,
            "{instance}: the tokens accrued once"
        );
        assert_eq!(
            books.metering,
            vec![row.clone()],
            "{instance}: exactly one metering row, posted once"
        );
    }
}

/// THE SERVED UNIT'S USAGE IS ACCRUED EXACTLY ONCE (the posting the meter step's posted-or-sealed
/// flag protected).
///
/// Legacy: the retiring engine crate's `src/unit/tests/meter.rs::the_step_says_whether_it_posted_or_only_sealed`
/// (coverage map row 722, REHOME). The posted-versus-sealed flag was the deleted meter step's own;
/// the 1.5.5 behaviour it protected, pinned here on the served unit: a delivered answer whose usage
/// the far end reported accrues its tokens exactly once — 11 + 7 = 18 tokens on the key, the durable
/// ledger row holding `{input: 11, output: 7}` for the lane, and exactly one metering row for the key
/// — and nothing posts a second time once the unit has ended (the books read the same after a
/// further settle).
///
/// RED: a second accrual of the same unit (36 tokens, `{input: 22, output: 14}`, a second metering
/// row), or none at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_units_usage_is_accrued_exactly_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-hook-seats-accrued-once";
    let _published = Published(instance);
    let far = far_end_answering(200, SPLIT_ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, _) = rig.chat().await;
    assert_eq!(status, 200, "the live lane serves the request");
    let books = accrued(&rig).await;
    let split = BTreeMap::from([
        ("input".to_string(), SPLIT_INPUT),
        ("output".to_string(), SPLIT_OUTPUT),
    ]);
    assert_eq!(
        books.tokens,
        SPLIT_INPUT + SPLIT_OUTPUT,
        "the unit's tokens, once"
    );
    assert_eq!(
        books.durable, split,
        "the durable ledger row holds the split once"
    );
    assert_eq!(
        books.metering.len(),
        1,
        "exactly one metering row for the key: {:?}",
        books.metering
    );
    // Nothing posts behind the unit's end: the books read the same after a further settle.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let again = accrued(&rig).await;
    assert_eq!(
        (again.tokens, again.durable, again.metering),
        (books.tokens, books.durable.clone(), books.metering.clone()),
        "no second posting once the unit has ended"
    );
    assert_eq!(far.served(), 1, "one far-end request served");
}
