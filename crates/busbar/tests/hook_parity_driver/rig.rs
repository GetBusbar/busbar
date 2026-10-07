// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RIG the hook parity suite runs on: the REAL llm plane door (linked, loaded through the one
//! loader and driven through the one dispatcher), the kernel's plane driver with the hook stage
//! bound ([`BoundHooks`]), the kernel's passing steps, a far end that walks the configured pools
//! the way the egress walk does (its candidates, the hooks' constraint, a fallback pool holding the
//! restricts), and a caller that records what it was answered. No fixture plugin: the plane is the
//! real one, the hooks are the 1.5.5 tests' own in-process policies.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{Blob, Outcome as AbiOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut, UnitCount};
use busbar_contract::abi::transport::STATUS_SUCCESS;
use busbar_contract::caps::{Canary, Outcome, Pass, ReasonCode, Route, StepName};
use busbar_contract::hooks::{BudgetBucketState, RoutingPolicy};
use busbar_kernel::hooks::{RequestedSignals, ResolvedPolicy};
use busbar_kernel::plane_driver::{
    refusal_status, Arrival, BoundHooks, BufferCaps, CallerEnd, CallerFacts, CallerKey, CancelBill,
    CandidateFacts, Candidates, Checkpoint, Constraint, DriverConfig, FarEnd, FarPiece, MoneySeam,
    OutboundRequest, Pick, PlaneDriver, StageTaps,
};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run, UnitCtx};
use busbar_plugin_loader::dispatch::{
    in_head, kinds::plane::Plane, load_linked, out_head, plane_calls::PlaneInstance, Bind,
    DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink, Plugin,
};
use serde_json::{json, Value};

use super::common::{cell, ctx, TestUnits};

// ── the deployment ───────────────────────────────────────────────────────────────────────────────

/// One member of a pool: the model it serves (a key of `models:`), the model its far end names in
/// its answer (what tells a test WHICH member served), its tags, and whether it is down.
#[derive(Clone, Debug)]
pub struct Member {
    pub model: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub tags: Vec<String>,
    pub dead: bool,
    /// The output tokens its far end reports in the answer's usage.
    pub output_tokens: u64,
}

/// A member served by the anthropic far end.
pub fn member(model: &'static str, label: &'static str) -> Member {
    Member {
        model,
        label,
        provider: "ant",
        tags: Vec::new(),
        dead: false,
        output_tokens: 1,
    }
}

impl Member {
    pub fn tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(|t| t.to_string()).collect();
        self
    }
    pub fn dead(mut self) -> Self {
        self.dead = true;
        self
    }
    pub fn provider(mut self, p: &'static str) -> Self {
        self.provider = p;
        self
    }
    pub fn output_tokens(mut self, n: u64) -> Self {
        self.output_tokens = n;
        self
    }
}

/// A pool and its members.
#[derive(Clone, Debug)]
pub struct Pool {
    pub name: &'static str,
    pub members: Vec<Member>,
}

/// The plane's settings for these pools: one far end per protocol, every member a model.
fn settings(pools: &[&Pool]) -> Vec<u8> {
    let mut models = serde_json::Map::new();
    let mut sections = serde_json::Map::new();
    for p in pools {
        let names: Vec<Value> = p.members.iter().map(|m| json!(m.model)).collect();
        sections.insert(p.name.to_string(), json!({ "members": names }));
        for m in &p.members {
            models.insert(m.model.to_string(), json!({ "provider": m.provider }));
        }
    }
    serde_json::to_vec(&json!({
        "providers": {
            "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" },
            "oai": { "protocol": "openai", "base_url": "https://openai.example" },
            "brk": { "protocol": "bedrock", "base_url": "https://bedrock.example" },
            "goo": { "protocol": "gemini", "base_url": "https://gemini.example" },
            "coh": { "protocol": "cohere", "base_url": "https://cohere.example" },
        },
        "models": models,
        "pools": sections,
    }))
    .expect("settings serialize")
}

// ── the far end ─────────────────────────────────────────────────────────────────────────────────

/// What a far end answers one attempt.
fn answer_of(m: &Member) -> Vec<FarPiece> {
    let body = match m.provider {
        "oai" => json!({
            "id": "chatcmpl-1", "object": "chat.completion", "model": m.label,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": m.output_tokens,
                      "total_tokens": 1 + m.output_tokens}
        }),
        _ => json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": m.label,
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": m.output_tokens}
        }),
    };
    vec![FarPiece {
        bytes: serde_json::to_vec(&body).expect("answer serializes"),
        status: Some((200, u32::from(STATUS_SUCCESS))),
        last: true,
        head: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        ..FarPiece::default()
    }]
}

/// One step of a walk: a pool's member, or the walk's refusal (its status and words).
type Step = Result<(String, Member), (u32, String)>;
/// What a walk has left.
type Plan = VecDeque<Step>;
/// A reply head: the status and the fields.
type Head = (u32, Vec<(Vec<u8>, Vec<u8>)>);

/// A WALK over the configured pools: the primary pool's live members in pool order (the hooks'
/// order first, when they set one, restricted to what they kept), then the fallback pool's, its
/// members held to the hooks' restricts (a required restrict nothing satisfies refuses, as 1.5.5
/// failed closed at the fallback boundary). A dead member fails over before the plane sees it.
pub struct Far {
    primary: Pool,
    fallback: Option<Pool>,
    constraint: Mutex<Option<Constraint>>,
    plan: Mutex<Option<Plan>>,
    tried: Mutex<usize>,
    sent: Mutex<Vec<OutboundRequest>>,
    current: Mutex<VecDeque<FarPiece>>,
}

impl Far {
    pub fn new(primary: Pool, fallback: Option<Pool>) -> Self {
        Far {
            primary,
            fallback,
            constraint: Mutex::new(None),
            plan: Mutex::new(None),
            tried: Mutex::new(0),
            sent: Mutex::new(Vec::new()),
            current: Mutex::new(VecDeque::new()),
        }
    }

    /// Every request the plane bound for the far end, in order.
    pub fn sent(&self) -> Vec<OutboundRequest> {
        self.sent.lock().unwrap().clone()
    }

    fn plan(&self) -> Plan {
        let c = self.constraint.lock().unwrap().clone().unwrap_or_default();
        let live: Vec<usize> = (0..self.primary.members.len())
            .filter(|i| c.keep.as_ref().is_none_or(|k| k.contains(i)))
            .collect();
        let mut order: Vec<usize> = c
            .order
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| live.contains(i))
            .collect();
        for i in &live {
            if !order.contains(i) {
                order.push(*i);
            }
        }
        let mut plan: VecDeque<_> = order
            .into_iter()
            .map(|i| {
                Ok((
                    self.primary.name.to_string(),
                    self.primary.members[i].clone(),
                ))
            })
            .collect();
        if let Some(fb) = &self.fallback {
            let tagged = fb
                .members
                .iter()
                .enumerate()
                .map(|(i, m)| (i, m.tags.as_slice()));
            match c.enforce(tagged) {
                Ok(kept) => plan.extend(
                    kept.into_iter()
                        .map(|i| Ok((fb.name.to_string(), fb.members[i].clone()))),
                ),
                Err(_) => plan.push_back(Err((
                    503,
                    "No upstream satisfies a required gate's restriction. Please retry shortly."
                        .to_string(),
                ))),
            }
        }
        plan
    }
}

fn candidate(i: usize, m: &Member) -> CandidateFacts {
    CandidateFacts {
        idx: i,
        model: m.model.to_string(),
        provider: m.provider.to_string(),
        weight: 1,
        tags: m.tags.clone(),
        ..CandidateFacts::default()
    }
}

impl FarEnd for Far {
    fn member<'a>(
        &'a self,
        _: &'a Pass<Route>,
        _attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a {
        let pick = {
            let mut plan = self.plan.lock().unwrap();
            let plan = plan.get_or_insert_with(|| self.plan());
            match plan.pop_front() {
                Some(Ok((pool, m))) => {
                    *self.tried.lock().unwrap() += 1;
                    Pick::Member {
                        name: m.model.to_string(),
                        pool,
                        passthrough: false,
                        provider: m.provider.to_string(),
                    }
                }
                Some(Err((status, text))) => Pick::Vetoed { status, text },
                None => Pick::Exhausted {
                    status: 503,
                    retry_after: None,
                    detail: "The service is temporarily overloaded. Please retry shortly.",
                },
            }
        };
        async move { pick }
    }

    fn send<'a>(
        &'a self,
        _: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        let m = self
            .primary
            .members
            .iter()
            .chain(self.fallback.iter().flat_map(|f| f.members.iter()))
            .find(|m| m.model == request.member)
            .cloned();
        self.sent.lock().unwrap().push(request);
        let ok = match m {
            Some(m) if !m.dead => {
                *self.current.lock().unwrap() = answer_of(&m).into();
                true
            }
            _ => false,
        };
        async move { ok }
    }

    fn next<'a>(
        &'a self,
        _: &'a Pass<Route>,
    ) -> impl Future<Output = Option<FarPiece>> + Send + 'a {
        let piece = self.current.lock().unwrap().pop_front();
        async move { piece }
    }

    fn remaining(&self, _: &Pass<Route>) -> Option<usize> {
        self.plan.lock().unwrap().as_ref().map(VecDeque::len)
    }

    fn failure(&self, _: &Pass<Route>) -> Option<&'static str> {
        Some("connect")
    }

    fn candidates(&self, _: &Pass<Route>) -> Option<Candidates> {
        Some(Candidates {
            pool: self.primary.name.to_string(),
            members: self
                .primary
                .members
                .iter()
                .enumerate()
                .map(|(i, m)| candidate(i, m))
                .collect(),
        })
    }

    fn constrain(&self, _: &Pass<Route>, constraint: Constraint) {
        *self.constraint.lock().unwrap() = Some(constraint);
    }

    /// A request/response far end holds no attempt open for a later frame.
    fn write<'a>(
        &'a self,
        _: &'a Pass<Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        std::future::ready(false)
    }
}

// ── the caller and the books ─────────────────────────────────────────────────────────────────────

/// What the caller was answered.
#[derive(Default)]
pub struct Caller {
    head: Mutex<Option<Head>>,
    bytes: Mutex<Vec<u8>>,
}

impl CallerEnd for Caller {
    fn head(&self, status: u32, fields: Vec<(Vec<u8>, Vec<u8>)>) {
        *self.head.lock().unwrap() = Some((status, fields));
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        true
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        self.write(bytes).await
    }
}

/// A request/response caller sends nothing after its request.
impl busbar_kernel::plane_driver::SessionCaller for Caller {
    fn read(&self) -> impl Future<Output = Option<Vec<u8>>> + Send + '_ {
        std::future::ready(None)
    }
}

/// The money seam: nothing to settle in a hook test.
#[derive(Default)]
pub struct Book;

impl MoneySeam for Book {
    fn checkpoint(&self, _: &UnitCtx, _: &[UnitCount]) -> Checkpoint {
        Checkpoint::Continue
    }
    fn cancelled(&self, _: &UnitCtx, _: &CancelBill) {}
    fn abandoned(&self, _: &UnitCtx, _: Ended) {}
    fn served(&self, _: &UnitCtx, _: &str, _: &str) {}
}

// ── the hooks ────────────────────────────────────────────────────────────────────────────────────

/// What the hooks may know of the caller: its key by principal, its group, nothing else; a hook
/// handed the prompt leaves its access amendment on the kernel's node journal.
#[derive(Default)]
pub struct Callers {
    pub keys: HashMap<String, CallerKey>,
    /// `principal -> the groups it is in` (self and ancestors).
    pub groups: HashMap<String, Vec<String>>,
}

impl CallerFacts for Callers {
    fn key(&self, principal: &str) -> Option<CallerKey> {
        self.keys.get(principal).cloned()
    }
    fn in_groups(&self, principal: Option<&str>, groups: &[String]) -> bool {
        if groups.is_empty() {
            return true;
        }
        let Some(mine) = principal.and_then(|p| self.groups.get(p)) else {
            return false;
        };
        groups.iter().any(|g| mine.contains(g))
    }
    fn rate_headroom(&self, _: &str, _: &str) -> Option<f64> {
        None
    }
    fn budget(&self, _: &str) -> Vec<BudgetBucketState> {
        Vec::new()
    }
}

/// The deployment's hooks, as a test states them.
#[derive(Default)]
pub struct Hooks {
    pub rewrites: Vec<(Duration, Arc<dyn RoutingPolicy>)>,
    pub gates: Vec<(u16, ResolvedPolicy)>,
    pub pool_rewrites: Vec<(Duration, Arc<dyn RoutingPolicy>)>,
    pub pool_gates: Vec<(u16, ResolvedPolicy)>,
    pub policy: Option<ResolvedPolicy>,
    pub taps: StageTaps,
    pub callers: Callers,
    /// The catalog signals the deployment's hooks declare.
    pub requested: RequestedSignals,
}

/// The process's one request-id counter, as the binder is handed it.
pub fn counter() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    Arc::new(|| NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
}

impl Hooks {
    fn bound(self, pool: &str, dialects: Vec<String>) -> BoundHooks {
        let mut gates = self.gates;
        gates.sort_by_key(|(p, _)| *p);
        BoundHooks {
            rewrites: self.rewrites,
            gates,
            pool_rewrites: std::iter::once((pool.to_string(), self.pool_rewrites)).collect(),
            pool_gates: std::iter::once((pool.to_string(), self.pool_gates)).collect(),
            pool_policies: self
                .policy
                .map(|p| (pool.to_string(), p))
                .into_iter()
                .collect(),
            taps: self.taps,
            requested: self.requested,
            next_request_id: counter(),
            caller: Arc::new(self.callers),
            dialects,
        }
    }
}

// ── one unit ─────────────────────────────────────────────────────────────────────────────────────

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

/// THE LINKED DOOR SERVING THE `pools` MAP, found by what its Statement declares
/// (`LINKED_PLANE_DOORS`, the manifest's plane-door rows): the plane under proof.
pub(crate) fn pools_door() -> busbar_contract::abi::mechanism::door::DoorFn {
    crate::LINKED_PLANE_DOORS
        .iter()
        .copied()
        .find(|door| {
            let dispatcher = Dispatcher::new(DispatchConfig::default());
            let row = LinkedRow::of(*door).expect("a linked door states itself");
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("pools-door-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
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

/// The plane under proof's dialects, in its tail's order, as its door states them.
pub(crate) fn dialects() -> Vec<String> {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(pools_door()).expect("the plane door states its Statement");
    load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from("the-plane-facts"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: None,
        },
    )
    .expect("the plane door loads")
    .served()
    .dialects
    .iter()
    .map(|d| (*d).to_string())
    .collect()
}

/// The door serving the `pools` map, linked, opened over `settings`.
fn door(dispatcher: &Dispatcher, settings: &[u8]) -> Plugin<Plane> {
    let row = LinkedRow::of(pools_door()).expect("the plane door states its Statement");
    let plugin = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from("the-plane"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: None,
        },
    )
    .expect("the plane door loads");
    let mut open = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: octets(settings),
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            public_url: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            owned: Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: busbar_contract::abi::mechanism::call::BLOB_ABSENT,
                flags: 0,
            },
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
            snapshot: std::ptr::null(),
        },
    );
    let (called, _) = plugin.open(&mut open);
    assert_eq!(called.outcome, AbiOutcome::Ready, "the plane door opens");
    plugin
}

/// What one unit came to.
pub struct Answered {
    pub status: u32,
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
    pub sent: Vec<OutboundRequest>,
    pub outcome: Outcome,
}

impl Answered {
    /// The answer's body as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    /// The model the answer names: which member served.
    pub fn model(&self) -> String {
        self.json()
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
    /// The answer's body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// THE RIG: one deployment (its pools and its hooks), ready to drive units.
pub struct Rig {
    driver: PlaneDriver,
    primary: Pool,
    fallback: Option<Pool>,
    _plugin: Plugin<Plane>,
}

impl Rig {
    pub fn new(primary: Pool, fallback: Option<Pool>, hooks: Hooks) -> Self {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
            workers: 2,
            ..DispatchConfig::default()
        }));
        let mut pools = vec![&primary];
        if let Some(f) = &fallback {
            pools.push(f);
        }
        let plugin = door(&dispatcher, &settings(&pools));
        let calls = Arc::new(PlaneInstance::new(plugin.clone(), dispatcher, 1));
        let refusal_statuses = calls.refusal_statuses();
        let served = plugin.served();
        let dialects: Vec<String> = served.dialects.iter().map(|d| (*d).to_string()).collect();
        let op_classes: Vec<_> = served
            .op_classes
            .iter()
            .map(|c| busbar_contract::caps::OpClassId::new(c))
            .collect();
        let driver = PlaneDriver::new(
            calls,
            DriverConfig {
                caps: BufferCaps::default(),
                op_classes,
                status_of: refusal_status,
                refusal_statuses,
                caller_refs: None,
            },
            Arc::new(Book),
            Arc::new(busbar_kernel::host_services::KernelServices::new()),
            ("pools", &serde_yaml::Value::Null),
        )
        .expect("the plane instance is admitted")
        .with_billable_classes(served.billable_classes.iter().map(|c| (*c).to_string()))
        .with_hooks(Arc::new(hooks.bound(primary.name, dialects)));
        Rig {
            driver,
            primary,
            fallback,
            _plugin: plugin,
        }
    }

    /// One unit: `body` posted to `target` with `fields`, the kernel steps `steps`.
    pub async fn fire_with(
        &self,
        steps: &TestUnits,
        target: &str,
        fields: &[(&str, &str)],
        body: &[u8],
    ) -> Answered {
        let far = Far::new(self.primary.clone(), self.fallback.clone());
        let caller = Caller::default();
        let arrival = Arrival {
            claim: 0,
            method: b"POST".to_vec(),
            target: target.as_bytes().to_vec(),
            fields: fields
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            body: Arc::from(body),
        };
        let units = self.driver.unit(steps, &far, &caller, arrival, 0);
        // The unit is driven under the request span the composition root opens around every unit
        // (`root/serve.rs`, 1.5.5's `forward`): the kernel records the unit's correlation id on it.
        let span = tracing::debug_span!("forward", request_id = tracing::field::Empty);
        let outcome = {
            use tracing::Instrument as _;
            drive(&units).instrument(span).await
        };
        let rendered = units.take_rendered();
        let (status, fields, body) = match rendered {
            Some(r) => (r.status, r.fields, r.body),
            None => {
                let head = caller.head.lock().unwrap().clone().unwrap_or_default();
                (head.0, head.1, caller.bytes.lock().unwrap().clone())
            }
        };
        Answered {
            status,
            fields,
            body,
            sent: far.sent(),
            outcome,
        }
    }

    /// One Anthropic Messages unit with every kernel step passing.
    pub async fn fire(&self, body: &Value) -> Answered {
        self.fire_with(
            &TestUnits::passing(),
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("anthropic-version", "2023-06-01"),
            ],
            &serde_json::to_vec(body).expect("body serializes"),
        )
        .await
    }

    /// One unit refused at authentication.
    pub async fn fire_unauthenticated(&self, target: &str, body: &[u8]) -> Answered {
        self.fire_with(
            &TestUnits::refusing(StepName::Authenticate, ReasonCode::Unauthenticated),
            target,
            &[("content-type", "application/json")],
            body,
        )
        .await
    }
}

/// Run one unit through the one loop; its outcome.
async fn drive<S, F, C>(units: &busbar_kernel::plane_driver::PlaneUnits<'_, S, F, C>) -> Outcome
where
    S: busbar_kernel::plane_driver::DriverSteps + Sync,
    F: FarEnd,
    C: busbar_kernel::plane_driver::SessionCaller,
{
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };
    match run_unit_async(&kernel, units, &ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}
