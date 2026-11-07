// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{Blob, Outcome as AbiOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut, UnitCount};
use busbar_contract::abi::transport::STATUS_SUCCESS;
use busbar_contract::caps::{DurableWrite, Grant, Outcome, Pass, ReasonCode, Route, StepName};
use busbar_contract::hooks::{BudgetBucketState, RoutingPolicy};
use busbar_kernel::canary::Canary;
use busbar_kernel::hooks::{RequestedSignals, ResolvedPolicy};
use busbar_kernel::plane_driver::{
    refusal_status, Arrival, BoundHooks, BufferCaps, CallerEnd, CallerFacts, CallerKey, CancelBill,
    CandidateFacts, Candidates, Checkpoint, Constraint, DriverConfig, FarEnd, FarPiece, MoneySeam,
    OutboundRequest, Pick, PlaneDriver, StageTaps,
};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run, UnitCtx};
use busbar_kernel_audit::amend::{self as amend, AmendBody, AmendSink, Amendment};
use busbar_kernel_wal::{BodyWriter, Entry, RecordClass};
use busbar_plugin_loader::dispatch::{
    in_head, kinds::plane::Plane, load_linked, out_head, plane_calls::PlaneInstance, Bind,
    DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink, Plugin,
};
use serde_json::Value;

use super::common::{cell, ctx, TestUnits};

/// One member of a pool: the model it serves (a key of `models:`), the model its far end names in
/// its answer (what tells a test WHICH member served), its tags, and whether it is down.
#[derive(Clone, Debug)]
pub struct Member {
    pub model: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub tags: Vec<String>,
    pub dead: bool,
}

pub fn member(model: &'static str, label: &'static str) -> Member {
    Member {
        model,
        label,
        provider: crate::proofs::wire::DEFAULT_PROVIDER,
        tags: Vec::new(),
        dead: false,
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
}

/// A pool and its members.
#[derive(Clone, Debug)]
pub struct Pool {
    pub name: &'static str,
    pub members: Vec<Member>,
}

fn settings(pools: &[&Pool]) -> Vec<u8> {
    crate::proofs::wire::settings(pools)
}

fn answer_of(m: &Member) -> Vec<FarPiece> {
    let body = crate::proofs::wire::answer_of(m);
    vec![FarPiece {
        bytes: serde_json::to_vec(&body).expect("answer serializes"),
        status: Some((200, u32::from(STATUS_SUCCESS))),
        last: true,
        head: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        ..FarPiece::default()
    }]
}

type Step = Result<(String, Member), (u32, String)>;

type Plan = VecDeque<Step>;

type Head = (u32, Vec<(Vec<u8>, Vec<u8>)>);

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

    fn write<'a>(
        &'a self,
        _: &'a Pass<Route>,
        _: busbar_kernel::plane_driver::OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        std::future::ready(false)
    }
}

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

/// What the hooks may know of the caller: its key by principal, its group, nothing else; a hook
/// handed the prompt leaves its access amendment on `journal`, the rig's node journal, as a node's
/// host leaves it on its own.
#[derive(Default)]
pub struct Callers {
    pub keys: HashMap<String, CallerKey>,
    /// `principal -> the groups it is in` (self and ancestors).
    pub groups: HashMap<String, Vec<String>>,
    /// The node amendment journal the rig's hook reads are recorded on ([`Rig::amendments`]).
    pub journal: Arc<busbar_kernel::audit::amend::NodeAmendments>,
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
    fn hook_read<'a>(
        &'a self,
        hook: &'a str,
        principal: Option<&'a str>,
        dialect: &'a str,
        identity: bool,
    ) -> busbar_kernel::audit::amend::ReadConfirmation<'a> {
        Box::pin(busbar_kernel::audit::amend::record_test_hook_read(
            &self.journal,
            hook,
            principal,
            dialect,
            identity,
        ))
    }
}

// The production amendment codec and retained-original sink, over this fixture's
// actual native Store. A content handoff must await Applied just as normal boot does.
const AMENDMENT: &str = "amend.v1";

fn amendment_entry(amendment: &Amendment) -> Entry {
    let (class, wall) = match &amendment.body {
        AmendBody::Access(a) => (RecordClass::Access, a.wall),
        AmendBody::Adjust(a) => (RecordClass::Transaction, a.wall),
    };
    Entry::new(class, amendment_body(amendment)).at(wall, 0)
}

fn amendment_body(amendment: &Amendment) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.text(AMENDMENT)
        .num(amendment.seq)
        .text(&amendment.prev_hash)
        .text(&amendment.hash)
        .text(amendment.class().as_str());
    let subject = |body: &mut BodyWriter, s| {
        let (tag, value) = amend::subject_fields(s);
        body.text(tag).text(&value);
    };
    match &amendment.body {
        AmendBody::Access(a) => {
            body.text(a.reader.as_str()).text(&a.name);
            subject(&mut body, &a.subject);
            body.text(a.op_class.as_str()).num(a.fields.len() as u64);
            for field in &a.fields {
                body.text(field);
            }
            body.num(a.wall);
        }
        AmendBody::Adjust(a) => {
            body.text(&a.amends_hash);
            subject(&mut body, &a.subject);
            body.text(&a.lane).num(a.card_epoch_ms);
            for side in [&a.was, &a.now] {
                body.num(side.len() as u64);
                for (class, count) in side {
                    body.text(class).text(&count.to_decimal_string());
                }
            }
            body.text(&a.authorised_by).text(&a.reason).num(a.wall);

            if let Some(pool) = &a.pool {
                body.text(pool);
            }
        }
    }
    body.finish()
}

type PendingAmendments = std::collections::BTreeMap<
    u64,
    (
        String,
        Arc<busbar_kernel::persistence::journal::runtime::StagedRun>,
    ),
>;

struct NativeAmendments {
    journal: Arc<busbar_kernel::persistence::journal::runtime::RuntimeJournal>,
    pending: Arc<Mutex<PendingAmendments>>,
    token: Grant<DurableWrite>,
}

impl AmendSink for NativeAmendments {
    fn sealed(
        &self,
        amendment: &Amendment,
    ) -> Result<
        busbar_kernel_audit::amend::AmendCommit,
        busbar_kernel_audit::amend::AmendPersistError,
    > {
        use busbar_kernel_audit::amend::AmendPersistError;
        let staged = (|| {
            let mut pending = self.pending.lock().map_err(|_| AmendPersistError)?;
            pending.retain(|_, (_, run)| !matches!(self.journal.is_confirmed(run), Ok(true)));
            if let Some((hash, run)) = pending.get(&amendment.seq) {
                if hash != &amendment.hash {
                    return Err(AmendPersistError);
                }
                return Ok(run.clone());
            }
            let run = self
                .journal
                .stage_run(&[amendment_entry(amendment)])
                .map_err(|_| AmendPersistError)?;
            pending.insert(amendment.seq, (amendment.hash.clone(), run.clone()));
            Ok(run)
        })()?;
        let journal = self.journal.clone();
        let pending = self.pending.clone();
        let seq = amendment.seq;
        Ok(Box::pin(async move {
            let run = staged;
            journal.confirm(&run).await.map_err(|_| AmendPersistError)?;
            pending.lock().map_err(|_| AmendPersistError)?.remove(&seq);
            Ok(())
        }))
    }
}

async fn bind_native_amendments(amendments: &amend::NodeAmendments) {
    let journal = busbar_kernel::persistence::journal::RuntimeJournal::open(
        crate::real_store::core().await,
        busbar_kernel::door::op_id().counter(),
        busbar_kernel::persistence::journal::BufferBudget {
            records: busbar_kernel_wal::MEMORY_BUFFER_RECORDS,
            bytes: 32 * 1024 * 1024,
        },
    )
    .await
    .expect("the actual native fixture amendment journal opens");
    let sink = Arc::new(NativeAmendments {
        journal,
        pending: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        token: Kernel::new().durability_token(),
    });
    amendments
        .bind(Some(sink.clone() as Arc<dyn AmendSink>), 0, &sink.token)
        .await
        .expect("content handoffs bind their actual native amendment sink");
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
    /// The signals the deployment's hooks declare (`signals:`); none by default.
    pub requested: RequestedSignals,
}

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

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

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
                    conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
                },
            )
            .expect("a linked door binds")
            .served()
            .section
                == busbar_contract::section::RESERVED_POOLS_KEY
        })
        .expect("the driver-proofs row links the door serving the `pools` map")
}

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
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
        },
    )
    .expect("the plane door loads")
    .served()
    .dialects
    .iter()
    .map(|d| (*d).to_string())
    .collect()
}

fn door(dispatcher: &Dispatcher, settings: &[u8]) -> Plugin<Plane> {
    let row = LinkedRow::of(pools_door()).expect("the plane door states its Statement");
    let plugin = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from("the-plane"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
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
            providers: std::ptr::null(),
            providers_len: 0,
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

pub struct Answered {
    pub status: u32,
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
    pub sent: Vec<OutboundRequest>,
    pub outcome: Outcome,
}

impl Answered {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn model(&self) -> String {
        self.json()
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub struct Rig {
    driver: PlaneDriver,
    primary: Pool,
    fallback: Option<Pool>,

    _plugin: Arc<Plugin<Plane>>,

    amendments: Arc<busbar_kernel::audit::amend::NodeAmendments>,
}

impl Rig {
    pub async fn new(primary: Pool, fallback: Option<Pool>, hooks: Hooks) -> Self {
        bind_native_amendments(&hooks.callers.journal).await;
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
            workers: 2,
            ..DispatchConfig::default()
        }));
        let mut pools = vec![&primary];
        if let Some(f) = &fallback {
            pools.push(f);
        }
        let plugin = Arc::new(door(&dispatcher, &settings(&pools)));
        let calls = Arc::new(PlaneInstance::new(Arc::clone(&plugin), dispatcher, 1));
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
        .await
        .expect("the plane instance is admitted");
        let amendments = Arc::clone(&hooks.callers.journal);
        let driver = driver.with_hooks(Arc::new(hooks.bound(primary.name, dialects)));
        Rig {
            driver,
            primary,
            fallback,
            _plugin: plugin,
            amendments,
        }
    }

    pub fn amendments(&self) -> Arc<busbar_kernel::audit::amend::NodeAmendments> {
        Arc::clone(&self.amendments)
    }

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
            body: bytes::Bytes::copy_from_slice(body),
        };
        let units = self.driver.unit(steps, &far, &caller, arrival, 0);
        let outcome = drive(&units).await;
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

    pub async fn fire(&self, body: &Value) -> Answered {
        self.fire_with(
            &TestUnits::passing(),
            crate::proofs::wire::FIRE_TARGET,
            crate::proofs::wire::FIRE_FIELDS,
            &serde_json::to_vec(body).expect("body serializes"),
        )
        .await
    }

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
        taps: None,
    };
    match run_unit_async(&kernel, units, &ctx(7), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}
