// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_ONCE};
use busbar_contract::abi::transport::FAULT_HEALTHY;
use busbar_contract::caps::{Dial, PrincipalId, Route};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc, Piece, PieceKind, PollConns, Ticket,
};
use busbar_contract::ids::{OpClassId, StreamId};
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_contract::transport::ConnFacts;
use busbar_kernel::plane_driver::{
    DriverSteps, Egress, FarEnd, MemberRoute, OutboundRequest, Pick, DEFAULT_ERROR_BODY_MAX,
};
use busbar_kernel::teller::UnitCtx;
use busbar_kernel::test_hooks::tokens::{grant, pass};
use busbar_kernel_egress::ports::{
    Admit, BoxFut, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched, Disposition,
    DurabilityUnavailable, Journal, Outcome, Permit, PermitHandle, Telemetry, Unavailable,
    UpstreamStatus,
};
use busbar_kernel_egress::{Failover, Member, OnExhausted, Pool, WeightedFloor};

use super::DoorFar;
use crate::root::door_steps::{door_facts, egress_pool, DoorCaller, DoorPools, DoorSteps};

/// A far end answering every open with a `502` (the transport's fault reading: transient) and a
/// body, then completing.
#[derive(Default)]
struct BadGateway {
    live: Mutex<VecDeque<(Piece, Vec<u8>)>>,
}

fn piece(kind: PieceKind, len: usize) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: kind == PieceKind::Completion,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl Conns for BadGateway {
    fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        let body = br#"{"error":"bad gateway"}"#.to_vec();
        let mut live = self.live.lock().unwrap();
        live.push_back((
            Piece {
                status: Some(WireStatusClass::FarEndFault),
                status_code: Some(502),
                fault: Some(WireFault::Transient),
                ..piece(PieceKind::Body, body.len())
            },
            body,
        ));
        live.push_back((piece(PieceKind::Completion, 0), Vec::new()));
        Ok(ConnId(1))
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Ok(b.len())
    }
    fn read(&self, _: InstanceId, _: ConnId, _: Ticket, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Pending)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Ok(ConnFacts::default())
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        Ok(())
    }
}

impl PollConns for BadGateway {
    fn poll_read(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        match self.live.lock().unwrap().pop_front() {
            Some((p, b)) => {
                buf[..b.len()].copy_from_slice(&b);
                Poll::Ready(Ok(p))
            }
            None => Poll::Pending,
        }
    }
}

/// A breaker that classifies by the fault reading it is handed and records every outcome.
#[derive(Default)]
struct Book {
    observed: Mutex<Vec<Outcome>>,
}

impl Breaker for Book {
    fn try_admit(&self, _: &str, _: DestinationId, _: u64) -> Result<Admit, Unavailable> {
        Ok(Admit { probe_epoch: None })
    }
    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &busbar_contract::caps::Pass<Route>,
    ) -> Option<Unavailable> {
        let _ = (pool, destination, now, token);
        None
    }

    fn ready(
        &self,
        _: &str,
        _: DestinationId,
        _: u64,
        _: &busbar_contract::caps::Pass<Route>,
    ) -> bool {
        true
    }
    fn admissible(&self, _: DestinationId) -> bool {
        true
    }
    fn cooldown_remaining(
        &self,
        _: &str,
        _: DestinationId,
        _: u64,
        _: &busbar_contract::caps::Pass<Route>,
    ) -> u64 {
        0
    }
    fn classify(&self, _: DestinationId, s: UpstreamStatus) -> Classified {
        let (disposition, outcome, label) = match s.fault {
            Some(WireFault::Hard) => (Disposition::HardDown, Outcome::HardDown, "hard_down"),
            Some(WireFault::Transient) => (
                Disposition::TransientUpstream,
                Outcome::Transient {
                    retry_after: s.retry_after,
                },
                "transient",
            ),
            Some(WireFault::Healthy) => (Disposition::ClientFault, Outcome::Success, "healthy"),
            Some(WireFault::Caller) | None => (
                Disposition::ClientFault,
                Outcome::RecordNothing,
                "client_fault",
            ),
        };
        Classified {
            disposition,
            outcome,
            label,
        }
    }
    fn observe(
        &self,
        _: &str,
        _: DestinationId,
        o: Outcome,
        _: u64,
        _: &busbar_contract::caps::Pass<Route>,
    ) -> bool {
        self.observed.lock().unwrap().push(o);
        false
    }
    fn suppressing(&self, _: DestinationId, _: u64) -> bool {
        false
    }
    fn probed(&self, _: DestinationId, _: Outcome, _: u64, _: &busbar_contract::caps::Pass<Route>) {
    }
    fn release_probe(&self, _: &str, _: DestinationId, _: u64, _: u64) {}
    fn spend_budget(&self, _: DestinationId) -> bool {
        true
    }
    fn refund_budget(&self, _: DestinationId) {}
}

#[derive(Debug)]
struct Slot(DestinationId);
impl PermitHandle for Slot {
    fn destination(&self) -> DestinationId {
        self.0
    }
}

struct Free;
impl Capacity for Free {
    fn try_acquire(&self, d: DestinationId) -> Option<Permit> {
        Some(Permit::new(Box::new(Slot(d))))
    }
    fn acquire_any<'a>(
        &'a self,
        _: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(async { None })
    }
}

struct Wall;
impl Clock for Wall {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    fn now_millis(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }
    fn sleep(&self, ms: u64) -> BoxFut<'_, ()> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
    }
}

struct Quiet;
impl Journal for Quiet {
    fn dispatched(&self, _: &Dispatched) -> Result<(), DurabilityUnavailable> {
        Ok(())
    }
    fn abandoned(&self, _: &Dispatched) {}
}
impl Telemetry for Quiet {
    fn upstream_attempt(&self, _: &str, _: DestinationId) {}
    fn upstream_failure(&self, _: &str, _: DestinationId, _: &'static str) {}
    fn failover(&self, _: &str, _: &'static str) {}
    fn breaker_trip(&self, _: &str, _: DestinationId) {}
    fn queued(&self, _: &str, _: i64) {}
}

#[tokio::test]
async fn the_planes_fault_reading_reaches_the_breaker_through_the_doors_far_end() {
    crate::dist_root_install::install();
    let module = crate::LINKED
        .stores
        .iter()
        .find(|row| row.1)
        .expect("the assembled product links an ephemeral store")
        .0;
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": {}}
    }))
    .expect("the actual deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual root builds the far-end generation");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD.keep_in_store(
        app.governance
            .as_ref()
            .expect("the actual deployment configured governance")
            .store_calls()
            .expect("the actual configured Store exposes its rate-history slots"),
        124,
    );
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual configured Store boots its rate history");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let facts = door_facts("p", &[], &[], &[], "a", Vec::new());
    let section: serde_yaml::Value = serde_yaml::from_str("e: {}").expect("yaml");
    let pools = DoorPools::of(&section, busbar_contract::section::TOOL_CALL_SECTION_KEY)
        .expect("the pools");
    let steps = DoorSteps::new(
        &facts,
        &pools,
        Arc::new(|_: &str| None),
        Arc::new(app),
        None,
        DoorCaller {
            principal: PrincipalId::new("vk_one"),
            key: None,
            open: true,
            arrived: 0,
            records: None,
            depth: 0,
            credential: None,
            ticket: None,
        },
    );
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    steps.decoded(&ctx, OpClassId::new("op"), ROUTE_DIRECT, Some(b"e"));
    steps.route_flags(&ctx, ROUTE_ONCE);
    let _ = steps.verify(&grant::<Dial>(), &ctx, &PrincipalId::new("vk_one"));
    let routed = steps.routed().expect("the unit is routed to `e`");
    assert!(steps.once(), "performed at most once");

    let pool_name = egress_pool("p", &routed);
    let destination = DestinationId::new(1);
    let book = Arc::new(Book::default());
    let egress = Egress {
        caller: InstanceId(9),
        conns: Arc::new(BadGateway::default()),
        breaker: busbar_kernel::plane_driver::fixed_breaker(book.clone()),
        capacity: Arc::new(Free),
        clock: Arc::new(Wall),
        journal: Arc::new(Quiet),
        telemetry: Arc::new(Quiet),
        pools: HashMap::from([(
            pool_name.clone(),
            Pool {
                name: pool_name.clone(),
                members: vec![Member::new(destination, "e", 1)],
                failover: Failover {
                    timeout_secs: 30,
                    max_hops: 1,
                    exclusions: Vec::new(),
                },
                on_exhausted: OnExhausted::Status503,
                floor: WeightedFloor::new(),
            },
        )]),
        routes: HashMap::from([(
            destination,
            MemberRoute {
                need: NeedId(0),
                base_url: "https://far.test/".into(),
                auth: None,
                provider: "e".into(),
                keep: Default::default(),
                rides: Vec::new(),
                anchors: Default::default(),
                spelled: Vec::new(),
            },
        )]),
        stream_ceiling_secs: 600,
        stated_ceiling_secs: 0,
        error_body_max: DEFAULT_ERROR_BODY_MAX,
    };
    let far = DoorFar {
        egress: Some(&egress),
        steps: &steps,
        unit: busbar_contract::UnitKey::new(1),
        credential: None,
        far: OnceLock::new(),
        shown: None,
    };
    let t = pass::<Route>();
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    let request = OutboundRequest {
        text: false,
        member: String::new(),
        pool: String::new(),
        attempt_no: 1,
        verb: b"POST".to_vec(),
        target: b"/x".to_vec(),
        fields: Vec::new(),
        body: b"{}".to_vec(),
        need: 0,
    };
    assert!(far.send(&t, request).await);
    let first = far.next(&t).await.expect("the 502 is relayed");
    assert!(
        !first.fail_over,
        "an operation performed at most once is relayed"
    );
    assert_eq!(first.status.map(|(code, _)| code), Some(502));

    far.judged(&t, FAULT_HEALTHY);
    while let Some(p) = far.next(&t).await {
        if p.last {
            break;
        }
    }
    drop(far);
    assert_eq!(
        *book.observed.lock().unwrap(),
        vec![Outcome::Success],
        "the plane's reading is recorded, never the transport's transient"
    );
}
