// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARRIVAL-WINDOW CELLS of the in-process LLM plane walk (deleted in a65deda3dd), held here
//! unchanged while their door-path port is designed: the behaviour they pin (a unit bills and is
//! admitted against the window it ARRIVED in, not the clock) still holds on the door path, but the
//! door reads its arrival from the wall clock, so a port needs an arrival seam the door does not
//! have yet. Compiled in no build until then.

use super::*;

use busbar_kernel::ingress::arrival::ArrivalPayload;

include!(concat!(env!("OUT_DIR"), "/node_plane.rs"));
use self::node_plane::{proto_codec, testkit as plane};

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_kernel::teller::{Ended, Kernel};
use busbar_kernel_testkit::test_support::{
    LaneSpec, MockResponse, MockServer, MockServerState, TestApp,
};

use busbar_kernel_testkit::test_support::MockResponse::{
    Sse as EventStream, SseTransportError as CutEventStream,
};

const PROTO: &str = proto_codec::PROTO_OPENAI;
const POOL: &str = "p";
const LANE: &str = "m0";

const FEE_CENTS: i64 = 1;

const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

/// The six ends these fixtures name. Each is an END a client reaches, not a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixture {
    /// The whole loop, delivered, buffered.
    BufferedOk,
    /// The same loop with the accrual landing at stream end rather than at the buffered tap.
    StreamedOk,
    /// A body that is not JSON: the arrival step's own parse refusal, before a model exists.
    Malformed,
    /// A key whose group budget is spent: the door refuses and nothing is charged.
    OverBudget,
    /// A key that may not reach the pool it named: the pre-admission guard, before pricing.
    PoolAcl,
    /// A model that resolves to no pool and no lane: refused AFTER the door, so it is charged.
    UnknownModel,
}

impl Fixture {
    fn model(self) -> &'static str {
        match self {
            Fixture::UnknownModel => "no-such-model",
            _ => POOL,
        }
    }

    fn streamed(self) -> bool {
        matches!(self, Fixture::StreamedOk)
    }

    fn key_scopes(self) -> Option<Vec<String>> {
        match self {
            Fixture::PoolAcl => Some(vec!["some-other-pool".to_string()]),
            _ => None,
        }
    }

    fn seeded_group_requests(self) -> Option<u64> {
        matches!(self, Fixture::OverBudget).then_some(250)
    }

    fn upstream(self) -> MockResponse {
        match self {
            Fixture::StreamedOk => EventStream {
                events: event_stream_events(),
                abort_at_index: None,
            },
            _ => MockResponse::Ok {
                status: reqwest::StatusCode::OK,
                body: serde_json::json!({
                    "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
                    "model": LANE,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                              "total_tokens": INPUT + OUTPUT}
                }),
            },
        }
    }

    fn body(self) -> Bytes {
        if self == Fixture::Malformed {
            return Bytes::from_static(b"{not json");
        }
        let mut v = serde_json::json!({
            "model": self.model(),
            "messages": [{"role": "user", "content": "hi"}],
        });
        if self.streamed() {
            v["stream"] = serde_json::Value::Bool(true);
        }
        Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
    }
}

fn event_stream_events() -> Vec<String> {
    vec![
        serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {"role": "assistant",
                                                              "content": "hello"}}]})
        .to_string(),
        serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                                     "total_tokens": INPUT + OUTPUT}})
        .to_string(),
        "[DONE]".to_string(),
    ]
}

fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    h
}

fn unique(prefix: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}-{}", N.fetch_add(1, Ordering::SeqCst))
}

struct Rig {
    app: Arc<busbar_kernel::state::App>,
    key: Arc<busbar_contract::records::VirtualKey>,

    token: String,

    expired_token: String,
    server: MockServer,

    upstream: Arc<MockServerState>,
    charged_at: u64,
    group: String,
}

const SIGNING_SECRET: [u8; 32] = [7u8; 32];

const MINTED_AT: u64 = 1_700_000_000;
const LIVE_EXP: u64 = 4_000_000_000;
const DEAD_EXP: u64 = 1_000_000_000;

async fn rig(fixture: Fixture) -> Rig {
    rig_with_billing(fixture, false).await
}

async fn rig_billed(fixture: Fixture) -> Rig {
    rig_with_billing(fixture, true).await
}

async fn rig_with_billing(fixture: Fixture, billed: bool) -> Rig {
    plane::install_test_seams();
    busbar_kernel_testkit::test_support::metrics::init();

    let state = Arc::new(MockServerState::new());
    for _ in 0..8 {
        state.push(fixture.upstream());
    }
    let server = MockServer::new(Arc::clone(&state)).await;

    let group = unique("root-node");
    let mut groups = std::collections::BTreeMap::new();
    if fixture.seeded_group_requests().is_some() {
        groups.insert(
            group.clone(),
            busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_kernel::config::groups::LimitCfg {
                    metric: busbar_kernel::config::groups::LimitMetric::Budget,
                    amount: 100,
                    per: Some(busbar_kernel::config::groups::LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                    admission: None,
                    on_exhaustion: None,
                }],
                ..Default::default()
            },
        );
    }

    let store = (crate::root::real_store::core()).await;
    if let Some(requests) = fixture.seeded_group_requests() {
        (store.ledger().put_usage(
            &format!("group:{group}@total"),
            0,
            &busbar_contract::records::UsageLedger {
                requests,
                billable_requests: requests,
                models: vec![],
            },
        ))
        .await
        .expect("seed the durable bucket");
    }

    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &SIGNING_SECRET,
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        (busbar_kernel::governance::GovState::new_with_core(store, None, Some(signer)))
            .await
            .expect("governance"),
    );
    let spec = |name: &str| busbar_kernel::governance::NewKeySpec {
        name: name.to_string(),
        allowed_pools: fixture.key_scopes(),
        group: fixture
            .seeded_group_requests()
            .is_some()
            .then(|| group.clone()),
        labels: Default::default(),
        ..Default::default()
    };
    let (key, token) = (gov.mint_signed_async(spec("root-node"), LIVE_EXP, MINTED_AT))
        .await
        .expect("mint the deployment's key");
    let (_, expired_token) =
        (gov.mint_signed_async(spec("root-node-expired"), DEAD_EXP, MINTED_AT))
            .await
            .expect("mint the expired key");

    let priced_card = std::collections::BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 1.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let cost = busbar_kernel::cost::CostModel::resolve_parts(
        billed.then_some(&priced_card),
        FEE_CENTS,
        &groups,
    );
    (gov.hydrate_budgets_async(&cost, 0))
        .await
        .expect("hydrate");

    let app = TestApp::new()
        .keys_chain()
        .lane(LaneSpec::new(LANE, PROTO, &server.base_url()).provider("test"))
        .pool(POOL, &[(0, 1)])
        .governance(gov)
        .cost(cost)
        .build();

    Rig {
        app,
        key: Arc::new(key),
        token: token.expose(&busbar_kernel::seal::lend()).clone(),
        expired_token: expired_token.expose(&busbar_kernel::seal::lend()).clone(),
        server,
        upstream: state,
        charged_at: busbar_kernel::store::now(),
        group,
    }
}

impl Rig {
    fn gov(&self) -> busbar_contract::records::PlaneRequestCtx {
        busbar_contract::records::PlaneRequestCtx {
            key: Some(self.key.clone()),
        }
    }

    fn host(&self) -> Arc<dyn busbar_kernel::plane_driver::EngineHost> {
        busbar_kernel::plane_driver::engine_host(&self.app)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unit_arriving_at_a_window_boundary_bills_in_the_window_it_arrived_in() {
    use busbar_kernel::governance::metering_bucket;

    let rig = rig_billed(Fixture::BufferedOk).await;

    let arrival_secs = metering_bucket(rig.charged_at) - 1;
    let arrived = Arrived::at(arrival_secs * 1_000 + 999, 0);
    assert_eq!(
        arrived.secs(),
        arrival_secs,
        "the fixture really is on the last second of a bucket"
    );
    assert_ne!(
        metering_bucket(arrived.secs()),
        metering_bucket(arrived.secs() + 1),
        "and one second later is a different bucket, which is what makes this a straddle"
    );

    let node = Node::new();
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: Fixture::BufferedOk.body(),
        path: None,
    };
    let resp = node
        .answer_arriving_at(plane::handed(arrival, None), arrived)
        .await;

    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    tokio::task::yield_now().await;
    rig.server.shutdown().await;

    let gov = rig
        .app
        .governance
        .clone()
        .expect("governance is configured");
    (gov.flush_metering()).await;
    let rows_in = async |bucket| {
        (gov.metering_for_async(bucket))
            .await
            .expect("metering read")
            .into_iter()
            .filter(|r| r.key_id == rig.key.id)
            .count()
    };
    assert_eq!(
        rows_in(metering_bucket(arrived.secs())).await,
        1,
        "the unit's figures land in the bucket it arrived in"
    );
    assert_eq!(
        rows_in(metering_bucket(arrived.secs() + 1)).await,
        0,
        "and nothing leaked into the bucket the clock was about to roll into"
    );
}

const EPOCH: u64 = 1_700_000_000;

async fn rig_over(
    limit: Option<busbar_kernel::config::groups::LimitCfg>,
    card: Option<std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg>>,
    fee: i64,
    lane: impl FnOnce(&str) -> LaneSpec,
    replies: Vec<MockResponse>,
) -> Rig {
    plane::install_test_seams();
    busbar_kernel_testkit::test_support::metrics::init();
    let state = Arc::new(MockServerState::new());
    for reply in replies {
        state.push(reply);
    }
    let server = MockServer::new(Arc::clone(&state)).await;
    let group = unique("root-node-over");
    let groups: std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> = limit
        .map(|limit| {
            (
                group.clone(),
                busbar_kernel::config::GroupCfg {
                    parent: None,
                    enabled: true,
                    limits: vec![limit],
                    ..Default::default()
                },
            )
        })
        .into_iter()
        .collect();
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &SIGNING_SECRET,
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        (busbar_kernel::governance::GovState::new_with_core(
            (crate::root::real_store::core()).await,
            None,
            Some(signer),
        ))
        .await
        .expect("governance"),
    );
    let spec = |name: &str| busbar_kernel::governance::NewKeySpec {
        name: name.to_string(),
        group: groups.keys().next().cloned(),
        ..Default::default()
    };
    let (key, token) = (gov.mint_signed_async(spec("root-node-over"), LIVE_EXP, MINTED_AT))
        .await
        .expect("mint the deployment's key");
    let (_, expired_token) =
        (gov.mint_signed_async(spec("root-node-over-expired"), DEAD_EXP, MINTED_AT))
            .await
            .expect("mint the expired key");
    let cost = busbar_kernel::cost::CostModel::resolve_parts(card.as_ref(), fee, &groups);
    (gov.hydrate_budgets_async(&cost, 0))
        .await
        .expect("hydrate");
    let app = TestApp::new()
        .keys_chain()
        .lane(lane(&server.base_url()))
        .pool(POOL, &[(0, 1)])
        .governance(gov)
        .cost(cost)
        .build();
    Rig {
        app,
        key: Arc::new(key),
        token: token.expose(&busbar_kernel::seal::lend()).clone(),
        expired_token: expired_token.expose(&busbar_kernel::seal::lend()).clone(),
        server,
        upstream: state,
        charged_at: busbar_kernel::store::now(),
        group,
    }
}

fn the_lane(origin: &str) -> LaneSpec {
    LaneSpec::new(LANE, PROTO, origin).provider("test")
}

fn budget_per_day(amount: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount,
        per: Some(busbar_kernel::config::groups::LimitWindow::Day),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

fn chat_arrival(rig: &Rig, fixture: Fixture) -> plane::WalkArrival {
    plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: fixture.body(),
        path: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admission_check_reads_the_arrival_window_and_not_the_clock() {
    use busbar_kernel::governance::SECS_PER_DAY;
    let rig = rig_over(
        Some(budget_per_day(FEE_CENTS.unsigned_abs())),
        None,
        FEE_CENTS,
        the_lane,
        (0..4).map(|_| Fixture::BufferedOk.upstream()).collect(),
    )
    .await;
    let past_day = EPOCH;
    assert_ne!(
        past_day / SECS_PER_DAY,
        busbar_kernel::store::now() / SECS_PER_DAY,
        "precondition: the arrival day is not today"
    );
    let gov = rig
        .app
        .governance
        .clone()
        .expect("governance is configured");
    gov.try_admit(&rig.app.cost, &rig.key, "", past_day)
        .expect("the first request fits the cap exactly");
    assert_eq!(
        (gov.derived_bucket_usage_async(
            &rig.app.cost,
            &format!("group:{}@day", rig.group),
            "day",
            true,
            past_day
        ))
        .await
        .expect("usage read")
        .spend_cents,
        FEE_CENTS,
        "precondition: the arrival day's window is at its cap"
    );

    let node = Node::new();
    let refused = node
        .answer_arriving_at(
            plane::handed(chat_arrival(&rig, Fixture::BufferedOk), None),
            Arrived::at(past_day * 1_000, 0),
        )
        .await;
    assert_eq!(
        refused.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the unit is refused against the window it arrived in, where the spend lives"
    );
    let served = node
        .answer(plane::handed(chat_arrival(&rig, Fixture::BufferedOk), None))
        .await;
    let status = served.status();
    let _ = axum::body::to_bytes(served.into_body(), usize::MAX).await;
    rig.server.shutdown().await;
    assert_eq!(
        status,
        StatusCode::OK,
        "today's window is empty, so a unit arriving now is admitted"
    );
}
