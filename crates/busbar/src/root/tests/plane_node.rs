use super::*;
use busbar_kernel_testkit::test_support::governance::GovStateFixtures;

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

    let store = crate::root::real_store::records();
    if let Some(requests) = fixture.seeded_group_requests() {
        use busbar_contract::records::RecordStore as _;
        store
            .put_usage(
                &format!("group:{group}@total"),
                0,
                &busbar_contract::records::UsageLedger {
                    requests,
                    billable_requests: requests,
                    models: vec![],
                },
            )
            .expect("seed the durable bucket");
    }

    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &SIGNING_SECRET,
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(store, None, Some(signer))
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
    let (key, token) = gov
        .mint_signed(spec("root-node"), LIVE_EXP, MINTED_AT)
        .expect("mint the deployment's key");
    let (_, expired_token) = gov
        .mint_signed(spec("root-node-expired"), DEAD_EXP, MINTED_AT)
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
    gov.hydrate_budgets(&cost, 0).expect("hydrate");

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

const VOLATILE_HEADERS: [&str; 6] = [
    "date",
    "request-id",
    "x-request-id",
    "x-amzn-requestid",
    "x-amzn-request-id",
    "retry-after",
];

/// Everything one leg left behind, as comparable strings.
#[derive(Debug, PartialEq, Eq)]
struct Observed(Vec<(&'static str, String)>);

fn normalize(s: &str) -> String {
    fn blank(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let is_id = k.ends_with("id") || k.ends_with("Id") || k.ends_with("ID");
                    let is_clock = matches!(k.as_str(), "created" | "created_at" | "createTime");
                    if is_id && val.is_string() {
                        *val = serde_json::Value::String("<id>".to_string());
                    } else if (is_clock || k == "latencyMs") && val.is_number() {
                        *val = serde_json::Value::from(0);
                    } else {
                        blank(val);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(blank),
            _ => {}
        }
    }
    if s.contains("data:") {
        return s
            .lines()
            .map(|line| match line.strip_prefix("data: ") {
                Some(rest) => format!("data: {}", normalize(rest)),
                None => line.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(mut v) => {
            blank(&mut v);
            v.to_string()
        }
        Err(_) => s.to_string(),
    }
}

fn normalize_body(body: &[u8]) -> String {
    match event_stream_frames(body) {
        Some(frames) => frames
            .into_iter()
            .map(|(headers, payload)| {
                format!(
                    "{}|{}",
                    String::from_utf8_lossy(headers),
                    normalize(&String::from_utf8_lossy(payload))
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        None => normalize(&String::from_utf8_lossy(body)),
    }
}

fn event_stream_frames(mut body: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let be = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    let mut frames = Vec::new();
    while !body.is_empty() {
        if body.len() < 16 {
            return None;
        }
        let (total, headers_len) = (be(&body[0..4]), be(&body[4..8]));
        if total < 16 + headers_len || total > body.len() {
            return None;
        }
        frames.push((
            &body[12..12 + headers_len],
            &body[12 + headers_len..total - 4],
        ));
        body = &body[total..];
    }
    (!frames.is_empty()).then_some(frames)
}

#[test]
fn event_stream_bodies_compare_without_their_clock() {
    fn frame(payload: &str) -> Vec<u8> {
        let headers = b":event-type metadata";
        let total = 12 + headers.len() + payload.len() + 4;
        let mut out = Vec::new();
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0xAA; 4]);
        out.extend_from_slice(headers);
        out.extend_from_slice(payload.as_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out
    }
    let stream = |ms: u32, text: &str| {
        let mut body = frame(&format!(r#"{{"delta":{{"text":"{text}"}}}}"#));
        body.extend(frame(&format!(r#"{{"metrics":{{"latencyMs":{ms}}}}}"#)));
        body
    };
    assert_eq!(
        normalize_body(&stream(0, "hello")),
        normalize_body(&stream(137, "hello"))
    );
    assert_ne!(
        normalize_body(&stream(0, "hello")),
        normalize_body(&stream(0, "hellp"))
    );
}

fn field(o: &Observed, k: &str) -> String {
    o.0.iter()
        .find(|(f, _)| *f == k)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn compare(label: &str, legacy: &Observed, looped: &Observed, failures: &mut Vec<String>) {
    for ((f, want), (_, got)) in legacy.0.iter().zip(looped.0.iter()) {
        if want != got {
            failures.push(format!(
                "{label}: field `{f}` diverges\n  shipped: {want}\n  loop:    {got}"
            ));
        }
    }
}

async fn observe(rig: &Rig, resp: Response) -> Observed {
    use busbar_kernel::store::BreakerState;

    let mut fields: Vec<(&'static str, String)> = Vec::new();
    fields.push(("status", resp.status().as_u16().to_string()));
    let mut headers: Vec<String> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            if VOLATILE_HEADERS.contains(&k.as_str()) {
                format!("{k}: <volatile>")
            } else {
                format!("{k}: {}", String::from_utf8_lossy(v.as_bytes()))
            }
        })
        .collect();
    headers.sort();
    fields.push(("headers", headers.join("\n")));
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    fields.push(("body", normalize_body(&body).replace(&rig.group, "<group>")));

    tokio::task::yield_now().await;

    let gov = rig
        .app
        .governance
        .clone()
        .expect("governance is configured");
    let derived = gov
        .derived_bucket_usage(&rig.app.cost, &rig.key.id, "total", true, rig.charged_at)
        .expect("usage read");
    fields.push(("ledger_requests", derived.requests.to_string()));
    fields.push(("ledger_tokens", derived.tokens.to_string()));
    fields.push(("ledger_spend_cents", derived.spend_cents.to_string()));
    gov.flush_metering();
    let mut rows: Vec<busbar_contract::records::MeteringRow> = gov
        .metering_for(busbar_kernel::governance::metering_bucket(rig.charged_at))
        .expect("metering read")
        .into_iter()
        .filter(|r| r.key_id == rig.key.id)
        .collect();
    rows.sort_by(|a, b| (&a.model, &a.provider).cmp(&(&b.model, &b.provider)));
    fields.push((
        "metering_rows",
        rows.iter()
            .map(|r| {
                format!(
                    "{}/{} in={} out={} cr={} cw={} req={} billable={}",
                    r.model,
                    r.provider,
                    r.tokens_input,
                    r.tokens_output,
                    r.tokens_cache_read,
                    r.tokens_cache_write,
                    r.requests,
                    r.billable_requests
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    ));

    let store = &*rig.app.store;
    fields.push((
        "breaker",
        match store.breaker_state_in(POOL, 0) {
            BreakerState::Closed => "Closed",
            BreakerState::Open { .. } => "Open",
            BreakerState::HalfOpen => "HalfOpen",
        }
        .to_string(),
    ));
    fields.push(("admissible", store.lane_admissible(0).to_string()));

    Observed(fields)
}

async fn leg_legacy(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let resp = plane::shell::operation_ingress(
        &ctx,
        json_headers(),
        fixture.body(),
        PROTO,
        busbar_contract::operation::OpVerb::CHAT,
        None,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

async fn leg_loop(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let resp = drive(&rig, fixture).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

async fn leg_loop_billed(fixture: Fixture) -> Observed {
    let rig = rig_billed(fixture).await;
    let resp = drive(&rig, fixture).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

async fn drive(rig: &Rig, fixture: Fixture) -> Response {
    let node = Node::new();
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: fixture.body(),
        path: None,
    };
    node.answer(plane::handed(arrival, None)).await
}

#[test]
fn one_arrival_reading_spells_both_the_figures_the_loop_asks_for() {
    const LAST_MILLISECOND: u64 = 1_700_000_000_999;
    let arrived = Arrived::at(LAST_MILLISECOND, 0);
    assert_eq!(arrived.ms(), LAST_MILLISECOND, "the reading, unmodified");
    assert_eq!(
        arrived.secs(),
        1_700_000_000,
        "and the window it lands in, which is the second that has not ended yet"
    );
    assert_eq!(
        arrived.ms() / 1_000,
        arrived.secs(),
        "the two figures are one instant: neither can be on the far side of a boundary the \
         other is on the near side of"
    );
}

#[test]
fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp() {
    let node = Node::new();
    let taken: Vec<Arrived> = (0..4).map(|_| node.arrived()).collect();

    for pair in taken.windows(2) {
        let (before, after) = (pair[0], pair[1]);
        assert!(
            after.mono() > before.mono(),
            "the reading that orders them only goes up: {} then {}",
            before.mono(),
            after.mono()
        );
    }

    assert!(
        taken
            .iter()
            .all(|a| a.secs() == taken[0].secs() || a.secs() == taken[0].secs() + 1),
        "the four were taken within a second of each other"
    );

    assert_ne!(taken[0].mono(), taken[0].secs());

    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let book = std::sync::Arc::new(std::sync::Mutex::new(durability));
    let seam = crate::root::durability::SharedBook::over(std::sync::Arc::clone(&book));
    let who = PrincipalId::new("acct:node");
    for arrived in [Arrived::at(EPOCH * 1_000, 7), Arrived::at(EPOCH * 1_000, 8)] {
        let ledger_token = busbar_kernel_testkit::test_support::tokens::grant::<
            busbar_contract::caps::WriteMoney,
        >();
        let accrual =
            busbar_contract::caps::HoldAccrual::after_terminal(who.clone(), 0, &ledger_token);
        let posted = busbar_contract::caps::Posted::settle_late(accrual, &ledger_token);
        settle(
            &seam,
            &who,
            arrived,
            None,
            &busbar_kernel_testkit::test_support::tokens::grant::<
                busbar_contract::caps::DurableWrite,
            >(),
            posted,
        )
        .expect("the memory-buffered journal takes it");
    }
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 2, "two postings, two records");
    assert_eq!(
        replayed[0].wall, replayed[1].wall,
        "settled at one wall second, so the date cannot separate them"
    );
    assert!(
        replayed[1].mono > replayed[0].mono,
        "and the stamp that can does: {} then {}",
        replayed[0].mono,
        replayed[1].mono
    );
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
    gov.flush_metering();
    let rows_in = |bucket| {
        gov.metering_for(bucket)
            .expect("metering read")
            .into_iter()
            .filter(|r| r.key_id == rig.key.id)
            .count()
    };
    assert_eq!(
        rows_in(metering_bucket(arrived.secs())),
        1,
        "the unit's figures land in the bucket it arrived in"
    );
    assert_eq!(
        rows_in(metering_bucket(arrived.secs() + 1)),
        0,
        "and nothing leaked into the bucket the clock was about to roll into"
    );
}

const CASES: [Fixture; 6] = [
    Fixture::BufferedOk,
    Fixture::StreamedOk,
    Fixture::Malformed,
    Fixture::OverBudget,
    Fixture::PoolAcl,
    Fixture::UnknownModel,
];

const EPOCH: u64 = 1_700_000_000;

fn history_of(entries: &[(u64, f64)]) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    for (n, (from, output)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(*output),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            0,
            true,
        );
        history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_kernel_ledger::cost::HistorySeq((entries.len() - 1) as u64),
    )
}

fn report_of(output: u64) -> Report {
    Report {
        usage: busbar_contract::billing::Usage {
            usage_units: std::collections::BTreeMap::from([(
                busbar_contract::records::UNIT_OUTPUT.to_string(),
                output,
            )]),
        },
        fee_count: 0,
        lane: "lane".to_string(),
    }
}

#[test]
fn a_unit_prices_at_the_entry_in_force_when_it_arrived_and_not_at_the_head() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0), (5_000, 100.0)]);

    let early = priced_amount(&history, Arrived::at(4_999, 1), &token, &report_of(1_000));
    let late = priced_amount(&history, Arrived::at(5_000, 2), &token, &report_of(1_000));

    assert_eq!(
        early,
        Ok(1_000_000),
        "a unit that arrived before the appended entry was re-priced at it"
    );
    assert_eq!(
        late,
        Ok(100_000_000),
        "a unit that arrived after the appended entry was priced at the entry it superseded"
    );
}

#[test]
fn a_snapshot_pinned_at_admission_cannot_see_an_entry_appended_behind_it() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(1.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            0,
            true,
        ),
        1_000,
    );
    let admitted = holder
        .pin()
        .expect("the boot resolution put an entry in place");

    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(100.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            0,
            true,
        ),
        2_000,
    );
    let next = holder.pin().expect("the apply put a second entry in place");

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&admitted, at, &token, &report_of(1_000)),
        Ok(1_000_000),
        "the pinned snapshot saw an entry appended after the unit was admitted"
    );
    assert_eq!(
        priced_amount(&next, at, &token, &report_of(1_000)),
        Ok(100_000_000),
        "the next admission did not see the appended entry"
    );
}

#[test]
fn a_pin_below_the_head_reads_the_history_as_it_stood_at_that_seq() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let head = history_of(&[(0, 1.0), (5_000, 100.0)]);
    let earlier = crate::root::kernel::PinnedHistory::for_test_at(
        &head,
        busbar_kernel_ledger::cost::HistorySeq(0),
    );

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&earlier, at, &token, &report_of(1_000)),
        Ok(1_000_000),
        "a snapshot at seq 0 resolved an entry that was appended after it"
    );
    assert_eq!(
        priced_amount(&head, at, &token, &report_of(1_000)),
        Ok(100_000_000),
        "the head snapshot did not resolve the entry appended onto it"
    );
}

#[test]
fn the_posting_carries_no_price_and_its_figure_is_the_lookups() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0)]);
    let at = Arrived::at(4_000, 7);

    let (posting, priced) = priced_posting(&history, at, &token, &report_of(1_000));
    let priced = priced.expect("a card in force at the instant prices the report");
    assert_eq!(
        posting.arrived_ms, 4_000,
        "the posting kept its own instant"
    );
    assert_eq!(posting.arrived_mono, 7);
    assert_eq!(
        posting
            .priced_nanos(&history.view())
            .expect("the lookup still answers"),
        priced.priced_nanos,
        "the posting's figure is the lookup's, asked again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_exit_arm_puts_the_loops_posting_on_the_journal() {
    let rig = rig(Fixture::BufferedOk).await;
    let node = Node::new();
    let ended = drive_to_end(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    rig.server.shutdown().await;

    let Ended::Settled { end, .. } = ended else {
        panic!("the exit path settles the unit");
    };
    let posted = end.into_posted().expect("the usage report fits the record");
    assert_eq!(
        posted.reserved(),
        0,
        "this plane's door opens the kernel's hold at zero; the spend is the governance ledger's"
    );

    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let book = std::sync::Arc::new(std::sync::Mutex::new(durability));
    let who = PrincipalId::new("acct:node");
    let settled = settle(
        &crate::root::durability::SharedBook::over(std::sync::Arc::clone(&book)),
        &who,
        Arrived::at(EPOCH * 1_000, 0),
        None,
        &busbar_kernel_testkit::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>(
        ),
        posted,
    )
    .expect("the memory-buffered journal takes it");
    assert!(settled.overdraft.is_none(), "nothing to carry out");

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, EPOCH);
    let figures = durability.ledger.book().get(&balance(&who), window);
    assert_eq!(figures.overdraft_carried_out, 0);
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 1, "one posting, one record");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_driven_planes_abandoned_end_posts_once_onto_the_nodes_book() {
    use busbar_kernel::plane_driver::EndPost;
    let rig = rig(Fixture::BufferedOk).await;
    let node = Arc::new(Node::new());
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));
    let posted = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies")
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let ctx = |key: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let who = PrincipalId::new("acct:node");

    let ended = drive_to_end(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    site.open(
        UnitKey::new(41),
        who.clone(),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );

    let before = posted();
    site.post(&ctx(41), ended);
    assert!(posted() > before, "the abandoned end is on the book");
    let ended = drive_to_end(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    let before = posted();
    site.post(&ctx(41), ended);
    assert_eq!(posted(), before, "an end posts at most once");

    let ended = drive_to_end(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    site.open(UnitKey::new(42), who, Arrived::at(EPOCH * 1_000, 1), None);
    site.close(UnitKey::new(42));
    let before = posted();
    site.post(&ctx(42), ended);
    assert_eq!(posted(), before, "a returned unit's end is not this site's");
    assert_eq!(site.open_units(), 0, "every unit's facts closed");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_driven_planes_abandoned_end_seals_one_audit_record() {
    use busbar_kernel::plane_driver::EndPost;
    let rig = rig(Fixture::BufferedOk).await;
    let node = Arc::new(Node::new());
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));
    let records = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .audit_records
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let ctx = |key: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let who = PrincipalId::new("acct:node");
    let facts = busbar_contract::caps::AuditFacts {
        op_class: busbar_contract::caps::OpClassId::new("call"),
        finish: busbar_contract::FinishClass::Complete,
    };

    let ended = drive_to_end(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    site.open(
        UnitKey::new(51),
        who.clone(),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    site.audited(
        UnitKey::new(51),
        facts,
        busbar_kernel_testkit::test_support::tokens::pass(),
    );
    let before = records();
    site.post(&ctx(51), ended);
    assert_eq!(
        records(),
        before + 1,
        "exactly one audit record for the abandoned unit"
    );

    let ended = drive_to_end(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    site.open(UnitKey::new(52), who, Arrived::at(EPOCH * 1_000, 1), None);
    let before = records();
    site.post(&ctx(52), ended);
    assert_eq!(records(), before, "no pass, no record");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_unit_the_node_answers_served_or_refused_seals_one_record_on_one_tamper_evident_chain(
) {
    let rig = rig(Fixture::BufferedOk).await;
    let node = Node::new();
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let answer = |fixture: Fixture| {
        let arrival = plane::WalkArrival {
            host: rig.host(),
            gov: rig.gov(),
            proto: PROTO,
            operation: busbar_contract::operation::OpVerb::CHAT,
            caller_token: None,
            headers: json_headers(),
            query: None,
            body: fixture.body(),
            path: None,
        };
        node.answer(plane::handed(arrival, None))
    };

    let served = answer(Fixture::BufferedOk).await;
    assert_eq!(served.status(), StatusCode::OK, "the completion is served");
    let _ = axum::body::to_bytes(served.into_body(), usize::MAX)
        .await
        .expect("the served body drains");
    let refused = answer(Fixture::Malformed).await;
    assert!(
        refused.status().is_client_error(),
        "the unreadable body is refused: {}",
        refused.status()
    );
    let _ = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .expect("the refusal drains");
    rig.server.shutdown().await;

    let durability = book.durability.lock().expect("unpoisoned");
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 2, "one record per unit: {records:?}");
    let (served, refused) = (&records[0], &records[1]);
    assert_eq!(
        served.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed,
        "the dispatch is chained as served"
    );
    assert!(
        matches!(
            refused.outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(..)
        ),
        "the refusal is chained as one: {:?}",
        refused.outcome
    );
    assert_eq!(refused.seq, served.seq + 1, "contiguous");
    assert_eq!(
        refused.prev_hash, served.hash,
        "linked to the record before"
    );
    assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());
    assert!(
        durability.retained_audit_findings().is_empty(),
        "the node's own verify finds nothing"
    );

    let mut forged = records.clone();
    forged[0].outcome.unit_end = refused.outcome.unit_end;
    assert!(
        busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
        "a record altered after its seal breaks the chain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_origin_unit_posts_no_flat_fee() {
    let rig = rig(Fixture::BufferedOk).await;
    let node = Node::new();
    let (unit, _ended) = drive_keeping_the_unit(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        plane::native_seats(),
    )
    .await;
    rig.server.shutdown().await;

    let fee = |origin| {
        let ctx = UnitCtx {
            call: busbar_contract::caps::CallId::UNBOUND,
            key: UnitKey::new(1),
            origin,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        unit.evidence(&ctx).fee_units
    };
    assert_eq!(
        fee(OriginKind::Client),
        1,
        "a client's delivered request pays the flat per-request fee"
    );
    assert_eq!(
        fee(OriginKind::Provider),
        0,
        "a unit the node ran for a provider is nobody's request and posts no fee"
    );
}

async fn drive_to_end(
    rig: &Rig,
    node: &Node,
    fixture: Fixture,
    gov: busbar_contract::records::PlaneRequestCtx,
    seats: &'static [&'static (dyn plane::VetoSeat + Sync)],
) -> Ended {
    drive_keeping_the_unit(rig, node, fixture, gov, seats)
        .await
        .1
}

async fn drive_keeping_the_unit(
    rig: &Rig,
    node: &Node,
    fixture: Fixture,
    gov: busbar_contract::records::PlaneRequestCtx,
    seats: &'static [&'static (dyn plane::VetoSeat + Sync)],
) -> (Arc<dyn Units + Send + Sync>, Ended) {
    drive_screened_by(rig, node, fixture, gov, seats, None).await
}

struct Screening<'r> {
    inner: &'r (dyn RouteAwait + Send + Sync),
    reason: busbar_contract::caps::ReasonCode,
}

impl RouteAwait for Screening<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        self.inner.route_leg(token, ctx, destinations)
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.inner.abandoned(ctx, ended);
    }

    fn screen<'a>(&'a self, _ctx: &'a UnitCtx) -> busbar_kernel::teller::Screen<'a> {
        let reason = self.reason;
        Box::pin(async move { Err(Refusal::new(reason)) })
    }
}

async fn drive_screened_by(
    rig: &Rig,
    node: &Node,
    fixture: Fixture,
    gov: busbar_contract::records::PlaneRequestCtx,
    seats: &'static [&'static (dyn plane::VetoSeat + Sync)],
    screen: Option<busbar_contract::caps::ReasonCode>,
) -> (Arc<dyn Units + Send + Sync>, Ended) {
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov,
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: fixture.body(),
        path: None,
    };
    let (principal, op_class, _proto, build) = plane::handed_seated(arrival, None, seats);
    let key = node.next_key.mint();
    let meter = Arc::new(AccrualMeter::new());
    let (units, route, _finish) = build((node.resolver(), EPOCH));
    let screening = screen.map(|reason| Screening {
        inner: &*route,
        reason,
    });
    let route: &(dyn RouteAwait + Send + Sync) = match &screening {
        Some(s) => s,
        None => &*route,
    };
    let history = crate::root::kernel::ROOT_CARD.pin();
    let hold = busbar_kernel::inflight::arrival_hold(
        &node.kernel,
        &node.door,
        principal.clone(),
        node.kernel.next_call(),
    );
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: busbar_kernel::store::now_ms(),
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let driven = Driven {
        node,
        route,
        op_class,
        principal: &principal,
        arrived: Arrived::at(EPOCH * 1_000, 0),
        history: history.as_ref(),
        sealing: Mutex::new(None),
    };
    let ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &*units,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
            taps: Some(&driven),
        },
        &driven,
    )
    .await;
    node.inflight.remove(key);
    (units, ended)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_matches_the_shipped_entry_point_on_every_fixture() {
    let mut failures: Vec<String> = Vec::new();
    for fixture in CASES {
        let legacy = leg_legacy(fixture).await;
        let looped = leg_loop(fixture).await;
        for ((field, want), (_, got)) in legacy.0.iter().zip(looped.0.iter()) {
            if want != got {
                failures.push(format!(
                    "{fixture:?}: field `{field}` diverges\n  shipped: {want}\n  loop:    {got}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} divergence(s) across {} fixtures:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_fixture_reaches_the_end_it_names() {
    let mut seen: Vec<(Fixture, String)> = Vec::new();
    for fixture in CASES {
        let observed = leg_loop(fixture).await;
        let status = observed
            .0
            .iter()
            .find(|(k, _)| *k == "status")
            .map(|(_, v)| v.clone())
            .expect("every leg observes a status");
        seen.push((fixture, status));
    }
    assert_eq!(
        seen,
        vec![
            (Fixture::BufferedOk, "200".to_string()),
            (Fixture::StreamedOk, "200".to_string()),
            // The arrival step's own parse refusal, before a model exists.
            (Fixture::Malformed, "400".to_string()),
            // The door's own turn-away.
            (Fixture::OverBudget, "429".to_string()),
            // The pre-admission guard, before pricing is asked about.
            (Fixture::PoolAcl, "403".to_string()),
            // Refused AFTER the door, so it is charged and audited as an admitted unit.
            (Fixture::UnknownModel, "404".to_string()),
        ],
        "the fixtures do not reach the six distinct ends they are named for"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_leaves_the_money_where_the_shipped_plane_leaves_it() {
    let streamed = leg_loop_billed(Fixture::StreamedOk).await;
    assert_eq!(field(&streamed, "ledger_requests"), "1");
    assert_eq!(
        field(&streamed, "ledger_tokens"),
        (INPUT + OUTPUT).to_string(),
        "the stream-end tap accrued the reported split"
    );
    assert_eq!(
        field(&streamed, "metering_rows"),
        format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1")
    );

    let delivered = leg_loop_billed(Fixture::BufferedOk).await;
    assert_eq!(field(&delivered, "ledger_requests"), "1");
    assert_eq!(
        field(&delivered, "metering_rows"),
        format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1")
    );

    let refused = leg_loop(Fixture::OverBudget).await;
    assert_eq!(field(&refused, "ledger_requests"), "0");
    assert_eq!(field(&refused, "metering_rows"), "");

    let guarded = leg_loop(Fixture::PoolAcl).await;
    assert_eq!(field(&guarded, "ledger_requests"), "0");

    let post_door = leg_loop(Fixture::UnknownModel).await;
    assert_eq!(field(&post_door, "ledger_requests"), "1");
    assert_eq!(field(&post_door, "metering_rows"), "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_that_hangs_up_mid_dispatch_keeps_its_flat_fee_charged() {
    let rig = rig_billed(Fixture::BufferedOk).await;
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());

    rig.upstream.push(MockResponse::Gated {
        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        body: serde_json::json!({"error": {"message": "still answering", "type": "server_error"}}),
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });
    tokio::select! {
        _ = drive(&rig, Fixture::BufferedOk) => {
            panic!("the upstream holds its body, so the unit cannot have answered");
        }
        // The route step is reading the held body: the caller goes away here, and the answer
        // future is dropped with the unit inside its one await.
        () = started.notified() => {}
    }
    release.notify_one();
    let observed = observe(&rig, Response::new(axum::body::Body::empty())).await;
    rig.server.shutdown().await;
    assert_eq!(
        field(&observed, "ledger_requests"),
        "1",
        "the door drew the admission slot"
    );
    assert_eq!(
        field(&observed, "ledger_spend_cents"),
        FEE_CENTS.to_string(),
        "a caller that went away mid-dispatch is refunded nothing: the flat fee stays charged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn billing_off_serves_free_writes_its_metering_row_reading_zero_yet_still_governs() {
    let free = leg_loop(Fixture::BufferedOk).await;
    assert_eq!(
        field(&free, "status"),
        "200",
        "billing off still serves the request (a free failover/routing proxy)"
    );
    let row = format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1");
    assert_eq!(
        field(&free, "metering_rows"),
        row,
        "billing off (no rate_card) still writes the plane's counts: the ledger is what the plane did (#43)"
    );

    assert_eq!(
        field(&free, "ledger_spend_cents"),
        FEE_CENTS.to_string(),
        "billing off is the VIEW reading the counts as 0 (#42): only the flat fee posts"
    );

    let billed = leg_loop_billed(Fixture::BufferedOk).await;
    assert_eq!(
        field(&billed, "metering_rows"),
        row,
        "the same request on a billed plane writes exactly the same metering row"
    );

    let guarded = leg_loop(Fixture::PoolAcl).await;
    assert_eq!(
        field(&guarded, "ledger_requests"),
        "0",
        "billing off still runs admission governance — the pool-ACL guard refuses"
    );
    assert_eq!(field(&guarded, "metering_rows"), "");
}

static DIALECTS: LazyLock<serde_json::Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
        .expect("the dialect fixture is JSON")
});

fn path_dialects() -> Vec<&'static str> {
    crate::LINKED
        .path_ingress
        .iter()
        .flat_map(|table| table.iter().map(|(name, _)| *name))
        .collect()
}

fn linked_dialect(name: &str) -> &'static str {
    path_dialects()
        .into_iter()
        .chain(body_dialects())
        .find(|d| *d == name)
        .unwrap_or_else(|| panic!("the fixture names `{name}`, which no linked table declares"))
}

fn path_row(proto: &str) -> &'static serde_json::Value {
    DIALECTS["path_model"]
        .as_array()
        .expect("the fixture's `path_model` is a list")
        .iter()
        .find(|row| row["dialect"] == proto)
        .unwrap_or_else(|| panic!("the fixture has no `path_model` row for `{proto}`"))
}

fn miss_copy(proto: &str, model: &str) -> Option<String> {
    path_row(proto)["model_not_found"]
        .as_str()
        .map(|copy| copy.replace("{model}", model))
}

fn over_budget_status(proto: &str) -> String {
    path_row(proto)["over_budget_status"]
        .as_str()
        .expect("every `path_model` row names its over-budget status")
        .to_string()
}

const PATH_CASES: [Fixture; 4] = [
    Fixture::BufferedOk,
    Fixture::StreamedOk,
    Fixture::UnknownModel,
    Fixture::OverBudget,
];

fn path_body(proto: &str) -> Bytes {
    let v = &path_row(proto)["body"];
    Bytes::from(serde_json::to_vec(v).expect("the fixture body serializes"))
}

type PathFacts = plane::PathModelFacts;

fn path_facts(proto: &'static str, fixture: Fixture) -> PathFacts {
    let model = fixture.model().to_string();
    let stream = fixture.streamed();
    PathFacts {
        operation: busbar_contract::operation::OpVerb::CHAT,
        stream,

        gemini_json_array: path_row(proto)["json_array_when_streamed"]
            .as_bool()
            .expect("every `path_model` row says whether it frames a stream as a JSON array")
            && stream,

        model_not_found_message: miss_copy(proto, &model),
        model,
    }
}

async fn leg_legacy_path(fixture: Fixture, proto: &'static str) -> Observed {
    let rig = rig(fixture).await;
    let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let facts = path_facts(proto, fixture);
    let resp = plane::shell::ingress_path_model(
        &ctx,
        json_headers(),
        path_body(proto),
        facts.model,
        facts.operation,
        facts.stream,
        facts.gemini_json_array,
        proto,
        facts.model_not_found_message,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

async fn leg_loop_path(fixture: Fixture, proto: &'static str) -> Observed {
    let rig = rig(fixture).await;
    let node = Node::new();
    let facts = path_facts(proto, fixture);
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto,
        operation: facts.operation,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: path_body(proto),
        path: Some(facts),
    };
    let resp = node.answer(plane::handed(arrival, None)).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_matches_the_shipped_path_model_entry_point() {
    let mut failures: Vec<String> = Vec::new();
    for proto in path_dialects() {
        for fixture in PATH_CASES {
            let legacy = leg_legacy_path(fixture, proto).await;
            let looped = leg_loop_path(fixture, proto).await;
            for ((field, want), (_, got)) in legacy.0.iter().zip(looped.0.iter()) {
                if want != got {
                    failures.push(format!(
                        "{proto}/{fixture:?}: field `{field}` diverges\n  shipped: {want}\n  loop:    {got}"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} divergence(s) across the two url-model dialects:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_url_model_fixture_reaches_the_end_it_names() {
    let mut seen: Vec<(&str, Fixture, String)> = Vec::new();
    for proto in path_dialects() {
        for fixture in PATH_CASES {
            let observed = leg_loop_path(fixture, proto).await;
            let status = observed
                .0
                .iter()
                .find(|(k, _)| *k == "status")
                .map(|(_, v)| v.clone())
                .expect("every leg observes a status");
            seen.push((proto, fixture, status));
        }
    }
    let want: Vec<(&str, Fixture, String)> = path_dialects()
        .into_iter()
        .flat_map(|proto| {
            [
                (proto, Fixture::BufferedOk, "200".to_string()),
                (proto, Fixture::StreamedOk, "200".to_string()),
                (proto, Fixture::UnknownModel, "404".to_string()),
                (proto, Fixture::OverBudget, over_budget_status(proto)),
            ]
        })
        .collect();
    assert_eq!(
        seen, want,
        "the url-model fixtures do not reach the ends they are named for"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_url_model_ends_where_the_shipped_path_model_entry_point_ends_it() {
    fn nameless(proto: &'static str) -> PathFacts {
        let mut facts = path_facts(proto, Fixture::UnknownModel);
        facts.model = String::new();
        facts.model_not_found_message = miss_copy(proto, "");
        facts
    }

    let mut failures: Vec<String> = Vec::new();
    for proto in path_dialects() {
        let shipped = {
            let rig = rig(Fixture::UnknownModel).await;
            let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
                host: rig.host(),
                gov: rig.gov(),
                caller_token: None,
            });
            let facts = nameless(proto);
            let resp = plane::shell::ingress_path_model(
                &ctx,
                json_headers(),
                path_body(proto),
                facts.model,
                facts.operation,
                facts.stream,
                facts.gemini_json_array,
                proto,
                facts.model_not_found_message,
            )
            .await;
            let observed = observe(&rig, resp).await;
            rig.server.shutdown().await;
            observed
        };
        let looped = {
            let rig = rig(Fixture::UnknownModel).await;
            let node = Node::new();
            let arrival = plane::WalkArrival {
                host: rig.host(),
                gov: rig.gov(),
                proto,
                operation: busbar_contract::operation::OpVerb::CHAT,
                caller_token: None,
                headers: json_headers(),
                query: None,
                body: path_body(proto),
                path: Some(nameless(proto)),
            };
            let resp = node.answer(plane::handed(arrival, None)).await;
            let observed = observe(&rig, resp).await;
            rig.server.shutdown().await;
            observed
        };
        for ((field, want), (_, got)) in shipped.0.iter().zip(looped.0.iter()) {
            if want != got {
                failures.push(format!(
                    "{proto}: field `{field}` diverges on a URL that named no model\n  \
                     shipped: {want}\n  loop:    {got}"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} divergence(s) on the empty URL model:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn the_switched_path_table_names_every_dialect_the_plane_names() {
    let shipped: Vec<&str> = plane::shell::PATH_INGRESS.iter().map(|(n, _)| *n).collect();
    let switched: Vec<&str> = crate::LINKED
        .path_ingress
        .iter()
        .flat_map(|table| table.iter().map(|(n, _)| *n))
        .collect();
    assert_eq!(switched, shipped);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_url_facts_ride_the_unit_and_not_the_thread() {
    let rig = rig(Fixture::BufferedOk).await;

    let proto = path_dialects()
        .into_iter()
        .find(|d| miss_copy(d, "").is_some())
        .expect("a URL-model dialect keeps its own miss copy");
    let facts = path_facts(proto, Fixture::BufferedOk);
    let base = |path| plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: path_body(proto),
        path,
    };
    let carried = plane::url_facts(base(Some(facts)));
    assert_eq!(
        carried.as_ref().map(|(model, _)| model.as_str()),
        Some(POOL),
        "a path-model unit reads what its own URL said"
    );
    assert!(
        carried.and_then(|(_, miss_copy)| miss_copy).is_some(),
        "and the dialect's own miss copy is one of the facts it carries"
    );
    assert!(
        plane::url_facts(base(None)).is_none(),
        "a body-model unit carries no URL fact at all"
    );
    rig.server.shutdown().await;
}

#[test]
fn the_switched_table_names_every_dialect_the_plane_names() {
    let shipped: Vec<&str> = plane::shell::BODY_INGRESS.iter().map(|(n, _)| *n).collect();
    let switched: Vec<&str> = body_dialects();
    assert_eq!(switched, shipped);
}

#[test]
fn the_nodes_interner_leaks_a_lane_name_once() {
    let node = Node::new();
    let lanes = node.lanes();
    let first = lanes
        .lock()
        .expect("the node's interner is never poisoned")
        .lane(LANE);
    let again = lanes
        .lock()
        .expect("the node's interner is never poisoned")
        .lane(LANE);
    assert_eq!(first, again);
    let first = first.expect("an unfrozen image interns a configured lane");
    let again = again.expect("a repeated lane is the same lane");
    assert!(std::ptr::eq(first.as_str(), again.as_str()));
}

#[test]
fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
    let node = Node::new();
    let mut names = node
        .lane_names
        .lock()
        .expect("the node's lane table is never poisoned");

    let first = names
        .resolve(LANE)
        .expect("an unfrozen image interns a lane");
    for _ in 0..64 {
        let again = names
            .resolve(LANE)
            .expect("a repeated lane is the same lane");
        assert!(std::ptr::eq(first.as_str(), again.as_str()));
    }
    assert_eq!(names.consulted(), 1);

    let _ = names.resolve("a-second-configured-lane");
    assert_eq!(
        names.consulted(),
        2,
        "a name the node has not resolved still reaches the interner, exactly once"
    );
}

fn body_dialects() -> Vec<&'static str> {
    crate::LINKED
        .body_ingress
        .iter()
        .flat_map(|table| table.iter().map(|(name, _)| *name))
        .collect()
}

/// The four shapes step 1 is asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded {
    /// A well-formed native request naming a configured pool: both halves of the step answer.
    Named,
    /// A well-formed native request with no `model` member: the model ladder resolves nothing,
    /// which is the decode step's own refusal and belongs to no other step.
    NoModel,
    /// Bytes that are not a document at all. On this plane the parse is step 0's, so this is
    /// refused at ARRIVAL and never reaches the ladder — which is exactly the ordering the
    /// module header spells out, and it is asserted rather than assumed.
    Malformed,
    /// A verb the dialect declares no handler for: the handler half of the step, refused with
    /// the endpoint's own 404 sentence.
    UnsupportedVerb,
}

fn dialect_body(proto: &str, shape: Decoded) -> Bytes {
    if shape == Decoded::Malformed {
        return Bytes::from_static(b"{not json");
    }
    let mut v = DIALECTS["body_model"]
        .get(proto)
        .unwrap_or_else(|| panic!("the fixture has no `body_model` body for `{proto}`"))
        .clone();

    if shape != Decoded::NoModel {
        v["model"] = serde_json::Value::String(POOL.to_string());
    }
    Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
}

fn unsupported_verb(proto: &str) -> Option<busbar_contract::operation::OpVerb> {
    [
        busbar_contract::operation::OpVerb::EMBEDDINGS,
        busbar_contract::operation::OpVerb::MODERATION,
        busbar_contract::operation::OpVerb::IMAGE,
        busbar_contract::operation::OpVerb::TRANSCRIPTION,
        busbar_contract::operation::OpVerb::SPEECH,
        busbar_contract::operation::OpVerb::RERANK,
    ]
    .into_iter()
    .find(|op| plane::declines(proto, *op))
}

async fn leg_legacy_decode(
    proto: &'static str,
    operation: busbar_contract::operation::OpVerb,
    body: Bytes,
) -> Observed {
    let rig = rig(Fixture::BufferedOk).await;
    let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let resp =
        plane::shell::operation_ingress(&ctx, json_headers(), body, proto, operation, None).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

async fn leg_loop_decode(
    proto: &'static str,
    operation: busbar_contract::operation::OpVerb,
    body: Bytes,
) -> Observed {
    let rig = rig(Fixture::BufferedOk).await;
    let node = Node::new();
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto,
        operation,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body,
        path: None,
    };
    let resp = node.answer(plane::handed(arrival, None)).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_decodes_every_dialect_the_way_the_shipped_plane_decodes_it() {
    let mut failures: Vec<String> = Vec::new();
    let mut verbs_exercised = 0usize;
    for proto in body_dialects() {
        for shape in [Decoded::Named, Decoded::NoModel, Decoded::Malformed] {
            let label = format!("{proto}/{shape:?}");
            let body = dialect_body(proto, shape);
            let op = busbar_contract::operation::OpVerb::CHAT;
            let legacy = leg_legacy_decode(proto, op, body.clone()).await;
            let looped = leg_loop_decode(proto, op, body).await;
            compare(&label, &legacy, &looped, &mut failures);

            let status = field(&looped, "status");
            let answered = field(&looped, "body");
            let admitted = field(&looped, "ledger_requests");
            match shape {
                Decoded::Named => {
                    if admitted != "1" {
                        failures.push(format!(
                            "{label}: the resolved model never reached the door \
                             (ledger_requests={admitted})"
                        ));
                    }
                }
                Decoded::NoModel => {
                    if status != "400" || !answered.contains(plane::missing_model_sentence()) {
                        failures.push(format!(
                            "{label}: the ladder's own refusal is not what the client read \
                             (status={status}) {answered}"
                        ));
                    }
                    if admitted != "0" {
                        failures.push(format!("{label}: a refused unit was charged"));
                    }
                }

                Decoded::Malformed => {
                    if status != "400" || admitted != "0" {
                        failures.push(format!(
                            "{label}: the parse refusal is not the shipped one \
                             (status={status} ledger_requests={admitted})"
                        ));
                    }
                }
                Decoded::UnsupportedVerb => unreachable!("driven below, with its own verb"),
            }
        }

        if let Some(op) = unsupported_verb(proto) {
            verbs_exercised += 1;
            let label = format!("{proto}/UnsupportedVerb");
            let body = dialect_body(proto, Decoded::Named);
            let legacy = leg_legacy_decode(proto, op, body.clone()).await;
            let looped = leg_loop_decode(proto, op, body).await;
            compare(&label, &legacy, &looped, &mut failures);
            let status = field(&looped, "status");
            let answered = field(&looped, "body");
            if status != "404" || !answered.contains(plane::unsupported_operation_sentence()) {
                failures.push(format!(
                    "{label}: the endpoint's own 404 is not what the client read \
                     (status={status}) {answered}"
                ));
            }
        }
    }
    assert_eq!(
        verbs_exercised,
        body_dialects().len(),
        "every dialect in the family must decline at least one verb, driving the handler half \
         of step 1 for each of them - a floor of merely > 0 would still pass if all but one \
         dialect stopped declining any verb"
    );
    assert!(
        failures.is_empty(),
        "{} divergence(s) across {} dialect(s):\n{}",
        failures.len(),
        body_dialects().len(),
        failures.join("\n")
    );
}

/// The three credentials a client can present to a governed deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credential {
    /// The deployment's own live bearer.
    Good,
    /// A bearer this deployment did not mint. It is not the right shape and it is not signed by
    /// the rig's signer, which is the ordinary "wrong key" a door sees.
    Bad,
    /// A bearer this deployment DID mint, for a live and enabled binding, whose `exp` has
    /// passed. The only thing wrong with it is the clock.
    Expired,
}

impl Credential {
    fn present(self, rig: &Rig) -> String {
        match self {
            Credential::Good => rig.token.clone(),
            Credential::Bad => "vk_not_this_deployments_key".to_string(),
            Credential::Expired => rig.expired_token.clone(),
        }
    }
}

async fn admit(
    rig: &Rig,
    cred: Credential,
) -> Result<busbar_contract::records::PlaneRequestCtx, String> {
    busbar_kernel::auth::admit::admit_session(
        Arc::clone(&rig.app),
        Some(cred.present(rig)),
        String::new(),
    )
    .await
    .map(|(_, gov)| gov)
    .map_err(|refusal| format!("{refusal:?}"))
}

async fn principal_the_loop_settled_on(
    rig: &Rig,
    gov: busbar_contract::records::PlaneRequestCtx,
) -> String {
    let node = Node::new();
    let ended = drive_to_end(rig, &node, Fixture::BufferedOk, gov, plane::native_seats()).await;
    let Ended::Settled { end, .. } = ended else {
        panic!("the exit path settles a delivered unit");
    };
    end.into_posted()
        .expect("the usage report fits the record")
        .principal()
        .as_str()
        .to_string()
}

async fn leg_legacy_as(rig: &Rig, gov: busbar_contract::records::PlaneRequestCtx) -> Observed {
    let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov,
        caller_token: None,
    });
    let resp = plane::shell::operation_ingress(
        &ctx,
        json_headers(),
        Fixture::BufferedOk.body(),
        PROTO,
        busbar_contract::operation::OpVerb::CHAT,
        None,
    )
    .await;
    observe(rig, resp).await
}

async fn leg_loop_as(rig: &Rig, gov: busbar_contract::records::PlaneRequestCtx) -> Observed {
    let node = Node::new();
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov,
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: Fixture::BufferedOk.body(),
        path: None,
    };
    let resp = node.answer(plane::handed(arrival, None)).await;
    observe(rig, resp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_attributes_the_identity_the_door_resolved_and_invents_none() {
    let mut failures: Vec<String> = Vec::new();
    for cred in [Credential::Good, Credential::Bad, Credential::Expired] {
        let legacy_rig = rig(Fixture::BufferedOk).await;
        let legacy_admit = admit(&legacy_rig, cred).await;

        let loop_rig = rig(Fixture::BufferedOk).await;
        let loop_admit = admit(&loop_rig, cred).await;

        if legacy_admit.is_ok() != loop_admit.is_ok() {
            failures.push(format!(
                "{cred:?}: the two deployments' doors disagree ({legacy_admit:?} vs \
                 {loop_admit:?})"
            ));
        }

        match (legacy_admit, loop_admit) {
            (Ok(legacy_gov), Ok(loop_gov)) => {
                if cred != Credential::Good {
                    failures.push(format!(
                        "{cred:?}: the door admitted a credential it must refuse"
                    ));
                }

                if loop_gov.key().map(|k| k.id.clone()).as_deref() != Some(loop_rig.key.id.as_str())
                {
                    failures.push(format!(
                        "{cred:?}: the door resolved a key that is not this deployment's"
                    ));
                }

                let settle_rig = rig(Fixture::BufferedOk).await;
                match admit(&settle_rig, cred).await {
                    Ok(settle_gov) => {
                        let settled = principal_the_loop_settled_on(&settle_rig, settle_gov).await;
                        if settled != settle_rig.key.id {
                            failures.push(format!(
                                "{cred:?}: the loop settled on principal {settled:?}, not the \
                                 key the door resolved"
                            ));
                        }
                    }
                    Err(why) => failures.push(format!(
                        "{cred:?}: a third deployment's door refused the same bearer ({why})"
                    )),
                }
                settle_rig.server.shutdown().await;

                let legacy = leg_legacy_as(&legacy_rig, legacy_gov).await;
                let looped = leg_loop_as(&loop_rig, loop_gov).await;
                compare(&format!("{cred:?}"), &legacy, &looped, &mut failures);
                if field(&looped, "ledger_requests") != "1" {
                    failures.push(format!(
                        "{cred:?}: the admitted unit was not charged to the key"
                    ));
                }
            }
            (Err(_), Err(_)) => {
                if cred == Credential::Good {
                    failures.push(format!(
                        "{cred:?}: the door refused the deployment's own bearer"
                    ));
                }

                let open = busbar_contract::records::PlaneRequestCtx { key: None };
                let anonymous = busbar_contract::auth::AuthPrincipal(None)
                    .actor_id()
                    .to_string();

                let (unbound, ..) = plane::handed(
                    plane::WalkArrival {
                        host: loop_rig.host(),
                        gov: open.clone(),
                        proto: PROTO,
                        operation: busbar_contract::operation::OpVerb::CHAT,
                        caller_token: None,
                        headers: json_headers(),
                        query: None,
                        body: Fixture::BufferedOk.body(),
                        path: None,
                    },
                    None,
                );
                if unbound.as_str() != anonymous {
                    failures.push(format!(
                        "{cred:?}: an unbound request is not attributed to the anonymous actor"
                    ));
                }

                let settle_rig = rig(Fixture::BufferedOk).await;
                let settled = principal_the_loop_settled_on(&settle_rig, open.clone()).await;
                if settled != anonymous || settled == settle_rig.key.id {
                    failures.push(format!(
                        "{cred:?}: the loop settled on principal {settled:?} for a request the \
                         door bound no key to"
                    ));
                }
                settle_rig.server.shutdown().await;

                let legacy = leg_legacy_as(&legacy_rig, open.clone()).await;
                let looped = leg_loop_as(&loop_rig, open).await;
                compare(
                    &format!("{cred:?}/unbound"),
                    &legacy,
                    &looped,
                    &mut failures,
                );
            }
            (legacy_admit, loop_admit) => failures.push(format!(
                "{cred:?}: the doors disagreed ({legacy_admit:?} / {loop_admit:?})"
            )),
        }
        legacy_rig.server.shutdown().await;
        loop_rig.server.shutdown().await;
    }
    assert!(
        failures.is_empty(),
        "{} divergence(s) across the three credentials:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

struct StopsEverything(std::sync::atomic::AtomicBool);
impl plane::VetoSeat for StopsEverything {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        self.0.store(true, Ordering::SeqCst);
        true
    }
}

struct StopsNothing(std::sync::atomic::AtomicBool);
impl plane::VetoSeat for StopsNothing {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        self.0.store(true, Ordering::SeqCst);
        false
    }
}

async fn leg_loop_seated(
    rig: &Rig,
    seats: &'static [&'static (dyn plane::VetoSeat + Sync)],
) -> Observed {
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
        .answer(plane::handed_seated(arrival, None, seats))
        .await;
    observe(rig, resp).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seated_gate_stops_the_unit_before_the_door_and_an_empty_seat_list_changes_nothing() {
    use std::sync::atomic::AtomicBool;

    assert!(
        plane::native_seats().is_empty(),
        "the mount seats a native gate: the migrated hooks fire AFTER the door on the live \
         path, and a veto moved in front of a charge changes what is billed"
    );

    let shipped_rig = rig(Fixture::BufferedOk).await;
    let shipped = leg_legacy_as(&shipped_rig, shipped_rig.gov()).await;
    shipped_rig.server.shutdown().await;

    let mut failures: Vec<String> = Vec::new();

    let bare_rig = rig(Fixture::BufferedOk).await;
    let bare = leg_loop_seated(&bare_rig, plane::native_seats()).await;
    compare("no seat", &shipped, &bare, &mut failures);
    bare_rig.server.shutdown().await;

    let passing: &'static StopsNothing = Box::leak(Box::new(StopsNothing(AtomicBool::new(false))));
    let passing_rig = rig(Fixture::BufferedOk).await;
    let passed = leg_loop_seated(&passing_rig, Box::leak(Box::new([passing as _]))).await;
    compare(
        "a seat that does not veto",
        &shipped,
        &passed,
        &mut failures,
    );
    if !passing.0.load(Ordering::SeqCst) {
        failures.push(
            "the loop never consulted the seated gate, so the pass-through above is an \
             unwired field rather than a verdict"
                .to_string(),
        );
    }
    passing_rig.server.shutdown().await;

    let stopping: &'static StopsEverything =
        Box::leak(Box::new(StopsEverything(AtomicBool::new(false))));
    let veto_rig = rig(Fixture::BufferedOk).await;
    let stopped = leg_loop_seated(&veto_rig, Box::leak(Box::new([stopping as _]))).await;
    assert!(
        stopping.0.load(Ordering::SeqCst),
        "the vetoing gate was never asked"
    );
    if field(&stopped, "status") != "403" {
        failures.push(format!(
            "a vetoed unit answers {} rather than the plane's permission refusal: {}",
            field(&stopped, "status"),
            field(&stopped, "body")
        ));
    }

    if field(&stopped, "ledger_requests") != "0" || !field(&stopped, "metering_rows").is_empty() {
        failures.push(format!(
            "a veto was charged: requests={} rows={}",
            field(&stopped, "ledger_requests"),
            field(&stopped, "metering_rows")
        ));
    }

    if veto_rig.upstream.get_last_request_path().is_some() {
        failures.push("a vetoed unit reached the upstream".to_string());
    }
    veto_rig.server.shutdown().await;

    assert!(
        failures.is_empty(),
        "{} finding(s) at the approve seat:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

async fn drive_counting(rig: &Rig, fixture: Fixture) -> (Response, Option<u64>) {
    let node = Node::new();
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: fixture.body(),
        path: None,
    };
    let response = node.answer(plane::handed(arrival, None)).await;
    (response, node.driven())
}

/// **THE COUNT IS THE INSTRUMENT, AND A STATUS CANNOT BE.**
///
/// The question this closes is the one the rig's own upstream handle was kept for and could only
/// half answer: *"the unit stopped before the route step" is not a fact any counter on this side
/// of the loop reports* (see [`Rig::upstream`]). The scripted upstream answers it only where a
/// deployment HAS one and only for a unit that would have dialled it; the seam answers it for
/// every unit, on this side, without a socket.
///
/// It cannot be answered by the answer. A unit refused at Verify and a unit an upstream itself
/// refused are both a 4xx in this dialect's envelope, and a reader comparing the two legs on
/// status, headers and body — which is what every other cell in this file does — reads them as
/// the same event. Only "did anything run" tells them apart, and only the seam can say it.
///
/// THREE ENDS, THREE COUNTS. The two refusals bracket the door: `PoolAcl` is the pre-admission
/// guard, refused at Verify with nothing charged; `OverBudget` is the door itself, refused at
/// Admit. Neither may reach the engine, and *neither may reach it for a different reason* — a
/// refusal that dialled an upstream and then discarded its answer has spent a caller's quota
/// upstream and billed nobody for it. `BufferedOk` is the whole loop, and it drives EXACTLY once:
/// a second drive of one unit is a request the client sent once and the upstream saw twice.
///
/// RED FIRST, and it was run red. With `route_leg` handing the walk's leg straight back to the
/// loop — the line this seam replaced — the served fixture reports:
///
/// ```text
/// BufferedOk (served: the whole loop, through the engine, exactly once):
///     the engine was driven 0 time(s), expected 1
/// ```
///
/// The two refusals read 0 on both sides of the change, which is the point of them: they are not
/// what the seam moved, they are what the seam must not have moved. So the red is one finding and
/// not three, and the two that stayed silent are the ones holding the money still.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_route_seam_is_driven_once_by_a_served_unit_and_never_by_a_refused_one() {
    let mut failures: Vec<String> = Vec::new();

    for (fixture, expected, why) in [
        (
            Fixture::PoolAcl,
            0u64,
            "refused at Verify, before the door: the pre-admission guard",
        ),
        (
            Fixture::OverBudget,
            0,
            "refused at Admit, at the door: the group's budget is spent",
        ),
        (
            Fixture::BufferedOk,
            1,
            "served: the whole loop, through the engine, exactly once",
        ),
    ] {
        let rig = rig(fixture).await;
        let (response, driven) = drive_counting(&rig, fixture).await;

        let observed = observe(&rig, response).await;

        match driven {
            None => failures.push(format!(
                "{fixture:?} ({why}): the node reports no dispatch count at all — \
                 the Route step is not reaching a seam that counts"
            )),
            Some(got) if got != expected => failures.push(format!(
                "{fixture:?} ({why}): the engine was driven {got} time(s), expected {expected}"
            )),
            Some(_) => {}
        }

        let dialled = rig.upstream.get_last_request_path().is_some();
        if expected == 0 && dialled {
            failures.push(format!(
                "{fixture:?} ({why}): the count says the engine did not run and the upstream \
                 says it was dialled"
            ));
        }
        if expected > 0 && !dialled {
            failures.push(format!(
                "{fixture:?} ({why}): the count says the engine ran and the upstream was never \
                 dialled"
            ));
        }

        if field(&observed, "status").is_empty() {
            failures.push(format!(
                "{fixture:?} ({why}): the unit produced no status at all"
            ));
        }

        rig.server.shutdown().await;
    }

    assert!(
        failures.is_empty(),
        "{} finding(s) at the route seam:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

const RESOLVED_OP_CASES: [Fixture; 5] = [
    Fixture::BufferedOk,
    Fixture::StreamedOk,
    Fixture::OverBudget,
    Fixture::PoolAcl,
    Fixture::UnknownModel,
];

async fn leg_native_run(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let resp = plane::shell::operation_ingress(
        &ctx,
        json_headers(),
        fixture.body(),
        PROTO,
        busbar_contract::operation::OpVerb::CHAT,
        None,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

#[allow(clippy::too_many_arguments)]
async fn native_run_via_loop(
    host: &Arc<dyn busbar_kernel::plane_driver::EngineHost>,
    gov: &busbar_contract::records::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_contract::operation::OpVerb,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    arrived: Arrived,
) -> Response {
    let arrival = plane::WalkArrival {
        host: Arc::clone(host),
        gov: busbar_contract::records::PlaneRequestCtx {
            key: gov.key.clone(),
        },
        proto,
        operation,
        caller_token: None,
        headers: headers.clone(),
        query: None,
        body,
        path: None,
    };

    super::NODE
        .answer_arriving_at(plane::handed(arrival, Some(model.to_string())), arrived)
        .await
}

async fn leg_native_run_via_loop(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let host = rig.host();
    let arrived = Arrived::at(rig.charged_at * 1_000, 0);
    assert_eq!(
        arrived.secs(),
        rig.charged_at,
        "the pinned arrival lands in the window observe reads"
    );
    let resp = native_run_via_loop(
        &host,
        &rig.gov(),
        PROTO,
        busbar_contract::operation::OpVerb::CHAT,
        fixture.model(),
        &json_headers(),
        fixture.body(),
        arrived,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_matches_native_ingress_run_at_the_resolved_op_entry() {
    let mut failures: Vec<String> = Vec::new();
    for fixture in RESOLVED_OP_CASES {
        let shipped = leg_native_run(fixture).await;
        let looped = leg_native_run_via_loop(fixture).await;
        compare(&format!("{fixture:?}"), &shipped, &looped, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "{} divergence(s) at the resolved-op funnel across {} fixtures:\n{}",
        failures.len(),
        RESOLVED_OP_CASES.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_resolved_op_loop_leaves_the_money_where_run_gauntlet_leaves_it() {
    let shipped = leg_native_run(Fixture::BufferedOk).await;
    let looped = leg_native_run_via_loop(Fixture::BufferedOk).await;
    for f in [
        "ledger_requests",
        "ledger_tokens",
        "ledger_spend_cents",
        "metering_rows",
    ] {
        assert_eq!(
            field(&shipped, f),
            field(&looped, f),
            "delivered: `{f}` differs between run_gauntlet and the loop"
        );
    }
    assert_eq!(
        field(&looped, "ledger_requests"),
        "1",
        "one request, counted once"
    );
    assert_eq!(
        field(&looped, "ledger_tokens"),
        (INPUT + OUTPUT).to_string(),
        "the reported split, accrued once — not doubled against the late-accrual arm"
    );

    let s_shipped = leg_native_run(Fixture::StreamedOk).await;
    let s_looped = leg_native_run_via_loop(Fixture::StreamedOk).await;
    for f in ["ledger_requests", "ledger_tokens", "metering_rows"] {
        assert_eq!(
            field(&s_shipped, f),
            field(&s_looped, f),
            "streamed: `{f}` differs between run_gauntlet and the loop"
        );
    }
    assert_eq!(
        field(&s_looped, "ledger_tokens"),
        (INPUT + OUTPUT).to_string()
    );

    let refused = leg_native_run_via_loop(Fixture::OverBudget).await;
    assert_eq!(field(&refused, "ledger_requests"), "0");
    assert_eq!(field(&refused, "metering_rows"), "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_legs_report_the_same_ledger_spend() {
    let shipped = leg_native_run(Fixture::BufferedOk).await;
    let looped = leg_native_run_via_loop(Fixture::BufferedOk).await;
    assert_eq!(
        field(&shipped, "ledger_spend_cents"),
        field(&looped, "ledger_spend_cents"),
        "the two legs reported different ledger spend for the same delivered unit"
    );
}

#[test]
fn the_node_provenance_stamp_names_the_card_in_force_when_the_unit_arrived() {
    const SECOND_CARD_MS: u64 = 1_700_000_500_000;
    const THIRD_CARD_MS: u64 = 1_700_000_900_000;

    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(11),
        SECOND_CARD_MS,
    );
    holder.apply(
        busbar_kernel_ledger::cost::RateCard::absent(29),
        THIRD_CARD_MS,
    );
    let pinned = holder.pin().expect("three applies put entries in place");
    assert_eq!(
        pinned.view().entries().last().unwrap().seq().get(),
        2,
        "the snapshot's head is the third entry — the figure a stamp must NOT be for a unit that \
         arrived before it, and the one a `read the head` implementation would answer every time"
    );

    let keys: Vec<_> = pinned
        .view()
        .entries()
        .iter()
        .map(|entry| entry.key().0)
        .collect();
    let stamped_ms = |ms: u64| card_in_force(Some(&pinned), ms);

    assert_eq!(
        stamped_ms(1_700_000_100_000),
        Some(keys[0]),
        "a unit that arrived before the second card was published is priced by the opening entry"
    );
    assert_eq!(
        stamped_ms(1_700_000_600_000),
        Some(keys[1]),
        "a unit that arrived in the second card's window names the SECOND entry — not the third, \
         which had not been published when it arrived (#79: publishing never reprices backwards)"
    );
    assert_eq!(
        stamped_ms(1_700_001_000_000),
        Some(keys[2]),
        "a unit that arrived after the third card names the third entry"
    );

    assert_eq!(
        card_in_force(None, 1_700_000_600_000),
        None,
        "no pinned history has no card entry identity"
    );

    assert_eq!(
        stamped_ms(1_700_000_600),
        Some(keys[0]),
        "a seconds-valued instant matches only the from-zero opening entry — which is why the \
         settle path resolves at `Arrived::ms()` and never at `Arrived::secs()`"
    );
}

fn fee_history_of(
    entries: &[(u64, f64, f64, i64)],
    present: bool,
) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    for (n, (from, input, output, fee)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_contract::billing::RawTierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(*input),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(*output),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            )],
            *fee,
            present,
        );
        history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_kernel_ledger::cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_kernel_ledger::cost::HistorySeq((entries.len() - 1) as u64),
    )
}

fn split_report(input: u64, output: u64, fee_count: u32) -> Report {
    let mut units = std::collections::BTreeMap::new();
    if input != 0 {
        units.insert(busbar_contract::records::UNIT_INPUT.to_string(), input);
    }
    if output != 0 {
        units.insert(busbar_contract::records::UNIT_OUTPUT.to_string(), output);
    }
    Report {
        usage: busbar_contract::billing::Usage { usage_units: units },
        fee_count,
        lane: "lane".to_string(),
    }
}

fn invoice_micros(
    history: &crate::root::kernel::PinnedHistory,
    arrived_ms: u64,
    report: &Report,
) -> i64 {
    use busbar_core_admin::v1::service::read_path_money as invoice;
    let view = history.view();
    let era = view
        .entry_at(arrived_ms)
        .map_or(0, busbar_kernel_ledger::cost::CardEntry::effective_from);
    let bucket_start_secs = arrived_ms / 1_000 / 86_400 * 86_400;
    let at = invoice::row_priced_at_ms(bucket_start_secs, era);
    let (_, card) = view.card_at(at).expect("a card covers every instant");
    let unit = |k: &str| report.usage.usage_units.get(k).copied().unwrap_or(0);
    let row = invoice::UsageBreakdown {
        tokens_input: unit(busbar_contract::records::UNIT_INPUT),
        tokens_output: unit(busbar_contract::records::UNIT_OUTPUT),
        tokens_cache_read: unit(busbar_contract::records::UNIT_CACHE_READ),
        tokens_cache_creation: unit(busbar_contract::records::UNIT_CACHE_WRITE),
        requests: u64::from(report.fee_count),
        spend_micros: 0,
        classes: Default::default(),
    };
    let cost =
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    invoice::derive_spend_micros_row_at_card(&view, at, card, &cost, &report.lane, &row)
        .expect("the invoice's card prices every lane the fixture serves")
}

fn second_book_micros(
    second_book: Result<u64, busbar_kernel_ledger::cost::Unpriceable>,
) -> Result<i64, String> {
    let nanos = second_book.map_err(|refusal| format!("the second book refused: {refusal:?}"))?;
    busbar_kernel_ledger::cost::Money::of_nanos(u128::from(nanos))
        .and_then(busbar_kernel_ledger::cost::Money::micros_i64)
        .map_err(|refusal| format!("{nanos} nano-units do not project: {refusal:?}"))
}

fn books_agree(
    label: &str,
    second_book: Result<u64, busbar_kernel_ledger::cost::Unpriceable>,
    invoice: i64,
) -> Result<(), String> {
    let projected = second_book_micros(second_book.clone());
    if projected == Ok(invoice) {
        Ok(())
    } else {
        Err(format!(
            "{label}: the kernel-loop book posted {second_book:?} nano-units ({projected:?} micro) \
             but the invoice (/admin/usage over the governance ledger) serves {invoice} micro"
        ))
    }
}

#[test]
fn the_second_book_agrees_with_the_invoice_cell_by_cell_and_a_divergence_is_red() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let billed = fee_history_of(
        &[
            (0, 0.5, 1.0, 0),
            (5_000, 5.0, 10.0, 0),
            (9_000, 50.0, 100.0, 3),
        ],
        true,
    );
    let billing_off = fee_history_of(&[(0, 0.0, 0.0, 1)], false);

    let cells: [(&str, &crate::root::kernel::PinnedHistory, u64, Report); 7] = [
        (
            "boot card, before A",
            &billed,
            1_000,
            split_report(11, 7, 1),
        ),
        (
            "card A, between A and B",
            &billed,
            6_000,
            split_report(11, 7, 1),
        ),
        (
            "card B + fee, after B",
            &billed,
            10_000,
            split_report(11, 7, 1),
        ),
        (
            "fee only (billing failed)",
            &billed,
            10_000,
            split_report(0, 0, 1),
        ),
        (
            "provider origin (no fee)",
            &billed,
            10_000,
            split_report(11, 7, 0),
        ),
        (
            "billing off, tokens + fee",
            &billing_off,
            10_000,
            split_report(11, 7, 1),
        ),
        (
            "billing off, fee only",
            &billing_off,
            10_000,
            split_report(0, 0, 1),
        ),
    ];

    let mut failures = Vec::new();
    for (label, history, at, report) in &cells {
        let second = priced_amount(history, Arrived::at(*at, 1), &token, report);
        let invoice = invoice_micros(history, *at, report);
        if let Err(e) = books_agree(label, second, invoice) {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "the second book disagrees with the invoice on {} cell(s):\n{}",
        failures.len(),
        failures.join("\n")
    );

    assert_eq!(
        Ok(invoice_micros(&billed, 10_000, &split_report(11, 7, 1))),
        // 11 x 50 + 7 x 100 + the 3-unit fee at the one scale.
        second_book_micros(priced_amount(
            &billed,
            Arrived::at(10_000, 1),
            &token,
            &split_report(11, 7, 1)
        )),
    );
    assert_ne!(invoice_micros(&billed, 10_000, &split_report(11, 7, 1)), 0);

    let early = split_report(11, 7, 1);
    let at_head = priced_amount(&billed, Arrived::at(10_000, 1), &token, &early);
    assert!(
        books_agree(
            "planted: priced at head",
            at_head,
            invoice_micros(&billed, 1_000, &early)
        )
        .is_err(),
        "a second book priced at the head card was NOT caught disagreeing with the invoice"
    );

    let fee_dropped = priced_amount(
        &billed,
        Arrived::at(10_000, 1),
        &token,
        &split_report(11, 7, 0),
    );
    assert!(
        books_agree(
            "planted: fee dropped",
            fee_dropped,
            invoice_micros(&billed, 10_000, &split_report(11, 7, 1))
        )
        .is_err(),
        "a second book that dropped the fee was NOT caught disagreeing with the invoice"
    );
}

fn cache_silent_history() -> crate::root::kernel::PinnedHistory {
    use busbar_kernel_ledger::cost::{History, HistorySeq, LaneClass, RateCard};
    let card = RateCard::from_micro_rates(
        [
            (
                LaneClass::new("lane", busbar_contract::records::UNIT_INPUT),
                3.0,
            ),
            (
                LaneClass::new("lane", busbar_contract::records::UNIT_OUTPUT),
                16.0,
            ),
        ],
        0,
    );
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(History::opening(card, 0)),
        HistorySeq(0),
    )
}

#[test]
fn an_unpriced_class_on_a_present_card_keeps_its_counts_row_and_the_read_refuses() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000,
    );
    let at = Arrived::at(4_000, 7);

    let (posting, priced) = priced_posting(&history, at, &token, &report);
    let counts: std::collections::BTreeMap<&str, u64> = posting
        .quantities
        .iter()
        .map(|q| (q.class.as_str(), q.amount))
        .collect();
    assert_eq!(
        counts,
        std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT, 1_000),
            (busbar_contract::records::UNIT_OUTPUT, 250),
            (busbar_contract::records::UNIT_CACHE_READ, 10_000_000),
        ]),
        "the posting lost or zeroed a count the unit reported"
    );
    assert_eq!(posting.fee_count, 1, "the billable count rides the row");

    assert!(
        matches!(
            priced,
            Err(busbar_kernel_ledger::cost::Unpriceable::ClassUnpriced { ref class, .. })
                if class == busbar_contract::records::UNIT_CACHE_READ
        ),
        "settlement priced a class the present card is silent about: {priced:?}"
    );
    assert!(
        matches!(
            priced_amount(&history, at, &token, &report),
            Err(busbar_kernel_ledger::cost::Unpriceable::ClassUnpriced { .. })
        ),
        "the second book was handed a figure — a partial is a silent zero for the unpriced class"
    );

    use busbar_core_admin::v1::service::read_path_money as invoice;
    let view = history.view();
    let (_, card) = view.card_at(at.ms()).expect("the card is in force");
    let row = invoice::UsageBreakdown {
        tokens_input: 1_000,
        tokens_output: 250,
        tokens_cache_read: 10_000_000,
        tokens_cache_creation: 0,
        requests: 1,
        spend_micros: 0,
        classes: Default::default(),
    };
    let cost =
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new());
    assert!(
        invoice::derive_spend_micros_row_at_card(&view, at.ms(), card, &cost, "lane", &row)
            .is_err(),
        "the read priced a class the present card is silent about"
    );
}

#[test]
fn a_settled_figure_past_the_record_refuses_and_is_never_pinned() {
    let kernel = Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1_000.0)]);
    let (_, priced) = priced_posting(
        &history,
        Arrived::at(4_000, 7),
        &token,
        &report_of(100_000_000_000_000_000),
    );
    assert!(
        priced.is_ok_and(|p| p.priced_nanos > u128::from(u64::MAX)),
        "the fixture must price past the record, or this pins nothing"
    );
    assert_eq!(
        priced_amount(
            &history,
            Arrived::at(4_000, 7),
            &token,
            &report_of(100_000_000_000_000_000)
        ),
        Err(busbar_kernel_ledger::cost::Unpriceable::Overflow),
    );
}

#[test]
fn a_unit_whose_task_went_away_is_marked_and_the_sweep_posts_its_hold() {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));

    let who = PrincipalId::new("acct:swept");
    let key = UnitKey::new(41);
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                who,
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");

    drop(Occupied {
        node: &node,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 7),
        op_class: busbar_contract::caps::OpClassId::new("call"),
        hold: None,
        reached_end: false,
    });
    assert!(
        slot.is_marked(),
        "the guard MARKS the slot it could not end"
    );
    assert!(
        node.inflight.get(key).is_some(),
        "and leaves it in the table, where the sweep can see it"
    );
    assert_ne!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the hold is still in the cell: nobody has settled it"
    );

    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);
    assert_eq!(
        slot.cell().state(),
        busbar_contract::caps::HoldCellState::Taken,
        "the sweep took the hold out of the cell"
    );
    assert!(node.inflight.get(key).is_none(), "and gave the slot back");
    {
        let durability = book.lock().unwrap_or_else(|p| p.into_inner());
        let replayed = durability
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies");
        assert_eq!(
            replayed
                .iter()
                .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
                .count(),
            2,
            "the swept hold's posting is on the journal, and its one audit record beside it"
        );
        assert_eq!(durability.ledger.book().len(), 1, "and on the book");
    }

    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 6, 100)), 0);

    let key = UnitKey::new(42);
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                PrincipalId::new("acct:finished"),
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node: &node,
        slot: Arc::clone(&slot),
        arrived: Arrived::at(EPOCH * 1_000, 8),
        op_class: busbar_contract::caps::OpClassId::new("call"),
        hold: None,
        reached_end: true,
    });
    assert!(!slot.is_marked());
    assert!(node.inflight.get(key).is_none());
}

fn swept_node() -> (
    Node,
    Arc<std::sync::Mutex<crate::root::durability::Durability>>,
) {
    let node = Node::new();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ));
    node.bind_book(Arc::clone(&book));
    (node, book)
}

fn lose_a_unit(node: &Node, key: UnitKey, op_class: &'static str, hold: Option<u64>) {
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: busbar_kernel::inflight::arrival_hold(
                &node.kernel,
                &node.door,
                PrincipalId::new("acct:swept"),
                node.kernel.next_call(),
            ),
            now: EPOCH * 1_000,
        })
        .expect("the uncapped table takes the unit");
    drop(Occupied {
        node,
        slot,
        arrived: Arrived::at(EPOCH * 1_000, key.get()),
        op_class: busbar_contract::caps::OpClassId::new(op_class),
        hold,
        reached_end: false,
    });
}

#[test]
fn a_swept_unit_seals_exactly_one_audit_record_whose_amount_is_its_ledger_line() {
    let (node, book) = swept_node();
    let key = UnitKey::new(51);
    lose_a_unit(&node, key, "widget_call", Some(3));
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), 1);

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        durability.ledger.book().len(),
        1,
        "the swept unit posted one line"
    );
    let records: Vec<_> = durability
        .audit_records
        .iter()
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one record for the one swept unit: {:?}",
        durability.audit_records
    );
    let record = records[0];
    assert_eq!(
        record.outcome.unit_end,
        Outcome::Failed(
            busbar_contract::caps::StepName::Route,
            busbar_contract::caps::ReasonCode::TaskLost
        )
    );
    assert_eq!(record.outcome.finish, RecordFinish::Error);
    assert_eq!(record.what.op_class.as_str(), "widget_call");
    assert_eq!(record.controls.hold_ref.as_deref(), Some("3"));

    assert!(
        record.usage.lines.is_empty(),
        "a record names no money-class line: {:?}",
        record.usage.lines
    );
    let settled: i128 = durability
        .ledger
        .book()
        .iter()
        .map(|(_, totals)| totals.settled)
        .sum();
    assert_eq!(
        settled,
        record
            .usage
            .lines
            .iter()
            .map(|l| i128::from(l.quantity))
            .sum::<i128>(),
        "the record's amount equals the money its line moved"
    );
    assert!(durability.retained_audit_findings().is_empty());

    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    let read_back: Vec<_> = replayed
        .iter()
        .filter_map(|r| crate::root::durability::decode_audit(r).expect("every record decodes"))
        .filter(|r| r.what.unit_key == key)
        .collect();
    assert_eq!(
        read_back.len(),
        1,
        "the swept unit's record is on the journal"
    );
}

#[test]
fn no_swept_unit_settles_with_zero_audit_records() {
    let (node, book) = swept_node();
    let keys = [UnitKey::new(61), UnitKey::new(62), UnitKey::new(63)];
    for key in keys {
        lose_a_unit(&node, key, "widget_call", None);
    }
    assert_eq!(node.sweep(Arrived::at(EPOCH * 1_000 + 5, 99)), keys.len());

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(
        replayed
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Transaction)
            .count(),
        2 * keys.len(),
        "each swept unit has its posting on the journal and its one record beside it"
    );
    for key in keys {
        assert_eq!(
            durability
                .audit_records
                .iter()
                .filter(|r| r.what.unit_key == key)
                .count(),
            1,
            "unit {key:?} settled and must have exactly one record: {:?}",
            durability.audit_records
        );
    }
    assert_eq!(durability.audit_records.len(), keys.len());
}

const SEARCH_UNITS: &str = "search_units";

fn declare_test_classes() {
    let mut registration = crate::root::kernel::new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }
    let _ = registration.key(SEARCH_UNITS);
}

fn late_post(
    history: &crate::root::kernel::PinnedHistory,
    at: Arrived,
    principal: &str,
    report: &Report,
) -> crate::root::durability::NodeBook {
    declare_test_classes();

    let pinned = history.clone();
    let node = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let kernel = Kernel::new();
    let (durability, ledger, usage) = (
        kernel.durability_token(),
        kernel.ledger_token(),
        kernel.usage_token(),
    );
    post_late(
        &crate::root::durability::SharedBook::over(Arc::clone(&node.durability)),
        &LateTokens {
            durability: &durability,
            ledger: &ledger,
            usage: &usage,
        },
        history,
        &PrincipalId::new(principal),
        at,
        report,
        None,
    );
    node
}

fn second_book_rows(
    node: &crate::root::durability::NodeBook,
) -> Vec<crate::root::durability::Posting> {
    let durability = node.durability.lock().expect("unpoisoned");
    durability
        .read_back()
        .into_iter()
        .filter(|p| p.kind != crate::root::durability::PostingKind::Carry)
        .collect()
}

fn governance_row(report: &Report) -> crate::root::durability::UnitCounts {
    crate::root::durability::UnitCounts {
        lane: report.lane.clone(),
        fee_count: u64::from(report.fee_count),
        classes: report
            .usage
            .usage_units
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(class, count)| (class.clone(), *count))
            .collect(),
    }
}

fn every_cell_agrees(
    label: &str,
    second: &[crate::root::durability::Posting],
    governance: &crate::root::durability::UnitCounts,
    history: &crate::root::kernel::PinnedHistory,
    arrived_ms: u64,
) -> Result<(), String> {
    use crate::root::durability::PostingKind;
    let [row] = second else {
        return Err(format!(
            "{label}: the second book holds {} records for one unit, not one",
            second.len()
        ));
    };
    let Some(counts) = row.counts.as_ref() else {
        return Err(format!(
            "{label}: the second book's record carries no counts"
        ));
    };
    let mut cells = Vec::new();
    let classes: std::collections::BTreeSet<&String> = counts
        .classes
        .keys()
        .chain(governance.classes.keys())
        .collect();
    for class in classes {
        let (second_book, invoice) = (counts.classes.get(class), governance.classes.get(class));
        if second_book != invoice {
            cells.push(format!(
                "class {class}: second book {second_book:?}, governance ledger {invoice:?}"
            ));
        }
    }
    if counts.lane != governance.lane {
        cells.push(format!("lane: {:?} vs {:?}", counts.lane, governance.lane));
    }
    if counts.fee_count != governance.fee_count {
        cells.push(format!(
            "fee count: {} vs {}",
            counts.fee_count, governance.fee_count
        ));
    }
    let invoice =
        busbar_kernel_ledger::cost::price_exact(&[governance.entry(arrived_ms)], &history.view())
            .and_then(busbar_kernel_ledger::cost::nanos_of_exact);
    let money_agrees = match (&invoice, row.kind, row.refusal.as_ref()) {
        (Ok(nanos), PostingKind::Settlement, None) => {
            u128::try_from(row.settled).is_ok_and(|settled| settled == *nanos) && *nanos != 0
        }
        (Ok(0), PostingKind::Counted, None) => true,
        (Err(_), PostingKind::Counted, Some(_)) => true,
        _ => false,
    };
    if !money_agrees {
        cells.push(format!(
            "money: second book {:?} settled {} (refusal {:?}), invoice {invoice:?} nano-units",
            row.kind, row.settled, row.refusal
        ));
    }
    if cells.is_empty() {
        Ok(())
    } else {
        Err(format!("{label}: {}", cells.join("; ")))
    }
}

fn rerank_history(fee: i64, search_units: Option<u64>) -> crate::root::kernel::PinnedHistory {
    rerank_history_on("lane", fee, search_units)
}

fn rerank_history_on(
    lane: &str,
    fee: i64,
    search_units: Option<u64>,
) -> crate::root::kernel::PinnedHistory {
    use busbar_kernel_ledger::cost::{History, HistorySeq, LaneClass, RateCard};
    let card = RateCard::from_micro_rates(
        [
            (
                LaneClass::new(lane, busbar_contract::records::UNIT_INPUT),
                3.0,
            ),
            (
                LaneClass::new(lane, busbar_contract::records::UNIT_OUTPUT),
                16.0,
            ),
        ],
        fee,
    )
    .with_unit_rates(search_units.map(|nanos| (LaneClass::new(lane, SEARCH_UNITS), nanos)));
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(History::opening(card, 0)),
        HistorySeq(0),
    )
}

fn rerank_report(units: u64) -> Report {
    Report {
        usage: busbar_contract::billing::Usage {
            usage_units: std::collections::BTreeMap::from([(SEARCH_UNITS.to_string(), units)]),
        },
        fee_count: 1,
        lane: "lane".to_string(),
    }
}

#[test]
fn an_unpriced_class_on_a_present_card_leaves_a_durable_counts_row_and_the_read_refuses() {
    use crate::root::durability::PostingKind;
    let history = cache_silent_history();
    let mut report = split_report(1_000, 250, 1);
    report.usage.usage_units.insert(
        busbar_contract::records::UNIT_CACHE_READ.to_string(),
        10_000_000,
    );
    let at = Arrived::at(4_000, 7);
    let node = late_post(&history, at, "vk_refused", &report);

    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one counts row per refused unit: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.kind, PostingKind::Counted);
    let counts = row.counts.as_ref().expect("the row carries the counts");
    assert_eq!(
        counts.classes,
        std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT.to_string(), 1_000),
            (busbar_contract::records::UNIT_OUTPUT.to_string(), 250),
            (
                busbar_contract::records::UNIT_CACHE_READ.to_string(),
                10_000_000
            ),
        ]),
        "every count, whole — not zeroed, not trimmed to the priced classes"
    );
    assert_eq!((counts.lane.as_str(), counts.fee_count), ("lane", 1));
    assert!(
        row.refusal
            .as_deref()
            .is_some_and(|why| why.contains("ClassUnpriced") && why.contains("cache_read")),
        "the money is refused and says which class: {:?}",
        row.refusal
    );
    assert_eq!(
        (row.reserved, row.settled, row.overdraft),
        (0, 0, 0),
        "no figure: no zero posted as a price, no partial"
    );

    let durability = node.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new("vk_refused"));
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, at.secs());
    assert_eq!(
        durability.ledger.book().get(&key, window).settled,
        0,
        "a refused unit moves no balance"
    );
    assert!(
        durability.settled_read(&key, window).is_err(),
        "the read over a refused counts row refuses (#42), never the priced remainder"
    );
    assert_eq!(durability.refused_rows().len(), 1);

    every_cell_agrees(
        "refused",
        &rows,
        &governance_row(&report),
        &history,
        at.ms(),
    )
    .expect("both books refuse the same unit");
}

#[test]
fn a_reranks_search_units_agree_across_both_books() {
    let at = Arrived::at(4_000, 7);

    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let node = late_post(&priced, at, "vk_rerank", &report);
    let rows = second_book_rows(&node);
    every_cell_agrees(
        "rerank, priced",
        &rows,
        &governance_row(&report),
        &priced,
        at.ms(),
    )
    .expect("the books agree on the rerank");

    let fee_only = late_post(&priced, at, "vk_fee", &rerank_report(0));
    let fee_only = second_book_rows(&fee_only);
    assert_eq!(
        rows[0].settled - fee_only[0].settled,
        50 * 2_000_000,
        "the second book priced the 50 search units"
    );

    let silent = rerank_history(3, None);
    let node = late_post(&silent, at, "vk_silent", &report);
    let rows = second_book_rows(&node);
    every_cell_agrees(
        "rerank, card silent about search units",
        &rows,
        &governance_row(&report),
        &silent,
        at.ms(),
    )
    .expect("both books refuse a rerank the card is silent about");
    assert!(
        rows[0]
            .refusal
            .as_deref()
            .is_some_and(|w| w.contains(SEARCH_UNITS)),
        "{:?}",
        rows[0].refusal
    );

    let billed = fee_history_of(
        &[
            (0, 0.5, 1.0, 0),
            (5_000, 5.0, 10.0, 0),
            (9_000, 50.0, 100.0, 3),
        ],
        true,
    );
    let mut failures = Vec::new();
    for (label, at_ms, report) in [
        ("boot card", 1_000, split_report(11, 7, 1)),
        ("card A", 6_000, split_report(11, 7, 1)),
        ("card B + fee", 10_000, split_report(11, 7, 1)),
        ("fee only", 10_000, split_report(0, 0, 1)),
        ("no fee", 10_000, split_report(11, 7, 0)),
    ] {
        let at = Arrived::at(at_ms, 1);
        let node = late_post(&billed, at, "vk_tokens", &report);
        if let Err(e) = every_cell_agrees(
            label,
            &second_book_rows(&node),
            &governance_row(&report),
            &billed,
            at_ms,
        ) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_planted_open_class_divergence_goes_red() {
    let at = Arrived::at(4_000, 7);
    let priced = rerank_history(3, Some(2_000_000));
    let report = rerank_report(50);
    let governance = governance_row(&report);
    let rows = second_book_rows(&late_post(&priced, at, "vk_rerank", &report));
    every_cell_agrees("unplanted", &rows, &governance, &priced, at.ms())
        .expect("the unplanted rows agree, so a red below is the plant's");

    let mut undercounted = rows.clone();
    if let Some(counts) = undercounted[0].counts.as_mut() {
        counts.classes.insert(SEARCH_UNITS.to_string(), 49);
    }
    let red = every_cell_agrees("planted: 49", &undercounted, &governance, &priced, at.ms());
    assert!(
        red.as_ref()
            .is_err_and(|e| e.contains("class search_units")),
        "an under-counted open class was NOT caught: {red:?}"
    );

    let mut dropped = rows.clone();
    if let Some(counts) = dropped[0].counts.as_mut() {
        counts.classes.remove(SEARCH_UNITS);
    }
    assert!(
        every_cell_agrees("planted: dropped", &dropped, &governance, &priced, at.ms()).is_err(),
        "a dropped open class was NOT caught"
    );

    let fee_only = second_book_rows(&late_post(&priced, at, "vk_fee", &rerank_report(0)));
    let mut head_shaped = rows.clone();
    head_shaped[0].settled = fee_only[0].settled;
    assert!(
        every_cell_agrees(
            "planted: fee only",
            &head_shaped,
            &governance,
            &priced,
            at.ms()
        )
        .is_err_and(|e| e.contains("money")),
        "a second book that priced the rerank at the fee alone was NOT caught"
    );
    head_shaped[0].counts = None;
    assert!(
        every_cell_agrees(
            "planted: no counts",
            &head_shaped,
            &governance,
            &priced,
            at.ms()
        )
        .is_err(),
        "a second book with no counts was NOT caught"
    );
}

const RERANK_LANE: &str = "rerank-v3.5";

const RERANK_POOL: &str = "rr";

const RERANK_UNITS: u64 = 50;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_served_rerank_puts_identical_search_units_on_both_books() {
    declare_test_classes();
    plane::install_test_seams();
    busbar_kernel_testkit::test_support::metrics::init();

    let state = Arc::new(MockServerState::new());
    for _ in 0..4 {
        state.push(MockResponse::Ok {
            status: reqwest::StatusCode::OK,
            body: serde_json::json!({
                "id": "rr-1",
                "results": [{"index": 0, "relevance_score": 0.9}],
                "meta": {"billed_units": {"search_units": RERANK_UNITS}}
            }),
        });
    }
    let server = MockServer::new(Arc::clone(&state)).await;
    let store = crate::root::real_store::records();
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &SIGNING_SECRET,
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(store, None, Some(signer))
            .expect("governance"),
    );
    let (key, _token) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: unique("root-rerank"),
                ..Default::default()
            },
            LIVE_EXP,
            MINTED_AT,
        )
        .expect("mint the deployment's key");

    let cost = busbar_kernel::cost::CostModel::resolve_parts(None, FEE_CENTS, &Default::default());
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let app = TestApp::new()
        .keys_chain()
        .lane(
            LaneSpec::new(RERANK_LANE, proto_codec::PROTO_COHERE, &server.base_url()).provider(
                DIALECTS["rerank"]["provider"]
                    .as_str()
                    .expect("the fixture names the rerank lane's provider"),
            ),
        )
        .pool(RERANK_POOL, &[(0, 1)])
        .governance(Arc::clone(&gov))
        .cost(cost)
        .build();
    let key = Arc::new(key);
    let gov_ctx = busbar_contract::records::PlaneRequestCtx {
        key: Some(Arc::clone(&key)),
    };

    let history = rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let node = Node::new();
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    node.bind_book(Arc::clone(&book.durability));

    let arrival = plane::WalkArrival {
        host: busbar_kernel::plane_driver::engine_host(&app),
        gov: gov_ctx.clone(),
        proto: linked_dialect(
            DIALECTS["rerank"]["path_dialect"]
                .as_str()
                .expect("the fixture names the rerank unit's dialect"),
        ),
        operation: busbar_contract::operation::OpVerb::RERANK,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: Bytes::from_static(br#"{"query":"which is fastest","documents":["a","b","c"]}"#),
        path: Some(PathFacts {
            operation: busbar_contract::operation::OpVerb::RERANK,
            stream: false,
            gemini_json_array: false,
            model_not_found_message: None,
            model: RERANK_POOL.to_string(),
        }),
    };
    let arrived = Arrived::at(EPOCH * 1_000, 0);
    let key_n = node.next_key.mint();

    let (principal, op_class, _proto, build) = plane::handed(arrival, None);
    let meter = Arc::new(AccrualMeter::new());
    let (units, route, finish) = build((node.resolver(), EPOCH));
    let hold = busbar_kernel::inflight::arrival_hold(
        &node.kernel,
        &node.door,
        principal.clone(),
        node.kernel.next_call(),
    );
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key: key_n,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: key_n,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };

    let driven = Driven {
        node: &node,
        route: &*route,
        op_class,
        principal: &principal,
        arrived,
        history: Some(&history),
        sealing: Mutex::new(None),
    };
    let ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &*units,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
            taps: Some(&driven),
        },
        &driven,
    )
    .await;
    node.inflight.remove(key_n);

    let (answer, late) = finish();
    let response = answer
        .expect("the served unit posted its terminal")
        .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the rerank was served");
    let seal = driven.take_seal(ctx.key);
    assert!(seal.is_some(), "the audit door handed its pass back");
    let response = node.tail(
        ended,
        response,
        late,
        &principal,
        arrived,
        Some(&history),
        seal,
    );
    let _body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the served body drains");
    server.shutdown().await;

    gov.flush_budgets();
    let ledger = gov
        .store()
        .get_usage(
            &key.id,
            busbar_kernel::governance::budget_window(
                busbar_kernel::governance::WINDOW_TOTAL,
                EPOCH,
            ),
        )
        .expect("the governance ledger reads");
    let classes = ledger
        .models
        .iter()
        .find(|m| m.model == RERANK_LANE)
        .map(|m| {
            m.usage_units
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(class, count)| (class.clone(), *count))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    assert_eq!(
        classes.get(SEARCH_UNITS),
        Some(&RERANK_UNITS),
        "the governance ledger accrued the rerank's search units: {classes:?}"
    );
    let governance = crate::root::durability::UnitCounts {
        lane: RERANK_LANE.to_string(),
        fee_count: ledger.billable_requests,
        classes,
    };

    {
        let durability = book.durability.lock().expect("unpoisoned");
        assert_eq!(
            durability.audit_records.len(),
            1,
            "one record per unit: {:?}",
            durability.audit_records
        );
        let record = &durability.audit_records[0];
        assert_eq!(record.what.unit_key, key_n);
        assert_eq!(record.what.incarnation, durability.incarnation);
        assert_eq!(
            record.outcome.unit_end,
            busbar_contract::caps::Outcome::Completed
        );
        assert!(
            record
                .usage
                .lines
                .iter()
                .any(|l| l.class.as_str() == SEARCH_UNITS && l.quantity == RERANK_UNITS),
            "the record's amount is the line's counts: {:?}",
            record.usage.lines
        );
        assert!(durability.retained_audit_findings().is_empty());
    }

    let rows = second_book_rows(&book);
    assert_eq!(
        rows.len(),
        1,
        "one line per unit: the exit writes none when the late arm writes it: {rows:?}"
    );
    assert_eq!(
        rows[0].kind,
        crate::root::durability::PostingKind::Settlement,
        "the one line settles the unit's reservation: {rows:?}"
    );
    assert_eq!(
        rows.first()
            .and_then(|row| row.counts.as_ref())
            .and_then(|counts| counts.classes.get(SEARCH_UNITS)),
        Some(&RERANK_UNITS),
        "the durable book's row carries the rerank's search units: {rows:?}"
    );
    every_cell_agrees("served rerank", &rows, &governance, &history, arrived.ms())
        .expect("both books hold the same search units and the same figure");
}

#[test]
fn binding_the_node_to_the_book_journals_every_card_applied_after_it() {
    use crate::root::kernel::{CardApplied, RootHistory};
    fn apply(holder: &RootHistory, input: f64, at: u64) {
        let lanes = [(
            "gpt".to_string(),
            busbar_contract::billing::RawTierRates {
                input: busbar_kernel_ledger::cost::representable_nano_rate(input),
                output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
            },
        )];
        let _ = holder.apply_rates(
            &busbar_kernel::rate_apply::RawRates {
                lanes: &lanes,
                units: &[],
                flat_minor: 0,
                present: true,
                plane_fees: &busbar_kernel::config::PlaneFeesMap::new(),
            },
            at,
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "busbar-node-book-cards-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");

    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.arm_journal();
    apply(holder, 3.0, 1_000);
    let slots = crate::root::store_double::RecordSlots::new();
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store").unwrap();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig {
                data_dir: Some(dir.clone()),
            },
            7,
            lane,
            Some(holder),
        )
        .expect("the journal opens"),
    ));

    super::bind_node_book(&Node::new(), holder, Arc::clone(&book));
    apply(holder, 5.0, 20_000);

    let cards = book
        .lock()
        .expect("the book")
        .chain()
        .expect("reads")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter_map(|r| CardApplied::from_body(&r.body))
        .map(|applied| applied.effective_from)
        .collect::<Vec<_>>();
    assert_eq!(
        cards,
        vec![0, 20_000],
        "the boot card and the card applied after the binding are both on the chain"
    );
    let lane = book.lock().unwrap().lane().unwrap().clone();
    assert!(lane.drain(std::time::Duration::from_secs(5)));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    drop(book);
    let _ = std::fs::remove_dir_all(&dir);
}

struct ServedHost;

impl busbar_kernel::ingress::arrival::ArrivalHost for ServedHost {
    fn finish_rejected(
        &self,
        _ctx: &busbar_kernel::ingress::arrival::ArrivalCtx,
        _proto: &str,
        _pool: &str,
        _started: std::time::Instant,
        _charged_at: u64,
        resp: Response,
    ) -> Response {
        resp
    }

    fn ingress_error(
        &self,
        proto: &str,
        status: StatusCode,
        kind: &str,
        message: &str,
    ) -> Response {
        busbar_kernel::ingress::ingress_error(proto, status, kind, message)
    }

    fn envelope_dialect(
        &self,
        _ctx: &busbar_kernel::ingress::arrival::ArrivalCtx,
        _path: &str,
    ) -> &'static str {
        PROTO
    }

    fn fallback_not_found(
        &self,
        _ctx: &busbar_kernel::ingress::arrival::ArrivalCtx,
        _path: &str,
        status: StatusCode,
        err_type: &str,
        message: &str,
    ) -> Response {
        busbar_kernel::ingress::ingress_error(PROTO, status, err_type, message)
    }

    fn percent_decode(&self, s: &str) -> String {
        s.to_string()
    }

    fn kind_not_found(&self) -> &'static str {
        busbar_contract::protocol::KIND_NOT_FOUND
    }

    fn kind_invalid_request(&self) -> &'static str {
        busbar_contract::protocol::KIND_INVALID_REQUEST
    }

    fn err_type_not_found(&self) -> &'static str {
        busbar_contract::protocol::KIND_NOT_FOUND
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_linked_arrivals_hand_their_units_to_the_node_the_root_installs() {
    let rig = rig(Fixture::BufferedOk).await;
    assert!(
        !crate::LINKED.node.is_empty(),
        "no linked entry is on the node axis, so no arrival is ever handed a node"
    );
    let node = super::ROOT_UNIT
        .drive
        .expect("the node's root unit carries the node the axis is handed");
    for install in crate::LINKED.node {
        install(node);
    }
    let arrive = crate::LINKED
        .body_ingress
        .iter()
        .flat_map(|table| table.iter())
        .find(|(name, _)| *name == PROTO)
        .map(|(_, arrival)| *arrival)
        .expect("the linked table carries this dialect's arrival");
    let resp = arrive(busbar_kernel::ingress::arrival::Arrival {
        host: Arc::new(ServedHost),
        ctx: busbar_kernel::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
            host: rig.host(),
            gov: rig.gov(),
            caller_token: None,
        }),
        path: "/v1/chat/completions".to_string(),
        model_hint: None,
        uri: "/v1/chat/completions"
            .parse()
            .expect("the endpoint is a URI"),
        headers: json_headers(),
        body: Fixture::BufferedOk.body(),
    })
    .await
    .into_response();
    let observed = observe(&rig, resp).await;
    assert_eq!(
        field(&observed, "status"),
        "200",
        "the linked arrival did not serve through the node: {}",
        field(&observed, "body")
    );
    assert!(
        rig.upstream.get_last_request_path().is_some(),
        "the unit never reached the upstream, so no node drove its Route step"
    );
    rig.server.shutdown().await;
}

#[test]
fn a_late_arm_with_no_reading_writes_the_exits_own_line() {
    let history = rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    let kernel = Kernel::new();
    let who = PrincipalId::new("acct:late-none");
    let hold = busbar_contract::caps::Hold::open(&kernel.admit_token(), who.clone(), 0);
    let usage = busbar_contract::caps::Usage::report(&kernel.usage_token(), Vec::new())
        .expect("an empty report fits");
    let exit = busbar_contract::caps::Posted::settle(hold, 0, &usage, &kernel.ledger_token());
    let arm = LateAccrual {
        book: Arc::clone(&book.durability),
        history,
        durability_token: kernel.durability_token(),
        ledger_token: kernel.ledger_token(),
        usage_token: kernel.usage_token(),
        principal: who,
        arrived: Arrived::at(EPOCH * 1_000, 3),
        late: Box::new(|| None),
        exit: Some(exit),
        outcome: None,
        seal: None,
    };
    arm.post();
    let rows = second_book_rows(&book);
    assert_eq!(rows.len(), 1, "the unit keeps its one line: {rows:?}");
    assert_eq!(
        rows[0].kind,
        crate::root::durability::PostingKind::Settlement,
        "and it is the exit's settlement: {rows:?}"
    );
    assert_eq!(rows[0].settled, 0);
}

#[test]
fn a_class_no_plane_declared_is_refused_and_keeps_its_counts() {
    let history = cache_silent_history();
    let mut report = split_report(1_000, 0, 1);
    report
        .usage
        .usage_units
        .insert("units_nobody_declared".to_string(), 40);
    let at = Arrived::at(4_000, 7);
    let node = late_post(&history, at, "vk_undeclared", &report);

    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    let row = &rows[0];
    let counts = row.counts.as_ref().expect("the line carries the counts");
    assert_eq!(counts.classes.get("units_nobody_declared"), Some(&40));
    assert_eq!(
        counts.classes.get(busbar_contract::records::UNIT_INPUT),
        Some(&1_000)
    );
    assert!(
        row.refusal.as_deref().is_some_and(
            |why| why.contains("UndeclaredClass") && why.contains("units_nobody_declared")
        ),
        "the money is refused and names the class: {:?}",
        row.refusal
    );
    assert_eq!((row.reserved, row.settled, row.overdraft), (0, 0, 0));
    let durability = node.durability.lock().expect("unpoisoned");
    let key = balance(&PrincipalId::new("vk_undeclared"));
    let window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, at.secs());
    assert_eq!(durability.ledger.book().get(&key, window).settled, 0);
    assert!(durability.settled_read(&key, window).is_err());
    drop(durability);

    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let node = late_post(&absent, at, "vk_undeclared_absent", &report);
    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert!(
        rows[0]
            .refusal
            .as_deref()
            .is_some_and(|why| why.contains("UndeclaredClass")),
        "never billed at zero, and a replay keeps the refusal: {:?}",
        rows[0].refusal
    );
}

#[test]
fn a_declared_open_class_on_an_absent_card_posts_its_counts_unrefused() {
    let absent = fee_history_of(&[(0, 0.0, 0.0, 0)], false);
    let mut report = split_report(0, 0, 0);
    report
        .usage
        .usage_units
        .insert(SEARCH_UNITS.to_string(), 50);
    let node = late_post(&absent, Arrived::at(4_000, 7), "vk_absent", &report);
    let rows = second_book_rows(&node);
    assert_eq!(rows.len(), 1, "one line per unit: {rows:?}");
    assert_eq!(rows[0].refusal, None, "a declared class is never refused");
    assert_eq!(
        rows[0]
            .counts
            .as_ref()
            .and_then(|c| c.classes.get(SEARCH_UNITS)),
        Some(&50)
    );
}

#[test]
fn a_dispatch_record_is_written_on_the_book_under_its_units_facts() {
    use busbar_kernel_egress::ports::{Dispatched, DurabilityUnavailable, Journal};
    let node = Arc::new(Node::new());
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));
    let written = || {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies")
            .len()
    };
    let site = NodeEndPost::new(Arc::clone(&node));
    let record = |unit: u64| Dispatched {
        leg: 0,
        attempt: 1,
        pool: String::new(),
        destination: busbar_contract::DestinationId::new(0),
        lane: None,
        unit: UnitKey::new(unit),
    };
    site.open(
        UnitKey::new(51),
        PrincipalId::new("acct:dispatch"),
        Arrived::at(EPOCH * 1_000, 0),
        None,
    );
    let before = written();
    assert_eq!(site.dispatched(&record(51)), Ok(()));
    assert_eq!(written(), before + 1, "the dispatch is on the book");
    assert_eq!(
        site.dispatched(&record(52)),
        Err(DurabilityUnavailable),
        "no open facts, no record, no dial"
    );
    assert_eq!(written(), before + 1);
    site.close(UnitKey::new(51));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_screened_veto_through_the_node_admits_nothing() {
    let rig = rig(Fixture::BufferedOk).await;
    let node = Node::new();
    let (_unit, ended) = drive_screened_by(
        &rig,
        &node,
        Fixture::BufferedOk,
        rig.gov(),
        &[],
        Some(busbar_contract::caps::ReasonCode::HookVeto),
    )
    .await;
    let Ended::Settled { end, .. } = ended else {
        panic!("the unit ends here");
    };
    assert_eq!(
        end.outcome(),
        Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            busbar_contract::caps::ReasonCode::HookVeto
        ),
        "refused at the screen, before the door"
    );
    let gov = rig
        .app
        .governance
        .clone()
        .expect("governance is configured");
    let derived = gov
        .derived_bucket_usage(&rig.app.cost, &rig.key.id, "total", true, rig.charged_at)
        .expect("usage read");
    assert_eq!(derived.requests, 0, "a veto admits nothing");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_journal_lane_refuses_a_new_unit_503_with_the_reason() {
    for data_dir in [
        None,
        Some(std::path::PathBuf::from("/dev/null/legacy-journal")),
    ] {
        let slots = crate::root::store_double::RecordSlots::new();
        slots.refuse(true);
        let lane =
            crate::root::durability::JournalLane::with_capacity(slots.calls(), "test-store", 1)
                .expect("the lane starts");
        let book = Arc::new(std::sync::Mutex::new(
            crate::root::durability::build_on_store(
                &crate::root::durability::DurabilityConfig { data_dir },
                0,
                lane,
                None,
            )
            .expect("the store reads back"),
        ));
        let token = busbar_kernel_testkit::test_support::tokens::grant::<
            busbar_contract::caps::DurableWrite,
        >();
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
        let node = Node::new();
        node.bind_book(Arc::clone(&book));
        let built = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw = Arc::clone(&built);
        let handed: crate::root::linked::node::Handed = (
            PrincipalId::new("acct:full"),
            busbar_contract::caps::OpClassId::new("call"),
            PROTO,
            Box::new(move |_lent| {
                saw.store(true, std::sync::atomic::Ordering::SeqCst);
                panic!("a refused unit is never built");
            }),
        );
        let response = node.answer(handed).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("journal is full") && body.contains("`test-store`"),
            "the reason names the full journal and the store: {body}"
        );
        assert!(!built.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            book.lock().unwrap().journal.dropped_total(),
            0,
            "no record is dropped"
        );
    }
}

#[test]
fn the_exit_arm_seals_no_money_figure_into_the_record() {
    use busbar_contract::caps::{Admittance, Hold, Posted, Usage, WriteMoney};
    use busbar_kernel_testkit::test_support::tokens::{end, grant, origin, pass};

    let node = Node::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let book = Arc::new(std::sync::Mutex::new(durability));
    node.bind_book(Arc::clone(&book));

    const MONEY: u64 = 150;
    let who = PrincipalId::new("acct:h2");
    let hold = Hold::open(&grant::<Admittance>(), who.clone(), 100);
    let usage = Usage::report(&grant::<busbar_contract::caps::Consumption>(), Vec::new())
        .expect("an empty report fits the record");
    let posted = Posted::settle(hold, u128::from(MONEY), &usage, &grant::<WriteMoney>());
    assert_eq!(posted.settled(), MONEY, "the posting moved money");
    let ended = Ended::Settled {
        end: end(Outcome::Completed, Ok(posted)),
        requests: 0,
        fee: 0,
    };
    let seal = UnitSeal {
        facts: busbar_contract::caps::AuditFacts {
            op_class: busbar_contract::caps::OpClassId::new("call"),
            finish: busbar_contract::FinishClass::Complete,
        },
        pass: pass(),
        key: UnitKey::new(77),
        origin: origin(OriginKind::Client),
        parent: None,
    };
    node.settle_end(&who, Arrived::at(EPOCH * 1_000, 0), None, ended, Some(seal));

    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let record = durability
        .audit_records
        .last()
        .expect("the exit arm sealed the unit's record");
    assert!(
        record.usage.lines.iter().all(|line| line.class
            != busbar_kernel::teller::KERNEL_ACCRUAL_CLASS
            && line.quantity != MONEY),
        "the record carries counts, never the settled money figure: {:?}",
        record.usage.lines
    );
}

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
        busbar_kernel::governance::GovState::new_with_signer(
            crate::root::real_store::records(),
            None,
            Some(signer),
        )
        .expect("governance"),
    );
    let spec = |name: &str| busbar_kernel::governance::NewKeySpec {
        name: name.to_string(),
        group: groups.keys().next().cloned(),
        ..Default::default()
    };
    let (key, token) = gov
        .mint_signed(spec("root-node-over"), LIVE_EXP, MINTED_AT)
        .expect("mint the deployment's key");
    let (_, expired_token) = gov
        .mint_signed(spec("root-node-over-expired"), DEAD_EXP, MINTED_AT)
        .expect("mint the expired key");
    let cost = busbar_kernel::cost::CostModel::resolve_parts(card.as_ref(), fee, &groups);
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
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
async fn a_pre_routing_refusal_leaves_a_prior_charge_intact() {
    let rig = rig(Fixture::Malformed).await;
    rig.app
        .governance
        .clone()
        .expect("governance is configured")
        .try_admit(&rig.app.cost, &rig.key, "", rig.charged_at)
        .expect("an uncapped chain admits the prior request");
    let resp = drive(&rig, Fixture::Malformed).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    assert_eq!(
        field(&observed, "status"),
        "400",
        "a malformed body is a pre-routing 400"
    );
    assert_eq!(
        field(&observed, "ledger_requests"),
        "1",
        "the prior request is still on the key's bucket"
    );
    assert_eq!(
        field(&observed, "ledger_spend_cents"),
        FEE_CENTS.to_string(),
        "the pre-routing refusal refunded nothing: the prior fee stands"
    );
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
        gov.derived_bucket_usage(
            &rig.app.cost,
            &format!("group:{}@day", rig.group),
            "day",
            true,
            past_day
        )
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aliased_lane_prices_at_the_rate_card_under_its_config_name() {
    const WIRE: &str = "m0-on-the-wire";
    let card = std::collections::BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1000.0,
            output_utok: 1000.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let answered = || MockResponse::Ok {
        status: reqwest::StatusCode::OK,
        body: serde_json::json!({
            "id": "chatcmpl-aliased", "object": "chat.completion", "created": 0, "model": WIRE,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": 600, "completion_tokens": 400, "total_tokens": 1000}
        }),
    };
    let rig = rig_over(
        Some(budget_per_day(1_000_000_000)),
        Some(card),
        0,
        |origin| the_lane(origin).upstream_model(WIRE),
        (0..4).map(|_| answered()).collect(),
    )
    .await;
    let resp = drive(&rig, Fixture::BufferedOk).await;
    assert_eq!(resp.status(), StatusCode::OK, "the aliased lane served it");
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    tokio::task::yield_now().await;
    rig.server.shutdown().await;
    let sent: serde_json::Value = serde_json::from_slice(
        &rig.upstream
            .get_last_request_body()
            .expect("the upstream was dialled"),
    )
    .expect("the upstream was sent JSON");
    assert_eq!(
        sent["model"], WIRE,
        "precondition: the lane is ALIASED, or the fault is masked"
    );
    let derived = rig
        .app
        .governance
        .clone()
        .expect("governance is configured")
        .derived_bucket_usage(
            &rig.app.cost,
            &format!("group:{}@day", rig.group),
            "day",
            true,
            rig.charged_at,
        )
        .expect("usage read");
    assert_eq!(derived.tokens, 1000, "the tokens are ledgered either way");
    assert_eq!(
        derived.spend_cents, 100,
        "1,000 tokens at 1,000 micro-units each price at the card under the config name"
    );
}

const FIRST_FRAME: &str = r#"{"id":"chatcmpl-root","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"}}]}"#;

struct Reached {
    status: StatusCode,
    drained: Vec<u8>,
    reported: Option<Reported>,
}

async fn drive_reading_the_tap(rig: &Rig) -> Reached {
    use http_body_util::BodyExt as _;
    let node = Node::new();
    let arrived = node.arrived();
    let (principal, op_class, _proto, build) =
        plane::handed(chat_arrival(rig, Fixture::StreamedOk), None);
    let key = node.next_key.mint();
    let meter = Arc::new(AccrualMeter::new());
    let (units, route, finish) = build((node.resolver(), arrived.secs()));
    let hold = busbar_kernel::inflight::arrival_hold(
        &node.kernel,
        &node.door,
        principal.clone(),
        node.kernel.next_call(),
    );
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let driven = Driven {
        node: &node,
        route: &*route,
        op_class,
        principal: &principal,
        arrived,
        history: None,
        sealing: Mutex::new(None),
    };
    let _ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &*units,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
            taps: Some(&driven),
        },
        &driven,
    )
    .await;
    node.inflight.remove(key);
    let (answer, late) = finish();
    let response = answer
        .expect("the unit posted its terminal")
        .into_response();
    let status = response.status();
    let mut body = response.into_body();
    let mut drained = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            drained.extend_from_slice(&data);
        }
    }
    tokio::task::yield_now().await;
    Reached {
        status,
        drained,
        reported: late.and_then(|read| read()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tap_reports_the_end_a_status_line_cannot() {
    let tap_cases = [
        (
            "a stream cut after its first frame",
            CutEventStream {
                ok_events: vec![FIRST_FRAME.to_string()],
            },
            true,
        ),
        (
            "a transfer that failed before its first byte",
            CutEventStream {
                ok_events: Vec::new(),
            },
            false,
        ),
    ];
    for (label, cut, relayed) in tap_cases {
        let rig = rig_over(None, None, FEE_CENTS, the_lane, vec![cut; 8]).await;
        let reached = drive_reading_the_tap(&rig).await;
        let observed = observe(&rig, Response::new(axum::body::Body::empty())).await;
        rig.server.shutdown().await;
        assert_eq!(
            reached.status,
            StatusCode::OK,
            "{label}: the status line says success"
        );
        let text = String::from_utf8_lossy(&reached.drained);
        assert!(
            !text.contains("[DONE]"),
            "{label}: the answer never completed, and the caller is not told it did: {text}"
        );
        assert_eq!(
            text.contains("hello"),
            relayed,
            "{label}: the caller has exactly what was relayed before the end: {text}"
        );
        let (usage, _fee_count, lane) = reached
            .reported
            .unwrap_or_else(|| panic!("{label}: the tap reported nothing at all"));
        assert_eq!(
            lane, LANE,
            "{label}: the report is keyed to the lane that served it"
        );
        assert_eq!(
            usage.usage_units.values().sum::<u64>(),
            0,
            "{label}: no usage frame streamed before the end, so there is no token to bill"
        );
        assert_eq!(field(&observed, "ledger_tokens"), "0", "{label}");
        assert_eq!(field(&observed, "metering_rows"), "", "{label}");
    }
}

struct RerankBooks {
    status: StatusCode,
    governance: crate::root::durability::UnitCounts,
    spend: Result<i64, String>,
    rows: Vec<crate::root::durability::Posting>,
}

impl RerankBooks {
    fn durable_units(&self) -> Option<u64> {
        self.rows
            .first()
            .and_then(|row| row.counts.as_ref())
            .and_then(|counts| counts.classes.get(SEARCH_UNITS))
            .copied()
    }
}

async fn serve_rerank(
    lane_dialect: &'static str,
    arrival_dialect: &'static str,
    by_path: bool,
    upstream: serde_json::Value,
    cost: busbar_kernel::cost::CostModel,
    history: crate::root::kernel::PinnedHistory,
) -> RerankBooks {
    declare_test_classes();
    plane::install_test_seams();
    busbar_kernel_testkit::test_support::metrics::init();
    let state = Arc::new(MockServerState::new());
    for _ in 0..4 {
        state.push(MockResponse::Ok {
            status: reqwest::StatusCode::OK,
            body: upstream.clone(),
        });
    }
    let server = MockServer::new(Arc::clone(&state)).await;
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(crate::root::real_store::records(), None)
            .expect("governance"),
    );
    let (key, _secret) = gov
        .create_key(
            busbar_kernel::governance::NewKeySpec {
                name: unique("root-rerank-books"),
                ..Default::default()
            },
            MINTED_AT,
        )
        .expect("create key");
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let app = TestApp::new()
        .keys_chain()
        .lane(LaneSpec::new(RERANK_LANE, lane_dialect, &server.base_url()))
        .pool(RERANK_POOL, &[(0, 1)])
        .governance(Arc::clone(&gov))
        .cost(cost)
        .build();
    let key = Arc::new(key);
    let (body, path) = if by_path {
        let mut facts = path_facts(arrival_dialect, Fixture::BufferedOk);
        facts.operation = busbar_contract::operation::OpVerb::RERANK;
        facts.model = RERANK_POOL.to_string();
        (
            Bytes::from_static(br#"{"query":"which is fastest","documents":["a","b","c"]}"#),
            Some(facts),
        )
    } else {
        (
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "model": RERANK_POOL,
                    "query": "which is fastest",
                    "documents": ["a", "b", "c"]
                }))
                .expect("the rerank body serializes"),
            ),
            None,
        )
    };
    let node = Node::new();
    let pinned = history.clone();
    let book = crate::root::durability::node_book_over(Box::new(move || Some(pinned.clone())));
    node.bind_book(Arc::clone(&book.durability));
    let arrival = plane::WalkArrival {
        host: busbar_kernel::plane_driver::engine_host(&app),
        gov: busbar_contract::records::PlaneRequestCtx {
            key: Some(Arc::clone(&key)),
        },
        proto: arrival_dialect,
        operation: busbar_contract::operation::OpVerb::RERANK,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body,
        path,
    };
    let arrived = Arrived::at(EPOCH * 1_000, 0);
    let unit = node.next_key.mint();
    let (principal, op_class, _proto, build) = plane::handed(arrival, None);
    let meter = Arc::new(AccrualMeter::new());
    let (units, route, finish) = build((node.resolver(), EPOCH));
    let hold = busbar_kernel::inflight::arrival_hold(
        &node.kernel,
        &node.door,
        principal.clone(),
        node.kernel.next_call(),
    );
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key: unit,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            zero_hold_tick: false,
            arrival: hold,
            now: arrived.ms(),
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: unit,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let driven = Driven {
        node: &node,
        route: &*route,
        op_class,
        principal: &principal,
        arrived,
        history: Some(&history),
        sealing: Mutex::new(None),
    };
    let ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &*units,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
            taps: Some(&driven),
        },
        &driven,
    )
    .await;
    node.inflight.remove(unit);
    let (answer, late) = finish();
    let response = answer
        .expect("the served unit posted its terminal")
        .into_response();
    let status = response.status();
    let seal = driven.take_seal(ctx.key);
    let response = node.tail(
        ended,
        response,
        late,
        &principal,
        arrived,
        Some(&history),
        seal,
    );
    let _body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the served body drains");
    server.shutdown().await;

    let spend = gov
        .usage_for(&app.cost, &key.id, EPOCH)
        .map(|usage| usage.expect("the key exists").spend_cents)
        .map_err(|refusal| format!("{refusal:?}"));
    gov.flush_budgets();
    let ledger = gov
        .store()
        .get_usage(
            &key.id,
            busbar_kernel::governance::budget_window(
                busbar_kernel::governance::WINDOW_TOTAL,
                EPOCH,
            ),
        )
        .expect("the governance ledger reads");
    let classes = ledger
        .models
        .iter()
        .find(|row| row.model == RERANK_LANE)
        .map(|row| {
            row.usage_units
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(class, count)| (class.clone(), *count))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    RerankBooks {
        status,
        governance: crate::root::durability::UnitCounts {
            lane: RERANK_LANE.to_string(),
            fee_count: ledger.billable_requests,
            classes,
        },
        spend,
        rows: second_book_rows(&book),
    }
}

fn rerank_answer(units: Option<u64>) -> serde_json::Value {
    let mut answer = serde_json::json!({
        "id": "rr-1",
        "results": [{"index": 0, "relevance_score": 0.9}]
    });
    if let Some(units) = units {
        answer["meta"] = serde_json::json!({"billed_units": {"search_units": units}});
    }
    answer
}

fn rerank_dialects() -> (&'static str, &'static str) {
    let named = |key: &str| {
        linked_dialect(
            DIALECTS["rerank"][key]
                .as_str()
                .unwrap_or_else(|| panic!("the fixture names the rerank `{key}`")),
        )
    };
    (named("provider"), named("path_dialect"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reranks_search_units_reach_the_price_on_both_books() {
    let (provider, _) = rerank_dialects();
    let card = |entry: &str| {
        let rates: std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> =
            serde_yaml::from_str(&format!("{RERANK_LANE}: {entry}\n")).expect("the card parses");
        busbar_kernel::cost::CostModel::resolve_parts(Some(&rates), 0, &Default::default())
    };
    let priced = format!("{{ units: {{ {SEARCH_UNITS}: 2000 }} }}");
    let at = EPOCH * 1_000;
    for (units, cents) in [(50_u64, 10_i64), (1, 0)] {
        let books = serve_rerank(
            provider,
            provider,
            false,
            rerank_answer(Some(units)),
            card(&priced),
            rerank_history_on(RERANK_LANE, 0, Some(2_000_000)),
        )
        .await;
        assert_eq!(books.status, StatusCode::OK, "{units} units: served");
        assert_eq!(books.spend, Ok(cents), "{units} search units at 0.2 cents");
        assert_eq!(
            books.rows.first().map(|row| row.settled),
            Some(i128::from(units) * 2_000_000),
            "{units} units: the durable book settles them at the card"
        );
        every_cell_agrees(
            "rerank, priced",
            &books.rows,
            &books.governance,
            &rerank_history_on(RERANK_LANE, 0, Some(2_000_000)),
            at,
        )
        .expect("both books price the rerank alike");
    }

    let silent = serve_rerank(
        provider,
        provider,
        false,
        rerank_answer(Some(50)),
        card("{ input_utok: 1 }"),
        rerank_history_on(RERANK_LANE, 0, None),
    )
    .await;
    assert!(
        silent.spend.is_err(),
        "a present card silent about search_units REFUSES (#42), never a silent 0: {:?}",
        silent.spend
    );
    assert!(
        silent
            .rows
            .first()
            .and_then(|row| row.refusal.as_deref())
            .is_some_and(|why| why.contains(SEARCH_UNITS)),
        "the durable book refuses the same class: {:?}",
        silent.rows
    );

    let absent = crate::root::kernel::PinnedHistory::for_test(
        Arc::new(busbar_kernel_ledger::cost::History::opening(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                false,
            ),
            0,
        )),
        busbar_kernel_ledger::cost::HistorySeq(0),
    );
    let off = serve_rerank(
        provider,
        provider,
        false,
        rerank_answer(Some(50)),
        busbar_kernel::cost::CostModel::resolve_parts(None, 0, &Default::default()),
        absent.clone(),
    )
    .await;
    assert_eq!(off.spend, Ok(0), "no card: billing off reads 0");
    assert_eq!(
        off.durable_units(),
        Some(50),
        "billing off still keeps the counts"
    );
    every_cell_agrees(
        "rerank, billing off",
        &off.rows,
        &off.governance,
        &absent,
        at,
    )
    .expect("both books read the rerank at nothing with billing off");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_same_dialect_rerank_puts_identical_search_units_on_both_books() {
    let (provider, by_url) = rerank_dialects();
    let history = || rerank_history_on(RERANK_LANE, 3, Some(2_000_000));
    let cost =
        || busbar_kernel::cost::CostModel::resolve_parts(None, FEE_CENTS, &Default::default());
    for (dialect, by_path) in [(provider, false), (by_url, true)] {
        let billed = serve_rerank(
            dialect,
            dialect,
            by_path,
            rerank_answer(Some(RERANK_UNITS)),
            cost(),
            history(),
        )
        .await;
        assert_eq!(billed.status, StatusCode::OK, "{dialect}: served");
        assert_eq!(
            billed.governance.classes.get(SEARCH_UNITS),
            Some(&RERANK_UNITS),
            "{dialect} -> {dialect}: the governance ledger holds the rerank's search units"
        );
        assert_eq!(
            billed.durable_units(),
            Some(RERANK_UNITS),
            "{dialect} -> {dialect}: the durable book holds the rerank's search units"
        );

        let unbilled = serve_rerank(
            dialect,
            dialect,
            by_path,
            rerank_answer(None),
            cost(),
            history(),
        )
        .await;
        assert_eq!(
            (
                unbilled.governance.classes.get(SEARCH_UNITS).copied(),
                unbilled.durable_units()
            ),
            (None, None),
            "{dialect}: no units, none booked"
        );
    }
}
