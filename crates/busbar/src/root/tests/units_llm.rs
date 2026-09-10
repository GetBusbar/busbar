//! Tests for `units_llm.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_core::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use busbar_kernel::teller::Ended;

/// The one dialect these fixtures speak. Same-protocol openai→openai, so a divergence is about
/// the PATH rather than about a translation.
const PROTO: &str = busbar_llm::proto_codec::PROTO_OPENAI;
const POOL: &str = "p";
const LANE: &str = "m0";
/// One cent, so that derived spend in cents reads as the billable count.
const FEE_CENTS: i64 = 1;
/// The token figures the scripted upstream reports on a delivered answer.
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
            Fixture::StreamedOk => MockResponse::Sse {
                events: sse_events(),
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

    /// The bytes the caller sends.
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

fn sse_events() -> Vec<String> {
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

/// A unique group name per rig, so two rigs never share a bucket.
fn unique(prefix: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}-{}", N.fetch_add(1, Ordering::SeqCst))
}

/// One deployment: a governed key, a one-lane pool, and a scripted upstream.
struct Rig {
    app: Arc<busbar_core::state::App>,
    key: Arc<busbar_contract::store::VirtualKey>,
    /// The BEARER the deployment's own door will resolve back to [`Rig::key`]. Minted rather
    /// than synthesized, so a fixture that presents it is presenting the thing a client sends.
    token: String,
    /// A bearer for a SECOND key on the same deployment whose lifetime has already run out.
    /// It verifies against the same signer and names a live, enabled binding — the only thing
    /// wrong with it is the clock, which is what makes it an expiry fixture rather than a
    /// forgery fixture.
    expired_token: String,
    server: MockServer,
    /// The scripted upstream's own state, kept so a fixture can ask whether the upstream was
    /// dialled at all — "the unit stopped before the route step" is not a fact any counter on
    /// this side of the loop reports.
    upstream: Arc<MockServerState>,
    charged_at: u64,
    group: String,
}

/// The signing secret every rig's door verifies against. One process-wide constant, because a
/// per-rig secret would make "this token is not ours" and "this token has expired" the same
/// failure.
const SIGNING_SECRET: [u8; 32] = [7u8; 32];
/// When a rig's tokens are minted, and when the live one runs out. The live `exp` is far enough
/// out that a wall clock reads it as valid; the expired one is already behind every clock.
const MINTED_AT: u64 = 1_700_000_000;
const LIVE_EXP: u64 = 4_000_000_000;
const DEAD_EXP: u64 = 1_000_000_000;

async fn rig(fixture: Fixture) -> Rig {
    busbar_llm::testkit::install_test_seams();
    busbar_core::metrics::init();

    let state = Arc::new(MockServerState::new());
    for _ in 0..8 {
        state.push(fixture.upstream());
    }
    let server = MockServer::new(Arc::clone(&state)).await;

    let group = unique("root-llm");
    let mut groups = std::collections::BTreeMap::new();
    if fixture.seeded_group_requests().is_some() {
        groups.insert(
            group.clone(),
            busbar_core::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_core::config::groups::LimitCfg {
                    metric: busbar_core::config::groups::LimitMetric::Budget,
                    amount: 100,
                    per: Some(busbar_core::config::groups::LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        );
    }

    let store = Arc::new(busbar_core::governance::MemoryStore::new());
    if let Some(requests) = fixture.seeded_group_requests() {
        use busbar_contract::store::Store as _;
        store
            .put_usage(
                &format!("group:{group}@total"),
                0,
                &busbar_contract::store::UsageLedger {
                    requests,
                    billable_requests: requests,
                    models: vec![],
                },
            )
            .expect("seed the durable bucket");
    }
    // A SIGNER, so the keys below are minted as the credentials a client actually presents and
    // the deployment's own door can be asked to resolve them. Without one a rig could only ever
    // hand the plane a hand-built context, which is the one thing an authenticate fixture must
    // not do.
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &SIGNING_SECRET,
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_core::governance::GovState::new_with_signer(store, None, Some(signer))
            .expect("governance"),
    );
    let spec = |name: &str| busbar_substrate::governance::NewKeySpec {
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
        .mint_signed(spec("root-llm"), LIVE_EXP, MINTED_AT)
        .expect("mint the deployment's key");
    let (_, expired_token) = gov
        .mint_signed(spec("root-llm-expired"), DEAD_EXP, MINTED_AT)
        .expect("mint the expired key");
    let cost = busbar_core::cost::CostModel::resolve_parts(None, FEE_CENTS, &groups);
    gov.hydrate_budgets(&cost, 0).expect("hydrate");

    let app = TestApp::new()
        // THE CONFIGURED AUTH CHAIN, so `identity_admit` runs the same resolution the HTTP
        // middleware runs rather than falling through an open front door.
        .keys_chain()
        .lane(LaneSpec::new(LANE, PROTO, &server.base_url()).provider("test"))
        .pool(POOL, &[(0, 1)])
        .governance(gov)
        .cost(cost)
        .build();

    Rig {
        app,
        key: Arc::new(key),
        token,
        expired_token,
        server,
        upstream: state,
        charged_at: busbar_substrate::store::now(),
        group,
    }
}

impl Rig {
    fn gov(&self) -> busbar_contract::store::PlaneRequestCtx {
        busbar_contract::store::PlaneRequestCtx {
            key: Some(self.key.clone()),
        }
    }

    fn host(&self) -> Arc<dyn busbar_substrate::plane_host::EngineHost> {
        busbar_core::plane_host::engine_host(&self.app)
    }
}

/// Header values a response mints fresh per run. The NAME stays in the comparison and only the
/// value is blanked, so a leg that stopped emitting one is still a divergence.
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

/// Blank the values a response synthesizes per run — ids and clocks.
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

/// One field of what a leg left behind, by name. Absent reads as empty rather than panicking,
/// so a comparison that named a field nobody observes fails on the VALUE rather than on the
/// lookup — a missing field is a divergence, not a test bug.
fn field(o: &Observed, k: &str) -> String {
    o.0.iter()
        .find(|(f, _)| *f == k)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Compare the two legs field by field, collecting every divergence under `label` rather than
/// stopping at the first — one run should name everything that moved, not the earliest thing.
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
    use busbar_substrate::store::BreakerState;

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
    fields.push((
        "body",
        normalize(&String::from_utf8_lossy(&body)).replace(&rig.group, "<group>"),
    ));

    // The body wrapper records the stream's outcome on drop; give it a tick before the reads.
    tokio::task::yield_now().await;

    // THE MONEY. The derived figures the enforcer compares against a cap, and the raw per-model
    // series row the flush writes.
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
    let mut rows: Vec<busbar_contract::store::MeteringRow> = gov
        .metering_for(busbar_substrate::governance::metering_bucket(
            rig.charged_at,
        ))
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

    // THE BREAKER. The lane's own state after the walk.
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

/// LEG 1 — the shipped entry point, on its own deployment.
async fn leg_legacy(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let resp = busbar_llm::native_ingress::operation_ingress(
        &ctx,
        json_headers(),
        fixture.body(),
        PROTO,
        busbar_api::operation::Operation::CHAT,
        None,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

/// LEG 2 — the same request through the kernel's loop over the nine step files.
async fn leg_loop(fixture: Fixture) -> Observed {
    let rig = rig(fixture).await;
    let resp = drive(&rig, fixture).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

/// One request, through the real loop, awaited on this task — exactly as the mount drives it.
async fn drive(rig: &Rig, fixture: Fixture) -> Response {
    let node = LlmNode::new();
    let arrival = WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: fixture.body(),
        path: None,
    };
    node.answer(arrival, None).await
}

/// **One arrival is one reading, and both figures come out of it.**
///
/// The pure half of the straddle. A unit arriving at the last millisecond of a window has its
/// seconds in that window and its milliseconds one tick short of the next: read the clock twice
/// there and the second read is already over the line, so the table stamps the unit in one
/// window and the books bill it in another. Read once and the two figures are two spellings of
/// one instant, which is the property asserted here.
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

/// **Two units of one second are ordered by the monotonic stamp, not by the wall clock.**
///
/// The node's two clocks answer two different questions and the audit record and the posting
/// stamp each want both. The wall clock DATES: it says which window a unit belongs to, and it is
/// steppable, so an operator, an NTP correction or a leap second can hand two events timestamps
/// that run backwards. The monotonic reading ORDERS: it only goes up, whatever the wall clock
/// does.
///
/// So: units taken from one node inside one second — indistinguishable by the wall reading, and
/// on a stepped clock possibly backwards by it — still come out of the monotonic reading in the
/// order they were taken. Stamped from the wall clock twice, as this leg's postings were, the
/// second field is a copy of the first and this ordering does not exist.
#[test]
fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp() {
    let node = LlmNode::new();
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
    // Four units off one node inside one second is the ordinary case, not a contrived one — and
    // it is exactly the case a wall clock cannot resolve, whichever direction it was stepped.
    assert!(
        taken
            .iter()
            .all(|a| a.secs() == taken[0].secs() || a.secs() == taken[0].secs() + 1),
        "the four were taken within a second of each other"
    );
    // Two readings, not one written twice: a monotonic counter is a SEQUENCE and an epoch is a
    // date, so the day they compare equal is the day one of them stopped being what it is.
    assert_ne!(taken[0].mono(), taken[0].secs());

    // AND THE STAMP CARRIES IT. Two postings settled at one wall second, taken through the real
    // settle path onto a real journal, come back off it in the order they were written — which
    // is the ordering the record is FOR, and which does not exist if the second field is the
    // first one copied.
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let mut durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let who = PrincipalId::new("acct:llm");
    for arrived in [Arrived::at(EPOCH * 1_000, 7), Arrived::at(EPOCH * 1_000, 8)] {
        let ledger_token = busbar_caps::LedgerToken::mint(&seal);
        let accrual = busbar_caps::HoldAccrual::after_terminal(who.clone(), 0, &ledger_token);
        let posted = busbar_caps::Posted::settle_late(accrual, &ledger_token);
        settle(
            &mut durability,
            &who,
            arrived,
            &busbar_caps::DurabilityToken::mint(&seal),
            posted,
        )
        .expect("the memory-buffered journal takes it");
    }
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

/// **A unit that arrives in the last millisecond of a window bills in THAT window.**
///
/// The driven half. The arrival is placed one millisecond short of a metering-bucket boundary —
/// the one instant where two clock reads disagree — and the whole unit is run from it: the
/// entry the in-flight table takes, the epoch the charges land in, and the row the flush
/// writes. Every figure is then looked for in the bucket the unit arrived in, and the next
/// bucket is checked to be empty, because a charge that leaked forward would have to land
/// somewhere and that is where it would land.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unit_arriving_at_a_window_boundary_bills_in_the_window_it_arrived_in() {
    use busbar_substrate::governance::metering_bucket;

    let rig = rig(Fixture::BufferedOk).await;
    // The last SECOND of the bucket BEFORE the one the node's own clock is in, and the last
    // MILLISECOND of that second. Before, so that a figure derived from a fresh clock read
    // instead of from this arrival lands somewhere visibly different — in the live bucket,
    // which is the one asserted empty below.
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

    let node = LlmNode::new();
    let arrival = WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: Fixture::BufferedOk.body(),
        path: None,
    };
    let resp = node
        .answer_arriving_at(arrival, None, NATIVE_SEATS, arrived)
        .await;
    // Drain the body: this plane's money lands when the tap fills, which is on the drain.
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

/// The unit-arrival epoch this proof pins, so the window a posting lands in is a fixed one.
const EPOCH: u64 = 1_700_000_000;

// -----------------------------------------------------------------------------------------
// The lookup at the door
// -----------------------------------------------------------------------------------------

/// A history of one entry per `(effective_from_ms, output rate)`, built OUTSIDE the process
/// holder so these proofs name their own instants instead of racing the wall clock.
///
/// The first entry is effective from zero for the same reason the holder's is: an instant before
/// the first entry is a hole and a hole is a refusal.
fn history_of(entries: &[(u64, f64)]) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_unit_cost::History::new();
    for (n, (from, output)) in entries.iter().enumerate() {
        let card = crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_substrate::billing::RawTierRates {
                    input: 0.0,
                    output: *output,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            0,
            true,
            crate::root::kernel::node_currency(),
        );
        history.append(busbar_unit_cost::CardEntryDraft {
            effective_from: if n == 0 { 0 } else { *from },
            effective_until: None,
            card,
            appended_at: *from,
            author: busbar_unit_cost::Author::Config {
                policy_epoch: n as u64,
            },
        });
    }
    crate::root::kernel::PinnedHistory::for_test(
        std::sync::Arc::new(history),
        busbar_unit_cost::HistorySeq((entries.len() - 1) as u64),
    )
}

/// A report of `output` tokens on the lane the histories above price.
fn report_of(output: u64) -> LateReport {
    LateReport {
        usage: busbar_substrate::billing::Usage {
            usage_units: std::collections::BTreeMap::from([(
                busbar_contract::store::UNIT_OUTPUT.to_string(),
                output,
            )]),
        },
        fee_count: 0,
        lane: "lane".to_string(),
        provider: "provider".to_string(),
    }
}

/// **THE UNIT PRICES AT THE INSTANT IT ARRIVED**, not at the instant the question is asked.
///
/// Two units, one snapshot, one call each: the one that arrived before the second entry took
/// effect prices at the first entry's rate and the one that arrived after prices at the
/// second's. Both readings are taken from the SAME history at the SAME moment, so the only thing
/// that can be producing two answers is the arrival instant — which is the whole of rule 3.
///
/// A node that priced against "the current card" answers the later figure for both, which is
/// exactly the recorded 1.5.5 behaviour and exactly what this replaces.
#[test]
fn a_unit_prices_at_the_entry_in_force_when_it_arrived_and_not_at_the_head() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0), (5_000, 100.0)]);

    let early = priced_amount(&history, Arrived::at(4_999, 1), &token, &report_of(1_000));
    let late = priced_amount(&history, Arrived::at(5_000, 2), &token, &report_of(1_000));

    assert_eq!(
        early, 1_000_000,
        "a unit that arrived before the appended entry was re-priced at it"
    );
    assert_eq!(
        late, 100_000_000,
        "a unit that arrived after the appended entry was priced at the entry it superseded"
    );
}

/// **THE PIN HOLDS.** A snapshot taken at admission cannot see an entry appended after it, so an
/// apply landing mid-body does not reprice a request halfway through.
///
/// The pinned reader and the head are both asked about the SAME instant, and they answer
/// differently — which is only possible because the pin stops the snapshot's slice short of the
/// later entry. A holder that handed out the whole history and a live head would answer the new
/// figure to a request that was admitted under the old one.
#[test]
fn a_snapshot_pinned_at_admission_cannot_see_an_entry_appended_behind_it() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let token = kernel.usage_token();
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_substrate::billing::RawTierRates {
                    input: 0.0,
                    output: 1.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            0,
            true,
            crate::root::kernel::node_currency(),
        ),
        1_000,
    );
    let admitted = holder
        .pin()
        .expect("the boot resolution put an entry in place");

    // The apply that lands while the body is still draining.
    holder.apply(
        crate::root::kernel::card_from_config(
            [(
                "lane",
                busbar_substrate::billing::RawTierRates {
                    input: 0.0,
                    output: 100.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            0,
            true,
            crate::root::kernel::node_currency(),
        ),
        2_000,
    );
    let next = holder.pin().expect("the apply put a second entry in place");

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&admitted, at, &token, &report_of(1_000)),
        1_000_000,
        "the pinned snapshot saw an entry appended after the unit was admitted"
    );
    assert_eq!(
        priced_amount(&next, at, &token, &report_of(1_000)),
        100_000_000,
        "the next admission did not see the appended entry"
    );
}

/// **THE PIN IS A SEQ, NOT ONLY AN `Arc`.** A reader holding the same history at a lower
/// snapshot reads it as it stood at that snapshot.
///
/// The `Arc` alone is not the pin: an amendment, and a copy-on-write apply that a second reader
/// already took, both leave one history holding entries a reader was never admitted under. The
/// seq is what stops the slice short of them, and this asks the SAME history at two snapshots to
/// prove the stopping is real rather than an accident of when the `Arc` was cloned.
#[test]
fn a_pin_below_the_head_reads_the_history_as_it_stood_at_that_seq() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let token = kernel.usage_token();
    let head = history_of(&[(0, 1.0), (5_000, 100.0)]);
    let earlier =
        crate::root::kernel::PinnedHistory::for_test_at(&head, busbar_unit_cost::HistorySeq(0));

    let at = Arrived::at(9_000, 1);
    assert_eq!(
        priced_amount(&earlier, at, &token, &report_of(1_000)),
        1_000_000,
        "a snapshot at seq 0 resolved an entry that was appended after it"
    );
    assert_eq!(
        priced_amount(&head, at, &token, &report_of(1_000)),
        100_000_000,
        "the head snapshot did not resolve the entry appended onto it"
    );
}

/// **THE CACHE IS WRITTEN AND IS NEVER AUTHORITATIVE.**
///
/// The posting the pricing builds carries a cache — the head it settled at, the entry it
/// resolved to, the currency and both figures — so a reader has something to compare a
/// re-derivation against. Corrupt every one of those figures and ask again: the answer is
/// unchanged, because the lookup does not read them. A node that fell back to the cache would
/// answer the corrupted number and call it money.
#[test]
fn the_cached_price_rides_the_posting_and_is_never_read_back_for_money() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let token = kernel.usage_token();
    let history = history_of(&[(0, 1.0)]);
    let at = Arrived::at(4_000, 7);

    let (mut posting, priced) = priced_posting(&history, at, &token, &report_of(1_000));
    let priced = priced.expect("a card in force at the instant prices the report");
    let cached = posting
        .cached
        .expect("the pricing left its cache on the posting");
    assert_eq!(cached.priced_nanos, priced.priced_nanos);
    assert_eq!(cached.card_seq, priced.card_seq);
    assert_eq!(cached.history_seq, history.seq());
    assert_eq!(cached.currency, crate::root::kernel::node_currency());
    assert_eq!(
        posting.arrived_ms, 4_000,
        "the posting kept its own instant"
    );
    assert_eq!(posting.arrived_mono, 7);

    // The tamper. Every figure a reader could be tempted to trust, made a lie.
    posting.cached = Some(busbar_unit_cost::CachedPrice {
        history_seq: busbar_unit_cost::HistorySeq(u64::MAX),
        card_seq: busbar_unit_cost::HistorySeq(u64::MAX),
        currency: crate::root::kernel::node_currency(),
        pre_tier_nanos: 1,
        priced_nanos: 1,
    });
    assert_eq!(
        posting
            .priced_nanos(&history.view(), crate::root::kernel::node_currency())
            .expect("the lookup still answers"),
        priced.priced_nanos,
        "the money moved when the cache was corrupted, so the cache was on the money path"
    );
    assert!(
        posting.cache_diverges(&priced),
        "a corrupted cache went unnoticed"
    );
}

/// **THE EXIT ARM, END TO END.** The reservation the door opened reaches the journal.
///
/// The loop's exit path is where a hold stops existing, and what it hands back is a POSTING that
/// has moved no balance and left no record until something settles it. Before this arm was bound
/// nothing on this plane did, so a unit ran, ended, posted — and posted into a value that was
/// dropped. This drives the REAL loop over the real steps, takes the end it sealed, and puts the
/// posting on a journal it then reads back.
///
/// The figures are this plane's own: the door opens the kernel's hold at zero, because the spend
/// is the governance ledger's and the walk's tap already moved it. So what this proves is not a
/// price — it is that the kernel's record of a unit having run reaches a durable record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_exit_arm_puts_the_loops_posting_on_the_journal() {
    let rig = rig(Fixture::BufferedOk).await;
    let node = LlmNode::new();
    let ended = drive_to_end(&rig, &node, Fixture::BufferedOk, rig.gov(), NATIVE_SEATS).await;
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

    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let mut durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let who = PrincipalId::new("acct:llm");
    let settled = settle(
        &mut durability,
        &who,
        Arrived::at(EPOCH * 1_000, 0),
        &busbar_caps::DurabilityToken::mint(&seal),
        posted,
    )
    .expect("the memory-buffered journal takes it");
    assert!(settled.overdraft.is_none(), "nothing to carry out");

    let window =
        busbar_unit_admission::budget_window(busbar_unit_admission::window::WINDOW_DAY, EPOCH);
    let figures = durability.ledger.book().get(&balance(&who), window);
    assert_eq!(figures.overdraft_carried_out, 0);
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 1, "one posting, one record");
}

/// THE FLAT FEE IS A CLIENT'S FEE, and this plane reads which it has off the sealed origin.
///
/// One unit, driven once and then asked the same question under two origins. The delivered
/// answer, the selected upstream and the relayed first frame are identical in both readings —
/// the ONLY thing that differs is the origin the kernel sealed the unit under — so a difference
/// in the count is a difference the origin made and nothing else. A client's request pays one
/// fee; a unit the node ran for a provider pays none, which is the same answer the sibling plane
/// gives to the same question.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_origin_unit_posts_no_flat_fee() {
    let rig = rig(Fixture::BufferedOk).await;
    let node = LlmNode::new();
    let (unit, _ended) =
        drive_keeping_the_unit(&rig, &node, Fixture::BufferedOk, rig.gov(), NATIVE_SEATS).await;
    rig.server.shutdown().await;

    let fee = |origin| {
        let ctx = UnitCtx {
            key: UnitKey::new(1),
            origin,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        busbar_kernel::teller::fee_count(&unit.evidence(&ctx).fee).0
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

/// One request, driven through the real loop, answering with the END rather than the bytes.
///
/// The same drive [`LlmNode::answer`] performs — the same table, the same slot, the same
/// `run_unit_async` — kept apart only because the entry point answers a client and this answers
/// the exit arm's proof.
///
/// `gov` is the caller's own resolved context rather than the rig's, because what the
/// authenticate step ANSWERS is only visible on this side of the loop: the hold the door opens
/// is opened for the principal that step settled on, and the posting the exit hands back names
/// it. A drive that always used the rig's key could not tell the step's answer from the walk's.
async fn drive_to_end<'n>(
    rig: &Rig,
    node: &'n LlmNode,
    fixture: Fixture,
    gov: busbar_contract::store::PlaneRequestCtx,
    seats: &'n [&'n (dyn approve::VetoSeat + Sync)],
) -> Ended {
    drive_keeping_the_unit(rig, node, fixture, gov, seats)
        .await
        .1
}

/// The same drive, handing the UNIT back beside the end it sealed.
///
/// A unit's evidence is a reading OF the unit, so a test that asks what this plane would settle
/// has to hold the thing that ran rather than a copy of its answer. Everything below is the
/// drive above; the only difference is what is returned.
async fn drive_keeping_the_unit<'n>(
    rig: &Rig,
    node: &'n LlmNode,
    fixture: Fixture,
    gov: busbar_contract::store::PlaneRequestCtx,
    seats: &'n [&'n (dyn approve::VetoSeat + Sync)],
) -> (LlmUnit<'n>, Ended) {
    let arrival = WalkArrival {
        host: rig.host(),
        gov,
        proto: PROTO,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: fixture.body(),
        path: None,
    };
    let key = UnitKey::new(node.next_key.fetch_add(1, Ordering::Relaxed));
    let principal = authenticate::principal_id(&arrival.gov);
    let meter = Arc::new(AccrualMeter::new());
    let unit = LlmUnit {
        node,
        seats,
        meter: Arc::clone(&meter),
        op_class: OpClassId::new(arrival.operation.name()),
        model_hint: None,
        started: Instant::now(),
        charged_at: EPOCH,
        history: crate::root::kernel::ROOT_CARD.pin(),
        arrived: Arrived::at(EPOCH * 1_000, 0),
        deferred: Mutex::new(None),
        model: Mutex::new(String::new()),
        walk: Walk::open(arrival),
    };
    let hold = busbar_kernel::inflight::arrival_hold(&node.kernel, &node.door, principal);
    let slot = node
        .inflight
        .insert(busbar_kernel::inflight::Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: hold,
            now: busbar_substrate::store::now_ms(),
        })
        .expect("the uncapped table takes the unit");
    let ctx = UnitCtx {
        key,
        origin: OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let ended = busbar_kernel::teller::run_unit_async(
        &node.kernel,
        &unit,
        &ctx,
        busbar_kernel::teller::Run {
            cell: slot.cell(),
            parent: None,
            leases: slot.leases(),
            gauge: &node.gauge,
            canary: &node.canary,
            meter: &meter,
        },
        &unit,
    )
    .await;
    node.inflight.remove(key);
    (unit, ended)
}

/// THE SWITCH. Same fixture in, same bytes and same counters out — through the shipped entry
/// point and through the kernel's loop over the step files.
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

/// The ENDS are what the fixtures claim they are. Without this the comparison above could be
/// green on six identical 404s and prove nothing about the loop at all.
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

/// THE MONEY, spelled out rather than only compared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_leaves_the_money_where_the_shipped_plane_leaves_it() {
    // A STREAMED unit accrues at stream end rather than at the buffered tap, so it is asserted
    // in its own right: without this the comparison could be green on a stream metering nothing.
    let streamed = leg_loop(Fixture::StreamedOk).await;
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

    let delivered = leg_loop(Fixture::BufferedOk).await;
    assert_eq!(field(&delivered, "ledger_requests"), "1");
    assert_eq!(
        field(&delivered, "metering_rows"),
        format!("{LANE}/test in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1")
    );

    // The door refused: nothing was charged, so there is nothing on the key's bucket at all.
    let refused = leg_loop(Fixture::OverBudget).await;
    assert_eq!(field(&refused, "ledger_requests"), "0");
    assert_eq!(field(&refused, "metering_rows"), "");

    // The pre-admission guard refused: charged nothing either, and never reached the door.
    let guarded = leg_loop(Fixture::PoolAcl).await;
    assert_eq!(field(&guarded, "ledger_requests"), "0");

    // Refused after the door: the admission slot is drawn and NEVER released, which is the rule
    // that makes a request cap impossible to escape by failing.
    let post_door = leg_loop(Fixture::UnknownModel).await;
    assert_eq!(field(&post_door, "ledger_requests"), "1");
    assert_eq!(field(&post_door, "metering_rows"), "");
}

/// EXACTLY ONE LINK PER UNIT on the principal's chain, whichever door the unit left through.
///
/// The rule the switch could most easily break: the shipped door POSTS its own refusal, and the
/// step files' door does not — it renders, and the terminal posts. A unit that left through both
/// would carry two links and the chain would still verify, which is why the COUNT is asserted
/// rather than the verification alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_unit_leaves_exactly_one_link_on_the_chain() {
    use busbar_core::proxy::reqlog::REQUESTS;

    for fixture in [
        Fixture::BufferedOk,
        Fixture::OverBudget,
        Fixture::PoolAcl,
        Fixture::UnknownModel,
    ] {
        // LEG 1 — the shipped entry point names a destination on its link; whatever it names is
        // what the loop's link has to name too, so the expectation is READ rather than spelled.
        let shipped_rig = rig(fixture).await;
        let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
            host: shipped_rig.host(),
            gov: shipped_rig.gov(),
            caller_token: None,
        });
        let resp = busbar_llm::native_ingress::operation_ingress(
            &ctx,
            json_headers(),
            fixture.body(),
            PROTO,
            busbar_api::operation::Operation::CHAT,
            None,
        )
        .await;
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
        let shipped = REQUESTS.records_for(&shipped_rig.key.id);
        assert_eq!(shipped.len(), 1, "{fixture:?}: the shipped path posts once");
        shipped_rig.server.shutdown().await;

        // LEG 2 — the loop, on its own deployment.
        let rig = rig(fixture).await;
        let resp = drive(&rig, fixture).await;
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
        let records = REQUESTS.records_for(&rig.key.id);
        assert_eq!(records.len(), 1, "{fixture:?}: one unit, one link");
        assert_eq!(
            (
                records[0].pool.clone(),
                records[0].outcome.clone(),
                records[0].reason.clone(),
                records[0].status
            ),
            (
                shipped[0].pool.clone(),
                shipped[0].outcome.clone(),
                shipped[0].reason.clone(),
                shipped[0].status
            ),
            "{fixture:?}: the loop's link is the shipped path's link"
        );
        assert!(REQUESTS.verify_principal_chain(&rig.key.id).is_ok());
        rig.server.shutdown().await;
    }
}

// ── THE TWO SURFACES WHOSE MODEL IS IN THE URL ─────────────────────────────────────────────

/// The two dialects that keep their model in the path.
const GEMINI: &str = busbar_llm::proto_codec::PROTO_GEMINI;
const BEDROCK: &str = busbar_llm::proto_codec::PROTO_BEDROCK;

/// The four ends a URL-model fixture reaches. Malformed and the pool ACL are the body surface's
/// fixtures and are exercised there; what these four pin is the surface that was OFF the loop —
/// a delivered answer, a streamed one, a name that resolves to nothing, and a spent budget.
const PATH_CASES: [Fixture; 4] = [
    Fixture::BufferedOk,
    Fixture::StreamedOk,
    Fixture::UnknownModel,
    Fixture::OverBudget,
];

/// THE NATIVE REQUEST BODY each dialect's client sends. The model is NOT in it — that is the whole
/// point of the surface — so one body per dialect serves every fixture.
fn path_body(proto: &str) -> Bytes {
    let v = if proto == GEMINI {
        serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
    } else {
        serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
    };
    Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
}

/// The URL's facts, as the carry names them.
type PathFacts = busbar_llm::arrival::PathModelFacts;

/// WHAT THE URL SAYS, for the URL each fixture is sent to.
///
/// Spelled here rather than parsed, because the parse is the DIALECT'S and is pinned beside it —
/// `busbar_llm`'s own tests drive the real `gemini_path_parse` / `bedrock_path_parse` over these
/// exact URLs and assert these exact facts. What this file is responsible for is what the loop
/// does with them.
fn path_facts(proto: &'static str, fixture: Fixture) -> PathFacts {
    let model = fixture.model().to_string();
    let stream = fixture.streamed();
    PathFacts {
        operation: busbar_api::operation::Operation::CHAT,
        stream,
        // `/v1beta/models/{model}:streamGenerateContent` with no `?alt=sse` is the JSON-array
        // framing; bedrock has no such framing at all.
        gemini_json_array: proto == GEMINI && stream,
        // The gemini surface echoes its own versioned not-found copy; bedrock uses the neutral
        // sentence. The api version is the one the fixture's `/v1beta/...` URL carries.
        model_not_found_message: (proto == GEMINI).then(|| {
            format!(
                "models/{model} is not found for API version v1beta, \
                 or is not supported for the task you are trying to perform."
            )
        }),
        model,
    }
}

/// LEG 1 — the shipped path-model entry point, on its own deployment.
async fn leg_legacy_path(fixture: Fixture, proto: &'static str) -> Observed {
    let rig = rig(fixture).await;
    let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let facts = path_facts(proto, fixture);
    let resp = busbar_llm::native_ingress::ingress_path_model(
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

/// LEG 2 — the same request through the kernel's loop, with the URL's facts in the unit's carry.
async fn leg_loop_path(fixture: Fixture, proto: &'static str) -> Observed {
    let rig = rig(fixture).await;
    let node = LlmNode::new();
    let facts = path_facts(proto, fixture);
    let arrival = WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto,
        operation: facts.operation,
        caller_token: None,
        headers: json_headers(),
        body: path_body(proto),
        path: Some(facts),
    };
    let resp = node.answer(arrival, None).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

/// THE SWITCH, ON THE URL-MODEL SURFACES. Same request in, same bytes and same counters out —
/// through the shipped path-model entry point and through the kernel's loop over the step files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_matches_the_shipped_path_model_entry_point() {
    let mut failures: Vec<String> = Vec::new();
    for proto in [GEMINI, BEDROCK] {
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

/// The ENDS are what these fixtures claim they are. Without this the comparison above could be
/// green on eight identical 404s and prove nothing about the surface at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_url_model_fixture_reaches_the_end_it_names() {
    let mut seen: Vec<(&str, Fixture, String)> = Vec::new();
    for proto in [GEMINI, BEDROCK] {
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
    let want: Vec<(&str, Fixture, String)> = [GEMINI, BEDROCK]
        .into_iter()
        .flat_map(|proto| {
            [
                (proto, Fixture::BufferedOk, "200".to_string()),
                (proto, Fixture::StreamedOk, "200".to_string()),
                // Refused AFTER the door, so it is charged and audited as an admitted unit.
                (proto, Fixture::UnknownModel, "404".to_string()),
                // The door's own turn-away, in each dialect's own status vocabulary: gemini
                // answers a throttle as a throttle, bedrock's envelope carries it as a client
                // error. Both are the shipped entry point's answer, read off it rather than
                // assumed — the leg above proves the two legs agree.
                (
                    proto,
                    Fixture::OverBudget,
                    if proto == BEDROCK { "400" } else { "429" }.to_string(),
                ),
            ]
        })
        .collect();
    assert_eq!(
        seen, want,
        "the url-model fixtures do not reach the ends they are named for"
    );
}

/// A URL THAT NAMED NO MODEL ENDS WHERE THE SHIPPED ENTRY POINT ENDS IT.
///
/// The empty URL model is REACHABLE: bedrock's own path parse ends `unwrap_or_default()`, so a
/// converse path whose model segment the handler did not recognise arrives as a `PathModelFacts`
/// carrying an empty string. The shipped path-model entry point has no empty-model rung at all —
/// it injects whatever the URL gave into the body and lets resolution answer, which for an empty
/// name is the ordinary model-miss 404, taken after the door and therefore charged.
///
/// That is the answer the loop has to give too, and it is the whole reason this case is pinned:
/// the body-model entry point DOES carry an empty-model rung (`Some(m) if !m.is_empty()` → a
/// 400 "Missing required parameter"), and a step file that copies that rung onto the URL surface
/// turns one dialect's unrecognised path segment from a charged 404 into an uncharged 400. Two
/// different statuses, two different ledgers, on a request the shipped node answers one way.
///
/// Compared field for field against the shipped entry point rather than asserted as a number, so
/// the body, the headers and the money all have to agree and not merely the status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_url_model_ends_where_the_shipped_path_model_entry_point_ends_it() {
    /// The fixture's facts with the model taken out — the shape bedrock's parse produces for a
    /// path whose model segment resolved to nothing.
    fn nameless(proto: &'static str) -> PathFacts {
        let mut facts = path_facts(proto, Fixture::UnknownModel);
        facts.model = String::new();
        facts.model_not_found_message = (proto == GEMINI).then(|| {
            "models/ is not found for API version v1beta, or is not supported for the task \
             you are trying to perform."
                .to_string()
        });
        facts
    }

    let mut failures: Vec<String> = Vec::new();
    for proto in [GEMINI, BEDROCK] {
        let shipped = {
            let rig = rig(Fixture::UnknownModel).await;
            let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
                host: rig.host(),
                gov: rig.gov(),
                caller_token: None,
            });
            let facts = nameless(proto);
            let resp = busbar_llm::native_ingress::ingress_path_model(
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
            let node = LlmNode::new();
            let arrival = WalkArrival {
                host: rig.host(),
                gov: rig.gov(),
                proto,
                operation: busbar_api::operation::Operation::CHAT,
                caller_token: None,
                headers: json_headers(),
                body: path_body(proto),
                path: Some(nameless(proto)),
            };
            let resp = node.answer(arrival, None).await;
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

/// THE PATH TABLE IS THE PLANE'S PATH TABLE. Same dialects, same names, same order — the
/// path-axis twin of the body-table comparison below, and for the same reason: a dialect missing
/// from the replacement resolves no arrival and the surface 404s, which is a deletion wearing a
/// routing bug's clothes.
#[test]
fn the_switched_path_table_names_every_dialect_the_plane_names() {
    let shipped: Vec<&str> = busbar_llm::PATH_INGRESS.iter().map(|(n, _)| *n).collect();
    let switched: Vec<&str> = PATH_INGRESS.iter().map(|(n, _)| *n).collect();
    assert_eq!(switched, shipped);
}

/// THE URL'S FACTS ARE ONE UNIT'S, and they are the unit's for the whole of it.
///
/// They used to be pinned to the thread the loop ran on, which was sound only while the loop
/// occupied one blocking worker end to end. It does not any more: a unit yields at its Route step
/// and may be resumed on another thread, and the step that reads the dialect's miss copy is on
/// the far side of that yield. So they ride the carry, and this says what the carry answers on
/// each of the two shapes — the fact a body-model unit has none is half the seam.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_url_facts_ride_the_unit_and_not_the_thread() {
    let rig = rig(Fixture::BufferedOk).await;
    let facts = path_facts(GEMINI, Fixture::BufferedOk);
    let base = |path| WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: GEMINI,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: path_body(GEMINI),
        path,
    };
    let carried = Walk::open(base(Some(facts)));
    assert_eq!(
        carried.with_path(|f| f.model.clone()).as_deref(),
        Some(POOL),
        "a path-model unit reads what its own URL said"
    );
    assert!(
        carried
            .with_path(|f| f.model_not_found_message.clone())
            .flatten()
            .is_some(),
        "and the dialect's own miss copy is one of the facts it carries"
    );
    assert!(
        Walk::open(base(None)).with_path(|_| ()).is_none(),
        "a body-model unit carries no URL fact at all"
    );
    rig.server.shutdown().await;
}

/// THE TABLE IS THE PLANE'S TABLE. Same dialects, same names, same order.
///
/// The switch replaces one arrival table with another, and a dialect missing from the
/// replacement does not fail loudly — it resolves no arrival and the surface 404s, which is a
/// deletion wearing a routing bug's clothes. So the two tables are compared as data.
#[test]
fn the_switched_table_names_every_dialect_the_plane_names() {
    let shipped: Vec<&str> = busbar_llm::BODY_INGRESS.iter().map(|(n, _)| *n).collect();
    let switched: Vec<&str> = BODY_INGRESS.iter().map(|(n, _)| *n).collect();
    assert_eq!(switched, shipped);
}

/// THE INTERNER IS THE NODE'S, and it is idempotent.
///
/// A lane name is leaked to become the borrowed static one the priced axis is written in, so
/// interning the same name twice must yield the same pointer: a leak per request would be a
/// leak per request whatever it was called.
#[test]
fn the_nodes_interner_leaks_a_lane_name_once() {
    let node = LlmNode::new();
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

/// AND THE INTERNER IS REACHED ONCE PER NAME, not once per request.
///
/// The interner is one mutex for the whole image, and the Verify step resolves a name per
/// candidate lane, per request — so a node that asks it every time makes every plane in the
/// process queue behind one lock for an answer that was settled the first time. The count is
/// per distinct name and does not grow with how often the name is asked for.
#[test]
fn a_lane_name_reaches_the_interner_once_however_often_it_is_resolved() {
    let node = LlmNode::new();
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

// ── STEP 1, DECODE — the six dialects, over the loop ────────────────────────────────────────

/// The six dialects whose model rides the body. The same six the mount installs, read off the
/// table rather than retyped, so a dialect added to one and not the other cannot pass here.
fn body_dialects() -> Vec<&'static str> {
    BODY_INGRESS.iter().map(|(name, _)| *name).collect()
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

/// THE NATIVE REQUEST BODY, per dialect. Each is the shape that dialect's own client sends, and
/// the `model` member is the rung of the ladder a body-model surface resolves on.
fn dialect_body(proto: &str, shape: Decoded) -> Bytes {
    if shape == Decoded::Malformed {
        return Bytes::from_static(b"{not json");
    }
    let mut v = if proto == busbar_llm::proto_codec::PROTO_ANTHROPIC {
        serde_json::json!({"max_tokens": 16,
                           "messages": [{"role": "user", "content": "hi"}]})
    } else if proto == GEMINI {
        serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
    } else if proto == BEDROCK {
        serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
    } else if proto == busbar_llm::proto_codec::PROTO_RESPONSES {
        serde_json::json!({"input": "hi"})
    } else if proto == busbar_llm::proto_codec::PROTO_COHERE {
        serde_json::json!({"message": "hi"})
    } else {
        serde_json::json!({"messages": [{"role": "user", "content": "hi"}]})
    };
    // The ladder's rung 3 — and its absence, which is the whole of the `NoModel` shape.
    if shape != Decoded::NoModel {
        v["model"] = serde_json::Value::String(POOL.to_string());
    }
    Bytes::from(serde_json::to_vec(&v).expect("the fixture body serializes"))
}

/// A VERB THIS DIALECT DECLARES NO HANDLER FOR, found by ASKING the registry rather than by
/// guessing: the first of the family's seven the dialect does not answer. `None` for a dialect
/// that answers all seven, which is a dialect this shape has nothing to say about.
fn unsupported_verb(proto: &str) -> Option<busbar_api::operation::Operation> {
    [
        busbar_api::operation::Operation::EMBEDDINGS,
        busbar_api::operation::Operation::MODERATION,
        busbar_api::operation::Operation::IMAGE,
        busbar_api::operation::Operation::TRANSCRIPTION,
        busbar_api::operation::Operation::SPEECH,
        busbar_api::operation::Operation::RERANK,
    ]
    .into_iter()
    .find(|op| decode::handler_for(proto, *op).is_err())
}

/// LEG 1 — the shipped body-model entry point, for any dialect and any verb.
async fn leg_legacy_decode(
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    body: Bytes,
) -> Observed {
    let rig = rig(Fixture::BufferedOk).await;
    let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov: rig.gov(),
        caller_token: None,
    });
    let resp = busbar_llm::native_ingress::operation_ingress(
        &ctx,
        json_headers(),
        body,
        proto,
        operation,
        None,
    )
    .await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

/// LEG 2 — the same dialect and the same verb through the kernel's loop.
async fn leg_loop_decode(
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    body: Bytes,
) -> Observed {
    let rig = rig(Fixture::BufferedOk).await;
    let node = LlmNode::new();
    let arrival = WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto,
        operation,
        caller_token: None,
        headers: json_headers(),
        body,
        path: None,
    };
    let resp = node.answer(arrival, None).await;
    let observed = observe(&rig, resp).await;
    rig.server.shutdown().await;
    observed
}

/// **STEP 1 OVER THE LOOP, ON EVERY DIALECT THE PLANE MOUNTS.**
///
/// The decode step answers two questions — which handler owns this `(protocol, operation)` pair,
/// and which model the caller named — and every later step is about those two answers. So the
/// step is driven through `run_unit` for each of the six body-model dialects in four shapes, and
/// each is compared against the shipped entry point on its own deployment: the answer, the
/// headers, the money and the breaker.
///
/// The ends are asserted BESIDE the comparison, not instead of it, because six identical 404s
/// would compare equal and prove nothing about resolution at all:
///
/// * `Named` reaches the door, which is the observable fact that a model WAS resolved;
/// * `NoModel` is the ladder's own refusal, in the dialect's envelope, charged to nobody;
/// * `Malformed` is refused at step 0 — the plane parses before it reads the ladder;
/// * `UnsupportedVerb` is the handler half, refused with the endpoint's own sentence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_decodes_every_dialect_the_way_the_shipped_plane_decodes_it() {
    let mut failures: Vec<String> = Vec::new();
    let mut verbs_exercised = 0usize;
    for proto in body_dialects() {
        for shape in [Decoded::Named, Decoded::NoModel, Decoded::Malformed] {
            let label = format!("{proto}/{shape:?}");
            let body = dialect_body(proto, shape);
            let op = busbar_api::operation::Operation::CHAT;
            let legacy = leg_legacy_decode(proto, op, body.clone()).await;
            let looped = leg_loop_decode(proto, op, body).await;
            compare(&label, &legacy, &looped, &mut failures);

            let status = field(&looped, "status");
            let answered = field(&looped, "body");
            let admitted = field(&looped, "ledger_requests");
            match shape {
                // The model resolved, so the unit reached the door and drew its slot. A dialect
                // whose ladder answered nothing would be refused BEFORE the door and read "0".
                Decoded::Named => {
                    if admitted != "1" {
                        failures.push(format!(
                            "{label}: the resolved model never reached the door \
                             (ledger_requests={admitted})"
                        ));
                    }
                }
                Decoded::NoModel => {
                    if status != "400"
                        || !answered.contains(decode::DecodeRefusal::MissingModel.message())
                    {
                        failures.push(format!(
                            "{label}: the ladder's own refusal is not what the client read \
                             (status={status}) {answered}"
                        ));
                    }
                    if admitted != "0" {
                        failures.push(format!("{label}: a refused unit was charged"));
                    }
                }
                // Step 0's parse refusal: the bytes are not a document, so there is nothing for
                // the ladder to read and the unit never reaches step 1 at all.
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
        // THE HANDLER HALF. A verb the dialect declares nothing for, asked of the registry
        // rather than guessed — and skipped for a dialect that answers the whole family, which
        // is an honest absence rather than a fabricated 404.
        if let Some(op) = unsupported_verb(proto) {
            verbs_exercised += 1;
            let label = format!("{proto}/UnsupportedVerb");
            let body = dialect_body(proto, Decoded::Named);
            let legacy = leg_legacy_decode(proto, op, body.clone()).await;
            let looped = leg_loop_decode(proto, op, body).await;
            compare(&label, &legacy, &looped, &mut failures);
            let status = field(&looped, "status");
            let answered = field(&looped, "body");
            if status != "404"
                || !answered.contains(decode::DecodeRefusal::UnsupportedOperation.message())
            {
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

// ── STEP 2, AUTHENTICATE — the three credentials, over the loop ─────────────────────────────

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

/// THE DOOR, asked exactly as a transport asks it: the deployment's configured auth chain plus
/// the one verdict resolution the HTTP middleware runs, over this rig's live governance state.
/// No audience is expected, because the data-plane boundary expects none.
async fn admit(
    rig: &Rig,
    cred: Credential,
) -> Result<busbar_contract::store::PlaneRequestCtx, String> {
    rig.host()
        .identity_admit(Some(cred.present(rig)), String::new(), String::new())
        .await
        .map(|(_, gov)| gov)
        .map_err(|refusal| format!("{refusal:?}"))
}

/// WHO THE LOOP DECIDED THIS UNIT IS, taken from the far end of the loop rather than from the
/// fixture: the door opens the kernel's hold for the principal the AUTHENTICATE step settled
/// on, and the posting the exit path hands back carries it. Nothing else on this plane reads
/// that answer — the walk keeps its own context for the money and the record — so this is the
/// one observation that is about step 2 and about nothing else.
async fn principal_the_loop_settled_on(
    rig: &Rig,
    gov: busbar_contract::store::PlaneRequestCtx,
) -> String {
    let node = LlmNode::new();
    let ended = drive_to_end(rig, &node, Fixture::BufferedOk, gov, NATIVE_SEATS).await;
    let Ended::Settled { end, .. } = ended else {
        panic!("the exit path settles a delivered unit");
    };
    end.into_posted()
        .expect("the usage report fits the record")
        .principal()
        .as_str()
        .to_string()
}

/// LEG 1 — the shipped entry point, driven with a context the DOOR produced.
async fn leg_legacy_as(rig: &Rig, gov: busbar_contract::store::PlaneRequestCtx) -> Observed {
    let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(ArrivalPayload {
        host: rig.host(),
        gov,
        caller_token: None,
    });
    let resp = busbar_llm::native_ingress::operation_ingress(
        &ctx,
        json_headers(),
        Fixture::BufferedOk.body(),
        PROTO,
        busbar_api::operation::Operation::CHAT,
        None,
    )
    .await;
    observe(rig, resp).await
}

/// LEG 2 — the loop, driven with the same context the door produced.
async fn leg_loop_as(rig: &Rig, gov: busbar_contract::store::PlaneRequestCtx) -> Observed {
    let node = LlmNode::new();
    let arrival = WalkArrival {
        host: rig.host(),
        gov,
        proto: PROTO,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: Fixture::BufferedOk.body(),
        path: None,
    };
    let resp = node.answer(arrival, None).await;
    observe(rig, resp).await
}

/// **STEP 2 OVER THE LOOP: THE UNIT IS ATTRIBUTED TO WHAT THE DOOR RESOLVED, AND TO NOTHING
/// ELSE.**
///
/// The plane's authenticate step is a READ of an outcome the auth middleware already produced —
/// every 401 this plane could raise is raised upstream of it. A cell that hand-built a context
/// and handed it to the loop would prove nothing about that, because it would be asserting the
/// fixture. So every credential here goes through the deployment's OWN door
/// (`EngineHost::identity_admit`: the configured chain plus the one verdict resolution the HTTP
/// middleware runs) and the loop is driven with whatever the door left behind.
///
/// Three credentials, and the door's answer decides which half of the cell runs:
///
/// * the deployment's live bearer is ADMITTED, so both legs run with the resolved context and
///   are compared — and the unit's one link lands on that key's chain, which is the attribution
///   claim spelled as something a reader can see;
/// * a bearer this deployment never minted, and a bearer whose lifetime has run out, are both
///   REFUSED at the door, so neither leg is ever entered. The loop cannot be softer than the
///   shipped path here, because on both paths the plane is downstream of the same refusal; what
///   it could do wrong is invent an identity for the request that follows, so the shape the
///   middleware leaves when it binds no key is driven through both legs and must attribute the
///   anonymous actor — never the refused key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_attributes_the_identity_the_door_resolved_and_invents_none() {
    use busbar_core::proxy::reqlog::REQUESTS;

    let mut failures: Vec<String> = Vec::new();
    for cred in [Credential::Good, Credential::Bad, Credential::Expired] {
        // LEG 1, on its own deployment: its own door, its own key, its own counters.
        let legacy_rig = rig(Fixture::BufferedOk).await;
        let legacy_admit = admit(&legacy_rig, cred).await;
        // LEG 2, on another.
        let loop_rig = rig(Fixture::BufferedOk).await;
        let loop_admit = admit(&loop_rig, cred).await;

        // THE DOOR AGREES WITH ITSELF across the two deployments. A cell whose two rigs made
        // different admission decisions would compare two different requests.
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
                // THE RESOLVED KEY IS THE DEPLOYMENT'S KEY — the door read the bearer back to
                // the binding it was minted for, which is what makes the attribution below a
                // statement about a credential rather than about a struct literal.
                if loop_gov.key().map(|k| k.id.clone()).as_deref() != Some(loop_rig.key.id.as_str())
                {
                    failures.push(format!(
                        "{cred:?}: the door resolved a key that is not this deployment's"
                    ));
                }
                // THE STEP'S OWN ANSWER, read at the far end of the loop: the hold the door
                // opened names the principal step 2 settled on, and it is the resolved key. On
                // its OWN deployment, because a second drive would double the counters the
                // comparison below reads.
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
                // THE ATTRIBUTION, as an operator reads it: one link, on the resolved key's own
                // chain. A step that answered with any other principal would leave it elsewhere.
                let links = REQUESTS.records_for(&loop_rig.key.id);
                if links.len() != 1 {
                    failures.push(format!(
                        "{cred:?}: the loop left {} link(s) on the resolved key's chain",
                        links.len()
                    ));
                }
            }
            (Err(_), Err(_)) => {
                if cred == Credential::Good {
                    failures.push(format!(
                        "{cred:?}: the door refused the deployment's own bearer"
                    ));
                }
                // The door refused, so no unit exists on either leg. What the loop must not do
                // is invent one: driven with the context the middleware leaves when it binds no
                // key, both legs attribute the anonymous actor and leave the refused key's
                // chain empty.
                let open = busbar_contract::store::PlaneRequestCtx { key: None };
                let anonymous = busbar_api::AuthPrincipal(None).actor_id().to_string();
                if authenticate::principal_id(&open).as_str() != anonymous {
                    failures.push(format!(
                        "{cred:?}: an unbound request is not attributed to the anonymous actor"
                    ));
                }
                // And the loop SETTLES on that actor: the hold the door opened for this unit
                // names the anonymous caller, not the key whose bearer was just turned away.
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
                if !REQUESTS.records_for(&loop_rig.key.id).is_empty() {
                    failures.push(format!(
                        "{cred:?}: a refused credential's key carries a link it never earned"
                    ));
                }
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

// ── STEP 4, APPROVE — the native seat, over the loop ────────────────────────────────────────

/// A seated gate that stops every unit, and records that it was asked. The recording is what
/// makes "the loop consulted the seat" a fact rather than an inference from the refusal.
struct StopsEverything(std::sync::atomic::AtomicBool);
impl approve::VetoSeat for StopsEverything {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        self.0.store(true, Ordering::SeqCst);
        true
    }
}

/// A seated gate that stops nothing, and records that it was asked. Without this the pass-through
/// half of the cell would be satisfied by a seat list the loop never reached at all.
struct StopsNothing(std::sync::atomic::AtomicBool);
impl approve::VetoSeat for StopsNothing {
    fn vetoes(&self, _p: &PrincipalId, _d: &[VerifiedDestination]) -> bool {
        self.0.store(true, Ordering::SeqCst);
        false
    }
}

/// One request through the real loop with a named seat list, exactly as the mount drives it with
/// its own.
async fn leg_loop_seated(rig: &Rig, seats: &[&(dyn approve::VetoSeat + Sync)]) -> Observed {
    let node = LlmNode::new();
    let arrival = WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: Fixture::BufferedOk.body(),
        path: None,
    };
    let resp = node.answer_with(arrival, None, seats).await;
    observe(rig, resp).await
}

/// **STEP 4 OVER THE LOOP: THE NATIVE SEAT, BOTH WAYS.**
///
/// Approve is two halves and this plane's scope half has nothing to ask — its resource IS its
/// destination, and the destination set was sealed one step earlier. What is left is the hook
/// half, and the seat is the 1.6.0-native one: a gate that may stop a unit BEFORE the door and
/// may do nothing else.
///
/// The MIGRATED hooks are not seated here and this cell says so first: [`NATIVE_SEATS`] is the
/// list the mount installs, it is empty, and that emptiness is why a unit over the loop is
/// unit-for-unit what the shipped path answers. Seating the migrated hooks would move a veto
/// from after a charge to before one, which changes what is billed.
///
/// Then the three shapes, each on its own deployment:
///
/// * NOTHING SEATED — the shipped entry point's answer, field for field;
/// * A SEAT THAT DOES NOT VETO — the same answer again, and the seat records that it WAS asked,
///   so the pass-through above is a decision rather than an unwired field;
/// * A SEAT THAT VETOES — the unit stops at Approve: before the door, so nothing is charged and
///   no metering row exists; before the route step, so the upstream is never dialled; and it
///   still leaves through a terminal, with exactly one link on the principal's chain and the
///   plane's own permission answer in the caller's dialect rather than the node's overload one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seated_gate_stops_the_unit_before_the_door_and_an_empty_seat_list_changes_nothing() {
    use busbar_core::proxy::reqlog::REQUESTS;
    use std::sync::atomic::AtomicBool;

    assert!(
        NATIVE_SEATS.is_empty(),
        "the mount seats a native gate: the migrated hooks fire AFTER the door on the live \
         path, and a veto moved in front of a charge changes what is billed"
    );

    // THE SHIPPED ANSWER, on its own deployment — the expectation every seated run below is
    // read against, rather than a status spelled here.
    let shipped_rig = rig(Fixture::BufferedOk).await;
    let shipped = leg_legacy_as(&shipped_rig, shipped_rig.gov()).await;
    shipped_rig.server.shutdown().await;

    let mut failures: Vec<String> = Vec::new();

    // NOTHING SEATED: the mount's own list, which is the whole of today's behaviour.
    let bare_rig = rig(Fixture::BufferedOk).await;
    let bare = leg_loop_seated(&bare_rig, NATIVE_SEATS).await;
    compare("no seat", &shipped, &bare, &mut failures);
    bare_rig.server.shutdown().await;

    // A SEAT THAT DOES NOT VETO: consulted, and the unit goes on to the same end.
    let passing = StopsNothing(AtomicBool::new(false));
    let passing_rig = rig(Fixture::BufferedOk).await;
    let passed = leg_loop_seated(&passing_rig, &[&passing]).await;
    compare(
        "a seat that does not veto",
        &shipped,
        &passed,
        &mut failures,
    );
    if !passing.0.load(Ordering::SeqCst) {
        failures.push(
            "the loop never consulted the seated gate, so the pass-through above is an \
             unwired field rather than a decision"
                .to_string(),
        );
    }
    passing_rig.server.shutdown().await;

    // A SEAT THAT VETOES: the unit stops at Approve.
    let stopping = StopsEverything(AtomicBool::new(false));
    let veto_rig = rig(Fixture::BufferedOk).await;
    let stopped = leg_loop_seated(&veto_rig, &[&stopping]).await;
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
    // BEFORE THE DOOR. Nothing charged, nothing metered — which is the whole reason the seat is
    // at this step and not the next one.
    if field(&stopped, "ledger_requests") != "0" || !field(&stopped, "metering_rows").is_empty() {
        failures.push(format!(
            "a veto was charged: requests={} rows={}",
            field(&stopped, "ledger_requests"),
            field(&stopped, "metering_rows")
        ));
    }
    // BEFORE THE ROUTE STEP. The scripted upstream saw nothing at all.
    if veto_rig.upstream.get_last_request_path().is_some() {
        failures.push("a vetoed unit reached the upstream".to_string());
    }
    // AND IT STILL ENDS AT A TERMINAL: one link, never none and never two.
    let links = REQUESTS.records_for(&veto_rig.key.id);
    if links.len() != 1 {
        failures.push(format!(
            "a vetoed unit left {} link(s) on the chain",
            links.len()
        ));
    }
    assert!(
        REQUESTS.verify_principal_chain(&veto_rig.key.id).is_ok(),
        "the chain a vetoed unit left does not verify"
    );
    veto_rig.server.shutdown().await;

    assert!(
        failures.is_empty(),
        "{} finding(s) at the approve seat:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------------------------
// THE ROUTE SEAM'S OWN INSTRUMENT
// ---------------------------------------------------------------------------------------------

/// One request through the real loop, with the node's dispatch count read beside its answer.
///
/// A NODE PER REQUEST, exactly as [`drive`] builds one, so the figure is this unit's and not a
/// running total the order of the tests could change.
async fn drive_counting(rig: &Rig, fixture: Fixture) -> (Response, Option<u64>) {
    let node = LlmNode::new();
    let arrival = WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_api::operation::Operation::CHAT,
        caller_token: None,
        headers: json_headers(),
        body: fixture.body(),
        path: None,
    };
    let response = node.answer(arrival, None).await;
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

    // Each end gets its OWN deployment, so one fixture's seeded budget cannot decide another's.
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
        // The body is drained before the count is judged, because the seam is polled by the loop
        // and a response whose body is still owed is a unit whose leg may not have finished. It
        // also keeps this cell on the same footing as every other one in this file, which reads
        // its figures out of a drained answer.
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

        // THE SECOND WITNESS, where the deployment has one. A refusal that never reached the
        // seam must also never have reached a socket, and these two facts are independent: the
        // count is taken on this side of the loop and the path is recorded on the other. A cell
        // that asserted only the count would pass on a seam that stopped counting a drive it
        // still performed.
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

        // AND THE ANSWER IS UNCHANGED. The seam awaits the leg it was handed and returns that
        // leg's value, so what a client reads is what a client read. Asserted here rather than
        // taken on trust: an instrument that moved a byte would be an instrument that changed
        // the thing it measures.
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
