// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ATTEMPT-SEAM IDENTITY HARNESS: `engine::attempt::attempt` (driven in the degraded posture
//! through `exhaustion::dispatch_degraded`, the adapter every exhaustion path uses) against the
//! legacy degraded-path twin `forward_once`, kept verbatim in `legacy_forward_once.rs`.
//!
//! Table-driven over the scripted upstreams and the six ingress dialects, same- and
//! cross-protocol, from a Closed cell and from a HalfOpen cell whose recovery probe this dispatch
//! owns. Each case builds two identical apps (own lane store, own mock upstream), drives one leg
//! each, and compares: client status, headers (minus the volatile ones), the full body (streams
//! drained, synthesized ids and clocks normalized); the lane's breaker state, cooldown, probe
//! epoch, admissibility and request budget; and the request the upstream actually received.
//!
//! The differences the owner accepted when the two twins were unified are an explicit allow-table
//! keyed by (fixture, field), each naming its `testing/shadow-oracle/accepted-differences.json`
//! entry. Any unlisted divergence fails; any listed divergence that never fires also fails, so the
//! table cannot go stale.
//!
//! Not observable here, and therefore covered by the oracle rather than this harness: the
//! telemetry series (the metrics recorder is process-global, so two apps in one test cannot be
//! told apart) and the token ledger (a governed fixture needs core's governance state, which this
//! crate's tests may not name).

#[path = "legacy_forward_once.rs"]
mod legacy;

use crate::engine::{RequestCtx, APPLICATION_JSON};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use busbar_substrate::store::{now as store_now, BreakerState};
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;

/// The scripted upstreams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fixture {
    OkJson,
    OkSse,
    Auth401,
    ClientFault400,
    RateLimit429RetryAfter,
    ServerError503,
    Billing402,
    ContextLength400,
    ConnectRefused,
    HeadersTimeout,
    BodyCutAfterFirstByte,
    Untranslatable2xx,
}

const FIXTURES: [Fixture; 12] = [
    Fixture::OkJson,
    Fixture::OkSse,
    Fixture::Auth401,
    Fixture::ClientFault400,
    Fixture::RateLimit429RetryAfter,
    Fixture::ServerError503,
    Fixture::Billing402,
    Fixture::ContextLength400,
    Fixture::ConnectRefused,
    Fixture::HeadersTimeout,
    Fixture::BodyCutAfterFirstByte,
    Fixture::Untranslatable2xx,
];

const INGRESS: [&str; 6] = [
    crate::proto_codec::PROTO_ANTHROPIC,
    crate::proto_codec::PROTO_OPENAI,
    crate::proto_codec::PROTO_RESPONSES,
    crate::proto_codec::PROTO_GEMINI,
    crate::proto_codec::PROTO_BEDROCK,
    crate::proto_codec::PROTO_COHERE,
];

/// The breaker cell the dispatch starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Posture {
    /// A Closed cell: the dispatch owns no probe.
    Closed,
    /// An expired-Open cell driven HalfOpen by `try_admit_breaker`: the dispatch owns the probe.
    HalfOpenProbe,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    fixture: Fixture,
    ingress: &'static str,
    cross: bool,
    posture: Posture,
}

impl Case {
    fn egress(&self) -> &'static str {
        if !self.cross {
            self.ingress
        } else if self.ingress == crate::proto_codec::PROTO_OPENAI {
            crate::proto_codec::PROTO_ANTHROPIC
        } else {
            crate::proto_codec::PROTO_OPENAI
        }
    }

    fn streaming(&self) -> bool {
        matches!(
            self.fixture,
            Fixture::OkSse | Fixture::BodyCutAfterFirstByte
        )
    }

    /// Cases that do not apply: an untranslatable body only exists on a crossed boundary, and the
    /// black-holed upstream (a real one-second wait per leg) is exercised once per dialect.
    fn applies(&self) -> bool {
        match self.fixture {
            Fixture::Untranslatable2xx => self.cross,
            Fixture::HeadersTimeout => !self.cross && self.posture == Posture::Closed,
            _ => true,
        }
    }

    fn name(&self) -> String {
        format!(
            "{:?}/{}->{}/{:?}",
            self.fixture,
            self.ingress,
            self.egress(),
            self.posture
        )
    }
}

/// The ingress request body, in the dialect's own shape.
fn request_body(ingress: &str, stream: bool) -> Vec<u8> {
    let mut v = match ingress {
        "anthropic" => {
            json!({"model": "m", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]})
        }
        "openai" => json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
        "responses" => json!({"model": "m", "input": "hi"}),
        "gemini" => {
            json!({"model": "m", "contents": [{"role": "user", "parts": [{"text": "hi"}]}]})
        }
        "bedrock" => {
            json!({"model": "m", "messages": [{"role": "user", "content": [{"text": "hi"}]}]})
        }
        "cohere" => json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
        other => panic!("unknown ingress dialect {other}"),
    };
    if stream {
        v["stream"] = json!(true);
    }
    serde_json::to_vec(&v).unwrap()
}

/// A delivered 2xx completion in the EGRESS dialect's shape (the two egress dialects this harness
/// routes to), so a crossed boundary has something real to translate.
fn ok_body(egress: &str) -> serde_json::Value {
    if egress == crate::proto_codec::PROTO_ANTHROPIC {
        json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
               "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
               "usage": {"input_tokens": 3, "output_tokens": 2}})
    } else {
        json!({"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "m",
               "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
               "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}})
    }
}

fn sse_events() -> Vec<String> {
    vec![
        json!({"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":null}]}).to_string(),
        json!({"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}).to_string(),
    ]
}

fn mock_response(case: &Case) -> Option<MockResponse> {
    Some(match case.fixture {
        Fixture::OkJson => MockResponse::Ok {
            status: StatusCode::OK,
            body: ok_body(case.egress()),
        },
        Fixture::OkSse => MockResponse::Sse {
            events: sse_events(),
            abort_at_index: None,
        },
        Fixture::Auth401 => MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        },
        Fixture::ClientFault400 => MockResponse::Ok {
            status: StatusCode::BAD_REQUEST,
            body: json!({"error": {"message": "bad input", "type": "invalid_request_error"}}),
        },
        Fixture::RateLimit429RetryAfter => MockResponse::RateLimit {
            status: StatusCode::TOO_MANY_REQUESTS,
            provider_signal: None,
            retry_after: Some(7),
        },
        Fixture::ServerError503 => MockResponse::ServerError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: json!({"error": {"message": "overloaded", "type": "server_error"}}),
        },
        Fixture::Billing402 => MockResponse::Billing {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "insufficient_quota",
            message: "You exceeded your current quota",
        },
        Fixture::ContextLength400 => MockResponse::Ok {
            status: StatusCode::BAD_REQUEST,
            body: json!({"error": {"message": "This model's maximum context length is 8192 tokens",
                                   "type": "invalid_request_error", "code": "context_length_exceeded"}}),
        },
        Fixture::BodyCutAfterFirstByte => MockResponse::SseTransportError {
            ok_events: sse_events(),
        },
        Fixture::Untranslatable2xx => MockResponse::Ok {
            status: StatusCode::OK,
            body: json!({"nope": true}),
        },
        Fixture::ConnectRefused | Fixture::HeadersTimeout => return None,
    })
}

/// The upstream for one leg: a scripted mock, a refused port, or a socket that accepts and never
/// answers (the black-holed upstream the deadline envelope exists for).
enum Upstream {
    Mock(MockServer, Arc<MockServerState>),
    Refused,
    BlackHole(tokio::task::JoinHandle<()>, String),
}

impl Upstream {
    async fn start(case: &Case) -> Self {
        match case.fixture {
            Fixture::ConnectRefused => Upstream::Refused,
            Fixture::HeadersTimeout => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let task = tokio::spawn(async move {
                    let mut held = Vec::new();
                    loop {
                        let (sock, _) = listener.accept().await.unwrap();
                        held.push(sock);
                    }
                });
                Upstream::BlackHole(task, url)
            }
            _ => {
                let state = Arc::new(MockServerState::new());
                state.push(mock_response(case).unwrap());
                let server = MockServer::new(state.clone()).await;
                Upstream::Mock(server, state)
            }
        }
    }

    fn base_url(&self) -> String {
        match self {
            Upstream::Mock(server, _) => server.base_url(),
            Upstream::Refused => "http://127.0.0.1:1".to_string(),
            Upstream::BlackHole(_, url) => url.clone(),
        }
    }

    fn received(&self) -> (Option<String>, Vec<(String, Option<String>)>) {
        match self {
            Upstream::Mock(_, state) => (
                state
                    .get_last_request_body()
                    .map(|b| normalize(&String::from_utf8_lossy(&b))),
                ["content-type", "accept", "user-agent"]
                    .iter()
                    .map(|h| (h.to_string(), state.get_last_request_header(h)))
                    .collect(),
            ),
            _ => (None, Vec::new()),
        }
    }

    async fn stop(self) {
        match self {
            Upstream::Mock(server, _) => server.shutdown().await,
            Upstream::Refused => {}
            Upstream::BlackHole(task, _) => task.abort(),
        }
    }
}

/// Everything one leg observed, as comparable strings.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    fields: Vec<(&'static str, String)>,
}

impl Observed {
    fn get(&self, field: &str) -> &str {
        self.fields
            .iter()
            .find(|(k, _)| *k == field)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
}

/// Blank the values that are synthesized per response (ids, clocks, measured latency) so byte
/// comparison is about shape and content, not about a fresh UUID or a real wall-clock reading. JSON
/// bodies are normalized structurally; SSE bodies line by line on their `data:` payloads; anything
/// else is compared as-is.
///
/// `latencyMs` (Bedrock's `metrics.latencyMs`, see `busbar-llm-codec`'s `bedrock::mod` doc on
/// `FIELD_LATENCY_MS`) is busbar's OWN measured elapsed wall-clock time, injected when the upstream
/// response omits it — never a fixture value. `run_legacy` and `run_attempt` race each other via
/// `tokio::join!` against the SAME fast mock round trip, so under CPU contention (this whole
/// workspace's tests running in parallel) one leg can measure 0ms and the other 1ms purely from
/// scheduling jitter, with no difference in the two paths' actual behavior. That is exactly the
/// class of "synthesized, not identity-bearing" value this function already blanks ids and clocks
/// for, so it belongs here rather than in the `ALLOWED` divergence table (which is for BEHAVIORAL
/// differences, not measurement noise).
fn normalize(s: &str) -> String {
    fn blank(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let is_id = k.ends_with("id") || k.ends_with("Id") || k.ends_with("ID");
                    let is_clock = matches!(k.as_str(), "created" | "created_at" | "createTime");
                    let is_latency = k == "latencyMs";
                    if is_id && val.is_string() {
                        *val = serde_json::Value::String("<id>".to_string());
                    } else if (is_clock || is_latency) && val.is_number() {
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
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(s) {
        blank(&mut v);
        return v.to_string();
    }
    s.lines()
        .map(|line| match line.strip_prefix("data: ") {
            Some(payload) => match serde_json::from_str::<serde_json::Value>(payload) {
                Ok(mut v) => {
                    blank(&mut v);
                    format!("data: {v}")
                }
                Err(_) => line.to_string(),
            },
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Headers whose value is minted per response or per run.
const VOLATILE_HEADERS: [&str; 5] = [
    "date",
    "request-id",
    "x-request-id",
    "x-amzn-requestid",
    "x-amzn-request-id",
];

async fn observe(
    result: Result<axum::response::Response, ()>,
    store: &dyn busbar_substrate::store::LaneRuntime,
    upstream: &Upstream,
) -> Observed {
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    match result {
        Err(()) => fields.push(("client", "Err(try-next)".to_string())),
        Ok(resp) => {
            fields.push(("client", "Ok".to_string()));
            fields.push(("status", resp.status().as_u16().to_string()));
            let mut headers: Vec<String> = resp
                .headers()
                .iter()
                .filter(|(k, _)| !VOLATILE_HEADERS.contains(&k.as_str()))
                .map(|(k, v)| format!("{k}: {}", String::from_utf8_lossy(v.as_bytes())))
                .collect();
            headers.sort();
            fields.push(("headers", headers.join("\n")));
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap_or_default();
            fields.push(("body", normalize(&String::from_utf8_lossy(&body))));
        }
    }
    // The body wrapper records mid-stream outcomes on drop; give it a tick before reading the store.
    tokio::task::yield_now().await;
    let now = store_now();
    let state = match store.breaker_state_in("p", 0) {
        BreakerState::Closed => "Closed",
        BreakerState::Open { .. } => "Open",
        BreakerState::HalfOpen => "HalfOpen",
    };
    fields.push(("breaker", state.to_string()));
    // The cooldown length carries jitter; what is comparable is whether one is running at all.
    fields.push((
        "cooldown",
        if store.cooldown_remaining_in("p", 0, now) > 0 {
            "running".to_string()
        } else {
            "none".to_string()
        },
    ));
    fields.push(("probe_epoch", store.probe_epoch_in("p", 0).to_string()));
    fields.push(("admissible", store.lane_admissible(0).to_string()));
    fields.push(("budget", format!("{:?}", store.lane_budget_remaining(0))));
    let (up_body, up_headers) = upstream.received();
    fields.push(("upstream_body", format!("{up_body:?}")));
    fields.push(("upstream_headers", format!("{up_headers:?}")));
    Observed { fields }
}

/// One app per leg: a single lane in the egress dialect, budget-limited so the spend is visible,
/// as the only member of pool `p`, starting in the requested breaker posture. A macro (not a fn)
/// so the built app's concrete type stays inferred and this file names no core type.
macro_rules! build_leg {
    ($case:expr, $upstream:expr) => {{
        let app = TestApp::new()
            .lane(
                LaneSpec::new("m", $case.egress(), &$upstream.base_url())
                    .provider("test")
                    .budget(5),
            )
            .pool("p", &[(0, 1)])
            .build();
        if $case.posture == Posture::HalfOpenProbe {
            app.store
                .force_open_in("p", 0, store_now().saturating_sub(10));
        }
        app
    }};
}

/// The probe token for this posture: `try_admit_breaker` drives the expired-Open cell HalfOpen and
/// hands this dispatch the single-flight probe (`Some(epoch)`); a Closed cell yields `None`.
fn admit(store: &dyn busbar_substrate::store::LaneRuntime, case: &Case) -> Option<u64> {
    match case.posture {
        Posture::Closed => None,
        Posture::HalfOpenProbe => store
            .try_admit_breaker("p", 0, store_now())
            .expect("an expired-Open cell admits the recovery probe"),
    }
}

/// Whole seconds of failover budget each leg is given. One second for the black-holed upstream so
/// the test does not wait out the default budget; ample otherwise.
fn budget_secs(case: &Case) -> u64 {
    if case.fixture == Fixture::HeadersTimeout {
        1
    } else {
        5
    }
}

async fn run_legacy(case: &Case) -> Observed {
    let upstream = Upstream::start(case).await;
    let app = build_leg!(case, upstream);
    let (host, rt) = crate::engine::test_host_rt(&app);
    let probe_epoch = admit(&*app.store, case);
    let permit = app.store.try_acquire(0).expect("a fresh lane has capacity");
    let body = bytes::Bytes::from(request_body(case.ingress, case.streaming()));
    let result = legacy::forward_once(
        &host,
        &rt,
        0,
        permit,
        &body,
        None,
        budget_secs(case),
        case.ingress,
        "p",
        probe_epoch,
        crate::test_support::CHAT,
        APPLICATION_JSON,
        None,
        None,
        &[],
    )
    .await;
    let observed = observe(result, &*app.store, &upstream).await;
    upstream.stop().await;
    observed
}

async fn run_attempt(case: &Case) -> Observed {
    let upstream = Upstream::start(case).await;
    let app = build_leg!(case, upstream);
    let (host, rt) = crate::engine::test_host_rt(&app);
    let probe_epoch = admit(&*app.store, case);
    let permit = app.store.try_acquire(0).expect("a fresh lane has capacity");
    let body = bytes::Bytes::from(request_body(case.ingress, case.streaming()));
    let cands = vec![crate::engine::WeightedLane {
        idx: 0,
        weight: 1,
        reasoning: None,
        attempt_timeout_ms: None,
    }];
    let request_ctx = RequestCtx::new(budget_secs(case), 0);
    let mut usage_sink = None;
    let result = crate::engine::exhaustion::dispatch_degraded(
        &host,
        &rt,
        0,
        permit,
        probe_epoch,
        "p",
        &cands,
        &body,
        None,
        request_ctx.remaining(store_now()),
        case.ingress,
        crate::test_support::CHAT,
        APPLICATION_JSON,
        &mut usage_sink,
        request_ctx.forwarded_client_headers.as_slice(),
    )
    .await;
    let observed = observe(result, &*app.store, &upstream).await;
    upstream.stop().await;
    observed
}

/// One accepted divergence between the legacy twin and the unified attempt: which fixture, which
/// observed field, under which cases, and the `accepted-differences.json` entry that owns it.
struct Divergence {
    fixture: Fixture,
    field: &'static str,
    register: &'static str,
    when: fn(&Case) -> bool,
}

fn any(_: &Case) -> bool {
    true
}

fn openai_egress(c: &Case) -> bool {
    c.egress() == crate::proto_codec::PROTO_OPENAI
}

/// The allow-table. Every entry must fire at least once across the table (a stale row fails) and
/// nothing outside it may differ.
const ALLOWED: &[Divergence] = &[
    // A hard-down on the degraded path is now recorded: the lane goes Open in every cell and, for
    // busbar's own rejected credential, the client gets the ingress-native auth envelope instead
    // of the relayed upstream body. (The scripted billing 402 and the 429 classify the same way on
    // both twins in this harness — a 429 lands Open with a running cooldown either way, its
    // Retry-After floor being shorter than the base cooldown — so those rows have nothing to fire
    // on here; the oracle's route.failover cells carry their metrics-level differences.)
    Divergence {
        fixture: Fixture::Auth401,
        field: "status",
        register: "PR2-D2 degraded hard-down recorded",
        when: any,
    },
    Divergence {
        fixture: Fixture::Auth401,
        field: "headers",
        register: "PR2-D2 degraded hard-down recorded",
        when: any,
    },
    Divergence {
        fixture: Fixture::Auth401,
        field: "body",
        register: "PR2-D2 degraded hard-down recorded",
        when: any,
    },
    Divergence {
        fixture: Fixture::Auth401,
        field: "breaker",
        register: "PR2-D2 degraded hard-down recorded",
        when: any,
    },
    Divergence {
        fixture: Fixture::Auth401,
        field: "cooldown",
        register: "PR2-D2 degraded hard-down recorded",
        when: any,
    },
    // A streaming request to an OpenAI Chat lane now carries the injected usage opt-in upstream on
    // the degraded path too, so the fallback stream is billable.
    Divergence {
        fixture: Fixture::OkSse,
        field: "upstream_body",
        register: "PR2-D4 fallback stream billed",
        when: openai_egress,
    },
    Divergence {
        fixture: Fixture::BodyCutAfterFirstByte,
        field: "upstream_body",
        register: "PR2-D4 fallback stream billed",
        when: openai_egress,
    },
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn walk_vs_pipeline_attempt_identity() {
    crate::testkit::install_test_seams();
    let mut failures: Vec<String> = Vec::new();
    let mut fired: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut cases = 0usize;
    for fixture in FIXTURES {
        for ingress in INGRESS {
            for cross in [false, true] {
                for posture in [Posture::Closed, Posture::HalfOpenProbe] {
                    let case = Case {
                        fixture,
                        ingress,
                        cross,
                        posture,
                    };
                    if !case.applies() {
                        continue;
                    }
                    cases += 1;
                    let (legacy, unified) = tokio::join!(run_legacy(&case), run_attempt(&case));
                    for (field, want) in &legacy.fields {
                        let got = unified.get(field);
                        if got == want {
                            continue;
                        }
                        let allowed = ALLOWED.iter().position(|d| {
                            d.fixture == case.fixture && d.field == *field && (d.when)(&case)
                        });
                        match allowed {
                            Some(idx) => {
                                fired.insert(idx);
                            }
                            None => failures.push(format!(
                                "{}: field `{field}` diverges and is not an accepted difference\n  legacy:  {want}\n  attempt: {got}",
                                case.name()
                            )),
                        }
                    }
                }
            }
        }
    }
    assert!(cases > 200, "the table collapsed to {cases} cases");
    for (idx, d) in ALLOWED.iter().enumerate() {
        if !fired.contains(&idx) {
            failures.push(format!(
                "allow-table row ({:?}, `{}`, {}) never fired: the divergence stopped occurring; retire the row",
                d.fixture, d.field, d.register
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} identity failure(s) over {cases} cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
