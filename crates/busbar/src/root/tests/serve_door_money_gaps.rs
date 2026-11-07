// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};

use super::super::hook_seat_tests::{
    far_end_answering, far_end_scripted, rig, word, DoorRig, RigOpts, Script, ANSWER,
};
use super::super::planes_tests::PUBLISHING;
use super::{frame, stream_pausing, streamed_chat, STREAM_HEAD};

fn now() -> u64 {
    busbar_kernel::store::now()
}

fn limit(metric: LimitMetric, amount: u64, per: LimitWindow) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

async fn send_bytes(rig: &DoorRig, path: &str, body: &str) -> u16 {
    use tower::ServiceExt as _;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {}", rig.token))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = rig
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let _ = axum::body::to_bytes(response.into_body(), 1 << 20).await;
    status
}

async fn metering_rows(rig: &DoorRig, at: u64) -> Vec<String> {
    rig.gov.flush_metering().await;
    rig.gov
        .metering_for_async(busbar_kernel::governance::metering_bucket(at))
        .await
        .expect("metering read")
        .into_iter()
        .filter(|row| row.key_id == rig.key_id)
        .map(|row| {
            format!(
                "{}/{} in={} out={} cr={} cw={} req={} billable={}",
                row.model,
                row.provider,
                busbar_contract::Count::from_stored(row.tokens_input, row.scale).unwrap(),
                busbar_contract::Count::from_stored(row.tokens_output, row.scale).unwrap(),
                busbar_contract::Count::from_stored(row.tokens_cache_read, row.scale).unwrap(),
                busbar_contract::Count::from_stored(row.tokens_cache_write, row.scale).unwrap(),
                row.requests,
                row.billable_requests
            )
        })
        .collect()
}

async fn key_spend(rig: &DoorRig) -> Result<i64, String> {
    rig.gov
        .usage_for_async(&rig.app.cost, &rig.key_id, now())
        .await
        .map(|usage| usage.expect("the key exists").spend_cents)
        .map_err(|refusal| format!("{refusal:?}"))
}

fn card_of(entry: &str) -> BTreeMap<String, busbar_kernel::config::RateEntryCfg> {
    serde_yaml::from_str(&format!("m0: {entry}\n")).expect("the card parses")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_keeps_a_prior_charge_through_a_pre_routing_refusal() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-gap-pre-routing-refusal";
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let key = rig
        .gov
        .core_store_handle()
        .unwrap()
        .identity()
        .get_key(&rig.key_id)
        .await
        .expect("the key reads")
        .expect("the key exists");
    rig.gov
        .try_admit(&rig.app.cost, &key, "", now())
        .expect("an uncapped chain admits the prior request");
    assert_eq!(
        send_bytes(&rig, "/v1/chat/completions", "{ this is not json ").await,
        400,
        "a malformed body is a pre-routing 400"
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (requests, spend, _, billable) = rig.ledger_after(1).await;
    assert_eq!(
        requests, 1,
        "the prior request is still on the key's bucket"
    );
    assert_eq!(
        (spend, billable),
        (1, 1),
        "the pre-routing refusal refunded nothing: the prior 1-cent fee stands"
    );
    assert_eq!(far.served(), 0, "the refused body was never dialled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_prices_an_aliased_lane_at_its_config_names_card() {
    const WIRE: &str = "m0-on-the-wire";
    let _one = PUBLISHING.lock().await;
    let instance = "door-gap-aliased-lane";
    let received = Arc::new(std::sync::Mutex::new(None));
    let recorded = Arc::clone(&received);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = axum::Router::new().fallback(axum::routing::post(
        move |axum::Json(body): axum::Json<serde_json::Value>| {
            *recorded.lock().unwrap() = Some(body);
            async {
                axum::Json(serde_json::json!({
                "id": "chatcmpl-aliased", "object": "chat.completion", "created": 0, "model": WIRE,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "hello"}}],
                "usage": {"prompt_tokens": 600, "completion_tokens": 400, "total_tokens": 1000}
                }))
            }
        },
    ));
    let server = tokio::spawn(async move {
        axum::serve(listener, endpoint).await.unwrap();
    });
    let card = card_of("{ input_utok: 1000, output_utok: 1000 }");
    let rig = rig(
        instance,
        RigOpts {
            members: &[(port, 1)],
            model_yaml: &["upstream_model: m0-on-the-wire"],
            budget_cents: Some(1_000_000_000),
            rate_card: Some(&card),
            fee_cents: Some(0),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(
        status,
        200,
        "the aliased lane served it: {}",
        String::from_utf8_lossy(&body)
    );
    let sent = received
        .lock()
        .unwrap()
        .clone()
        .expect("the upstream was dialled with JSON");
    assert_eq!(
        sent["model"], WIRE,
        "precondition: the lane is ALIASED, or the fault is masked"
    );
    assert_eq!(rig.tokens_after().await, 1000, "the key's tokens");
    let derived = rig
        .gov
        .derived_bucket_usage_async(
            &rig.app.cost,
            &format!("group:{instance}-group@day"),
            "day",
            true,
            now(),
        )
        .await
        .expect("usage read");
    assert_eq!(derived.tokens, 1000, "the tokens are ledgered either way");
    assert_eq!(
        derived.spend_cents, 100,
        "1,000 tokens at 1,000 micro-units each price at the card under the config name"
    );
    server.abort();
    let _ = server.await;
}

const FIRST_FRAME: &str = r#"{"id":"chatcmpl-root","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"}}]}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_report_carries_the_end_a_status_line_cannot() {
    use http_body_util::BodyExt as _;
    let _one = PUBLISHING.lock().await;
    let cases = [
        (
            "door-gap-tap-cut-after-first-frame",
            "a stream cut after its first frame",
            vec![(0, frame(FIRST_FRAME))],
            true,
        ),
        (
            "door-gap-tap-failed-before-first-byte",
            "a transfer that failed before its first byte",
            Vec::new(),
            false,
        ),
    ];
    for (instance, label, pieces, relayed) in cases {
        let far = far_end_scripted(Script {
            head: STREAM_HEAD.to_string(),
            pieces,
            finish: None,
        })
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let charged_at = now();
        let response = rig
            .open("POST", "/v1/chat/completions", Some(streamed_chat()), &[])
            .await;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut drained = Vec::new();
        while let Some(piece) = body.frame().await {
            let Ok(piece) = piece else { break };
            if let Ok(data) = piece.into_data() {
                drained.extend_from_slice(&data);
            }
        }
        let text = String::from_utf8_lossy(&drained).to_string();
        assert_eq!(status, 200, "{label}: the status line says success: {text}");
        assert!(
            !text.contains("[DONE]"),
            "{label}: the answer never completed, and the caller is not told it did: {text}"
        );
        assert_eq!(
            text.contains("hello"),
            relayed,
            "{label}: the caller has exactly what was relayed before the end: {text}"
        );
        assert_eq!(rig.tokens_after().await, 0, "{label}: no token ledgered");
        let (requests, _, _, _) = rig.ledger_after(0).await;
        assert_eq!(
            requests, 1,
            "{label}: the request unit still counts (oracle cell \
             `route.failover|fo|primary-cut-stream`, golden usage {{\"requests\":1}})"
        );
        let rows = metering_rows(&rig, charged_at).await;
        assert_eq!(rows.len(), 1, "{label}: one metering row: {rows:?}");
        assert!(
            rows[0].starts_with("m0/") && rows[0].contains(" in=0 out=0 cr=0 cw=0 "),
            "{label}: and it carries no token, as the plane ledgered none: {rows:?}"
        );
    }
}

const FIRST_FRAME_WITH_USAGE: &str = r#"{"id":"chatcmpl-root","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":600,"completion_tokens":400,"total_tokens":1000}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_what_its_plane_ledgered_for_a_stream_cut_after_its_first_frame() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-gap-cut-stream-plane-ledger";
    let far = far_end_scripted(Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![(0, frame(FIRST_FRAME_WITH_USAGE)), (50, Vec::new())],
        finish: None,
    })
    .await;
    let card = card_of("{ input_utok: 1000, output_utok: 1000 }");
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            budget_cents: Some(1_000_000_000),
            rate_card: Some(&card),
            fee_cents: Some(0),
            ..RigOpts::default()
        },
    )
    .await;
    let charged_at = now();
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    let text = String::from_utf8_lossy(&body).to_string();
    assert_eq!(status, 200, "the stream had begun: {text}");
    assert!(
        !text.contains("[DONE]"),
        "precondition: the far end cut the stream before its end: {text}"
    );
    assert_eq!(
        rig.tokens_after().await,
        1000,
        "the 1,000 tokens the plane ledgered are the key's"
    );
    let derived = rig
        .gov
        .derived_bucket_usage_async(
            &rig.app.cost,
            &format!("group:{instance}-group@day"),
            "day",
            true,
            now(),
        )
        .await
        .expect("usage read");
    assert_eq!(derived.tokens, 1000, "the group's bucket holds them");
    assert_eq!(
        derived.spend_cents, 100,
        "and they are charged: 1,000 tokens at 1,000 micro-units each"
    );
    let rows = metering_rows(&rig, charged_at).await;
    assert_eq!(rows.len(), 1, "one metering row: {rows:?}");
    assert!(
        rows[0].starts_with("m0/") && rows[0].contains(" in=600 out=400 "),
        "the row carries what the plane ledgered: {rows:?}"
    );
}

const SEARCH_UNITS: &str = "search_units";

static RERANK_CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| {
        use busbar_kernel_ledger::cost::{LaneClass, RateCard};
        let holder = crate::root::kernel::RootHistory::default();
        holder.apply(
            RateCard::from_micro_rates(
                [
                    (
                        LaneClass::new("m0", busbar_contract::records::UNIT_INPUT),
                        3.0,
                    ),
                    (
                        LaneClass::new("m0", busbar_contract::records::UNIT_OUTPUT),
                        16.0,
                    ),
                ],
                0,
            )
            .with_unit_rates([(LaneClass::new("m0", SEARCH_UNITS), 2_000_000)]),
            1_000,
        );
        holder
    });

fn rerank_pin() -> Option<crate::root::kernel::PinnedHistory> {
    RERANK_CARD.pin()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_prices_a_reranks_search_units() {
    let _one = PUBLISHING.lock().await;
    let card = card_of(&format!("{{ units: {{ {SEARCH_UNITS}: 2000 }} }}"));
    for (instance, answer, units, cents) in [
        (
            "door-gap-rerank-50",
            word("rerank_answer_50"),
            Some(50_u64),
            10_i64,
        ),
        ("door-gap-rerank-1", word("rerank_answer_1"), Some(1), 0),
        (
            "door-gap-rerank-none",
            word("rerank_answer_unbilled"),
            None,
            0,
        ),
    ] {
        let far = far_end_answering(200, answer).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                dialect: Some(word("rerank_dialect")),
                rate_card: Some(&card),
                fee_cents: Some(0),
                pin: Some(rerank_pin),
                ..RigOpts::default()
            },
        )
        .await;
        let body: serde_json::Value =
            serde_json::from_str(word("rerank_body")).expect("the rerank body is JSON");
        let before = busbar_kernel::governance::metering_bucket(now());
        let (status, _, answered) = rig.send("POST", word("rerank_path"), Some(body)).await;
        assert_eq!(
            status,
            200,
            "{units:?} units: served: {}",
            String::from_utf8_lossy(&answered)
        );
        assert_eq!(far.served(), 1, "{units:?} units: dialled once");

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                rig.gov.flush_metering().await;
                let after = busbar_kernel::governance::metering_bucket(now());
                let mut rows = rig
                    .gov
                    .metering_for_async(before)
                    .await
                    .expect("metering reads");
                if after != before {
                    rows.extend(
                        rig.gov
                            .metering_for_async(after)
                            .await
                            .expect("metering reads"),
                    );
                }
                let requests: u64 = rows
                    .iter()
                    .filter(|row| row.key_id == rig.key_id && row.model == "m0")
                    .map(|row| row.requests)
                    .sum();
                if requests != 0 {
                    assert_eq!(requests, 1, "{units:?} units: one settled request");
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the delivered rerank records its metered request after its usage");
        assert_eq!(
            key_spend(&rig).await,
            Ok(cents),
            "{units:?} search units at 0.2 cents each"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_charges_a_client_request_exactly_one_flat_fee() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-strong-client-fee";
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let (requests, spend, row_requests, billable) = rig.ledger_after(1).await;
    assert_eq!(
        (requests, spend, row_requests, billable),
        (1, 1, 1, 1),
        "one request, one 1-cent fee, one billable request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_keeps_the_fee_of_a_caller_that_hung_up_mid_dispatch() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-strong-hang-up";
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (announced, allowed) = (Arc::clone(&started), Arc::clone(&release));
    let endpoint = axum::Router::new().fallback(axum::routing::post(move || {
        let (announced, allowed) = (Arc::clone(&announced), Arc::clone(&allowed));
        async move {
            announced.notify_one();
            allowed.notified().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": {"message": "still answering", "type": "server_error"}
                })),
            )
        }
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, endpoint).await.unwrap();
    });
    let rig = rig(
        instance,
        RigOpts {
            members: &[(port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    tokio::select! {
        _ = rig.chat() => {
            panic!("the far end holds its body, so the unit cannot have answered");
        }
        // The unit is reading the held body: the caller goes away here, and its request future is
        // dropped with the unit inside it.
        () = started.notified() => {}
    }
    release.notify_one();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (requests, spend, _, _) = rig.ledger_after(1).await;
    assert_eq!(requests, 1, "the door drew the admission slot");
    assert_eq!(
        spend, 1,
        "a caller that went away mid-dispatch is refunded nothing: the 1-cent fee stays charged"
    );
    server.abort();
    let _ = server.await;
}

async fn served_streamed(
    instance: &'static str,
    rate_card: Option<&BTreeMap<String, busbar_kernel::config::RateEntryCfg>>,
) -> (u16, i64, Vec<String>) {
    let far = far_end_scripted(stream_pausing(0)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            rate_card,
            ..RigOpts::default()
        },
    )
    .await;
    let charged_at = now();
    let (status, _, _) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    let (_, spend, _, _) = rig.ledger_after(1).await;
    assert_eq!(
        rig.tokens_after().await,
        18,
        "{instance}: the stream's tokens"
    );
    (status, spend, metering_rows(&rig, charged_at).await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_serves_free_with_billing_off_writes_its_row_and_still_governs() {
    let _one = PUBLISHING.lock().await;
    let card = card_of("{ input_utok: 1, output_utok: 1 }");
    let row = vec!["m0/oai0 in=11 out=7 cr=0 cw=0 req=1 billable=1".to_string()];

    let (status, spend, rows) = served_streamed("door-strong-billing-off", None).await;
    assert_eq!(
        status, 200,
        "billing off still serves the request (a free failover/routing proxy)"
    );
    assert_eq!(
        rows, row,
        "billing off (no rate_card) still writes the plane's counts (#43)"
    );
    assert_eq!(
        spend, 1,
        "billing off is the VIEW reading the counts as 0 (#42): only the 1-cent fee posts"
    );

    let (_, _, billed) = served_streamed("door-strong-billing-on", Some(&card)).await;
    assert_eq!(
        billed, row,
        "the same request on a billed door writes exactly the same metering row"
    );

    let instance = "door-strong-billing-off-governed";
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            allowed_pools: Some(&["denied-elsewhere"]),
            ..RigOpts::default()
        },
    )
    .await;
    let charged_at = now();
    assert_eq!(rig.chat().await.0, 403, "the pool-ACL guard refuses");
    let (requests, _, _, _) = rig.ledger_after(0).await;
    assert_eq!(
        requests, 0,
        "billing off still runs admission governance: the guard refused before any charge"
    );
    assert_eq!(metering_rows(&rig, charged_at).await, Vec::<String>::new());
    assert_eq!(far.served(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_attributes_the_identity_its_auth_resolved_and_invents_none() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-strong-identity";
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;

    assert_eq!(rig.chat().await.0, 200, "the deployment's own bearer");
    let (requests, _, _, _) = rig.ledger_after(1).await;
    assert_eq!(requests, 1, "the admitted unit was charged to the key");
    let records = rig.audit_records();

    let chat = serde_json::json!({"model": "p", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]});
    let (bad, _, _) = rig
        .send_bare(
            "POST",
            "/v1/chat/completions",
            Some(chat.clone()),
            &[("authorization", "Bearer not-a-token-this-deployment-minted")],
        )
        .await;
    assert_eq!(bad, 401, "a bearer never minted is refused at the door");

    let (expired_key, expired_token) = rig
        .gov
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "expired".to_string(),
                ..Default::default()
            },
            1_700_000_100,
            1_700_000_000,
        )
        .await
        .expect("mint");
    let expired_bearer = format!(
        "Bearer {}",
        expired_token.expose(&busbar_kernel::seal::lend())
    );
    let (expired, _, _) = rig
        .send_bare(
            "POST",
            "/v1/chat/completions",
            Some(chat),
            &[("authorization", expired_bearer.as_str())],
        )
        .await;
    assert_eq!(
        expired, bad,
        "an expired bearer is refused at the door as a bearer never minted is"
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        far.served(),
        1,
        "neither refused credential reached a far end"
    );
    assert_eq!(
        rig.audit_records(),
        records,
        "no unit exists for a refused credential: no record"
    );
    let expired_usage = rig
        .gov
        .usage_for_async(&rig.app.cost, &expired_key.id, now())
        .await
        .expect("usage read")
        .map_or(0, |usage| usage.requests);
    assert_eq!(
        expired_usage, 0,
        "nothing was charged to the key whose bearer expired"
    );
    let (requests, _, _, _) = rig.ledger_after(1).await;
    assert_eq!(requests, 1, "nor to the live key a second time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_gate_stops_a_unit_and_a_passing_gate_changes_nothing() {
    let _one = PUBLISHING.lock().await;
    for (instance, reject_at_gate) in [
        ("door-strong-gate-veto", true),
        ("door-strong-gate-pass", false),
    ] {
        let far = far_end_answering(200, ANSWER).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                reject_at_gate,
                ..RigOpts::default()
            },
        )
        .await;
        let charged_at = now();
        let (status, _, _) = rig.chat().await;
        assert!(
            rig.seats().iter().any(|seat| seat == "gate"),
            "{instance}: the gate was asked: {:?}",
            rig.seats()
        );
        if reject_at_gate {
            assert_eq!(status, 451, "the gate's own status");
            assert_eq!(far.served(), 0, "a vetoed unit reached no far end");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let (requests, spend, row_requests, billable) = rig.ledger_after(0).await;
            assert_eq!(
                (requests, spend, row_requests, billable),
                (1, 0, 1, 0),
                "the admission is kept and the fee is refunded"
            );
            assert_eq!(
                metering_rows(&rig, charged_at).await,
                Vec::<String>::new(),
                "a veto is metered nowhere"
            );
        } else {
            assert_eq!(status, 200, "a gate that passes changes nothing");
            assert_eq!(far.served(), 1, "the unit went on to its far end once");
            let (requests, spend, _, billable) = rig.ledger_after(1).await;
            assert_eq!((requests, spend, billable), (1, 1, 1));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_dials_a_served_unit_once_and_a_refused_one_never() {
    const EXACT: &str = concat!(
        module_path!(),
        "::the_pools_door_dials_a_served_unit_once_and_a_refused_one_never"
    );
    let Some(case) = super::independent_cases(
        EXACT,
        &[
            "door-strong-dial-pool-acl",
            "door-strong-dial-over-budget",
            "door-strong-dial-served",
        ],
    ) else {
        return;
    };
    let _one = PUBLISHING.lock().await;
    let spent = [limit(LimitMetric::Budget, 0, LimitWindow::Total)];
    for (instance, opts_of, expected, why) in [
        (
            "door-strong-dial-pool-acl",
            0_u8,
            0_usize,
            "refused before the door: the pre-admission guard",
        ),
        (
            "door-strong-dial-over-budget",
            1,
            0,
            "refused at the door: the group's budget is spent",
        ),
        (
            "door-strong-dial-served",
            2,
            1,
            "served: the whole walk, exactly once",
        ),
    ] {
        if case != instance {
            continue;
        }
        let far = far_end_answering(200, ANSWER).await;
        let members = [(far.port, 1)];
        let opts = match opts_of {
            0 => RigOpts {
                members: &members,
                allowed_pools: Some(&["denied-elsewhere"]),
                ..RigOpts::default()
            },
            1 => RigOpts {
                members: &members,
                group: Some(("spent", &spent)),
                ..RigOpts::default()
            },
            _ => RigOpts {
                members: &members,
                ..RigOpts::default()
            },
        };
        let rig = rig(instance, opts).await;
        let (status, _, _) = rig.chat().await;
        assert!(
            (100..600).contains(&status),
            "{why}: the unit produced a status"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            far.served(),
            expected,
            "{why}: the far end was dialled {} time(s), expected {expected} (status {status})",
            far.served()
        );
        super::independent_case_done(EXACT, &case);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_provider_counts_reach_real_store_and_the_same_priced_view() {
    use busbar_contract::Count;
    let _one = PUBLISHING.lock().await;
    let card = card_of("{ input_utok: 1000, output_utok: 1000 }");
    for (instance, raw, decimal) in [
        ("exact-provider-275", "27.5", "27.5"),
        ("exact-provider-271", "27.1", "27.1"),
        ("exact-provider-270", "27.0", "27"),
        ("exact-provider-exp", "1e3", "1000"),
    ] {
        let response = format!(
            r#"{{"id":"exact","object":"chat.completion","created":0,"model":"m0","choices":[{{"index":0,"finish_reason":"stop","message":{{"role":"assistant","content":"exact"}}}}],"usage":{{"prompt_tokens":{raw},"completion_tokens":0,"total_tokens":{raw}}}}}"#
        );
        let endpoint = axum::Router::new().fallback(axum::routing::post(move || {
            let response = response.clone();
            async move { ([("content-type", "application/json")], response) }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { axum::serve(listener, endpoint).await.unwrap() });
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port, 1)],
                rate_card: Some(&card),
                fee_cents: Some(0),
                ..RigOpts::default()
            },
        )
        .await;
        let at = now();
        let (status, _, body) = rig.chat().await;
        assert_eq!(
            status,
            200,
            "{instance}: {}",
            String::from_utf8_lossy(&body)
        );
        let _ = rig.ledger_after(1).await;
        rig.gov.flush_budgets().await;
        rig.gov.flush_metering().await;
        let expected = Count::parse(decimal).unwrap();
        let row = rig
            .gov
            .core_store_handle()
            .unwrap()
            .ledger()
            .get_usage(&rig.key_id, 0)
            .await
            .unwrap();
        let model = row
            .models
            .iter()
            .find(|row| row.model == "m0")
            .expect("raw model row");
        assert_eq!(model.scale, 6);
        assert_eq!(model.usage_units["input"], expected.micros());
        let counts = model.counts().unwrap();
        assert_eq!(counts["input"], expected);
        let nanos = rig.app.cost.price_counts_nanos("m0", &counts).unwrap();
        assert_eq!(nanos, u128::try_from(expected.micros()).unwrap());
        let usage = rig
            .gov
            .usage_for_async(&rig.app.cost, &rig.key_id, at)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(usage.tokens, expected);
        assert_eq!(
            usage.spend_cents,
            i64::try_from(nanos / 10_000_000).unwrap()
        );
        let metering = rig
            .gov
            .metering_for_async(busbar_kernel::governance::metering_bucket(at))
            .await
            .unwrap();
        let measured = metering
            .iter()
            .find(|row| row.key_id == rig.key_id && row.model == "m0")
            .unwrap();
        assert_eq!(measured.scale, 6);
        assert_eq!(
            Count::from_stored(measured.tokens_input, measured.scale).unwrap(),
            expected
        );
        let reopened = busbar_kernel::governance::GovState::new_with_core(
            rig.gov.core_store_handle().unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
        let reread = reopened
            .usage_for_async(&rig.app.cost, &rig.key_id, at)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reread, usage,
            "new governor reads the exact durable ledger and price"
        );
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrepresentable_provider_count_refuses_before_success_or_usage_commit() {
    let _one = PUBLISHING.lock().await;
    const BAD: &str = r#"{"id":"bad-count","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"must not escape"}}],"usage":{"prompt_tokens":27.0000001,"completion_tokens":2,"total_tokens":29.0000001}}"#;
    let far = far_end_answering(200, BAD).await;
    let card = card_of("{ input_utok: 1000, output_utok: 1000 }");
    let rig = rig(
        "exact-provider-refused",
        RigOpts {
            members: &[(far.port, 1)],
            rate_card: Some(&card),
            fee_cents: Some(0),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert!(
        status >= 400,
        "an unpriced measurement cannot return success: {status}"
    );
    assert!(!String::from_utf8_lossy(&body).contains("must not escape"));
    rig.gov.flush_budgets().await;
    rig.gov.flush_metering().await;
    let usage = rig
        .gov
        .usage_for_async(&rig.app.cost, &rig.key_id, now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.tokens, busbar_contract::Count::ZERO);
    assert_eq!(usage.spend_cents, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrepresentable_stream_count_cuts_at_the_last_exact_report() {
    let _one = PUBLISHING.lock().await;
    const GOOD: &str = r#"{"id":"exact-stream","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"accepted"},"finish_reason":null}],"usage":{"prompt_tokens":27.5,"completion_tokens":0,"total_tokens":27.5}}"#;
    const BAD: &str = r#"{"id":"exact-stream","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"content":"must not escape"},"finish_reason":null}],"usage":{"prompt_tokens":27.5000001,"completion_tokens":0,"total_tokens":27.5000001}}"#;
    let far = far_end_scripted(Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![(0, frame(GOOD)), (20, frame(BAD)), (0, frame("[DONE]"))],
        finish: Some(b"0\r\n\r\n".to_vec()),
    })
    .await;
    let card = card_of("{ input_utok: 1000, output_utok: 1000 }");
    let rig = rig(
        "exact-provider-stream-refused",
        RigOpts {
            members: &[(far.port, 1)],
            rate_card: Some(&card),
            fee_cents: Some(0),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    assert_eq!(
        status, 200,
        "the first exact piece already committed its head"
    );
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("accepted"));
    assert!(!body.contains("must not escape"));
    assert!(
        body.contains("error"),
        "the committed stream gets its protocol refusal: {body}"
    );
    let _ = rig.ledger_after(1).await;
    rig.gov.flush_budgets().await;
    rig.gov.flush_metering().await;
    let usage = rig
        .gov
        .usage_for_async(&rig.app.cost, &rig.key_id, now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.tokens, busbar_contract::Count::parse("27.5").unwrap());
    assert_eq!(usage.spend_cents, 2);
}
