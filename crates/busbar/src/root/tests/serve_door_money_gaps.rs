// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PATH'S MONEY, WHERE THE NODE'S LEGACY ANSWER PATH WAS THE ONLY WITNESS. Each cell here
//! is the door-path successor of one money test in `root/tests/plane_node.rs` (the node's legacy
//! answer path, deleted by #1161), driven end to end through the door serving the `pools` map
//! (`super::super::hook_seat_tests::rig`): a keyed caller through the data router, the kernel's
//! steps, the model-serving walk to a loopback far end, and the money steps on the governance
//! book. Every expected value is the original's literal or the 1.5.5 behaviour the
//! original pinned, and each cell names its original.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
use busbar_kernel::test_support::{MockResponse, MockServer, MockServerState};

use super::super::hook_seat_tests::{
    far_end_answering, far_end_scripted, rig, word, DoorRig, RigOpts, Script, ANSWER,
};
use super::super::planes_tests::{Published, PUBLISHING};
use super::{frame, stream_pausing, streamed_chat, STREAM_HEAD};

/// The store's clock.
fn now() -> u64 {
    busbar_kernel::store::now()
}

/// A recording far end answering its requests with `replies`, in order.
async fn mock(replies: Vec<MockResponse>) -> (Arc<MockServerState>, MockServer) {
    let state = Arc::new(MockServerState::new());
    for reply in replies.into_iter().rev() {
        state.push(reply);
    }
    let server = MockServer::new(Arc::clone(&state)).await;
    (state, server)
}

/// One group limit of `amount` `metric` per `per`.
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

/// One request through the door as the keyed caller, its body sent as these very bytes: its
/// status.
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

/// The key's metering rows in the bucket `at` falls in, once flushed: `model/provider in= out= cr=
/// cw= req= billable=`, one line per row, as `plane_node.rs`'s `observe` spelled them.
fn metering_rows(rig: &DoorRig, at: u64) -> Vec<String> {
    rig.gov.flush_metering();
    rig.gov
        .metering_for(busbar_kernel::governance::metering_bucket(at))
        .expect("metering read")
        .into_iter()
        .filter(|row| row.key_id == rig.key_id)
        .map(|row| {
            format!(
                "{}/{} in={} out={} cr={} cw={} req={} billable={}",
                row.model,
                row.provider,
                row.tokens_input,
                row.tokens_output,
                row.tokens_cache_read,
                row.tokens_cache_write,
                row.requests,
                row.billable_requests
            )
        })
        .collect()
}

/// The key's all-time derived spend in cents on the governance book (`Err`: the read refused).
fn key_spend(rig: &DoorRig) -> Result<i64, String> {
    rig.gov
        .usage_for(&rig.app.cost, &rig.key_id, now())
        .map(|usage| usage.expect("the key exists").spend_cents)
        .map_err(|refusal| format!("{refusal:?}"))
}

/// A rate card of one entry, `m0`, as the deployment writes it.
fn card_of(entry: &str) -> BTreeMap<String, busbar_kernel::config::RateEntryCfg> {
    serde_yaml::from_str(&format!("m0: {entry}\n")).expect("the card parses")
}

// ── GAP 1: a pre-routing refusal leaves a prior charge intact ──────────────────────────────────

/// A PRE-ROUTING REFUSAL ON THE DOOR NEVER REFUNDS A PRIOR CHARGE. Door successor of
/// `plane_node.rs::a_pre_routing_refusal_leaves_a_prior_charge_intact`. 1.5.5 behaviour, as the original pinned it: a key carrying one legitimately
/// charged request (one 1-cent flat fee, admitted on the real admission charge) sends a body that
/// is not JSON; it is refused 400 before any model resolves, was never charged, so refunds nothing:
/// the prior request and its fee stay on the key's bucket (requests 1, spend 1 cent).
///
/// RED: the 400 finished through the refunding arm and eroded the prior charge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_keeps_a_prior_charge_through_a_pre_routing_refusal() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-gap-pre-routing-refusal";
    let _published = Published(instance);
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
        .store()
        .get_key(&rig.key_id)
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
    // A refund, were there one, settles at the unit's end: give it the time to land.
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

// ── GAP 3: an aliased lane prices at the rate card of its config name ─────────────────────────

/// AN ALIASED LANE PRICES AT THE RATE CARD UNDER ITS CONFIG NAME, ON THE DOOR. Door successor of
/// `plane_node.rs::an_aliased_lane_prices_at_the_rate_card_under_its_config_name`.
/// 1.5.5 behaviour, as the original pinned it: the card is keyed by the CONFIG model name; a lane
/// whose `upstream_model` differs is sent the wire name but ledgered and priced under its config
/// name, so 600 input and 400 output tokens at 1,000 micro-units each land as 1,000 tokens on the
/// key's group bucket and derive 100 cents against the card (no request fee).
///
/// RED: the accrual keyed by the wire model, which the card cannot name: the spend derives 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_prices_an_aliased_lane_at_its_config_names_card() {
    const WIRE: &str = "m0-on-the-wire";
    let _one = PUBLISHING.lock().await;
    let instance = "door-gap-aliased-lane";
    let _published = Published(instance);
    let answered = || MockResponse::Ok {
        status: StatusCode::OK,
        body: serde_json::json!({
            "id": "chatcmpl-aliased", "object": "chat.completion", "created": 0, "model": WIRE,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": 600, "completion_tokens": 400, "total_tokens": 1000}
        }),
    };
    let (state, server) = mock((0..4).map(|_| answered()).collect()).await;
    let card = card_of("{ input_utok: 1000, output_utok: 1000 }");
    let rig = rig(
        instance,
        RigOpts {
            members: &[(server.address().port(), 1)],
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
    let sent: serde_json::Value = serde_json::from_slice(
        &state
            .get_last_request_body()
            .expect("the upstream was dialled"),
    )
    .expect("the upstream was sent JSON");
    assert_eq!(
        sent["model"], WIRE,
        "precondition: the lane is ALIASED, or the fault is masked"
    );
    assert_eq!(rig.tokens_after().await, 1000, "the key's tokens");
    let derived = rig
        .gov
        .derived_bucket_usage(
            &rig.app.cost,
            &format!("group:{instance}-group@day"),
            "day",
            true,
            now(),
        )
        .expect("usage read");
    assert_eq!(derived.tokens, 1000, "the tokens are ledgered either way");
    assert_eq!(
        derived.spend_cents, 100,
        "1,000 tokens at 1,000 micro-units each price at the card under the config name"
    );
}

// ── GAP 4: the tap reports the end a status line cannot carry ─────────────────────────────────

/// The first frame of the streamed answer: one content delta, no usage (the original's
/// `FIRST_FRAME`).
const FIRST_FRAME: &str = r#"{"id":"chatcmpl-root","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"}}]}"#;

/// THE DOOR'S REPORT CARRIES THE END A STATUS LINE CANNOT. Door successor of
/// `plane_node.rs::the_tap_reports_the_end_a_status_line_cannot`. 1.5.5 behaviour, as the original pinned it for its two fixtures (a 2xx stream cut after
/// one content frame, and a 2xx transfer that failed before its first byte): both answer the caller
/// under a 200 status line and neither completes, so the caller holds the cut (the one relayed
/// frame, no terminator) or nothing; and the key's ledger holds no tokens. The plane ledgered nothing, so nothing bills:
/// the 2xx end's one metering row carries no token (owner ruling 2026-10-20: the plane's ledger is
/// final, cut or not; a cut does not drop the row).
///
/// RED: tokens that never streamed, a terminator the far end never reached, or a metering row
/// carrying a token that never streamed.
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
        let _published = Published(instance);
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
        let rows = metering_rows(&rig, charged_at);
        assert_eq!(rows.len(), 1, "{label}: one metering row: {rows:?}");
        assert!(
            rows[0].starts_with("m0/") && rows[0].contains(" in=0 out=0 cr=0 cw=0 "),
            "{label}: and it carries no token, as the plane ledgered none: {rows:?}"
        );
    }
}

/// The first frame of a streamed answer that carries its content, its stop and its usage together:
/// 600 input and 400 output tokens, the 1,000 the plane ledgers before the far end cuts. The usage
/// rides the stop: the chat dialect's reader takes a content chunk's `usage` only with its
/// `finish_reason` (or on a usage-only chunk).
const FIRST_FRAME_WITH_USAGE: &str = r#"{"id":"chatcmpl-root","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":600,"completion_tokens":400,"total_tokens":1000}}"#;

/// A STREAM ITS FAR END CUT AFTER ITS FIRST FRAME BILLS WHAT ITS PLANE LEDGERED. The far
/// end streams one frame carrying 600 input and 400 output tokens under a 200 head, then cuts the
/// stream before its end. The plane ledgered those 1,000 tokens, so the door takes that ledger as
/// final: the key's ledger holds the 1,000 tokens, its group's spend derives 100 cents against
/// the card (1,000 micro-units a token, no request fee), and one metering row carries 600 in and
/// 400 out. Core does not override the plane's ledger because of the cut or the caller's status.
///
/// RED: the cut stream's ledgered tokens dropped, its charge withheld, or its metering row skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_what_its_plane_ledgered_for_a_stream_cut_after_its_first_frame() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-gap-cut-stream-plane-ledger";
    let _published = Published(instance);
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
        .derived_bucket_usage(
            &rig.app.cost,
            &format!("group:{instance}-group@day"),
            "day",
            true,
            now(),
        )
        .expect("usage read");
    assert_eq!(derived.tokens, 1000, "the group's bucket holds them");
    assert_eq!(
        derived.spend_cents, 100,
        "and they are charged: 1,000 tokens at 1,000 micro-units each"
    );
    let rows = metering_rows(&rig, charged_at);
    assert_eq!(rows.len(), 1, "one metering row: {rows:?}");
    assert!(
        rows[0].starts_with("m0/") && rows[0].contains(" in=600 out=400 "),
        "the row carries what the plane ledgered: {rows:?}"
    );
}

// ── GAP 6: rerank pricing ────────────────────────────────────────────────────────

/// The open class a rerank's far end bills (`plane_node.rs`'s `SEARCH_UNITS`).
const SEARCH_UNITS: &str = "search_units";

/// The rerank card pinned at the door: `m0` pricing `search_units` at 2,000,000 nano-units (2,000
/// micro-units) each, no fee (`plane_node.rs`'s `rerank_history_on(lane, 0, Some(2_000_000))`).
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

/// A RERANK'S SEARCH UNITS REACH THE PRICE, THROUGH THE DOOR. Door successor of
/// `plane_node.rs::a_reranks_search_units_reach_the_price_on_both_books` and of the unbilled arm of `a_same_dialect_rerank_puts_identical_search_units_on_both_books`.
/// 1.5.5 behaviour, as the originals pinned it: a card pricing `search_units` at 2,000 micro-units
/// (0.2 cents) each derives 10 cents for 50 units and 0 cents for 1 unit (one unit rounds to
/// nothing); a rerank whose far end bills no units derives 0 cents.
///
/// RED: the search units dropped or priced as a flat request (10 cents read 0), or one unit
/// rounded up.
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
        let _published = Published(instance);
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
        let (status, _, answered) = rig.send("POST", word("rerank_path"), Some(body)).await;
        assert_eq!(
            status,
            200,
            "{units:?} units: served: {}",
            String::from_utf8_lossy(&answered)
        );
        assert_eq!(far.served(), 1, "{units:?} units: dialled once");

        // THE GOVERNANCE BOOK: the key's derived spend, once the unit's money settled.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut spend = key_spend(&rig);
        while spend != Ok(cents) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            spend = key_spend(&rig);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            key_spend(&rig),
            Ok(cents),
            "{units:?} search units at 0.2 cents each"
        );
    }
}

// ── STRENGTHENED: the flat fee is a client's fee ───────────────────────────────────────────────

/// A CLIENT'S DELIVERED REQUEST ON THE DOOR PAYS EXACTLY ONE FLAT FEE. Door successor of the
/// client half of `plane_node.rs::a_provider_origin_unit_posts_no_flat_fee` (its provider half is
/// the door's probe unit: `busbar-kernel` `plane_driver/tests/probe_unit_tests.rs`
/// `a_probe_recovers_a_tripped_member` asserts a probe makes no money call at all, "zero-billed",
/// though its plane reported units). The original's literal: a client's delivered request pays the
/// one flat per-request fee (`fee_units == 1`). On the door that is the fee unit the plane reported
/// on the unit's line (`fee_count == 1`), the one billable request on the key and the key's 1-cent
/// spend.
///
/// RED: no fee unit on a delivered client request, or a second one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_charges_a_client_request_exactly_one_flat_fee() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-strong-client-fee";
    let _published = Published(instance);
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

// ── STRENGTHENED: a caller that hangs up mid-dispatch keeps its fee charged ────────────────────

/// A CALLER THAT HANGS UP MID-DISPATCH KEEPS ITS FLAT FEE CHARGED, ON THE DOOR. Door successor of
/// `plane_node.rs::a_caller_that_hangs_up_mid_dispatch_keeps_its_flat_fee_charged` (MONEY-AUDIT
/// C-F1, spec §7 F13). The far end answers its head and holds its body, so the unit is parked
/// reading it; the caller's request future is dropped there. 1.5.5's dropped request never reached
/// the non-2xx refund, so, as the original pinned: the door drew the admission slot (requests 1)
/// and the 1-cent fee stays charged.
///
/// RED: the abandoned end finished as a non-2xx no client saw, and its refund took the fee back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_keeps_the_fee_of_a_caller_that_hung_up_mid_dispatch() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-strong-hang-up";
    let _published = Published(instance);
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (_state, server) = mock(vec![MockResponse::Gated {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        body: serde_json::json!({"error": {"message": "still answering", "type": "server_error"}}),
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    }])
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(server.address().port(), 1)],
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
    // The abandoned end settles once the unit's future is gone: give it the time to land.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (requests, spend, _, _) = rig.ledger_after(1).await;
    assert_eq!(requests, 1, "the door drew the admission slot");
    assert_eq!(
        spend, 1,
        "a caller that went away mid-dispatch is refunded nothing: the 1-cent fee stays charged"
    );
}

// ── STRENGTHENED: billing off serves free, writes its row, still governs ──────────────────────

/// One streamed chat (11 in, 7 out) through a door priced by `rate_card`: its status, the key's
/// spend in cents, and the key's metering rows.
async fn served_streamed(
    instance: &'static str,
    rate_card: Option<&BTreeMap<String, busbar_kernel::config::RateEntryCfg>>,
) -> (u16, i64, Vec<String>) {
    let _published = Published(instance);
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
    (status, spend, metering_rows(&rig, charged_at))
}

/// BILLING OFF SERVES FREE, WRITES ITS METERING ROW, YET STILL GOVERNS, ON THE DOOR. Door
/// successor of `plane_node.rs::billing_off_serves_free_writes_its_metering_row_reading_zero_yet_still_governs`
/// (W3.c, DECISIONS #42 + #43). As the original pinned: with no `rate_card:` a delivered request is
/// served 200 and writes the plane's counts as its metering row (11 in, 7 out, cache 0 and 0,
/// requests 1, billable 1); the money view reads them as 0, so the key's spend is the 1-cent flat
/// fee alone; the same request on a billed door writes the identical row; and a pool-ACL guard
/// still refuses with billing off, charging nothing and metering nothing.
///
/// RED: billing off refusing to serve, writing no row (or another row than billed), pricing the
/// tokens, or skipping governance.
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
    let _published = Published(instance);
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
    assert_eq!(metering_rows(&rig, charged_at), Vec::<String>::new());
    assert_eq!(far.served(), 0);
}

// ── STRENGTHENED: the unit is attributed to what the door resolved, and to nothing else ────────

/// THE DOOR ATTRIBUTES THE IDENTITY ITS AUTH RESOLVED AND INVENTS NONE. Door successor of
/// `plane_node.rs::the_loop_attributes_the_identity_the_door_resolved_and_invents_none`. Three
/// credentials through the deployment's own data door: the live bearer is admitted, its unit is
/// charged to that key (requests 1); a bearer this deployment never minted and a bearer whose lifetime has run out are
/// both refused at the door (401, the chat dialect's `invalid_api_key` refusal the wrong-key door
/// cells pin), so no unit exists: nothing is dialled, no line or record is written for either, and
/// the expired key's own ledger stays empty.
///
/// RED: a refused credential admitted, a unit charged to a key nobody presented, or a line
/// attributed to anything but the resolved key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_attributes_the_identity_its_auth_resolved_and_invents_none() {
    let _one = PUBLISHING.lock().await;
    let instance = "door-strong-identity";
    let _published = Published(instance);
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;

    // THE LIVE BEARER: admitted, and the unit is the resolved key's.
    assert_eq!(rig.chat().await.0, 200, "the deployment's own bearer");
    let (requests, _, _, _) = rig.ledger_after(1).await;
    assert_eq!(requests, 1, "the admitted unit was charged to the key");
    let records = rig.audit_records();

    // A BEARER THIS DEPLOYMENT NEVER MINTED.
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

    // A BEARER WHOSE LIFETIME HAS RUN OUT, minted on this deployment's own book for a key of its
    // own, so a unit attributed to it would be visible on that key.
    let (expired_key, expired_token) = rig
        .gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "expired".to_string(),
                ..Default::default()
            },
            1_700_000_100,
            1_700_000_000,
        )
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
        .usage_for(&rig.app.cost, &expired_key.id, now())
        .expect("usage read")
        .map_or(0, |usage| usage.requests);
    assert_eq!(
        expired_usage, 0,
        "nothing was charged to the key whose bearer expired"
    );
    let (requests, _, _, _) = rig.ledger_after(1).await;
    assert_eq!(requests, 1, "nor to the live key a second time");
}

// ── STRENGTHENED: a gate stops a unit, and a gate that passes changes nothing ─────────────────

/// A GATE THAT VETOES STOPS THE UNIT; A GATE THAT PASSES IS ASKED AND CHANGES NOTHING, ON THE
/// DOOR. Door successor of
/// `plane_node.rs::a_seated_gate_stops_the_unit_before_the_door_and_an_empty_seat_list_changes_nothing`.
/// The original's native seat list is empty on the live mount (its first assertion), because the
/// migrated gates fire AFTER the door, as 1.5.5's did (v1.5.5 `ingress/dispatch.rs` admits and
/// charges before `proxy/engine/mod.rs:946` runs the gates; the door's seat order cell
/// `serve_hook_seats.rs::migrated_request_hook_seats_after_admit_before_candidate`). So, on the
/// door, as the original pinned for both shapes: a vetoing gate is asked, the unit answers the
/// gate's 451, the upstream is never dialled and no metering row is written, its admission kept
/// and its fee refunded (spend 0, billable 0); a gate that does not veto is asked too, and the unit
/// goes on to the same served end (200, one far-end dial, one billable request).
///
/// RED: a veto that reached the far end or kept its fee, or a passing gate never consulted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_gate_stops_a_unit_and_a_passing_gate_changes_nothing() {
    let _one = PUBLISHING.lock().await;
    for (instance, reject_at_gate) in [
        ("door-strong-gate-veto", true),
        ("door-strong-gate-pass", false),
    ] {
        let _published = Published(instance);
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
                metering_rows(&rig, charged_at),
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

// ── STRENGTHENED: the far end is reached once by a served unit, never by a refused one ─────────

/// A SERVED UNIT REACHES ITS FAR END EXACTLY ONCE; A REFUSED ONE NEVER DOES, ON THE DOOR. Door
/// successor of `plane_node.rs::the_route_seam_is_driven_once_by_a_served_unit_and_never_by_a_refused_one`.
/// Three ends, three counts, each on its own deployment: refused at the pool-ACL guard before the
/// door (0), refused at the door for a spent budget (0), and served through the whole walk
/// (exactly 1: a second dial of one unit is a request the client sent once and the upstream saw
/// twice). Each unit produces a status. On the door the witness is the far end's own count (the
/// original's second witness); the node's dispatch count is reached only from its legacy answer
/// path.
///
/// RED: a refusal that dialled, or a served unit dialled twice or never.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_dials_a_served_unit_once_and_a_refused_one_never() {
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
        let _published = Published(instance);
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
    }
}
