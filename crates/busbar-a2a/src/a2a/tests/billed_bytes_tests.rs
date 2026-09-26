// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A HOP LEDGERS THE PAYLOAD BYTES IT RELAYED, BOTH WAYS**: a billed A2A byte is payload bytes
//! relayed BOTH ways per hop (request + response), class `bytes`, priced by `agents.rate_card`; no
//! card → 0.
//!
//! Before this, the plane's one charge was a `Queries` meter at amount 0: the declared `bytes` class
//! was never counted, so `Σ count × rate` over it was 0 whatever an agent moved, and a `budget:` cap
//! reached A2A traffic only through the flat per-request fee. What a payload byte IS is
//! `relay::HopBytes`'s doc: body bytes on the hop's wire, request sent + response received, headers
//! excluded.
//!
//! Every assertion goes through the real router and the recording seam, for the reason
//! `relay_tests` gives: the charge is reached from the ingress, and the byte counts are read off the
//! same recorded wire the relay handed the transport.

use super::relay_harness::*;
use busbar_kernel::{
    config::{self, groups::GroupCfg, groups::LimitCfg, groups::LimitMetric, groups::LimitWindow},
    config_validate::validate,
    cost::CostModel,
    governance::{budget_window, PLANE_LANE_SEP},
    test_support::engine_kit::CostKit,
};

fn per_day(metric: LimitMetric, amount: u64) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per: Some(LimitWindow::Day),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

/// The ledger lane a hop to `planner` is keyed on: the admitted resource, qualified by the plane, so
/// the A2A plane's own card prices it.
fn planner_lane() -> String {
    format!("{}{}agent:planner", crate::PLANE_KEY, PLANE_LANE_SEP)
}

/// The `bytes` the caller's group bucket holds on the `planner` lane, or `None` when no row exists.
fn bytes_ledgered(h: &Harness) -> Option<u64> {
    h.gov.flush_budgets();
    let now = busbar_kernel::store::now();
    let window = budget_window("day", now);
    let ledger = h.gov.store().get_usage("group:g@day", window).ok()?;
    let lane = planner_lane();
    ledger
        .models
        .iter()
        .find(|m| m.model == lane)
        .and_then(|m| m.usage_units.get("bytes").copied())
}

/// The group bucket's derived spend, through the one pricing function.
fn group_spend(h: &Harness) -> Result<i64, String> {
    let cost = h
        .cost
        .as_ref()
        .expect("a priced harness carries its cost model");
    h.gov
        .derived_bucket_usage(
            &**cost,
            "group:g@day",
            "day",
            true,
            busbar_kernel::store::now(),
        )
        .map(|u| u.spend_cents)
}

/// The request body bytes every recorded hop put on the wire.
fn request_bytes(h: &Harness) -> u64 {
    h.sent().iter().map(|r| r.body.len() as u64).sum()
}

/// `agents.rate_card` pricing `planner`'s bytes at one minor unit (10,000 micro-units) a byte.
fn a_card_pricing_planner() -> Option<Card> {
    composed_card("agents:\n  rate_card:\n    agent:planner: { units: { bytes: 10000 } }\n")
}

/// **N REQUEST BYTES + M RESPONSE BYTES LEDGER N+M `bytes`** — and with no card at all that count
/// reads 0 and nothing refuses: a `budget:` of one minor unit is never tripped by it.
#[tokio::test]
async fn a_hop_ledgers_its_request_and_response_body_bytes_and_no_card_reads_zero() {
    crate::testkit::install_test_seams();
    let answer = backend_ok();
    let h = harness_priced(
        Outcome::Answers(200, answer.clone()),
        None,
        vec![per_day(LimitMetric::Budget, 1)],
    )
    .await;

    for n in 1..=3u64 {
        let (status, body) = call(&h).await;
        assert_eq!(
            status, 200,
            "call {n}: billing off serves every call: {body}"
        );
    }
    let sent = h.sent();
    assert_eq!(sent.len(), 3, "every call made its hop");
    let n = request_bytes(&h);
    assert!(n > 0, "the recorded hops carried a body");
    let m = 3 * answer.len() as u64;
    assert_eq!(
        bytes_ledgered(&h),
        Some(n + m),
        "three hops ledger their request bodies ({n}) plus the backend's answers ({m}) verbatim \
         under the plane's declared `bytes` class (#71); before Q35 nothing was ledgered at all"
    );
    assert_eq!(
        group_spend(&h),
        Ok(0),
        "no card: A2A billing is off and the counts read 0 (#42), never refused"
    );
}

/// **AN `agents.rate_card` PRICES THE BYTES, AND A `budget:` CAP TRIPS ON A2A TRAFFIC.** One minor
/// unit a byte: the first hop's N+M bytes read as N+M minor units, and the second submission is
/// refused at the door on the budget the bytes spent — without reaching the backend. Before Q35 the
/// hop priced at 0 (flat fee 0) and the second call was served.
#[tokio::test]
async fn an_agents_card_prices_the_bytes_and_a_budget_cap_trips_on_a2a() {
    crate::testkit::install_test_seams();
    let answer = backend_ok();
    let h = harness_priced(
        Outcome::Answers(200, answer.clone()),
        a_card_pricing_planner(),
        vec![per_day(LimitMetric::Budget, 1)],
    )
    .await;

    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "call 1 is under the cap: {body}");
    let billed = request_bytes(&h) + answer.len() as u64;
    assert_eq!(bytes_ledgered(&h), Some(billed));
    assert_eq!(
        group_spend(&h),
        Ok(i64::try_from(billed).expect("small")),
        "{billed} bytes x 10,000 micro-units = {billed} minor units"
    );

    let (status, body) = call(&h).await;
    assert_eq!(
        status, 429,
        "call 2 trips the budget the agents card priced: {body}"
    );
    assert!(body.to_string().contains("budget"), "{body}");
    assert_eq!(h.sent().len(), 1, "the refused call never left");
}

/// #42 SCOPED TO THE PLANE: a PRESENT `agents.rate_card` silent about the agent the traffic hit
/// REFUSES — the first hop is served and ledgered, then the door cannot price the bucket and refuses,
/// and the bucket's usage read fails. Never a silent 0.
#[tokio::test]
async fn a_present_agents_card_silent_about_the_agent_refuses() {
    crate::testkit::install_test_seams();
    let h = harness_priced(
        Outcome::AnswersCorrelated(200, backend_ok()),
        composed_card("agents:\n  rate_card:\n    agent:payments: { units: { bytes: 10000 } }\n"),
        vec![per_day(LimitMetric::Budget, 1_000_000)],
    )
    .await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "call 1 is served: {body}");
    assert!(bytes_ledgered(&h).is_some_and(|b| b > 0));
    let (status, body) = call(&h).await;
    assert_ne!(
        status, 200,
        "call 2 is REFUSED: the agents card cannot price the bytes call 1 ledgered: {body}"
    );
    assert_eq!(h.sent().len(), 1);
    assert!(
        group_spend(&h).is_err(),
        "the usage read refuses rather than reading 0"
    );
}

/// **A STREAMED RELAY COUNTS EVERY FRAME.** The response side of a streaming hop is the sum of every
/// chunk the backend sent, not the first frame and not the last.
#[tokio::test]
async fn a_streamed_relay_counts_every_frame() {
    crate::testkit::install_test_seams();
    let frame = |result: serde_json::Value| {
        format!(
            "data: {}\n\n",
            serde_json::json!({ "jsonrpc": "2.0", "id": 11, "result": result })
        )
    };
    let frames = vec![
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "kind": "status-update",
            "status": { "state": "working" }
        })),
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "kind": "artifact-update",
            "artifact": { "artifactId": "a1", "parts": [{ "kind": "text", "text": "CHUNK ONE" }] }
        })),
        frame(serde_json::json!({
            "id": "B1", "contextId": "BC", "kind": "status-update",
            "status": { "state": "completed" }
        })),
    ];
    let streamed: u64 = frames.iter().map(|f| f.len() as u64).sum();
    let h = harness_priced(
        Outcome::Streams(frames),
        None,
        vec![per_day(LimitMetric::Budget, 1)],
    )
    .await;
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "message/stream",
        "params": {
            "message": {
                "role": "user",
                "contextId": "ctx-bytes-stream",
                "parts": [{ "kind": "text", "text": "STREAM THE PLAN" }]
            }
        }
    });
    let (status, _ct, body) = call_raw(&h, "planner", &envelope).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.matches("data:").count(), 3, "every frame was relayed");
    assert!(h.sent()[0].is_stream, "the hop went out as a stream");
    // The ledger write lands on the relay thread as the hop settles; the caller's stream ends when
    // that thread lets go of the channel, which is after the settle — but wait boundedly regardless.
    let want = request_bytes(&h) + streamed;
    let mut got = None;
    for _ in 0..200 {
        got = bytes_ledgered(&h);
        if got == Some(want) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        got,
        Some(want),
        "a stream hop ledgers its request body plus EVERY streamed frame ({streamed} bytes)"
    );
}

/// **A HOP REFUSED BEFORE THE SOCKET COUNTS NOTHING.** The CONTROL is the first submission: it
/// reached the backend (which answered 401 and tripped the breaker), so its request and the
/// backend's 6-byte refusal ARE ledgered — a hop that left moved those bytes whatever the answer
/// was. The second is refused by the tripped breaker before the socket and adds nothing.
#[tokio::test]
async fn a_hop_refused_before_the_socket_counts_nothing() {
    crate::testkit::install_test_seams();
    let h = harness_priced(
        Outcome::Answers(401, "denied".to_string()),
        None,
        vec![per_day(LimitMetric::Budget, 1)],
    )
    .await;

    let (s1, b1) = call(&h).await;
    assert_eq!(s1, 502, "the first hop reaches the dying backend: {b1}");
    let left = request_bytes(&h) + "denied".len() as u64;
    assert_eq!(
        bytes_ledgered(&h),
        Some(left),
        "the hop that left is counted"
    );

    let sent = h.sent().len();
    let (s2, b2) = call(&h).await;
    assert_eq!(s2, 503, "the tripped agent refuses before the socket: {b2}");
    assert_eq!(h.sent().len(), sent, "and the backend saw nothing");
    assert_eq!(
        bytes_ledgered(&h),
        Some(left),
        "a hop refused before the socket moved no byte and ledgers none"
    );
}

/// **`agents.fees.per_request` BOOTS AND CHARGES; `agents.fees.per_session` REFUSES** (ARCHITECT
/// ruling, fees). Each hop is admitted under the plane-qualified pool, one fee unit on the plane's
/// fee lane, so a fee of 2 reads 2 × 3 = 6 over three hops. The plane opens no session account, so a
/// session fee would charge nothing: boot and `--validate` refuse it, naming the key and the counted
/// list.
#[tokio::test]
async fn agents_fees_per_request_boots_and_charges_and_per_session_refuses() {
    crate::testkit::install_test_seams();
    let resolved = |yaml: &str| {
        let text = format!("providers: {{}}\nmodels: {{}}\n{yaml}");
        let deploy = config::deploy_from_yaml_str(&text).expect("the config parses");
        config::resolve(&deploy, &Default::default()).expect("resolves")
    };
    assert_eq!(
        validate(&resolved("agents:\n  fees: { per_session: 40 }\n")),
        Err(vec![
            "agents.fees.per_session is not counted by this plane (counted: per_request); \
             remove it"
                .to_string()
        ])
    );
    let root = resolved("agents:\n  fees: { per_request: 2 }\n");
    assert_eq!(validate(&root), Ok(()), "a counted fee boots");

    let limits = vec![per_day(LimitMetric::Budget, 1_000)];
    let h = harness_priced(Outcome::Answers(200, backend_ok()), None, limits.clone()).await;
    for n in 1..=3 {
        let (status, body) = call(&h).await;
        assert_eq!(status, 200, "call {n}: {body}");
    }
    let group = GroupCfg {
        limits,
        ..Default::default()
    };
    let groups = [("g".to_string(), group)].into();
    let cost = CostModel::resolve_parts(None, 0, &groups).with_plane_fees(&root.plane_fees);
    let priced: std::sync::Arc<dyn CostKit> = std::sync::Arc::new(cost);
    let now = busbar_kernel::store::now();
    let read = h
        .gov
        .derived_bucket_usage(&*priced, "group:g@day", "day", true, now)
        .expect("the group reads");
    assert_eq!(
        read.spend_cents, 6,
        "three hops at agents.fees.per_request 2"
    );
}
