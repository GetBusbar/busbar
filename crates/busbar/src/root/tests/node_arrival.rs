// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARRIVAL-WINDOW CELLS on the door path: a unit's arrival is read once, from the node's
//! clock, and the windows it is admitted and billed in are the ones that reading names, never the
//! clock as it stands when the money lands.

use std::sync::Arc;

use axum::http::StatusCode;
use busbar_kernel::ManualClock;

use super::node_rig::{far_end, node_rig, reply, NodeRigOpts, LANE, POOL};
use crate::root::plane_node::Arrived;

const FEE_CENTS: i64 = 1;
const EPOCH: u64 = 1_700_000_000;

fn chat() -> serde_json::Value {
    serde_json::json!({
        "model": POOL,
        "messages": [{"role": "user", "content": "hi"}],
    })
}

fn answer() -> String {
    reply(
        "application/json",
        &serde_json::json!({
            "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
            "model": LANE,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        })
        .to_string(),
    )
}

fn clock_at(ms: u64) -> Arc<ManualClock> {
    let clock = Arc::new(ManualClock::new());
    clock.advance(ms);
    clock
}

fn budget_per_day(amount: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount,
        per: Some(busbar_kernel::config::groups::LimitWindow::Day),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unit_arriving_at_a_window_boundary_bills_in_the_window_it_arrived_in() {
    use busbar_kernel::governance::metering_bucket;

    let charged_at = busbar_kernel::store::now();
    let arrival_secs = metering_bucket(charged_at) - 1;
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

    let card = std::collections::BTreeMap::from([(
        LANE.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 1.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let rig = node_rig(
        "arrival-window-bills",
        far_end(answer()).await,
        NodeRigOpts {
            clock: Some(clock_at(arrived.ms()) as Arc<dyn busbar_kernel::Clock>),
            rate_card: Some(card),
            fee_cents: FEE_CENTS,
            ..Default::default()
        },
    )
    .await;

    let resp = rig.open("/v1/chat/completions", &chat()).await;
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    tokio::task::yield_now().await;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admission_check_reads_the_arrival_window_and_not_the_clock() {
    use busbar_kernel::governance::SECS_PER_DAY;
    let past_day = EPOCH;
    assert_ne!(
        past_day / SECS_PER_DAY,
        busbar_kernel::store::now() / SECS_PER_DAY,
        "precondition: the arrival day is not today"
    );
    let clock = clock_at(past_day * 1_000);
    let rig = node_rig(
        "arrival-window-admits",
        far_end(answer()).await,
        NodeRigOpts {
            clock: Some(Arc::clone(&clock) as Arc<dyn busbar_kernel::Clock>),
            fee_cents: FEE_CENTS,
            group_limit: Some(budget_per_day(FEE_CENTS.unsigned_abs())),
            ..Default::default()
        },
    )
    .await;
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

    let refused = rig.open("/v1/chat/completions", &chat()).await;
    assert_eq!(
        refused.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the unit is refused against the window it arrived in, where the spend lives"
    );
    clock.advance(busbar_kernel::store::now_ms() - past_day * 1_000);
    let served = rig.open("/v1/chat/completions", &chat()).await;
    let status = served.status();
    let _ = axum::body::to_bytes(served.into_body(), usize::MAX).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "today's window is empty, so a unit arriving now is admitted"
    );
}
