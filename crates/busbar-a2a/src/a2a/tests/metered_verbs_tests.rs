// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **EVERY VERB THAT REACHES A HANDLER LEAVES A LEDGER ROW.**
//!
//! Two calls on this plane did work and were billed nothing, for every call, forever:
//!
//! * `GetExtendedAgentCard` on `POST /a2a` — the catalogue card. It is answered before an agent is
//!   selected, and "answered early" had quietly become "answered for free". It reads this caller's
//!   whole catalogue and builds a document out of it.
//! * `ListTasks` — a scan of every task the caller owns, which is the most expensive READ on the
//!   plane. Its own section header in `receive` claimed it sat "AFTER admission and the meter";
//!   admission ran, and then the arm returned ABOVE the plane's one `meter_charge`.
//!
//! A verb no deployment can see, cap or bill is a verb an unbounded caller can sit on. These read
//! the LEDGER, which is where an operator sees it, rather than a counter inside the handler.
//!
//! **Every assertion here goes through the real router and a real socket**, for the reason
//! `relay_tests` gives: the meter is reached from the ingress, and a test that called the handler
//! directly would pass against a router that never routed there.
//!
//! The row's shape is asserted as well as its existence, because the two ways to "fix" an unmetered
//! verb badly are to bill it under a resource nobody can attribute and to bill it as if it had made
//! a hop. See `receive::PLANE_POOL` for why the catalogue card's subject is the plane pool, and
//! `receive::meter_request` for why the amount is zero.

use super::relay_harness::*;

/// Every metering row this plane wrote in the current bucket.
async fn a2a_rows(h: &Harness) -> Vec<busbar_contract::store::MeteringRow> {
    h.gov.flush_metering();
    h.gov
        .store()
        .list_metering(busbar_substrate::governance::metering_bucket(
            busbar_substrate::store::now(),
        ))
        .expect("metering reads back")
        .into_iter()
        .filter(|r| r.provider == "a2a")
        .collect()
}

/// POST one envelope to the plane's OWN endpoint — the catalogue mount, where no agent is named.
async fn call_catalogue(h: &Harness, body: &serde_json::Value) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

fn card_call() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "GetExtendedAgentCard",
        "params": {}
    })
}

fn list_call() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "ListTasks",
        "params": {}
    })
}

/// **THE CATALOGUE CARD IS BILLED, AND IT IS BILLED TO THE PLANE POOL.**
///
/// The verb has no agent — that is what it is FOR — so it has no `agent:<id>` to attribute a row
/// to, and that absence is what kept it off the ledger. The subject is the plane's own pool
/// (`receive::PLANE_POOL`, read from the codec's config section rather than restated), which cannot
/// collide with a member line because members are keyed through
/// `busbar_substrate::store::agent_key` and carry an `agent:` prefix.
///
/// The counts are asserted too. `requests` is 1 — the accrual — and every token field is 0, because
/// the kernel's flat per-request fee needs a SELECTED UPSTREAM and a relayed response frame, and a
/// verb busbar answers out of its own state has neither. Billing this as though it had made a hop
/// would be the other way to get this wrong.
#[tokio::test]
async fn the_catalogue_card_verb_is_metered_against_the_plane_pool() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call_catalogue(&h, &card_call()).await;
    assert_eq!(status, 200, "the card is still answered: {body}");
    assert!(
        body.get("result").is_some(),
        "the card verb must still return a card, not merely a bill: {body}"
    );

    let rows = a2a_rows(&h).await;
    assert_eq!(
        rows.len(),
        1,
        "the catalogue card reached a handler, read this caller's whole catalogue and built a \
         document, and left NO ledger row — it was the one call on this plane an operator could \
         not see, cap or bill: {rows:?}"
    );
    assert_eq!(
        rows[0].model, "agents",
        "the card names no agent, so it is billed to the PLANE POOL — this plane's config section, \
         which cannot collide with an `agent:`-prefixed member line in the same ledger"
    );
    assert_eq!(rows[0].requests, 1, "one call, one request accrual");
    assert_eq!(
        (
            rows[0].tokens_input,
            rows[0].tokens_output,
            rows[0].tokens_cache_read,
            rows[0].tokens_cache_write
        ),
        (0, 0, 0, 0),
        "a locally-answered verb selects no upstream and relays no frame, so the kernel's flat \
         per-request fee cannot land on it however it is asked"
    );
}

/// **AND `ListTasks` IS BILLED, UNDER THE AGENT IT WAS ADMITTED ON.**
///
/// Unlike the card, this arm sits after admission and already HAS the agent it was admitted against
/// — so the row is the ordinary `agent:<id>` line every other admitted call writes, and the only
/// thing that was missing was the charge itself.
///
/// The `contextId`-free scan is the most expensive read on the plane; before this it cost the
/// caller nothing at all.
#[tokio::test]
async fn list_tasks_is_metered_under_the_agent_it_was_admitted_on() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call_agent(&h, "planner", &list_call()).await;
    assert_eq!(status, 200, "the list is still answered: {body}");

    let rows = a2a_rows(&h).await;
    assert_eq!(
        rows.len(),
        1,
        "a locally-answered `ListTasks` returned above the plane's one `meter_charge`, so a scan \
         of every task the caller owns was free, for every call: {rows:?}"
    );
    assert_eq!(
        rows[0].model, "agent:planner",
        "this arm was admitted against an agent, so it bills the agent — the plane pool is for the \
         verbs that have no agent, not for every local answer"
    );
    assert_eq!(rows[0].requests, 1, "one call, one request accrual");
}

/// **THE CONTROL.** A relayed hop still writes exactly ONE row, under the agent, and the two new
/// charges have not turned into a second charge on the path that was already correct.
///
/// Without this, "meter everything" would pass the two tests above by billing every call twice.
#[tokio::test]
async fn an_ordinary_hop_is_still_metered_exactly_once() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");

    let rows = a2a_rows(&h).await;
    assert_eq!(
        rows.len(),
        1,
        "the hop must still be metered exactly once: {rows:?}"
    );
    assert_eq!(rows[0].model, "agent:planner");
    assert_eq!(rows[0].requests, 1);
}
