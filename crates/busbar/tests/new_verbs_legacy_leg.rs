// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seventeen 1.6.0 verbs exist on no legacy route, and this is what that costs today.
//!
//! ## What is actually at stake
//!
//! The composition root's admin leg GATES all seventeen of the 1.6.0-additive verbs: a request to
//! one of their paths is resolved against `busbar_plane_admin::verbs::resolve`, walked through the
//! real auth chain, scope-checked, rate-classed, and put past the operator-ceremony and dual-control
//! gates. Three of them — `chain_break`, `store_restore`, `reseal_epoch_floor` — then land on the
//! `Store` seam and are answered by the loop. The other fourteen are handed to
//! `Governance::execute_new_verb`, which re-serves them on the legacy administrative router.
//!
//! That router has never had a route for any of them. So the fourteen pass every gate the design
//! put in front of them and are then told the resource does not exist.
//!
//! This test pins that. It is not a complaint about the 404 — an absent route SHOULD 404, and the
//! ledger views' own test beside this one asserts exactly that for the five paths the loop does
//! serve. It is a pin on WHICH of the seventeen are in that state, so that the day one of them
//! grows a real answer, the row moves here first and deliberately rather than drifting.
//!
//! The `set_operator_key` row is the one with teeth. `busbar_unit_verbs::ADMITTED_UNDER_UNSET`
//! names it as one of the two verbs a node with no sealed operator key may still run — it is the
//! ceremony's own bootstrap, the thing the architecture document says must always be reachable so
//! that a fleet can be brought under the key. It is admitted by every gate and then 404s.
//!
//! ## Why this is an integration test and not a unit one
//!
//! The claim is about a router, and the only honest way to ask a router what it answers is to serve
//! it and ask. The unit tests beside the loop prove which verbs the loop routes where; only this one
//! can prove what the surface underneath says when the loop hands a verb back to it.

use std::net::SocketAddr;

/// The three of the seventeen the loop answers itself, from `Store`, without asking any router.
///
/// Named rather than counted, because "the loop serves three" is the fact under test in the
/// negative: every OTHER new verb's path must reach the legacy surface, and if one of these three
/// ever stopped being loop-served it would silently join them.
const LOOP_SERVED_VERBS: &[&str] = &["chain_break", "store_restore", "reseal_epoch_floor"];

/// A path the administrative surface has never mounted and never will.
///
/// The same control the ledger-views test uses, and for the same reason: the force of the
/// comparison is that the new-verb paths are indistinguishable from a path that does not exist, and
/// a control that later became a real route would turn this test green for the wrong reason.
const A_PATH_THAT_DOES_NOT_EXIST: &str = "/api/v1/admin/nope";

/// One response, reduced to the three things the oracle compares.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: String,
}

/// Ask the surface, with the method the plane's own table declares for the row.
///
/// The method matters here in a way it does not for the ledger views. Those are all `GET`; the
/// seventeen are a mix, and asking a `POST` row with a `GET` would collect a 405 from a route that
/// existed rather than the 404 of one that does not — which is a different claim, and the weaker of
/// the two.
async fn ask(addr: SocketAddr, method: &str, path: &str) -> Answer {
    let url = format!("http://{addr}{path}");
    let request = match method {
        "GET" => reqwest::Client::new().get(url),
        "POST" => reqwest::Client::new().post(url).body(""),
        other => panic!("the table declares a method this test cannot drive: {other}"),
    };
    let response = request.send().await.expect("the surface answers");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let body = response.text().await.expect("a body");
    Answer {
        status,
        content_type,
        body,
    }
}

/// Every row of the closed table the executing unit calls a NEW verb, taken from the two crates
/// rather than transcribed.
///
/// The plane holds the method and the path; the unit holds which verbs are the seventeen. Joining
/// them here rather than writing a literal list is what keeps this test honest when the plane's
/// flagged judgment call about those bindings is revisited: the paths move, the test follows.
fn new_verb_rows() -> Vec<busbar_plane_admin::verbs::ResolvedVerb> {
    let new_verb_names: Vec<String> = busbar_unit_verbs::NEW_VERBS
        .iter()
        .map(|verb| format!("{verb:?}"))
        .collect();
    // The unit spells its verbs `ChainBreak`; the plane spells the same row `chain_break`. Comparing
    // the two with the separators and the case removed joins them on the letters both crates copied
    // out of the design, and on nothing either crate is free to restyle.
    let squashed = |name: &str| name.replace('_', "").to_ascii_lowercase();
    let rows: Vec<_> = busbar_plane_admin::verbs::table()
        .into_iter()
        .filter(|row| {
            new_verb_names
                .iter()
                .any(|name| squashed(name) == squashed(row.verb))
        })
        .collect();
    assert_eq!(
        rows.len(),
        busbar_unit_verbs::NEW_VERBS.len(),
        "the plane's table and the unit's list disagree about how many new verbs there are"
    );
    rows
}

/// On the legacy leg, every new-verb path the loop hands back answers exactly as a path that does
/// not exist.
#[tokio::test]
async fn the_legacy_admin_surface_has_never_heard_of_a_new_verb_path() {
    busbar_core::metrics::init();
    // An OPEN admin posture, so that a path which DID exist would reach its handler rather than an
    // authentication refusal. Without this the test would pass on a surface that had grown all
    // seventeen routes and simply refused the credential.
    let app = busbar_core::test_support::TestApp::new()
        .admin_chain(vec![])
        .build();
    let (_data, admin, _handle) =
        busbar_core::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let addr = listener.local_addr().expect("an address");
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await });

    let unknown = ask(addr, "GET", A_PATH_THAT_DOES_NOT_EXIST).await;
    assert_eq!(
        unknown.status, 404,
        "the control is not the unknown-path answer this test compares against"
    );

    let rows = new_verb_rows();
    for row in &rows {
        let answer = ask(addr, row.method, row.template).await;
        assert_eq!(
            answer.status, unknown.status,
            "{} {} does not answer the way an unknown admin path answers",
            row.method, row.template
        );
        assert_eq!(
            answer.content_type, unknown.content_type,
            "{} {} answers 404 in a different envelope from an unknown admin path",
            row.method, row.template
        );
    }

    // Which rows this is a statement about. Fourteen of the seventeen are handed back to this
    // surface by `execute_new_verb` and get the answer above; the three recovery verbs never reach
    // it at all, because the loop answers them from `Store`. Both halves are asserted, so a change
    // that moved a verb from one half to the other has to say so here.
    let loop_served = rows
        .iter()
        .filter(|row| {
            LOOP_SERVED_VERBS
                .iter()
                .any(|verb| row.verb.eq_ignore_ascii_case(verb))
        })
        .count();
    assert_eq!(
        loop_served,
        LOOP_SERVED_VERBS.len(),
        "a verb the loop answers from its own store is no longer in the table"
    );
    assert_eq!(
        rows.len() - loop_served,
        14,
        "the number of new verbs answered by a 404 from the legacy surface has changed"
    );

    // The control from the other direction: a path the surface DOES have answers differently, so
    // the green above is the new-verb paths being absent rather than the surface answering 404 to
    // everything.
    let known = ask(addr, "GET", "/api/v1/admin/info").await;
    assert_ne!(
        known.status, 404,
        "the surface answered 404 to an operation it has always had"
    );

    serving.abort();
}

/// The 1.5.5 document the surface serves has no new-verb path in it either.
///
/// The other half of "additive": the seventeen are absent from the pinned document as well as from
/// the router, so a 1.5.5 client that reads `openapi.json` to discover what a node can do gets the
/// same list it always got. This is the byte-level half of the claim — the document's bytes are
/// pinned by the shadow oracle's `admin.ops|GetOpenapiJson|ok` cell, and a route that appeared here
/// would move them.
#[tokio::test]
async fn the_pinned_document_gained_no_new_verb_path() {
    busbar_core::metrics::init();
    let app = busbar_core::test_support::TestApp::new()
        .admin_chain(vec![])
        .build();
    let (_data, admin, _handle) =
        busbar_core::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let addr = listener.local_addr().expect("an address");
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await });

    let served = ask(addr, "GET", "/api/v1/admin/openapi.json").await;
    assert_eq!(served.status, 200, "the surface serves its document");
    let document: serde_json::Value =
        serde_json::from_str(&served.body).expect("the served document is JSON");
    let paths = document["paths"].as_object().expect("it declares paths");

    for row in new_verb_rows() {
        assert!(
            !paths.contains_key(row.template),
            "{} appears in the document whose bytes are pinned",
            row.template
        );
    }
    // Not a vacuous absence: the document is the real one, with the operations it has always had.
    assert!(
        paths.contains_key("/api/v1/admin/usage"),
        "the served document is not the administrative document"
    );

    serving.abort();
}
