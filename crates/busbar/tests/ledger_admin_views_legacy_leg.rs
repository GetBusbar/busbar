// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ledger views exist on the root leg only, and the legacy leg has never heard of them.
//!
//! ## What is actually at stake
//!
//! The five `/api/v1/admin/ledger/*` operations are 1.6.0-additive: they are served by the
//! composition root's own loop, which a node runs only when it was built with the `root-admin`
//! feature. A node built without it serves the administrative surface the previous release served,
//! and that surface has no ledger route — so the correct answer on those paths is not a 501, not an
//! empty 200 and not a hint that the operation exists elsewhere. It is exactly the answer any other
//! path the surface does not have already gets.
//!
//! That answer is pinned. The shadow oracle records it as `http.crosscut|admin-unknown|admin`
//! against the previous release's binary: a 404 whose body is the nested not-found envelope. This
//! test asserts the ledger paths land on it, and it asserts it by COMPARISON with a path nobody has
//! ever proposed adding — not against a transcribed literal, which would keep passing on the day
//! the envelope changed and the ledger paths were left behind on the old one.
//!
//! ## Why this is an integration test and not a unit one
//!
//! The claim is about a router, and the only honest way to ask a router what it answers is to serve
//! it and ask. The unit tests beside the loop can prove the loop never sees these paths; only this
//! one can prove the surface underneath answers them the way it answers anything else it has never
//! heard of.

use std::net::SocketAddr;

/// The five paths this row adds, and the one path this test uses as its control.
///
/// The control is deliberately absurd. It has to be a path nobody would ever mount, because the
/// whole force of the comparison is that the ledger paths are indistinguishable from a path that
/// does not exist — and a control that later became a real route would turn this test green for the
/// wrong reason.
const LEDGER_PATHS: &[&str] = &[
    "/api/v1/admin/ledger/totals",
    "/api/v1/admin/ledger/checkpoints",
    "/api/v1/admin/ledger/reconciliation",
    "/api/v1/admin/ledger/migration",
    "/api/v1/admin/ledger/openapi.json",
];

/// A path the administrative surface has never mounted and never will.
const A_PATH_THAT_DOES_NOT_EXIST: &str = "/api/v1/admin/nope";

/// One response, reduced to the three things the oracle compares.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: String,
}

async fn ask(addr: SocketAddr, path: &str) -> Answer {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .send()
        .await
        .expect("the surface answers");
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

/// On the legacy leg, every ledger path answers exactly as a path that does not exist.
#[tokio::test]
async fn the_legacy_admin_surface_has_never_heard_of_a_ledger_path() {
    busbar_core::metrics::init();
    // An OPEN admin posture, so that a path which DID exist would reach its handler rather than an
    // authentication refusal. Without this the test would pass on a surface that had grown all five
    // routes and simply refused the credential.
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

    let unknown = ask(addr, A_PATH_THAT_DOES_NOT_EXIST).await;
    assert_eq!(
        unknown.status, 404,
        "the control is not the unknown-path answer this test compares against"
    );

    for path in LEDGER_PATHS {
        assert_eq!(
            ask(addr, path).await,
            unknown,
            "{path} does not answer the way an unknown admin path answers"
        );
    }

    // The control from the other direction: a path the surface DOES have answers differently, so
    // the green above is the ledger paths being absent rather than the surface answering 404 to
    // everything.
    let known = ask(addr, "/api/v1/admin/info").await;
    assert_ne!(
        known.status, 404,
        "the surface answered 404 to an operation it has always had"
    );

    serving.abort();
}

/// The 1.5.5 document the surface serves has no ledger path in it either.
///
/// The other half of "additive": the new operations are absent from the pinned document as well as
/// from the router, so a 1.5.5 client that reads `openapi.json` to discover what a node can do gets
/// the same list it always got. The operations are described in a document of their own, which the
/// root-leg tests check against the closed table.
#[tokio::test]
async fn the_pinned_document_gained_no_ledger_path() {
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

    let served = ask(addr, "/api/v1/admin/openapi.json").await;
    assert_eq!(served.status, 200, "the surface serves its document");
    let document: serde_json::Value =
        serde_json::from_str(&served.body).expect("the served document is JSON");
    let paths = document["paths"].as_object().expect("it declares paths");

    for path in LEDGER_PATHS {
        assert!(
            !paths.contains_key(*path),
            "{path} appears in the document whose bytes are pinned"
        );
    }
    assert!(
        !paths.keys().any(|p| p.starts_with("/api/v1/admin/ledger")),
        "the pinned document has grown a ledger path"
    );
    // Not a vacuous absence: the document is the real one, with the operations it has always had.
    assert!(
        paths.contains_key("/api/v1/admin/usage"),
        "the served document is not the administrative document"
    );

    serving.abort();
}
