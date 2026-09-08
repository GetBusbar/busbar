// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which of the 88 administrative operations the loop owns, and which the surface underneath still
//! answers — as a table joined from the two crates that declare them, not as a sentence.
//!
//! ## Why this pin exists beside the other one
//!
//! `new_verbs_legacy_leg.rs` pins one row of this question: of the seventeen 1.6.0-additive verbs,
//! three are answered by the loop and fourteen reach a surface that has never had a route for them.
//! It says nothing about the other seventy-one, and the sixty-six legacy operations are the ones the
//! admin leg's migration is actually about — each of them is a verb the loop will one day produce the
//! answer for and the surface underneath will stop answering, and the two halves of that have to
//! become true in the same commit or one request has two answers.
//!
//! So the claim under test here is the WHOLE partition, over every row of
//! `busbar_plane_admin::verbs::table()`:
//!
//! | side | how it is decided | today |
//! |---|---|---|
//! | the loop answers, and the surface has no route | the operation is a ledger view or a recovery verb | 8 |
//! | the surface answers, and the loop hands it back | everything else that is mounted | 66 |
//! | nobody answers | gated, then `404` — the shipped defect the sibling pin names | 14 |
//!
//! ## Why it is derived and then measured, rather than written down
//!
//! Every column comes from a crate that owns it. The paths and methods are the plane's table. Which
//! verbs are ledger views is the executing unit's `LEDGER_VERBS`. Which are recovery verbs is named
//! here for the reason the sibling pin gives for naming the same three: "the loop serves three" is a
//! fact under test in the negative, and counting them would let one silently leave.
//!
//! Then the derivation is MEASURED. The test serves the administrative surface and asks it, path by
//! path with the method the table declares, which of the 88 it has a route for — and requires that
//! set to be exactly the rows this file derived as the surface's. A table checked only against
//! itself would agree with any code; this one is checked against a running router, which is the only
//! thing that can say what a router answers.
//!
//! ## The phantom-endpoint guard lives here now
//!
//! `busbar-core` used to hold one of its own: a loop over `V1_GET_PATHS` — the const its OpenAPI
//! document is emitted from — asking its own router whether each documented GET resolves. That is a
//! crate checking itself, and it has exactly one failure mode the admin leg's migration guarantees:
//! a verb that crosses leaves that router, so a document the COMPOSITION serves correctly is called
//! a phantom by a crate that is no longer the thing answering.
//!
//! The claim is the same claim this pin already makes, so it is made here instead, over the served
//! document rather than over a const: every GET the composition DOCUMENTS is answered by the loop or
//! by the surface underneath, and never by both. Both directions are live — a documented path
//! nobody serves is red, and a documented path both serve is red.
//!
//! ## What has to change here when a verb crosses
//!
//! Exactly two things, and they are the point of the file. The verb moves out of the surface's row
//! and into the loop's, and the counts below move with it. A crossing that changed the loop without
//! removing the route leaves the verb answered twice and this test red on the second half; a
//! deletion that removed the route without the loop taking it over leaves it answered by nobody and
//! this test red on the first. Neither is expressible as an edit that looks accidental.

use std::collections::BTreeSet;
use std::net::SocketAddr;

/// The path the composition serves its own discovery document at.
///
/// Named rather than spelled at the two call sites, because it is the one row of the table this
/// file both ASKS and READS: the answer to this request is the list of every other request the
/// composition claims to answer.
const OPENAPI_PATH: &str = "/api/v1/admin/openapi.json";

/// The three of the eighty-eight whose effect lands on `Store` through the executing unit's own
/// per-verb entry points, so the governance seam — and therefore the surface underneath — is never
/// reached.
///
/// Named rather than counted, for the reason the sibling pin gives: every OTHER verb's path must
/// reach the surface, and a verb that stopped being loop-served would silently join them.
const RECOVERY_VERBS: &[&str] = &["chain_break", "store_restore", "reseal_epoch_floor"];

/// A path the administrative surface has never mounted and never will — the control the two other
/// admin pins use, and for the same reason: "the surface has no route for this" is only a claim if
/// there is a known-absent path to compare the answer against.
const A_PATH_THAT_DOES_NOT_EXIST: &str = "/api/v1/admin/nope";

/// The plane spells a row `get_audit`; the unit spells the same operation `GetAudit`. Comparing the
/// two with separators and case removed joins them on the letters both crates copied out of the
/// design, and on nothing either is free to restyle.
fn squashed(name: &str) -> String {
    name.replace('_', "").to_ascii_lowercase()
}

/// Whether the loop produces this verb's answer itself.
///
/// The two closed sets the composition root branches on, read from where each is defined: the
/// executing unit's ledger views, and the three recovery verbs above.
fn loop_answers(verb: &str) -> bool {
    if RECOVERY_VERBS.iter().any(|v| v.eq_ignore_ascii_case(verb)) {
        return true;
    }
    busbar_unit_verbs::LEDGER_VERBS
        .iter()
        .any(|v| squashed(&format!("{v:?}")) == squashed(verb))
}

/// Ask a FRESH administrative surface one question, and take down the surface again.
///
/// A new one per question, which is not fastidiousness. The mutation rate limiter is held on `App`,
/// it counts FAILED attempts on purpose (probing 404s spends the same budget as mutating, which is
/// the anti-enumeration rule), and it runs in the auth middleware BEFORE any routing happens. Ask
/// one surface about all eighty-eight rows and the config-class budget of ten is gone by the
/// thirteenth, after which every remaining mutating row answers `429` — an answer that says the
/// middleware ran and says nothing whatsoever about whether the route exists. The measurement would
/// then depend on the order the table happens to be in.
///
/// The limiter is per-`App`, so a surface that has been asked nothing has spent nothing.
async fn ask_a_fresh_surface(method: &str, path: &str) -> (u16, String) {
    // An OPEN admin posture, so a path that DID exist reaches its handler rather than an
    // authentication refusal. Without this every row would answer `401` and this would prove nothing
    // about which routes are mounted.
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
    let answer = answer_of(addr, method, path).await;
    serving.abort();
    answer
}

/// What the surface answers, for one row asked with the method its own table declares.
///
/// The method matters. Asking a `POST` row with a `GET` collects the `405` of a route that EXISTS
/// rather than the answer of one that does not, which is the opposite of the claim being measured.
///
/// The BODY comes back with the status because the status alone cannot answer the question. A
/// mounted route asked about a resource that is not there answers `404` too, and it is a genuine
/// `404` from a genuine handler — thirteen of the sixty-six do exactly that when asked about a name
/// no deployment uses. What distinguishes them is what they SAY: the router's unmatched-path
/// fallback renders one fixed envelope, and a handler that looked for something and did not find it
/// names the thing it looked for.
async fn answer_of(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    let request = match method {
        "GET" => client.get(url),
        "POST" => client.post(url).body(""),
        "PUT" => client.put(url).body(""),
        "PATCH" => client.patch(url).body(""),
        "DELETE" => client.delete(url),
        other => panic!("the table declares a method this test cannot drive: {other}"),
    };
    let response = request.send().await.expect("the surface answers");
    let status = response.status().as_u16();
    let body = response.text().await.expect("a body");
    (status, body)
}

/// A concrete path for a row whose template names parameters.
///
/// A template is not a request. `/api/v1/admin/keys/{id}` is not a path a client can send, and
/// sending it literally would ask the router about a resource named `{id}` — which, for a route that
/// exists, is exactly the same question with the same answer shape, and for a route that does not
/// exist is still a `404`. Substituting a name keeps the request well-formed and keeps the two
/// answers distinguishable, which is all this test reads from them.
fn concrete(template: &str) -> String {
    let mut out = String::with_capacity(template.len());
    for (i, segment) in template.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if segment.starts_with('{') && segment.ends_with('}') {
            out.push_str("a-name-no-deployment-uses");
        } else {
            out.push_str(segment);
        }
    }
    out
}

/// The documented GET paths that belong to a DIFFERENT plane's surface, named in full.
///
/// The admin surface carries one named-definition map per plane that declares one, mounted from the
/// plane REGISTRY rather than from this plane's closed table: `tools:` is the MCP plane's and
/// `agents:` is the A2A plane's. They are documented in the same discovery document because there is
/// one document, and they are not rows of the eighty-eight because the eighty-eight are the admin
/// plane's own.
///
/// Named rather than skipped by a pattern, for the reason every other set in this file is named: a
/// pattern would let a genuinely phantom path join them by being spelled the right way, and the
/// count is small enough to write down.
const ANOTHER_PLANES_SURFACE: &[&str] = &[
    "/api/v1/admin/agents",
    "/api/v1/admin/agents/{name}",
    "/api/v1/admin/tools",
    "/api/v1/admin/tools/{name}",
    "/api/v1/admin/tools/{name}/changes",
    "/api/v1/admin/tools/{name}/health",
];

/// Every GET path the SERVED discovery document claims the composition answers.
///
/// Read off the document the composition actually serves rather than off a table in a source file,
/// which is the whole reason this guard could move here: `busbar-core` used to hold the same claim
/// as a loop over its own `V1_GET_PATHS` const against its own router, and that pairing can only
/// ever say whether one crate is self-consistent. A verb that CROSSES leaves that router, and the
/// core-side guard would then call the composition's own document a phantom.
///
/// Only GETs, and that is a rule rather than an omission: this asks the composition every path it
/// collects, and asking a mutating operation whether it is mounted is performing it. The retired
/// core-side guard drew the line in the same place and for the same reason.
async fn documented_gets() -> Vec<String> {
    let (status, body) = ask_a_fresh_surface("GET", OPENAPI_PATH).await;
    assert_eq!(
        status, 200,
        "the composition does not serve its own discovery document: {body}"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&body).expect("the served discovery document parses");
    let paths = doc["paths"]
        .as_object()
        .expect("the served discovery document has a paths object");
    let mut documented: Vec<String> = paths
        .iter()
        .filter(|(_, item)| item["get"].is_object())
        .map(|(path, _)| path.clone())
        .collect();
    documented.sort();
    assert!(
        !documented.is_empty(),
        "the served discovery document claims no GET at all, so this guard would assert nothing"
    );
    documented
}

/// The whole partition, derived from the two crates and then measured against a running surface.
#[tokio::test]
async fn the_eighty_eight_are_split_between_the_loop_and_the_surface() {
    busbar_core::metrics::init();

    let absent = ask_a_fresh_surface("GET", A_PATH_THAT_DOES_NOT_EXIST).await;
    assert_eq!(
        absent.0, 404,
        "the control is not the answer an unmounted admin path gives"
    );
    assert!(
        absent.1.contains(r#""code":"not_found""#),
        "the control does not carry the frozen envelope this test compares against: {}",
        absent.1
    );

    let table = busbar_plane_admin::verbs::table();
    assert_eq!(
        table.len(),
        88,
        "the plane's table is no longer the 88 operations this partition covers"
    );

    // THE JOIN. Every row of the plane's table has to be a verb the executing unit knows, or the two
    // crates are describing different surfaces and nothing below means anything.
    let unit_verbs: BTreeSet<String> = busbar_unit_verbs::LEGACY_VERBS
        .iter()
        .map(|row| squashed(&format!("{:?}", row.verb)))
        .chain(
            busbar_unit_verbs::NEW_VERBS
                .iter()
                .chain(busbar_unit_verbs::LEDGER_VERBS.iter())
                .map(|v| squashed(&format!("{v:?}"))),
        )
        .collect();
    for row in &table {
        assert!(
            unit_verbs.contains(&squashed(row.verb)),
            "the plane declares `{}` and the executing unit has never heard of it",
            row.verb
        );
    }

    // THE MEASUREMENT. Three buckets, each named by what it means rather than by a number.
    let mut loop_owned = Vec::new();
    let mut surface_answers = Vec::new();
    let mut nobody_answers = Vec::new();
    for row in &table {
        let mounted = ask_a_fresh_surface(row.method, &concrete(row.template)).await != absent;
        match (loop_answers(row.verb), mounted) {
            (true, false) => loop_owned.push(row.verb),
            (false, true) => surface_answers.push(row.verb),
            (false, false) => nobody_answers.push(row.verb),
            (true, true) => panic!(
                "`{}` is answered by the loop AND still mounted on the surface underneath: one \
                 request, two answers",
                row.verb
            ),
        }
    }

    assert_eq!(
        loop_owned.len(),
        8,
        "the loop answers a different number of operations than it did: {loop_owned:?}"
    );
    assert_eq!(
        surface_answers.len(),
        66,
        "the surface underneath answers a different number of operations than it did"
    );
    assert_eq!(
        nobody_answers.len(),
        14,
        "the number of operations gated by every gate and then answered by nobody has changed: \
         {nobody_answers:?}"
    );
    assert_eq!(
        loop_owned.len() + surface_answers.len() + nobody_answers.len(),
        table.len(),
        "the three buckets do not account for the whole table"
    );

    // The eight, named. A count would let one verb leave the loop as another arrived.
    let mut owned: Vec<&str> = loop_owned.clone();
    owned.sort_unstable();
    assert_eq!(
        owned,
        vec![
            "chain_break",
            "get_ledger_checkpoints",
            "get_ledger_migration",
            "get_ledger_openapi_json",
            "get_ledger_reconciliation",
            "get_ledger_totals",
            "reseal_epoch_floor",
            "store_restore",
        ],
        "the set of operations the loop produces the answer for has changed"
    );

    // THE PHANTOM-ENDPOINT GUARD, RETIRED INTO THIS PIN. It used to live in `busbar-core` as a loop
    // over that crate's own `V1_GET_PATHS` against that crate's own router — a claim one crate made
    // about itself, which stops being true the moment a verb crosses and the composition, not the
    // crate, is what answers. Here it is the same claim against the composition: a path the served
    // document CLAIMS is answered must be answered by one of the two halves, and by exactly one.
    let mut elsewhere: Vec<String> = Vec::new();
    for template in documented_gets().await {
        let path = concrete(&template);
        let Some(row) = busbar_plane_admin::verbs::resolve("GET", &path) else {
            // Not a row of the eighty-eight. The only documented GETs that can be true of are the
            // named-definition maps another plane owns, and the assertion after the loop says the
            // set collected here is exactly those and nothing else.
            elsewhere.push(template);
            continue;
        };
        let by_the_loop = loop_answers(row.verb);
        let mounted = ask_a_fresh_surface("GET", &path).await != absent;
        assert!(
            by_the_loop || mounted,
            "the composition documents GET {template} and neither the loop nor the surface \
             underneath answers it (a phantom endpoint in the discovery contract)"
        );
        assert!(
            !(by_the_loop && mounted),
            "the composition documents GET {template} and BOTH halves answer it: one request, two \
             answers"
        );
    }
    assert_eq!(
        elsewhere, ANOTHER_PLANES_SURFACE,
        "the document claims a GET the admin plane's closed table does not declare and that is not \
         one of the named-definition maps another plane owns"
    );
}
