// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLOSED SET OF ISSUED METHODS, checked against the GENERATED matrix rather than against a
//! list in a comment.
//!
//! The failure this file exists to catch is the one `tests/method_coverage.rs` was written for, one
//! level down: a column of the matrix whose contents are a property of its call sites drifts from
//! the specification silently, because an absent verb and a considered-and-inapplicable verb look
//! identical in source. So [`UpstreamVerb::all`] is compared against `qa/method-inventory.json` —
//! which is generated from rmcp's own model — in BOTH directions.

use super::super::verb::UpstreamVerb;

/// Every `mcp|stdio|client|client|<method>` cell the generated inventory owes an implementation.
///
/// Read from the file rather than restated, for the reason the coverage gate itself gives: a list
/// written from knowledge of the specification is exactly how a list ends at J with nobody noticing.
fn inventory_methods() -> std::collections::BTreeSet<String> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../qa/method-inventory.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("method-inventory.json parses");
    doc["cells"]
        .as_array()
        .expect("a `cells` array")
        .iter()
        .filter(|c| {
            c["protocol"] == "mcp"
                && c["transport"] == "stdio"
                && c["role"] == "client"
                && c["originator"] == "client"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("a method").to_string())
        .collect()
}

/// THE COLUMN IS COMPLETE, AND IT IS NOT WIDER THAN THE SPECIFICATION.
///
/// Both directions, because each catches a different mistake. A method in the inventory with no
/// variant is a cell busbar cannot serve and would be claiming. A variant with no inventory row is
/// busbar sending an upstream a method the specification does not define, which is not coverage —
/// it is a made-up verb that an upstream will answer `-32601` to.
#[test]
fn the_issued_set_is_exactly_the_inventory_column() {
    let owed = inventory_methods();
    assert!(
        owed.len() >= 20,
        "only {} issuable stdio methods in the inventory. This test refuses to pass vacuously: a \
         filter that matched nothing would report a complete column of nothing.",
        owed.len()
    );
    let built: std::collections::BTreeSet<String> = UpstreamVerb::all()
        .iter()
        .map(|v| v.method().to_string())
        .collect();
    let missing: Vec<&String> = owed.difference(&built).collect();
    let invented: Vec<&String> = built.difference(&owed).collect();
    assert!(
        missing.is_empty(),
        "the inventory owes these methods on the stdio client leg and `UpstreamVerb` has no variant \
         for them: {missing:#?}"
    );
    assert!(
        invented.is_empty(),
        "`UpstreamVerb` sends methods the generated matrix does not define: {invented:#?}\n\
         Do not edit qa/method-inventory.json — it is generated from the SDKs and will come back."
    );
}

/// `all()` IS ONE INSTANCE OF EVERY VARIANT, not most of them.
///
/// Without this, a variant added to the enum and forgotten in `all()` would narrow every test above
/// and below silently — the exact shape of the four batteries this release found reporting green
/// over a shrinking denominator.
#[test]
fn every_variant_appears_in_all_exactly_once() {
    let all = UpstreamVerb::all();
    let mut names: Vec<&str> = all.iter().map(UpstreamVerb::method).collect();
    let before = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        before,
        names.len(),
        "`UpstreamVerb::all()` lists a method twice, which would double-count the column"
    );
}

/// A NOTIFICATION HAS NO `id` AND A REQUEST DOES, and it is the VARIANT that decides.
///
/// This is the property `McpWire::notify` exists for. A notification carrying an `id` is a request,
/// and a peer would be right to answer it — which on a stdio child puts an unexpected line on the
/// stream and desynchronises every later call.
#[test]
fn notifications_carry_no_id_and_requests_do() {
    let mut notifications = 0;
    for verb in UpstreamVerb::all() {
        let request = verb.build("https://u.example.com/mcp", 42, None);
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("the body is JSON");
        assert_eq!(
            body["jsonrpc"],
            "2.0",
            "{} must carry the JSON-RPC version",
            verb.method()
        );
        assert_eq!(
            body["method"],
            verb.method(),
            "the body's method must be the verb's own"
        );
        if verb.is_notification() {
            notifications += 1;
            assert!(
                body.get("id").is_none(),
                "{} is a notification and must carry NO `id` member: {body}",
                verb.method()
            );
        } else {
            assert_eq!(
                body["id"],
                42,
                "{} is a request and must carry the id it was built with: {body}",
                verb.method()
            );
        }
    }
    assert_eq!(
        notifications, 5,
        "the five client-originated notifications of this revision must be classified as \
         notifications; a request misclassified as one would never be answered, and a notification \
         misclassified as a request hangs the leg"
    );
}

/// EVERY VERB CARRIES `params._meta`, which this revision REQUIRES on every request.
///
/// Asserted over the whole set rather than on a sample, because the failure mode is exactly one verb
/// forgetting it — and busbar's own ingress answers `-32602` to a request whose `_meta` is missing,
/// so a verb that omitted it would be one busbar could not itself accept.
#[test]
fn every_verb_carries_the_required_meta() {
    for verb in UpstreamVerb::all() {
        let request = verb.build("https://u.example.com/mcp", 1, None);
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
        let meta = &body["params"]["_meta"];
        assert!(
            meta.is_object(),
            "{} must carry `params._meta`: {body}",
            verb.method()
        );
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            super::super::verb::CLIENT_PROTOCOL_VERSION,
            "{} must state the protocol revision in `_meta`",
            verb.method()
        );
    }
}

/// THE MIRRORED `Mcp-Method` HEADER IS THE BODY'S OWN METHOD, on every verb.
///
/// A mirrored header whose value is computed twice is a mirrored header that can differ, which is
/// the request-smuggling primitive the mirroring exists to close.
#[test]
fn the_mirrored_method_header_matches_the_body() {
    for verb in UpstreamVerb::all() {
        let request = verb.build("https://u.example.com/mcp", 1, None);
        let sent: Vec<&str> = request
            .headers
            .iter()
            .filter(|(n, _)| n == "mcp-method")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            sent,
            vec![verb.method()],
            "{} must mirror its method in exactly one `Mcp-Method` header",
            verb.method()
        );
    }
}

/// THE CREDENTIAL IS SENT WHEN THERE IS ONE AND NEVER OTHERWISE.
///
/// The negative half is the one that matters: a verb that attached a bearer unconditionally would
/// send an empty `Authorization: Bearer ` to a public upstream, which is a malformed credential
/// header rather than an absent one.
#[test]
fn the_bearer_is_present_only_when_one_was_planned() {
    for verb in UpstreamVerb::all() {
        let bare = verb.build("https://u.example.com/mcp", 1, None);
        assert!(
            !bare.headers.iter().any(|(n, _)| n == "authorization"),
            "{} must send no `Authorization` when no credential was planned",
            verb.method()
        );
        let credentialled = verb.build("https://u.example.com/mcp", 1, Some("tok"));
        assert!(
            credentialled
                .headers
                .iter()
                .any(|(n, v)| n == "authorization" && v == "Bearer tok"),
            "{} must send the planned credential",
            verb.method()
        );
    }
}
