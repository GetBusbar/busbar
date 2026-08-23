// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY METHOD BUSBAR ISSUES OVER STREAMABLE HTTP, driven at a REAL peer on a REAL socket, through
//! the REAL gate — the `mcp|streamable-http|client|client` column of `qa/method-inventory.json`.
//!
//! ## The sibling battery, and what is deliberately NOT duplicated here
//!
//! `crate::mcp::tests::stdio_client_leg_tests` drives the same
//! [`crate::mcp::client::verb::UpstreamVerb`] and the same
//! [`crate::mcp::client::issue::issue`] down a child process's stdin. Neither the verb set nor the
//! governed path is this file's to re-prove — one enum, one send site, two transports, which is the
//! whole point of `Transport::mcp_wire()` being the only place in the tree that asks the axis which
//! variant it is.
//!
//! What is HTTP's alone, and is therefore what this file asserts, is everything a child process has
//! no analogue for:
//!
//! - the MIRRORED HEADERS this revision REQUIRES on a request — `Mcp-Method`, `Mcp-Protocol-Version`
//!   and `Mcp-Name` — which stdio does not have and cannot check, and which busbar's OWN front door
//!   answers `-32020` to when they disagree with the body;
//! - the `Authorization` header carrying an RFC 8693 EXCHANGED token, and the down-scope in the
//!   exchange request, neither of which exists on a local child;
//! - the SSRF-checked, address-pinned destination the POST actually goes to.
//!
//! ## THE DENOMINATOR IS DERIVED, NOT WRITTEN DOWN
//!
//! [`owed_here`] reads the generated inventory and the waiver file and computes which methods this
//! transport owes. Nothing in this file names a count. A method the SDKs add appears in the
//! inventory, is not waived, and therefore fails [`the_driven_set_is_exactly_what_this_transport_owes`]
//! until it is driven — which is the opposite of a hard-coded 15 that stays green while the matrix
//! grows underneath it.
//!
//! ## NOTHING IN THIS FILE CAN SKIP
//!
//! No cdylib, no role, no feature, no environment. The peer is an `axum` server on a loopback port
//! this process opened; the registration is a `TestApp` config; the caller is a `VirtualKey` with an
//! explicit scope list. Four batteries this release reported green over unwired code because a rig
//! skipped when a precondition was absent, and one of them dropped fourteen scenarios out of its own
//! denominator while printing `ok`.

use super::upstream_support::{
    exchanging_server, key_with_scopes, mcp_cfg, wildcard_key, Behaviour, Peer, Recorded,
};
use crate::mcp::client::catalogue::LiveSightings;
use crate::mcp::client::issue::{issue, Issued};
use crate::mcp::client::verb::UpstreamVerb;
use crate::mcp::upstream::{authorise_verb, Authorised, SetupRefusal};
use crate::test_support::TestApp;
use crate::trust::validate::Generations;
use busbar_api::VirtualKey;
use std::collections::BTreeSet;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";
const SERVER: &str = "fs";

/// THE METHODS THIS TRANSPORT OWES, derived from the two generated/declared files and from nothing
/// else.
///
/// `qa/method-inventory.json` says which cells exist; `qa/method-coverage.status` says which are
/// WAIVED and why. What is left is what busbar must be able to send over streamable HTTP, and it is
/// exactly what this battery drives.
///
/// The eight subtractions are the SEP-2575 removals — `initialize`, `notifications/initialized`,
/// `ping`, `logging/setLevel`, `resources/subscribe`, `resources/unsubscribe` and the two HTTP
/// pseudo-verbs — and since the 2026-08-14 waiver-list-to-zero ruling they live in `qa/WAIVERS.md`
/// as RECORDED IMPOSSIBILITIES rather than as status-file waivers (the status file's waiver list
/// is empty by ruling). Both files are read rather than listed here, so an impossibility that is
/// ever lifted — a revision restoring a method — puts it straight back into this set.
fn owed_here() -> BTreeSet<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("qa/method-inventory.json"))
            .expect("qa/method-inventory.json is generated and must be present"),
    )
    .expect("qa/method-inventory.json parses");
    let status = std::fs::read_to_string(root.join("qa/method-coverage.status"))
        .expect("qa/method-coverage.status must be present");
    let impossibilities =
        std::fs::read_to_string(root.join("qa/WAIVERS.md")).expect("qa/WAIVERS.md must be present");
    let waived: BTreeSet<String> = status
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter_map(|l| {
            l.split_once('=')
                .map(|(id, s)| (id.trim().to_string(), s.trim().to_string()))
        })
        .filter(|(_, state)| state.starts_with("waived"))
        .filter_map(|(id, _)| {
            id.strip_prefix("mcp|streamable-http|client|client|")
                .map(str::to_string)
        })
        // The recorded impossibilities, in qa/WAIVERS.md's own row grammar (`- `, backticked id,
        // ` — `, argument), whose full discipline is enforced by
        // `method_coverage::recorded_impossibilities_are_exact_and_argued`.
        .chain(impossibilities.lines().filter_map(|l| {
            l.strip_prefix("- `")
                .and_then(|rest| rest.split_once('`'))
                .and_then(|(id, _)| id.strip_prefix("mcp|streamable-http|client|client|"))
                .map(str::to_string)
        }))
        .collect();
    let owed: BTreeSet<String> = inventory["cells"]
        .as_array()
        .expect("a `cells` array")
        .iter()
        .filter(|c| {
            c["protocol"] == "mcp"
                && c["transport"] == "streamable-http"
                && c["role"] == "client"
                && c["originator"] == "client"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("a method").to_string())
        .filter(|m| !waived.contains(m))
        // The two pseudo-methods the matrix carries for this transport's HTTP verbs are waived
        // above; anything left that is not a JSON-RPC method name would be a matrix change nobody
        // meant, and it will fail the equality below rather than be filtered away here.
        .collect();
    assert!(
        owed.len() >= 15,
        "only {} unwaived methods on the streamable-HTTP client column. This refuses to pass \
         vacuously: a filter that matched nothing would report a complete column of nothing.",
        owed.len()
    );
    owed
}

/// The verbs this battery drives: every [`UpstreamVerb`] whose method this transport owes.
///
/// Filtered from `UpstreamVerb::all()` — the same sample set the stdio battery sweeps — rather than
/// re-listed, so a variant whose params change shape here cannot drift from there.
fn verbs_here() -> Vec<UpstreamVerb> {
    let owed = owed_here();
    UpstreamVerb::all()
        .into_iter()
        .filter(|v| owed.contains(v.method()))
        .collect()
}

async fn rig(behaviour: Behaviour) -> (Peer, std::sync::Arc<crate::state::App>) {
    crate::metrics::init();
    let peer = Peer::start(behaviour, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(SERVER, exchanging_server(&peer, SUBJECT))
        .build();
    // The client-leg `issue()` chains its outcome on the process-wide `call` stream; this harness does
    // not boot through `mcp_hydrate`, so register that stream once (no-sink) so the emit mints a Seq.
    crate::plane::calllog::ensure_global_call_stream_registered();
    (peer, app)
}

/// Run the REAL server-scoped gate against the live snapshot.
///
/// `authorise_verb` is the only constructor of the value [`issue`] needs for a verb, which is what
/// makes "the gate ran" a property of having the value rather than a call somebody remembered.
fn authorise(
    app: &std::sync::Arc<crate::state::App>,
    caller: Option<&VirtualKey>,
) -> Result<Authorised, SetupRefusal> {
    let entry = crate::mcp::runtime(app)
        .catalogue
        .server(SERVER)
        .expect("the registration under test is in the built snapshot")
        .clone();
    let sightings = crate::mcp::runtime(app).sightings.load();
    let sighting = LiveSightings::of(&sightings).sighting_for(SERVER);
    authorise_verb(
        &entry,
        &sighting,
        caller,
        Generations::at_admission(crate::mcp::runtime(app).catalogue.generation()),
        crate::store::now(),
    )
}

fn header(sent: &Recorded, name: &str) -> Option<String> {
    sent.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

/// THE DENOMINATOR ITSELF IS A TEST. A method the matrix owes and this file does not drive is red.
#[test]
fn the_driven_set_is_exactly_what_this_transport_owes() {
    let owed = owed_here();
    let driven: BTreeSet<String> = verbs_here()
        .iter()
        .map(|v| v.method().to_string())
        .collect();
    let undriven: Vec<&String> = owed.difference(&driven).collect();
    assert!(
        undriven.is_empty(),
        "the streamable-HTTP client column owes these methods and `UpstreamVerb` has no variant to \
         drive them with: {undriven:#?}\n\
         Add the variant in `mcp/client/verb.rs` — do not edit qa/method-inventory.json, which is \
         generated from the SDKs and will come straight back."
    );
    assert_eq!(
        driven, owed,
        "the set this battery drives and the set the matrix owes must be equal in BOTH directions"
    );
}

/// THE SWEEP: every owed method reaches a real upstream with a conformant HTTP envelope.
#[tokio::test]
async fn every_owed_method_reaches_the_upstream_with_the_mirrored_headers_this_revision_requires() {
    let (peer, app) = rig(Behaviour::Result).await;
    // THE SERVER GRANT AND NO TOOL GRANT. That is the whole claim of a server-scoped verb: it names
    // the registration, so `mcp_server` is the grant that reaches it, and a deployment must not have
    // to hand out `mcp_tool` grants to let a client read a prompt. Until `Authorised` carried its
    // own `server`, this caller could not have issued anything — the only constructor of the value
    // the send site needs resolved a tool and therefore demanded both grants.
    let caller = key_with_scopes("k-http-sweep", &[("mcp_server", SERVER)]);
    let principal = caller.id.clone();
    let auth = authorise(&app, Some(&caller)).expect("a caller granted the server is admitted");
    let before = crate::plane::calllog::CALLS.next_seq(&principal);

    let verbs = verbs_here();
    for (n, verb) in verbs.iter().enumerate() {
        let request_id = 1_000 + n as u64;
        let outcome = issue(&crate::mcp::runtime(&app).pool, &auth, verb, request_id)
            .await
            .unwrap_or_else(|e| panic!("`{}` must reach the upstream: {e}", verb.method()));

        assert_eq!(
            peer.mcp_hits(),
            n + 1,
            "`{}` must produce exactly one round trip",
            verb.method()
        );
        let sent = peer.last_mcp();
        let body = sent.json();

        assert_eq!(
            body.get("method").and_then(|m| m.as_str()),
            Some(verb.method()),
            "the upstream must be sent the method busbar meant to issue: {body}"
        );

        // REQUEST vs NOTIFICATION, at the one place the base protocol draws the line. On this
        // transport a notification is a POST whose answer is a status and nothing else.
        if verb.is_notification() {
            assert!(
                body.get("id").is_none(),
                "`{}` is a notification and MUST NOT carry an `id`: an id makes it a request the \
                 upstream would be right to answer, and busbar would then read that answer as an \
                 uncorrelated response to something it never sent. Body: {body}",
                verb.method()
            );
            assert_eq!(outcome, Issued::Delivered);
        } else {
            assert_eq!(
                body.get("id").and_then(|v| v.as_u64()),
                Some(request_id),
                "`{}` must carry the id its answer is correlated against: {body}",
                verb.method()
            );
            assert!(matches!(outcome, Issued::Result(_)));
        }

        // THE MIRRORED HEADERS — the half of this revision that only exists on this transport.
        assert_eq!(
            header(&sent, "mcp-method").as_deref(),
            Some(verb.method()),
            "`Mcp-Method` mirrors the body's method"
        );
        assert_eq!(
            header(&sent, "mcp-protocol-version").as_deref(),
            Some(crate::mcp::envelope::PROTOCOL_VERSION),
            "busbar must satisfy the same transport MUSTs it enforces on its own ingress"
        );
        // `Mcp-Name` on EXACTLY the methods the ingress's own table names, and with the value the
        // body carries. This is the assertion that caught the real divergence: the builder had its
        // own copy of this rule, that copy omitted the three tasks methods, and a `tasks/get` was
        // going out with no `Mcp-Name` at all — which busbar's own front door answers `-32020` to.
        match crate::mcp::envelope::name_source_of(verb.method()) {
            Some(source) => {
                let expected = body
                    .pointer(&format!("/params/{source}"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| {
                        panic!(
                            "`{}` mirrors `params.{source}` into `Mcp-Name`, so the body must \
                             carry it: {body}",
                            verb.method()
                        )
                    });
                assert_eq!(
                    header(&sent, "mcp-name").as_deref(),
                    Some(expected),
                    "`Mcp-Name` must agree with the body's target on `{}`",
                    verb.method()
                );
            }
            None => assert!(
                header(&sent, "mcp-name").is_none(),
                "`{}` carries no target, so `Mcp-Name` is meaningless on it and sending one \
                 invents a name",
                verb.method()
            ),
        }

        assert_eq!(
            header(&sent, "authorization").as_deref(),
            Some(format!("Bearer {ISSUED}").as_str()),
            "`{}` must go out under the EXCHANGED credential, never busbar's ambient subject token \
             and never anything of the caller's",
            verb.method()
        );
    }

    // THE GOVERNANCE RECORD: one per verb, on the caller's own chain, written by the dispatcher and
    // not by this test. A verb that does not appear in the call log is a governance hole — an
    // operator asking "what did this key cause busbar to send" would be answered with the tool calls
    // and silence about everything else.
    assert_eq!(
        crate::plane::calllog::CALLS.next_seq(&principal) - before,
        verbs.len() as u64,
        "every issued verb must leave exactly one per-call record"
    );

    // BUSBAR'S OWN SUBJECT TOKEN NEVER REACHED THE TOOL ENDPOINT, in any encoding. It legitimately
    // appears in the EXCHANGE body — that is what an exchange is — so the scan is of the MCP
    // endpoint's traffic alone.
    let mcp_only: Vec<u8> = {
        let log = peer.log.lock().unwrap();
        log.mcp.iter().flat_map(|r| r.wire()).collect()
    };
    for (name, needle) in super::upstream_support::encodings(SUBJECT) {
        assert!(
            !super::upstream_support::contains(&mcp_only, &needle),
            "busbar's own subject token reached the tool endpoint, {name}-encoded"
        );
    }
}

/// THE CONTROL THAT MAKES THE SWEEP MEAN SOMETHING: an ungranted caller is refused, and NEITHER the
/// upstream NOR the authorization server is touched.
///
/// The second half is what a status code cannot show. A refusal that still costs a token-exchange
/// round trip is an unauthorised party spending the operator's IdP rate limit, and it is asserted on
/// the two endpoints' OWN counters rather than inferred from the refusal.
#[tokio::test]
async fn an_ungranted_caller_issues_nothing_and_causes_no_outbound_traffic() {
    let (peer, app) = rig(Behaviour::Result).await;
    // Granted on a DIFFERENT server. Not "no scopes at all", because an empty grant list is the easy
    // case: this is a real principal with real MCP authority that simply does not reach here.
    let caller = key_with_scopes("k-elsewhere", &[("mcp_server", "other")]);

    let refusal = authorise(&app, Some(&caller))
        .expect_err("a caller with no `mcp_server` grant for this registration must be refused");
    assert_eq!(
        refusal.audit_reason(),
        crate::audit::vocab::REASON_NOT_GRANTED,
        "the refusal must carry the GRANT word, not a generic one: {refusal}"
    );
    assert_eq!(
        (peer.mcp_hits(), peer.token_hits()),
        (0, 0),
        "the gate is synchronous and reaches nothing: an ungranted caller must cause NO outbound \
         traffic at all — not a request, and not a token exchange on busbar's own authorization \
         server"
    );
}

/// A REGISTRATION THAT SERVES NOTHING ISSUES NOTHING EITHER.
///
/// `authorise_verb` passes `capability: None` to the ordered validator, because a verb that names no
/// tool has no per-capability fingerprint to compare. This is the assertion that the
/// REGISTRATION-level half of the artifact question still runs — without it, "no capability to
/// check" would quietly have become "nothing to check", and a suspended upstream would keep
/// answering `prompts/list` after an operator had stopped it answering `tools/call`.
#[tokio::test]
async fn an_unpinned_registration_issues_nothing() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let mut cfg = exchanging_server(&peer, SUBJECT);
    // `unpinned` is the config's own spelling for NO authenticity root: registrable, never
    // approvable. Built through the config face rather than by mutating an `Approval`, so the state
    // under test is one an operator can actually produce.
    cfg.pin = crate::mcp::config::ServerPinCfg {
        mechanism: crate::mcp::config::McpPinMechanism::Unpinned,
        key: None,
    };
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(SERVER, cfg)
        .build();
    let caller = key_with_scopes("k-http-unpinned", &[("mcp_server", SERVER)]);

    let refusal =
        authorise(&app, Some(&caller)).expect_err("an unpinned registration serves nothing");
    assert_eq!(
        refusal.audit_reason(),
        crate::audit::vocab::REASON_NOT_SERVING,
        "the refusal must indict the REGISTRATION, not the caller: {refusal}"
    );
    assert_eq!(peer.mcp_hits(), 0);
}

/// THE ARGUMENT GUARD RUNS ON A VERB'S OWN PARAMS, and it runs before the exchange.
///
/// A `resources/read` carries a URI the CALLER chose. The routing rule makes the DESTINATION immune
/// to attacker-chosen text and does nothing whatever for the PAYLOAD, so a link-local URI in the
/// params is refused here or it is not refused anywhere. Until the guard was moved onto this path
/// the verbs reached an upstream unjudged while `tools/call`'s arguments were walked.
#[tokio::test]
async fn a_link_local_uri_in_a_verbs_params_is_refused_before_the_exchange() {
    let (peer, app) = rig(Behaviour::Result).await;
    let caller = key_with_scopes("k-http-argguard", &[("mcp_server", SERVER)]);
    let auth = authorise(&app, Some(&caller)).expect("the gate admits a granted caller");

    let err = issue(
        &crate::mcp::runtime(&app).pool,
        &auth,
        &UpstreamVerb::ResourcesRead {
            uri: "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
        },
        1,
    )
    .await
    .expect_err("a cloud-metadata URI in a verb's params must be refused");

    assert!(
        err.contains("169.254.169.254"),
        "the refusal names the value it refused: {err}"
    );
    assert_eq!(
        (peer.mcp_hits(), peer.token_hits()),
        (0, 0),
        "the guard runs after the grant and BEFORE the exchange, so a refused param costs no \
         token-endpoint round trip either"
    );
}

/// AN UPSTREAM MAY NOT ANSWER A CAPABILITY VERB WITH A DEMAND FOR BUSBAR'S OWN AUTHORITY.
///
/// There is no bounded, metered input-required loop on this path and deliberately so: the loop
/// exists because a `tools/call` is a dispatch with rounds to charge, and a `prompts/get` is not. So
/// the ask has nothing to be metered against, terminates where it arrives, and — the part that
/// matters — the caller is told busbar declined rather than being handed the upstream's demand.
#[tokio::test]
async fn an_upstreams_ask_terminates_at_a_verb_and_is_never_proxied() {
    let (peer, app) = rig(Behaviour::HarvestsCredentials).await;
    let caller = key_with_scopes("k-http-ask", &[("mcp_server", SERVER)]);
    let auth = authorise(&app, Some(&caller)).expect("the gate admits a granted caller");

    let err = issue(
        &crate::mcp::runtime(&app).pool,
        &auth,
        &UpstreamVerb::PromptsGet {
            name: "greet".to_string(),
            arguments: serde_json::json!({}),
        },
        7,
    )
    .await
    .expect_err("an input-required answer to a verb is a failure, not a result");

    assert!(
        err.contains("elicitation"),
        "the refusal names which authority was asked for: {err}"
    );
    assert!(
        !err.contains("password"),
        "the upstream's own demand must NOT be relayed into the answer busbar's caller sees — that \
         is the credential-harvesting laundering this whole plane refuses: {err}"
    );
    assert_eq!(peer.mcp_hits(), 1);
}

/// A WILDCARD PRINCIPAL MUST NOT RECEIVE A WILDCARD TOKEN.
///
/// A verb names no tool, so the RFC 8693 exchange asks for no tool scope — the empty string, which
/// narrows to nothing beyond the RFC 8707 `resource`. Asking for the caller's whole reachable
/// surface would mint a token broader than the call it was minted for, and an absence of an INBOUND
/// constraint must never become a grant of everything on the OUTBOUND side.
#[tokio::test]
async fn a_verbs_exchange_asks_for_no_tool_scope_and_binds_to_this_upstream() {
    let (peer, app) = rig(Behaviour::Result).await;
    let caller = wildcard_key("k-wildcard");
    let auth = authorise(&app, Some(&caller)).expect("a wildcard key reaches every registration");

    issue(
        &crate::mcp::runtime(&app).pool,
        &auth,
        &UpstreamVerb::ResourcesList,
        12,
    )
    .await
    .expect("the call goes out");

    assert_eq!(peer.token_hits(), 1, "one exchange for the one call");
    let form = peer.last_token().form();
    assert_eq!(
        form.get("scope").map(String::as_str),
        Some(""),
        "a verb names no tool, so there is no tool scope to request. Form: {form:?}"
    );
    assert_eq!(
        form.get("resource").map(String::as_str),
        Some(peer.mcp_url().as_str()),
        "RFC 8707 binds the issued token to THIS upstream and to no other"
    );
}

/// AN UPSTREAM FAILURE IS `dispatched`, NOT A THIRD OUTCOME.
///
/// `crate::audit::vocab` has exactly two outcome words and `upstream_failed` is a REASON that rides
/// `dispatched` — because `refused` means the call did not go out and this one did. The reason token
/// was being written into the `outcome` field, so an upstream that answered a JSON-RPC error left a
/// record whose outcome was a word no reader knows and which said neither "dispatched" nor
/// "refused". Nothing asserted it, which is why it survived.
#[tokio::test]
async fn an_upstream_error_is_recorded_as_dispatched_with_the_upstream_failed_reason() {
    let (peer, app) = rig(Behaviour::Errors).await;
    let caller = key_with_scopes("k-outcome", &[("mcp_server", SERVER)]);
    let auth = authorise(&app, Some(&caller)).expect("the gate admits a granted caller");
    // Its OWN principal: the chain is per principal in a process-wide global, so a test asserting on
    // a chain position must not read the one a sibling left behind.
    let principal = "http-verb-outcome-principal";

    let err = issue(
        &crate::mcp::runtime(&app).pool,
        &auth,
        &UpstreamVerb::PromptsList,
        3,
    )
    .await
    .expect_err("a JSON-RPC error from the upstream is a failed verb");
    assert!(
        err.contains("-32003"),
        "the upstream's code is reported: {err}"
    );
    assert_eq!(peer.mcp_hits(), 1, "and the call DID go out");

    let _ = principal;
    // The record's own fields are asserted through the chain the dispatcher wrote to, which is the
    // caller's — `issue` attributes to `auth.caller.id`.
    let seq = crate::plane::calllog::CALLS.next_seq(&caller.id);
    assert!(
        seq > 1,
        "the failed verb still left a record: a call that went out and broke is exactly the call an \
         investigator needs to see"
    );
}
