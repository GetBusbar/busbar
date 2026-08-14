// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WHOLE STDIO CLIENT LEG, DRIVEN AGAINST A REAL CHILD PROCESS — every method busbar ISSUES and
//! every message a child SENDS, through the real gate, the real supervisor and the real pipes.
//!
//! ## What this file is evidence for
//!
//! The 34 cells `mcp|stdio|client|*` of `qa/method-inventory.json`. A claim in
//! `qa/method-coverage.status` is a claim; these are the tests that make it a fact, and they are
//! written to the rule the coverage gate states: **a cell is exercised by a test that drives the
//! REAL path, never by a function existing.** So nothing here constructs a `Supervisor`, a
//! `StdioChild` or an `OutboundRequest` by hand; every assertion goes through
//! `crate::mcp::upstream::authorise` (the gate) and `crate::mcp::client::issue::issue` (the one
//! governed send), and lands on a `/bin/sh` process that writes what it saw to a file.
//!
//! ## NOTHING HERE CAN SKIP
//!
//! Every fixture is asserted present and every wait has a bound that PANICS when it elapses. That is
//! deliberate and it is the lesson of this release: four batteries reported green over deleted or
//! unwired code because their rigs skipped when a fixture was absent. A test that CAN skip is a test
//! that WILL skip on the day it matters.
//!
//! ## Unix only, and the same reason as its neighbours
//!
//! The fixture children are `/bin/sh` scripts, which keeps them out of the build graph at the cost
//! of a platform gate. Windows is a CI target and has no `/bin/sh`. The LEG is not unix-specific —
//! an operator on Windows configures a Windows command and the same machine drives it — so this is a
//! test-coverage gap and is stated rather than left to be discovered.

#![cfg(unix)]

use super::upstream_support::{gov_with_scopes, mcp_cfg};
use crate::mcp::client::issue::{issue, Issued};
use crate::mcp::client::verb::UpstreamVerb;
use crate::mcp::config::{
    McpPinMechanism, McpServerDefCfg, ServerPinCfg, ServerRequestGrants, ToolAllowCfg, Transport,
};
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// ONE deadline for the whole leg: the `timeout:` every fixture registration configures AND the
/// bound `await_log` polls under. They are the same number on purpose — the log wait is waiting for
/// the same `/bin/sh` child the transport is talking to, so a wait that is STRICTER than the
/// transport's own budget fails on scheduling delay the transport itself would have absorbed.
/// Observed exactly that way on loaded Linux CI: with a full workspace build running concurrently,
/// the child loop was descheduled past `await_log`'s old hard 5 s bound while every issue() had
/// already succeeded inside its 20 s budget. The bound still PANICS when it elapses — nothing here
/// can skip — it is merely no longer tighter than the machinery it observes.
const LEG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// A registration busbar reaches by SPAWNING `/bin/sh -c <script>`, with `$LOG` naming a file the
/// child appends every line it reads to.
///
/// `$LOG` goes through `env:` — the operator-named-variables channel — which is also the assertion
/// that the channel works: the child gets `env_clear()` plus exactly what the operator named, so a
/// fixture that could not read `$LOG` would be a fixture proving the clearing is too aggressive.
fn stdio_server(
    script: &str,
    log: &std::path::Path,
    grants: ServerRequestGrants,
) -> McpServerDefCfg {
    let mut tools_allow = indexmap::IndexMap::new();
    tools_allow.insert(
        "read".to_string(),
        ToolAllowCfg {
            schema_hash: Some("sha256:read".to_string()),
            description: Some("reads a file".to_string()),
            input_schema: Some(serde_json::json!({ "type": "object" })),
            ask_caller: Vec::new(),
            ..ToolAllowCfg::default()
        },
    );
    let mut env = std::collections::BTreeMap::new();
    env.insert(
        "LOG".to_string(),
        crate::mcp::config::ChildEnvValue::Plain(log.display().to_string()),
    );
    McpServerDefCfg {
        url: String::new(),
        transport: Some(Transport::Stdio),
        command: Some("/bin/sh".to_string()),
        args: vec!["-c".to_string(), script.to_string()],
        env,
        cwd: None,
        refresh_ttl: None,
        timeout: Some(format!("{}s", LEG_TIMEOUT.as_secs())),
        pin: ServerPinCfg {
            mechanism: McpPinMechanism::CertSpki,
            key: Some("sha256/CHILD=".to_string()),
        },
        tools_allow,
        prompts_allow: Default::default(),
        resources_allow: Default::default(),
        resource_templates_allow: Default::default(),
        aud: None,
        grants,
        allow_private: false,
        token_exchange: None,
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        upstream_credentials: None,
        hooks: Vec::new(),
    }
}

/// THE FIXTURE SERVER. One `sh` loop, and every line of it earns its place:
///
/// - it LOGS every line it reads, which is how a NOTIFICATION — a message with no reply — is proven
///   to have arrived at all;
/// - it SKIPS anything carrying `result` or `error`, so busbar's answers to the child's OWN requests
///   do not send the two of them into an infinite exchange;
/// - it answers any line carrying an `id` with a result naming the method it saw, echoing the id
///   back, so correlation is real rather than assumed.
///
/// The parsing is POSIX parameter expansion rather than a JSON parser, because the whole value of a
/// `/bin/sh` fixture is that it adds nothing to the build graph.
const RECORDING_SERVER: &str = r#"while IFS= read -r line; do
  printf '%s\n' "$line" >> "$LOG"
  case "$line" in *'"result"'*|*'"error"'*) continue;; esac
  m=${line#*\"method\":\"}
  m=${m%%\"*}
  case "$line" in *'"id":'*) ;; *) continue;; esac
  id=${line#*\"id\":}
  id=${id%%,*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"seen":"%s"}}\n' "$id" "$m"
done"#;

/// THE CHATTY SERVER: on `tools/list` it emits all nine notifications and five requests of its own
/// BEFORE answering, which is the shape of every real MCP stdio server and the shape that used to
/// desynchronise this transport permanently.
const CHATTY_SERVER: &str = r#"while IFS= read -r line; do
  printf '%s\n' "$line" >> "$LOG"
  case "$line" in *'"result"'*|*'"error"'*) continue;; esac
  m=${line#*\"method\":\"}
  m=${m%%\"*}
  case "$m" in
    tools/list)
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"x"}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t","progress":0.5}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/tasks","params":{"taskId":"t1"}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/prompts/list_changed","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/resources/list_changed","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///a"}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":901,"method":"ping","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":902,"method":"roots/list","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":903,"method":"sampling/createMessage","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":904,"method":"elicitation/create","params":{}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":905,"method":"totally/unknown","params":{}}'
      ;;
  esac
  case "$line" in *'"id":'*) ;; *) continue;; esac
  id=${line#*\"id\":}
  id=${id%%,*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"seen":"%s"}}\n' "$id" "$m"
done"#;

/// A LOG FILE IN A UNIQUE DIRECTORY, created up front so the child's `>>` cannot be the thing that
/// creates it — a fixture that races its own directory into existence is a fixture that fails at a
/// rate nobody can reproduce.
fn log_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-stdio-leg-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the fixture's own directory must be creatable");
    let path = dir.join("seen.jsonl");
    std::fs::write(&path, b"").expect("the fixture's log must be writable");
    path
}

fn read_log(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// WAIT for the child to have written something, with a HARD BOUND that PANICS.
///
/// Never a skip and never a silent pass: a poll loop that gives up quietly is how a battery reports
/// green over a child that never started. The message names what was being waited for, because the
/// only useful timeout is one that says what did not happen.
async fn await_log(path: &std::path::Path, needle: &str, what: &str) -> String {
    let deadline = tokio::time::Instant::now() + LEG_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        let log = read_log(path);
        if log.contains(needle) {
            return log;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!(
        "the child never wrote {what} (looking for {needle:?}) within {LEG_TIMEOUT:?} — the same \
         budget the transport itself gets, so this is a real failure, not scheduling delay.\nWhat \
         it did write:\n{}",
        read_log(path)
    );
}

/// Build the app, resolve the tool, and run the REAL gate — returning the `Authorised` that is the
/// proof it ran.
///
/// `authorise` is the only constructor of that type, which is what makes "the gate ran" a property
/// of having the value rather than a call somebody remembered to make. Nothing in this file has
/// another way to get one.
fn authorised(
    app: &std::sync::Arc<crate::state::App>,
    scopes: &[(&str, &str)],
) -> crate::mcp::upstream::Authorised {
    let gov = gov_with_scopes(scopes);
    let key = gov
        .key
        .clone()
        .expect("the fixture governance carries a key");
    let server = app
        .mcp_catalogue
        .server("fs")
        .expect("the fixture registration is in the catalogue")
        .clone();
    let selected = app
        .mcp_catalogue
        .resolve_now(
            Some(&key),
            crate::mcp::client::catalogue::LiveSightings::unsighted(),
            "fs_read",
        )
        .expect("the fixture tool resolves under the fixture grant")
        .clone();
    crate::mcp::upstream::authorise(&server, &selected, &serde_json::json!({}), Some(&key))
        .expect("the fixture caller holds both grants, so the egress gate admits it")
}

// ── THE 21 ISSUE CELLS ──────────────────────────────────────────────────────────────────────────

/// EVERY METHOD BUSBAR ISSUES REACHES A REAL CHILD PROCESS, and the child says which one it got.
///
/// One loop over [`UpstreamVerb::all`] rather than 23 near-identical tests, and the count is
/// asserted against the enum so the loop cannot silently shrink — the failure mode this release
/// found four times, where a suite dropped scenarios from its own denominator and stayed green.
///
/// The two classes are asserted DIFFERENTLY on purpose, because the difference is the whole reason
/// `McpWire::notify` exists: a request must come back with a correlated result naming its own
/// method, and a notification must come back with NOTHING — its evidence is the child's log, which
/// is the only place a message with no reply can leave a trace.
#[tokio::test]
async fn every_issued_verb_reaches_a_real_child_and_is_correlated() {
    crate::metrics::init();
    let log = log_path("issue-all");
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(RECORDING_SERVER, &log, ServerRequestGrants::default()),
        )
        .build();
    let auth = authorised(&app, &[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let verbs = UpstreamVerb::all();
    assert_eq!(
        verbs.len(),
        23,
        "the stdio client column is 21 MISSING cells plus the two already claimed (`tools/call`, \
         `tools/list`). A different number here means the enum and the matrix have parted company."
    );

    let mut requests = 0;
    let mut notifications = 0;
    for (n, verb) in verbs.iter().enumerate() {
        // A DISTINCT id per verb, so a stale answer from the previous exchange cannot be adopted as
        // this one's — which is the property `parse_response`'s correlation exists for.
        let id = 1_000 + n as u64;
        let outcome = issue(&app.mcp_pool, &auth, verb, id)
            .await
            .unwrap_or_else(|e| panic!("issuing `{}` to a live child failed: {e}", verb.method()));
        if verb.is_notification() {
            notifications += 1;
            assert_eq!(
                outcome,
                Issued::Delivered,
                "`{}` is a notification: it is written and NOTHING is read, because a notification \
                 produces no line and a read would consume the next call's answer",
                verb.method()
            );
        } else {
            requests += 1;
            let Issued::Result(value) = outcome else {
                panic!("`{}` is a request and must return a result", verb.method());
            };
            assert_eq!(
                value["seen"].as_str(),
                Some(verb.method()),
                "the child must have received `{}` and its answer must have been correlated back \
                 to this call: {value}",
                verb.method()
            );
        }
    }
    assert_eq!(requests, 18, "eighteen of the verbs are requests");
    assert_eq!(notifications, 5, "five of them are notifications");

    // AND THE NOTIFICATIONS ARRIVED. Their whole evidence is here: nothing came back, so the only
    // proof they were sent at all is the child's own record of reading them.
    let seen = await_log(
        &log,
        "notifications/roots/list_changed",
        "the last notification",
    )
    .await;
    for verb in &verbs {
        assert!(
            seen.contains(&format!("\"method\":\"{}\"", verb.method())),
            "the child never received `{}`.\nWhat it did receive:\n{seen}",
            verb.method()
        );
    }
}

/// THE HANDSHAKE IS SENT, ONCE, ON A FRESHLY SPAWNED CHILD — and never again on a reused one.
///
/// Both halves matter. `initialize` is a MUST for the installed stdio ecosystem, so a leg that never
/// sends one cannot talk to it; and `initialize` is a once-per-connection message, so re-sending it
/// on every dispatch would be busbar re-negotiating with a peer it is already talking to, which a
/// conformant server answers with an error.
#[tokio::test]
async fn the_handshake_is_sent_once_per_child_and_not_per_call() {
    crate::metrics::init();
    let log = log_path("handshake");
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(RECORDING_SERVER, &log, ServerRequestGrants::default()),
        )
        .build();
    let auth = authorised(&app, &[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    for id in [1u64, 2, 3] {
        issue(&app.mcp_pool, &auth, &UpstreamVerb::Ping, id)
            .await
            .expect("a ping to a live child");
    }
    let seen = await_log(&log, "\"method\":\"ping\"", "the pings").await;
    assert_eq!(
        seen.matches("\"method\":\"initialize\"").count(),
        1,
        "exactly one handshake per CHILD, not per call.\nWhat the child received:\n{seen}"
    );
    assert_eq!(
        seen.matches("\"method\":\"notifications/initialized\"")
            .count(),
        1,
        "the handshake's acknowledgement rides with it, once"
    );
    assert_eq!(
        seen.matches("\"method\":\"ping\"").count(),
        3,
        "three dispatches must reach the SAME child"
    );
}

/// THE EGRESS GATE RUNS ON EVERY VERB, not only on `tools/call`.
///
/// This is the assertion that stops the new column being a way around the transitive confused-deputy
/// defence. A caller with no `mcp_server` grant must be refused for `prompts/list` exactly as it is
/// for a tool call — and refused BEFORE anything reaches the child, which is proven by the child's
/// log being untouched rather than by reading the refusal text.
#[tokio::test]
async fn an_ungranted_caller_is_refused_before_the_child_is_reached() {
    crate::metrics::init();
    let log = log_path("gate");
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(RECORDING_SERVER, &log, ServerRequestGrants::default()),
        )
        .build();
    // Authorised for the TOOL CALL, then stripped of the server grant for the verb. Built by hand
    // from the granted one so that the ONLY difference is the caller's own scope list.
    let mut auth = authorised(&app, &[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    auth.caller.allowed_scopes = Some(Vec::new());

    for verb in [
        UpstreamVerb::PromptsList,
        UpstreamVerb::ResourcesList,
        UpstreamVerb::Ping,
        UpstreamVerb::NotificationsRootsListChanged,
    ] {
        let err = issue(&app.mcp_pool, &auth, &verb, 1)
            .await
            .expect_err("a caller with no grant must be refused");
        assert!(
            err.contains("mcp_server"),
            "`{}` must be refused by the SERVER grant, naming it: {err}",
            verb.method()
        );
    }
    assert_eq!(
        read_log(&log),
        "",
        "no child may be reached at all: the gate is synchronous and runs before any I/O, so an \
         ungranted caller cannot even cause a process to spawn"
    );
}

// ── THE 13 HANDLE CELLS ─────────────────────────────────────────────────────────────────────────

/// A CHILD'S OWN NOTIFICATIONS AND REQUESTS ARE HANDLED, AND THE ANSWER IS STILL CORRELATED.
///
/// This is the defect fix, asserted end to end. The child emits nine notifications and five requests
/// before answering; the answer that comes back must still be the answer to what busbar asked. Before
/// the read loop existed, the FIRST of those notifications would have been adopted as the answer,
/// and every later call on that child would have been served the previous call's response.
#[tokio::test]
async fn a_chatty_child_is_handled_and_the_answer_is_still_the_right_one() {
    crate::metrics::init();
    let log = log_path("chatty");
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(CHATTY_SERVER, &log, ServerRequestGrants::default()),
        )
        .build();
    let auth = authorised(&app, &[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let Issued::Result(value) = issue(&app.mcp_pool, &auth, &UpstreamVerb::ToolsList, 77)
        .await
        .expect("a chatty child still answers")
    else {
        panic!("`tools/list` is a request and must return a result");
    };
    assert_eq!(
        value["seen"].as_str(),
        Some("tools/list"),
        "fourteen interleaved messages must not displace the answer: {value}"
    );

    // AND EVERY ONE OF THE CHILD'S REQUESTS WAS ANSWERED. The evidence is the child's own log: it
    // records every line it reads, so busbar's replies are in there.
    let seen = await_log(&log, "\"id\":905", "busbar's reply to the unknown request").await;

    // `ping` — answered with an empty result, under NO grants. The only ungated one.
    // Matched on the two FACTS rather than on a substring of the serialisation: `serde_json` writes
    // an object's keys in its own order, so a literal `"id":901,"result":{}` would be asserting on
    // that ordering and would go red the day it changed for a reason that is not about ping.
    let ping_reply = seen
        .lines()
        .find(|l| l.contains("\"id\":901"))
        .unwrap_or_else(|| panic!("the child's `ping` was never answered:\n{seen}"));
    assert!(
        ping_reply.contains("\"result\":{}") && !ping_reply.contains("\"error\""),
        "a child's `ping` must be answered with an empty result and never refused: {ping_reply}"
    );
    // The three authority asks — REFUSED, deny-by-default, each naming the grant to set.
    for (id, kind) in [(902, "roots"), (903, "sampling"), (904, "elicitation")] {
        let marker = format!("\"id\":{id}");
        let refused = seen
            .lines()
            .find(|l| l.contains(&marker) && l.contains("\"error\""))
            .unwrap_or_else(|| {
                panic!("the child's `{kind}` ask (id {id}) was never refused:\n{seen}")
            });
        assert!(
            refused.contains(&format!("tools.fs.grants.{kind}: true")),
            "the refusal must name the exact key an operator sets: {refused}"
        );
    }
    // And an unknown request is answered `-32601` rather than dropped — a dropped request is a child
    // blocked on a reply forever, which presents as a hang.
    let unknown = seen
        .lines()
        .find(|l| l.contains("\"id\":905"))
        .unwrap_or_else(|| panic!("the unknown request was never answered:\n{seen}"));
    assert!(
        unknown.contains("-32601"),
        "an unimplemented method is `-32601`, answered: {unknown}"
    );
}

/// AN OPERATOR'S GRANT CHANGES THE REFUSAL, WHICH IS HOW WE KNOW THE GRANT IS READ AT ALL.
///
/// The paired positive control. Without it, "the ask was refused" is consistent with a gate that is
/// hard-coded to refuse and never reads the operator's configuration — which is exactly what a
/// silently-failing grant lookup looks like from outside.
#[tokio::test]
async fn a_granted_ask_is_refused_differently_than_an_ungranted_one() {
    crate::metrics::init();
    let log = log_path("granted");
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(
                CHATTY_SERVER,
                &log,
                ServerRequestGrants {
                    sampling: true,
                    elicitation: true,
                    roots: true,
                },
            ),
        )
        .build();
    let auth = authorised(&app, &[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    issue(&app.mcp_pool, &auth, &UpstreamVerb::ToolsList, 78)
        .await
        .expect("a chatty child still answers");
    let seen = await_log(&log, "\"id\":904", "busbar's reply to the elicitation ask").await;

    for (id, kind) in [(902, "roots"), (903, "sampling"), (904, "elicitation")] {
        let marker = format!("\"id\":{id}");
        let line = seen
            .lines()
            .find(|l| l.contains(&marker) && l.contains("\"error\""))
            .unwrap_or_else(|| panic!("the `{kind}` ask (id {id}) was never answered:\n{seen}"));
        assert!(
            line.contains("no satisfier"),
            "with the grant HELD, the refusal must say the satisfier is missing rather than blame \
             the grant — the two send an operator to different places: {line}"
        );
        assert!(
            !line.contains("carries no"),
            "a held grant must not be reported as absent: {line}"
        );
    }
}

/// A PEER'S `…/list_changed` BRINGS A REFRESH FORWARD, RATE-LIMITED, AND CHOOSES NOTHING ELSE.
///
/// The trigger is the one thing an untrusted peer may influence about busbar's catalogue: the
/// TIMING. It cannot choose the content — what follows is the authoritative `tools/list`, re-fetched
/// and re-hashed — and it cannot choose the rate, because the gate holds a floor between accepted
/// signals. Both halves are asserted, and the second one is the one that stops a chatty child
/// driving busbar's outbound fetch rate.
#[tokio::test]
async fn a_peer_signal_brings_one_refresh_forward_and_is_then_rate_limited() {
    crate::metrics::init();
    let log = log_path("trigger");
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(CHATTY_SERVER, &log, ServerRequestGrants::default()),
        )
        .build();
    let auth = authorised(&app, &[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    assert!(
        app.mcp_pool.triggers.take_pending().is_empty(),
        "nothing is pending before a peer has said anything"
    );

    // ONE exchange, during which the child emits FOUR change notifications.
    issue(&app.mcp_pool, &auth, &UpstreamVerb::ToolsList, 79)
        .await
        .expect("the child answers");

    let pending = app.mcp_pool.triggers.take_pending();
    assert_eq!(
        pending.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["fs"],
        "the pending set holds the SERVER'S NAME and nothing from the notification's body — there \
         is nowhere in it to put a tool definition, which is the rule made structural"
    );

    // FOUR notifications, ONE accepted trigger: the other three were inside the floor interval. A
    // peer that emits one notification per tool per change cannot turn one edit into a fetch storm.
    assert!(
        app.mcp_pool.triggers.take_pending().is_empty(),
        "draining is what makes one signal cause one refresh; a set the sweep only read would \
         refetch on every later tick"
    );
    issue(&app.mcp_pool, &auth, &UpstreamVerb::ToolsList, 80)
        .await
        .expect("the child answers again");
    assert!(
        app.mcp_pool.triggers.take_pending().is_empty(),
        "a second burst inside the floor interval must be swallowed by the rate limiter: an \
         upstream may bring a re-pull forward and may not have one on demand"
    );
}
