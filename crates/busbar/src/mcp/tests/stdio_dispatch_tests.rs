// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO TRANSPORT, DRIVEN THROUGH THE REAL DISPATCH PATH — an inbound `tools/call` on busbar's
//! own front door reaching a CHILD PROCESS, and the crash-loop supervisor refusing that same call.
//!
//! ## Why this file exists separately from `client/tests/stdio_tests.rs`
//!
//! That file proves what the supervisor DOES. This one proves that ANYTHING ASKS IT — which is the
//! entire difference between the supervisor that shipped and the supervisor that was deleted. The
//! deleted one was complete, adversarially tested and unreachable: it had a battery exactly like the
//! one next door, and a header admitting "nothing calls it, because a `tools:` entry carrying a
//! stdio transport has no dispatch arm yet". A test that calls `Supervisor::crashed` directly would
//! have passed on that tree too, and would therefore prove nothing about this one.
//!
//! So every assertion below goes through `mcp::method::dispatch` — the same entry an authenticated
//! MCP client reaches — and reads the answer off the CALLER'S result. Nothing in this file names
//! `Supervisor`, `StdioChild` or `StdioWire`, and that is deliberate: the only handle it has on the
//! supervisor is the refusal text arriving at a caller who asked for a tool.
//!
//! ## Unix only, and the same reason as next door
//!
//! The fixture children are `/bin/sh` scripts, which keeps them out of the build graph at the cost
//! of a platform gate. Windows is a CI target and has no `/bin/sh`, so the dispatch arm is proven on
//! unix; the arm itself is not unix-specific.

#![cfg(unix)]

use super::upstream_support::{call, gov_with_scopes, mcp_cfg};
use crate::mcp::config::{
    McpPinMechanism, McpServerDefCfg, ServerPinCfg, ServerRequestGrants, ToolAllowCfg, Transport,
};
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// A registration busbar reaches by SPAWNING `/bin/sh -c <script>`.
///
/// No `url:`, no `token_exchange:`, no `aud:` — `mcp::config::validate_endpoint` refuses all three
/// on this transport, so a fixture that set them would not be a fixture of anything an operator can
/// deploy.
fn stdio_server(script: &str) -> McpServerDefCfg {
    let mut tools_allow = indexmap::IndexMap::new();
    tools_allow.insert(
        "read".to_string(),
        ToolAllowCfg {
            schema_hash: Some("sha256:read".to_string()),
            description: Some("reads a file".to_string()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
            })),
            ask_caller: Vec::new(),
            ..ToolAllowCfg::default()
        },
    );
    McpServerDefCfg {
        url: String::new(),
        transport: Some(Transport::Stdio),
        command: Some("/bin/sh".to_string()),
        args: vec!["-c".to_string(), script.to_string()],
        env: Default::default(),
        cwd: None,
        refresh_ttl: None,
        timeout: Some("5s".to_string()),
        pin: ServerPinCfg {
            mechanism: McpPinMechanism::CertSpki,
            key: Some("sha256/CHILD=".to_string()),
        },
        tools_allow,
        prompts_allow: Default::default(),
        resources_allow: Default::default(),
        resource_templates_allow: Default::default(),
        aud: None,
        grants: ServerRequestGrants::default(),
        roots: Vec::new(),
        allow_private: false,
        token_exchange: None,
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        upstream_credentials: None,
        hooks: Vec::new(),
    }
}

/// A `sh` MCP server that answers every REQUEST with a result, echoing back the JSON-RPC id it was
/// sent. The id is extracted with POSIX parameter expansion rather than a JSON parser, because the
/// whole value of a `/bin/sh` fixture is that it adds nothing to the build graph.
///
/// IT SKIPS NOTIFICATIONS, and that line is not decoration. busbar sends `notifications/initialized`
/// as the second half of its handshake, and a notification has no reply by definition — a fixture
/// that answered one would put an extra line on the stream and every later call would be served the
/// previous one's response. That is exactly the desynchronisation `client::peer` was written for,
/// and a fixture that could not model a conformant server would be unable to demonstrate it.
const ECHO_SERVER: &str = r#"while IFS= read -r line; do
  case "$line" in *'"id":'*) ;; *) continue;; esac
  id=${line#*\"id\":}
  id=${id%%,*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"STDIO RESULT"}]}}\n' "$id"
done"#;

/// THE ARM ITSELF. A `tools:` entry carrying `transport: stdio` is no longer refused at config
/// validation — it boots, it spawns, and an authenticated caller's `tools/call` comes back with the
/// CHILD'S OWN result.
///
/// This is the assertion the staged claim `MCP_STDIO_TRANSPORT` was staged against, and it is a
/// conjunction on purpose: an enum arm that only ever appears inside a refusal is what the previous
/// two releases had.
#[tokio::test]
async fn a_tools_call_reaches_a_child_process_and_returns_its_result() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", stdio_server(ECHO_SERVER))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;

    assert_eq!(status, 200, "a granted call to a live child: {body}");
    assert_eq!(
        body.pointer("/result/content/0/text")
            .and_then(|v| v.as_str()),
        Some("STDIO RESULT"),
        "the CALLER is handed the child process's own result: {body}"
    );
    assert_eq!(
        body.pointer("/result/isError").and_then(|v| v.as_bool()),
        None,
        "a successful child call is not an error result: {body}"
    );
}

/// THE CHILD IS REUSED, not respawned per call. A transport that forked a process per `tools/call`
/// would pass the test above and would be a different, much worse thing.
///
/// Proven by the child's own memory: the fixture counts the lines it has seen and reports the count,
/// so a second call answering `2` is a second call served by the SAME process.
#[tokio::test]
async fn the_same_child_serves_consecutive_calls() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(
                // COUNTS `tools/call` AND NOTHING ELSE. busbar's handshake is a real request on
                // this stream, so a fixture that counted every line would report the tool call as
                // number two and the test would be asserting on the handshake rather than on child
                // reuse.
                r#"n=0
while IFS= read -r line; do
  case "$line" in *'"id":'*) ;; *) continue;; esac
  case "$line" in *'"method":"tools/call"'*) n=$((n+1));; esac
  id=${line#*\"id\":}
  id=${id%%,*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"call-%s"}]}}\n' "$id" "$n"
done"#,
            ),
        )
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": {} });

    let (_, first) = call(&app, &g, "tools/call", params.clone()).await;
    let (_, second) = call(&app, &g, "tools/call", params).await;
    assert_eq!(
        first
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str()),
        Some("call-1"),
        "{first}"
    );
    assert_eq!(
        second
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str()),
        Some("call-2"),
        "a second dispatch must reach the SAME child, not a fresh fork: {second}"
    );
}

/// THE DRIFT RE-CHECK RUNS ON A CHILD PROCESS TOO — `tools/list`, over the same vtable.
///
/// This was a REAL DEFECT and not a nicety. `mcp::connect::refresh` sent through `HttpTransport`
/// directly, which was correct while there was one transport: with two, a stdio registration (which
/// carries no `url:`) would have been POSTed to an empty string, the failure recorded as a FAILED
/// CONTACT, and the server demoted — a drift quarantine on a healthy server, caused entirely by
/// busbar asking the wrong channel.
///
/// The property that matters more is the one asserted here: rug-pull detection RUNS on stdio. A
/// transport whose tool list is never re-observed is a transport where the operator's approved
/// digests are never compared against anything, which is the whole defence switched off for a
/// registration that looks exactly like every other on the admin surface.
#[tokio::test]
async fn a_refresh_re_observes_a_child_process_tool_list() {
    crate::metrics::init();
    let cache = std::sync::Arc::new(crate::mcp::client::catalogue::CatalogueCache::new());
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server(
            "fs",
            stdio_server(
                // A LOOP, NOT A ONE-SHOT `read`. busbar handshakes a freshly spawned child before
                // it asks anything, so a fixture that answered exactly one line would answer the
                // handshake and then exit — and the refresh would record a healthy server as a
                // failed contact. Echoing the id back is what makes the two exchanges correlate.
                r#"while IFS= read -r line; do
  case "$line" in *'"id":'*) ;; *) continue;; esac
  id=${line#*\"id\":}
  id=${id%%,*}
  case "$line" in
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read","description":"reads a file","inputSchema":{"type":"object"}}]}}\n' "$id"
      ;;
    *) printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id";;
  esac
done"#,
            ),
        )
        .with_mcp_sightings(cache.clone())
        .build();
    let entry = app.mcp_catalogue.server("fs").unwrap().clone();

    let report = crate::mcp::connect::refresh(&app.mcp_pool, &cache, &entry)
        .await
        .expect("a stdio registration is refreshable, not a refusal");

    assert_eq!(
        report.failure, None,
        "a healthy child must not be recorded as a failed contact: {:?}",
        report.failure
    );
    assert_eq!(
        report.observed, 1,
        "the child's own tool list is what was observed"
    );
}

/// THE SUPERVISOR, PROVEN REACHED — the backoff and the quarantine, both observed by KILLING THE
/// CHILD and then asking busbar for a tool, never by calling the supervisor.
///
/// The fixture exits the instant it is spawned, which is the shape of every real crash-loop: a
/// missing dependency, a bad argument, a permission error. The sequence and what each step proves:
///
/// | dispatch | expected | proves |
/// |---|---|---|
/// | 1 | the child died mid-exchange | the wire notices a dead child rather than hanging |
/// | 2, immediately | `restart backoff` | the BACKOFF is consulted on the dispatch path |
/// | 3–5, after waiting out each backoff | four more crashes | the crash count survives the child |
/// | 6 | `quarantined` | the BREAKER refuses a caller, and no process is spawned to do it |
///
/// Nothing is asserted about wall-clock duration, only about ORDER and REFUSAL TEXT: a test that
/// asserted on timings would be asserting on the machine it ran on.
///
/// ## The core plane breaker is RESET between dispatches, and that is this test staying honest
///
/// The dispatch path now consults the ONE core breaker cell for this server BEFORE the wire (see
/// `method.rs` (3b)), and each child crash records a transient into it — so in production the
/// SECOND call inside the cooldown is refused by the core cell in milliseconds and the supervisor
/// is never asked (`mcp/tests/breaker_fastfail_tests.rs` proves exactly that). This file's subject
/// is the INNER arm — the supervisor's backoff and quarantine, which guard every spawn including
/// the refresh sweep's — so each step clears the outer cell first (`PlaneBreakers::reset`, a
/// test-only bypass) to reach it through the same front door as before. The supervisor's own
/// refusals are NOT recorded into the core cell (that would double-account one crash), which is
/// what keeps the two devices co-existing without either feeding the other.
#[tokio::test]
async fn a_crash_looping_child_backs_off_and_is_quarantined_through_the_dispatch_path() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        // The child exits before reading anything. Its stdout closes, which is what busbar sees.
        .mcp_server("fs", stdio_server("exit 1"))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": {} });
    let reach_the_supervisor = || {
        app.plane_breakers
            .reset(&crate::store::PlaneBreakers::tool_key("fs"))
    };

    let text = |b: &serde_json::Value| {
        b.pointer("/result/content/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };

    // (1) THE FIRST CRASH. A dead child is an upstream failure the model can read, not a busbar
    // refusal and not a hang.
    let (status, first) = call(&app, &g, "tools/call", params.clone()).await;
    assert_eq!(status, 200, "an upstream failure is not a refusal: {first}");
    assert_eq!(
        first.pointer("/result/isError").and_then(|v| v.as_bool()),
        Some(true),
        "a child that died must reach the model as an error result: {first}"
    );
    // EITHER child-death phrasing: the child exiting is one event that two syscalls can notice
    // first. When the read side sees EOF the transport says "closed its stdout"; when the child is
    // already gone as busbar writes (observed on a loaded CI runner), the write fails with
    // "write to stdio MCP child: Broken pipe". Both are the CHILD failing — the supervisor's
    // refusals (backoff, quarantine) read differently, and those are what this must not be.
    assert!(
        text(&first).contains("closed its stdout")
            || text(&first).contains("write to stdio MCP child"),
        "the first dispatch must fail on the CHILD, not on the supervisor: {}",
        text(&first)
    );

    // (2)+(3) THE BACKOFF AND THE CRASH COUNT, driven to quarantine BY ORDER rather than by wall
    // clock. The old shape dispatched exactly once "immediately" after each crash and asserted it
    // landed inside that crash's backoff window — a 100ms window on a machine running 4500 tests,
    // which is an assertion about the scheduler, not about busbar (and it flaked exactly there
    // under a full-gate load). So the sequence is now event-driven: after every observed CRASH the
    // next dispatch goes out with no sleep at all — inside the (doubling) window on any sane
    // scheduler, and if a pathological stall skips one window the crash simply counts toward the
    // quarantine and a LATER, longer window catches the proof; after every observed BACKOFF a
    // short sleep lets the window elapse so the next crash can happen. Every answer must still be
    // one of exactly three things — a crash, the backoff refusal, or the quarantine — and by the
    // time the quarantine lands the backoff arm MUST have been observed at least once, which is
    // the same "reached through a real tools/call" claim as before, minus the stopwatch.
    let mut saw_backoff = false;
    let mut quarantined = None;
    for _ in 0..40 {
        reach_the_supervisor();
        let (_, body) = call(&app, &g, "tools/call", params.clone()).await;
        let t = text(&body);
        if t.contains("quarantined") {
            quarantined = Some(t);
            break;
        }
        if t.contains("restart backoff") {
            saw_backoff = true;
            // Let this window elapse so the next dispatch produces the next crash. The waits stay
            // generous-not-exact: the loop re-checks, it never counts sleeps.
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            continue;
        }
        // "write to stdio MCP child" (Broken pipe) is the SAME crash noticed by the write syscall
        // instead of the read — see the phrasing note at (1). The supervisor counts it identically
        // (any exchange failure calls `crashed()`), so the quarantine arithmetic below holds.
        assert!(
            t.contains("closed its stdout") || t.contains("write to stdio MCP child"),
            "an unquarantined crash-looper either crashes again or is in backoff: {t}"
        );
    }
    assert!(
        saw_backoff,
        "the BACKOFF must be observed on the dispatch path before the quarantine lands: a run that \
         reached quarantine without one backoff refusal spawned a child on every single dispatch"
    );
    let t = quarantined.expect(
        "five crashes in the window must QUARANTINE the child — an unbounded restart loop against \
         a binary that always fails is a fork bomb with a config file behind it",
    );
    assert!(
        !t.contains("restart backoff"),
        "a tripped breaker is not a backoff: {t}"
    );

    // (4) THE QUARANTINE DOES NOT REOPEN WITH TIME — no amount of waiting turns it back into a
    // backoff, and nothing is spawned to answer the refusal.
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    reach_the_supervisor();
    let (_, last) = call(&app, &g, "tools/call", params).await;
    let t = text(&last);
    assert!(
        t.contains("quarantined"),
        "waiting must not reopen a quarantine: {t}"
    );
    assert!(
        !t.contains("restart backoff"),
        "a tripped breaker is not a backoff: waiting must not reopen it: {t}"
    );
}
