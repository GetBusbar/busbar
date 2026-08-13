// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen` — THE SERVER-TO-CLIENT CHANNEL, driven over a real socket.
//!
//! ## Why every case here reads bytes off a live connection
//!
//! The claim this file exists to support is that A CUSTOMER CAN BE NOTIFIED, and a customer is a
//! process reading an HTTP response body over time. A unit test that called
//! [`crate::mcp::subscribe::listen`] and inspected the `Response` value would establish that a
//! stream was CONSTRUCTED, which is exactly the claim the sibling subscription CODEC deliberately
//! did not make: it read and wrote the right bytes, and the served endpoint still answered `-32601`,
//! so no customer could do anything with it. The difference between those two states is only visible
//! from the far end of a socket, so that is where every case below stands.
//!
//! ## Why the catalogue is CHANGED rather than mocked
//!
//! [`a_catalogue_change_wakes_an_open_stream`] swaps a real second `App` onto the live handle — the
//! same seam an admin apply, a config reload and every registration mutation go through. A test that
//! poked a change-notification helper directly would pass on a build where nothing on the real
//! mutation path ever reaches it, which is the failure mode a notification surface has by default.

use crate::mcp::ingress::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::test_support::TestApp;
use futures::StreamExt as _;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// The `_meta` key every listen-stream frame is tagged with.
///
/// Spelled as a LITERAL for the reason `sse_tests` spells its own: this is the string a CLIENT
/// reads. Importing the SDK constant would assert that busbar agrees with itself and would keep
/// passing through a rename that broke every client.
const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// One registered MCP server, in the operator's own YAML — through the grammar and `validate_server`
/// exactly as `config.yaml` is, so a fixture cannot register something an operator could not write.
const ONE_TOOL: &str = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
tools_allow:
  alpha: {}
"#;

/// The same registration with a second tool. What makes the catalogue's generation move AND makes
/// the caller-visible tool list differ — both are required, and the second is the one that decides
/// whether THIS caller is woken.
const TWO_TOOLS: &str = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
tools_allow:
  alpha: {}
  beta: {}
"#;

/// The same registration with a PROMPT added. The tool list is untouched, so a stream that asked
/// only for prompts must be woken and a stream that asked only for tools must not be.
const ONE_TOOL_ONE_PROMPT: &str = r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
tools_allow:
  alpha: {}
prompts_allow:
  greeting:
    description: "A greeting"
    template: "hello"
"#;

fn app_with(yaml: &str) -> std::sync::Arc<crate::state::App> {
    let def: crate::mcp::config::McpServerDefCfg = serde_yaml::from_str(yaml)
        .unwrap_or_else(|e| panic!("the `tools:` registration was refused by the grammar: {e}"));
    TestApp::new()
        .mcp(&McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .mcp_server("tools", def)
        .build()
}

/// Boot a deployment and hand back its URL AND the live handle, so a case that needs the catalogue
/// to change can swap a second `App` onto it mid-stream.
async fn serve(yaml: &str) -> (String, std::sync::Arc<crate::state::AppHandle>) {
    crate::metrics::init();
    let (router, handle) = crate::build_router_with_limits(
        app_with(yaml),
        crate::limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), handle)
}

/// Open a listen stream with `notifications`, returning the live response.
async fn listen(url: &str, notifications: serde_json::Value) -> reqwest::Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "subscriptions/listen",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "notifications": notifications,
        },
    });
    reqwest::Client::new()
        .post(url)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", "subscriptions/listen")
        // `application/json` FIRST, which is what every real client sends and what the official
        // suite sends. A subscription answers with a stream regardless — see the note on
        // `crate::mcp::subscribe::listen` — and asserting that here is the point of the ordering.
        .header("accept", "application/json, text/event-stream")
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// Read frames off a live stream until `want` of them have arrived or `deadline` passes.
///
/// Bounded by BOTH, and the timeout is not a flake guard: a stream that is working correctly is
/// silent most of the time, so "no more frames" is the ordinary state rather than an error, and a
/// reader that waited for a fixed count would hang on exactly the behaviour the module is supposed
/// to have.
async fn frames(
    response: reqwest::Response,
    want: usize,
    deadline: std::time::Duration,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut stream = response.bytes_stream();
    let _ = tokio::time::timeout(deadline, async {
        while let Some(Ok(chunk)) = stream.next().await {
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(cut) = buffer.find('\n') {
                let line: String = buffer.drain(..=cut).collect();
                if let Some(data) = line.trim_end().strip_prefix("data: ") {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                        out.push(v);
                    }
                }
            }
            if out.len() >= want {
                return;
            }
        }
    })
    .await;
    out
}

fn method_of(frame: &serde_json::Value) -> &str {
    frame.get("method").and_then(|m| m.as_str()).unwrap_or("")
}

// ── The acknowledgement, which is a MUST about ordering ────────────────────────────────────────

/// The FIRST message on a listen stream is `notifications/subscriptions/acknowledged`, and it is
/// tagged with the subscription id.
///
/// Both halves in one case because they are one requirement: an acknowledgement that arrives second
/// tells a client nothing it can act on, and one that arrives untagged cannot be related to the
/// request that opened the stream — under a revision with no sessions there is no other name for it.
#[tokio::test]
async fn the_first_frame_is_the_acknowledgement_and_it_carries_the_subscription_id() {
    let (url, _h) = serve(ONE_TOOL).await;
    let response = listen(&url, serde_json::json!({ "toolsListChanged": true })).await;
    assert_eq!(response.status().as_u16(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "a subscription was answered `{content_type}`, which is not a stream"
    );
    let got = frames(response, 1, std::time::Duration::from_secs(3)).await;
    let first = got
        .first()
        .expect("a listen stream writes its first frame immediately");
    assert_eq!(
        method_of(first),
        "notifications/subscriptions/acknowledged",
        "the first frame was `{}`",
        method_of(first)
    );
    assert_eq!(
        first
            .pointer("/params/_meta")
            .and_then(|m| m.get(META_SUBSCRIPTION_ID)),
        Some(&serde_json::json!(7)),
        "the acknowledgement is not tagged with the id of the request that opened the stream"
    );
}

/// The acknowledgement carries the ACCEPTED subset, and `resourceSubscriptions` is narrowed away.
///
/// This is the honest half of the design and the one a client can act on: busbar cannot observe a
/// resource's contents changing at the upstream that owns it, so a client that asked for that
/// category learns here that it will not get it — rather than waiting for a notification that was
/// never going to come.
#[tokio::test]
async fn resource_subscriptions_are_narrowed_away_in_the_acknowledgement() {
    let (url, _h) = serve(ONE_TOOL).await;
    let response = listen(
        &url,
        serde_json::json!({
            "toolsListChanged": true,
            "resourceSubscriptions": ["test://one"],
        }),
    )
    .await;
    let got = frames(response, 1, std::time::Duration::from_secs(3)).await;
    let ack = got.first().expect("an acknowledgement");
    let accepted = ack
        .pointer("/params/notifications")
        .expect("the acknowledgement carries the accepted filter");
    assert_eq!(
        accepted.get("toolsListChanged"),
        Some(&serde_json::json!(true)),
        "a category busbar delivers was not acknowledged"
    );
    assert!(
        accepted.get("resourceSubscriptions").is_none(),
        "busbar acknowledged a category it cannot deliver: {accepted}"
    );
}

/// A filter that opts in to nothing busbar delivers is REFUSED, not acknowledged.
///
/// The alternative — acknowledge it and go quiet — is indistinguishable from a working subscription
/// on a quiet deployment, so a client would wait rather than fall back. The refusal is `-32602`
/// because the defect is in the request's own params, which is the same reading `params._meta` gets.
#[tokio::test]
async fn a_subscription_that_could_deliver_nothing_is_refused() {
    let (url, _h) = serve(ONE_TOOL).await;
    let response = listen(
        &url,
        serde_json::json!({ "resourceSubscriptions": ["test://one"] }),
    )
    .await;
    assert_eq!(response.status().as_u16(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body.pointer("/error/code"),
        Some(&serde_json::json!(-32602)),
        "an undeliverable subscription was answered {body}"
    );
}

// ── The delivery, which is the reason the stream is worth opening ───────────────────────────────

/// A REAL catalogue change on the live handle wakes an OPEN stream with
/// `notifications/tools/list_changed`, tagged with the subscription id.
///
/// The swap is the production mutation seam (`AppHandle::swap`), which is what an admin apply and a
/// config reload both go through — so a build where the notification never reaches that path fails
/// here rather than passing on a helper nobody calls.
#[tokio::test]
async fn a_catalogue_change_wakes_an_open_stream() {
    let (url, handle) = serve(ONE_TOOL).await;
    let response = listen(&url, serde_json::json!({ "toolsListChanged": true })).await;
    // The change is made while the stream is open, from a task of its own, because that is the only
    // ordering under which the notification is a NOTIFICATION: a change made first and observed
    // afterwards would be indistinguishable from the acknowledgement's own initial reading.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        handle.swap(app_with(TWO_TOOLS));
        // Held so the swapped-in `App` outlives the assertion below.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    let got = frames(response, 2, std::time::Duration::from_secs(5)).await;
    assert_eq!(
        got.first().map(method_of),
        Some("notifications/subscriptions/acknowledged"),
        "the acknowledgement is still owed first"
    );
    let change = got
        .iter()
        .find(|f| method_of(f) == "notifications/tools/list_changed")
        .unwrap_or_else(|| {
            panic!("the tool list changed and the open subscription was not told: {got:?}")
        });
    assert_eq!(
        change
            .pointer("/params/_meta")
            .and_then(|m| m.get(META_SUBSCRIPTION_ID)),
        Some(&serde_json::json!(7)),
        "a listen-stream notification arrived untagged"
    );
}

/// A PROMPT-list change wakes a stream that asked for prompts.
///
/// The second of the three categories, driven end to end rather than left to the symmetry of the
/// loop that emits them: three kinds sharing one code path is a reason to expect them to behave
/// alike, not evidence that they do, and the fingerprint each one is compared on is a different
/// slice of the catalogue.
#[tokio::test]
async fn a_prompt_change_wakes_a_stream_that_asked_for_prompts() {
    let (url, handle) = serve(ONE_TOOL).await;
    let response = listen(&url, serde_json::json!({ "promptsListChanged": true })).await;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        handle.swap(app_with(ONE_TOOL_ONE_PROMPT));
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    let got = frames(response, 2, std::time::Duration::from_secs(5)).await;
    assert!(
        got.iter()
            .any(|f| method_of(f) == "notifications/prompts/list_changed"),
        "the prompt list changed and the open subscription was not told: {got:?}"
    );
}

/// A stream delivers ONLY the categories it acknowledged.
///
/// A client that subscribed to prompts and receives a tool notification has been told something it
/// filtered out — which on a multi-tenant gateway is the wrong side of a boundary, not merely noise:
/// the filter is the only statement a client makes about what it wants to learn from this server.
#[tokio::test]
async fn a_stream_delivers_only_what_it_acknowledged() {
    let (url, handle) = serve(ONE_TOOL).await;
    let response = listen(&url, serde_json::json!({ "promptsListChanged": true })).await;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        handle.swap(app_with(TWO_TOOLS));
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });
    let got = frames(response, 3, std::time::Duration::from_secs(2)).await;
    assert!(
        !got.is_empty(),
        "a narrowed subscription produced no frames at all, not even its acknowledgement"
    );
    assert!(
        !got.iter()
            .any(|f| method_of(f) == "notifications/tools/list_changed"),
        "a stream filtered to prompts leaked a tool notification: {got:?}"
    );
}

/// `subscriptions/listen` is advertised by `server/discover`, and the two lists cannot disagree.
///
/// The catalogue read and the dispatch table are the same slice by construction; this case is what
/// makes that visible from OUTSIDE, which is where a client decides whether to open a stream at all.
#[tokio::test]
async fn discover_advertises_the_method_that_dispatch_accepts() {
    let (url, _h) = serve(ONE_TOOL).await;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }},
    });
    let response: serde_json::Value = reqwest::Client::new()
        .post(&url)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", "server/discover")
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let methods = response
        .pointer("/result/methods")
        .and_then(|m| m.as_array())
        .expect("discover names its methods");
    assert!(
        methods.contains(&serde_json::json!("subscriptions/listen")),
        "discover does not advertise the channel this revision notifies over: {methods:?}"
    );
}

/// CHARACTERISATION — **THIS PINS A KNOWN-WRONG BEHAVIOUR, NOT A DESIRED ONE.**
///
/// The two halves of a subscription's authorisation do not age alike, and this case exists to make
/// that asymmetry impossible to rediscover by accident:
///
/// * The CATALOGUE is re-read live. A registration that appears mid-stream is reflected within
///   [`crate::mcp::subscribe::POLL_INTERVAL`], which is what
///   [`a_catalogue_change_wakes_an_open_stream`] already proves over a socket.
/// * The KEY is FROZEN AT OPEN. `GovCtx` is cloned into the long-lived stream as an
///   `Arc<VirtualKey>` resolved once by the auth middleware, and nothing in the poll loop
///   re-resolves it. A key that is deleted, disabled or re-scoped while the stream is held
///   therefore keeps being served for the rest of the stream's life.
///
/// **THE TEMPTING LOCAL FIX IS A PLACEBO, AND THE TEST SAYS SO IN AN ASSERTION.** It looks as
/// though `grant_of` could simply consult `enabled`/`is_live()` alongside
/// [`busbar_api::VirtualKey::scope_allowed`] (which reads `allowed_scopes` alone). It cannot: those
/// fields live on the SAME frozen snapshot, so they still read "live" long after the store row
/// says otherwise. Only re-reading the key from the store closes this, and that needs a standing-
/// permission primitive rather than a local patch — the auth chain that produced the key is async
/// and consumes the presented credential, which the stream deliberately does not retain.
///
/// The assertions below are written the way they are BECAUSE THEY ARE WRONG: a change that makes a
/// revoked key stop being served mid-stream is a FIX, and it must REPLACE this test rather than be
/// blocked by it. What must never happen silently is the reverse — this behaviour surviving a
/// change to [`crate::mcp::subscribe::MAX_LIFETIME`], which is the only bound on how long a dead
/// credential is honoured. The closing assertion pins that bound for exactly that reason.
#[test]
fn a_revoked_key_keeps_being_served_until_the_lifetime_bound() {
    use std::time::{Duration, Instant};

    // A LIVE, admitted key — exactly what the auth middleware resolves and attaches at ingress.
    // The fixture must start live, because the defect is about what happens to a key AFTER it was
    // legitimately admitted; a key already dead at open is one the auth chain would have refused.
    let admitted = std::sync::Arc::new(busbar_api::VirtualKey {
        id: "k-live".to_string(),
        name: "k-live".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: None,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
    });
    assert!(admitted.is_live() && admitted.enabled, "admitted at open");

    let gov = crate::governance::GovCtx {
        key: Some(admitted.clone()),
    };
    let handle = std::sync::Arc::new(crate::state::AppHandle::new(app_with(ONE_TOOL)));
    let id = serde_json::json!(7);
    let now = Instant::now();
    let mut state = crate::mcp::subscribe::Listen {
        handle: handle.clone(),
        gov,
        // Through the production narrowing rather than hand-built, so this fixture cannot ask for a
        // category the served endpoint would have refused.
        accepted: crate::mcp::subscribe::accept(
            &serde_json::from_value(serde_json::json!({ "toolsListChanged": true }))
                .expect("the SDK filter type accepts the wire shape"),
        ),
        meta: crate::mcp::subscribe::subscription_meta(&id),
        id,
        phase: crate::mcp::subscribe::Phase::Acknowledge,
        deadline: now + crate::mcp::subscribe::MAX_LIFETIME,
        last_write: now,
    };

    let ack = state.step().expect("the acknowledgement is owed first");
    assert!(
        ack.contains("notifications/subscriptions/acknowledged"),
        "the first frame is the acknowledgement: {ack}"
    );

    // GOVERNANCE MOVES UNDER THE STREAM. The catalogue half IS live — swapping a second `App` onto
    // the handle is the same seam an admin apply, a config reload and a key revocation all go
    // through, and the stream sees the catalogue half of it on the very next poll.
    handle.swap(app_with(TWO_TOOLS));

    // WRONG-BY-DESIGN #1 — THE SNAPSHOT NEVER MOVES. Whatever governance now says about this key,
    // the stream's authorisation input is still the very `Arc` handed to it at open: not an equal
    // value, the SAME ALLOCATION. Nothing in the poll loop re-resolves the key against the store,
    // so there is no code path by which a revocation could reach this decision.
    assert!(
        std::sync::Arc::ptr_eq(
            state.gov.key.as_ref().expect("the stream holds a key"),
            &admitted
        ),
        "characterisation: the stream re-resolved its key — if this now fails, the freeze is FIXED \
         and this whole test should be replaced by one asserting revocation bites"
    );

    // WRONG-BY-DESIGN #2 — AND NO FIELD CHECK COULD RESCUE IT. Because the snapshot is frozen, the
    // `enabled` and `deleted_at` fields the stream can see are also frozen at their open-time
    // values, so they still read "live" no matter what the store now holds. Tightening `grant_of`
    // to consult `is_live()`/`enabled` would therefore change NOTHING in production — it is a
    // placebo, and this assertion exists so nobody lands one believing it closed the hole. The only
    // real fix re-reads the key.
    let seen = state.gov.key.as_ref().expect("the stream holds a key");
    assert!(
        seen.is_live() && seen.enabled,
        "characterisation: the frozen snapshot still reports itself live, whatever the store says"
    );

    // WRONG-BY-DESIGN #3 — the caller is still served. If the key were re-resolved per poll this
    // stream would have been closed or starved instead.
    let after = state.step().expect("the stream is still open");
    assert!(
        after.contains("notifications/tools/list_changed"),
        "characterisation: the stream is still served under a key nobody re-checked: {after}"
    );

    // THE ONLY THING THAT STOPS IT. Move the deadline into the past — the same transition
    // `MAX_LIFETIME` produces after 300s — and the stream closes gracefully. That bound, and
    // nothing else, is what caps how long the revoked key above is honoured, so a change raising
    // `MAX_LIFETIME` widens a credential-revocation window and must be argued for as such.
    state.deadline = Instant::now() - Duration::from_secs(1);
    let closing = state
        .step()
        .expect("the lifetime bound writes a graceful result");
    assert!(
        closing.contains("\"result\""),
        "the bound ends the stream with the revision's graceful result: {closing}"
    );
    assert!(
        state.step().is_none(),
        "and the stream is then closed, which is the whole of the bound on a frozen key"
    );
}
