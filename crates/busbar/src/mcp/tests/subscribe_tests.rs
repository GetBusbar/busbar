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

use crate::mcp::envelope::PROTOCOL_VERSION;
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

/// The same fixture as [`app_with`], plus a GOVERNANCE RUNTIME on the snapshot.
///
/// A separate builder rather than a parameter on `app_with` because governance is what the
/// re-resolution reads, and a swapped-in snapshot that quietly lost it would make the stream
/// fail closed for the right reason at the wrong moment — which is exactly the confusion that cost
/// this test its first run.
fn governed_app_with(
    yaml: &str,
    gov: &std::sync::Arc<crate::governance::GovState>,
) -> std::sync::Arc<crate::state::App> {
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
        .governance(std::sync::Arc::clone(gov))
        .build()
}

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

/// `server/discover` DECLARES the capability the listen stream DELIVERS, per category.
///
/// The half `discover_advertises_the_method_that_dispatch_accepts` cannot see: a client does not
/// look for `subscriptions/listen` in a method list, it looks at `capabilities.*.listChanged` —
/// that is the field the specification gives it to decide whether change notifications exist at
/// all. Advertising `false` there while `subscriptions/listen` serves a working stream is an
/// UNDECLARED surface: no conforming client will ever open it, and one that probes the method
/// anyway has been told by the declaration to expect `-32601`, so a stream response reads as a
/// hang. The official battery's CONC.SUBSCRIPTION-ACK-FIRST failed on exactly that disagreement.
///
/// Asserted per category against what `subscribe::accept` actually narrows to: the three
/// list-changed kinds are declared, and `resources.subscribe` stays `false` because
/// `resourceSubscriptions` is narrowed away — a declaration and a delivery that must keep agreeing
/// in both directions.
#[tokio::test]
async fn discover_declares_the_capabilities_the_listen_stream_delivers() {
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
    let caps = response
        .pointer("/result/capabilities")
        .expect("discover names its capabilities");
    for category in ["tools", "prompts", "resources"] {
        assert_eq!(
            caps.pointer(&format!("/{category}/listChanged")),
            Some(&serde_json::json!(true)),
            "`subscriptions/listen` delivers `{category}` list-changed notifications, but \
             discover declares the capability absent — an undeclared surface no client will \
             ever open: {caps}"
        );
    }
    assert_eq!(
        caps.pointer("/resources/subscribe"),
        Some(&serde_json::json!(false)),
        "`resourceSubscriptions` is narrowed away by the stream, so declaring it here would \
         promise a notification that never comes: {caps}"
    );
}

/// **THE FREEZE IS LIFTED, AND THIS IS THE CASE THAT PROVED IT.**
///
/// This was `a_revoked_key_keeps_being_served_until_the_lifetime_bound`, a CHARACTERISATION test
/// that pinned a known-wrong behaviour: the catalogue half of a subscription's authorisation was
/// re-read live while the KEY half was an `Arc<VirtualKey>` cloned into the stream at open, so a key
/// deleted, disabled or re-scoped mid-stream kept being served for the rest of the stream's life.
/// Its own doc said a change making revocation bite is a FIX and must REPLACE it rather than be
/// blocked by it, and its `Arc::ptr_eq` assertion carried the trigger in as many words: *"if this
/// now fails, the freeze is FIXED and this whole test should be replaced by one asserting revocation
/// bites"*. [`crate::trust::validate::Standing`] is that fix, and this is that replacement. Renamed
/// from the negative to the positive; same subject, opposite polarity.
///
/// **THE PLACEBO FINDING IS PRESERVED, because it is the reason the fix had to be a core primitive.**
/// The tempting local patch was to teach `grant_of` to consult `enabled`/`is_live()` beside
/// [`busbar_api::VirtualKey::scope_allowed`], which reads `allowed_scopes` alone and looks at
/// neither. That would have changed nothing: those fields sat on the SAME frozen snapshot and
/// reported "live" whatever the store row said. `the_placebo_fix_would_still_have_been_a_placebo`
/// below keeps that finding executable rather than remembered.
///
/// **AND THE BOUND IS STILL PINNED.** `MAX_LIFETIME` is no longer the only thing standing between a
/// revoked credential and a served stream, but it is still the bound on everything a poll cannot
/// re-derive, so the closing assertions keep it under test.
///
/// Driven against a REAL `GovState` with a REAL `delete_key` — the call the admin DELETE handler
/// makes — rather than a double that answers "gone" on cue. A double would pass on a `Standing` that
/// never looked anything up, which is the exact defect.
#[test]
fn a_revoked_key_stops_being_served_on_the_next_poll() {
    use std::time::Duration;

    let gov = std::sync::Arc::new(
        crate::governance::GovState::new(
            std::sync::Arc::new(crate::governance::MemoryStore::new()),
            None,
        )
        .expect("a memory-backed registry constructs"),
    );
    // A LIVE, ADMITTED key — exactly what the auth middleware resolves and attaches at ingress. The
    // fixture must start live, because the defect is about what happens to a key AFTER it was
    // legitimately admitted; a key already dead at open is one the auth chain would have refused.
    let (admitted, _secret) = gov
        .create_key(
            crate::governance::NewKeySpec {
                name: "k-live".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
            },
            0,
        )
        .expect("mint");
    assert!(admitted.is_live() && admitted.enabled, "admitted at open");

    let handle = std::sync::Arc::new(crate::state::AppHandle::new(governed_app_with(
        ONE_TOOL, &gov,
    )));
    let id = serde_json::json!(7);
    let mut state = crate::mcp::subscribe::Listen {
        handle: handle.clone(),
        // THE ID AND THE BOUND, never the principal. `Snapshot::Watching` because a generation move
        // is what this response exists to REPORT — pinning it would end the stream on the first
        // change it was opened to hear about.
        standing: crate::trust::validate::Standing::opened(
            Some(&admitted),
            crate::trust::validate::Snapshot::Watching,
            crate::mcp::subscribe::MAX_LIFETIME,
        ),
        // Through the production narrowing rather than hand-built, so this fixture cannot ask for a
        // category the served endpoint would have refused.
        accepted: crate::mcp::subscribe::accept(
            &serde_json::from_value(serde_json::json!({ "toolsListChanged": true }))
                .expect("the SDK filter type accepts the wire shape"),
        ),
        meta: crate::mcp::subscribe::subscription_meta(&id),
        id,
        phase: crate::mcp::subscribe::Phase::Acknowledge,
        last_write: std::time::Instant::now(),
    };

    let ack = state.step().expect("the acknowledgement is owed first");
    assert!(
        ack.contains("notifications/subscriptions/acknowledged"),
        "the first frame is the acknowledgement: {ack}"
    );

    // THE CONTROL. Nothing has been revoked, so a catalogue change is delivered exactly as
    // `a_catalogue_change_wakes_an_open_stream` proves over a socket. Without this half the refusal
    // below would be indistinguishable from a stream that refuses everything.
    handle.swap(governed_app_with(TWO_TOOLS, &gov));
    let served = state.step().expect("the stream is open");
    assert!(
        served.contains("notifications/tools/list_changed"),
        "a live key is still served: {served}"
    );

    // REVOCATION, through the call the admin DELETE handler makes.
    gov.delete_key(&admitted.id).expect("revoke");

    // AND IT BITES ON THE VERY NEXT POLL — not at `MAX_LIFETIME`, which is what it used to do.
    let closing = state
        .step()
        .expect("the stream writes a closing frame rather than going quiet");
    assert!(
        closing.contains("\"error\""),
        "a revoked key must END the stream with a refusal, not keep it open: {closing}"
    );
    assert!(
        closing.contains(crate::audit::vocab::REASON_IDENTITY_NOT_LIVE),
        "and the refusal must name WHICH lapse it was, in the shared vocabulary: {closing}"
    );
    assert!(state.step().is_none(), "and the stream is then closed");

    // THE BOUND IS STILL LOAD-BEARING and still under test. It no longer caps how long a revoked
    // credential is honoured — that is now one poll — but it is still the cap on everything a poll
    // cannot re-derive, so a change raising it still has to be argued for.
    assert_eq!(
        crate::mcp::subscribe::MAX_LIFETIME,
        Duration::from_secs(300),
        "MAX_LIFETIME is the bound on what a poll cannot re-check; raising it widens that window"
    );
    let expired = crate::trust::validate::Standing::opened(
        Some(&admitted),
        crate::trust::validate::Snapshot::Watching,
        Duration::ZERO,
    );
    assert_eq!(
        expired.still_permitted(Some(&gov), 1, 0),
        Err(crate::trust::validate::Lapsed::Expired),
        "the bound still ends a standing permission on its own"
    );
}

/// THE PLACEBO, KEPT EXECUTABLE. The sibling unit's most useful finding was not the hole itself but
/// that the obvious local patch would not have closed it, and a finding that survives only in prose
/// is one the next author re-discovers the hard way.
///
/// `scope_allowed` reads `allowed_scopes` alone — it consults neither `enabled` nor `is_live()`. So
/// teaching the stream's grant closure to check those fields would have changed nothing while the
/// key was a frozen snapshot: the snapshot's own fields report "live" for ever. Both halves are
/// asserted, because either alone is a different claim.
#[test]
fn the_placebo_fix_would_still_have_been_a_placebo() {
    let mut frozen = busbar_api::VirtualKey {
        id: "k".to_string(),
        name: "k".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: None,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
    };

    // HALF ONE: the grant predicate does not read liveness at all, so a dead key answers a grant
    // question exactly as a live one does.
    frozen.enabled = false;
    frozen.deleted_at = Some(1);
    assert!(
        frozen.scope_allowed("mcp_tool", "tools_alpha"),
        "scope_allowed consults `allowed_scopes` alone; a field check beside it is a SEPARATE check"
    );

    // HALF TWO: and a field check beside it would have read the FROZEN copy, which is why it was a
    // placebo rather than merely insufficient. A snapshot taken while the key was live reports live
    // for as long as the snapshot is held, whatever the store now says.
    let snapshot_taken_at_open = busbar_api::VirtualKey {
        enabled: true,
        deleted_at: None,
        ..frozen.clone()
    };
    assert!(
        snapshot_taken_at_open.is_live() && snapshot_taken_at_open.enabled,
        "the copy taken at open still reports itself live — the fix has to RE-RESOLVE, not re-read \
         the same value more carefully"
    );
}
