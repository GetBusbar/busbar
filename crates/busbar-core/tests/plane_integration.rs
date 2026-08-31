// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE INTEGRATION TESTS for busbar-core, relocated here from `src/tests/tests.rs` when the
//! `#[path]` dual-compile was removed. They hand a REAL, `build_app_from_config`-built `App` to the
//! extracted plane crates (`busbar_mcp`/`busbar_a2a`) — their accessors and testkit builders. That
//! only type-checks when there is ONE `busbar_core` in the graph, which is exactly what an
//! integration-test target gives (busbar_core links as a normal dependency, the same instance the
//! plane crates link), rather than the two copies a `#[cfg(test)]` unit module would see.

use busbar_core::test_support::*;
use busbar_mcp::testkit::TestAppMcpExt as _;

/// The A2A verify-on-call gate now lives ON THE `A2aPlane` runtime object (like MCP's
/// `McpRuntime::verify`), carried across a config apply off the prior generation's plane by
/// `carried_a2a_gates`. This exercises the two ways a carried entry stops leaking:
///
/// 1. A SURVIVING plane whose live set no longer names a subject must PRUNE that subject's carried
///    flight/drift-latch — the `a2a_retain_verify_gates` hook, now reading the gate off the plane slot
///    (`runtime_slots`) rather than off a shared `App` field.
/// 2. REMOVING the `agents:` block drops the whole plane, and with it the gate — the unobservable
///    analogue of the old `retain(&empty)`, since a deployment fronting no agents runs no delegation
///    that could read a leaked entry.
#[cfg(feature = "plane-a2a")]
#[test]
fn the_carried_a2a_verify_gate_prunes_dead_subjects_and_drops_with_the_plane() {
    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    let cfg_with_agents = || {
        let mut c = cfg_with_provider_api_key(busbar_core::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_A2A_PRUNE",
        ));
        c.agent_defs = Box::new(busbar_a2a::testkit::agents_cfg_with_one_receiving_agent());
        c
    };
    let prior = build_once(cfg_with_agents(), None).expect("boot with an agents: block");
    // The plane's OWN verify gate accumulated per-subject coordination for an agent this deployment
    // once fronted (a latched drift diagnostic tracks the subject just as an in-flight verify would).
    // "retired-agent" is NOT the live "planner", so a retain against the live set must drop it.
    let prior_plane =
        busbar_a2a::a2a::runtime(&prior).expect("agents: configured => a2a plane present");
    prior_plane
        .verify()
        .report("a2a", "retired-agent", true, false);
    assert!(
        prior_plane.verify().tracks_subject("retired-agent"),
        "seed: the plane's a2a VerifyGate must track the subject before the apply"
    );

    // (1) Re-apply KEEPING the `agents:` block: the new plane carries the same gate forward, and the
    // retain hook prunes the dead subject against the live set (`{planner}`).
    let kept =
        build_once(cfg_with_agents(), Some(&prior)).expect("re-apply keeping the agents: block");
    let kept_plane =
        busbar_a2a::a2a::runtime(&kept).expect("agents: still configured => a2a plane present");
    assert!(
        !kept_plane.verify().tracks_subject("retired-agent"),
        "a surviving plane must prune the carried gate entry no live agent names, not leak it"
    );

    // (2) Re-apply REMOVING the `agents:` block: the plane — and the gate it holds — is dropped whole.
    let removed = build_once(
        cfg_with_provider_api_key(busbar_core::config::SecretRef::env(
            "BUSBAR_TEST_NO_SUCH_KEY_A2A_PRUNE",
        )),
        Some(&prior),
    )
    .expect("apply with agents removed");
    assert!(
        busbar_a2a::a2a::runtime(&removed).is_none(),
        "removing the agents: block leaves no a2a plane and no carried verify gate to leak"
    );
}

/// An MCP resource mounted at `/mcp`, from the same `mcp:` config shape an operator writes.
/// THE SHIPPED DEFECT: an oversized POST to a MOUNTED MCP plane was answered with an
/// **OpenAI** error envelope — `{"error":{"message","type","code"}}` — because the error-shaping
/// classifier read the PATH SHAPE only, knew nothing of the mount table, and fell through its
/// unknown-ingress arm to OpenAI. An MCP client speaks JSON-RPC 2.0 and cannot decode that body;
/// worse, the answer contradicted the mount the operator configured.
///
/// RED before the merge: the body carried `error.type` and no `jsonrpc` member.
#[tokio::test]
async fn oversized_post_to_a_mounted_mcp_plane_is_refused_in_the_planes_own_dialect() {
    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    let app = busbar_core::test_support::TestApp::new()
        .mcp(&busbar_mcp::testkit::mcp_cfg_at(
            "https://gateway.example.com/mcp",
        ))
        .build();

    let v = oversized_413_body(app, "/mcp").await;

    assert_eq!(
        v.get("jsonrpc").and_then(|j| j.as_str()),
        Some("2.0"),
        "a mounted MCP plane must refuse in JSON-RPC 2.0, the only wire format it speaks; got {v}"
    );
    assert!(
        v.pointer("/error/code").and_then(|c| c.as_i64()).is_some(),
        "a JSON-RPC refusal carries a numeric `error.code`; got {v}"
    );
    assert!(
        v.pointer("/error/type").is_none(),
        "`error.type` is the OpenAI envelope's member — the vendor shape must not survive on a \
         mounted plane; got {v}"
    );
}

/// THE SEGMENT BOUNDARY, IN BOTH DIRECTIONS. A mount at `/mcp` claims `/mcp` and everything
/// beneath it at a segment boundary, and claims `/mcpx` not at all. A sibling path must inherit
/// neither the plane's grants nor its refusals, so `/mcpx` keeps the residual plane's answer.
#[tokio::test]
async fn a_mount_claims_its_own_segment_and_not_its_sibling() {
    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    let app = busbar_core::test_support::TestApp::new()
        .mcp(&busbar_mcp::testkit::mcp_cfg_at(
            "https://gateway.example.com/mcp",
        ))
        .build();

    // UNDER the mount, at a segment boundary: claimed.
    let under = oversized_413_body(app.clone(), "/mcp/anything").await;
    assert_eq!(
        under.get("jsonrpc").and_then(|j| j.as_str()),
        Some("2.0"),
        "`/mcp/anything` lies beneath the `/mcp` mount at a segment boundary; got {under}"
    );

    // The SIBLING: a bare-prefix match would claim it. It must fall through to the residual.
    let sibling = oversized_413_body(app, "/mcpx").await;
    assert!(
        sibling.get("jsonrpc").is_none(),
        "`/mcpx` is NOT under a `/mcp` mount — it must not inherit the plane's refusal shape; \
         got {sibling}"
    );
    assert!(
        sibling.pointer("/error/message").is_some(),
        "the residual plane still answers a legible native envelope; got {sibling}"
    );
}

/// A `agents:` entry lowering to a real, RECEIVING `A2aPlane` — the same shape
/// `plane::tests::registry_tests::a2a_slot_receiving` uses, duplicated here rather than shared
/// because that fixture is `pub(crate)` to `plane::tests` only.
/// THE POSITIVE CASE: with `mcp:` and a receiving `agents:` both configured,
/// `App::plane_slot("mcp")`/`("a2a")` are `Some`, and downcasting each is the exact same `Arc`
/// object the plane's neutral accessor (`busbar_mcp::mcp::resource` / `busbar_a2a::a2a::runtime`) reads — not a
/// second, merely-equal construction. Both typed `App::mcp`/`App::a2a` fields are now dissolved, so
/// this proves `build_app_from_config` builds each plane ONCE via `PlaneDecl::build` and the accessor
/// reads that one slot object, rather than a typed-field mirror.
#[test]
fn plane_slot_mirrors_the_typed_mcp_and_a2a_fields_when_configured() {
    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    let mut cfg = cfg_with_provider_api_key(busbar_core::config::SecretRef::env(
        "BUSBAR_TEST_NO_SUCH_KEY_PLANE_SLOT_PRESENT",
    ));
    cfg.endpoint_resources.insert(
        busbar_core::config::named_map::NamedMapSection::Tools.key(),
        std::sync::Arc::new(
            busbar_mcp::mcp::McpResource::from_cfg(&busbar_mcp::testkit::mcp_cfg_at(
                "https://gw.example.com/mcp",
            ))
            .expect("valid mcp cfg"),
        ) as std::sync::Arc<dyn std::any::Any + Send + Sync>,
    );
    cfg.agent_defs = Box::new(busbar_a2a::testkit::agents_cfg_with_one_receiving_agent());
    cfg.public_url = Some("https://busbar.example".to_string());
    // `mcp:` refuses an open data-plane chain — close it with the test-only stand-in module.
    cfg.auth = Some(closed_auth_chain("test-groups-module"));

    let app = build_once(cfg, None).expect("app builds with mcp: + agents: configured");

    let mcp_slot = app
        .plane_slot("mcp")
        .expect("mcp: configured => plane_slot(\"mcp\") is Some")
        .clone();
    let mcp_via_slot = mcp_slot
        .downcast::<busbar_mcp::mcp::McpResource>()
        .expect("the mcp plane's slot is an McpResource");
    // `App::mcp` was dissolved: the MCP plane now reads its runtime object ONLY through the
    // type-erased slot, via the neutral accessor `busbar_mcp::mcp::resource`. The invariant this used to
    // state as "typed field and slot are the same Arc" is now "the neutral accessor reads the SAME
    // object the slot holds, not a second construction".
    assert!(
        std::ptr::eq(
            std::sync::Arc::as_ptr(&mcp_via_slot),
            busbar_mcp::mcp::resource(&app).expect("mcp: configured => resource(app) is Some")
                as *const busbar_mcp::mcp::McpResource
        ),
        "busbar_mcp::mcp::resource must read the SAME object plane_slot(\"mcp\") holds, not a second \
         construction"
    );

    let a2a_slot = app
        .plane_slot("a2a")
        .expect("a receiving agents: entry => plane_slot(\"a2a\") is Some")
        .clone();
    let a2a_via_slot = a2a_slot
        .downcast::<busbar_a2a::a2a::plane::A2aPlane>()
        .expect("the a2a plane's slot is an A2aPlane");
    // `App::a2a` was dissolved exactly like `App::mcp`: the A2A plane now reads its runtime object
    // ONLY through the type-erased slot, via the neutral accessor `busbar_a2a::a2a::runtime`. The invariant
    // this used to state as "typed field and slot are the same Arc" is now "the neutral accessor reads
    // the SAME object the slot holds, not a second construction".
    assert!(
        std::ptr::eq(
            std::sync::Arc::as_ptr(&a2a_via_slot),
            busbar_a2a::a2a::runtime(&app).expect("agents: configured => runtime(app) is Some")
                as *const busbar_a2a::a2a::plane::A2aPlane
        ),
        "busbar_a2a::a2a::runtime must read the SAME object plane_slot(\"a2a\") holds, not a second \
         construction"
    );
}

/// THE NEGATIVE CASE (the RED-first gate): a deployment with NO `tools:`/`agents:` gets no slot
/// for either plane — exactly the absence the neutral accessors (`busbar_mcp::mcp::resource` /
/// `busbar_a2a::a2a::runtime`) already encode.
/// Watched RED before `PlaneDecl::build` guarded absence (an unconditional `build` that always
/// constructs an object regardless of `ctx.mcp_slot`/`ctx.agent_defs` makes this fail: `plane_slot`
/// answers `Some` on a deployment that configured no plane, disagreeing with the neutral accessor's
/// `None` right beside it).
#[test]
fn plane_slot_is_none_when_the_plane_is_not_configured() {
    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
    let cfg = cfg_with_provider_api_key(busbar_core::config::SecretRef::env(
        "BUSBAR_TEST_NO_SUCH_KEY_PLANE_SLOT_ABSENT",
    ));
    assert!(
        cfg.endpoint_resources.is_empty(),
        "fixture control: not an mcp: deployment"
    );
    assert!(
        cfg.agent_defs.def_names().is_empty(),
        "fixture control: no agents: entries"
    );

    let app = build_once(cfg, None).expect("app builds with neither plane configured");

    assert!(
        busbar_mcp::mcp::resource(&app).is_none(),
        "control: the neutral mcp accessor is None"
    );
    assert!(
        busbar_a2a::a2a::runtime(&app).is_none(),
        "control: the neutral a2a accessor is None"
    );
    assert!(
        app.plane_slot("mcp").is_none(),
        "no tools: => no mcp slot, matching the neutral accessor's own None"
    );
    assert!(
        app.plane_slot("a2a").is_none(),
        "no agents: => no a2a slot, matching the neutral a2a accessor's own None"
    );
}

/// A pool name used by NOTHING else in this binary. The test process shares one global recorder and
/// runs tests in parallel, so an exact-delta assertion has to be made on a label set no other test
/// can touch; `"unresolved"` would not be one.
const POOL: &str = "observe-residual-exactness-pool";

/// A MODEL-plane request is counted EXACTLY ONCE with the planes mounted alongside it.
///
/// The residual plane is the one the boundary must not touch: it labels its own requests from
/// `ingress::finish_inner`, which also owns the non-2xx flat-fee refund and therefore cannot be
/// replaced by the layer. If the layer ever stops asking the mount table and starts counting
/// everything, this goes to 2 and says so.
#[tokio::test]
async fn a_model_plane_request_is_counted_exactly_once() {
    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();
    // Register the residual LLM plane (as the composition root does in production and the MCP/A2A
    // testkits do for their planes), so the neutral residual-key derivation recognises `llm` as the
    // residual — otherwise the model-plane boundary would not know this request rides the residual and
    // would double-count it. Idempotent, process-wide.
    busbar_core::plane::registry::register_test_plane(&busbar_llm::PLANE_DECL);
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "observe-residual-model",
            busbar_core::proto::PROTO_OPENAI,
            "http://127.0.0.1:1",
        ))
        .pool(POOL, &[(0, 1)])
        .mcp(&busbar_mcp::mcp::McpCfg {
            canonical_uri: "https://gateway.example.com/mcp".to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .build();
    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // The model plane's `busbar_requests_total` carries NO `plane` label (v1.5.4-identical); this
    // pool name is unique to this test, so it alone pins the delta.
    let labels = [("pool", POOL)];
    let before = metric_sum(busbar_core::metrics::REQUESTS_TOTAL, &labels);
    // The upstream is a closed port, so this fails to forward — which is fine and deliberate. What
    // is under test is HOW MANY TIMES the request is counted, not what it returned.
    let _ = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": POOL,
            "messages": [{ "role": "user", "content": "hi" }],
        }))
        .send()
        .await
        .unwrap();
    let after = metric_sum(busbar_core::metrics::REQUESTS_TOTAL, &labels);
    server.abort();

    assert_eq!(
        (after - before).round() as u64,
        1,
        "one model-plane request must produce ONE count, not one from `finish_inner` plus one from \
         the plane ingress boundary"
    );
}

#[cfg(test)]
mod metrics_scrape {
    #![allow(unused_imports)]
    use busbar_a2a::testkit::TestAppA2aExt as _;
    use busbar_core::test_support::*;
    use busbar_mcp::testkit::TestAppMcpExt as _;

    use busbar_a2a::a2a::config::{AgentDefCfg, AgentPinCfg, PinMechanism};
    use busbar_core::test_support::TestApp;
    use busbar_mcp::mcp::envelope::PROTOCOL_VERSION;
    use busbar_mcp::mcp::McpCfg;
    use busbar_mcp::testkit::TestAppMcpExt as _;

    const CANONICAL: &str = "https://gateway.example.com/mcp";

    fn mcp_cfg() -> McpCfg {
        McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        }
    }

    /// A well-formed MCP JSON-RPC envelope for `method`, with the mirrored headers the transport
    /// requires. Nothing here is malformed: the point is REAL tool-plane traffic.
    fn mcp_envelope(method: &str) -> (serde_json::Value, Vec<(&'static str, String)>) {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        });
        let headers = vec![
            ("mcp-protocol-version", PROTOCOL_VERSION.to_string()),
            ("mcp-method", method.to_string()),
        ];
        (body, headers)
    }

    /// Every non-comment `/metrics` line for `family` that carries `plane="<plane>"`.
    fn series_for<'a>(exposition: &'a str, family: &str, plane: &str) -> Vec<&'a str> {
        let want = format!("plane=\"{plane}\"");
        exposition
            .lines()
            .filter(|l| !l.starts_with('#') && l.starts_with(family) && l.contains(&want))
            .collect()
    }

    /// Every non-comment `/metrics` line for `family` (no plane filter) — used for the model-plane
    /// families, which carry no `plane` label.
    fn lines_for<'a>(exposition: &'a str, family: &str) -> Vec<&'a str> {
        exposition
            .lines()
            .filter(|l| !l.starts_with('#') && l.starts_with(family))
            .collect()
    }

    /// The sorted label KEYS of one exposition line.
    fn keys_of(line: &str) -> Vec<String> {
        line.split_once('{')
            .and_then(|(_, rest)| rest.rsplit_once('}'))
            .map(|(inner, _)| {
                let mut ks: Vec<String> = inner
                    .split(',')
                    .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string()))
                    .collect();
                ks.sort();
                ks
            })
            .unwrap_or_default()
    }

    /// A TOOL CALL and an AGENT TASK each produce a `busbar_plane_requests_total` and a
    /// `busbar_plane_request_duration_seconds` series on a real `/metrics` scrape, labelled with the
    /// plane they arrived on — WHILE the model plane's `busbar_requests_total` stays v1.5.4-identical
    /// (no `plane` label).
    ///
    /// Delete the observation layer and this test fails: without it, no MCP or A2A request reaches an
    /// emission site at all. That is what the test is for — the two planes were invisible on `/metrics`.
    #[tokio::test]
    async fn mcp_and_a2a_traffic_appear_on_a_real_metrics_scrape() {
        busbar_core::metrics::init();
        busbar_llm::testkit::install_test_seams();
        // Register the residual LLM plane (as the composition root does in production and the MCP/A2A
        // testkits do for their planes), so the neutral residual-key derivation recognises `llm` as the
        // residual and the model-plane traffic below stays on the v1.5.4 model family (no `plane`
        // label, one count) rather than being mistaken for a mounted plane. Idempotent, process-wide.
        busbar_core::plane::registry::register_test_plane(&busbar_llm::PLANE_DECL);
        let app = TestApp::new()
            .public_url("https://busbar.example")
            .mcp(&mcp_cfg())
            .agent_def(
                "planner",
                busbar_a2a::testkit::unpinned_agent("https://a2a.vendor/planner"),
            )
            .build();
        let router = busbar_core::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // ── TOOL-PLANE TRAFFIC ──────────────────────────────────────────────────────────────────────
        let (body, headers) = mcp_envelope("tools/list");
        let mut req = client.post(format!("{base}/mcp")).json(&body);
        for (k, v) in &headers {
            req = req.header(*k, v.clone());
        }
        let mcp_status = req.send().await.unwrap().status().as_u16();

        // ── AGENT-PLANE TRAFFIC ─────────────────────────────────────────────────────────────────────
        let a2a_status = client
            .post(format!("{base}/a2a/agents/planner"))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": { "message": { "role": "user", "parts": [{ "kind": "text", "text": "go" }] } },
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();

        // ── MODEL-PLANE TRAFFIC, so the three planes are compared on ONE scrape ─────────────────────
        // An unroutable model is deliberate: it reaches `ingress::finish_inner` without needing an
        // upstream, which is all this assertion needs. The point is the SERIES SHAPE, not the status.
        let llm_status = client
            .post(format!("{base}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": "no-such-model",
                "messages": [{ "role": "user", "content": "hi" }],
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();

        // ── THE SCRAPE, through the real `/metrics` route ───────────────────────────────────────────
        let scrape = client.get(format!("{base}/metrics")).send().await.unwrap();
        assert_eq!(
            scrape.status().as_u16(),
            200,
            "the built-in prometheus exporter must serve /metrics on this router"
        );
        let exposition = scrape.text().await.unwrap();
        server.abort();

        // THE MOUNTED PLANES ARE VISIBLE. MCP and A2A each land on `busbar_plane_requests_total` /
        // `busbar_plane_request_duration_seconds`, labelled with the plane they arrived on, so an
        // operator can write `sum by (plane) (rate(busbar_plane_requests_total[5m]))`.
        for plane in ["mcp", "a2a"] {
            let counters = series_for(
                &exposition,
                busbar_core::metrics::PLANE_REQUESTS_TOTAL,
                plane,
            );
            assert!(
                !counters.is_empty(),
                "no `{}` series for plane=\"{plane}\" after driving real traffic \
                 (mcp {mcp_status}, a2a {a2a_status}, llm {llm_status}). Exposition:\n{exposition}",
                busbar_core::metrics::PLANE_REQUESTS_TOTAL,
            );
            let durations = series_for(
                &exposition,
                busbar_core::metrics::PLANE_REQUEST_DURATION_SECONDS,
                plane,
            );
            assert!(
                !durations.is_empty(),
                "no `{}` series for plane=\"{plane}\" after driving real traffic. Exposition:\n{exposition}",
                busbar_core::metrics::PLANE_REQUEST_DURATION_SECONDS,
            );
            // The mounted planes' family carries exactly {plane, ingress_protocol, pool, outcome}.
            for line in &counters {
                assert_eq!(
                    keys_of(line),
                    vec![
                        "ingress_protocol".to_string(),
                        "outcome".to_string(),
                        "plane".to_string(),
                        "pool".to_string()
                    ],
                    "plane=\"{plane}\" invented a differently-shaped series: {line}"
                );
            }
        }

        // THE MODEL PLANE STAYS v1.5.4-IDENTICAL. `busbar_requests_total` carries the exact 1.5.4 label
        // set {ingress_protocol, pool, outcome} and NO `plane` label — the whole point of the split.
        // (The recorder is process-global and shared across the whole test binary, so other tests'
        // model-plane series are present too; the positive claim is that a correctly-shaped one exists,
        // and the byte-identity guard below then holds for EVERY model-family line regardless of origin.)
        let llm_counters = lines_for(&exposition, busbar_core::metrics::REQUESTS_TOTAL);
        assert!(
            llm_counters.iter().any(|line| keys_of(line)
                == vec![
                    "ingress_protocol".to_string(),
                    "outcome".to_string(),
                    "pool".to_string()
                ]),
            "no v1.5.4-shaped `{}` series {{ingress_protocol,pool,outcome}} after driving model traffic \
             (llm {llm_status}). Exposition:\n{exposition}",
            busbar_core::metrics::REQUESTS_TOTAL,
        );
        assert!(
            !lines_for(&exposition, busbar_core::metrics::REQUEST_DURATION_SECONDS).is_empty(),
            "no `{}` series after driving model traffic. Exposition:\n{exposition}",
            busbar_core::metrics::REQUEST_DURATION_SECONDS,
        );
        // BYTE-IDENTITY GUARD: the two model families never carry a `plane` label anywhere in the whole
        // exposition. This is the assertion that fails if the BI-2 regression (a `plane` label on these
        // pre-existing families) is ever reintroduced by any emission site.
        for family in [
            busbar_core::metrics::REQUESTS_TOTAL,
            busbar_core::metrics::REQUEST_DURATION_SECONDS,
        ] {
            for line in lines_for(&exposition, family) {
                assert!(
                    !line.contains("plane=\""),
                    "a `plane` label leaked onto the v1.5.4 model family `{family}`: {line}"
                );
            }
        }
    }
}

/// THE PLANE-BOUNDARY RATCHET (1.6.0), driven by the
/// ROUTER TABLE rather than by a hand-listed sample.
///
/// The rule: an MCP access token is admissible on the MCP plane and nowhere else. A
/// sampled test proves that of the paths someone remembered; this one walks
/// `CoreRouteTable::routes()` — the table every core route is entered into at the moment it is
/// mounted — plus `App::boot_route_paths` for the plugin surface, so a route added later JOINS the
/// assertion instead of quietly joining the blast radius. There is no skip arm: a path whose shape
/// this test cannot turn into a concrete request PANICS rather than passing.
///
/// `MCP_ADMISSIBLE` is empty because no MCP ingress is mounted yet; when it is, it goes in that set
/// and nowhere else. `DECLARED_PUBLIC` is the mirror ratchet on the other axis: a route mounted
/// `RouteAuth::None` answers everyone, so adding one must be a deliberate act that shows up here.
#[tokio::test]
async fn test_mcp_token_is_confined_to_the_mcp_plane() {
    use busbar_core::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_core::governance::{GovState, MemoryStore};
    use busbar_core::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use std::sync::Arc;

    busbar_core::metrics::init();
    busbar_llm::testkit::install_test_seams();

    /// The MCP ingress paths, the ONLY places an audience-bound token may be admitted. The app
    /// below MOUNTS the plane, so this list is exercised in both directions: an audience-bound
    /// token is admitted here and nowhere else, and a plain data-plane token is admitted everywhere
    /// else and not here.
    const MCP_ADMISSIBLE: &[&str] = &["/mcp"];
    /// Core routes declared `RouteAuth::None`: unauthenticated by design, so no token of any kind
    /// is consulted there. `/healthz` is a liveness probe; `/auth/token` runs the auth chain in its
    /// own handler; the RFC 9728 metadata document must be readable by a caller that has no token
    /// yet, because that caller is the entire population the document exists for.
    const DECLARED_PUBLIC: &[&str] = &[
        "/healthz",
        "/auth/token",
        "/.well-known/oauth-protected-resource/mcp",
    ];
    /// The canonical URI of the MCP plane in this test. It is BOTH the audience minted into
    /// `bound_token` below AND the `mcp.canonical_uri` the app is built with — one string, used
    /// twice, because a test in which they differed would prove only that two spellings disagree.
    const MCP_CANONICAL: &str = "https://busbar.example.com/mcp";

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    // An UNRESTRICTED key: `allowed_scopes: None` is the wildcard (`store.rs`), so the only thing
    // that can turn the audience-bound sibling away is the plane boundary itself, never a scope.
    let (key, plain_token) = gov
        .mint_signed(
            busbar_core::governance::NewKeySpec {
                name: "mcp-agent".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
    let generation = verifier
        .verify(plain_token.as_str(), 1_000_000_000, None)
        .expect("plain claims")
        .generation;
    let bound_token = signer.mint_for_audience(
        &key.id,
        2_000_000_000,
        generation.as_deref(),
        "https://busbar.example.com/mcp",
        Some("client-1"),
    );

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                busbar_core::proto::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .mcp(&busbar_mcp::mcp::McpCfg {
            canonical_uri: MCP_CANONICAL.to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .build();

    // The table the SERVED router was built from: same function, same plugin-route input, same MCP
    // resource, so the enumeration cannot describe a different surface than the one under test. Read
    // through the curated `(path, method, auth)` test-support seam so this cross-crate integration
    // test names PUBLIC types only, never core's sealed `CoreRoute`/`CoreRouteTable`.
    let core_routes = busbar_core::base_data_route_method_view(&app);
    // FLOOR ON THE DISCOVERED SET, in the one dimension that matters here: the walk below is only a
    // plane-boundary test if the router actually mounted the plane. Without this, deleting the MCP
    // mount would leave every assertion below trivially satisfied and the test would still pass.
    for admissible in MCP_ADMISSIBLE {
        assert!(
            core_routes.iter().any(|(path, _, _)| path == *admissible),
            "{admissible} is declared MCP-admissible but no core route mounts it — the walk would              assert nothing about the plane it is named for"
        );
    }
    let boot_plugin_paths: Vec<String> = busbar_core::boot_route_paths_of(&app);
    assert!(
        !core_routes.is_empty(),
        "an empty table would make every assertion below vacuous"
    );

    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Turn an axum path PATTERN into one concrete request path. Every `{capture}` segment is a
    // routing wildcard, so any non-empty segment matches; the values below are real names in this
    // app so the request reaches the handler rather than dying earlier for an unrelated reason.
    // A pattern shape this cannot render PANICS — that is the ratchet.
    fn concrete(pattern: &str) -> String {
        let mut out = String::new();
        for seg in pattern.split('/').skip(1) {
            out.push('/');
            if seg.starts_with('{') && seg.ends_with('}') {
                out.push_str(match seg {
                    "{name}" => "pa",
                    "{provider}" => "anthropic",
                    "{model}" => "test-model",
                    other => panic!(
                        "route pattern segment {other} has no fixture value: give it one, never \
                         skip the route"
                    ),
                });
            } else {
                out.push_str(seg);
            }
        }
        if out.is_empty() {
            "/".to_string()
        } else {
            out
        }
    }

    let body = serde_json::json!({
        "model": "pa",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16
    })
    .to_string();

    let mut checked = 0usize;
    let mut mcp_checked = 0usize;
    for route in &core_routes {
        let path = concrete(&route.0);
        if route.2 == busbar_plugin_loader::RouteAuth::None {
            assert!(
                DECLARED_PUBLIC.contains(&route.0.as_str()),
                "{} is mounted RouteAuth::None but is not in DECLARED_PUBLIC — an unauthenticated \
                 core route must be a deliberate, reviewed act",
                route.0
            );
            continue;
        }
        let method = reqwest::Method::from_bytes(route.1.as_bytes()).unwrap();
        // THE MCP ARM, and it is the reciprocal of the data-plane arm below rather than a weaker
        // version of it: on this plane the audience-bound token is the one that WORKS and the plain
        // data-plane token is the one that must buy nothing. Asserting only the first half would
        // pass against a server that admitted both, which is the failure mode the boundary exists
        // to prevent.
        if MCP_ADMISSIBLE.contains(&route.0.as_str()) {
            let url = format!("http://{addr}{path}");
            let anon = client
                .request(method.clone(), &url)
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                anon.status(),
                401,
                "an unauthenticated caller on the MCP plane must get 401, not a vendor-shaped \
                 envelope, on {} {}",
                route.1,
                path
            );
            assert!(
                anon.headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("Bearer ") && v.contains("resource_metadata=")),
                "a 401 on an OAuth protected resource must carry a Bearer challenge naming its \
                 resource_metadata — without it the client has no way to find the authorization \
                 server, on {} {}",
                route.1,
                path
            );
            let bound = client
                .request(method.clone(), &url)
                .header("authorization", format!("Bearer {bound_token}"))
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_ne!(
                bound.status(),
                401,
                "the audience-bound token is minted for exactly this resource and must be admitted \
                 on {} {}",
                route.1,
                path
            );
            let plain = client
                .request(method.clone(), &url)
                .header("authorization", format!("Bearer {}", plain_token.as_str()))
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                plain.status(),
                401,
                "a plain data-plane key carries no audience and must be inadmissible on the MCP \
                 plane, on {} {}",
                route.1,
                path
            );
            mcp_checked += 1;
            continue;
        }
        let url = format!("http://{addr}{path}");
        // The denial BASELINE for this exact route: no credential at all. Auth failures are
        // protocol-shaped (`auth_failure_status_and_kind` — Gemini answers 400, Bedrock 403), so a
        // literal 401 would be a claim about the envelope rather than about admission. Comparing
        // against the no-credential response asserts the thing that matters: the audience-bound
        // token buys exactly nothing here.
        let anon = client
            .request(method.clone(), &url)
            .body(body.clone())
            .send()
            .await
            .unwrap()
            .status();
        let bound = client
            .request(method.clone(), &url)
            .header("authorization", format!("Bearer {bound_token}"))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            bound.status(),
            anon,
            "audience-bound MCP token must be treated as no credential on {} {}",
            route.1,
            path
        );
        // Control on the SAME route: the plain sibling of the same unrestricted binding IS
        // admitted, so the denial above is the plane boundary and not an unrelated rejection.
        let plain = client
            .request(method, &url)
            .header("authorization", format!("Bearer {}", plain_token.as_str()))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            plain.status(),
            anon,
            "the plain data-plane sibling must still be admitted on {} {}",
            route.1,
            path
        );
        checked += 1;
    }
    assert_eq!(
        mcp_checked,
        core_routes
            .iter()
            .filter(|(path, _, _)| MCP_ADMISSIBLE.contains(&path.as_str()))
            .count(),
        "every MCP-admissible mounted route must have been walked; a mismatch means a route named \
         in MCP_ADMISSIBLE was mounted with an auth level that skipped the arm"
    );
    assert!(
        mcp_checked > 0,
        "no MCP route was walked, so the reciprocal half of the boundary was never asserted"
    );
    assert!(
        checked >= 4,
        "the walk covered only {checked} guarded core routes, which is fewer than the surface this \
         binary mounts — the enumeration is not seeing the router"
    );

    // The plugin surface is enumerable through the same boot capture. This app loads no plugins,
    // so the set is empty; the loop is here so a plugin route is covered the moment one exists.
    for path in &boot_plugin_paths {
        let url = format!("http://{addr}{path}");
        let anon = client.get(&url).send().await.unwrap().status();
        let bound = client
            .get(&url)
            .header("authorization", format!("Bearer {bound_token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            bound.status(),
            anon,
            "audience-bound MCP token must be treated as no credential on plugin route {path}"
        );
    }

    handle.abort();
    server.shutdown().await;
}
