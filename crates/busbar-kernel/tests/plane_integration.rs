// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE INTEGRATION TESTS for busbar-kernel: a REAL `build_app_from_config`-built (or
//! `TestApp`-built) `App` serving the REAL linked planes. That only type-checks when there is ONE
//! `busbar_kernel` in the graph, which is exactly what an integration-test target gives.
//!
//! The planes come from the test-linked table (`tests/linked/mod.rs`, architect ruling N02 MOVE
//! rows); this file names none of them. A plane is addressed by what it declares — the config section
//! it owns, its endpoint door — read back from the registry, and it is CONFIGURED the way an operator
//! configures it: a deploy document run through the kernel's own `resolve`, and the plane's runtime
//! object built through its own declared `build`, `claims` and `admission` hooks.

mod linked;

use busbar_kernel::config::RootCfg;
use busbar_kernel::plane::registry::{BuildCtx, PlaneDecl};
use busbar_kernel::test_support::*;
use std::sync::Arc;

/// The linked plane that owns the `tools:` section and serves the endpoint door.
fn door_plane() -> &'static PlaneDecl {
    linked::owning("tools")
}

/// The linked plane that owns the `agents:` section.
fn agents_plane() -> &'static PlaneDecl {
    linked::owning("agents")
}

/// The door plane's endpoint block, as an operator writes it, with its canonical URI at
/// `https://<host>/<plane key>` — so the mount path is the key the plane declared, read back.
fn door_section_yaml(host: &str) -> String {
    let door = door_plane();
    format!(
        "{section}:\n  canonical_uri: \"https://{host}/{key}\"\n  \
         authorization_servers: [\"https://login.example.com\"]\n",
        section = linked::door_section(door),
        key = door.key,
    )
}

/// One receiving `agents:` entry, `planner`.
const AGENTS_YAML: &str =
    "agents:\n  planner: { url: \"https://agent.example/planner\", pin: { mechanism: unpinned } }\n";

/// Parse and RESOLVE a deploy document carrying `sections`, the way boot and `--validate` do — the
/// plane sections are lowered by the planes' own hooks, never by a plane type named here.
fn resolved(sections: &str) -> RootCfg {
    linked::install();
    let yaml = format!(
        "providers:\n  acme: {{ api_key: none }}\n\
         models:\n  m: {{ provider: acme }}\n{sections}"
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("the document parses");
    let mut defs = std::collections::HashMap::new();
    defs.insert(
        "acme".to_string(),
        serde_yaml::from_str(&format!(
            "protocol: {}\nbase_url: https://api.example.com\n",
            busbar_kernel::proto::residual_default_dialect().expect("a residual-default dialect")
        ))
        .expect("provider def"),
    );
    busbar_kernel::config::resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("the document resolves: {e:?}"))
}

/// A resolved config ready for `build_once`: the given sections, a public URL, and the closed
/// data-plane chain a configured endpoint door requires.
fn bootable(sections: &str) -> RootCfg {
    let mut cfg = resolved(sections);
    cfg.public_url = Some("https://busbar.example".to_string());
    cfg.auth = Some(closed_auth_chain("test-groups-module"));
    cfg
}

/// Every linked plane the resolved config configures, with the runtime object its OWN `build` hook
/// constructs from that config — the same `BuildCtx` `build_app_from_config` hands it.
fn built_planes(cfg: &RootCfg) -> Vec<(&'static PlaneDecl, Arc<dyn std::any::Any + Send + Sync>)> {
    linked::planes()
        .iter()
        .copied()
        .filter(|d| cfg.plane_sections.contains(d.config_section))
        .filter_map(|decl| {
            let ctx = BuildCtx {
                endpoint_slot: cfg.endpoint_resources.get(decl.config_section).cloned(),
                agent_defs: cfg.agent_defs.as_any(),
                public_url: cfg.public_url.as_deref(),
                prior: None,
            };
            (decl.build)(&ctx).map(|obj| (decl, obj))
        })
        .collect()
}

/// Configure a `TestApp` with every plane `sections` configures: install each plane's runtime
/// object, mount every path it CLAIMS off that object, and bind the admission it DECLARES — the
/// kernel's own `build_dispatch` contract, driven through the neutral fixture seams.
fn configured(mut app: TestApp, sections: &str, public_url: Option<&str>) -> TestApp {
    let mut cfg = resolved(sections);
    cfg.public_url = public_url.map(str::to_string);
    for (decl, obj) in built_planes(&cfg) {
        let claims = (decl.claims)(&*obj);
        let admission = (decl.admission)(&*obj);
        for (path, wire) in claims {
            app.mount_plane(decl.key, &path, wire);
        }
        if let Some(admission) = admission {
            app.admit_plane(decl.key, admission);
        }
        app.install_plane_runtime(decl.key, obj);
    }
    app
}

/// The path `decl` claims for its JSON-RPC front door, read off the object its `build` constructs
/// from `sections`.
fn jsonrpc_mount(decl: &'static PlaneDecl, sections: &str) -> String {
    let mut cfg = resolved(sections);
    cfg.public_url = Some("https://busbar.example".to_string());
    let (_, obj) = built_planes(&cfg)
        .into_iter()
        .find(|(d, _)| d.key == decl.key)
        .unwrap_or_else(|| panic!("the `{}` plane builds from its section", decl.key));
    (decl.claims)(&*obj)
        .into_iter()
        .find(|(_, wire)| *wire == busbar_kernel::plane::WIRE_JSONRPC)
        .map(|(path, _)| path)
        .unwrap_or_else(|| panic!("the `{}` plane claims a JSON-RPC front door", decl.key))
}

/// THE CARRIED VERIFY GATE of the `agents:` plane. The gate is a field of that plane's runtime
/// object, whose type this file cannot name, so the plane's own test-seam entry reads it off the
/// built App's plane slots — found in the registry by the key the plane declares.
fn carried_gate(app: &busbar_kernel::state::App) -> Option<Arc<busbar_kernel::trust::VerifyGate>> {
    let read = linked::seam(agents_plane())
        .verify_gate
        .expect("the `agents:` plane reads its carried verify gate through its test seam");
    read(app)
}

/// The `agents:` plane's verify-on-call gate lives ON its runtime object, carried across a config
/// apply off the prior generation's plane. This exercises the two ways a carried entry stops
/// leaking:
///
/// 1. A SURVIVING plane whose live set no longer names a subject must PRUNE that subject's carried
///    flight/drift-latch — the plane's `retain_verify_gates` hook, reading the gate off the plane
///    slot rather than off a shared `App` field.
/// 2. REMOVING the `agents:` block drops the whole plane, and with it the gate — a deployment
///    fronting no agents runs no delegation that could read a leaked entry.
#[test]
fn the_carried_verify_gate_prunes_dead_subjects_and_drops_with_the_plane() {
    busbar_kernel::metrics::init();
    let key = agents_plane().key;
    let prior = build_once(resolved(AGENTS_YAML), None).expect("boot with an agents: block");
    // The plane's OWN verify gate accumulated per-subject coordination for an agent this deployment
    // once fronted. "retired-agent" is NOT the live "planner", so a retain against the live set
    // must drop it.
    let prior_gate = carried_gate(&prior).expect("agents: configured => the plane is present");
    prior_gate.report(key, "retired-agent", true, false);
    assert!(
        prior_gate.tracks_subject("retired-agent"),
        "seed: the plane's VerifyGate must track the subject before the apply"
    );

    // (1) Re-apply KEEPING the `agents:` block: the new plane carries the same gate forward, and the
    // retain hook prunes the dead subject against the live set (`{planner}`).
    let kept = build_once(resolved(AGENTS_YAML), Some(&prior)).expect("re-apply keeping agents:");
    let kept_gate = carried_gate(&kept).expect("agents: still configured => the plane is present");
    assert!(
        Arc::ptr_eq(&kept_gate, &prior_gate),
        "the surviving plane must carry the prior generation's gate forward, not start a new one"
    );
    assert!(
        !kept_gate.tracks_subject("retired-agent"),
        "a surviving plane must prune the carried gate entry no live agent names, not leak it"
    );
    assert!(
        kept.plane_slot(key).is_some(),
        "the surviving plane holds its slot"
    );

    // (2) Re-apply REMOVING the `agents:` block: the plane — and the gate it holds — is dropped whole.
    let removed = build_once(resolved(""), Some(&prior)).expect("apply with agents removed");
    assert!(
        carried_gate(&removed).is_none() && removed.plane_slot(key).is_none(),
        "removing the agents: block leaves no `{key}` plane and no carried verify gate to leak"
    );
}

/// THE SHIPPED DEFECT: an oversized POST to a MOUNTED endpoint-door plane was answered with an
/// **OpenAI** error envelope — `{"error":{"message","type","code"}}` — because the error-shaping
/// classifier read the PATH SHAPE only, knew nothing of the mount table, and fell through its
/// unknown-ingress arm to OpenAI. The door plane's clients speak JSON-RPC 2.0 and cannot decode that
/// body; worse, the answer contradicted the mount the operator configured.
///
/// RED before the merge: the body carried `error.type` and no `jsonrpc` member.
#[tokio::test]
async fn oversized_post_to_a_mounted_door_plane_is_refused_in_the_planes_own_dialect() {
    busbar_kernel::metrics::init();
    let sections = door_section_yaml("gateway.example.com");
    let mount = jsonrpc_mount(door_plane(), &sections);
    let app = configured(TestApp::new(), &sections, None).build();

    let v = oversized_413_body(app, &mount).await;

    assert_eq!(
        v.get("jsonrpc").and_then(|j| j.as_str()),
        Some("2.0"),
        "a mounted door plane must refuse in JSON-RPC 2.0, the only wire format it speaks; got {v}"
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

/// THE SEGMENT BOUNDARY, IN BOTH DIRECTIONS. A mount claims its path and everything beneath it at a
/// segment boundary, and claims `<mount>x` not at all. A sibling path must inherit neither the
/// plane's grants nor its refusals, so `<mount>x` keeps the residual plane's answer.
#[tokio::test]
async fn a_mount_claims_its_own_segment_and_not_its_sibling() {
    busbar_kernel::metrics::init();
    let sections = door_section_yaml("gateway.example.com");
    let mount = jsonrpc_mount(door_plane(), &sections);
    let app = configured(TestApp::new(), &sections, None).build();

    // UNDER the mount, at a segment boundary: claimed.
    let under = oversized_413_body(app.clone(), &format!("{mount}/anything")).await;
    assert_eq!(
        under.get("jsonrpc").and_then(|j| j.as_str()),
        Some("2.0"),
        "`{mount}/anything` lies beneath the `{mount}` mount at a segment boundary; got {under}"
    );

    // The SIBLING: a bare-prefix match would claim it. It must fall through to the residual.
    let sibling = oversized_413_body(app, &format!("{mount}x")).await;
    assert!(
        sibling.get("jsonrpc").is_none(),
        "`{mount}x` is NOT under the `{mount}` mount — it must not inherit the plane's refusal \
         shape; got {sibling}"
    );
    assert!(
        sibling.pointer("/error/message").is_some(),
        "the residual plane still answers a legible native envelope; got {sibling}"
    );
}

/// THE POSITIVE CASE: with the endpoint door and a receiving `agents:` entry both configured,
/// `App::plane_slot(<key>)` is `Some` for EACH configured plane, every read hands back the SAME
/// object (one construction, not a second, merely-equal one), and that object is the plane's own:
/// its declared `admission` hook reads it, and every JSON-RPC path its declared `claims` hook reads
/// off it is a route the built router mounted. So `build_app_from_config` builds each plane ONCE via its
/// `build` hook, and the router surface and the audience check come off that one slot object.
#[test]
fn plane_slot_holds_the_one_built_object_of_each_configured_plane() {
    busbar_kernel::metrics::init();
    let sections = format!("{}{AGENTS_YAML}", door_section_yaml("gw.example.com"));
    let cfg = bootable(&sections);
    let configured: Vec<&'static PlaneDecl> = linked::planes()
        .iter()
        .copied()
        .filter(|d| cfg.plane_sections.contains(d.config_section))
        .collect();
    assert_eq!(
        configured.len(),
        2,
        "the door and the agents: section configure two planes: {:?}",
        configured.iter().map(|d| d.key).collect::<Vec<_>>()
    );

    let app = build_once(cfg, None).expect("app builds with the door + agents: configured");
    let routes = busbar_kernel::base_data_route_method_view(&app);

    for decl in configured {
        let key = decl.key;
        let slot = app
            .plane_slot(key)
            .unwrap_or_else(|| panic!("`{key}` configured => plane_slot(\"{key}\") is Some"))
            .clone();
        let again = app.plane_slot(key).expect("a second read").clone();
        assert!(
            Arc::ptr_eq(&slot, &again),
            "plane_slot(\"{key}\") must hand back the SAME object on every read, not a second \
             construction"
        );
        assert!(
            (decl.admission)(&*slot).is_some(),
            "the `{key}` slot must be the plane's own object: its declared admission reads it"
        );
        let claims: Vec<String> = (decl.claims)(&*slot)
            .into_iter()
            .filter(|(_, wire)| *wire == busbar_kernel::plane::WIRE_JSONRPC)
            .map(|(path, _)| path)
            .collect();
        assert!(
            !claims.is_empty(),
            "the `{key}` plane claims its JSON-RPC door"
        );
        for path in claims {
            assert!(
                routes.iter().any(|(p, _, _)| *p == path),
                "`{path}`, claimed off the `{key}` slot object, must be a route the router mounted"
            );
        }
    }
}

/// THE NEGATIVE CASE (the RED-first gate): a deployment configuring NO plane section gets no slot
/// for any mounting plane. Watched RED before `PlaneDecl::build` guarded absence (an unconditional
/// `build` that always constructs an object makes `plane_slot` answer `Some` on a deployment that
/// configured no plane).
#[test]
fn plane_slot_is_none_when_the_plane_is_not_configured() {
    busbar_kernel::metrics::init();
    let cfg = resolved("");
    assert!(
        cfg.endpoint_resources.is_empty(),
        "fixture control: no endpoint door configured"
    );
    assert!(
        cfg.agent_defs.def_names().is_empty(),
        "fixture control: no agents: entries"
    );
    assert!(
        cfg.plane_sections.is_empty(),
        "fixture control: no plane section configured"
    );

    let app = build_once(cfg, None).expect("app builds with no plane configured");

    let mounting: Vec<&'static PlaneDecl> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .collect();
    assert!(
        mounting.len() >= 2,
        "the roster carries the planes this negative is about"
    );
    for decl in mounting {
        assert!(
            app.plane_slot(decl.key).is_none(),
            "no `{}:` section => no `{}` slot",
            decl.config_section,
            decl.key
        );
    }
}

/// A pool name used by NOTHING else in this binary. The test process shares one global recorder and
/// runs tests in parallel, so an exact-delta assertion has to be made on a label set no other test
/// can touch; `"unresolved"` would not be one.
const POOL: &str = "observe-residual-exactness-pool";

/// A MODEL-plane request is counted EXACTLY ONCE with the door plane mounted alongside it.
///
/// The residual plane is the one the boundary must not touch: it labels its own requests from
/// `ingress::finish_inner`, which also owns the non-2xx flat-fee refund and therefore cannot be
/// replaced by the layer. If the layer ever stops asking the mount table and starts counting
/// everything, this goes to 2 and says so.
#[tokio::test]
async fn a_model_plane_request_is_counted_exactly_once() {
    busbar_kernel::metrics::init();
    // The linked roster registers the fallback plane (as the composition root does in production),
    // so the neutral residual-key derivation recognises it as the residual — otherwise the
    // model-plane boundary would not know this request rides the residual and would double-count it.
    linked::install();
    assert!(
        linked::fallback().fallback,
        "the roster carries the fallback plane"
    );
    let app = configured(
        TestApp::new()
            .lane(LaneSpec::new(
                "observe-residual-model",
                busbar_kernel::proto::PROTO_OPENAI,
                "http://127.0.0.1:1",
            ))
            .pool(POOL, &[(0, 1)]),
        &door_section_yaml("gateway.example.com"),
        None,
    )
    .build();
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // The model plane's `busbar_requests_total` carries NO `plane` label (v1.5.4-identical); this
    // pool name is unique to this test, so it alone pins the delta.
    let labels = [("pool", POOL)];
    let before = metric_sum(busbar_kernel::metrics::REQUESTS_TOTAL, &labels);
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
    let after = metric_sum(busbar_kernel::metrics::REQUESTS_TOTAL, &labels);
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
    use super::*;

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

    /// A TOOL-PLANE call and an AGENT-PLANE task each produce a `busbar_plane_requests_total` and a
    /// `busbar_plane_request_duration_seconds` series on a real `/metrics` scrape, labelled with the
    /// plane they arrived on — WHILE the model plane's `busbar_requests_total` stays v1.5.4-identical
    /// (no `plane` label).
    ///
    /// Delete the observation layer and this test fails: without it, no mounted-plane request
    /// reaches an emission site at all. That is what the test is for — the mounted planes were
    /// invisible on `/metrics`.
    ///
    /// The test's NAME is pinned by `qa/capability-equality.json`, which cites it; the body names
    /// no plane.
    #[tokio::test]
    async fn mounted_plane_traffic_appears_on_a_real_metrics_scrape() {
        busbar_kernel::metrics::init();
        linked::install();
        let sections = format!("{}{AGENTS_YAML}", door_section_yaml("gateway.example.com"));
        let door_mount = jsonrpc_mount(door_plane(), &sections);
        let agents_mount = jsonrpc_mount(agents_plane(), &sections);
        let app = configured(
            TestApp::new().public_url("https://busbar.example"),
            &sections,
            Some("https://busbar.example"),
        )
        .build();
        let router = busbar_kernel::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // ── TOOL-PLANE TRAFFIC: a JSON-RPC list call on the door plane's mount ────────────────────
        let door_status = client
            .post(format!("{base}{door_mount}"))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();

        // ── AGENT-PLANE TRAFFIC ─────────────────────────────────────────────────────────────────────
        let agents_status = client
            .post(format!("{base}{agents_mount}/agents/planner"))
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
        let model_status = client
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

        // THE MOUNTED PLANES ARE VISIBLE. Each lands on `busbar_plane_requests_total` /
        // `busbar_plane_request_duration_seconds`, labelled with the plane it arrived on, so an
        // operator can write `sum by (plane) (rate(busbar_plane_requests_total[5m]))`.
        for plane in [door_plane().key, agents_plane().key] {
            let counters = series_for(
                &exposition,
                busbar_kernel::metrics::PLANE_REQUESTS_TOTAL,
                plane,
            );
            assert!(
                !counters.is_empty(),
                "no `{}` series for plane=\"{plane}\" after driving real traffic \
                 (door {door_status}, agents {agents_status}, model {model_status}). \
                 Exposition:\n{exposition}",
                busbar_kernel::metrics::PLANE_REQUESTS_TOTAL,
            );
            let durations = series_for(
                &exposition,
                busbar_kernel::metrics::PLANE_REQUEST_DURATION_SECONDS,
                plane,
            );
            assert!(
                !durations.is_empty(),
                "no `{}` series for plane=\"{plane}\" after driving real traffic. Exposition:\n{exposition}",
                busbar_kernel::metrics::PLANE_REQUEST_DURATION_SECONDS,
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
        let model_counters = lines_for(&exposition, busbar_kernel::metrics::REQUESTS_TOTAL);
        assert!(
            model_counters.iter().any(|line| keys_of(line)
                == vec![
                    "ingress_protocol".to_string(),
                    "outcome".to_string(),
                    "pool".to_string()
                ]),
            "no v1.5.4-shaped `{}` series {{ingress_protocol,pool,outcome}} after driving model traffic \
             (model {model_status}). Exposition:\n{exposition}",
            busbar_kernel::metrics::REQUESTS_TOTAL,
        );
        assert!(
            !lines_for(
                &exposition,
                busbar_kernel::metrics::REQUEST_DURATION_SECONDS
            )
            .is_empty(),
            "no `{}` series after driving model traffic. Exposition:\n{exposition}",
            busbar_kernel::metrics::REQUEST_DURATION_SECONDS,
        );
        // BYTE-IDENTITY GUARD: the two model families never carry a `plane` label anywhere in the whole
        // exposition. This is the assertion that fails if the BI-2 regression (a `plane` label on these
        // pre-existing families) is ever reintroduced by any emission site.
        for family in [
            busbar_kernel::metrics::REQUESTS_TOTAL,
            busbar_kernel::metrics::REQUEST_DURATION_SECONDS,
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

/// THE PLANE-BOUNDARY RATCHET (1.6.0), driven by the ROUTER TABLE rather than by a hand-listed
/// sample.
///
/// The rule: an access token minted for the endpoint-door plane's resource is admissible on that
/// plane and nowhere else. A sampled test proves that of the paths someone remembered; this one
/// walks `CoreRouteTable::routes()` — the table every core route is entered into at the moment it is
/// mounted — plus `App::boot_route_paths` for the plugin surface, so a route added later JOINS the
/// assertion instead of quietly joining the blast radius. There is no skip arm: a path whose shape
/// this test cannot turn into a concrete request PANICS rather than passing.
///
/// The admissible set is the set of paths the plane CLAIMS off its own configured object, so it is
/// the plane's declaration, never a list written here. `declared_public` is the mirror ratchet on
/// the other axis: a route mounted `RouteAuth::None` answers everyone, so adding one must be a
/// deliberate act that shows up here.
///
/// The test's NAME is pinned by `qa/design-bindings.json` (PB-33) and the structure-lint choke-point
/// table, which cite it; the body names no plane.
#[tokio::test]
async fn an_audience_bound_token_is_confined_to_its_door_plane() {
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, MemoryStore};

    busbar_kernel::metrics::init();
    let door = door_plane();

    /// The host of the door plane's canonical URI in this test. The canonical URI is BOTH the
    /// audience minted into `bound_token` below AND the `canonical_uri` the app is built with — one
    /// string, used twice, because a test in which they differed would prove only that two
    /// spellings disagree.
    const HOST: &str = "busbar.example.com";
    let canonical = format!("https://{HOST}/{}", door.key);
    let sections = door_section_yaml(HOST);
    // The door's ingress paths, the ONLY places an audience-bound token may be admitted: every
    // JSON-RPC path the plane claims off its configured object. The app below MOUNTS the plane, so
    // this list is exercised in both directions: an audience-bound token is admitted here and
    // nowhere else, and a plain data-plane token is admitted everywhere else and not here.
    let admissible: Vec<String> = vec![jsonrpc_mount(door, &sections)];
    // Core routes declared `RouteAuth::None`: unauthenticated by design, so no token of any kind
    // is consulted there. `/healthz` is a liveness probe; `/auth/token` runs the auth chain in its
    // own handler; the RFC 9728 metadata document for the door's resource must be readable by a
    // caller that has no token yet, because that caller is the entire population the document
    // exists for.
    let declared_public: Vec<String> = vec![
        "/healthz".to_string(),
        "/auth/token".to_string(),
        format!("/.well-known/oauth-protected-resource{}", admissible[0]),
    ];

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
            busbar_kernel::governance::NewKeySpec {
                name: "door-agent".to_string(),
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
        &canonical,
        Some("client-1"),
    );

    let app = configured(
        TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    busbar_kernel::proto::PROTO_ANTHROPIC,
                    &server.base_url(),
                )
                .api_key("busbar-upstream-key"),
            )
            .pool("pa", &[(0, 1)])
            .keys_chain()
            .governance(gov),
        &sections,
        None,
    )
    .build();

    // The table the SERVED router was built from: same function, same plugin-route input, same
    // plane resource, so the enumeration cannot describe a different surface than the one under
    // test. Read through the curated `(path, method, auth)` test-support seam so this cross-crate
    // integration test names PUBLIC types only, never core's sealed `CoreRoute`/`CoreRouteTable`.
    let core_routes = busbar_kernel::base_data_route_method_view(&app);
    // FLOOR ON THE DISCOVERED SET, in the one dimension that matters here: the walk below is only a
    // plane-boundary test if the router actually mounted the plane. Without this, deleting the door
    // mount would leave every assertion below trivially satisfied and the test would still pass.
    for path in &admissible {
        assert!(
            core_routes.iter().any(|(p, _, _)| p == path),
            "{path} is claimed by the `{}` plane but no core route mounts it — the walk would \
             assert nothing about the plane it is named for",
            door.key
        );
    }
    // THE MATCHING FLOOR ON `declared_public`, and it is the half the walk below cannot supply.
    //
    // The loop's public arm is one-directional: it fires only for a route the table reports as
    // `RouteAuth::None`, and asks whether that route was declared. Nothing anywhere asked the
    // reciprocal — whether a path NAMED here is still mounted `None` at all. So a route silently
    // leaving the unauthenticated bypass set (remounted `Key`, or unmounted outright) does not fail
    // this test: it simply takes the guarded arm, or vanishes from the walk, and the entry here
    // becomes a comment about a rule nothing checks.
    //
    // That is not hypothetical bookkeeping. Appendix B binding PB-33 cites THIS test, by name, as
    // the proof that `/auth/token` is in the unauthenticated exact-path bypass set — a property the
    // test could not observe. This floor is what makes the citation true, and it is the exact
    // sibling of the admissible floor above (same argument, other axis).
    for public in &declared_public {
        assert!(
            core_routes
                .iter()
                .any(|(path, _, auth)| path == public
                    && *auth == busbar_plugin_loader::RouteAuth::None),
            "{public} is declared unauthenticated-by-design but no core route mounts it with \
             RouteAuth::None — the bypass set this names is not the one the router built"
        );
    }
    let boot_plugin_paths: Vec<String> = busbar_kernel::boot_route_paths_of(&app);
    assert!(
        !core_routes.is_empty(),
        "an empty table would make every assertion below vacuous"
    );

    let router = busbar_kernel::build_router(app);
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
    let mut door_checked = 0usize;
    for route in &core_routes {
        let path = concrete(&route.0);
        if route.2 == busbar_plugin_loader::RouteAuth::None {
            assert!(
                declared_public.contains(&route.0),
                "{} is mounted RouteAuth::None but is not in declared_public — an unauthenticated \
                 core route must be a deliberate, reviewed act",
                route.0
            );
            continue;
        }
        let method = reqwest::Method::from_bytes(route.1.as_bytes()).unwrap();
        // THE DOOR ARM, and it is the reciprocal of the data-plane arm below rather than a weaker
        // version of it: on this plane the audience-bound token is the one that WORKS and the plain
        // data-plane token is the one that must buy nothing. Asserting only the first half would
        // pass against a server that admitted both, which is the failure mode the boundary exists
        // to prevent.
        if admissible.contains(&route.0) {
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
                "an unauthenticated caller on the door plane must get 401, not a vendor-shaped \
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
                "a plain data-plane key carries no audience and must be inadmissible on the door \
                 plane, on {} {}",
                route.1,
                path
            );
            door_checked += 1;
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
            "an audience-bound door-plane token must be treated as no credential on {} {}",
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
        door_checked,
        core_routes
            .iter()
            .filter(|(path, _, _)| admissible.contains(path))
            .count(),
        "every admissible mounted route must have been walked; a mismatch means a claimed route \
         was mounted with an auth level that skipped the arm"
    );
    assert!(
        door_checked > 0,
        "no door-plane route was walked, so the reciprocal half of the boundary was never asserted"
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
            "an audience-bound door-plane token must be treated as no credential on plugin route \
             {path}"
        );
    }

    handle.abort();
    server.shutdown().await;
}
