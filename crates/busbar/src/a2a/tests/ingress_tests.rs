// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECEIVING HOT PATH, driven through the REAL router.
//!
//! Every assertion here goes through `crate::build_router`, not through the handlers directly. A
//! handler that behaves correctly when called by a test and is mounted nowhere is the exact defect
//! this plane had before this module existed, so a test that called the handler would have passed
//! against it.

use crate::a2a::config::{AgentDefCfg, AgentPinCfg, PinMechanism};
use crate::core_routes::CoreRouteTable;

fn unpinned_agent(url: &str) -> AgentDefCfg {
    AgentDefCfg {
        url: url.to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::Unpinned,
            key: None,
            fingerprint: None,
        },
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        allow_private: false,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        client_identity: None,
        hooks: Vec::new(),
    }
}

/// The core route table the DATA router was actually built from — the same function production
/// calls, with the same inputs, so the enumeration cannot describe a different surface.
fn mounted(app: &std::sync::Arc<crate::state::App>) -> CoreRouteTable {
    crate::base_data_router(
        &app.plugin_routes,
        app.mcp.as_deref(),
        app.a2a.as_ref(),
        app.oauth_as.as_ref(),
    )
    .1
}

fn paths(table: &CoreRouteTable) -> Vec<String> {
    table.routes().iter().map(|r| r.path.clone()).collect()
}

#[test]
fn no_agents_configured_means_no_route_in_the_table_at_all() {
    // THE GATE, asserted on the mounted surface rather than on a flag. A deployment that fronts no
    // agents must not carry an A2A path the auth middleware could be asked about — "is this an A2A
    // server?" is answered by what is mounted, and a route that exists only to refuse is still a
    // route somebody has to reason about.
    crate::metrics::init();
    let app = crate::test_support::TestApp::new().build();
    assert!(app.a2a.is_none());
    let table = mounted(&app);
    // EVERY path this plane can claim, listed here rather than a prefix test: the plane serves two
    // routes OUTSIDE its own `/a2a` prefix — the RFC 9728 metadata document and the well-known
    // agent card — and a `starts_with("/a2a")` check silently stops covering each one as it is
    // added. This assertion is the reason to enumerate.
    assert!(
        !paths(&table).iter().any(|p| p.starts_with("/a2a")
            || p == crate::a2a::serve::METADATA_PATH
            || p == crate::a2a::card::WELL_KNOWN_CARD_PATH),
        "a deployment with no `agents:` mounted an A2A route: {:?}",
        paths(&table)
    );
    assert!(
        app.planes.mount_of(crate::plane::Plane::A2a).is_none(),
        "with no plane there is nothing to claim a path"
    );
}

#[test]
fn agents_configured_mounts_the_plane_and_binds_its_audience() {
    // The reciprocal, and BOTH halves matter: mounting routes without binding an audience would
    // leave the ingress admitting any data-plane token, which is the confused-deputy hole the
    // plane's admission facts exist to close.
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let table = mounted(&app);
    let ps = paths(&table);
    assert!(
        ps.contains(&crate::a2a::serve::METADATA_PATH.to_string()),
        "the RFC 9728 document is not mounted: {ps:?}"
    );
    assert!(
        ps.iter().any(|p| p == "/a2a/agents/{agent_id}"),
        "the agent endpoint is not mounted: {ps:?}"
    );
    // THE DISCOVERY PATH THE SPECIFICATION MAKES A MUST. Without it busbar is not reachable by a
    // conformant A2A client at all — a stock client asks here first and has nowhere else to look —
    // and the conformance battery reports the subject as unreachable rather than as failing.
    assert!(
        ps.iter()
            .any(|p| p == crate::a2a::card::WELL_KNOWN_CARD_PATH),
        "busbar's own agent card is not mounted at the well-known path: {ps:?}"
    );

    // The audience the middleware will demand is the SAME string the metadata document advertises
    // and the same one the served card points a caller at. One derivation, so a client that does
    // what the document says obtains a token this server accepts.
    let admission = app
        .planes
        .admission_for("/a2a/agents/planner")
        .expect("the mounted path resolves to this plane's admission facts");
    assert_eq!(admission.audience, "https://busbar.example/a2a");
    assert_eq!(
        admission.resource_metadata,
        "https://busbar.example/.well-known/oauth-protected-resource/a2a"
    );
}

#[test]
fn a_delegation_only_deployment_mounts_no_receiving_surface() {
    // `agents:` WITHOUT `public_url` is a real configuration: an operator may front agents for the
    // DELEGATING direction alone. There is then no resource for a token to be bound to and no
    // endpoint to advertise, so mounting an ingress would mount one that could only ever refuse.
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    assert!(
        app.a2a.is_some(),
        "the registry exists for the delegating side"
    );
    let ps = paths(&mounted(&app));
    assert!(
        !ps.iter().any(|p| p.starts_with("/a2a")),
        "a delegation-only deployment mounted a receiving route: {ps:?}"
    );
}

#[test]
fn the_metadata_document_is_the_one_open_route_and_the_endpoint_is_not() {
    // The discovery document must be readable without a token — every caller who needs it is by
    // definition one that has none. The endpoint beside it must NOT be: which agents this
    // deployment fronts is exactly what a caller with no grant must not learn.
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let table = mounted(&app);
    for route in table.routes() {
        if route.path == crate::a2a::serve::METADATA_PATH {
            assert_eq!(
                route.auth,
                busbar_plugin_loader::RouteAuth::None,
                "the discovery document must be readable without a token"
            );
        }
        if route.path.starts_with("/a2a/agents") {
            assert_eq!(
                route.auth,
                busbar_plugin_loader::RouteAuth::Key,
                "{} must take the data-plane bar",
                route.path
            );
        }
    }
}

#[tokio::test]
async fn an_anonymous_caller_is_refused_and_told_where_to_get_a_token() {
    // The refusal owes a machine-readable challenge naming this plane's metadata document. Without
    // it a conforming client has no entrance: it knows it was refused and not where to go.
    crate::metrics::init();
    let store: std::sync::Arc<dyn crate::governance::Store> =
        std::sync::Arc::new(busbar_store_memory::MemoryStore::new());
    let gov = std::sync::Arc::new(
        crate::governance::GovState::new_with_signer(
            store,
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[9u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("gov"),
    );
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        // THE CHAIN MUST ACTUALLY DENY for this to be a test about the challenge. With the default
        // empty chain an anonymous caller is ADMITTED (the explicit open-front-door posture) and is
        // then refused by the handler for want of a key — fail-closed, but no challenge, so a
        // conforming client would learn it was refused and not where to go.
        .keys_chain()
        .governance(gov)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/a2a/agents/planner"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        challenge.contains("https://busbar.example/.well-known/oauth-protected-resource/a2a"),
        "the challenge does not name this plane's metadata document: {challenge:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn the_metadata_document_advertises_the_audience_the_verifier_demands() {
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let expected = app
        .planes
        .admission_for("/a2a/agents/planner")
        .unwrap()
        .audience
        .clone();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // No credential presented, and that is the point: this route is open.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{}", crate::a2a::serve::METADATA_PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let doc: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        doc["resource"], expected,
        "the document advertises an audience the verifier does not demand"
    );
    handle.abort();
}

#[test]
fn the_credential_kind_is_conferred_by_an_audience_bound_mount() {
    // THE POINT OF THE WHOLE INTEGRATION, pinned as a property rather than a comment.
    //
    // `inbound::authorize` refuses anything that is not an `a2a_inbound` credential, and that value
    // cannot be a `CredentialMeta.kind`: that type admits a kind only if its verification path
    // resolves a row from a wire-supplied public identifier, and this plane's credential is a
    // bearer token, which resolves none. What makes it an A2A credential is that the mount it
    // arrived on is AUDIENCE-BOUND, which the verifier has already checked. So the kind must be
    // derived from the mount — never passed as a constant — or the check is a tautology at its only
    // production call site.
    crate::metrics::init();
    let bound = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    assert!(
        bound
            .planes
            .mount_of(crate::plane::Plane::A2a)
            .and_then(|m| bound.planes.admission_for(m))
            .is_some(),
        "a mounted receiving plane must be audience-bound"
    );

    // The unbound case is the delegation-only deployment: a plane exists, nothing is audience-bound,
    // and therefore nothing arriving anywhere is an A2A inbound credential.
    let unbound = crate::test_support::TestApp::new()
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    assert!(
        unbound
            .planes
            .mount_of(crate::plane::Plane::A2a)
            .and_then(|m| unbound.planes.admission_for(m))
            .is_none(),
        "an unbound plane must confer no credential kind"
    );
}

#[test]
fn the_served_endpoint_and_the_mounted_path_are_one_derivation() {
    // The card tells a caller where to send its request. If that string and the path the router
    // actually serves were derived separately, the card would advertise an endpoint that 404s — and
    // nothing would notice, because each half is individually correct.
    let endpoint = crate::a2a::serve::agent_endpoint("https://busbar.example", "planner").unwrap();
    assert_eq!(endpoint, "https://busbar.example/a2a/agents/planner");

    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let mounted_pattern = paths(&mounted(&app))
        .into_iter()
        .find(|p| p.starts_with("/a2a/agents"))
        .expect("the endpoint is mounted");
    let served_path = reqwest::Url::parse(&endpoint).unwrap().path().to_string();
    // The mounted pattern with its one parameter filled in is the path the card advertises.
    assert_eq!(
        mounted_pattern.replace("{agent_id}", "planner"),
        served_path,
        "the card advertises an endpoint the router does not serve"
    );
}

#[tokio::test]
async fn the_well_known_card_is_served_without_a_credential() {
    // THE A2A PROTOCOL SPECIFICATION MAKES THIS A MUST, and a 404 here means Busbar is invisible to
    // every conformant client: a stock client asks this path FIRST and has nowhere else to look.
    // No credential is presented, and that is the whole point — this document is what tells a
    // caller which scheme to present, so demanding one to read it is circular.
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def("planner", unpinned_agent("https://a2a.vendor/planner"))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}{}",
            crate::a2a::card::WELL_KNOWN_CARD_PATH
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "busbar's own agent card is not served at the path the protocol defines"
    );

    let doc: serde_json::Value = resp.json().await.unwrap();
    // The endpoint it names must be BUSBAR'S, not a backend's, and must be the mount this
    // deployment actually answers on.
    let iface = doc["supportedInterfaces"][0]["url"]
        .as_str()
        .unwrap_or_default();
    assert!(
        iface.starts_with("https://busbar.example/a2a"),
        "the card points a caller somewhere other than this busbar: {iface:?}"
    );
    // A capability busbar does not implement must not be claimed. `getAuthenticatedExtendedCard`
    // does not exist yet, and a card that says otherwise is the false-green this release keeps
    // producing.
    assert_eq!(
        doc["capabilities"]["extendedAgentCard"],
        serde_json::Value::Bool(false),
        "the card claims an extended-card verb busbar does not implement"
    );
    handle.abort();
}

#[tokio::test]
async fn the_well_known_card_does_not_name_the_agents_busbar_fronts() {
    // THIS IS THE SECURITY PROPERTY OF THAT ROUTE. It is unauthenticated by design, so it cannot
    // ask who is calling; publishing the fronted agents there would hand an anonymous caller the
    // internal inventory — every agent id, every vendor, every capability. The per-agent cards stay
    // behind `RouteAuth::Key`, where a caller who is entitled to one can still get it.
    //
    // Asserted over the SERIALISED DOCUMENT rather than over named members, because the hazard is a
    // field nobody thought to check. A future member that happens to carry the agent id would pass
    // a `doc["skills"]` assertion and fail this one.
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .public_url("https://busbar.example")
        .agent_def(
            "secret-internal-planner",
            unpinned_agent("https://a2a.internal-vendor.corp/planner"),
        )
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let body = reqwest::Client::new()
        .get(format!(
            "http://{addr}{}",
            crate::a2a::card::WELL_KNOWN_CARD_PATH
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        !body.contains("secret-internal-planner"),
        "the public card names a fronted agent: {body}"
    );
    assert!(
        !body.contains("internal-vendor.corp"),
        "the public card names a backend host: {body}"
    );
    handle.abort();
}
