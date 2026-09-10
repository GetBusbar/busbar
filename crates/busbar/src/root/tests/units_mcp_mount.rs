//! Tests for `units_mcp_mount.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! The shared mount's own cells (`tests/plane_mount.rs`) own the path walk and the trailing-slash
//! reading. What is here is what only THIS plane can answer: which addresses it claims, which of
//! them are units and which are handed straight through, and that a request that IS one travels the
//! loop and comes back carrying the surface's own bytes.

use super::*;

use busbar_contract::{
    grammar::{PathSeg, Selector},
    ids::LaneId,
};
use busbar_kernel::teller::Kernel;
use busbar_plane_mcp::claims;
use busbar_unit_auth::{Auth, AuthChain};
use busbar_unit_ledger::legacy::RecordingRows;
use busbar_unit_trust::{lane::BreakerView, net::Denylist, net::GuardPolicy, Unavailable};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT IS CLAIMED IS THE PLANE'S OWN TABLE, AND NOTHING BESIDE IT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Every document address the plane declares is claimed by this mount.**
///
/// Read off `claims::CLAIMS` rather than against a list here, so the cell says what it means: an
/// address the plane gains is an address this mount gains, and a mount that quietly stopped claiming
/// one would be serving it around the loop while the plane still said it owned it.
///
/// A claim whose selector is not a path — the locally launched surface's named stream — contributes
/// no address and is skipped, for the same reason the matcher does not match one.
#[test]
fn every_document_claim_of_the_plane_is_claimed_by_the_mount() {
    let mut addresses: Vec<String> = Vec::new();
    for claim in claims::CLAIMS {
        let example = match claim.selector {
            Selector::ExactPath(path) => path.to_string(),
            Selector::PathPattern(pattern) => example_path(pattern),
            // Not an address on this listener, and not a gap: a stream name is a different carrier.
            Selector::StreamName(_) => continue,
            other => panic!("this plane declares a selector this cell cannot walk: {other:?}"),
        };
        assert!(
            claims_the_path(&example),
            "the plane claims `{example}` and the mount would have handed it straight through"
        );
        if !addresses.contains(&example) {
            addresses.push(example);
        }
    }
    // DISTINCT addresses, not claims. The request surface is claimed TWICE — once as a document and
    // once as a run of events — because they are two framings of one address, and counting claims
    // here would make the cell agree with itself about a number that is not the one it means.
    assert_eq!(
        addresses.len(),
        2,
        "this plane declares exactly two document addresses — the request surface and the \
         discovery document — and a cell that walked one of them would pass for a matcher that had \
         stopped matching the other: {addresses:?}"
    );
}

/// One concrete path that a segment pattern matches.
fn example_path(pattern: &[PathSeg]) -> String {
    let mut out = String::new();
    for seg in pattern {
        out.push('/');
        match seg {
            PathSeg::Lit(lit) => out.push_str(lit),
            PathSeg::Var | PathSeg::Tail => out.push_str("an-identifier"),
        }
    }
    out
}

/// **`/mcp` AND `/mcp/`, and nothing that merely looks like either.**
///
/// The trailing slash is the same address to every router in this tree and to every client of this
/// protocol, so a mount that took one and handed the other straight through would run the same
/// request past the loop or around it depending on a character. The near misses are the other half:
/// `/mcpx` shares a prefix and belongs to somebody else, and `/mcp/x` is a deeper address no claim
/// of this plane names.
#[test]
fn the_request_surface_is_claimed_with_and_without_its_trailing_slash() {
    assert!(claims_the_path(claims::DEFAULT_MOUNT));
    assert!(claims_the_path("/mcp/"));
    assert!(claims_the_path(claims::DEFAULT_METADATA));

    for elsewhere in [
        "/mcpx",
        "/mcp/x",
        "/mcp//",
        "/",
        "/api/v1/admin/info",
        "/a2a",
        "/.well-known/oauth-protected-resource",
    ] {
        assert!(
            !claims_the_path(elsewhere),
            "`{elsewhere}` is not an address this plane declares, and the mount claimed it"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE SURFACE THIS MOUNT WRAPS, AS AN INSTRUMENT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The status the mounted surface answers a unit of this plane with.
///
/// Deliberately not one the loop's own narrowing would ever produce, and not one any handler in this
/// tree returns. A cell that asserted on a plausible status would pass for a mount that had rendered
/// its own answer, which is the one thing the whole seam exists to make impossible.
const SURFACE_STATUS: u16 = 207;

/// The header the mounted surface emits, which no step of the loop writes.
const SURFACE_HEADER: (&str, &str) = ("x-answered-by", "the-mounted-surface");

/// The bytes it writes.
const SURFACE_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"from":"the surface"}}"#;

/// The status the mounted surface answers everything it does not recognise with.
///
/// The instrument for the fallthrough cells: the loop, had it taken one of those requests, would
/// have refused it at Decode and spelled that refusal with a status of its own. Reading this one
/// back is what says the request went AROUND the loop rather than through it.
const SURFACE_FALLBACK_STATUS: u16 = 299;

/// How many times the mounted surface was asked anything at all.
#[derive(Default)]
struct SurfaceCalls(std::sync::atomic::AtomicUsize);

impl SurfaceCalls {
    fn seen(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A stand-in for the router this protocol is already mounted on.
///
/// It answers a POST on the request surface with bytes nothing else could produce, and everything
/// else with the fallback status. What it is NOT is a reimplementation of the protocol: it exists to
/// be observed — was it asked, and did its answer reach the wire unchanged.
fn a_mounted_surface(calls: Arc<SurfaceCalls>) -> axum::Router {
    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let calls = Arc::clone(&calls);
            async move {
                calls.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let is_the_rpc_surface = req.method() == axum::http::Method::POST
                    && req.uri().path().starts_with(claims::DEFAULT_MOUNT);
                if is_the_rpc_surface {
                    axum::http::Response::builder()
                        .status(SURFACE_STATUS)
                        .header(SURFACE_HEADER.0, SURFACE_HEADER.1)
                        .body(axum::body::Body::from(SURFACE_BODY))
                        .expect("the stand-in's answer always builds")
                } else {
                    axum::http::Response::builder()
                        .status(SURFACE_FALLBACK_STATUS)
                        .body(axum::body::Body::empty())
                        .expect("the stand-in's answer always builds")
                }
            }
        },
    ))
}

/// The registration these cells' node carries.
static ONE_SERVER: &[busbar_plane_mcp::Server] = &[busbar_plane_mcp::Server {
    id: "fs",
    lane: LaneId::new("fs-lane"),
    host: "127.0.0.1:9",
    transport: claims::TRANSPORT_HTTP,
}];

/// A breaker that benches nothing, so a cell about the mount is not also a cell about readiness.
struct EveryLaneOpen;

impl BreakerView for EveryLaneOpen {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(&self, _pool: &str, _lane: usize, _now: u64) -> Result<(), Unavailable> {
        Ok(())
    }
}

/// Every source the leg needs, with the auth chain the caller asks for.
fn sources_with_chain(
    kernel: &Kernel,
    auth: Auth,
    auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
) -> crate::root::units_mcp_leg::McpLegSources<'_> {
    use busbar_unit_admission::{Door, GroupTable, InMemoryCells, Pricer};
    crate::root::units_mcp_leg::McpLegSources {
        plane: busbar_plane_mcp::McpPlane::new(ONE_SERVER),
        kernel,
        auth: Some(auth),
        auth_bindings: Some(auth_bindings),
        breaker: Some(Arc::new(EveryLaneOpen)),
        guard: Some(GuardPolicy {
            allow_private: true,
            ..GuardPolicy::default()
        }),
        denylist: Some(Denylist::default()),
        door: Some(Door::new(InMemoryCells::new())),
        groups: Some(GroupTable::default()),
        pricer: Some(Pricer::flat(0)),
        store: Some(crate::root::mount_ingress::tests::memory_store()),
        meter_policy: Some(crate::root::policy::build(
            &crate::root::policy::MeterPolicyConfig::default(),
        )),
        scope_policy: Some(crate::root::units_mcp_leg::McpLeg::scope_policy(
            crate::root::policy::ScopePolicy::new(),
        )),
        durability: Some(Arc::new(std::sync::Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_unit_wal::NullShipper::new()),
                Box::new(RecordingRows::new()),
            )
            .expect("a memory-buffered journal cannot fail to open"),
        ))),
        key_scopes: None,
        priced: true,
        has_key: true,
        catalogue: Vec::new(),
    }
}

/// A leg with an OPEN chain, for the cells that are about the path rather than about the door.
fn an_open_leg(kernel: &Kernel) -> Arc<McpLeg> {
    let auth = Auth::new(AuthChain::new(Vec::new(), false));
    let bindings = crate::root::kernel::auth_bindings::AuthBindings::without_directory();
    Arc::new(
        McpLeg::assemble(sources_with_chain(kernel, auth, bindings))
            .expect("every source is present"),
    )
}

/// One request through a mounted router, as a caller would send it.
async fn through(
    router: axum::Router,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .body(axum::body::Body::from(body.to_vec()))
        .expect("the probe always builds");
    let response = router.oneshot(request).await.unwrap_or_else(|e| match e {});
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("the probe's answer is readable");
    (
        parts.status.as_u16(),
        parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        bytes.to_vec(),
    )
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LOOP TAKES WHAT IT HAS, AND HANDS BACK EVERYTHING ELSE UNTOUCHED
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A unit of this plane travels through the loop, and the SURFACE's whole answer reaches the wire.**
///
/// RED FIRST: `McpLeg::assemble` had no caller that served anything, so this request had no loop to
/// travel through — the mount is the caller. The three assertions are the three halves of the seam,
/// and the status and the headers are the half a frame cannot carry: a mount that read only the
/// encoded frame would serve every operation of this protocol under one status with no headers.
#[tokio::test(flavor = "multi_thread")]
async fn a_unit_of_this_plane_travels_through_the_loop_and_the_surfaces_answer_reaches_the_wire() {
    let kernel = Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        Kernel::new(),
        Arc::new(crate::root::data_plane::NodeParts::new()),
        1024 * 1024,
    );

    let (status, headers, body) = through(
        router,
        "POST",
        claims::DEFAULT_MOUNT,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .await;

    assert_eq!(
        status, SURFACE_STATUS,
        "the status is the surface's; a status the loop's own narrowing produced would mean this \
         mount rendered an answer rather than carried one"
    );
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == SURFACE_HEADER.0 && v == SURFACE_HEADER.1),
        "and its header reached the wire: {headers:?}"
    );
    assert_eq!(body, SURFACE_BODY, "and its bytes, unchanged");
    assert_eq!(calls.seen(), 1, "asked exactly once");
}

/// **The same address with a trailing slash travels the same loop.**
///
/// The character that would otherwise decide whether a request is gated.
#[tokio::test(flavor = "multi_thread")]
async fn the_trailing_slash_form_travels_the_same_loop() {
    let kernel = Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        Kernel::new(),
        Arc::new(crate::root::data_plane::NodeParts::new()),
        1024 * 1024,
    );

    let (status, _, body) = through(
        router,
        "POST",
        "/mcp/",
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!(status, SURFACE_STATUS);
    assert_eq!(body, SURFACE_BODY);
    assert_eq!(calls.seen(), 1);
}

/// **A path this plane does not claim never reaches the loop.**
///
/// The listener carries routes that are deliberately outside this protocol, and walking one of them
/// through a loop whose decode reads a table it was never in would refuse a route that has always
/// answered. The fallback status is what says it went around.
#[tokio::test(flavor = "multi_thread")]
async fn a_path_this_plane_does_not_claim_goes_straight_to_the_surface() {
    let kernel = Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        Kernel::new(),
        Arc::new(crate::root::data_plane::NodeParts::new()),
        1024 * 1024,
    );

    let (status, _, _) = through(router, "GET", "/api/v1/admin/info", b"").await;
    assert_eq!(status, SURFACE_FALLBACK_STATUS, "it went around the loop");
    assert_eq!(calls.seen(), 1);
}

/// **A body this plane cannot name an operation for goes straight to the surface too.**
///
/// The second question, and it is the one that keeps a method this server does not answer byte-for-
/// byte what release pinned: the surface's own `-32601`, not a status this mount manufactured for
/// bytes the plane never claimed. The address IS claimed — that is what makes this the second
/// question rather than the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_method_this_plane_does_not_name_is_answered_by_the_surface_and_not_by_the_loop() {
    let kernel = Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        Kernel::new(),
        Arc::new(crate::root::data_plane::NodeParts::new()),
        1024 * 1024,
    );

    assert!(
        claims_the_path(claims::DEFAULT_MOUNT),
        "the address is claimed, so this is the decode question and not the path one"
    );
    let (status, _, body) = through(
        router,
        "POST",
        claims::DEFAULT_MOUNT,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/obliterate"}"#,
    )
    .await;
    assert_eq!(
        status, SURFACE_STATUS,
        "the surface answered it, exactly as it did before this mount existed"
    );
    assert_eq!(body, SURFACE_BODY);
    assert_eq!(calls.seen(), 1, "asked once, and by the fallthrough");
}

/// **The discovery document is claimed and is not a unit.**
///
/// It is one of this plane's four claims, so the first question takes it; it carries no JSON-RPC
/// body, so the plane's own decode names no operation for it and the second question hands it
/// straight to the surface that already serves it. That surface answers with the deployment's own
/// `mcp.canonical_uri` — the RFC 8707 resource indicator this node publishes — and this mount does
/// not re-derive it, because a second reading of the audience is a second answer to which tokens
/// open this surface.
#[tokio::test(flavor = "multi_thread")]
async fn the_discovery_document_is_claimed_and_is_served_by_the_surface() {
    let kernel = Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        Kernel::new(),
        Arc::new(crate::root::data_plane::NodeParts::new()),
        1024 * 1024,
    );

    assert!(claims_the_path(claims::DEFAULT_METADATA));
    let (status, _, _) = through(router, "GET", claims::DEFAULT_METADATA, b"").await;
    assert_eq!(
        status, SURFACE_FALLBACK_STATUS,
        "the plane names no operation for it, so it is not a unit and the surface answers"
    );
    assert_eq!(calls.seen(), 1);
}

/// **A body over the operator's cap is not this wrap's to answer.**
///
/// The mounted surface carries that cap and the answer release pinned for exceeding it, and this
/// wrap reads the body first — so a request that DECLARES more than the cap goes straight there
/// rather than being buffered into this node's memory on the way to being rejected anyway.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_the_operators_cap_goes_straight_to_the_surface() {
    let kernel = Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        Kernel::new(),
        Arc::new(crate::root::data_plane::NodeParts::new()),
        // One byte, which every well-formed request of this protocol exceeds.
        1,
    );

    let (status, _, _) = through(
        router,
        "POST",
        claims::DEFAULT_MOUNT,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!(
        status, SURFACE_STATUS,
        "the surface answered it; the cap it is judged against is the one it was built with"
    );
    assert_eq!(calls.seen(), 1);
}
