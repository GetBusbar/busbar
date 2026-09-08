//! Tests for `units_a2a_mount.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::*;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT IS CLAIMED IS THE PLANE'S OWN TABLE, AND NOTHING BESIDE IT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Every address the plane declares is claimed by this mount.**
///
/// Read off `claims::CLAIMS` rather than against a list here, so the cell says what it means: a
/// route the plane gains is a route this mount gains, and a mount that quietly stopped claiming one
/// would be serving that address around the loop while the plane still said it owned it.
///
/// Every claim, and the transport each one names is not read — by the cell for the same reason the
/// matcher does not read it. A claim whose selector is not a path contributes no example and is
/// skipped here; there are none today, and the panic arm is what would say so if there were.
#[test]
fn every_claim_of_the_plane_is_claimed_by_the_mount() {
    let mut checked = 0;
    for claim in busbar_plane_a2a::claims::CLAIMS {
        let example = match claim.selector {
            Selector::ExactPath(path) => path.to_string(),
            Selector::PathPattern(pattern) => example_path(pattern),
            other => {
                panic!("this plane declares a document selector this cell cannot walk: {other:?}")
            }
        };
        assert!(
            claims_the_path(&example),
            "the plane claims `{example}` and the mount would have handed it straight to the surface"
        );
        checked += 1;
    }
    assert!(
        checked >= 3,
        "this plane declares more than a couple of document addresses; a cell that walked one or \
         two of them would pass for a matcher that had stopped matching the rest"
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

/// **And a path this plane does not claim is NOT claimed — including the near misses.**
///
/// The near misses are the cell. `/a2ax` shares a prefix with the mount and is somebody else's path;
/// `/a2a/agents` without an identifier is a collection this plane's pattern does not name; and the
/// administrative surface's own prefix is a different plane's entirely. A `starts_with` would take
/// all three, which is exactly why the matcher walks segments.
#[test]
fn a_path_this_plane_does_not_claim_goes_straight_to_the_surface() {
    for path in [
        "/a2ax",
        "/a2a/agents",
        "/a2a/agents/one/two",
        "/api/v1/admin/keys",
        "/healthz",
        "/",
        "",
    ] {
        assert!(
            !claims_the_path(path),
            "`{path}` is not an address this plane declares, so the loop must not take it"
        );
    }
}

/// **The three addresses this cut is about are claimed, spelled out.**
///
/// The generic walk above is the rule; this is the acceptance. It is written with the paths in it on
/// purpose — a regression that made the matcher claim nothing would still pass the walk, because the
/// walk derives its examples from the same table the matcher reads.
#[test]
fn the_json_rpc_surfaces_and_one_agent_are_claimed() {
    for path in ["/a2a", "/a2a/", "/a2a/agents/conformance"] {
        assert!(claims_the_path(path), "`{path}` reaches the loop");
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE STATUS EVERY ENDING IS SPELLED WITH
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Every outcome the loop can reach has a status, and the two credential doors stay apart.**
///
/// The statuses are the ones this protocol's own surface already answers each condition with.
///
/// A caller refused at Authenticate is told its credential was not accepted; one refused at Approve
/// or Verify is told the credential was accepted and does not cover this. Collapsing them onto one
/// status sends a caller with a bad token away to fix its permissions.
#[test]
fn the_two_credential_doors_are_spelled_with_different_statuses() {
    use busbar_contract::transport::Outcome as O;
    assert_eq!(status_of(O::Unauthenticated), 401);
    assert_eq!(status_of(O::Forbidden), 403);
    assert_ne!(
        status_of(O::Unauthenticated),
        status_of(O::Forbidden),
        "a caller with a bad token and a caller with a good one that does not reach must not be \
         told the same thing"
    );
    // And none of the eight is spelled with a success.
    for outcome in [
        O::Unauthenticated,
        O::Forbidden,
        O::NotFound,
        O::Throttled,
        O::TimedOut,
        O::Cancelled,
        O::Unavailable,
    ] {
        assert!(
            status_of(outcome) >= 400,
            "{outcome:?} is not a success and must not be spelled as one"
        );
    }
    assert_eq!(status_of(O::Completed), 200);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE MOUNT, END TO END: THE LOOP CHOOSES THE PATH AND THE SURFACE WRITES THE BYTES
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
/// It answers the plane's own JSON-RPC surface with bytes nothing else could produce, and everything
/// else with the fallback status. What it is NOT is a reimplementation of the protocol: it exists to
/// be observed — was it asked, and did its answer reach the wire unchanged.
fn a_mounted_surface(calls: Arc<SurfaceCalls>) -> axum::Router {
    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let calls = Arc::clone(&calls);
            async move {
                calls.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let is_the_rpc_surface = req.method() == axum::http::Method::POST
                    && req.uri().path().starts_with("/a2a");
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

/// The RFC 8707 canonical URI this fixture's node publishes.
const THIS_NODES_AUDIENCE: &str = "http://127.0.0.1:8080/a2a";

/// Every source the leg needs, with the auth chain the caller asks for.
fn sources_with_chain(
    kernel: &busbar_kernel::teller::Kernel,
    auth: busbar_unit_auth::Auth,
    auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
) -> crate::root::units_a2a_leg::A2aLegSources<'_> {
    use busbar_unit_admission::{Door, GroupTable, InMemoryCells, Pricer};
    crate::root::units_a2a_leg::A2aLegSources {
        plane: busbar_plane_a2a::A2aPlane::EMPTY,
        kernel,
        auth: Some(auth),
        auth_bindings: Some(auth_bindings),
        breaker: Some(Arc::new(EveryLaneOpen)),
        guard: Some(busbar_unit_trust::net::GuardPolicy::default()),
        denylist: Some(busbar_unit_trust::net::Denylist::default()),
        pinned: Some(Vec::new()),
        door: Some(Door::new(InMemoryCells::new())),
        groups: Some(GroupTable::default()),
        pricer: Some(Pricer::flat(0)),
        bytes_nanos: Some(0),
        store: Some(Arc::new(busbar_core::governance::MemoryStore::new())),
        meter_policy: Some(crate::root::policy::build(
            &crate::root::policy::MeterPolicyConfig::default(),
        )),
        scope_policy: Some(crate::root::units_a2a::scope_policy(
            crate::root::policy::ScopePolicy::new(),
        )),
        durability: Some(Arc::new(std::sync::Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_unit_wal::NullShipper::new()),
                Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
            )
            .expect("a memory-buffered journal cannot fail to open"),
        ))),
        key_scopes: None,
        expected_aud: Some(THIS_NODES_AUDIENCE.to_string()),
        priced: false,
        has_key: false,
    }
}

/// A breaker that benches nothing, so a cell about the mount is not also a cell about readiness.
struct EveryLaneOpen;

impl busbar_unit_trust::lane::BreakerView for EveryLaneOpen {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
    ) -> Result<(), busbar_unit_trust::Unavailable> {
        Ok(())
    }
}

/// A leg with an OPEN chain, for the cells that are about the path rather than about the door.
fn an_open_leg(kernel: &busbar_kernel::teller::Kernel) -> Arc<A2aLeg> {
    let auth = busbar_unit_auth::Auth::new(busbar_unit_auth::AuthChain::new(Vec::new(), false));
    let bindings = crate::root::kernel::auth_bindings::AuthBindings::without_directory();
    Arc::new(
        A2aLeg::assemble(sources_with_chain(kernel, auth, bindings))
            .expect("every source is present"),
    )
}

/// A key directory that enforces the plane boundary the way the node's real verifier does.
struct TheNodesOwnBoundary;

impl crate::root::kernel::auth_bindings::VirtualKeyDirectory for TheNodesOwnBoundary {
    fn verify(
        &self,
        credential: &str,
        _now: u64,
        expected_aud: Option<&str>,
    ) -> Option<crate::root::kernel::auth_bindings::KeyFacts> {
        let carried = match credential {
            "bound-to-this-mount" => Some(THIS_NODES_AUDIENCE),
            "bound-to-nothing" => None,
            _ => return None,
        };
        let admissible = match (expected_aud, carried) {
            (None, None) => true,
            (Some(expected), Some(aud)) => expected == aud,
            _ => false,
        };
        admissible.then(|| crate::root::kernel::auth_bindings::KeyFacts {
            id: "key-a2a-1".to_string(),
            name: "an approved key".to_string(),
        })
    }

    fn revoked(&self, _credential: &str) -> bool {
        false
    }
}

/// A leg whose door is shut to everything but a token minted for THIS node's mount.
fn a_leg_that_checks_the_audience(kernel: &busbar_kernel::teller::Kernel) -> Arc<A2aLeg> {
    let auth = busbar_unit_auth::Auth::new(busbar_unit_auth::AuthChain::new(Vec::new(), true));
    let bindings =
        crate::root::kernel::auth_bindings::AuthBindings::new(Arc::new(TheNodesOwnBoundary));
    Arc::new(
        A2aLeg::assemble(sources_with_chain(kernel, auth, bindings))
            .expect("every source is present"),
    )
}

/// One request through a mounted router, as a caller would send it.
async fn through(
    router: axum::Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tower::ServiceExt;
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(credential) = credential {
        builder = builder.header(axum::http::header::AUTHORIZATION, credential);
    }
    let request = builder
        .body(axum::body::Body::from(body.to_vec()))
        .expect("the probe always builds");
    let response = router.oneshot(request).await.unwrap_or_else(|e| match e {});
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("the probe's answer is readable");
    (
        parts.status.as_u16(),
        header_pairs(&parts.headers),
        bytes.to_vec(),
    )
}

/// **A unit of this plane travels through the loop, and the SURFACE's whole answer reaches the wire.**
///
/// RED FIRST: `A2aLeg::assemble` had no production caller at all, so this request had no loop to
/// travel through — the mount is the caller. The three assertions are the three halves of the seam,
/// and the status and the headers are the half a frame cannot carry: a mount that read only the
/// encoded frame would serve every operation of this protocol under one status with no headers.
#[tokio::test(flavor = "multi_thread")]
async fn a_unit_of_this_plane_travels_through_the_loop_and_the_surfaces_answer_reaches_the_wire() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        busbar_kernel::teller::Kernel::new(),
        1024 * 1024,
    );

    let (status, headers, body) = through(
        router,
        "POST",
        "/a2a",
        None,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
    )
    .await;

    assert_eq!(calls.seen(), 1, "the surface answered exactly once");
    assert_eq!(status, SURFACE_STATUS, "the status is the surface's own");
    assert!(
        headers.contains(&(SURFACE_HEADER.0.to_string(), SURFACE_HEADER.1.to_string())),
        "and so is every header it emitted: {headers:?}"
    );
    assert_eq!(body, SURFACE_BODY, "and so is every byte of the body");
}

/// **A body this plane cannot name an operation for goes AROUND the loop, untouched.**
///
/// The address is claimed and the bytes are not a unit, which is the ordinary case for every REST
/// route this plane declares and for anything a client sends that this protocol does not carry. The
/// surface's own routing already has an answer — the document, the 404 or the 405 that release
/// pinned — and manufacturing a status here for bytes the plane never claimed would be the root
/// inventing an answer it has no basis for.
///
/// The fallback status is the instrument: had the loop taken this request it would have refused it at
/// Decode and spelled that with a status of its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_this_plane_does_not_name_goes_around_the_loop() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        busbar_kernel::teller::Kernel::new(),
        1024 * 1024,
    );

    // A claimed address, and the card fetch every client makes first: no JSON-RPC body at all.
    let (status, _, _) = through(router, "GET", "/a2a/agents/conformance", None, b"").await;

    assert_eq!(calls.seen(), 1, "the surface answered it");
    assert_eq!(
        status, SURFACE_FALLBACK_STATUS,
        "and answered it as itself, rather than the loop refusing bytes it could not read"
    );
}

/// **A path this plane does not claim is not this mount's business at all.**
#[tokio::test(flavor = "multi_thread")]
async fn a_path_outside_the_claim_reaches_the_surface_unchanged() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        busbar_kernel::teller::Kernel::new(),
        1024 * 1024,
    );

    let (status, _, _) = through(router, "GET", "/healthz", None, b"").await;

    assert_eq!(calls.seen(), 1, "the surface answered it");
    assert_eq!(status, SURFACE_FALLBACK_STATUS, "exactly as it always did");
}

/// **A bearer minted for another audience is refused BY THE LOOP, and the surface is never asked.**
///
/// The rig's boundary proof, at the mount. The credential travels as a header, becomes the arrival's
/// own reserved fact, is narrowed to the carrier the plane declared and is checked against the
/// audience this node publishes — and the refusal happens at Authenticate, which runs long before
/// Route. THE COUNT IS THE INSTRUMENT: a 401 whose surface already ran is an operation executed for a
/// caller the door said no to, and no assertion on the status can tell the two apart.
///
/// The refusal document is the PLANE's, so the caller reads its own protocol's error shape rather
/// than a sentence this mount made up.
#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_for_another_audience_is_refused_and_the_surface_is_never_asked() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        a_leg_that_checks_the_audience(&kernel),
        busbar_kernel::teller::Kernel::new(),
        1024 * 1024,
    );

    let (status, _, body) = through(
        router,
        "POST",
        "/a2a",
        // A token this node minted and honours on its plain data plane, presented here.
        Some("Bearer bound-to-nothing"),
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
    )
    .await;

    assert_eq!(
        calls.seen(),
        0,
        "the surface was NEVER asked, so nothing was executed for a caller the door refused"
    );
    assert_eq!(
        status, 401,
        "and the caller is told its credential was not accepted"
    );
    let rendered = String::from_utf8_lossy(&body);
    assert!(
        rendered.contains("jsonrpc"),
        "the refusal is the plane's own document, not this mount's prose: {rendered}"
    );
}

/// **And the token minted FOR this mount is admitted, and does reach it.**
///
/// The other half, and the half that makes the cell above a boundary rather than a door shut to
/// everything: a mount that refused every credential would pass the counterfactual and serve nobody.
#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_for_this_mount_is_admitted_and_the_surface_answers() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        a_leg_that_checks_the_audience(&kernel),
        busbar_kernel::teller::Kernel::new(),
        1024 * 1024,
    );

    let (status, _, body) = through(
        router,
        "POST",
        "/a2a",
        Some("Bearer bound-to-this-mount"),
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
    )
    .await;

    assert_eq!(calls.seen(), 1, "the surface answered it");
    assert_eq!(status, SURFACE_STATUS, "with its own status");
    assert_eq!(body, SURFACE_BODY, "and its own bytes");
}

/// **A request bigger than the operator's cap is not this wrap's to answer.**
///
/// The mounted surface carries that cap and the answer release pinned for exceeding it, and this
/// wrap reads the body first — so a request that DECLARES more than the cap goes straight there
/// rather than being buffered into this node's memory on the way to being rejected anyway.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_the_operators_cap_is_the_surfaces_to_refuse() {
    let kernel = busbar_kernel::teller::Kernel::new();
    let calls = Arc::new(SurfaceCalls::default());
    let router = mount(
        a_mounted_surface(Arc::clone(&calls)),
        an_open_leg(&kernel),
        busbar_kernel::teller::Kernel::new(),
        8,
    );

    let (status, _, _) = through(
        router,
        "POST",
        "/a2a",
        None,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
    )
    .await;

    assert_eq!(calls.seen(), 1, "the surface got it");
    assert_eq!(
        status, SURFACE_STATUS,
        "and answered as itself; the wrap did not buffer it to refuse it"
    );
}

/// **One arrival's seam may be driven exactly once.**
///
/// A seam bound to a request, and the request TAKEN when it is driven. A second drive cannot execute
/// the operation a second time, which is what makes "the loop chose the path" a statement about what
/// ran rather than about what came back — a Route step that somehow reached the seam twice would
/// otherwise send one caller's request to the surface twice.
#[tokio::test(flavor = "multi_thread")]
async fn the_seam_of_one_arrival_executes_at_most_once() {
    use crate::root::units_a2a::A2aDispatch as _;

    let calls = Arc::new(SurfaceCalls::default());
    let runtime = tokio::runtime::Handle::current();
    let errands = drive(a_mounted_surface(Arc::clone(&calls)), &runtime);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/a2a")
        .body(axum::body::Body::from(&b"{}"[..]))
        .expect("the probe always builds");
    let dispatch = RequestDispatch::new(errands, request);

    let op = busbar_plane_a2a::ops::OP_TASK_LIST;
    let (first, second) = tokio::task::spawn_blocking(move || {
        let first = dispatch.execute(op);
        let second = dispatch.execute(op);
        (first, second)
    })
    .await
    .expect("the blocking probe ran");

    assert_eq!(first.status, SURFACE_STATUS, "the first drive reached it");
    assert_eq!(
        second.status, 503,
        "and the second could not, because the request had already gone"
    );
    assert_eq!(calls.seen(), 1, "so the surface ran exactly once");
}
