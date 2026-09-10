//! Tests for `units_llm_mount.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! What is here is the PLANE-SIDE half of the claim walk: the generic cells beside `plane_mount`
//! prove the grammar's shapes are read, and these prove that this plane's own declared surface — the
//! fourteen-rung ladder, not a list restated in a test — is claimed by the mount that would serve it.

use super::*;

/// **The plane's own declared surface is claimed by the generic walk.**
///
/// Not a path list: every address below is one this plane's ladder declares, and the assertion is
/// that the mount's walk over `claims::CLAIMS` reaches them. Before the seam commit beside this one,
/// every one of these was false — the walk read `ExactPath` and `PathPattern` and this plane
/// declares neither for these rungs — which is the same sentence as "this plane could be mounted and
/// never reached".
#[test]
fn the_ladders_own_addresses_are_claimed_by_the_mounts_walk() {
    // Rung 7, the widely-copied chat surface, declared as a suffix.
    assert!(claims_the_path("/v1/chat/completions"));
    // The same surface behind a deployment prefix, which is exactly why the rung is a suffix and
    // not an address.
    assert!(claims_the_path("/openai/v1/chat/completions"));
    // Rung 11, declared as a contained literal.
    assert!(claims_the_path("/v1/messages"));
    // Rung 10, and rung 14's two non-chat surfaces.
    assert!(claims_the_path("/v1/responses"));
    assert!(claims_the_path("/v1/embeddings"));
    assert!(claims_the_path("/v1/moderations"));
    // Rung 6, declared as a segment pattern — the shape the walk always read.
    assert!(claims_the_path("/v1/models/gemini-2.0-flash"));
}

/// **A trailing slash is the same address here too**, by the mount's one normalisation and not by
/// anything this file does.
#[test]
fn a_trailing_slash_is_the_same_address_on_this_planes_surface() {
    assert!(claims_the_path("/v1/embeddings"));
    assert!(claims_the_path("/v1/embeddings/"));
}

/// **A path no rung of the ladder names is not this plane's**, which is what keeps a mounted
/// listener's other routes answering as they always did.
#[test]
fn a_path_the_ladder_does_not_name_is_left_to_the_surface_underneath() {
    assert!(!claims_the_path("/healthz"));
    assert!(!claims_the_path("/mcp"));
    assert!(!claims_the_path("/a2a/agents/one"));
    assert!(!claims_the_path("/"));
    // The voice plane's two one-shot audio operations, which this plane's rung 14 deliberately does
    // NOT claim — the rung names the audio paths one at a time for exactly this reason.
    assert!(!claims_the_path("/v1/audio/transcriptions"));
    assert!(!claims_the_path("/v1/audio/speech"));
}

/// **The media type is the plane's, and it is the one its dialects answer with.**
#[test]
fn the_document_answers_carry_this_planes_own_media_type() {
    assert_eq!(media_type(), "application/json");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LEG, THROUGH THE MOUNT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

use std::sync::Mutex;

use busbar_core::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use tower::ServiceExt as _;

use crate::root::durability::Durability;
use crate::root::mount_ingress::BootIngress;
use crate::root::units_llm::LlmNode;

/// The one dialect these cells speak, and the address its ladder rung names.
const PROTO: &str = busbar_llm::proto_codec::PROTO_OPENAI;
const CHAT: &str = "/v1/chat/completions";
const POOL: &str = "p";
const LANE: &str = "m0";
/// One cent, so derived spend in cents reads as the billable count.
const FEE_CENTS: i64 = 1;
/// The token figures the scripted upstream reports.
const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

/// One deployment behind one mount: a governed key, a one-lane pool, a scripted upstream, a node
/// with a book bound to it, and the router a client talks to.
struct Mounted {
    router: axum::Router,
    book: Arc<Mutex<Durability>>,
    server: MockServer,
}

/// The events a streamed answer relays, with the usage split on the last data frame — which is what
/// makes the tap fill at the END of the body rather than at the terminal.
fn sse_events() -> Vec<String> {
    vec![
        serde_json::json!({"id": "chatcmpl-mount", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {"role": "assistant",
                                                              "content": "hello"}}]})
        .to_string(),
        serde_json::json!({"id": "chatcmpl-mount", "object": "chat.completion.chunk",
                           "created": 0, "model": LANE,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                                     "total_tokens": INPUT + OUTPUT}})
        .to_string(),
        "[DONE]".to_string(),
    ]
}

/// The bytes a client of this dialect sends.
fn chat_body(streamed: bool) -> Vec<u8> {
    let mut v = serde_json::json!({
        "model": POOL,
        "messages": [{"role": "user", "content": "hi"}],
    });
    if streamed {
        v["stream"] = serde_json::Value::Bool(true);
    }
    serde_json::to_vec(&v).expect("the fixture body serializes")
}

/// **A DEPLOYMENT THAT PRICES THIS LANE**, through the root's own rate-apply seam.
///
/// The late arm exists to post a FIGURE, and a figure nothing can price is a figure nothing posts —
/// `LateAccrual::post` declines a zero rather than writing a record claiming the node settled
/// something. So a cell about the arm firing has to be a cell on a deployment that has rates, and
/// the rates are applied the one way production applies them: the engine resolved them, and the root
/// rebuilds its card from the same two figures.
fn priced() {
    busbar_substrate::rate_apply::RateApply::rates_applied(
        &crate::root::kernel::CardRepricer,
        &busbar_substrate::rate_apply::RawRates {
            lanes: &[(
                LANE.to_string(),
                busbar_substrate::billing::RawTierRates {
                    input: 1.0,
                    output: 1.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
            )],
            fee_cents: FEE_CENTS,
            present: true,
        },
    );
}

/// A memory-buffered book, the shape the node binds on a deployment with no data directory.
fn a_book() -> Arc<Mutex<Durability>> {
    Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ))
}

/// What the surface underneath answers. It is the instrument for the one thing that must not happen
/// on a claimed address: a request that reaches it is a request the mount handed around the loop.
fn a_surface_underneath() -> axum::Router {
    axum::Router::new().fallback(axum::routing::any(|| async {
        axum::http::Response::builder()
            .status(418)
            .body(axum::body::Body::from("the surface underneath"))
            .expect("builds")
    }))
}

/// One deployment: a scripted upstream, a governed key, a one-lane pool, a node and its own book.
///
/// The CALLER is a parameter rather than always this deployment's own mint, so two deployments can
/// be asked about the SAME caller. That is what the paired cell needs and nothing else does: a
/// posting is keyed by principal, and two legs compared under two principals are two rows.
struct Deployment {
    app: Arc<busbar_core::state::App>,
    key: Arc<busbar_api::VirtualKey>,
    book: Arc<Mutex<Durability>>,
    node: LlmNode,
    server: MockServer,
}

/// Compose one deployment and mount this plane's leg in front of it.
async fn mounted(streamed: bool) -> Mounted {
    let d = deployment(streamed, None).await;
    let resolved = Arc::clone(&d.key);
    let leg = LlmLeg::assemble(
        d.node,
        Arc::new(BootIngress::new(
            busbar_core::plane_host::engine_host(&d.app),
            move |_| busbar_api::PlaneRequestCtx {
                key: Some(Arc::clone(&resolved)),
            },
        )),
    );
    Mounted {
        router: mount(
            a_surface_underneath(),
            Arc::new(leg),
            busbar_kernel::teller::Kernel::new(),
            1024 * 1024,
        ),
        book: d.book,
        server: d.server,
    }
}

/// Compose one deployment, resolving every caller to `caller` where one is handed in.
async fn deployment(streamed: bool, caller: Option<Arc<busbar_api::VirtualKey>>) -> Deployment {
    busbar_llm::testkit::install_test_seams();
    busbar_core::metrics::init();
    priced();

    let state = Arc::new(MockServerState::new());
    for _ in 0..8 {
        state.push(if streamed {
            MockResponse::Sse {
                events: sse_events(),
                abort_at_index: None,
            }
        } else {
            MockResponse::Ok {
                status: reqwest::StatusCode::OK,
                body: serde_json::json!({
                    "id": "chatcmpl-mount", "object": "chat.completion", "created": 0,
                    "model": LANE,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                              "total_tokens": INPUT + OUTPUT}
                }),
            }
        });
    }
    let server = MockServer::new(Arc::clone(&state)).await;

    let store = Arc::new(busbar_core::governance::MemoryStore::new());
    // A SIGNER, so the key below is minted as the credential a client actually presents rather than
    // hand-built beside the deployment that has to resolve it.
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_core::governance::GovState::new_with_signer(store, None, Some(signer))
            .expect("governance"),
    );
    let (key, _token) = gov
        .mint_signed(
            busbar_substrate::governance::NewKeySpec {
                name: "root-llm-mount".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint the deployment's key");
    let cost = busbar_core::cost::CostModel::resolve_parts(
        None,
        FEE_CENTS,
        &std::collections::BTreeMap::new(),
    );
    gov.hydrate_budgets(&cost, 0).expect("hydrate");

    let app = TestApp::new()
        .lane(LaneSpec::new(LANE, PROTO, &server.base_url()).provider("test"))
        .pool(POOL, &[(0, 1)])
        .governance(gov)
        .cost(cost)
        .build();

    let book = a_book();
    let node = LlmNode::new();
    node.bind_book(Arc::clone(&book));

    Deployment {
        app,
        key: caller.unwrap_or_else(|| Arc::new(key)),
        book,
        node,
        server,
    }
}

/// One request through the mounted router, exactly as a client makes it.
async fn through(router: axum::Router, body: Vec<u8>) -> axum::response::Response {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(CHAT)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::AUTHORIZATION, "Bearer sk-mounted")
        .body(axum::body::Body::from(body))
        .expect("the probe always builds");
    router.oneshot(request).await.unwrap_or_else(|e| match e {})
}

/// How many records this book's journal holds.
fn journalled(book: &Arc<Mutex<Durability>>) -> usize {
    book.lock()
        .unwrap_or_else(|p| p.into_inner())
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies")
        .len()
}

/// **THE CELL THE LATE MONEY IS READ OUT OF REACHES THE CLIENT'S ANSWER, THROUGH THE MOUNT.**
///
/// RED FIRST: this plane had no mounted leg at all, so there was nothing for a request to travel
/// through. And it is the first cell of any mount in this tree that a leg handing back three fields
/// could not pass — which is exactly what the two mounts before this one hand back, and exactly what
/// this plane cannot survive.
///
/// This plane's money is not a fact at the terminal. A streamed answer's consumption is known when
/// the BODY drains, and the cell it is read out of rides on the response as an extension. So a mount
/// that read the leg's bytes to rebuild a frame would drain the stream into memory, drop the
/// extension with the response it rode on, and post nothing for a request the driven path charges
/// for. Every one of those is silent.
///
/// The assertion is therefore about what a CLIENT holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tap_the_late_money_is_read_out_of_rides_the_answer_through_the_mount() {
    let rig = mounted(true).await;
    let response = through(rig.router.clone(), chat_body(true)).await;

    assert_eq!(
        response.status(),
        200,
        "the mounted loop answered, and not the surface underneath"
    );
    assert!(
        busbar_llm::unit::walk::Walk::tap_of(&response).is_some(),
        "the cell the late accrual is read out of reached the client's response"
    );

    drop(response);
    rig.server.shutdown().await;
}

/// **AND THE LATE ARM FIRES ON THE FRAME THE CLIENT READS LAST.**
///
/// The other half, and the one that is about money rather than about a type. The exit arm settles at
/// the terminal — one record — and the figure the tap reports does not exist until the last frame of
/// the body has been handed over. A mount that buffered the body would fire that arm before the
/// client had anything; a mount that dropped the wrapper would never fire it at all.
///
/// So the book is read twice: once with the answer in hand and its body untouched, and once after
/// the client has drained it. One record becomes two, and the second one is the money.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_late_accrual_lands_when_the_client_drains_the_body_it_was_handed() {
    let rig = mounted(true).await;
    let response = through(rig.router.clone(), chat_body(true)).await;
    assert_eq!(response.status(), 200);

    let settled_at_the_terminal = journalled(&rig.book);
    assert_eq!(
        settled_at_the_terminal, 1,
        "the exit arm settled, and the streamed figure is not a fact yet"
    );

    // THE CLIENT DRAINS IT. Every frame, in order, exactly as a caller reads a stream.
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer is readable");
    assert!(
        !bytes.is_empty(),
        "and the frames are the surface's own bytes"
    );

    // TWO MORE RECORDS, not one, and the second is what makes this the money rather than a marker:
    // the late posting reserved nothing and settled at a price, so the chain carries its settlement
    // AND the overdraft entry that says what part of it nothing backed — which is how the carry into
    // the next window is read off the chain rather than inferred.
    assert_eq!(
        journalled(&rig.book),
        settled_at_the_terminal + 2,
        "the figure that arrived after the terminal reached the book"
    );
    rig.server.shutdown().await;
}

/// **A CLIENT THAT HANGS UP MID-ANSWER IS STILL BILLED FOR WHAT IT TOOK.**
///
/// The `Drop` end of the same arm, through the mount. A body dropped rather than drained is the
/// client cutting the connection, and the engine's own stream wrapper files its partial from its own
/// `Drop` — so the wrapper's ordering, inner body first and then the arm, has to survive the trip
/// through the mount as well. A mount that rebuilt the response would have dropped this wrapper at
/// the seam, where there is no client and nothing to report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_body_still_reaches_the_book_through_the_mount() {
    let rig = mounted(true).await;
    let response = through(rig.router.clone(), chat_body(true)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(journalled(&rig.book), 1);

    // THE CUT: the client goes away holding an unread body.
    drop(response);

    assert_eq!(
        journalled(&rig.book),
        3,
        "the arm fired on the drop, for what the tap had"
    );
    rig.server.shutdown().await;
}

/// **A ROUTE THIS PLANE DOES NOT CLAIM STILL REACHES THE SURFACE UNDERNEATH.**
///
/// The mount's own rule, asserted on this plane because this plane's claim table is the one that is
/// fourteen rungs long: a listener carrying this mount also carries routes deliberately outside it,
/// and a mount that took them would refuse a route that has always answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unclaimed_route_goes_around_the_loop_to_the_surface_underneath() {
    let rig = mounted(false).await;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(axum::body::Body::empty())
        .expect("builds");
    let response = rig
        .router
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|e| match e {});
    assert_eq!(
        response.status(),
        418,
        "the surface underneath answered it, untouched"
    );
    rig.server.shutdown().await;
}
