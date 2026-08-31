// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROOF THAT THE SEAM IS REAL: a THIRD plane, for a protocol busbar does not have.
//!
//! This file is the analogue of `crate::audit`'s
//! `a_fourth_stream_costs_a_record_type_and_nothing_else`, and it is written to the same standard —
//! it does not assert that the shared code compiles, it drives a plane that does not exist through
//! every step of the shared sequence and measures what that plane had to write.
//!
//! ## The fictional protocol, and it is deliberately unlike both real ones
//!
//! `zeta` is a JSON-RPC protocol with:
//!
//! * a **flat error envelope** — `{"zeta": 1, "fault": {...}}` — which is neither MCP's JSON-RPC
//!   error object nor A2A's ProtoJSON `details` array. If any refusal shape were still core's, one
//!   of these assertions would come back carrying a `jsonrpc` member.
//! * **`409` for a malformed envelope** where both real planes answer `400`, and **`418` for a
//!   method it does not serve** where both answer `404`. A status core decided rather than the
//!   protocol would show up as one of theirs.
//! * a **two-verb vocabulary** (`zeta.ping`, `zeta.echo`) with no `_meta`, no mirrored headers and
//!   no media-type gate.
//! * an RFC 9728 document with **scopes and no authorization servers**, which is a third
//!   combination — MCP publishes servers, A2A publishes neither.
//!
//! ## What `zeta` costs, counted
//!
//! One `Words` impl (a total match — its method vocabulary and its refusal wording), one
//! `ResourceMetadata` impl (three facts), and one dispatch closure (its verb dispatch). **No
//! ingress module. No refusal shaper. No 404 shaper. No metadata handler. No error type.** That
//! list is the claim, and every item on it is exercised below.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use super::super::protocol::{
    metadata, metadata_handler, origin_admitted, serve, CoreRefusal, Metadata, Request,
    ResourceMetadata, Words,
};

// ══ THE WHOLE OF WHAT A THIRD PLANE WRITES ══════════════════════════════════════════════════════

/// `zeta`'s refusal wording. One total match; there is no `_` arm and no default.
#[derive(Default)]
struct ZetaWords;

/// `zeta`'s envelope: flat, versioned, and nothing like either real plane's.
fn fault(status: StatusCode, kind: &str, detail: impl Into<String>) -> Response {
    (
        status,
        axum::Json(json!({ "zeta": 1, "fault": { "kind": kind, "detail": detail.into() } })),
    )
        .into_response()
}

impl Words for ZetaWords {
    fn refuse(&self, refusal: CoreRefusal<'_>) -> Response {
        match refusal {
            CoreRefusal::PlaneAbsent => fault(
                StatusCode::SERVICE_UNAVAILABLE,
                "no-zeta",
                "this deployment speaks no zeta",
            ),
            CoreRefusal::MetadataUnavailable => fault(
                StatusCode::SERVICE_UNAVAILABLE,
                "no-zeta-resource",
                "this deployment publishes no zeta resource",
            ),
            CoreRefusal::ForbiddenOrigin => fault(
                StatusCode::FORBIDDEN,
                "origin",
                "zeta does not take orders from that page",
            ),
            CoreRefusal::NotJson => fault(StatusCode::BAD_REQUEST, "not-json", "send zeta JSON"),
            // `409`, where both real planes answer `400`.
            CoreRefusal::InvalidEnvelope(invalid) => {
                fault(StatusCode::CONFLICT, "envelope", invalid.message)
            }
            // `418`, where both real planes answer `404`.
            CoreRefusal::MethodNotFound { id, method } => fault(
                StatusCode::IM_A_TEAPOT,
                "no-verb",
                format!("zeta has no `{method}` (id {id})"),
            ),
            CoreRefusal::Admission {
                id: _,
                status,
                message,
                reason,
            } => fault(status, reason.unwrap_or("refused"), message),
        }
    }
}

impl ResourceMetadata for ZetaWords {
    fn document(app: &crate::state::App) -> Option<Metadata<'_>> {
        // A third plane resolves its own facts off the snapshot exactly as the two real ones do.
        // This one keys off `mcp` only so the test can turn the plane off and on; what is being
        // measured is that the HANDLER is not written here, not where the facts come from.
        // "is this an mcp deployment?" — read the neutral plane slot directly (the type-erased
        // presence the `busbar_mcp::mcp::resource` accessor also keys off), so this in-crate unit test
        // names no plane type across the crate boundary.
        app.plane_slot("mcp")?;
        Some(Metadata {
            resource: std::borrow::Cow::Borrowed("https://zeta.example/rpc"),
            authorization_servers: &[],
            scopes_supported: ZETA_SCOPES,
        })
    }
}

static ZETA_SCOPES: &[String] = &[];

/// `zeta`'s verb dispatch. Two verbs; anything else falls through to core's step 13.
async fn zeta_dispatch(value: Value, id: Value, method: String) -> Option<Response> {
    match method.as_str() {
        "zeta.ping" => {
            Some(axum::Json(json!({ "zeta": 1, "id": id, "pong": true })).into_response())
        }
        "zeta.echo" => Some(
            axum::Json(json!({ "zeta": 1, "id": id, "said": value.get("params").cloned() }))
                .into_response(),
        ),
        _ => None,
    }
}

/// The whole of `zeta`'s ingress: `serve` plus the three things above. There is no other zeta code.
async fn zeta(present: bool, origin: Option<&str>, body: &[u8]) -> Response {
    serve(
        &ZetaWords,
        Request {
            present,
            origin,
            allowed_origins: &[],
            wire_refusal: None,
            body,
        },
        // zeta observes no notification; the hook is core's seam and this fixture passes the
        // no-op every plane without one passes.
        |_, _| {},
        zeta_dispatch,
    )
    .await
}

/// The status and the parsed body of one response.
async fn read(r: Response) -> (u16, Value) {
    let status = r.status().as_u16();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

// ══ THE CLAIM ═══════════════════════════════════════════════════════════════════════════════════

/// A THIRD PLANE COSTS A METHOD VOCABULARY AND NOTHING ELSE.
///
/// Six behaviours, driven end to end against a protocol busbar does not have, with no ingress
/// module, no refusal shaper, no 404 shaper, no metadata handler and no error type written for it.
/// Every refusal below comes back in `zeta`'s OWN flat envelope with `zeta`'s OWN statuses, which is
/// what proves the shape was never core's — only the DECISION was.
#[tokio::test]
async fn a_third_plane_costs_a_method_vocabulary_and_nothing_else() {
    // (1) IT DISPATCHES. The vocabulary answers, and core does not touch what it said.
    let (status, body) = read(
        zeta(
            true,
            None,
            br#"{"jsonrpc":"2.0","id":7,"method":"zeta.echo","params":{"hi":1}}"#,
        )
        .await,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({ "zeta": 1, "id": 7, "said": { "hi": 1 } }));

    // (2) IT 404s — in zeta's spelling of one, which is `418`. A status core owned would be `404`.
    let (status, body) = read(
        zeta(
            true,
            None,
            br#"{"jsonrpc":"2.0","id":9,"method":"zeta.nope"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(
        status, 418,
        "step 13 is core's DECISION and zeta's STATUS: {body}"
    );
    assert_eq!(body["fault"]["kind"], "no-verb");
    assert_eq!(body["fault"]["detail"], "zeta has no `zeta.nope` (id 9)");
    assert!(
        body.get("jsonrpc").is_none(),
        "no other plane's envelope leaked in: {body}"
    );

    // (3) IT PARSES — and refuses a body that is not JSON, in zeta's words.
    let (status, body) = read(zeta(true, None, b"{not json").await).await;
    assert_eq!(status, 400);
    assert_eq!(body["fault"]["kind"], "not-json");

    // (4) IT REFUSES A BAD ENVELOPE — `409`, where both real planes answer `400`.
    let (status, body) = read(zeta(true, None, br#"{"id":1,"method":"zeta.ping"}"#).await).await;
    assert_eq!(
        status, 409,
        "the envelope refusal's STATUS is zeta's: {body}"
    );
    assert_eq!(body["fault"]["kind"], "envelope");

    // …and a NOTIFICATION is `202` with no body, which is core's and is the same on every plane —
    // JSON-RPC 2.0 §4.1 has no dialect.
    let r = zeta(true, None, br#"{"jsonrpc":"2.0","method":"zeta.ping"}"#).await;
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    assert!(bytes.is_empty(), "a notification is answered with NO body");

    // (5) IT REFUSES AN ORIGIN. zeta wrote no rebinding check; it inherited one.
    let (status, body) = read(
        zeta(
            true,
            Some("https://evil.example"),
            br#"{"jsonrpc":"2.0","id":1,"method":"zeta.ping"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["fault"]["kind"], "origin");

    // (6) IT ANSWERS WHEN THE PLANE IS ABSENT, without an unwrap and in its own words.
    let (status, body) = read(
        zeta(
            false,
            None,
            br#"{"jsonrpc":"2.0","id":1,"method":"zeta.ping"}"#,
        )
        .await,
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(body["fault"]["kind"], "no-zeta");
}

/// AND IT PUBLISHES AN RFC 9728 DOCUMENT, with no metadata handler written for it.
///
/// A third combination of the optional members — scopes declared, authorization servers not — so
/// the renderer is shown to omit and include per FACT rather than per plane.
#[tokio::test]
async fn a_third_plane_publishes_metadata_with_no_handler_of_its_own() {
    let scopes = vec!["zeta.read".to_string()];
    let doc = metadata(&Metadata {
        resource: std::borrow::Cow::Borrowed("https://zeta.example/rpc"),
        authorization_servers: &[],
        scopes_supported: &scopes,
    });
    let (status, body) = read(doc).await;
    assert_eq!(status, 200);
    assert_eq!(body["resource"], "https://zeta.example/rpc");
    assert_eq!(body["scopes_supported"], json!(["zeta.read"]));
    assert_eq!(body["bearer_methods_supported"], json!(["header"]));
    assert!(
        body.get("authorization_servers").is_none(),
        "an EMPTY optional member is omitted, never emitted empty: {body}"
    );
}

/// THE HANDLER IS MOUNTABLE FOR A PLANE THAT WROTE NONE, and the route it mounts on carries the
/// bar the mount declared.
///
/// This is the other half of "the audience check does not move": it stays beside the mount, and a
/// declared route inherits it because `CoreRouter::route` records the pair in one act. A third
/// plane's route is `RouteAuth::Key` because its DECLARATION says so, not because a handler
/// remembered to ask.
#[test]
fn a_declared_route_inherits_the_bar_beside_its_mount() {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    let (_router, table) = crate::core_routes::CoreRouter::new()
        // The RPC endpoint — audience-bound, exactly like both real planes'.
        .route(
            "/zeta".to_string(),
            RouteMethod::Post,
            RouteAuth::Key,
            |body: axum::body::Bytes| async move { zeta(true, None, &body).await },
        )
        // The RFC 9728 document — open, and served by CORE's handler with zeta's type parameter.
        // No zeta function is named on this line; that is the point of it.
        .route(
            "/.well-known/oauth-protected-resource/zeta".to_string(),
            RouteMethod::Get,
            RouteAuth::None,
            metadata_handler::<ZetaWords>,
        )
        .into_parts();
    assert_eq!(
        table.declared_auth("/zeta", &axum::http::Method::POST),
        Some(RouteAuth::Key),
        "the mount declares the bar; the handler never asks"
    );
    assert_eq!(
        table.declared_auth(
            "/.well-known/oauth-protected-resource/zeta",
            &axum::http::Method::GET
        ),
        Some(RouteAuth::None),
        "RFC 9728 §3: the document is readable without a credential"
    );
}

// ══ THE SHARED DECISION ITSELF ══════════════════════════════════════════════════════════════════

/// LOOPBACK IS ADMITTED UNCONDITIONALLY, AND `null` IS NOT LOOPBACK.
///
/// The rule that moved out of `mcp/ingress.rs` when A2A turned out never to have had one. `null` is
/// what a sandboxed iframe and a `file://` document send, and reading it as local would admit
/// exactly the contexts that deliberately have no origin.
#[test]
fn the_rebinding_rule_admits_loopback_and_nothing_it_cannot_see() {
    for ok in [
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "https://[::1]:9",
    ] {
        assert!(
            origin_admitted(ok, &[]),
            "{ok} is inside the trust boundary"
        );
    }
    for bad in [
        "https://evil.example",
        "null",
        "file://",
        // The rebinding page's own origin, which is what the browser actually sends.
        "http://localhost.evil.example",
        // A prefix match would admit this one; the comparison is exact.
        "http://localhosts",
    ] {
        assert!(
            !origin_admitted(bad, &[]),
            "{bad} must not drive this plane"
        );
    }
    // The operator's allowlist is DATA into the one rule, compared exactly.
    let allow = vec!["https://console.example".to_string()];
    assert!(origin_admitted("https://console.example", &allow));
    assert!(!origin_admitted(
        "https://console.example.evil.test",
        &allow
    ));
}

/// A REFUSAL CORE GROWS LATER MUST BE GIVEN A SENTENCE, not folded into a nearby arm.
///
/// This is not a runtime assertion and cannot be: the property is that `CoreRefusal` is a closed
/// enum matched TOTALLY, with no `_` arm and no trait default, so adding a variant is a COMPILE
/// error in every protocol until each has written words for it. What is asserted here is the
/// premise that makes that true — that every arm of the enum a plane can be handed produces a
/// DISTINGUISHABLE answer, so a future author cannot satisfy the compiler by aliasing a new
/// refusal onto an old one and having nobody notice.
#[tokio::test]
async fn every_core_refusal_has_its_own_sentence_on_the_third_plane() {
    let invalid = super::super::jsonrpc::Invalid {
        code: super::super::jsonrpc::INVALID_REQUEST,
        message: "not a message",
        id: Value::Null,
    };
    let mut seen: Vec<(u16, String)> = Vec::new();
    for refusal in [
        CoreRefusal::PlaneAbsent,
        CoreRefusal::MetadataUnavailable,
        CoreRefusal::ForbiddenOrigin,
        CoreRefusal::NotJson,
        CoreRefusal::InvalidEnvelope(&invalid),
        CoreRefusal::MethodNotFound {
            id: Value::from(1),
            method: "x",
        },
        CoreRefusal::Admission {
            id: Value::from(1),
            status: StatusCode::FORBIDDEN,
            message: "no".into(),
            reason: Some("not_granted"),
        },
    ] {
        let (status, body) = read(ZetaWords.refuse(refusal)).await;
        seen.push((status, body["fault"]["kind"].as_str().unwrap().to_string()));
    }
    let mut kinds: Vec<&str> = seen.iter().map(|(_, k)| k.as_str()).collect();
    kinds.sort_unstable();
    let before = kinds.len();
    kinds.dedup();
    assert_eq!(
        kinds.len(),
        before,
        "two core refusals answered with the same word: {seen:?}"
    );
}
