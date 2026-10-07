// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STREAM FRAMED BY ITS CLAIM'S FRAMER, SERVED ON THE DATA LISTENER (ARCHITECT 4l, 2026-10-05):
//! the test plane's open claim `/framed` arrives over the neutral `frame` claim, whose framer (the
//! neutral frame door, dropped in) frames the stream alone: the request body's length-byte messages
//! are what the unit arrives with, its reply message is framed on the way out, and its close is the
//! framer's own closing block — the unit's final status as trailers after the body, a refusal as
//! the whole answer. The data listener renders none of the claim's wire. RED: a status the claim's
//! numbering does not have never reaches the framer as one.

use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::money_tests::{governed, Governed};
use super::planes_tests::PUBLISHING;

/// What a framed stream answered: the status, the head, the body and the trailers.
struct Answered {
    status: u16,
    head: axum::http::HeaderMap,
    body: Vec<u8>,
    trailers: Option<axum::http::HeaderMap>,
}

async fn framed(g: &Governed, path: &str, body: &'static [u8]) -> Answered {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .body(axum::body::Body::from(body))
        .expect("a request");
    let resp = g
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    let status = resp.status().as_u16();
    let head = resp.headers().clone();
    let collected = resp.into_body().collect().await.expect("the body");
    let trailers = collected.trailers().cloned();
    Answered {
        status,
        head,
        body: collected.to_bytes().to_vec(),
        trailers,
    }
}

fn field<'a>(h: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// The trailers' three closing fields.
fn closing(a: &Answered) -> (Option<&str>, Option<&str>, Option<&str>) {
    let t = a.trailers.as_ref().expect("the answer has trailers");
    (
        field(t, "frame-status"),
        field(t, "frame-message"),
        field(t, "frame-details"),
    )
}

#[tokio::test]
async fn a_framed_streams_messages_and_its_final_status_are_its_framers() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-framed-status", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    // Two messages in; the plane echoes what it arrived with as one message.
    let a = framed(&g, "/framed/status", b"\x02hi\x03abc").await;
    assert_eq!(a.status, 200);
    assert_eq!(
        a.body, b"\x05hiabc",
        "the reply message, framed by the framer"
    );
    assert!(
        a.head.get("content-length").is_none(),
        "the framed body is the framer's length, not the unit's"
    );
    assert_eq!(
        closing(&a),
        (Some("5"), Some("not here"), Some("dead")),
        "the unit's final status, message and details, rendered by the framer alone"
    );
}

#[tokio::test]
async fn a_framed_stream_that_ends_whole_is_closed_by_its_framer_as_whole() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-framed-whole", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let a = framed(&g, "/framed/ok", b"\x01x").await;
    assert_eq!((a.status, a.body.as_slice()), (200, b"\x01x".as_slice()));
    assert_eq!(closing(&a), (Some("0"), Some(""), Some("")));
}

#[tokio::test]
async fn a_refused_framed_stream_is_answered_by_its_framers_closing_block_alone() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-framed-refused", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let a = framed(&g, "/framed/refuse", b"\x01x").await;
    assert_eq!(
        a.status, 200,
        "the framer's `:status`, not the refusal's 404"
    );
    assert_eq!(field(&a.head, "frame-status"), Some("404"));
    assert!(
        a.body.is_empty() && a.trailers.is_none(),
        "the block is the whole answer"
    );
}

#[tokio::test]
async fn a_final_status_the_claims_numbering_does_not_have_never_reaches_the_framer() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-framed-wild", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let a = framed(&g, "/framed/wild", b"\x01x").await;
    let t = a.trailers.as_ref().expect("the stream is still closed");
    assert_eq!(
        field(t, "frame-status"),
        Some(
            busbar_kernel::plane_driver::refusal_status(
                busbar_contract::caps::ReasonCode::PlanePanic
            )
            .to_string()
            .as_str()
        ),
        "RED: 42 is refused before it crosses; the stream closes as a plane fault"
    );
    assert!(t.get("frame-message").is_none(), "no final status crossed");
}

/// THE LINE CARRIER IS NEVER FRAMED (SEAM-4l regression): a claim over the root's own line carrier
/// is served as the line arrived, even where a framer claims that carrier's name (the stdio
/// transport's framer does), while any other carrier such a framer answers is still framed by it.
/// RED without the line-carrier rule: the stdio line went to the framer and never completed.
#[test]
fn the_line_carrier_is_never_handed_to_a_framer_that_claims_its_name() {
    use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
    use std::sync::Arc;
    struct Claims(DoorFacts);
    impl FramerDoor for Claims {
        fn facts(&self) -> &DoorFacts {
            &self.0
        }
        fn cross(&self, _: Call<'_>) -> Crossed {
            unreachable!("never crossed: only the choice is judged")
        }
    }
    let line = super::lines::LINE_CARRIER;
    let door: Arc<dyn FramerDoor> = Arc::new(Claims(DoorFacts {
        name: "claims-the-line".into(),
        claims: vec![line, "framed"],
        composes_over: Vec::new(),
        status_rows: Vec::new(),
    }));
    let any = |_: &str| Some(Arc::clone(&door));
    assert!(
        super::serve_framed::stream_framer(line, super::DATA_CARRIER, any).is_some(),
        "the hazard exists: a framer claims the line carrier's name"
    );
    assert!(
        super::framed_by(line, any).is_none(),
        "a line is served as it arrived, never framed"
    );
    assert!(
        super::framed_by("framed", any).is_some(),
        "another carrier such a framer answers is still framed by it"
    );
}
