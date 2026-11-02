// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::money_tests::{governed, Governed};
use super::planes_tests::PUBLISHING;

struct Answered {
    status: u16,
    head: axum::http::HeaderMap,
    body: Vec<u8>,
    trailers: Option<axum::http::HeaderMap>,
}

fn plain() -> busbar_kernel::plane_routes::ListenerScheme {
    busbar_kernel::plane_routes::ListenerScheme(busbar_contract::abi::host::service::SCHEME_PLAIN)
}

async fn framed(g: &Governed, path: &str, body: &'static [u8]) -> Answered {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .extension(plain())
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

fn closing(a: &Answered) -> (Option<&str>, Option<&str>, Option<&str>) {
    let t = a.trailers.as_ref().expect("the answer has trailers");
    (
        field(t, "frame-status"),
        field(t, "frame-message"),
        field(t, "frame-details"),
    )
}

#[tokio::test]
async fn a_framed_stream_carries_messages_and_its_final_status_is_its_framers() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-framed-status", false);

    let a = framed(&g, "/framed/status", b"\x02hi\x03abc").await;
    assert_eq!(a.status, 200);
    assert_eq!(
        field(&a.head, "trailer"),
        Some("frame-status, frame-reason, frame-message, frame-details"),
        "the stream framer declares its closing fields before the first body byte"
    );
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
    let g = governed("serve-framed-whole", false);
    let a = framed(&g, "/framed/ok", b"\x01x").await;
    assert_eq!((a.status, a.body.as_slice()), (200, b"\x01x".as_slice()));
    assert_eq!(closing(&a), (Some("0"), Some(""), Some("")));
}

#[tokio::test]
async fn a_framed_unit_that_fails_after_its_head_closes_as_a_refusal_never_as_whole() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-framed-fail", false);
    let a = framed(&g, "/framed/fail", b"\x01x").await;
    assert_eq!(
        (a.status, a.body.as_slice()),
        (200, b"\x01x".as_slice()),
        "the head and the one message reached the client before the unit failed"
    );
    let t = a.trailers.as_ref().expect("the stream is closed");
    assert_ne!(
        field(t, "frame-status"),
        Some("0"),
        "RED: a unit that failed after its head is never closed as whole"
    );
    assert_eq!(
        field(t, "frame-status"),
        Some(
            busbar_kernel::plane_driver::refusal_status(
                busbar_contract::caps::ReasonCode::PlanePanic
            )
            .to_string()
            .as_str()
        ),
        "the stream closes as the unit's refusal, the plane's fault"
    );
}

#[tokio::test]
async fn a_framed_unit_the_kernel_cuts_after_its_head_closes_as_the_cuts_refusal() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-framed-drain", false);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/framed/drain")
        .extension(plain())
        .body(axum::body::Body::from(&b"\x01x"[..]))
        .expect("a request");
    let resp = g
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    assert_eq!(resp.status().as_u16(), 200, "the head reached the client");
    let mut body = resp.into_body();
    let mut first = Vec::new();
    while first.len() < 2 {
        let frame = body
            .frame()
            .await
            .expect("a frame before the close")
            .expect("the body");
        first.extend_from_slice(&frame.into_data().expect("the message before the close"));
    }
    assert_eq!(first, b"\x01x", "the one message reached the client");

    g.driver.reload();
    let rest = tokio::time::timeout(std::time::Duration::from_secs(30), body.collect())
        .await
        .expect("the cut unit's stream closes")
        .expect("the rest of the body");
    let t = rest.trailers().expect("the stream is closed");
    assert_ne!(
        field(t, "frame-status"),
        Some("0"),
        "RED: a unit the kernel cut after its head is never closed as whole"
    );
    assert_eq!(
        field(t, "frame-status"),
        Some(
            busbar_kernel::plane_driver::refusal_status(busbar_contract::caps::ReasonCode::Drain)
                .to_string()
                .as_str()
        ),
        "the stream closes as the cut's refusal, the drain"
    );
}

#[tokio::test]
async fn a_refused_framed_stream_is_answered_by_its_framers_closing_block_alone() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-framed-refused", false);
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
    let g = governed("serve-framed-wild", false);
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

struct Uncrossed(busbar_core_connector::framer::DoorFacts);

impl busbar_core_connector::framer::FramerDoor for Uncrossed {
    fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
        &self.0
    }

    fn cross(
        &self,
        _call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        unreachable!("judging which framer frames a stream crosses nothing")
    }
}

fn lp_door(
    duplex: Vec<&'static str>,
) -> std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> {
    std::sync::Arc::new(Uncrossed(busbar_core_connector::framer::DoorFacts {
        name: "lp".into(),
        claims: vec!["lp"],
        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        ported: false,
        status_rows: Vec::new(),
        duplex,
        datagram: false,
    }))
}

#[test]
fn a_datagram_framer_is_never_a_streams_framer_though_its_claim_states_a_session() {
    let facts = |datagram| busbar_core_connector::framer::DoorFacts {
        name: "dg".into(),
        claims: vec!["dg"],
        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        ported: false,
        status_rows: Vec::new(),
        duplex: vec!["dg"],
        datagram,
    };
    let stream: std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> =
        std::sync::Arc::new(Uncrossed(facts(false)));
    assert!(
        super::serve_framed::stream_framer("dg", |_| Some(std::sync::Arc::clone(&stream)))
            .is_some(),
        "RED arm: the same rows on a stream framer frame the claim"
    );
    let datagram: std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> =
        std::sync::Arc::new(Uncrossed(facts(true)));
    assert!(
        super::serve_framed::stream_framer("dg", |_| Some(std::sync::Arc::clone(&datagram)))
            .is_none()
    );
}

#[test]
fn a_claim_stating_no_stream_is_not_stream_framed_though_its_carrier_has_a_framer() {
    let plain = lp_door(Vec::new());
    assert!(
        super::serve_framed::stream_framer("lp", |c| (c == "lp").then(|| plain.clone())).is_none(),
        "a claim stating neither an upgrade nor a session is the data listener's to frame"
    );
    let streamed = lp_door(vec!["lp"]);
    let framer =
        super::serve_framed::stream_framer("lp", |c| (c == "lp").then(|| streamed.clone()));
    assert!(
        framer.is_some_and(|d| std::sync::Arc::ptr_eq(&d, &streamed)),
        "a claim its framer's rows state a stream is framed by that framer"
    );
    assert!(
        super::serve_framed::stream_framer("other", |c| (c == "lp").then(|| streamed.clone()))
            .is_none(),
        "a carrier no framer answers is framed by none"
    );
}

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
    let line = super::lines::carrier().expect("this build links a line carrier");
    let door: Arc<dyn FramerDoor> = Arc::new(Claims(DoorFacts {
        name: "claims-the-line".into(),
        claims: vec![line, "framed"],

        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        ported: false,
        status_rows: Vec::new(),
        duplex: vec![line, "framed"],
        datagram: false,
    }));
    let any = |_: &str| Some(Arc::clone(&door));
    assert!(
        super::serve_framed::stream_framer(line, any).is_some(),
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

#[tokio::test]
async fn folded_closing_fields_do_not_advertise_a_trailer_block() {
    let fields = vec![
        (
            b"content-type".to_vec(),
            b"application/test-framed".to_vec(),
        ),
        (b"trailer".to_vec(), b"frame-status, frame-details".to_vec()),
        (b"x-retained".to_vec(), b"head-value".to_vec()),
    ];
    let streaming = super::stated((200, fields.clone()), axum::body::Body::empty());
    assert_eq!(
        field(streaming.headers(), "trailer"),
        Some("frame-status, frame-details")
    );
    let mut closing = axum::http::HeaderMap::new();
    closing.insert("frame-status", "5".parse().unwrap());
    closing.insert("frame-details", "details".parse().unwrap());
    let response = super::closed_whole((200, fields), closing);
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert!(response.headers().get("trailer").is_none());
    assert_eq!(
        field(response.headers(), "content-type"),
        Some("application/test-framed")
    );
    assert_eq!(field(response.headers(), "x-retained"), Some("head-value"));
    assert_eq!(field(response.headers(), "frame-status"), Some("5"));
    assert_eq!(field(response.headers(), "frame-details"), Some("details"));
    let collected = response.into_body().collect().await.unwrap();
    assert!(collected.trailers().is_none());
    assert!(collected.to_bytes().is_empty());
}
