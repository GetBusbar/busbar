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
        eprintln!("skip: the test plane's cdylib (the plane_driver_test_plane example) is not built; run `cargo build --workspace --examples`");
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
        eprintln!("skip: the test plane's cdylib (the plane_driver_test_plane example) is not built; run `cargo build --workspace --examples`");
        return;
    };
    let a = framed(&g, "/framed/ok", b"\x01x").await;
    assert_eq!((a.status, a.body.as_slice()), (200, b"\x01x".as_slice()));
    assert_eq!(closing(&a), (Some("0"), Some(""), Some("")));
}

/// A UNIT THAT FAILS AFTER ITS HEAD IS TOLD TO THE CLIENT (`BUSBAR-1.6.0.md` §7, "a cut is told
/// to the client"; audit root-R1 leftover C2): `/framed/fail` states its head and one message,
/// then the plane fails the unit on the re-call for the rest, and the route step refuses it for
/// the plane's fault. Its stream closes as that refusal, the framer rendering the refusal's status
/// in the claim's numbering. RED before the fix: the stream closed as one that ended whole
/// (`frame-status: 0`), a failed unit read as a success.
#[tokio::test]
async fn a_framed_unit_that_fails_after_its_head_closes_as_a_refusal_never_as_whole() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-framed-fail", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
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

/// A UNIT THE KERNEL CUTS AFTER ITS HEAD IS TOLD TO THE CLIENT (`BUSBAR-1.6.0.md` §7; audit
/// root-R1 leftover C2): `/framed/drain` states its head and one message, then pends its re-call
/// for the rest. Once the client holds that message, the plane's generation is reloaded, and the
/// pump cuts the unit for the drain, a cut that is the kernel's own, never the plane's. Its stream
/// closes as that refusal, the framer rendering `refusal_status` of the drain. RED before the fix:
/// the stream closed as one that ended whole (`frame-status: 0`).
#[tokio::test]
async fn a_framed_unit_the_kernel_cuts_after_its_head_closes_as_the_cuts_refusal() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-framed-drain", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/framed/drain")
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
    // The unit now pends its re-call: the kernel cuts it.
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
    let Some(g) = governed("serve-framed-refused", false) else {
        eprintln!("skip: the test plane's cdylib (the plane_driver_test_plane example) is not built; run `cargo build --workspace --examples`");
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
        eprintln!("skip: the test plane's cdylib (the plane_driver_test_plane example) is not built; run `cargo build --workspace --examples`");
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

/// A framer door that answers `lp` and is never crossed: what [`super::serve_framed::stream_framer`]
/// judges is its Statement's facts alone.
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

/// A door answering `lp`, its claim rows stating a stream on each claim in `duplex`.
fn lp_door(
    duplex: Vec<&'static str>,
) -> std::sync::Arc<dyn busbar_core_connector::framer::FramerDoor> {
    std::sync::Arc::new(Uncrossed(busbar_core_connector::framer::DoorFacts {
        name: "lp".into(),
        claims: vec!["lp"],
        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        status_rows: Vec::new(),
        duplex,
    }))
}

/// WHICH CLAIM IS STREAM-FRAMED IS JUDGED PER CLAIM OFF THE STATEMENT (ARCHITECT ruling on Q128 U7
/// over 4l, 2026-10-07), never by a transport's name: a claim whose carrier has a framer but whose
/// rows state no upgrade and no session is a request and its answer, served on the data listener's
/// own route, so it is NOT stream-framed; the same framer whose rows state the claim a stream frames
/// it. RED: judged by whether a framer answers the carrier alone, the first arm frames it.
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
        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        status_rows: Vec::new(),
        duplex: vec![line, "framed"],
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
