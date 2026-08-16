// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane plugin's own tests — driven entirely through `busbar-api`, because that is the only
//! busbar crate this plugin can name. A third-party author writes exactly these.

use super::*;
use std::sync::Arc;

/// The operator section these tests drive the plane with. Named once, because the route table is
/// DERIVED from it.
const CFG: &str = r#"{"greeting":"hei","base":"/example"}"#;

struct FixedClock(u64);
impl busbar_api::plane::PlaneClock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

struct NoJournal;
impl busbar_api::plane::PlaneJournal for NoJournal {
    fn append(&self, _subject: &str, _payload: &str) -> Result<(), PlaneError> {
        Ok(())
    }
    fn read(&self, _subject: &str, _limit: usize) -> Result<Vec<String>, PlaneError> {
        Ok(Vec::new())
    }
    fn verify(&self, _subject: &str) -> Result<busbar_api::plane::ChainVerdict, PlaneError> {
        Ok(busbar_api::plane::ChainVerdict::Absent)
    }
}

struct NoMetrics;
impl busbar_api::plane::PlaneMetrics for NoMetrics {
    fn counter(&self, _n: &str, _v: u64, _l: &[(&str, &str)]) {}
    fn histogram(&self, _n: &str, _v: f64, _l: &[(&str, &str)]) {}
}

fn ctx(config: &str) -> PlaneCtx {
    PlaneCtx::builder(
        Arc::from(config),
        Arc::new(FixedClock(1_700_000_000)),
        Arc::new(NoMetrics),
    )
    .with_journal(Arc::new(NoJournal))
    .build()
}

fn get(path: &str) -> PlaneRequest {
    PlaneRequest {
        method: "GET".to_string(),
        path: path.to_string(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// THE PROPERTY THIS CRATE EXISTS TO SHOW: the config section is parsed into a type core does not
/// know, and the answer reflects the operator's text. Core carried the bytes and named nothing.
#[tokio::test]
async fn the_typed_config_section_is_parsed_by_the_plane_not_by_core() {
    let out = DECL
        .handler
        .unwrap()
        .serve(&ctx(CFG), &get("/example/hello"))
        .await
        .expect("hello serves");
    assert_eq!(out.status, 200);
    let body = String::from_utf8(out.body.as_unary().expect("hello is unary").to_vec()).unwrap();
    // The operator's word, round-tripped through an opaque-text seam.
    assert!(body.contains("\"greeting\":\"hei\""), "body was {body}");
    // The clock came from the granted capability, not from a core module path.
    assert!(body.contains("\"at\":1700000000"), "body was {body}");
}

/// A section the operator got wrong is a REFUSAL, not a default. A plane quietly serving its own
/// defaults over a misconfigured section is the failure mode a typed section exists to prevent.
#[tokio::test]
async fn a_malformed_config_section_is_refused_rather_than_defaulted() {
    let err = DECL
        .handler
        .unwrap()
        .serve(&ctx(r#"{"greetings":"hei"}"#), &get("/example/hello"))
        .await
        .expect_err("a section with no `greeting` must refuse");
    assert_eq!(err.class, "invalid");
}

/// The declared route table is the whole of what this plane claims, and the unauthenticated route
/// is visible IN THAT TABLE — which is the point of declaring the bar rather than implementing it.
#[test]
fn the_declared_routes_carry_their_own_admission_bar() {
    let hello = (DECL.routes)(CFG)
        .into_iter()
        .find(|r| r.path == "/example/hello")
        .expect("hello is declared");
    assert_eq!(hello.auth, PlaneAuth::None);
    let echo = (DECL.routes)(CFG)
        .into_iter()
        .find(|r| r.path == "/example/echo")
        .expect("echo is declared");
    assert_eq!(echo.auth, PlaneAuth::Key);
    // Wholly unary ⇒ this plane could be dlopen'd as well as linked.
    assert!(!DECL.requires_linking(CFG));
}
