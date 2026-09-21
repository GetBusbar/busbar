//! The plane, driven over three byte fixtures this crate authors itself.
//!
//! jev has no public conformance battery the way MCP/A2A do (no third-party suite exists for a
//! provider-scoped decision protocol this workspace does not operate). So these fixtures are
//! authored here, against the shapes `JEV-DESIGN-SIGNED-v4.md` and the ruling describe: a
//! `systemone` success carrying a usage count, a `systemone` 422 whose body echoes the caller's
//! `state` and the provider's `answers` (the PII witness case — see `pii_witness` below and
//! `tests/jev.rs`), and a `models` list. Each is driven through `decode_ingress`/`decode_response`
//! and the operation class + correlation/finish it produces is pinned; the encoder is pinned
//! byte-for-byte against the same fixture, because byte-identity passthrough IS the dialect.

mod common;

use busbar_contract::bounded::FactValue;
use busbar_contract::plane::{Ingress, Plane, Progress, Response};
use busbar_contract::unit::FinishClass;
use busbar_contract::wire::FrameCursor;
use busbar_plane_decision::{facts, ops, DecisionPlane};
use common::{frame, response_frame, Scaffold};

/// `POST /v1/systemone` — a successful decision, billing 42 units.
const SYSTEMONE_SUCCESS: &[u8] =
    br#"{"request_id":"req_1","usage":{"units":42},"answers":{"decision":"approve"}}"#;

/// `POST /v1/systemone` — a 422, echoing the caller's `state` and the provider's `answers`. The
/// PII witness fixture: `tests/jev.rs::pii_witness` drives this and asserts neither value ever
/// reaches a fact this plane emits.
const SYSTEMONE_422: &[u8] = br#"{"error":{"code":"invalid_state","message":"bad transition"},"state":{"session":"caller-secret-state-xyz"},"answers":{"leaked":"should-never-surface"}}"#;

/// `GET /v1/models` — the provider's own catalogue, relayed as-is.
const MODELS_LIST: &[u8] =
    br#"{"request_id":"req_2","data":[{"id":"jev-1.13.0","object":"model"}]}"#;

/// The request body a `systemone` call carries — this plane never reads a pointer off it (see
/// `codec::REQUEST_PTRS`), so its shape only matters for byte-identity forwarding.
const SYSTEMONE_REQUEST: &[u8] = br#"{"state":{"session":"caller-secret-state-xyz"},"context":{}}"#;

#[test]
fn decode_ingress_names_systemone_and_waits_for_its_body() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http")
        .with_method("POST")
        .on_path("/v1/systemone");
    let ctx = scaffold.ctx();
    let frames = vec![frame(SYSTEMONE_REQUEST)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
        panic!("a systemone POST with a body decodes as one shot");
    };
    assert_eq!(draft.op, ops::OP_SYSTEMONE);
    assert_eq!(
        draft.facts.get(facts::FACT_OP),
        Some(FactValue::Str("systemone"))
    );
    // Byte-identity: the whole request body is carried, untouched.
    assert_eq!(draft.body_ir.body(), SYSTEMONE_REQUEST);
}

#[test]
fn decode_ingress_names_models_with_no_body_to_wait_for() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http")
        .with_method("GET")
        .on_path("/v1/models");
    let ctx = scaffold.ctx();
    // No frame at all — a GET carries no body, and `models` must not wait for one.
    let frames: Vec<busbar_contract::wire::Frame> = Vec::new();
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
        panic!("a bodyless GET /v1/models decodes as one shot with no frame read");
    };
    assert_eq!(draft.op, ops::OP_MODELS);
}

#[test]
fn decode_ingress_refuses_an_unclaimed_surface() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http")
        .with_method("POST")
        .on_path("/v1/unknown");
    let ctx = scaffold.ctx();
    let frames = vec![frame(b"{}")];
    let mut cursor = FrameCursor::new(&frames);
    assert!(plane.decode_ingress(&mut cursor, None, &ctx).is_err());
}

#[test]
fn decode_response_reads_success_as_complete_with_usage() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let frames = vec![response_frame(SYSTEMONE_SUCCESS)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Progress::Terminal { r, .. }) =
        plane.decode_response(&mut cursor, &common::sealed_destination(), None, &ctx)
    else {
        panic!("a whole systemone answer decodes as terminal");
    };
    assert_eq!(r.finish, FinishClass::Complete);
    assert_eq!(
        r.facts.get(facts::FACT_HAS_ERROR),
        Some(FactValue::Bool(false))
    );
    assert_eq!(
        r.facts.get(facts::FACT_USAGE_UNITS),
        Some(FactValue::Int(42))
    );
    assert_eq!(r.ir.body(), SYSTEMONE_SUCCESS);
}

#[test]
fn decode_response_reads_422_as_error_with_no_usage() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let frames = vec![response_frame(SYSTEMONE_422)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Progress::Terminal { r, .. }) =
        plane.decode_response(&mut cursor, &common::sealed_destination(), None, &ctx)
    else {
        panic!("a whole 422 answer decodes as terminal");
    };
    assert_eq!(r.finish, FinishClass::Error);
    assert_eq!(
        r.facts.get(facts::FACT_HAS_ERROR),
        Some(FactValue::Bool(true))
    );
    assert_eq!(r.facts.get(facts::FACT_USAGE_UNITS), None);
}

#[test]
fn encode_response_is_byte_identical_to_the_fixture() {
    let plane = DecisionPlane::EMPTY;
    for fixture in [SYSTEMONE_SUCCESS, SYSTEMONE_422, MODELS_LIST] {
        let scaffold = Scaffold::new("http");
        let ctx = scaffold.ctx();
        let r = Response {
            ir: busbar_contract::bounded::Ir::new(fixture, &[]),
            finish: FinishClass::Complete,
            facts: busbar_contract::bounded::Facts::new(),
        };
        let out = plane
            .encode_response(&r, None, &ctx)
            .expect("every fixture re-encodes");
        assert_eq!(
            out.as_slice(),
            fixture,
            "encode_response is not byte-identical"
        );
    }
}
