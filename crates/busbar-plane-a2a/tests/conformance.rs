//! The plane, driven over the vocabulary the conformance rigs actually send.
//!
//! ## Why this shape, and what it is not
//!
//! The judges of this work are the rigs: the official suite and the in-house battery, both of which
//! speak to a booted node over a socket. Neither can run here, because the composition root does not
//! yet hand a request to this plane — the existing engine still answers every one of them. So these
//! tests do the next thing that is actually evidence rather than decoration: they take the METHOD
//! VOCABULARY out of the rig's own table and out of the codec's own source, drive each entry through
//! this plane's decode step, and assert the operation class and the correlation it produces.
//!
//! What these tests DO NOT do is drive the existing engine beside this plane and compare. That is
//! written down as a limitation rather than worked around: the existing plane's request entry point
//! is visible to its own crate only, it takes an engine handle and an async runtime, and its request
//! and target types are private. There is no way to call it from here at all. The envelope side is
//! therefore pinned differently — against the serializer and the codec's own error table, byte for
//! byte — and the operation side is pinned against the rig's own vocabulary.

mod common;

use busbar_contract::plane::{Ingress, Plane, Progress, Response, SessionPlane, UnitDraft};
use busbar_contract::wire::{Decode, FrameCursor};
use busbar_plane_a2a::{facts, jsonrpc, ops, A2aPlane};
use common::{frame, response_frame, Scaffold};

/// The rig's own vocabulary table, read out of the file the rig imports it from.
///
/// Reading the rig's source rather than restating it is the whole point: a rig that starts sending a
/// method this plane does not carry must fail HERE, at build time, rather than in a battery run that
/// someone has to interpret.
fn rig_vocabulary(table: &str) -> Vec<(String, String)> {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testing/a2a-supplement/a2asup/transport.py"),
    )
    .expect("the rig's vocabulary table is readable");
    let start = source
        .find(&format!("{table} = {{"))
        .unwrap_or_else(|| panic!("the rig no longer declares {table}"));
    let body = &source[start..];
    let end = body.find('}').expect("the table closes");
    let mut rows = Vec::new();
    for line in body[..end].lines().skip(1) {
        let line = line.trim().trim_end_matches(',');
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let value = value.trim().trim_matches('"');
        if !key.is_empty() && !value.is_empty() {
            rows.push((key.to_string(), value.to_string()));
        }
    }
    assert!(!rows.is_empty(), "the rig's {table} table read as empty");
    rows
}

/// One request envelope of this protocol, with the method and identifier a caller would send.
fn request(id: &str, method: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{}}}}"#).into_bytes()
}

/// Drive one body through the decode step and hand back what the plane made of it.
fn decode(plane: &A2aPlane, body: &[u8]) -> Result<(ops::MethodRow, u64), Decode> {
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let frames = vec![frame(body)];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane.decode_ingress(&mut cursor, None, &ctx)?;
    let draft: UnitDraft<'_> = match ingress {
        Ingress::Open(d) | Ingress::OneShot(d) | Ingress::Handshake(d) => d,
        other => panic!("a well-formed request decoded as {other:?}"),
    };
    // The row is found by the method the plane RECORDED, not by the class: two spellings share one
    // class on purpose, so looking a class up would always answer with the first spelling.
    let method = match draft.facts.get(busbar_plane_a2a::facts::FACT_METHOD) {
        Some(busbar_contract::bounded::FactValue::Str(s)) => s,
        other => panic!("the draft recorded no method: {other:?}"),
    };
    let row = *ops::row_for(method).expect("the recorded method is one the plane carries");
    assert_eq!(row.op, draft.op, "{method} was drafted under another class");
    let correlation = draft
        .correlation_out
        .expect("a request with an identifier correlates")
        .value;
    Ok((row, correlation))
}

/// Every method the rig's later-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_later_vocabulary_decodes() {
    let plane = A2aPlane::EMPTY;
    for (slot, method) in rig_vocabulary("METHODS_1_0") {
        let body = request("1", &method);
        let (row, correlation) = decode(&plane, &body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(
            row.wording,
            ops::Wording::Verb,
            "{method} is the verb wording"
        );
        assert_eq!(correlation, 1, "{method} lost its identifier");
        assert!(!slot.is_empty());
    }
}

/// Every method the rig's earlier-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_earlier_vocabulary_decodes() {
    let plane = A2aPlane::EMPTY;
    for (_, method) in rig_vocabulary("METHODS_0_3") {
        let body = request("1", &method);
        let (row, _) = decode(&plane, &body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(row.wording, ops::Wording::Slashed);
    }
}

/// The two vocabularies agree slot for slot on the class the unit is.
///
/// This is the property that says a caller's choice of wording does not move the money, checked
/// against the rig's OWN pairing of the two tables rather than against this crate's.
#[test]
fn the_two_vocabularies_agree_slot_for_slot() {
    let plane = A2aPlane::EMPTY;
    let later = rig_vocabulary("METHODS_1_0");
    let earlier = rig_vocabulary("METHODS_0_3");
    assert_eq!(
        later.len(),
        earlier.len(),
        "the rig's two tables differ in size"
    );
    for (slot, method) in &later {
        let partner = earlier
            .iter()
            .find(|(k, _)| k == slot)
            .unwrap_or_else(|| panic!("the rig names {slot} in one table only"));
        let (a, _) = decode(&plane, &request("1", method)).expect("the later wording decodes");
        let (b, _) =
            decode(&plane, &request("1", &partner.1)).expect("the earlier wording decodes");
        assert_eq!(
            a.op, b.op,
            "the two wordings of {slot} price differently: {} against {}",
            a.op, b.op
        );
        assert_eq!(
            a.streaming, b.streaming,
            "the two wordings of {slot} stream differently"
        );
    }
}

/// Every method the codec's own local-verb table names is one this plane carries.
///
/// The table is visible to its own crate only, so this reads its source. A method the codec answers
/// and this plane does not carry would arrive here as an unsupported operation.
#[test]
fn every_local_verb_of_the_codec_is_carried() {
    let source = include_str!("../../busbar-a2a/src/a2a/local.rs");
    let start = source
        .find("pub(crate) fn verb_of")
        .expect("the codec still names its verb table");
    let body = &source[start..];
    let end = body.find("\n}").expect("the function closes");
    let plane = A2aPlane::EMPTY;
    let mut seen = 0usize;
    for line in body[..end].lines() {
        for piece in line.split('"').skip(1).step_by(2) {
            if piece.contains('/') || piece.chars().next().is_some_and(char::is_uppercase) {
                assert!(
                    decode(&plane, &request("1", piece)).is_ok(),
                    "the codec answers {piece} and this plane does not carry it"
                );
                seen += 1;
            }
        }
    }
    assert!(
        seen >= 11,
        "only {seen} verbs were read out of the codec's table"
    );
}

/// A streamed method opens a unit; a single-answer method is complete in one frame.
#[test]
fn a_streamed_method_opens_a_unit() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    for (method, streams) in [
        ("message/stream", true),
        ("SendStreamingMessage", true),
        ("tasks/resubscribe", true),
        ("message/send", false),
        ("tasks/get", false),
    ] {
        let body = request("1", method);
        let frames = vec![frame(&body)];
        let mut cursor = FrameCursor::new(&frames);
        let ingress = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .expect("a known method decodes");
        match (ingress, streams) {
            (Ingress::Open(_), true) | (Ingress::OneShot(_), false) => {}
            (other, _) => panic!("{method} decoded as {other:?}"),
        }
    }
}

/// A named identifier survives the round trip, bytes for bytes.
///
/// The correlation carries a number the identifier cannot be; the identifier itself travels as a
/// fact, and this is the assertion that it arrives intact.
#[test]
fn a_named_identifier_survives_the_round_trip() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let body = request(r#""a2a-http-json""#, "message/send");
    let frames = vec![frame(&body)];
    let mut cursor = FrameCursor::new(&frames);
    let Ok(Ingress::OneShot(draft)) = plane.decode_ingress(&mut cursor, None, &ctx) else {
        panic!("a single-answer method decodes as one shot");
    };
    let recorded = match draft.facts.get(facts::FACT_RPC_ID) {
        Some(busbar_contract::bounded::FactValue::Str(s)) => s,
        other => panic!("the identifier was recorded as {other:?}"),
    };
    assert_eq!(recorded, r#""a2a-http-json""#);
    // And the correlation is the digested form, which is above every bare counter.
    assert!(draft.correlation_out.expect("it correlates").value >= 1 << 63);
}

/// An answer that already is an envelope goes back exactly as it arrived.
#[test]
fn an_answer_goes_back_as_it_arrived() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let answer = br#"{"id":1,"jsonrpc":"2.0","result":{"id":"t1","kind":"task"}}"#;
    let r = Response {
        ir: busbar_contract::bounded::Ir::new(answer, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    let out = plane
        .encode_response(&r, None, &ctx)
        .expect("an envelope re-encodes");
    assert_eq!(out.as_slice(), answer);
}

/// An answer this node composed itself is wrapped with the identifier the decode step recorded.
#[test]
fn a_composed_answer_is_wrapped_with_the_callers_identifier() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let mut facts_map = busbar_contract::bounded::Facts::new();
    facts_map
        .set(
            facts::FACT_RPC_ID,
            busbar_contract::bounded::FactValue::Str("7"),
        )
        .expect("one key fits");
    let r = Response {
        ir: busbar_contract::bounded::Ir::new(br#"{"tasks":[]}"#, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: facts_map,
    };
    let out = plane
        .encode_response(&r, None, &ctx)
        .expect("a bare result wraps");
    assert_eq!(
        core::str::from_utf8(out.as_slice()).unwrap(),
        r#"{"id":7,"jsonrpc":"2.0","result":{"tasks":[]}}"#
    );
}

/// A document arriving on an upstream with no identifier opens a unit of the agent's own.
#[test]
fn an_unsolicited_document_opens_a_provider_unit() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let dest = None::<()>;
    let _ = dest;
    let pushed = br#"{"taskId":"t1","status":{"state":"completed"}}"#;
    let frames = vec![response_frame(pushed)];
    let mut cursor = FrameCursor::new(&frames);
    let sealed = sealed_destination();
    let progress = plane
        .decode_response(&mut cursor, &sealed, None, &ctx)
        .expect("a pushed document decodes");
    match progress {
        Progress::OneShot(draft) => assert_eq!(draft.op, ops::OP_PUSH_EVENT),
        other => panic!("a pushed document decoded as {other:?}"),
    }
}

/// An answer carrying an error is terminal and is reported as an error.
#[test]
fn an_error_answer_is_terminal() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let answer = br#"{"error":{"code":-32001,"message":"gone"},"id":1,"jsonrpc":"2.0"}"#;
    let frames = vec![response_frame(answer)];
    let mut cursor = FrameCursor::new(&frames);
    let sealed = sealed_destination();
    match plane
        .decode_response(&mut cursor, &sealed, None, &ctx)
        .expect("an error answer decodes")
    {
        Progress::Terminal { for_, r } => {
            assert_eq!(r.finish, busbar_contract::unit::FinishClass::Error);
            assert_eq!(for_.expect("it correlates").value, 1);
        }
        other => panic!("an error answer decoded as {other:?}"),
    }
}

/// A refusal is rendered as this dialect's own error envelope, with the caller's identifier.
#[test]
fn a_refusal_is_rendered_in_this_dialect() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let mut facts_map = busbar_contract::bounded::Facts::new();
    facts_map
        .set(
            facts::FACT_RPC_ID,
            busbar_contract::bounded::FactValue::Str("3"),
        )
        .expect("one key fits");
    let draft = UnitDraft {
        op: ops::OP_MESSAGE_SEND,
        body_ir: busbar_contract::bounded::Ir::new(b"{}", &[]),
        correlates: None,
        correlation_out: None,
        facts: facts_map,
    };
    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Approve,
        reason: busbar_contract::unit::RefusalReason::ScopeMissing,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let out = plane
        .encode_refusal(&refusal, Some(&draft), None, &ctx)
        .expect("a refusal renders");
    let value: serde_json::Value =
        serde_json::from_slice(out.as_slice()).expect("it is a document");
    assert_eq!(value["id"], 3);
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["error"]["code"], jsonrpc::CODE_UNSUPPORTED_OPERATION);
    // This dialect names a word for that code, so the typed detail entry is present.
    assert_eq!(value["error"]["data"][0]["reason"], "UNSUPPORTED_OPERATION");
}

/// A refusal with no draft still renders, with an empty identifier.
///
/// This is the case where bytes were refused before anything could be read off them, and a caller
/// that gets nothing back learns nothing at all.
#[test]
fn a_refusal_without_a_draft_still_renders() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::BodyTooLarge,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let out = plane
        .encode_refusal(&refusal, None, None, &ctx)
        .expect("a refusal renders");
    let value: serde_json::Value =
        serde_json::from_slice(out.as_slice()).expect("it is a document");
    assert!(value["id"].is_null());
    assert_eq!(value["error"]["code"], jsonrpc::CODE_INVALID_REQUEST);
}

/// Every operation class routes to at least one leg, and every leg is one a unit may reach.
#[test]
fn every_operation_routes_somewhere() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    for op in <A2aPlane as busbar_contract::plane::PlaneMeta>::OP_CLASSES {
        let unit = busbar_contract::unit::Unit::new(
            &seal,
            busbar_contract::UnitKey::new(1),
            busbar_contract::unit::Origin::Client,
            None,
            None,
            busbar_contract::wire::Direction::Inbound,
            Some(common::principal()),
            *op,
            busbar_contract::bounded::Ir::new(b"{}", &[]),
            busbar_contract::bounded::Facts::new(),
            None,
        );
        let plan = plane.route(&unit, &ctx);
        assert!(!plan.legs.is_empty(), "{op} routes nowhere");
        assert!(
            plan.legs.len() <= plan.legs.capacity(),
            "{op} routes past the leg ceiling"
        );
        for leg in plan.legs.as_slice() {
            if let busbar_contract::dest::DestinationFacts::PlaneRecord { schema, op: rop } =
                leg.destination
            {
                assert!(
                    busbar_plane_a2a::records::operations_for(schema).contains(&rop),
                    "{op} reaches {schema} with an operation it does not declare: {rop}"
                );
            }
        }
    }
}

/// The metering step reports the class the plane declares, and a quantity it actually read.
#[test]
fn the_metering_step_reports_what_it_read() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let answer = br#"{"id":1,"jsonrpc":"2.0","result":{}}"#;
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_MESSAGE_SEND,
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    );
    let r = Response {
        ir: busbar_contract::bounded::Ir::new(answer, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    let locators = plane.meter(&unit, &r, &ctx);
    let lines = locators.lines.as_slice();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].class, busbar_plane_a2a::meta::CLASS_BYTES);
    assert_eq!(lines[0].quantity, Some(answer.len() as u64));
    // A plane names no lane and no price.
    assert!(lines[0].lane.is_none());
}

/// The introspection verb answers, and an undeclared verb does not.
#[test]
fn the_introspection_verb_answers_only_what_is_declared() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let facts = plane
        .plane_facts(busbar_plane_a2a::meta::VERB_AGENTS, &ctx)
        .expect("the declared verb answers");
    assert_eq!(
        facts.facts.get("count"),
        Some(busbar_contract::bounded::FactValue::Int(0))
    );
    assert!(plane
        .plane_facts(busbar_contract::ids::AdminVerbId::new("secrets"), &ctx)
        .is_err());
}

/// The session halves open, and each one starts fresh.
#[test]
fn the_session_halves_open_fresh() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let client = plane.open_session(&ctx);
    let upstream = plane.open_upstream(&sealed_destination(), &ctx);
    for half in [&client, &upstream] {
        let codec = half
            .get::<busbar_plane_a2a::plane::Codec>()
            .expect("the half carries this plane's own state");
        assert_eq!(codec.events_read, 0);
    }
}

/// A sealed destination, for the calls that take one.
fn sealed_destination() -> busbar_contract::dest::VerifiedDestination {
    let seal = common::TestSeal;
    busbar_contract::dest::VerifiedDestination::seal(
        &seal,
        busbar_contract::dest::DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("agent.example"),
            lane: busbar_contract::ids::LaneId::new("standard"),
        },
        "http",
        None,
    )
}
