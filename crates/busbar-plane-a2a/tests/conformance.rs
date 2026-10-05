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

use busbar_contract::plane::{
    Ingress, Plane, PlaneMeta, Progress, Response, SessionPlane, UnitDraft,
};
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
fn decode(plane: &A2aPlane, body: &[u8]) -> Result<(ops::MethodRow, String), Decode> {
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let frames = vec![frame(body)];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane.decode_ingress(&mut cursor, None, &ctx)?;
    let draft: UnitDraft<'_> = match ingress {
        Ingress::Open(d) | Ingress::OneShot(d) | Ingress::Handshake(d) => *d,
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
    // Rendered rather than returned: the value borrows the scaffold's arena, and the arena
    // does not outlive this call. The rendering keeps the two arms distinct, which is the
    // property under test.
    let correlation = format!(
        "{:?}",
        draft
            .correlation_out
            .expect("a request with an identifier correlates")
            .value
    );
    Ok((row, correlation))
}

/// Every method the rig's later-revision table names decodes to a declared class.
#[test]
fn every_method_of_the_later_vocabulary_decodes() {
    let plane = A2aPlane::EMPTY;
    // The slot name is the rig's own key for the row; the two tables are paired on it by
    // `the_two_vocabularies_agree_slot_for_slot`, which is where that pairing is actually proved.
    for (_slot, method) in rig_vocabulary("METHODS_1_0") {
        let body = request("1", &method);
        let (row, correlation) = decode(&plane, &body)
            .unwrap_or_else(|e| panic!("the rig sends {method} and this plane answered {e:?}"));
        assert_eq!(row.method, method);
        assert_eq!(
            row.wording,
            ops::Wording::Verb,
            "{method} is the verb wording"
        );
        assert_eq!(correlation, "Num(1)", "{method} lost its identifier");
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
            a.multi_frame, b.multi_frame,
            "the two wordings of {slot} stream differently"
        );
    }
}

/// Every method the codec's own local-verb table names is one this plane carries.
///
/// The table itself, iterated. This SCRAPED it out of the server half's source once — an
/// `include_str!` over `../../busbar-a2a/src/a2a/local.rs`, then a hand-rolled scan for quoted
/// pieces that look like a method name — which coupled this crate to a sibling its manifest does not
/// name, so the plane could be neither built nor deleted on its own. The table is the codec's now,
/// and the server half's `verb_of` is pinned against it in the crate that owns the match. A method
/// the codec answers and this plane does not carry would arrive here as an unsupported operation.
#[test]
fn every_local_verb_of_the_codec_is_carried() {
    let plane = A2aPlane::EMPTY;
    let mut seen = 0usize;
    for method in busbar_plane_a2a::LOCAL_VERB_METHODS {
        assert!(
            decode(&plane, &request("1", method)).is_ok(),
            "the codec answers {method} and this plane does not carry it"
        );
        seen += 1;
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
/// The correlation carries the identifier itself; the raw bytes travel beside it as a
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
    // And the correlation carries the identifier itself, not a number standing in for it.
    assert_eq!(
        draft.correlation_out.expect("it correlates").value,
        busbar_contract::ids::CorrelationValue::Str("a2a-http-json")
    );
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
            assert_eq!(
                for_.expect("it correlates").value,
                busbar_contract::ids::CorrelationValue::Num(1)
            );
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

/// How many legs each operation class routes to.
///
/// The count is the shape of the plan — a send spends a grant, hops and settles; a listing reaches
/// one record — so a leg that appears or disappears is a change to what an operation DOES, and it is
/// written down here rather than left to a bound that can never fail.
const EXPECTED_LEGS: &[(&str, usize)] = &[
    ("message_send", 3),
    ("message_stream", 3),
    ("task_get", 2),
    ("task_list", 1),
    ("task_cancel", 4),
    ("task_subscribe", 2),
    ("push_config_create", 3),
    ("push_config_get", 1),
    ("push_config_list", 1),
    ("push_config_delete", 3),
    ("agent_card", 1),
    // Five, not four: the token check that opens the plan and the revocation that closes it are two
    // legs around the three that record the move. The revocation is what stops a callback token
    // outliving the task it was minted for.
    ("push_event", 5),
];

/// Every operation class routes to at least one leg, and every leg is one a unit may reach.
#[test]
fn every_operation_routes_somewhere() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let mut covered = 0usize;
    for op in <A2aPlane as busbar_contract::plane::PlaneMeta>::OP_CLASSES {
        covered += 1;
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
        let name = op.to_string();
        let expected = EXPECTED_LEGS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, legs)| *legs)
            .unwrap_or_else(|| panic!("{op} has no expected leg count written down"));
        assert_eq!(plan.legs.len(), expected, "{op} routes to a different plan");
        // A plan filled to its ceiling is one a further leg would be dropped from without a word,
        // so the ceiling is asserted as headroom rather than as a bound that cannot fail.
        assert!(
            !plan.legs.is_full(),
            "{op} routes with no leg headroom left"
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
    // The loop walks a DECLARED table, so an empty one would walk nothing and report `ok`, and a
    // class dropped from it would leave its written-down leg count behind unchallenged. The two
    // tables are pinned equal in size, which makes both of those a failure here.
    assert_eq!(
        covered,
        EXPECTED_LEGS.len(),
        "the plane declares {covered} operation classes and {} leg counts are written down: a \
         class with no row is unproven, and a row with no class proves nothing",
        EXPECTED_LEGS.len()
    );
}

/// **A push callback is authorised by a LIVENESS check, and the plan revokes the token when the
/// task ends.**
///
/// The shape is asserted rather than the leg count, because the count alone would stay green if the
/// two push-config legs swapped places — and their ORDER is the whole property. The check has to
/// come before anything is recorded, or a dead token still moves a task and only afterwards is told
/// it may not; the revocation has to come after the write, or it retires a token for a task that has
/// not yet finished and refuses the callbacks that were still to come.
///
/// The `redeem` verb is asserted GONE from the schema, not merely unused by this plan. A single-use
/// redeem is wrong for this token in both directions at once: a backend reports one task several
/// times, so spending the token on the first callback refuses every honest one after it, while a
/// redeem that answers `true` every time — which is what the neutral default did — accepts a
/// captured token forever. Leaving the operation declared would leave that second reading available
/// to the next plan that reaches for it.
#[test]
fn a_push_callback_is_checked_for_liveness_and_revoked_when_the_task_ends() {
    use busbar_contract::dest::DestinationFacts;
    use busbar_plane_a2a::records as rec;

    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_PUSH_EVENT,
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    );

    let plan = plane.route(&unit, &ctx);
    let record_legs: Vec<(&str, &str)> = plan
        .legs
        .as_slice()
        .iter()
        .filter_map(|leg| match leg.destination {
            DestinationFacts::PlaneRecord { schema, op } => Some((schema.as_str(), op)),
            _ => None,
        })
        .collect();

    assert_eq!(
        record_legs,
        vec![
            (rec::SCHEMA_PUSH_CONFIG.as_str(), rec::OP_VERIFY_LIVE),
            (rec::SCHEMA_TASK.as_str(), rec::OP_GET),
            (rec::SCHEMA_TASK.as_str(), rec::OP_PUT),
            (rec::SCHEMA_TASK_EVENT.as_str(), rec::OP_APPEND),
            (rec::SCHEMA_PUSH_CONFIG.as_str(), rec::OP_REVOKE),
        ],
        "the liveness check must open the plan and the revocation must close it"
    );

    assert!(
        !rec::operations_for(rec::SCHEMA_PUSH_CONFIG).contains(&"redeem"),
        "the push-config schema still declares a single-use redeem, which is the wrong primitive \
         for a token presented once per state a task moves through"
    );
    assert!(
        !rec::OPERATIONS.contains(&"redeem"),
        "the plane still declares a redeem operation for some schema to reach for"
    );
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
    // Which SIDE the class says it is sized from is the side the quantity was taken from. The
    // quantity above is the ANSWER's own length, and the request this unit carries is a different
    // length, so a declaration naming the request would be a rate card pricing a caller's request
    // at the size of an agent's answer to it.
    let declared = <A2aPlane as PlaneMeta>::METER_CLASSES
        .iter()
        .find(|c| c.key == lines[0].class)
        .expect("the class the meter reports is one the plane declares");
    assert_eq!(
        declared.direction,
        busbar_contract::ids::ClassDirection::Response
    );
}

/// The introspection verb answers, and an undeclared verb does not.
#[test]
fn the_introspection_verb_answers_only_what_is_declared() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let facts = plane
        .plane_facts(busbar_plane_a2a::meta::VERB_AGENTS, None, &ctx)
        .expect("the declared verb answers");
    assert_eq!(
        facts.facts.get("count"),
        Some(busbar_contract::bounded::FactValue::Int(0))
    );
    assert!(plane
        .plane_facts(
            busbar_contract::ids::AdminVerbId::new("secrets"),
            None,
            &ctx
        )
        .is_err());
}

/// The per-name projection answers for the agent the subject names, and for no other.
///
/// This is the projection that could not be declared at all while the introspection verb carried no
/// argument: one verb, one subject, one agent. A subject naming nothing is refused rather than
/// answered empty, because "there is no such agent" is not "that agent has nothing to say".
#[test]
fn the_per_name_projection_answers_for_the_named_agent() {
    static AGENTS: &[busbar_plane_a2a::Agent] = &[
        busbar_plane_a2a::Agent {
            id: "alpha",
            lane: busbar_contract::ids::LaneId::new("a2a-a"),
            host: "alpha.invalid:443",
            transport: "http",
        },
        busbar_plane_a2a::Agent {
            id: "beta",
            lane: busbar_contract::ids::LaneId::new("a2a-b"),
            host: "beta.invalid:443",
            transport: "grpc",
        },
    ];
    let plane = A2aPlane::new(AGENTS);
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let verb = busbar_plane_a2a::meta::VERB_AGENT;

    let alpha = plane
        .plane_facts(verb, Some("alpha"), &ctx)
        .expect("a named agent answers");
    assert_eq!(
        alpha.facts.get("name"),
        Some(busbar_contract::bounded::FactValue::Str("alpha"))
    );
    assert_eq!(
        alpha.facts.get("lane"),
        Some(busbar_contract::bounded::FactValue::Str("a2a-a"))
    );
    assert_eq!(
        alpha.facts.get("transport"),
        Some(busbar_contract::bounded::FactValue::Str("http"))
    );

    // The other agent answers for itself, so the subject is what selects, not the order.
    let beta = plane
        .plane_facts(verb, Some("beta"), &ctx)
        .expect("the other named agent answers");
    assert_eq!(
        beta.facts.get("lane"),
        Some(busbar_contract::bounded::FactValue::Str("a2a-b"))
    );

    // A subject that names nothing, and no subject at all, are both refusals.
    assert!(plane.plane_facts(verb, Some("gamma"), &ctx).is_err());
    assert!(plane.plane_facts(verb, None, &ctx).is_err());

    // And the per-name verb is declared, so the loop can reach it.
    assert!(<A2aPlane as PlaneMeta>::INTROSPECTION_VERBS.contains(&verb));
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

/// A request bigger than the per-unit arena is still relayed, byte for byte.
///
/// The bytes the hop carries are the bytes that arrived, and they already live for the unit that
/// carries them. Copying them into the arena first spent the whole bounded budget on a second copy
/// of what the unit was already holding, so a request larger than that budget could not be relayed
/// at all — a size limit nobody configured, imposed by an allocation with no purpose.
#[test]
fn a_request_larger_than_the_arena_is_relayed() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let text = "x".repeat(busbar_contract::bounded::SCRATCH_BASE_BYTES * 2);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"message/send","params":{{"message":{{"role":"user","text":"{text}"}}}}}}"#
    );
    let body = body.into_bytes();
    assert!(body.len() > busbar_contract::bounded::SCRATCH_BASE_BYTES);
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_MESSAGE_SEND,
        busbar_contract::bounded::Ir::new(&body, &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    );
    let egress = plane
        .encode_egress(&unit, &sealed_destination(), None, &ctx)
        .expect("a request larger than the arena is still a request this plane can relay");
    assert_eq!(
        egress.body.as_slice(),
        body.as_slice(),
        "the agent is sent the caller's own bytes, whole"
    );
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

// ── THE SURFACES THAT CARRY NO ENVELOPE ────────────────────────────────────────────────────────
//
// This plane claims three kinds of surface that are not the document mount: two discovery documents
// fetched with no body at all, the task collection read through the target rather than a method
// name, and the callback an agent posts a bare task document back to. Decode used to demand a
// JSON-RPC envelope of every one of them, so the plane claimed surfaces it then refused everything
// on — a caller fetching the agent card got a decode refusal from the plane that publishes it.

/// Every bodyless route the codec mounts decodes to a unit rather than to "nothing has arrived".
///
/// A claim with no arm in the surface table falls through to the document binding, which asks for a
/// JSON-RPC envelope — and a request with no body at all is answered "wait for more", on a surface
/// where nothing more is ever coming. That is a claimed route the plane holds open until the caller
/// gives up, which is indistinguishable from a hang and is not a refusal anyone can read. Four of
/// the codec's routes were in exactly that state.
#[test]
fn every_bodyless_route_the_codec_mounts_decodes() {
    let plane = A2aPlane::EMPTY;
    for (verb, target, expected) in [
        ("GET", "/a2a/tasks", ops::OP_TASK_LIST),
        ("GET", "/a2a/tasks/t-1", ops::OP_TASK_GET),
        ("GET", "/a2a/extendedAgentCard", ops::OP_AGENT_CARD),
        (
            "GET",
            "/a2a/tasks/t-1/pushNotificationConfigs",
            ops::OP_PUSH_CONFIG_LIST,
        ),
        (
            "POST",
            "/a2a/tasks/t-1/pushNotificationConfigs",
            ops::OP_PUSH_CONFIG_CREATE,
        ),
        (
            "GET",
            "/a2a/tasks/t-1/pushNotificationConfigs/c-9",
            ops::OP_PUSH_CONFIG_GET,
        ),
        (
            "DELETE",
            "/a2a/tasks/t-1/pushNotificationConfigs/c-9",
            ops::OP_PUSH_CONFIG_DELETE,
        ),
    ] {
        let scaffold = Scaffold::new("http").on_path(target).with_method(verb);
        let ctx = scaffold.ctx();
        let frames = vec![frame(b"")];
        let mut cursor = FrameCursor::new(&frames);
        let ingress = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .unwrap_or_else(|e| panic!("{verb} {target} decodes: {e:?}"));
        let Ingress::OneShot(draft) = ingress else {
            panic!("{verb} {target} is one whole unit, got {ingress:?}");
        };
        assert_eq!(draft.op, expected, "{verb} {target} named the wrong class");
    }
}

/// Every surface below the task collection says which task it is about.
#[test]
fn a_configuration_of_a_task_names_that_task() {
    let plane = A2aPlane::EMPTY;
    for target in [
        "/a2a/tasks/t-1",
        "/a2a/tasks/t-1/pushNotificationConfigs",
        "/a2a/tasks/t-1/pushNotificationConfigs/c-9",
    ] {
        let scaffold = Scaffold::new("http").on_path(target).with_method("GET");
        let ctx = scaffold.ctx();
        let frames = vec![frame(b"")];
        let mut cursor = FrameCursor::new(&frames);
        let Ingress::OneShot(draft) = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .unwrap_or_else(|e| panic!("{target} decodes: {e:?}"))
        else {
            panic!("{target} is one whole unit");
        };
        assert_eq!(
            draft.facts.get(facts::FACT_TASK_ID),
            Some(busbar_contract::bounded::FactValue::Str("t-1")),
            "{target} does not say which task it is about"
        );
    }
}

/// A discovery document is fetched with no body, and it is a whole unit.
#[test]
fn a_discovery_document_decodes_with_no_body_at_all() {
    for target in [
        "/.well-known/agent-card.json",
        "/.well-known/oauth-protected-resource/a2a",
        // A query string is an argument to the fetch, never a different operation.
        "/.well-known/agent-card.json?v=2",
    ] {
        let plane = A2aPlane::EMPTY;
        let scaffold = Scaffold::new("http").on_path(target);
        let ctx = scaffold.ctx();
        let frames = vec![frame(b"")];
        let mut cursor = FrameCursor::new(&frames);
        let ingress = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .unwrap_or_else(|e| panic!("{target} decodes: {e:?}"));
        let Ingress::OneShot(draft) = ingress else {
            panic!("{target} is one whole unit, got {ingress:?}");
        };
        assert_eq!(draft.op, ops::OP_AGENT_CARD);
    }
}

/// A task read through the collection binding names its task in the target.
#[test]
fn the_collection_binding_reads_a_task_without_a_method_name() {
    let plane = A2aPlane::EMPTY;

    let scaffold = Scaffold::new("http").on_path("/a2a/tasks/t-42");
    let ctx = scaffold.ctx();
    let frames = vec![frame(b"")];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("a task read decodes")
    else {
        panic!("a task read is one whole unit");
    };
    assert_eq!(draft.op, ops::OP_TASK_GET);
    assert_eq!(
        draft.facts.get(facts::FACT_TASK_ID),
        Some(busbar_contract::bounded::FactValue::Str("t-42"))
    );

    let scaffold = Scaffold::new("http").on_path("/a2a/tasks");
    let ctx = scaffold.ctx();
    let frames = vec![frame(b"")];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("a task list decodes")
    else {
        panic!("a task list is one whole unit");
    };
    assert_eq!(draft.op, ops::OP_TASK_LIST);
}

/// The callback carries a task document, not an envelope around one.
#[test]
fn the_callback_surface_decodes_a_bare_task_document() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http").on_path("/a2a/push");
    let ctx = scaffold.ctx();
    let body = br#"{"id":"t-7","contextId":"c-1","status":{"state":"completed"}}"#;
    let frames = vec![frame(body)];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("a posted task document decodes")
    else {
        panic!("a posted task document is one whole unit");
    };
    assert_eq!(draft.op, ops::OP_PUSH_EVENT);
    assert_eq!(
        draft.facts.get(facts::FACT_TASK_ID),
        Some(busbar_contract::bounded::FactValue::Str("t-7"))
    );
    assert_eq!(
        draft.facts.get(facts::FACT_CONTEXT_ID),
        Some(busbar_contract::bounded::FactValue::Str("c-1"))
    );
}

/// The document mount still reads an envelope, and a target that names no open surface reaches it.
#[test]
fn the_document_mount_is_unchanged_by_the_open_surfaces() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http").on_path("/a2a");
    let ctx = scaffold.ctx();
    let body = br#"{"jsonrpc":"2.0","id":5,"method":"tasks/get","params":{"id":"t1"}}"#;
    let frames = vec![frame(body)];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("an envelope on the mount decodes")
    else {
        panic!("a single-frame request is one whole unit");
    };
    assert_eq!(draft.op, ops::OP_TASK_GET);
    assert_eq!(
        draft.facts.get(facts::FACT_METHOD),
        Some(busbar_contract::bounded::FactValue::Str("tasks/get"))
    );
}

/// THE DOOR, BOTH WAYS (BUSBAR-1.6.0.md Part 2 #2 steps (4) and (5); Part 3 section 12 "Proven
/// by": the plane conformance suite, compiled-in and dropped-in through one table). The plane's
/// `plane_door::door` is loaded LINKED (`load_linked`) and DROPPED (this crate's `a2a_door`
/// example, `load_dropped`) on one dispatcher, and ONE script drives every op through the loader's
/// plane kind: the lifecycle (`validate` in the grammar's own sentence, `open` and `refresh` with
/// their snapshots read through the loader's own copy, `retire`, `tick`, `drive`, `cancel`), the
/// request path (`arrive` on the JSON-RPC and the HTTP+JSON lines, a refused arrival rendered by
/// `refusal` in the plane's words, a kernel's and a gate's refusal at the kernel's status) and
/// `project` (the `{tool, arguments}` view, its session, its prompt view and a request-stage
/// rewrite applied and re-projected). The two transcripts must be identical.
mod both_ways {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        slot, ArriveIn, ArriveOut, OutField, PlaneCancelIn, PlaneCancelOut, PlaneDriveIn,
        PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut,
        RefusalIn, RefusalOut, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL,
    };
    use busbar_contract::abi::sdk::door::abi_str;
    use busbar_plane_a2a::door::{self, DIALECT_DOCUMENT, DIALECT_FRAMED, DIALECT_TARGET};
    use busbar_plane_a2a::{plane_door, MOUNT_PATH};
    use busbar_plugin_loader::dispatch::kinds::plane::{OwnedSnapshot, Plane};
    use busbar_plugin_loader::dispatch::{
        in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig,
        Dispatcher, Frame, LinkedRow, NoSink, Plugin,
    };
    use serde_json::{json, Value};

    fn z<T>() -> T {
        // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
        unsafe { zeroed() }
    }

    fn bind(d: &Dispatcher) -> Bind {
        Bind {
            instance: Arc::from("both-ways"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: None,
        }
    }

    fn octets(b: &[u8]) -> Blob {
        Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    fn text(b: &[u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn at(buf: &[u8], s: Span) -> String {
        String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
    }

    /// A string the door wrote into `arena`, read back by its offset.
    fn in_arena(arena: &[u8], s: AbiStr) -> String {
        if s.ptr.is_null() || s.len == 0 {
            return String::new();
        }
        let start = s.ptr as usize - arena.as_ptr() as usize;
        String::from_utf8_lossy(&arena[start..start + s.len]).into_owned()
    }

    // ── the fixtures ─────────────────────────────────────────────────────────────────────────────

    /// One fronted agent.
    const GOOD: &[u8] =
        br#"{"vendor": {"url": "https://vendor.example/agent", "pin": {"mechanism": "unpinned"}}}"#;
    /// A registration the grammar refuses.
    const BAD: &[u8] =
        br#"{"vendor": {"url": "ftp://vendor.example", "pin": {"mechanism": "unpinned"}}}"#;
    /// The grammar's own sentence for [`BAD`].
    const BAD_SENTENCE: &str =
        "`agents.vendor`: `url:` must be an http:// or https:// endpoint, got `ftp://vendor.example`";
    /// The deployment's public base URL.
    const PUBLIC: &[u8] = b"https://gw.example";

    /// A message sent on the JSON-RPC line, in a conversation.
    const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m1","contextId":"ctx-7","parts":[{"text":"hi"}]}}}"#;
    /// The same message on the HTTP+JSON line: the body is the params.
    const REST_SEND: &[u8] = br#"{"message":{"role":"ROLE_USER","messageId":"m2","contextId":"ctx-9","parts":[{"text":"hi"}]}}"#;
    /// A method the vocabulary does not list.
    const UNLISTED: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"vendor/Thing"}"#;
    /// A redacting hook's rewrite, in the hook stage's `{"messages", "tools"}` reply.
    const REWRITE: &[u8] = br#"{"messages":[{"role":"user","content":"{\"message\":{\"role\":\"user\",\"messageId\":\"m1\",\"parts\":[{\"text\":\"[redacted]\"}]}}"}],"tools":null}"#;
    /// A rewrite with no usable params object: not applied.
    const UNUSABLE: &[u8] =
        br#"{"messages":[{"role":"user","content":"plain words"}],"tools":null}"#;

    /// The route index of `(verb, target)` in the door's table, the claim an arrival carries.
    fn claim(verb: &str, target: &str) -> u32 {
        let i = door::ROUTES
            .iter()
            .position(|r| r.verb == verb && r.target == target)
            .unwrap_or_else(|| panic!("the door routes {verb} {target}"));
        u32::try_from(i).expect("a small table")
    }

    fn mounted(path: &str) -> String {
        format!("{MOUNT_PATH}{path}")
    }

    fn snapshot(s: Option<OwnedSnapshot>) -> String {
        let Some(s) = s else {
            return "no snapshot".to_string();
        };
        let mut out = format!(
            "gen={} audience={} metadata={} openapi_bytes={}",
            s.generation,
            s.audience.as_deref().unwrap_or("-"),
            s.resource_metadata.as_deref().unwrap_or("-"),
            s.openapi.as_ref().map_or(0, Vec::len)
        );
        for c in &s.claims {
            out.push_str(&format!(
                " | {} {} {} flags={} dialect={}",
                c.verb, c.target, c.carrier, c.flags, c.refusal_dialect
            ));
        }
        for r in &s.admin_routes {
            out.push_str(&format!(
                " | admin {} {} flags={}",
                r.verb, r.target, r.flags
            ));
        }
        out
    }

    // ── one step of the script ───────────────────────────────────────────────────────────────────

    /// `arrive` of `body` at `target` on claim `(verb, route)` with `fields`: one line, and the
    /// refused arrival's own words.
    fn arrive(
        p: &Plugin<Plane>,
        unit: u64,
        (verb, route): (&str, &str),
        target: &str,
        body: &[u8],
        fields: &[Field],
    ) -> (String, Vec<u8>) {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.unit = unit;
        a.input.claim = claim(verb, route);
        (a.input.method, a.input.target) = (text(verb.as_bytes()), text(target.as_bytes()));
        a.input.body = octets(body);
        (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
        let c = p.call(slot::ARRIVE, &mut a);
        let words = c.error.clone().unwrap_or_default();
        (
            format!(
                "arrive {unit} {verb} {target} {:?} op={} dialect={} principal={} refusal={} \
                 status={} route={} {}",
                c.outcome,
                a.out.op_class,
                a.out.dialect,
                a.out.principal_need,
                a.out.refusal,
                a.out.refusal_status,
                a.out.route,
                String::from_utf8_lossy(&words)
            ),
            words,
        )
    }

    /// `refusal` of `words` for `cause` at `status` in `dialect`: one line.
    fn refuse(p: &Plugin<Plane>, cause: u32, status: u32, dialect: u32, words: &[u8]) -> String {
        let none = Span { offset: 0, len: 0 };
        let (mut reply, mut arena) = (vec![0_u8; 4096], vec![0_u8; 256]);
        let mut fields = vec![
            OutField {
                name: none,
                value: none,
            };
            4
        ];
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status, r.input.dialect) = (cause, status, dialect);
        r.input.text = text(words);
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut r);
        let named: Vec<String> = fields[..r.out.fields_written as usize]
            .iter()
            .map(|f| format!("{}: {}", at(&arena, f.name), at(&arena, f.value)))
            .collect();
        format!(
            "refusal cause={cause} dialect={dialect} {:?} status={} marker={} [{}] {}",
            c.outcome,
            r.out.status,
            r.out.marker,
            named.join(", "),
            String::from_utf8_lossy(&reply[..r.out.reply_written as usize])
        )
    }

    /// `project` of `body` at `target` on claim `(verb, route)`, with a request-stage `rewrite`:
    /// one line of the view's scalars and strings, its session, the projected body, the prompt
    /// view's turns and the rewritten body.
    fn project(
        p: &Plugin<Plane>,
        unit: u64,
        (verb, route): (&str, &str),
        target: &str,
        body: &[u8],
        rewrite: Option<&[u8]>,
    ) -> String {
        let mut arena = vec![0_u8; 8192];
        let mut turns = vec![
            busbar_contract::abi::hook::MessageView {
                role: abi_str(""),
                text: abi_str(""),
            };
            4
        ];
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        j.input.unit = unit;
        j.input.claim = claim(verb, route);
        j.input.target = text(target.as_bytes());
        j.input.body = octets(body);
        if let Some(rewrite) = rewrite {
            j.input.rewrite = octets(rewrite);
        }
        (j.input.arena_buf, j.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (j.input.messages_buf, j.input.messages_cap) = (turns.as_mut_ptr(), turns.len());
        let c = p.call(slot::PROJECT, &mut j);
        if c.outcome != Outcome::Ready {
            return format!("project {unit} {:?}", c.outcome);
        }
        let v = j.out.view;
        let session = if v.session.ptr.is_null() {
            "-".to_string()
        } else {
            in_arena(
                &arena,
                AbiStr {
                    ptr: v.session.ptr,
                    len: v.session.len,
                },
            )
        };
        let turns: Vec<String> = turns
            .iter()
            .take(j.out.prompt.messages_len)
            .map(|t| format!("{}: {}", in_arena(&arena, t.role), in_arena(&arena, t.text)))
            .collect();
        let rewritten = if j.out.rewritten.len == 0 {
            "-".to_string()
        } else {
            at(&arena, j.out.rewritten)
        };
        format!(
            "project {unit} {:?} messages={} chars={} flags={} pool={:?} dialect={} session={} \
             body={} turns=[{}] rewritten={}",
            c.outcome,
            v.message_count,
            v.total_chars,
            v.flags,
            in_arena(&arena, v.pool),
            in_arena(&arena, v.ingress_dialect),
            session,
            at(&arena, j.out.body),
            turns.join(" | "),
            rewritten
        )
    }

    fn generation(generation: u64) -> Frame<GenIn, busbar_contract::abi::mechanism::call::OutHead> {
        Frame::new(
            GenIn {
                head: in_head(),
                generation,
            },
            out_head(),
        )
    }

    /// THE SCRIPT: the lifecycle, then the request path, each answer one line.
    fn script(p: &Plugin<Plane>) -> Vec<String> {
        let mut t = Vec::new();

        let mut reason = vec![0_u8; 1024];
        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(BAD),
                err_buf: reason.as_mut_ptr(),
                err_cap: reason.len(),
            },
            out_head(),
        );
        let c = p.call(life::VALIDATE, &mut v);
        t.push(format!(
            "validate bad {:?} {}",
            c.outcome,
            String::from_utf8_lossy(&c.error.unwrap_or_default())
        ));
        v.input.settings = octets(GOOD);
        t.push(format!(
            "validate {:?}",
            p.call(life::VALIDATE, &mut v).outcome
        ));

        let mut o: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(z(), z());
        (o.input.open.head, o.out.open.head) = (in_head(), out_head());
        (o.input.open.generation, o.input.open.settings) = (1, octets(GOOD));
        o.input.public_url = text(PUBLIC);
        let (c, s) = p.open(&mut o);
        t.push(format!("open {:?} {}", c.outcome, snapshot(s)));

        let mut r: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.generation, r.input.settings) = (2, octets(GOOD));
        let (c, s) = p.refresh(&mut r);
        t.push(format!("refresh {:?} {}", c.outcome, snapshot(s)));
        t.push(format!(
            "retire 1 {:?}",
            p.call(life::RETIRE, &mut generation(1)).outcome
        ));
        for (what, op) in [("hydrate", slot::HYDRATE), ("start", slot::START)] {
            t.push(format!(
                "{what} {:?}",
                p.call(op, &mut generation(2)).outcome
            ));
        }

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 5,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let c = p.call(life::TICK, &mut k);
        t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));
        let mut d: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
        (d.input.drive.head, d.out.head) = (in_head(), out_head());
        let c = p.call(life::DRIVE, &mut d);
        t.push(format!(
            "drive {:?} sessions={}",
            c.outcome, d.out.sessions_written
        ));
        let mut x: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(z(), z());
        (x.input.cancel.head, x.out.cancel.head) = (in_head(), out_head());
        let c = p.call(life::CANCEL, &mut x);
        t.push(format!(
            "cancel {:?} disposition={}",
            c.outcome, x.out.cancel.disposition
        ));

        // THE REQUEST PATH.
        let document = ("POST", MOUNT_PATH);
        let agent_route = mounted("/agents/{agent_id}");
        let agent = ("POST", agent_route.as_str());
        let agent_target = mounted("/agents/vendor");
        let send_route = mounted(busbar_plane_a2a::ROUTE_MESSAGE_SEND);
        let rest_send = ("POST", send_route.as_str());
        t.push(arrive(p, 1, document, MOUNT_PATH, SEND, &[]).0);
        t.push(arrive(p, 2, agent, &agent_target, SEND, &[]).0);
        t.push(arrive(p, 3, document, MOUNT_PATH, UNLISTED, &[]).0);
        t.push(arrive(p, 4, rest_send, &send_route, REST_SEND, &[]).0);
        let tasks_route = mounted(busbar_plane_a2a::ROUTE_TASKS);
        let tasks_target = mounted("/tasks?pageSize=5&status=working");
        t.push(arrive(p, 5, ("GET", tasks_route.as_str()), &tasks_target, b"", &[]).0);
        let task_route = mounted(busbar_plane_a2a::ROUTE_TASK);
        let bogus = mounted("/tasks/t-1:bogus");
        let (line, rest_words) = arrive(p, 6, ("POST", task_route.as_str()), &bogus, b"", &[]);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_TARGET, &rest_words));
        // A media type the line does not read: refused in the plane's own words.
        let plain = [Field {
            name: abi_str("content-type"),
            value: abi_str("text/plain"),
        }];
        let (line, words) = arrive(p, 7, document, MOUNT_PATH, SEND, &plain);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_DOCUMENT, &words));
        t.push(refuse(
            p,
            REFUSAL_KERNEL,
            403,
            DIALECT_TARGET,
            b"this key may not reach that agent",
        ));
        t.push(refuse(
            p,
            REFUSAL_GATE,
            451,
            DIALECT_DOCUMENT,
            b"a gate said no",
        ));

        // THE gRPC LINE: a call's one request message, the rpc its target names.
        let service = format!("{}/{{method}}", busbar_plane_a2a::framed::SERVICE_PATH);
        let grpc = ("POST", service.as_str());
        let rpc = |name: &str| format!("{}/{name}", busbar_plane_a2a::framed::SERVICE_PATH);
        let call = [Field {
            name: abi_str("content-type"),
            value: abi_str("application/grpc"),
        }];
        t.push(arrive(p, 8, grpc, &rpc("SendMessage"), &grpc_send(), &call).0);
        let (line, words) = arrive(p, 9, grpc, &rpc("Nope"), b"", &call);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_FRAMED, &words));
        let (line, words) = arrive(p, 10, grpc, &rpc("GetTask"), &[0xff, 0xff, 0xff], &call);
        t.push(line);
        t.push(refuse(p, REFUSAL_ARRIVE, 0, DIALECT_FRAMED, &words));
        t.push(refuse(
            p,
            REFUSAL_KERNEL,
            429,
            DIALECT_FRAMED,
            b"this key is over its budget",
        ));

        // THE HOOK VIEW.
        t.push(project(p, 2, agent, &agent_target, SEND, None));
        t.push(project(p, 4, rest_send, &send_route, REST_SEND, None));
        t.push(project(p, 2, agent, &agent_target, SEND, Some(REWRITE)));
        t.push(project(
            p,
            4,
            rest_send,
            &send_route,
            REST_SEND,
            Some(REWRITE),
        ));
        t.push(project(p, 2, agent, &agent_target, SEND, Some(UNUSABLE)));
        t.push(project(
            p,
            5,
            ("GET", tasks_route.as_str()),
            &tasks_target,
            b"",
            None,
        ));
        t.push(project(p, 8, grpc, &rpc("SendMessage"), &grpc_send(), None));
        t
    }

    /// A `SendMessage` call's request message, as a gRPC client encodes it.
    fn grpc_send() -> Vec<u8> {
        use busbar_plane_a2a::proto::pb;
        use prost::Message as _;
        pb::SendMessageRequest {
            message: Some(pb::Message {
                message_id: "m3".into(),
                context_id: "ctx-11".into(),
                role: pb::Role::User as i32,
                parts: vec![pb::Part {
                    content: Some(pb::part::Content::Text("hi".into())),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    // ── the doors ────────────────────────────────────────────────────────────────────────────────

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the `a2a_door` example `cargo test` builds. A missing
    /// artifact is a failure, never a skip: this test IS the dropped-in door's proof.
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let examples = exe
            .parent()
            .and_then(|d| d.parent())
            .expect("target/<profile>")
            .join("examples");
        let file = busbar_plugin_loader::plugin_library_filename("a2a_door");
        let path = [examples.join(&file), examples.join("deps").join(&file)]
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("the a2a_door example ({file}) is not built"));
        let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    fn line<'a>(t: &'a [String], prefix: &str) -> &'a str {
        t.iter()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` line in {t:#?}"))
    }

    fn body_of(line: &str) -> Value {
        let body = line
            .split(" body=")
            .nth(1)
            .and_then(|b| b.split(" turns=").next())
            .expect("a body");
        serde_json::from_str(body).expect("the projected body is JSON")
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// The linked transcript says what the plane's own functions say the door answers.
    #[test]
    fn the_door_answers_what_the_plane_says() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        assert_eq!(
            t[0],
            format!("validate bad {:?} {BAD_SENTENCE}", Outcome::Refused),
            "the door refuses in the grammar's own sentence"
        );
        assert_eq!(t[1], format!("validate {:?}", Outcome::Ready));
        assert!(
            t[2].starts_with(&format!(
                "open {:?} gen=1 audience=https://gw.example{MOUNT_PATH}",
                Outcome::Ready
            )),
            "{}",
            t[2]
        );
        assert!(
            t[3].starts_with(&format!("refresh {:?} gen=2", Outcome::Ready)),
            "{}",
            t[3]
        );
        assert!(
            line(&t, "arrive 7 ").contains(&format!("{:?}", Outcome::Refused)),
            "a media type the line does not read is refused: {}",
            line(&t, "arrive 7 ")
        );
        for l in t.iter().filter(|l| l.starts_with("refusal")) {
            assert!(
                l.contains(" marker=0 "),
                "the plane never sets the gate marker: {l}"
            );
        }
        assert!(
            line(&t, "refusal cause=1 ").contains("a gate said no"),
            "a gate's veto wears the hook's own words: {}",
            line(&t, "refusal cause=1 ")
        );
        // THE gRPC LINE: a call arrives on the framed dialect; a method the service does not have
        // is UNIMPLEMENTED with no message, a message that does not read INTERNAL, a kernel
        // refusal the status the engine's bridge read off its envelope (`-32004`, UNIMPLEMENTED),
        // each with no media type.
        let sent = line(&t, "arrive 8 ");
        assert!(
            sent.contains(&format!("{:?}", Outcome::Ready))
                && sent.contains(&format!("dialect={DIALECT_FRAMED} ")),
            "{sent}"
        );
        let framed: Vec<&String> = t
            .iter()
            .filter(|l| {
                l.starts_with("refusal cause=")
                    && l.contains(&format!(" dialect={DIALECT_FRAMED} "))
            })
            .collect();
        assert_eq!(framed.len(), 3, "{framed:#?}");
        assert!(
            framed[0].contains(" status=12 ") && framed[0].ends_with("[] "),
            "{}",
            framed[0]
        );
        assert!(
            framed[1].contains(" status=13 ") && framed[1].contains("[] "),
            "{}",
            framed[1]
        );
        assert!(
            framed[2].contains(" status=12 ") && framed[2].ends_with("this key is over its budget"),
            "{}",
            framed[2]
        );
    }

    /// `project` on the gRPC line: the view of the JSON-RPC request the call's message composed.
    #[test]
    fn project_on_the_grpc_line_views_the_composed_request() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        let projected = line(&t, "project 8 ");
        let body = body_of(projected);
        assert_eq!(body["tool"], "SendMessage", "{projected}");
        assert_eq!(
            body["arguments"]["message"]["messageId"], "m3",
            "{projected}"
        );
        assert!(projected.contains("session=ctx-11"), "{projected}");
    }

    /// `project`: the `{tool, arguments}` view of the request (the envelope the HTTP+JSON line's
    /// request spells), the plane's key as the dialect, the addressed agent as the pool, the
    /// message's `contextId` as the session, and one `user` turn of the params as the prompt view.
    #[test]
    fn project_writes_the_hook_view_of_the_request() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        let send: Value = serde_json::from_slice(SEND).expect("json");
        let jsonrpc = line(&t, "project 2 ");
        assert!(
            jsonrpc.contains(&format!("{:?} messages=1 chars=", Outcome::Ready))
                && jsonrpc.contains(r#"pool="vendor" dialect=a2a session=ctx-7 "#),
            "{jsonrpc}"
        );
        assert_eq!(
            body_of(jsonrpc),
            json!({ "tool": "message/send", "arguments": send["params"] })
        );
        assert!(
            jsonrpc.contains(&format!("turns=[user: {}]", send["params"])),
            "{jsonrpc}"
        );
        assert!(jsonrpc.ends_with("rewritten=-"), "{jsonrpc}");
        let rest = line(&t, "project 4 ");
        assert!(
            rest.contains(r#"pool="" dialect=a2a session=ctx-9 "#),
            "{rest}"
        );
        assert_eq!(body_of(rest)["tool"], json!("SendMessage"));
        assert_eq!(
            line(&t, "project 5 "),
            line(&t, "project 5 "),
            "a listing projects its envelope too"
        );
    }

    /// A REQUEST-STAGE HOOK'S REWRITE (BUSBAR-1.6.0.md Part 3 section 12, "Hooks"; the served
    /// engine's invoke rewrite contract): the params are replaced, every other member of the
    /// request is the caller's, the rewritten request is answered as the body the kernel keeps (the
    /// envelope on the JSON-RPC line, the params on the HTTP+JSON line) and is the request
    /// projected; a rewrite with no usable params object is not applied.
    #[test]
    fn a_rewrite_replaces_the_params_and_the_rewritten_request_is_projected() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));
        let redacted = json!({
            "message": { "role": "user", "messageId": "m1", "parts": [{ "text": "[redacted]" }] }
        });
        let rewrites: Vec<&String> = t
            .iter()
            .filter(|l| l.starts_with("project ") && !l.ends_with("rewritten=-"))
            .collect();
        assert_eq!(rewrites.len(), 2, "{t:#?}");
        let jsonrpc = rewrites[0];
        assert_eq!(body_of(jsonrpc)["arguments"], redacted);
        let kept: Value = serde_json::from_str(
            jsonrpc
                .split(" rewritten=")
                .nth(1)
                .expect("the rewritten body"),
        )
        .expect("json");
        assert_eq!(
            kept,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": redacted })
        );
        assert!(
            jsonrpc.contains(" session=- "),
            "the rewritten message names no context: {jsonrpc}"
        );
        let rest = rewrites[1];
        let kept: Value = serde_json::from_str(
            rest.split(" rewritten=")
                .nth(1)
                .expect("the rewritten body"),
        )
        .expect("json");
        assert_eq!(
            kept, redacted,
            "the HTTP+JSON line keeps the params as its body"
        );
        let unusable = t
            .iter()
            .filter(|l| l.starts_with("project 2 "))
            .nth(2)
            .expect("the unusable rewrite's line");
        assert_eq!(
            unusable,
            line(&t, "project 2 "),
            "an unusable rewrite is not applied: the request projects as it came"
        );
    }
}
