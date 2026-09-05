//! The plane, driven over the bytes the conformance battery actually sends.
//!
//! ## Why this shape, and what it is not
//!
//! The judge of this work is the battery: the official suite and the in-house adversarial battery,
//! both of which speak to a booted node over a socket. Neither can run here, because the composition
//! root does not yet hand a request to this plane — the existing engine still answers every one of
//! them. So these tests do the next thing that is actually evidence rather than decoration: they
//! build requests the way the battery's own request builder builds them, drive each through this
//! plane's decode step, and assert the operation class and the correlation it produces. The
//! vocabulary is read out of the battery's own suites and out of the codec's own source, so a
//! battery that starts sending something new fails HERE rather than in a run someone has to
//! interpret.
//!
//! What these tests DO NOT do is drive the existing engine beside this plane and compare. That is
//! written down as a limitation rather than worked around: the existing plane's request entry point
//! is visible to its own crate only, it takes an engine handle and an async runtime, and its request
//! and context types are private. There is no way to call it from here at all. The envelope side is
//! therefore pinned differently — against the serializer, the codec's own code table and the
//! battery's own metadata keys, byte for byte — and the operation side is pinned against the
//! battery's own vocabulary.

mod common;

use busbar_contract::plane::{
    Ingress, Plane, PlaneMeta, Progress, Response, SessionPlane, UnitDraft,
};
use busbar_contract::wire::{Decode, DiscardCode, FrameCursor};
use busbar_plane_mcp::{facts, jsonrpc, ops, McpPlane};
use common::{frame, response_frame, Scaffold};
use std::path::{Path, PathBuf};

/// The battery's own source tree.
fn battery() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/mcp-conformance")
}

/// Every method name the battery's suites and fake peers name.
///
/// Read out of the battery rather than restated, which is the whole point: a battery that starts
/// sending a method this plane does not carry must fail at build time, not in a run.
fn battery_methods() -> Vec<String> {
    let mut found = Vec::new();
    let mut walk = |dir: PathBuf| {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "mjs") {
                let text = std::fs::read_to_string(&path).expect("a battery source is readable");
                for piece in text.split('\'').skip(1).step_by(2) {
                    if looks_like_a_method(piece) && !found.contains(&piece.to_string()) {
                        found.push(piece.to_string());
                    }
                }
            }
        }
    };
    walk(battery().join("src/suites"));
    walk(battery().join("src/core"));
    walk(battery().join("fakepeer"));
    assert!(
        !found.is_empty(),
        "no method names were read out of the battery"
    );
    found
}

/// Whether a quoted piece of the battery's source is a method name of this protocol.
fn looks_like_a_method(piece: &str) -> bool {
    let heads = [
        "server/",
        "tools/",
        "prompts/",
        "resources/",
        "completion/",
        "tasks/",
        "subscriptions/",
        "notifications/",
        "sampling/",
        "roots/",
        "elicitation/",
    ];
    heads.iter().any(|h| piece.starts_with(h)) && !piece.contains(' ')
}

/// One request envelope, built the way the battery's own builder builds one.
///
/// The battery always sends the metadata block, so every request here does too: a fixture that
/// omitted it would be exercising a shape no run ever produces.
fn request(id: &str, method: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"_meta":{{"{}":"2026-07-28","{}":{{}}}}}}}}"#,
        facts::META_PROTOCOL_VERSION,
        facts::META_CLIENT_CAPABILITIES
    )
    .into_bytes()
}

/// One notification, built the same way.
fn notification(method: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}}}}"#).into_bytes()
}

/// Drive one body through the decode step and hand back what the plane made of it.
fn decode(plane: &McpPlane, body: &[u8]) -> Result<Ingress<'static>, Decode> {
    let scaffold = Box::leak(Box::new(Scaffold::new("http")));
    let ctx = scaffold.ctx();
    let frames: &'static [busbar_contract::wire::Frame] = Box::leak(vec![frame(body)].into());
    let mut cursor = FrameCursor::new(frames);
    // The context borrows the leaked scaffold, so the draft it produces borrows the leaked frames
    // and outlives this call. Leaking is the right trade for a test: the real arena resets per unit,
    // and a test that had to model the reset would be testing the arena rather than the plane.
    plane.decode_ingress(&mut cursor, None, &ctx)
}

/// The draft a decode produced, or a failure naming what it produced instead.
fn draft_of(ingress: Ingress<'static>) -> UnitDraft<'static> {
    match ingress {
        Ingress::Open(d) | Ingress::OneShot(d) | Ingress::Handshake(d) => d,
        other => panic!("a well-formed request decoded as {other:?}"),
    }
}

/// Every method the battery sends is one this plane carries, in one of its three roles.
#[test]
fn every_method_the_battery_sends_is_carried() {
    for method in battery_methods() {
        let carried = ops::row_for(&method).is_some() || ops::is_known_notification(&method);
        // The battery names three notices this node emits rather than receives, and one deliberate
        // nonsense name. Everything else it names, it sends.
        let emitted_only = matches!(
            method.as_str(),
            "notifications/message"
                | "notifications/progress"
                | "notifications/cancelled"
                | "notifications/subscriptions/acknowledged"
        );
        assert!(
            carried || emitted_only,
            "the battery names {method} and this plane neither carries nor emits it"
        );
    }
}

/// Every method a caller sends decodes to a declared class, carrying the caller's identifier.
#[test]
fn every_client_method_decodes() {
    let plane = McpPlane::EMPTY;
    for row in ops::METHODS
        .iter()
        .filter(|r| r.sender == ops::Sender::Client)
    {
        let body = request("1", row.method);
        let draft = draft_of(decode(&plane, &body).unwrap_or_else(|e| {
            panic!(
                "a caller may send {} and this plane answered {e:?}",
                row.method
            )
        }));
        assert_eq!(draft.op, row.op, "{} named the wrong class", row.method);
        assert_eq!(
            draft.correlation_out.expect("a request correlates").value,
            busbar_contract::ids::CorrelationValue::Num(1),
            "{} lost its identifier",
            row.method
        );
        // A request answers nothing; it is answered.
        assert!(draft.correlates.is_none());
    }
}

/// The four the battery sends by name decode to exactly the classes they should.
///
/// The battery's suites send these four and no others, so this is the narrowest statement that
/// covers what a run actually exercises.
#[test]
fn the_four_the_battery_sends_name_their_classes() {
    let plane = McpPlane::EMPTY;
    for (method, expected) in [
        ("server/discover", ops::OP_DISCOVER),
        ("tools/list", ops::OP_TOOLS_LIST),
        ("tools/call", ops::OP_TOOL_CALL),
        ("subscriptions/listen", ops::OP_SUBSCRIPTIONS_LISTEN),
    ] {
        let draft = draft_of(
            decode(&plane, &request("1", method)).expect("the battery's own method decodes"),
        );
        assert_eq!(draft.op, expected);
    }
}

/// A method the battery sends deliberately, expecting a refusal, is refused.
#[test]
fn the_batterys_nonsense_method_is_refused() {
    let plane = McpPlane::EMPTY;
    assert_eq!(
        decode(&plane, &request("1", "this/method/does/not/exist")),
        Err(Decode::UnsupportedOperation)
    );
}

/// A method only an upstream may send is refused on the ingress side.
///
/// A caller that could send one would be opening a unit only a paired server is allowed to open,
/// and this node would answer it on the caller's behalf.
#[test]
fn a_caller_cannot_send_an_upstreams_method() {
    let plane = McpPlane::EMPTY;
    for row in ops::METHODS
        .iter()
        .filter(|r| r.sender == ops::Sender::Provider)
    {
        assert_eq!(
            decode(&plane, &request("1", row.method)),
            Err(Decode::UnsupportedOperation),
            "a caller was allowed to send {}",
            row.method
        );
    }
}

/// A held stream opens a unit; every other method is complete in one frame.
#[test]
fn only_the_held_stream_opens_a_unit() {
    let plane = McpPlane::EMPTY;
    for row in ops::METHODS
        .iter()
        .filter(|r| r.sender == ops::Sender::Client)
    {
        match (decode(&plane, &request("1", row.method)), row.streaming) {
            (Ok(Ingress::Open(_)), true) | (Ok(Ingress::OneShot(_)), false) => {}
            (other, _) => panic!("{} decoded as {other:?}", row.method),
        }
    }
}

/// A notice this plane recognises opens a unit that answers nothing.
#[test]
fn a_recognised_notice_opens_a_unit_that_answers_nothing() {
    let plane = McpPlane::EMPTY;
    for name in ops::NOTIFICATIONS {
        let draft = draft_of(decode(&plane, &notification(name)).expect("a notice decodes"));
        assert_eq!(draft.op, ops::OP_NOTIFICATION);
        // Nothing correlates: a notice obliges no answer, so there is nothing to answer it with.
        assert!(draft.correlation_out.is_none());
        assert!(draft.correlates.is_none());
    }
}

/// A notice this plane does not recognise is dropped, never refused.
///
/// The specification forbids answering a notice, and a refusal is an answer.
#[test]
fn an_unrecognised_notice_is_dropped() {
    let plane = McpPlane::EMPTY;
    assert_eq!(
        decode(&plane, &notification("notifications/something/else")),
        Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported
        })
    );
}

/// The metadata block the battery sends is read, keys and all.
///
/// The keys carry separators, which a pointer would read as levels, so this is the case that would
/// silently read as absent if the reader were written the obvious way.
#[test]
fn the_batterys_metadata_block_is_read() {
    let plane = McpPlane::EMPTY;
    let draft = draft_of(decode(&plane, &request("1", "tools/list")).expect("it decodes"));
    assert_eq!(
        draft.facts.get(facts::FACT_PROTOCOL_VERSION),
        Some(busbar_contract::bounded::FactValue::Str("2026-07-28"))
    );
}

/// The revision the battery declares is the revision the codec declares.
#[test]
fn the_revision_is_the_codecs_own() {
    let spec = std::fs::read_to_string(battery().join("src/core/spec.mjs"))
        .expect("the battery's own revision is readable");
    assert!(
        spec.contains(busbar_mcp::mcp::envelope::PROTOCOL_VERSION),
        "the battery and the codec no longer agree on the revision"
    );
}

/// The battery's own error code table is the one this plane writes from.
#[test]
fn the_error_codes_are_the_batterys_own() {
    let source = std::fs::read_to_string(battery().join("src/core/jsonrpc.mjs"))
        .expect("the battery's own code table is readable");
    for code in [
        jsonrpc::CODE_PARSE_ERROR,
        jsonrpc::CODE_INVALID_REQUEST,
        jsonrpc::CODE_METHOD_NOT_FOUND,
        jsonrpc::CODE_INVALID_PARAMS,
        jsonrpc::CODE_INTERNAL,
        jsonrpc::CODE_HEADER_MISMATCH,
        jsonrpc::CODE_MISSING_CLIENT_CAPABILITY,
        jsonrpc::CODE_UNSUPPORTED_PROTOCOL_VERSION,
    ] {
        assert!(
            source.contains(&format!("{code}")),
            "the battery no longer names the code {code}"
        );
    }
    // And the two the battery calls RETIRED are two this plane cannot write.
    for retired in jsonrpc::RETIRED_CODES {
        assert!(
            source.contains(&format!("{retired}")),
            "the battery no longer names the retired code {retired}"
        );
        assert!(!jsonrpc::CODES.contains(retired));
    }
}

/// The metadata keys are the ones the battery actually sends.
#[test]
fn the_metadata_keys_are_the_batterys_own() {
    let source = std::fs::read_to_string(battery().join("src/core/jsonrpc.mjs"))
        .expect("the battery's own key table is readable");
    for key in [
        facts::META_PROTOCOL_VERSION,
        facts::META_CLIENT_CAPABILITIES,
        facts::META_PROGRESS_TOKEN,
    ] {
        assert!(source.contains(key), "the battery no longer sends {key}");
    }
}

/// An answer that already is an envelope goes back exactly as it arrived.
#[test]
fn an_answer_goes_back_as_it_arrived() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let answer = br#"{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete","tools":[]}}"#;
    let r = Response {
        ir: busbar_contract::bounded::Ir::new(answer, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    let out = plane
        .encode_response(&r, None, &ctx)
        .expect("it re-encodes");
    assert_eq!(out.as_slice(), answer);
}

/// An answer this node composed itself is wrapped, stamped and given the caller's identifier.
#[test]
fn a_composed_answer_is_stamped_and_wrapped() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let mut facts_map = busbar_contract::bounded::Facts::new();
    facts_map
        .set(
            facts::FACT_RPC_ID,
            busbar_contract::bounded::FactValue::Str("1"),
        )
        .expect("one key fits");
    let r = Response {
        ir: busbar_contract::bounded::Ir::new(br#"{"tools":[]}"#, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: facts_map,
    };
    let out = plane.encode_response(&r, None, &ctx).expect("it wraps");
    assert_eq!(
        core::str::from_utf8(out.as_slice()).unwrap(),
        r#"{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete","tools":[]}}"#
    );
}

/// A document a server sends back mid-call opens a unit of the server's own.
#[test]
fn a_servers_own_request_opens_a_provider_unit() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let asked = br#"{"jsonrpc":"2.0","id":42,"method":"sampling/createMessage","params":{}}"#;
    let frames = vec![response_frame(asked)];
    let mut cursor = FrameCursor::new(&frames);
    match plane
        .decode_response(&mut cursor, &sealed_destination(), None, &ctx)
        .expect("a server's own request decodes")
    {
        Progress::OneShot(draft) => {
            assert_eq!(draft.op, ops::OP_SAMPLING);
            assert_eq!(
                draft.correlation_out.expect("it correlates").value,
                busbar_contract::ids::CorrelationValue::Num(42)
            );
        }
        other => panic!("a server's own request decoded as {other:?}"),
    }
}

/// A result that asks the caller for something is a turn, not an ending.
#[test]
fn a_result_that_asks_for_something_is_a_turn() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    for (kind, expected) in [
        (
            jsonrpc::RESULT_TYPE_COMPLETE,
            busbar_contract::unit::FinishClass::Complete,
        ),
        (
            jsonrpc::RESULT_TYPE_INPUT_REQUIRED,
            busbar_contract::unit::FinishClass::TurnComplete,
        ),
        (
            jsonrpc::RESULT_TYPE_TASK,
            busbar_contract::unit::FinishClass::TurnComplete,
        ),
    ] {
        let answer = format!(r#"{{"id":1,"jsonrpc":"2.0","result":{{"resultType":"{kind}"}}}}"#)
            .into_bytes();
        let frames = vec![response_frame(&answer)];
        let mut cursor = FrameCursor::new(&frames);
        match plane
            .decode_response(&mut cursor, &sealed_destination(), None, &ctx)
            .expect("an answer decodes")
        {
            Progress::Terminal { r, .. } => assert_eq!(r.finish, expected, "{kind} ended wrongly"),
            other => panic!("{kind} decoded as {other:?}"),
        }
    }
}

/// A refusal is rendered as this dialect's error envelope, with the caller's identifier.
#[test]
fn a_refusal_is_rendered_in_this_dialect() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let draft = draft_of(decode(&plane, &request("8", "tools/call")).expect("it decodes"));
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
    assert_eq!(value["id"], 8);
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["error"]["code"], jsonrpc::CODE_REFUSED);
}

/// A refusal that implies a wait says so, under a member a caller can act on.
#[test]
fn a_refusal_that_implies_a_wait_says_so() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Admit,
        reason: busbar_contract::unit::RefusalReason::OverBudget,
        retry_after_secs: Some(30),
        stream: None,
        correlates: None,
    };
    let out = plane
        .encode_refusal(&refusal, None, None, &ctx)
        .expect("a refusal renders");
    let value: serde_json::Value =
        serde_json::from_slice(out.as_slice()).expect("it is a document");
    assert_eq!(value["error"]["data"]["retryAfterSeconds"], 30);
    // And the identifier member is present and empty, because a peer's own test for "is this a
    // response" is whether the member is there at all.
    assert!(value["id"].is_null());
    assert!(value.as_object().expect("an object").contains_key("id"));
}

/// Every operation class routes to at least one leg, and every leg is one its schema declares.
#[test]
fn every_operation_routes_somewhere() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    for op in McpPlane::OP_CLASSES {
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
                    busbar_plane_mcp::records::operations_for(schema).contains(&rop),
                    "{op} reaches {schema} with an operation it does not declare: {rop}"
                );
            }
        }
    }
}

/// A call spends its grant before the hop, never after.
///
/// A grant spent after a hop is a grant a failed hop leaves unspent, and a retry can then spend it
/// again. The order of the legs is what makes that impossible, so the order is what is asserted.
#[test]
fn a_call_spends_its_grant_before_the_hop() {
    let plane = McpPlane::EMPTY;
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
        ops::OP_TOOL_CALL,
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    );
    let plan = plane.route(&unit, &ctx);
    let legs = plan.legs.as_slice();
    let redeem = legs
        .iter()
        .position(|l| {
            matches!(
                l.destination,
                busbar_contract::dest::DestinationFacts::PlaneRecord { op, .. }
                    if op == busbar_plane_mcp::records::OP_REDEEM
            )
        })
        .expect("a call spends a grant");
    let hop = legs
        .iter()
        .position(|l| {
            matches!(
                l.destination,
                busbar_contract::dest::DestinationFacts::Upstream { .. }
            )
        })
        .expect("a call hops");
    assert!(redeem < hop, "the grant is spent after the hop");
}

/// The metering step reports both declared classes for a call, and one for everything else.
#[test]
fn the_metering_step_reports_what_it_read() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let answer = br#"{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete"}}"#;
    let r = Response {
        ir: busbar_contract::bounded::Ir::new(answer, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    for (op, lines) in [(ops::OP_TOOL_CALL, 2), (ops::OP_TOOLS_LIST, 1)] {
        let unit = busbar_contract::unit::Unit::new(
            &seal,
            busbar_contract::UnitKey::new(1),
            busbar_contract::unit::Origin::Client,
            None,
            None,
            busbar_contract::wire::Direction::Inbound,
            Some(common::principal()),
            op,
            busbar_contract::bounded::Ir::new(b"{}", &[]),
            busbar_contract::bounded::Facts::new(),
            None,
        );
        let locators = plane.meter(&unit, &r, &ctx);
        assert_eq!(
            locators.lines.len(),
            lines,
            "{op} metered the wrong number of lines"
        );
        for line in locators.lines.as_slice() {
            // A plane names no lane and no price.
            assert!(line.lane.is_none());
            assert!(McpPlane::METER_CLASSES.iter().any(|c| c.key == line.class));
        }
    }
}

/// The introspection verb answers, and an undeclared verb does not.
#[test]
fn the_introspection_verb_answers_only_what_is_declared() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let facts = plane
        .plane_facts(busbar_plane_mcp::meta::VERB_TOOLS, None, &ctx)
        .expect("the declared verb answers");
    assert_eq!(
        facts.facts.get("count"),
        Some(busbar_contract::bounded::FactValue::Int(0))
    );
    assert!(plane
        .plane_facts(busbar_contract::ids::AdminVerbId::new("secrets"), None, &ctx)
        .is_err());
}

/// The per-name projection answers for the registration the subject names, and for no other.
///
/// This is the projection that could not be declared at all while the introspection verb carried no
/// argument: one verb, one subject, one registration. A subject naming nothing is refused rather
/// than answered empty, because "there is no such server" is not "that server has nothing to say".
#[test]
fn the_per_name_projection_answers_for_the_named_registration() {
    static SERVERS: &[busbar_plane_mcp::Server] = &[
        busbar_plane_mcp::Server {
            id: "alpha",
            lane: busbar_contract::ids::LaneId::new("mcp-a"),
            host: "alpha.invalid:443",
            transport: "http",
        },
        busbar_plane_mcp::Server {
            id: "beta",
            lane: busbar_contract::ids::LaneId::new("mcp-b"),
            host: "",
            transport: "stdio",
        },
    ];
    let plane = McpPlane::new(SERVERS);
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let verb = busbar_plane_mcp::meta::VERB_SERVER;

    let alpha = plane
        .plane_facts(verb, Some("alpha"), &ctx)
        .expect("a named registration answers");
    assert_eq!(
        alpha.facts.get("name"),
        Some(busbar_contract::bounded::FactValue::Str("alpha"))
    );
    assert_eq!(
        alpha.facts.get("lane"),
        Some(busbar_contract::bounded::FactValue::Str("mcp-a"))
    );
    assert_eq!(
        alpha.facts.get("transport"),
        Some(busbar_contract::bounded::FactValue::Str("http"))
    );
    assert_eq!(
        alpha.facts.get("local"),
        Some(busbar_contract::bounded::FactValue::Bool(false))
    );

    // The other registration answers for itself, so the subject is what selects, not the order.
    let beta = plane
        .plane_facts(verb, Some("beta"), &ctx)
        .expect("the other named registration answers");
    assert_eq!(
        beta.facts.get("lane"),
        Some(busbar_contract::bounded::FactValue::Str("mcp-b"))
    );
    assert_eq!(
        beta.facts.get("local"),
        Some(busbar_contract::bounded::FactValue::Bool(true))
    );

    // A subject that names nothing, and no subject at all, are both refusals.
    assert!(plane.plane_facts(verb, Some("gamma"), &ctx).is_err());
    assert!(plane.plane_facts(verb, None, &ctx).is_err());

    // And the per-name verb is declared, so the loop can reach it.
    assert!(<McpPlane as PlaneMeta>::ADMIN_VERBS.contains(&verb));
}

/// The session halves open, and each one starts fresh.
#[test]
fn the_session_halves_open_fresh() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let client = plane.open_session(&ctx);
    let upstream = plane.open_upstream(&sealed_destination(), &ctx);
    for half in [&client, &upstream] {
        let codec = half
            .get::<busbar_plane_mcp::plane::Codec>()
            .expect("the half carries this plane's own state");
        assert_eq!((codec.events_read, codec.rounds_asked), (0, 0));
    }
}

/// A locally launched server's units narrow to the alternative that has no request to sit on.
#[test]
fn a_local_server_narrows_to_the_environment_alternative() {
    let plane = McpPlane::EMPTY;
    let seal = common::TestSeal;
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_TOOL_CALL,
        busbar_contract::bounded::Ir::new(b"{}", &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    );
    for (transport, expected) in [("stdio", "environment"), ("http", "bearer")] {
        let scaffold = Scaffold::new(transport);
        let ctx = scaffold.ctx();
        let locator = plane.authenticate(&unit, &ctx);
        assert_eq!(
            locator.narrowing.expect("it narrows").as_str(),
            expected,
            "{transport} narrowed wrongly"
        );
    }
}

/// Every alternative the plane narrows to is one its claims declare.
///
/// A plane may only narrow within the set its claim declares; anything else is refused at the
/// authenticate step, and a plane that narrowed outside it would be refusing its own units.
#[test]
fn every_narrowing_is_declared() {
    // The alternatives of a claim that DECLARES a scheme. The open surface's claim declares none,
    // which is the whole point of it: there is nothing there to narrow to, so it cannot be the
    // claim this check is read against.
    let declared = McpPlane::CLAIMS
        .iter()
        .find(|c| c.scheme.is_some())
        .expect("some claim declares a scheme")
        .scheme_alternatives;
    let plane = McpPlane::EMPTY;
    let seal = common::TestSeal;
    for op in McpPlane::OP_CLASSES {
        for transport in ["http", "sse", "stdio"] {
            let scaffold = Scaffold::new(transport);
            let ctx = scaffold.ctx();
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
            let narrowing = plane
                .authenticate(&unit, &ctx)
                .narrowing
                .expect("it narrows");
            assert!(
                declared.contains(&narrowing.as_str()),
                "{op} on {transport} narrows to {narrowing}, which no claim declares"
            );
        }
    }
}

/// A sealed destination, for the calls that take one.
fn sealed_destination() -> busbar_contract::dest::VerifiedDestination {
    let seal = common::TestSeal;
    busbar_contract::dest::VerifiedDestination::seal(
        &seal,
        busbar_contract::dest::DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("server.example"),
            lane: busbar_contract::ids::LaneId::new("standard"),
        },
        "http",
        None,
    )
}
