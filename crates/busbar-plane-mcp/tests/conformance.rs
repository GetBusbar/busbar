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
        // A directory that is not there is NOT "no methods here". The three below are the three
        // places the battery keeps the names this plane is checked against, and a missing one used
        // to return quietly: the surviving two still filled `found`, the non-empty floor below
        // still held, and the coverage this test claims silently shrank to whatever was left. If
        // the battery moves a directory, that must be a red here rather than a smaller test.
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("the battery's {} is readable ({e})", dir.display()));
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
        Ingress::Open(d) | Ingress::OneShot(d) | Ingress::Handshake(d) => *d,
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

/// How many rows of each role the method table declares, and how many notices this plane knows.
///
/// Every loop below is a FILTER over a declared table, so a table that lost the rows a loop selects
/// would leave that loop iterating zero times — and a conformance test that drove nothing reports
/// `ok`. These three numbers are what turns "the loop found nothing" into a failure. Raise one
/// deliberately, in the commit that adds the row.
const CLIENT_ROWS: usize = 13;
/// The rows only a paired server may send. See [`CLIENT_ROWS`].
const PROVIDER_ROWS: usize = 3;
/// The notices this plane recognises. See [`CLIENT_ROWS`].
const NOTICE_ROWS: usize = 3;

/// The declared method rows of one role.
fn rows_of(sender: ops::Sender) -> Vec<&'static ops::MethodRow> {
    ops::METHODS.iter().filter(|r| r.sender == sender).collect()
}

/// Every method a caller sends decodes to a declared class, carrying the caller's identifier.
#[test]
fn every_client_method_decodes() {
    let plane = McpPlane::EMPTY;
    let rows = rows_of(ops::Sender::Client);
    assert_eq!(rows.len(), CLIENT_ROWS);
    for row in rows {
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
    let rows = rows_of(ops::Sender::Provider);
    assert_eq!(rows.len(), PROVIDER_ROWS);
    for row in rows {
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
    let rows = rows_of(ops::Sender::Client);
    assert_eq!(rows.len(), CLIENT_ROWS);
    for row in rows {
        match (decode(&plane, &request("1", row.method)), row.event_framed) {
            (Ok(Ingress::Open(_)), true) | (Ok(Ingress::OneShot(_)), false) => {}
            (other, _) => panic!("{} decoded as {other:?}", row.method),
        }
    }
}

/// A notice this plane recognises opens a unit that answers nothing.
#[test]
fn a_recognised_notice_opens_a_unit_that_answers_nothing() {
    let plane = McpPlane::EMPTY;
    assert_eq!(ops::NOTIFICATIONS.len(), NOTICE_ROWS);
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
        spec.contains(busbar_plane_mcp::codec::PROTOCOL_VERSION),
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
            names_the_number(&source, code),
            "the battery no longer names the code {code}"
        );
    }
    // And the two the battery calls RETIRED are two this plane cannot write.
    for retired in jsonrpc::RETIRED_CODES {
        assert!(
            names_the_number(&source, *retired),
            "the battery no longer names the retired code {retired}"
        );
        assert!(!jsonrpc::CODES.contains(retired));
    }
}

/// Whether a source file names EXACTLY this number, rather than merely containing its digits.
///
/// A bare substring search answers yes for a code that is a prefix of a longer one — `-32700` is
/// inside `-327001` — and yes for the digits of a code that appears in a version string, a byte
/// count or a comment. Either way the check would report the battery still names a code it had
/// dropped. Requiring a non-digit on each side is what makes the match the number itself.
fn names_the_number(source: &str, code: i64) -> bool {
    let needle = code.to_string();
    let bytes = source.as_bytes();
    source.match_indices(&needle).any(|(at, _)| {
        let before_ok = at == 0 || !bytes[at - 1].is_ascii_digit();
        let after = at + needle.len();
        let after_ok = after == bytes.len() || !bytes[after].is_ascii_digit();
        before_ok && after_ok
    })
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

/// AN UPSTREAM CANNOT SEND A CALLER'S METHOD — the mirror of
/// [`a_caller_cannot_send_an_upstreams_method`], and the direction that is actually dangerous.
///
/// `ops::row_for` searches the WHOLE vocabulary with no sender filter. Without the guard in
/// `decode_response`, a compromised upstream naming `tools/call` on the response leg had it minted
/// as a genuine unit and run through all seven governance steps under the ORIGINAL CALLER's
/// identity, budget and approval grant — a confused deputy spending its victim's authority for work
/// the victim never requested. Ingress had this check; egress did not.
#[test]
fn an_upstream_cannot_send_a_callers_method() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let rows = rows_of(ops::Sender::Client);
    assert_eq!(rows.len(), CLIENT_ROWS);
    for row in rows {
        let asked = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"{}","params":{{}}}}"#,
            row.method
        );
        let frames = vec![response_frame(asked.as_bytes())];
        let mut cursor = FrameCursor::new(&frames);
        match plane
            .decode_response(&mut cursor, &sealed_destination(), None, &ctx)
            .expect("a refused method still decodes to a verdict")
        {
            Progress::Discard { .. } => {}
            other => panic!(
                "an upstream was allowed to open a unit with the caller-only method {}: {other:?}",
                row.method
            ),
        }
    }
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

/// An envelope with a real result is billed complete exactly once; one with neither result nor
/// error is not billed complete.
///
/// This is a money boundary. A JSON-RPC answer carries exactly one of `result` or `error`; a
/// document with NEITHER used to fall through to `Complete` and charge the caller for a full answer
/// that never came. A genuine result closes the unit `Complete`; an empty envelope is `Partial`.
#[test]
fn only_a_real_result_bills_complete() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();

    // A genuine result: complete, exactly once (one Terminal, one Complete).
    let answer = br#"{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete","tools":[]}}"#;
    let frames = vec![response_frame(answer)];
    let mut cursor = FrameCursor::new(&frames);
    match plane
        .decode_response(&mut cursor, &sealed_destination(), None, &ctx)
        .expect("a real answer decodes")
    {
        Progress::Terminal { r, .. } => assert_eq!(
            r.finish,
            busbar_contract::unit::FinishClass::Complete,
            "a real result must bill complete"
        ),
        other => panic!("a real result decoded as {other:?}"),
    }

    // An envelope with neither result nor error must NOT bill complete.
    let empty = br#"{"id":1,"jsonrpc":"2.0"}"#;
    let frames = vec![response_frame(empty)];
    let mut cursor = FrameCursor::new(&frames);
    match plane
        .decode_response(&mut cursor, &sealed_destination(), None, &ctx)
        .expect("an empty envelope decodes")
    {
        Progress::Terminal { r, .. } => assert_ne!(
            r.finish,
            busbar_contract::unit::FinishClass::Complete,
            "an empty envelope must not bill complete"
        ),
        other => panic!("an empty envelope decoded as {other:?}"),
    }
}

/// `isError` yields a fact only when it is a JSON boolean.
///
/// A non-boolean `isError` (the string `"true"`, a number) used to read as `false`, reporting a
/// failing tool as a succeeding one. It now yields no fact at all; a real boolean still yields
/// itself. The answer is relayed unchanged either way, as predev relays it.
#[test]
fn a_non_boolean_is_error_is_not_read_as_success() {
    let plane = McpPlane::EMPTY;
    // Reading an answer consults no carrier, so the scaffold names none.
    let scaffold = Scaffold::new("");
    let ctx = scaffold.ctx();
    for (flag, expected) in [
        ("true", Some(true)),
        ("false", Some(false)),
        ("\"true\"", None),
        ("\"false\"", None),
        ("1", None),
        ("{}", None),
    ] {
        let answer =
            format!(r#"{{"id":1,"jsonrpc":"2.0","result":{{"content":[],"isError":{flag}}}}}"#)
                .into_bytes();
        let frames = vec![response_frame(&answer)];
        let mut cursor = FrameCursor::new(&frames);
        match plane
            .decode_response(&mut cursor, &sealed_destination(), None, &ctx)
            .expect("an answer decodes")
        {
            Progress::Terminal { r, .. } => {
                let read = match r.facts.get(facts::FACT_IS_ERROR) {
                    Some(busbar_contract::bounded::FactValue::Bool(b)) => Some(b),
                    None => None,
                    other => panic!("isError {flag} read as {other:?}"),
                };
                assert_eq!(read, expected, "isError {flag}");
            }
            other => panic!("isError {flag} decoded as {other:?}"),
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

/// How many legs each operation class routes to.
///
/// The count is the shape of the plan — a call spends a grant, hops, and settles; a listing reaches
/// one record — so a leg that appears or disappears is a change to what an operation DOES, and it is
/// written down here rather than left to a bound that can never fail.
const EXPECTED_LEGS: &[(&str, usize)] = &[
    ("discover", 2),
    ("tools_list", 2),
    ("tool_call", 5),
    ("prompts_list", 2),
    ("prompt_get", 3),
    ("resources_list", 2),
    ("resource_templates_list", 2),
    ("resource_read", 3),
    ("completion", 1),
    ("task_get", 1),
    ("task_update", 2),
    ("task_cancel", 2),
    ("subscriptions_listen", 2),
    ("sampling", 2),
    ("roots_list", 1),
    ("elicitation", 1),
    ("notification", 1),
];

/// Every operation class routes to at least one leg, and every leg is one its schema declares.
#[test]
fn every_operation_routes_somewhere() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let mut covered = 0usize;
    for op in McpPlane::OP_CLASSES {
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
                    busbar_plane_mcp::records::operations_for(schema).contains(&rop),
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
            let declared = McpPlane::METER_CLASSES
                .iter()
                .find(|c| c.key == line.class)
                .unwrap_or_else(|| panic!("{op} meters the undeclared class {}", line.class));
            // Which SIDE the class says it is sized from is the side the quantity was taken from.
            // Both quantities here come off the answer — the call is counted once it has been
            // answered, and the byte count is the answer's own length — so both classes declare
            // themselves sized from the answer. A class that declared the request and reported the
            // answer would have a rate card pricing one side of the exchange at the size of the
            // other.
            assert_eq!(
                declared.direction,
                busbar_contract::ids::ClassDirection::Response,
                "{} is metered off the answer and declares another side",
                line.class
            );
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
        .plane_facts(
            busbar_contract::ids::AdminVerbId::new("secrets"),
            None,
            &ctx
        )
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
    assert!(<McpPlane as PlaneMeta>::INTROSPECTION_VERBS.contains(&verb));
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

/// A request bigger than the per-unit arena is still relayed, byte for byte.
///
/// The bytes the hop carries are the bytes that arrived, and they already live for the unit that
/// carries them. Copying them into the arena first spent the whole bounded budget on a second copy
/// of what the unit was already holding, so a request larger than that budget could not be relayed
/// at all — a size limit nobody configured, imposed by an allocation with no purpose.
#[test]
fn a_request_larger_than_the_arena_is_relayed() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let argument = "x".repeat(busbar_contract::bounded::SCRATCH_BASE_BYTES * 2);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"search","arguments":{{"q":"{argument}"}}}}}}"#
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
        ops::OP_TOOL_CALL,
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
        "the server is sent the caller's own bytes, whole"
    );
}

/// What every operation SEALS is somewhere its own plan then goes.
///
/// The verify step seals one destination and the route step lists the legs the unit dials. A class
/// that seals an upstream and then plans no leg to it has had an upstream admitted, checked against
/// the allow-list and counted against this node's admission for a hop that never happens; a class
/// that plans a leg it was not verified for is the other half of the same seam. Asserted over the
/// whole declared vocabulary, so a class added later cannot quietly acquire either shape.
#[test]
fn every_operation_is_verified_for_a_destination_its_plan_reaches() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    for op in <McpPlane as PlaneMeta>::OP_CLASSES {
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
        let verified = plane.verify(&unit, &ctx);
        let plan = plane.route(&unit, &ctx);
        assert!(
            plan.legs
                .as_slice()
                .iter()
                .any(|l| l.destination == verified),
            "{op} is verified for {verified:?}, which none of its legs reach"
        );
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

/// THE MCP PLANE'S CONFORMANCE RIG, BOTH WAYS (BUSBAR-1.6.0.md, the plane driver's "Proven by":
/// the plane conformance suite, compiled-in and dropped-in through one table).
///
/// The linked door (`plane_door::door`) and this crate's dropped-in image (the `mcp_door` example,
/// the same door behind `export_door!`) are each admitted through the one loader on one
/// dispatcher and run ONE script through every plane op, each answer read back. The two
/// transcripts must be identical, step for step, and the linked one must say what the plane's
/// own pure functions say the door answers: the snapshot is `door::snapshot_spec`'s, a refused
/// arrival renders the plane's own words at its own status, and a request the plane answers from
/// what it holds is the catalogue's answer.
///
/// RED ARM, kept: the same door with `on_piece` swapped for one that relays the caller's bytes
/// back instead of answering from the catalogue. Its transcript differs at the answer, so a door
/// that stopped answering from what the plane holds cannot pass for this one.
mod both_ways {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn,
        PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn,
        ServeOut, EMIT_DONE, FROM_CALLER, FROM_FAR_END, PIECE_LAST, PRINCIPAL_REQUIRED,
        REFUSAL_ARRIVE, REFUSAL_GATE,
    };
    use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
    use busbar_contract::abi::sdk::door::{abi_str, kind_op};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_plane_mcp::codec::{H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION, PROTOCOL_VERSION};
    use busbar_plane_mcp::{door, ops, plane_door};
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
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: None,
        }
    }

    fn octets(b: &'static [u8]) -> Blob {
        Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    fn text(b: &'static [u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn at(buf: &[u8], s: Span) -> String {
        String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
    }

    // ── the fixtures ─────────────────────────────────────────────────────────────────────────────────

    /// One fronted server, the section the door's own tests read.
    const SECTION: &[u8] =
        br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
    /// A registration the grammar refuses: a server id holding the routing-key separator.
    const BAD_SECTION: &[u8] =
        br#"{"my_fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
    /// The deployment's public base URL the host lends `open`.
    const PUBLIC_URL: &str = "https://busbar.example";

    /// A stateless-revision `tools/list`.
    const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    /// A stateless-revision `tools/call`: sent on, never answered from what the plane holds.
    const TOOLS_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fs__read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    /// A notification: acknowledged, never answered.
    const NOTICE: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    /// A body that is not JSON.
    const NOT_JSON: &[u8] = b"{not json";

    const fn field(name: &'static str, value: &'static str) -> Field {
        Field {
            name: abi_str(name),
            value: abi_str(value),
        }
    }

    const LIST_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/list"),
    ];
    const CALL_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs__read_file"),
    ];

    /// The route index of `(verb, target)` in the door's route table (its first such row), the claim
    /// an arrival carries.
    fn claim(verb: &str, target: &str) -> u32 {
        let i = door::ROUTES
            .iter()
            .position(|r| r.verb == verb && r.target == target)
            .expect("the door routes it");
        u32::try_from(i).expect("a small table")
    }

    // ── one step of the transcript ───────────────────────────────────────────────────────────────────

    /// What one op answered, read back: the outcome, the status it stated, the bytes it wrote and
    /// the head fields, and anything else the op answers in its own out struct.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Step {
        what: &'static str,
        outcome: Outcome,
        status: u32,
        reply: Vec<u8>,
        fields: Vec<(String, String)>,
        detail: String,
        snapshot: Option<OwnedSnapshot>,
    }

    impl Step {
        fn new(what: &'static str, outcome: Outcome) -> Self {
            Step {
                what,
                outcome,
                status: 0,
                reply: Vec::new(),
                fields: Vec::new(),
                detail: String::new(),
                snapshot: None,
            }
        }
    }

    fn arrive(
        p: &Plugin<Plane>,
        what: &'static str,
        unit: u64,
        (verb, target): (&'static str, &'static str),
        body: &'static [u8],
        fields: &'static [Field],
    ) -> (Step, Option<Vec<u8>>) {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.unit = unit;
        a.input.claim = claim(verb, target);
        (a.input.method, a.input.target) = (text(verb.as_bytes()), text(target.as_bytes()));
        a.input.body = octets(body);
        (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
        let c = p.call(slot::ARRIVE, &mut a);
        let mut s = Step::new(what, c.outcome);
        s.status = a.out.refusal_status;
        s.detail = format!(
            "op_class={} principal_required={} dialect={} refusal={}",
            a.out.op_class,
            a.out.principal_need == PRINCIPAL_REQUIRED,
            a.out.dialect,
            a.out.refusal
        );
        (s, c.error)
    }

    /// One `on_piece` of `unit` with a reply buffer of `cap` bytes, then re-called with the same
    /// `from` and zero bytes while the door answers `more = 1`. The bytes of every call, in order.
    fn piece(
        p: &Plugin<Plane>,
        what: &'static str,
        unit: u64,
        from: u32,
        body: &'static [u8],
        cap: usize,
    ) -> Step {
        let mut reply = vec![0_u8; cap];
        let mut out = Step::new(what, Outcome::Ready);
        let mut calls = 0;
        let mut bytes = body;
        loop {
            let mut i: OnPieceIn = z();
            i.head = in_head();
            (i.unit, i.from, i.flags, i.bytes) = (unit, from, PIECE_LAST, octets(bytes));
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            calls += 1;
            out.outcome = c.outcome;
            if f.out.reply_status != 0 {
                out.status = f.out.reply_status;
            }
            out.reply
                .extend_from_slice(&reply[..usize::try_from(f.out.emitted).expect("small")]);
            let done = f.out.flags & EMIT_DONE != 0;
            if c.outcome != Outcome::Ready || f.out.more == 0 || calls > 64 {
                out.detail = format!("calls={calls} done={done} more={}", f.out.more);
                return out;
            }
            bytes = b"";
        }
    }

    fn refusal(
        p: &Plugin<Plane>,
        what: &'static str,
        cause: u32,
        status: u32,
        words: &[u8],
    ) -> Step {
        let (mut reply, mut fields, mut arena) = ([0_u8; 512], [z::<OutField>(); 2], [0_u8; 64]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status) = (cause, status);
        r.input.text = AbiStr {
            ptr: words.as_ptr(),
            len: words.len(),
        };
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut r);
        let mut s = Step::new(what, c.outcome);
        s.status = r.out.status;
        s.reply = reply[..usize::try_from(r.out.reply_written).expect("small")].to_vec();
        s.fields = fields[..r.out.fields_written as usize]
            .iter()
            .map(|f| (at(&arena, f.name), at(&arena, f.value)))
            .collect();
        s
    }

    /// THE SCRIPT: every plane op, each answer read back.
    fn script(p: &Plugin<Plane>) -> Vec<Step> {
        let mut t = Vec::new();

        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(BAD_SECTION),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        t.push(Step::new(
            "validate refused",
            p.call(life::VALIDATE, &mut v).outcome,
        ));
        v.input.settings = octets(SECTION);
        t.push(Step::new(
            "validate",
            p.call(life::VALIDATE, &mut v).outcome,
        ));

        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (c, snapshot) = p.open(&mut Frame::new(i, o));
        let mut s = Step::new("open", c.outcome);
        s.snapshot = snapshot;
        t.push(s);

        for (what, op) in [("hydrate", slot::HYDRATE), ("start", slot::START)] {
            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            t.push(Step::new(what, p.call(op, &mut g).outcome));
        }

        // A request the plane answers from what it holds, written 32 bytes at a time.
        let post = ("POST", "/mcp");
        t.push(arrive(p, "arrive tools/list", 7, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/list",
            7,
            FROM_CALLER,
            TOOLS_LIST,
            32,
        ));
        // A notification: acknowledged with no body.
        t.push(arrive(p, "arrive notice", 8, post, NOTICE, &[]).0);
        t.push(piece(p, "answer notice", 8, FROM_CALLER, NOTICE, 256));
        // A call the plane sends on: not answered here.
        t.push(arrive(p, "arrive tools/call", 9, post, TOOLS_CALL, CALL_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/call",
            9,
            FROM_CALLER,
            TOOLS_CALL,
            256,
        ));
        // A far end's piece for a unit the plane answered itself.
        t.push(arrive(p, "arrive again", 10, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(p, "far end", 10, FROM_FAR_END, b"{}", 256));

        // Refused arrivals, each rendered in the plane's own words.
        let (s, words) = arrive(p, "arrive not json", 11, post, NOT_JSON, &[]);
        t.push(s);
        let words = words.unwrap_or_default();
        t.push(refusal(p, "refusal not json", REFUSAL_ARRIVE, 0, &words));
        let (s, words) = arrive(p, "arrive GET /mcp", 12, ("GET", "/mcp"), b"", &[]);
        t.push(s);
        let words = words.unwrap_or_default();
        t.push(refusal(p, "refusal GET /mcp", REFUSAL_ARRIVE, 0, &words));
        let metadata = ("GET", busbar_plane_mcp::claims::DEFAULT_METADATA);
        t.push(arrive(p, "arrive metadata", 13, metadata, b"", &[]).0);
        // A refusal the kernel decided (a gate), in the one error envelope.
        t.push(refusal(p, "refusal gate", REFUSAL_GATE, 403, b"denied"));

        let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
        (s.input.head, s.out.head) = (in_head(), out_head());
        t.push(Step::new("serve", p.call(slot::SERVE, &mut s).outcome));
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        t.push(Step::new("project", p.call(slot::PROJECT, &mut j).outcome));

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1_000,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 7,
            },
        );
        let mut s = Step::new("tick", p.call(life::TICK, &mut k).outcome);
        s.detail = format!("next={}", k.out.next_tick_ns);
        t.push(s);
        let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
        (x.input.head, x.out.head) = (in_head(), out_head());
        let mut s = Step::new("cancel", p.call(life::CANCEL, &mut x).outcome);
        s.detail = format!("disposition={}", x.out.disposition);
        t.push(s);

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        (f.input.generation, f.input.settings) = (2, octets(b""));
        let (c, snapshot) = p.refresh(&mut f);
        let mut s = Step::new("refresh", c.outcome);
        s.snapshot = snapshot;
        t.push(s);

        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        t.push(Step::new("retire", p.call(life::RETIRE, &mut g).outcome));
        let mut e = Frame::new(in_head(), out_head());
        t.push(Step::new("close", p.call(life::CLOSE, &mut e).outcome));
        t
    }

    fn step<'a>(t: &'a [Step], what: &str) -> &'a Step {
        t.iter()
            .find(|s| s.what == what)
            .unwrap_or_else(|| panic!("the script has no `{what}` step"))
    }

    fn document(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("a JSON document")
    }

    /// The op class index the door's tail holds for `op`.
    fn class(op: busbar_contract::ids::OpClassId) -> u32 {
        door::op_class_index(op).expect("the tail holds it")
    }

    // ── the doors ────────────────────────────────────────────────────────────────────────────────────

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the `mcp_door` example `cargo test` builds. A missing artifact
    /// is a failure, never a skip: this test IS the dropped-in door's proof.
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let exe = std::env::current_exe().expect("the test binary has a path");
        let examples = exe
            .parent()
            .and_then(|d| d.parent())
            .expect("target/<profile>")
            .join("examples");
        let file = busbar_plugin_loader::plugin_library_filename("mcp_door");
        let path = [examples.join(&file), examples.join("deps").join(&file)]
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("the mcp_door example ({file}) is not built"));
        let stated = rendering_of(plane_door::door).expect("the door renders its Statement");
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// The linked transcript is the one the plane's own pure functions say the door answers.
    #[test]
    fn the_door_answers_what_the_plane_says() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));

        // Lifecycle: the grammar judges the section; the snapshot is the door's own.
        assert_eq!(step(&t, "validate refused").outcome, Outcome::Refused);
        assert_eq!(step(&t, "validate").outcome, Outcome::Ready);
        let open = step(&t, "open");
        assert_eq!(open.outcome, Outcome::Ready);
        let snapshot = open.snapshot.as_ref().expect("open publishes a snapshot");
        let spec = door::snapshot_spec(Some(PUBLIC_URL));
        assert_eq!(snapshot.generation, 1);
        let claims: Vec<_> = snapshot
            .claims
            .iter()
            .map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.carrier.as_str(),
                    c.flags,
                )
            })
            .collect();
        let want: Vec<_> = spec
            .claims
            .iter()
            .map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.carrier.as_str(),
                    c.flags,
                )
            })
            .collect();
        assert_eq!(claims, want, "the claims are the door's routes");
        assert_eq!(claims.len(), door::ROUTES.len());
        let admin: Vec<_> = snapshot
            .admin_routes
            .iter()
            .map(|r| (r.verb.as_str(), r.target.as_str(), r.flags))
            .collect();
        let want: Vec<_> = spec
            .admin_routes
            .iter()
            .map(|r| (r.verb.as_str(), r.target.as_str(), r.flags))
            .collect();
        assert_eq!(admin, want, "the admin routes are the door's");
        assert_eq!(snapshot.audience, spec.audience);
        assert_eq!(snapshot.resource_metadata, spec.resource_metadata);
        assert_eq!(
            snapshot.audience.as_deref(),
            Some("https://busbar.example/mcp")
        );

        // A request answered from what the plane holds: the catalogue's answer, written whole.
        let a = step(&t, "arrive tools/list");
        assert_eq!(a.outcome, Outcome::Ready);
        assert_eq!(
            a.detail,
            format!(
                "op_class={} principal_required=true dialect=0 refusal=0",
                class(ops::OP_TOOLS_LIST)
            )
        );
        let answer = step(&t, "answer tools/list");
        assert_eq!((answer.outcome, answer.status), (Outcome::Ready, 200));
        assert!(
            answer.detail.starts_with("calls=") && answer.detail.ends_with("done=true more=0"),
            "{}",
            answer.detail
        );
        let calls: usize = answer.detail["calls=".len()..]
            .split(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .expect("a call count");
        assert!(
            calls > 1,
            "a 32-byte buffer takes the answer over several calls"
        );
        let catalogue = busbar_plane_mcp::catalogue::Catalogue::build(
            1,
            &door::read_settings(SECTION).expect("the section reads"),
        );
        let want = catalogue.tools_list(&json!(9), &|_: &str, _: &str| false, |_| false);
        assert_eq!(answer.reply, want, "the catalogue's own bytes");
        assert_eq!(document(&answer.reply)["id"], json!(9));

        // A notification: acknowledged, no body.
        let a = step(&t, "arrive notice");
        assert_eq!(a.outcome, Outcome::Ready);
        assert!(a
            .detail
            .starts_with(&format!("op_class={} ", class(ops::OP_NOTIFICATION))));
        let n = step(&t, "answer notice");
        assert_eq!(
            (n.outcome, n.status, n.reply.as_slice()),
            (Outcome::Ready, 202, &b""[..])
        );

        // A call the plane sends on is not answered here; nor is a far end's piece.
        assert_eq!(step(&t, "arrive tools/call").outcome, Outcome::Ready);
        assert_eq!(step(&t, "answer tools/call").outcome, Outcome::Refused);
        assert_eq!(step(&t, "far end").outcome, Outcome::Refused);

        // Refused arrivals: the plane's own words at its own status.
        let a = step(&t, "arrive not json");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 400));
        let r = step(&t, "refusal not json");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 400));
        let body = document(&r.reply);
        assert_eq!(body["error"]["code"], json!(-32700));
        assert_eq!(
            body["error"]["message"],
            json!(busbar_plane_mcp::arrival::NOT_JSON)
        );
        assert_eq!(body["id"], Value::Null);

        let a = step(&t, "arrive GET /mcp");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 405));
        let r = step(&t, "refusal GET /mcp");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 405));
        assert_eq!(r.reply, door::method_not_allowed_body());
        assert_eq!(r.fields, vec![("allow".to_string(), "POST".to_string())]);

        let a = step(&t, "arrive metadata");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 404));
        assert!(a
            .detail
            .ends_with(&format!("refusal={}", plane_door::UNSERVED)));

        let r = step(&t, "refusal gate");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 0));
        let body = document(&r.reply);
        assert_eq!(
            body["error"]["code"],
            json!(busbar_plane_mcp::codec::CODE_REFUSED)
        );
        assert_eq!(body["error"]["message"], json!("denied"));

        // The ops the driver does not call on this door yet, and the rest of the lifecycle.
        for what in ["hydrate", "start", "serve", "project"] {
            assert_eq!(step(&t, what).outcome, Outcome::Refused, "{what}");
        }
        assert_eq!(step(&t, "tick").detail, "next=0");
        assert_eq!(
            step(&t, "cancel").detail,
            format!("disposition={}", plane::CANCEL_ABORTED)
        );
        let refresh = step(&t, "refresh");
        assert_eq!(refresh.outcome, Outcome::Ready);
        let snapshot = refresh.snapshot.as_ref().expect("refresh publishes");
        assert_eq!(snapshot.generation, 2);
        assert_eq!(
            snapshot.audience, spec.audience,
            "the base URL `open` was lent"
        );
        for what in ["retire", "close"] {
            assert_eq!(step(&t, what).outcome, Outcome::Ready, "{what}");
        }
    }

    // ── the red arm ──────────────────────────────────────────────────────────────────────────────────

    /// A call capture for the hand-built table entry below: one slot per thread, as `plugin_door!`
    /// expands for a plugin's own image.
    struct TestCapture;
    impl CaptureHome for TestCapture {
        fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
            thread_local! {
                static SLOT: std::cell::RefCell<CaptureSlot> =
                    std::cell::RefCell::new(CaptureSlot::new());
            }
            SLOT.with(|s| f(&mut s.borrow_mut()))
        }
    }

    /// An `on_piece` that relays the caller's bytes back instead of answering from the catalogue.
    struct Echo;
    impl SafeSlot for Echo {
        type In = OnPieceIn;
        type Out = OnPieceOut;
        type State = ();
        fn call(
            _: Instance<'_, ()>,
            input: Lent<'_, OnPieceIn>,
            mut out: Out<'_, OnPieceOut>,
        ) -> Outcome {
            let bytes = input.field(|i| &i.bytes).bytes();
            let n = input.reply_buf().stream(bytes);
            out.set(|o| &o.emitted, n as u64);
            out.set(|o| &o.reply_status, 200);
            out.set(|o| &o.flags, EMIT_DONE);
            Outcome::Ready
        }
    }

    /// The mcp door with `on_piece` swapped for [`Echo`].
    extern "C" fn echo_door() -> *const Door {
        // SAFETY: the macro's `'static` door and its plane table.
        let (d, mut ops) = unsafe {
            let d = &*plane_door::door();
            (d, *d.ops.cast::<plane::Ops>())
        };
        ops.on_piece = kind_op::<plane::Ops, Safe<Echo>, TestCapture, { slot::ON_PIECE }>();
        let ops: &'static plane::Ops = Box::leak(Box::new(ops));
        Box::leak(Box::new(Door {
            ops: std::ptr::from_ref(ops).cast(),
            ..*d
        }))
    }

    #[test]
    fn red_a_door_that_stops_answering_from_the_catalogue_answers_differently() {
        let d = Dispatcher::new(DispatchConfig::default());
        let honest = script(&linked(&d));
        let row = LinkedRow::of(echo_door).expect("the door states its Statement");
        let red = script(&load_linked::<Plane>(&row, bind(&d)).expect("the door loads"));
        let (h, r) = (
            step(&honest, "answer tools/list"),
            step(&red, "answer tools/list"),
        );
        assert_ne!(r.reply, h.reply, "the answer is where the two differ");
        assert_ne!(red, honest);
    }
}
