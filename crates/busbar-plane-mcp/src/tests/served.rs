//! Tests for `served.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! ## Why three of these read another crate's source
//!
//! The two console-era answers were WRITTEN inside `busbar-mcp`'s console serve loop, in private
//! functions of a crate this one's manifest does not name and must not. The move is only honest if
//! the two are the same document, and the only way to say so from here is to read the source the
//! other one is written in. That is the pin this crate's header describes: a copy that is checked is
//! not a second opinion.
//!
//! It is a text read and it is deliberately narrow — the members and their values, one at a time,
//! not a whole-file digest. A digest would go red on a comment; these go red on a byte of the wire.

use busbar_contract::ids::OpClassId;

use super::{
    cache_hints, initialize_result, instructions, ping_result, reads, tool_call_result,
    tools_list_result, Reads, ANSWERED, CACHE_SCOPE, CACHE_TTL_MS, PROTOCOL_VERSION, SERVER_NAME,
};
use crate::{ops, records};

/// The console serve loop this module's two constant answers were moved out of.
const CONSOLE_SOURCE: &str = include_str!("../../../busbar-mcp/src/mcp/stdio_serve.rs");

/// The server half's method file, where the caching hints and the listing shape were written.
const METHOD_SOURCE: &str = include_str!("../../../busbar-mcp/src/mcp/method.rs");

/// The revision is the codec's own string and not a copy of it.
#[test]
fn the_revision_is_the_codecs_own() {
    assert_eq!(PROTOCOL_VERSION, busbar_mcp_codec::codec::PROTOCOL_VERSION);
}

/// Every member of the handshake document is the one the console loop writes, value included.
///
/// Read member by member off the answer this module composes, then looked for in the loop's own
/// source. A member this module invented would not be found there; a value it changed would be found
/// under a different spelling.
#[test]
fn the_handshake_is_the_console_loops_own() {
    let answer = initialize_result("9.9.9");
    let object = answer.as_object().expect("the handshake is a document");

    assert_eq!(object["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(object["serverInfo"]["name"], SERVER_NAME);
    // The version is the NODE's, handed in. That is the one thing the move changed, and it changed
    // because `env!("CARGO_PKG_VERSION")` read in a different crate is a different number.
    assert_eq!(object["serverInfo"]["version"], "9.9.9");

    // The five capability members, each with the value the loop declares.
    let capabilities = &object["capabilities"];
    assert_eq!(
        capabilities["tools"],
        serde_json::json!({"listChanged": true})
    );
    assert_eq!(
        capabilities["prompts"],
        serde_json::json!({"listChanged": true})
    );
    assert_eq!(
        capabilities["resources"],
        serde_json::json!({"listChanged": true, "subscribe": true})
    );
    assert_eq!(capabilities["completions"], serde_json::json!({}));
    assert_eq!(capabilities["logging"], serde_json::json!({}));
    assert_eq!(
        capabilities
            .as_object()
            .expect("capabilities is a document")
            .len(),
        5,
        "the handshake declares a capability the console loop does not"
    );

    // And the same five, found in the loop's own source beside the handshake it belongs to.
    for fragment in [
        "\"protocolVersion\": PROTOCOL_VERSION",
        "\"tools\": { \"listChanged\": true }",
        "\"prompts\": { \"listChanged\": true }",
        "\"resources\": { \"listChanged\": true, \"subscribe\": true }",
        "\"completions\": {}",
        "\"logging\": {}",
        "\"name\": \"busbar\"",
    ] {
        assert!(
            CONSOLE_SOURCE.contains(fragment),
            "the console loop no longer writes {fragment}"
        );
    }
}

/// The sentence the handshake carries is the console loop's own, word for word.
///
/// Its own test because it is the one member that is FORMATTED: the loop writes it across three
/// source lines with a continuation, so the comparison is over the words rather than over the
/// literal. Each phrase is long enough that a rewording moves it.
#[test]
fn the_instructions_are_the_console_loops_own() {
    let said = instructions();
    assert!(said.starts_with("This server speaks MCP revision "));
    assert!(said.contains(PROTOCOL_VERSION));
    for phrase in [
        "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required,",
        "and every request states its protocol version and client capabilities in",
        "`params._meta`.",
    ] {
        assert!(
            CONSOLE_SOURCE.contains(phrase),
            "the console loop no longer says: {phrase}"
        );
    }
}

/// The liveness answer is the empty document, here and there.
#[test]
fn the_liveness_answer_is_empty() {
    assert_eq!(ping_result(), serde_json::json!({}));
    assert!(
        CONSOLE_SOURCE.contains("\"ping\" => return Some(json_result(id, serde_json::json!({})))"),
        "the console loop no longer answers ping with the empty document"
    );
}

/// The caching hints are the pair the server half writes, under the names it writes them.
#[test]
fn the_cache_hints_are_the_server_halfs_own() {
    let hinted = cache_hints(serde_json::json!({ "tools": [] }));
    assert_eq!(hinted["cacheScope"], CACHE_SCOPE);
    assert_eq!(hinted["ttlMs"], CACHE_TTL_MS);
    for fragment in [
        "const CACHE_SCOPE: &str = \"private\";",
        "const CACHE_TTL_MS: i64 = 0;",
        "obj.insert(\"cacheScope\".into(), CACHE_SCOPE.into());",
        "obj.insert(\"ttlMs\".into(), CACHE_TTL_MS.into());",
    ] {
        assert!(
            METHOD_SOURCE.contains(fragment),
            "the server half no longer writes {fragment}"
        );
    }
}

/// A value that is not a document is handed back untouched.
#[test]
fn a_hint_is_only_added_to_a_document() {
    assert_eq!(
        cache_hints(serde_json::json!([1, 2])),
        serde_json::json!([1, 2])
    );
    assert_eq!(
        cache_hints(serde_json::json!(null)),
        serde_json::json!(null)
    );
}

/// The listing is the tools handed in, under the member the server half writes, with the hints.
#[test]
fn the_listing_is_the_server_halfs_shape() {
    let listed = tools_list_result(vec![serde_json::json!({"name": "a"})]);
    assert_eq!(listed["tools"], serde_json::json!([{"name": "a"}]));
    assert_eq!(listed["cacheScope"], CACHE_SCOPE);
    assert_eq!(listed["ttlMs"], CACHE_TTL_MS);
    assert_eq!(
        listed.as_object().expect("a listing is a document").len(),
        3,
        "the listing carries a member the server half does not write"
    );
    assert!(
        METHOD_SOURCE.contains("result(id, cache_hints(serde_json::json!({ \"tools\": tools })))"),
        "the server half no longer composes its listing this way"
    );
    // A caller whose grant reaches nothing gets the empty list rather than an error.
    assert_eq!(
        tools_list_result(Vec::new())["tools"],
        serde_json::json!([])
    );
}

/// A call's answer carries NO caching hint, and is otherwise the upstream's own document.
///
/// The absence is the assertion: a hint here would invite a client to reuse the answer to an effect.
#[test]
fn a_call_is_not_cacheable() {
    let answered = tool_call_result(serde_json::json!({"content": []}));
    assert_eq!(answered, serde_json::json!({"content": []}));
    assert!(answered.get("cacheScope").is_none());
    assert!(answered.get("ttlMs").is_none());
}

/// Every class this module answers is a class the plane declares, and every one has a reading.
#[test]
fn every_answered_class_is_declared_and_read() {
    for op in ANSWERED {
        assert!(
            ops::OP_CLASSES.contains(op),
            "{op} is answered and is not a declared class"
        );
        assert!(reads(*op).is_some(), "{op} is answered and reads nothing");
    }
    assert_eq!(ANSWERED.len(), 4, "this stage answers the first four");
}

/// A class this stage does not answer says so, rather than being read as reading nothing.
#[test]
fn an_unanswered_class_has_no_reading() {
    for op in [
        ops::OP_DISCOVER,
        ops::OP_PROMPTS_LIST,
        ops::OP_RESOURCE_READ,
        ops::OP_NOTIFICATION,
        ops::OP_SAMPLING,
    ] {
        assert_eq!(reads(op), None, "{op} has a reading this stage cannot run");
    }
    assert_eq!(reads(OpClassId::new("not_a_class")), None);
}

/// The two constant answers read nothing, and say so.
#[test]
fn the_constant_answers_read_nothing() {
    assert_eq!(reads(ops::OP_INITIALIZE), Some(Reads::Nothing));
    assert_eq!(reads(ops::OP_PING), Some(Reads::Nothing));
    assert!(Reads::Nothing.legs().is_empty());
}

/// Every leg a reading names is a leg the plane's own plan for that class runs.
///
/// The containment in the ONE direction it holds. The plan is the single source for what a unit
/// runs; a reading naming a leg the plan never runs would be an answer assembled from a record
/// nobody read, and this is what makes that red rather than empty.
#[test]
fn every_named_leg_is_a_planned_leg() {
    for op in ANSWERED {
        let Some(reading) = reads(*op) else {
            unreachable!("every answered class has a reading")
        };
        for (schema, operation) in reading.legs() {
            assert!(
                records::operations_for(*schema).contains(operation),
                "{op} names {operation} on {schema}, which the schema does not declare"
            );
        }
    }
}

/// The two readings that touch records name the schemas their own names claim.
#[test]
fn the_readings_name_the_schemas_they_say_they_do() {
    let snapshot: Vec<&str> = Reads::CatalogueSnapshot
        .legs()
        .iter()
        .map(|(schema, _)| schema.as_str())
        .collect();
    assert_eq!(
        snapshot,
        vec![
            records::SCHEMA_CATALOGUE.as_str(),
            records::SCHEMA_DEMOTION.as_str()
        ]
    );
    let registry: Vec<&str> = Reads::ServerRegistry
        .legs()
        .iter()
        .map(|(schema, _)| schema.as_str())
        .collect();
    assert_eq!(
        registry,
        vec![
            records::SCHEMA_CATALOGUE.as_str(),
            records::SCHEMA_DEMOTION.as_str()
        ]
    );
    // A listing SCANS and a call GETS: the two readings differ in the operation, not only in the
    // schema, and reading a listing with a get would answer one record where a caller asked for all
    // of them.
    assert!(Reads::CatalogueSnapshot
        .legs()
        .iter()
        .all(|(_, op)| *op == records::OP_SCAN));
    assert!(Reads::ServerRegistry
        .legs()
        .iter()
        .all(|(_, op)| *op == records::OP_GET));
}
