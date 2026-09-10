//! Tests for `served.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! ## The last two source reads, retired
//!
//! Five of these asked their question TWICE: once of the answer this module composes, and once of
//! the SOURCE the console-era answer was written in — `include_str!` over
//! `../../../busbar-mcp/src/…`. That second half was the move-pin, and it cost what every one of
//! this directory's other source reads cost before it was retired: a coupling to a sibling crate
//! this manifest does not name and must not. It left the plane unable to be BUILT or DELETED on its
//! own, which is not a style complaint — `scripts/plane-delete-test.sh mcp` builds this crate with
//! `busbar-mcp` physically removed, and two `include_str!` lines were the whole of why that build
//! failed:
//!
//! ```text
//! error: couldn't read `crates/busbar-plane-mcp/src/tests/../../../busbar-mcp/src/mcp/stdio_serve.rs`
//! error: couldn't read `crates/busbar-plane-mcp/src/tests/../../../busbar-mcp/src/mcp/method.rs`
//! ```
//!
//! So they go, on the same terms `claims.rs`, `facts.rs`, `ops.rs` and `jsonrpc.rs` retired theirs
//! on. Every value assertion stays — each of the five already read the member and its value off
//! this module's own answer, and that half is the half that goes red on a byte of the wire. What is
//! given up is a text search for a fragment of another crate's private function, which went red on a
//! reformatting and could not have survived that crate's own deletion in any case. The two halves
//! stay pinned to one wire where a wire pin belongs: the MCP conformance battery
//! (`testing/mcp-conformance`) drives both and judges them against the same protocol.

use busbar_contract::ids::OpClassId;

use super::{
    cache_hints, initialize_result, instructions, ping_result, reads, tool_call_result,
    tools_list_result, Reads, ANSWERED, CACHE_SCOPE, CACHE_TTL_MS, PROTOCOL_VERSION, SERVER_NAME,
};
use crate::{ops, records};

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

    // And the server's own name, as the wire carries it.
    assert_eq!(SERVER_NAME, "busbar");
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
    // Each phrase is long enough that a rewording moves it, and it is asked of what this module
    // SAYS rather than of the source another crate says it in.
    for phrase in [
        "no handshake is required,",
        "and every request states its protocol version and client capabilities in",
        "`params._meta`.",
    ] {
        assert!(
            said.contains(phrase),
            "the handshake no longer says: {phrase}"
        );
    }
}

/// The liveness answer is the empty document, here and there.
#[test]
fn the_liveness_answer_is_empty() {
    assert_eq!(ping_result(), serde_json::json!({}));
}

/// The caching hints are the pair the server half writes, under the names it writes them.
#[test]
fn the_cache_hints_are_the_server_halfs_own() {
    let hinted = cache_hints(serde_json::json!({ "tools": [] }));
    assert_eq!(hinted["cacheScope"], CACHE_SCOPE);
    assert_eq!(hinted["ttlMs"], CACHE_TTL_MS);
    // The two values themselves, as the wire carries them: a scope that is not `private` or a TTL
    // that is not zero is a different caching instruction to every client that reads them.
    assert_eq!(CACHE_SCOPE, "private");
    assert_eq!(CACHE_TTL_MS, 0);
    // And nothing else is attached: a third hint would be a member no client was told to expect.
    assert_eq!(
        hinted
            .as_object()
            .expect("a hinted answer is a document")
            .len(),
        3
    );
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
