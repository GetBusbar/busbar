// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PAYLOADS, FED HOSTILE INPUT.
//!
//! These are the payloads of the two methods the plane is made of, CATALOGUE (`tools/list`) and
//! DISPATCH (`tools/call`), plus the handshake that precedes them. They are OUR structs, mirrored
//! from the specification by hand, and the tests below are as much about what we refuse to believe
//! from a server as about what we read from it.

use super::super::spec::{
    CataloguePage, ContentBlock, DispatchParams, DispatchResult, InitializeParams,
    InitializeResult, SpecError, ToolDefinition, LATEST_PROTOCOL_VERSION, METHOD_CATALOGUE,
    METHOD_DISPATCH, METHOD_INITIALIZE, NOTIFY_CATALOGUE_CHANGED, NOTIFY_INITIALIZED,
};
use serde_json::json;

#[test]
fn the_method_names_are_the_wire_spellings() {
    // The project's vocabulary is CATALOGUE and DISPATCH; the wire's is `tools/list` and
    // `tools/call`. This is the one place both are written down, so the translation happens once.
    assert_eq!(METHOD_CATALOGUE, "tools/list");
    assert_eq!(METHOD_DISPATCH, "tools/call");
    assert_eq!(METHOD_INITIALIZE, "initialize");
    assert_eq!(NOTIFY_INITIALIZED, "notifications/initialized");
    assert_eq!(NOTIFY_CATALOGUE_CHANGED, "notifications/tools/list_changed");
}

// The catalogue page ------------------------------------------------------------------------------

#[test]
fn a_catalogue_page_carries_its_tools_and_its_cursor() {
    let page = CataloguePage::parse(&json!({
        "tools": [{
            "name": "read_file",
            "title": "Read a file",
            "description": "Reads a file",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            "outputSchema": {"type": "object"}
        }],
        "nextCursor": "page-2"
    }))
    .expect("a well-formed page parses");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "read_file");
    assert_eq!(page.tools[0].title.as_deref(), Some("Read a file"));
    assert_eq!(page.tools[0].description.as_deref(), Some("Reads a file"));
    assert!(page.tools[0].output_schema.is_some());
    assert_eq!(page.next_cursor.as_deref(), Some("page-2"));
}

#[test]
fn a_catalogue_page_with_no_tools_is_a_page_not_an_error() {
    let page = CataloguePage::parse(&json!({"tools": []})).expect("parses");
    assert!(page.tools.is_empty());
    assert_eq!(page.next_cursor, None);
}

#[test]
fn a_catalogue_page_without_a_tools_member_is_refused() {
    // "No tools member" and "an empty tools array" are different claims, and only the second is a
    // server saying it has no tools. Defaulting the first to the second would turn a malformed reply
    // into a silent, plausible-looking empty catalogue.
    let e = CataloguePage::parse(&json!({"nextCursor": "x"})).expect_err("refused");
    assert!(matches!(e, SpecError::Malformed(_)), "got {e:?}");
}

#[test]
fn a_tool_without_a_name_or_with_an_empty_one_is_refused() {
    for body in [
        json!({"tools": [{"inputSchema": {"type": "object"}}]}),
        json!({"tools": [{"name": "", "inputSchema": {"type": "object"}}]}),
        json!({"tools": [{"name": 7, "inputSchema": {"type": "object"}}]}),
    ] {
        let e = CataloguePage::parse(&body).expect_err("refused");
        assert!(
            matches!(e, SpecError::Malformed(_) | SpecError::EmptyToolName),
            "body {body} gave {e:?}"
        );
    }
}

#[test]
fn a_tool_whose_input_schema_is_not_an_object_is_refused() {
    // The input schema is what the dispatch path validates arguments against, and it is what the
    // schema-hash pins. A non-object there is not a schema, and accepting it would mean pinning a
    // digest of something that can never be validated.
    let e = CataloguePage::parse(&json!({
        "tools": [{"name": "read_file", "inputSchema": "a string"}]
    }))
    .expect_err("refused");
    assert!(matches!(e, SpecError::SchemaNotAnObject(_)), "got {e:?}");
}

#[test]
fn a_tool_with_no_input_schema_at_all_is_refused() {
    let e = CataloguePage::parse(&json!({"tools": [{"name": "read_file"}]})).expect_err("refused");
    assert!(matches!(e, SpecError::Malformed(_)), "got {e:?}");
}

#[test]
fn a_page_offering_the_same_tool_name_twice_is_refused() {
    // The server is the one being ambiguous here, and there is no correct way to pick. Taking the
    // first (or the last) means the tool a caller reaches depends on the ORDER a server listed them
    // in, which is a routing decision made by the untrusted party.
    let e = CataloguePage::parse(&json!({
        "tools": [
            {"name": "read_file", "inputSchema": {"type": "object"}},
            {"name": "read_file", "inputSchema": {"type": "object", "extra": true}}
        ]
    }))
    .expect_err("refused");
    assert_eq!(e, SpecError::DuplicateTool("read_file".into()));
}

#[test]
fn a_next_cursor_that_is_not_a_string_is_refused() {
    let e = CataloguePage::parse(&json!({"tools": [], "nextCursor": 2})).expect_err("refused");
    assert!(matches!(e, SpecError::Malformed(_)), "got {e:?}");
}

#[test]
fn an_unknown_member_on_a_tool_does_not_stop_it_parsing() {
    let page = CataloguePage::parse(&json!({
        "tools": [{"name": "read_file", "inputSchema": {"type": "object"}, "somethingNew": 1}]
    }))
    .expect("a newer server is not a hostile one");
    assert_eq!(page.tools.len(), 1);
}

#[test]
fn the_cursor_becomes_the_params_of_the_next_catalogue_request() {
    // The cursor is opaque and belongs to the server; all we do with it is hand it straight back.
    // Rebuilding it, or reading it, would be inventing meaning in a value we were told not to.
    let page = CataloguePage::parse(&json!({"tools": [], "nextCursor": "p2"})).expect("parses");
    assert_eq!(page.next_params(), Some(json!({"cursor": "p2"})));
    let last = CataloguePage::parse(&json!({"tools": []})).expect("parses");
    assert_eq!(last.next_params(), None);
}

// Dispatch ----------------------------------------------------------------------------------------

#[test]
fn dispatch_params_name_the_tool_and_carry_its_arguments() {
    let p = DispatchParams::new("read_file", Some(json!({"path": "/etc/hosts"})));
    assert_eq!(
        p.to_value(),
        json!({"name": "read_file", "arguments": {"path": "/etc/hosts"}})
    );
    // Absent arguments stay absent rather than becoming an empty object: a server may distinguish
    // them, and inventing a member is a change to the request we were asked to make.
    assert_eq!(
        DispatchParams::new("ping", None).to_value(),
        json!({"name": "ping"})
    );
}

#[test]
fn a_dispatch_result_reads_its_content_blocks() {
    let r = DispatchResult::parse(&json!({
        "content": [
            {"type": "text", "text": "hello"},
            {"type": "image", "data": "aGk=", "mimeType": "image/png"}
        ]
    }))
    .expect("parses");
    assert!(!r.is_error);
    assert_eq!(r.content.len(), 2);
    assert_eq!(
        r.content[0],
        ContentBlock::Text {
            text: "hello".into()
        }
    );
    assert_eq!(
        r.content[1],
        ContentBlock::Image {
            data: "aGk=".into(),
            mime_type: "image/png".into()
        }
    );
}

#[test]
fn a_tool_error_is_a_result_not_a_transport_failure() {
    // `isError` is the tool saying it failed, which is data the caller must see. A JSON-RPC error is
    // the SERVER saying the call could not be made. Collapsing the two loses the tool's own message.
    let r = DispatchResult::parse(&json!({
        "content": [{"type": "text", "text": "no such file"}],
        "isError": true
    }))
    .expect("parses");
    assert!(r.is_error);
    assert_eq!(r.content.len(), 1);
}

#[test]
fn an_unknown_content_type_is_preserved_rather_than_dropped() {
    // Dropping it would silently hide part of a tool's output from the caller and from the audit
    // record. The block is kept whole, with its type, so a newer server's content survives us.
    let r = DispatchResult::parse(&json!({
        "content": [{"type": "hologram", "frames": 3}]
    }))
    .expect("parses");
    match &r.content[0] {
        ContentBlock::Other { kind, raw } => {
            assert_eq!(kind, "hologram");
            assert_eq!(raw, &json!({"type": "hologram", "frames": 3}));
        }
        other => panic!("expected the preserved arm, got {other:?}"),
    }
}

#[test]
fn a_dispatch_result_without_a_content_array_is_refused() {
    for body in [
        json!({}),
        json!({"content": "text"}),
        json!({"content": {}}),
    ] {
        let e = DispatchResult::parse(&body).expect_err("refused");
        assert!(
            matches!(e, SpecError::Malformed(_)),
            "body {body} gave {e:?}"
        );
    }
}

#[test]
fn a_content_block_with_no_type_is_refused() {
    let e = DispatchResult::parse(&json!({"content": [{"text": "hi"}]})).expect_err("refused");
    assert!(matches!(e, SpecError::Malformed(_)), "got {e:?}");
}

#[test]
fn a_text_block_missing_its_text_is_refused_rather_than_read_as_empty() {
    let e = DispatchResult::parse(&json!({"content": [{"type": "text"}]})).expect_err("refused");
    assert!(matches!(e, SpecError::Malformed(_)), "got {e:?}");
}

#[test]
fn structured_content_is_carried_through_untouched() {
    let r = DispatchResult::parse(&json!({
        "content": [],
        "structuredContent": {"rows": [1, 2, 3]}
    }))
    .expect("parses");
    assert_eq!(r.structured_content, Some(json!({"rows": [1, 2, 3]})));
}

// The handshake -----------------------------------------------------------------------------------

#[test]
fn initialize_params_state_our_version_and_who_we_are() {
    let p = InitializeParams::new("busbar", "9.9.9");
    let v = p.to_value();
    assert_eq!(v["protocolVersion"], json!(LATEST_PROTOCOL_VERSION));
    assert_eq!(v["clientInfo"]["name"], json!("busbar"));
    assert_eq!(v["clientInfo"]["version"], json!("9.9.9"));
    assert!(v["capabilities"].is_object());
}

#[test]
fn an_initialize_result_reports_the_version_the_server_chose() {
    let r = InitializeResult::parse(&json!({
        "protocolVersion": LATEST_PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": true}},
        "serverInfo": {"name": "fs", "version": "0.1"}
    }))
    .expect("parses");
    assert_eq!(r.protocol_version, LATEST_PROTOCOL_VERSION);
    assert_eq!(r.server_name.as_deref(), Some("fs"));
    assert!(r.offers_catalogue_change_notifications);
}

#[test]
fn a_protocol_version_we_do_not_speak_is_refused_before_anything_else_happens() {
    // The handshake is where a version mismatch is cheap. Proceeding on an unknown version means
    // reading later payloads under rules that may not be the ones the server is using, and the
    // failure would then look like a data problem rather than a version problem.
    let e = InitializeResult::parse(&json!({
        "protocolVersion": "2099-01-01",
        "capabilities": {},
        "serverInfo": {"name": "fs", "version": "0.1"}
    }))
    .expect_err("refused");
    assert_eq!(
        e,
        SpecError::UnsupportedProtocolVersion("2099-01-01".into())
    );
}

#[test]
fn an_initialize_result_with_no_version_is_refused() {
    let e = InitializeResult::parse(&json!({"capabilities": {}})).expect_err("refused");
    assert!(matches!(e, SpecError::Malformed(_)), "got {e:?}");
}

#[test]
fn a_server_that_advertises_no_tools_capability_offers_no_change_notifications() {
    let r = InitializeResult::parse(&json!({
        "protocolVersion": LATEST_PROTOCOL_VERSION,
        "capabilities": {}
    }))
    .expect("parses");
    assert!(!r.offers_catalogue_change_notifications);
    assert_eq!(r.server_name, None);
}

#[test]
fn a_tool_definition_is_our_struct_and_survives_a_round_trip_through_the_wire_shape() {
    let t = ToolDefinition {
        name: "read_file".into(),
        title: None,
        description: Some("Reads a file".into()),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
    };
    let page = CataloguePage::parse(&json!({"tools": [t.to_value()]})).expect("parses");
    assert_eq!(page.tools[0], t);
}
