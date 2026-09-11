//! THE CATALOGUE VIEW'S BYTES, asserted as strings.
//!
//! A projection is judged on what it puts on the wire, so every cell below compares a rendered
//! `Value` against the exact JSON the serving path writes today. `serde_json`'s map is ordered (this
//! tree does not enable `preserve_order`), so a string comparison is a comparison of the bytes a
//! client receives and not of an insertion order that happens to match.

use super::*;

#[test]
fn a_tool_with_everything_declared_renders_every_member() {
    let input = serde_json::json!({ "type": "object", "properties": {} });
    let output = serde_json::json!({ "type": "object" });
    let v = tool(&ToolView {
        name: "acme/search",
        description: Some("Search the thing"),
        input_schema: Some(&input),
        output_schema: Some(&output),
        schema_hash: Some("abc123"),
    });
    assert_eq!(
        v.to_string(),
        r#"{"_meta":{"io.busbar/schemaHash":"abc123"},"description":"Search the thing","inputSchema":{"properties":{},"type":"object"},"name":"acme/search","outputSchema":{"type":"object"}}"#
    );
}

/// An undeclared `inputSchema` is a schema-shaped answer; an undeclared `outputSchema` is ABSENT.
/// The two rules are opposite on purpose and this is the cell that says so.
#[test]
fn an_undeclared_input_schema_is_shaped_and_an_undeclared_output_schema_is_absent() {
    let v = tool(&ToolView {
        name: "acme/bare",
        description: None,
        input_schema: None,
        output_schema: None,
        schema_hash: None,
    });
    assert_eq!(
        v.to_string(),
        r#"{"inputSchema":{"type":"object"},"name":"acme/bare"}"#
    );
}

#[test]
fn a_prompt_carries_its_namespaced_name_and_nothing_it_was_not_given() {
    assert_eq!(
        prompt(&PromptView {
            name: "acme/greet",
            description: None
        })
        .to_string(),
        r#"{"name":"acme/greet"}"#
    );
    assert_eq!(
        prompt(&PromptView {
            name: "acme/greet",
            description: Some("Say hello")
        })
        .to_string(),
        r#"{"description":"Say hello","name":"acme/greet"}"#
    );
}

/// The one difference between a resource and a template is the key the address hangs under, and the
/// cell asserts exactly that by rendering the SAME view through both.
#[test]
fn a_resource_and_a_template_differ_in_one_key_and_nothing_else() {
    let v = ResourceView {
        address: "file:///x",
        name: Some("X"),
        description: Some("The x"),
        mime_type: Some("text/plain"),
    };
    assert_eq!(
        resource(&v).to_string(),
        r#"{"description":"The x","mimeType":"text/plain","name":"X","uri":"file:///x"}"#
    );
    assert_eq!(
        resource_template(&v).to_string(),
        r#"{"description":"The x","mimeType":"text/plain","name":"X","uriTemplate":"file:///x"}"#
    );
}

/// The caching hints are the same two members on all four classes, and an empty listing carries them
/// too — a value that is only correct while the registry is empty becomes wrong silently.
#[test]
fn every_listing_class_carries_the_same_two_cache_hints_even_when_empty() {
    for (got, member) in [
        (tools_result(vec![]), "tools"),
        (prompts_result(vec![]), "prompts"),
        (resources_result(vec![]), "resources"),
        (resource_templates_result(vec![]), "resourceTemplates"),
    ] {
        assert_eq!(
            got.to_string(),
            format!(r#"{{"cacheScope":"private","{member}":[],"ttlMs":0}}"#)
        );
    }
}

/// `cacheable` is the ONE place the pair is written, and a caller that hands it a non-object gets its
/// value back rather than a fabricated object — a hint has nowhere to go on a bare array.
#[test]
fn the_hints_are_stamped_on_an_object_and_never_invented_on_anything_else() {
    assert_eq!(
        cacheable(serde_json::json!({ "a": 1 })).to_string(),
        r#"{"a":1,"cacheScope":"private","ttlMs":0}"#
    );
    assert_eq!(cacheable(serde_json::json!([1])).to_string(), "[1]");
}
