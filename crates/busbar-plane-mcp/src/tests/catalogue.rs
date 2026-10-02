// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The catalogue answers as the served engine does: both grants for every capability, the
//! published name, the normalised description, the caching hints, and an approval visible from the
//! generation that carries it and no earlier one.

use serde_json::{json, Value};

use super::*;

/// Two servers: `fs` with an approved tool, a pending tool, a renamed tool, a prompt, a resource
/// and a template; `db` with one approved tool.
const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {
      "read_file": {"schema_hash": "sha256:aa", "description": "Reads <b>a</b> file."},
      "write_file": {},
      "stat": {"schema_hash": "  ", "publish_as": "file_stat"}
    },
    "prompts_allow": {"summarise": {"description": "Summarise."}},
    "resources_allow": {"file:///readme": {"name": "readme", "mime_type": "text/plain", "text": "hi"}},
    "resource_templates_allow": {"file:///logs/{date}": {"name": "log", "text": "log {date}"}}
  },
  "db": {
    "url": "https://mcp.example/db",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"query": {"schema_hash": "sha256:bb"}}
  }
}"#;

fn catalogue(generation: u64, section: &[u8]) -> Catalogue {
    Catalogue::build(
        generation,
        &crate::door::read_settings(section).expect("the section reads"),
    )
}

/// A caller holding exactly `grants`, each `kind:name`.
fn holding(grants: &'static [&'static str]) -> impl Fn(&str, &str) -> bool {
    move |kind, name| grants.contains(&format!("{kind}:{name}").as_str())
}

fn everyone(_: &str, _: &str) -> bool {
    true
}

fn read(bytes: Vec<u8>) -> Value {
    serde_json::from_slice(&bytes).expect("a document")
}

fn names(listing: &Value, member: &str, key: &str) -> Vec<String> {
    listing["result"][member]
        .as_array()
        .expect("a list")
        .iter()
        .map(|e| e[key].as_str().expect("a string").to_string())
        .collect()
}

/// Every capability is listed under its published name, in published-name order, pending ones
/// included, and each is rendered as the served engine renders it.
#[test]
fn the_whole_catalogue_is_listed_under_published_names_pending_included() {
    let c = catalogue(1, SECTION);
    let tools = read(c.tools_list(&json!(1), &everyone, |_| false));
    assert_eq!(
        names(&tools, "tools", "name"),
        ["db_query", "file_stat", "fs_read_file", "fs_write_file"]
    );
    let read_file = &tools["result"]["tools"][2];
    assert_eq!(read_file["description"], "Reads a file.");
    assert_eq!(read_file["inputSchema"], json!({"type": "object"}));
    assert_eq!(
        read_file["_meta"],
        json!({"io.busbar/schemaHash": "sha256:aa"})
    );
    // A pending tool, and a blank hash, publish no hash.
    assert!(tools["result"]["tools"][3].get("_meta").is_none());
    assert!(tools["result"]["tools"][1].get("_meta").is_none());
    assert_eq!(c.tool("file_stat").map(|t| t.tool.as_str()), Some("stat"));
}

/// Every listing is a complete, cacheable result: the id echoed, `resultType`, and both hints.
#[test]
fn every_listing_is_a_complete_cacheable_result() {
    let c = catalogue(1, SECTION);
    for listing in [
        c.tools_list(&json!("a"), &everyone, |_| false),
        c.prompts_list(&json!("a"), &everyone),
        c.resources_list(&json!("a"), &everyone),
        c.resource_templates_list(&json!("a"), &everyone),
    ] {
        let v = read(listing);
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], "a");
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(v["result"]["cacheScope"], CACHE_SCOPE);
        assert_eq!(v["result"]["ttlMs"], CACHE_TTL_MS);
    }
}

/// Two grants see two different catalogues and a third sees none.
#[test]
fn two_grants_see_two_catalogues_and_a_third_sees_none() {
    let c = catalogue(1, SECTION);
    let fs = holding(&["mcp_server:fs", "mcp_tool:fs_read_file"]);
    let db = holding(&["mcp_server:db", "mcp_tool:db_query"]);
    let none = holding(&[]);
    let list = |admit: &dyn Fn(&str, &str) -> bool| {
        names(
            &read(c.tools_list(&json!(1), &|k, n| admit(k, n), |_| false)),
            "tools",
            "name",
        )
    };
    assert_eq!(list(&fs), ["fs_read_file"]);
    assert_eq!(list(&db), ["db_query"]);
    assert!(list(&none).is_empty());
}

/// The server grant alone reaches nothing, and the capability grant alone reaches nothing: both
/// are asked for every kind of capability.
#[test]
fn the_server_grant_and_the_capability_grant_are_both_required() {
    let c = catalogue(1, SECTION);
    let halves: [&'static [&'static str]; 2] = [
        &["mcp_server:fs"],
        &["mcp_tool:fs_read_file", "mcp_tool:fs_summarise"],
    ];
    for half in halves {
        let admit = holding(half);
        assert!(c.tools_for(&admit).is_empty());
        assert!(c.prompts_for(&admit).is_empty());
        assert!(c.resources_for(&admit).is_empty());
        assert!(c.resource_templates_for(&admit).is_empty());
    }
    let prompt = holding(&["mcp_server:fs", "mcp_tool:fs_summarise"]);
    assert_eq!(c.prompts_for(&prompt).len(), 1);
    // The grant value of a resource is its namespaced uri; the wire carries the raw one.
    let resource = holding(&["mcp_server:fs", "mcp_tool:fs_file:///readme"]);
    let listed = read(c.resources_list(&json!(1), &resource));
    assert_eq!(names(&listed, "resources", "uri"), ["file:///readme"]);
    assert_eq!(listed["result"]["resources"][0]["mimeType"], "text/plain");
}

/// A caller reaching no template gets the empty list, never a refusal.
#[test]
fn a_caller_reaching_no_template_gets_an_empty_list() {
    let c = catalogue(1, SECTION);
    let v = read(c.resource_templates_list(&json!(1), &holding(&[])));
    assert_eq!(v["result"]["resourceTemplates"], json!([]));
    let all = read(c.resource_templates_list(&json!(1), &everyone));
    assert_eq!(
        names(&all, "resourceTemplates", "uriTemplate"),
        ["file:///logs/{date}"]
    );
}

/// A quarantined tool is hidden; the verdict is asked only of what the grants admitted.
#[test]
fn a_quarantined_tool_is_hidden_and_only_granted_tools_are_asked() {
    let c = catalogue(1, SECTION);
    let fs = holding(&["mcp_server:fs", "mcp_tool:fs_read_file"]);
    let v = read(c.tools_list(&json!(1), &fs, |t| {
        assert_eq!(
            t.namespaced, "fs_read_file",
            "an ungranted tool is never asked"
        );
        true
    }));
    assert_eq!(v["result"]["tools"], json!([]));
}

/// An APPROVAL IS VISIBLE FROM THE GENERATION THAT CARRIES IT, AND NOT BEFORE: the hash an
/// operator approves appears in the listing built over the section that holds it, while the
/// catalogue built before it still lists the tool as pending.
#[test]
fn an_approval_is_visible_from_its_generation_and_not_before() {
    let before = catalogue(1, SECTION);
    let approved = String::from_utf8(SECTION.to_vec()).expect("utf-8").replace(
        r#""write_file": {}"#,
        r#""write_file": {"schema_hash": "sha256:cc"}"#,
    );
    let after = catalogue(2, approved.as_bytes());
    let hash = |c: &Catalogue| {
        read(c.tools_list(&json!(1), &everyone, |_| false))["result"]["tools"][3]
            .get("_meta")
            .cloned()
    };
    assert_eq!(hash(&before), None);
    assert_eq!(
        hash(&after),
        Some(json!({"io.busbar/schemaHash": "sha256:cc"}))
    );
    assert_eq!((before.generation(), after.generation()), (1, 2));
}

#[test]
fn an_empty_section_is_an_empty_registry() {
    let c = catalogue(1, b"");
    assert!(c.is_empty());
    let v = read(c.tools_list(&json!(1), &everyone, |_| false));
    assert_eq!(v["result"]["tools"], json!([]));
    assert!(!catalogue(1, SECTION).is_empty());
}
