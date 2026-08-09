// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` GRAMMAR — the named map whose mere existence declares the mcp plane — parsed from
//! the YAML an operator actually writes, and refused for the reasons the locked named-map grammar
//! and the out-of-band pin trust root give.
//!
//! Every test here goes through `serde_yaml` rather than constructing the struct, because the thing
//! under test IS the grammar: a test that built `McpServerDefCfg` directly would skip the custom
//! `Deserialize` where the reserved keys, the section knobs and the value rules all live.

use super::{ToolsCfg, RESERVED_TOOLS_SECTION_KEYS};

fn parse(yaml: &str) -> Result<ToolsCfg, String> {
    serde_yaml::from_str::<ToolsCfg>(yaml).map_err(|e| e.to_string())
}

/// THE LOCKED SECTION SHAPE, verbatim: the section knobs, the object pin, the
/// `tools_allow` MAP, the per-server credential mode and the bare-name hook attach.
const LOCKED_EXAMPLE: &str = r#"
hooks: [mcp-sanitizer]
filesystem:
  url: "https://mcp.internal/fs"
  pin: { mechanism: cert_spki, key: "sha256/PIN==" }
  tools_allow: { read_file: {} }
  upstream_credentials: own
  hooks: [mcp-sanitizer, dispatch-order]
"#;

#[test]
fn the_locked_section_shape_parses_into_the_values_it_declares() {
    let cfg = parse(LOCKED_EXAMPLE).expect("the §5.1 locked example must parse");
    assert_eq!(cfg.all_server_hooks, vec!["mcp-sanitizer".to_string()]);
    assert_eq!(cfg.servers.len(), 1, "one server, and `hooks:` is not one");
    let fs = &cfg.servers["filesystem"];
    assert_eq!(fs.url, "https://mcp.internal/fs");
    assert_eq!(fs.pin.mechanism.token(), "cert_spki");
    assert_eq!(fs.pin.key.as_deref(), Some("sha256/PIN=="));
    // THE MAP, not a list: `read_file` has a SLOT, and it is empty, which is "allowed, no hash
    // approved yet". A list could not have expressed the slot at all.
    assert!(fs.tools_allow.contains_key("read_file"));
    assert_eq!(fs.tools_allow["read_file"].schema_hash, None);
    // LIST ⇒ ADDITIVE, deduped: the section attach plus the server's own, the shared name once.
    assert_eq!(
        cfg.effective_hooks("filesystem"),
        vec!["mcp-sanitizer".to_string(), "dispatch-order".to_string()]
    );
    // SCALAR ⇒ OVERRIDE.
    assert_eq!(
        cfg.effective_upstream_credentials("filesystem"),
        Some(crate::auth::UpstreamCreds::Own)
    );
}

/// The reserved word space does NOT vary per plane. Pinned to the pool plane's own constant rather
/// than to a copy of its contents: an operator who learns the rule once must not discover that a
/// name legal on one plane is a section knob on another.
#[test]
fn the_reserved_section_words_are_identical_to_the_pool_planes() {
    assert_eq!(
        RESERVED_TOOLS_SECTION_KEYS,
        crate::config::RESERVED_POOLS_SECTION_KEYS,
        "the two reserved section words are one word space across every plane (§5.1)"
    );
}

#[test]
fn a_server_may_not_be_named_with_a_reserved_section_word() {
    for reserved in RESERVED_TOOLS_SECTION_KEYS {
        let yaml =
            format!("{reserved}:\n  url: \"https://x/\"\n  pin: {{ mechanism: unpinned }}\n");
        let err = parse(&yaml).expect_err("a reserved name holding a mapping must be refused");
        assert!(
            err.contains("RESERVED"),
            "the refusal must name the real problem, got: {err}"
        );
    }
}

/// The pin IS the authenticity root, so the mechanism is checked against the MATERIAL it needs, in
/// both directions: a keyed mechanism with no key protects nothing, and `unpinned` carrying key
/// material reads as protection that is not there. This is the rule the object pin form exists to
/// make expressible, and a scalar `spki_pin:` could state neither half of it.
#[test]
fn a_pin_must_carry_exactly_the_material_its_mechanism_needs() {
    for mech in ["pinned_pubkey", "cert_spki", "mtls"] {
        let yaml = format!("s:\n  url: \"https://x/\"\n  pin: {{ mechanism: {mech} }}\n");
        let err = parse(&yaml).expect_err("a keyed mechanism with no key is not a pin");
        assert!(
            err.contains("needs `pin.key:`"),
            "for {mech}, the refusal must say what is missing, got: {err}"
        );
    }
    let err = parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned, key: \"k\" }\n")
        .expect_err("`unpinned` carrying key material reads as protection that does not exist");
    assert!(err.contains("must not carry `pin.key:`"), "got: {err}");

    // And the legal shapes are legal, so the rule is a rule and not a blanket refusal.
    parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n")
        .expect("unpinned is legal");
    parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: mtls, key: \"k\" }\n")
        .expect("mtls with material is legal");
}

/// THE SEPARATOR RULE, and the asymmetry in it.
///
/// `{server}_{tool}` IS the routing key — the bound identity busbar dispatches on — while the locked
/// config example writes a tool named `read_file`. Both hold only if ONE half is separator-free, and
/// the spec constrains neither.
/// busbar constrains the SERVER ID: an operator-chosen registry label is free to rename, an upstream
/// tool name is not. This test pins both halves of that decision, because relaxing either one
/// silently re-opens the grant collision.
#[test]
fn the_namespace_separator_is_refused_in_a_server_id_and_allowed_in_a_tool_name() {
    let err = parse("my_server:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n")
        .expect_err("a server id carrying the separator is ambiguous");
    assert!(err.contains("namespaced routing key"), "got: {err}");
    assert!(
        err.contains("my-server"),
        "the refusal must suggest a legal spelling: {err}"
    );

    // Straight out of the locked example. Refusing it would make busbar unable to front the very
    // config shape this plane is specified around.
    parse("fs:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  tools_allow: { read_file: {} }\n")
        .expect("a tool name may carry the separator — §5.1's locked example does");

    // THE COLLISION the server-id rule prevents, stated as the arithmetic it is. `a_b` + `c` and
    // `a` + `b_c` render the SAME grant value; with `a_b` unregistrable, only one of the two pairs
    // can exist, and the key splits exactly one way at the FIRST separator.
    assert_eq!(
        super::super::catalogue::namespaced("a_b", "c"),
        super::super::catalogue::namespaced("a", "b_c"),
        "if this equality ever stops holding, the server-id rule can be relaxed — and not before"
    );
    assert_ne!(
        super::super::catalogue::namespaced("a", "b_c"),
        super::super::catalogue::namespaced("a", "b-c"),
        "and two tools on ONE server never collide, whatever they are called"
    );
}

/// DENY-BY-DEFAULT is the `Default` impl, not a rule written down somewhere else and remembered at
/// each call site. A registry entry that names no grants grants nothing.
#[test]
fn server_initiated_grants_default_to_denied() {
    let cfg = parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n").unwrap();
    let g = cfg.servers["s"].grants;
    assert!(!g.sampling && !g.elicitation && !g.roots);
    for kind in ["sampling", "elicitation", "roots", "some_future_ask"] {
        assert!(
            !g.allows(kind),
            "an unwritten grant must deny `{kind}` — including a kind this build has never heard of"
        );
    }
    // And a granted one is granted, so the default is a default and not a hardcoded refusal.
    let cfg = parse(
        "s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  grants: { sampling: true }\n",
    )
    .unwrap();
    let g = cfg.servers["s"].grants;
    assert!(g.allows("sampling"));
    assert!(!g.allows("elicitation") && !g.allows("roots"));
}

/// A transport nothing implements must fail at BOOT, where the operator who typed it is standing,
/// rather than at the first dispatch an hour later.
#[test]
fn an_unimplemented_transport_is_refused_at_parse() {
    let err =
        parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  transport: stdio\n")
            .expect_err("stdio has no supervisor in this build");
    assert!(
        err.contains("not implemented in this release"),
        "got: {err}"
    );
    parse(
        "s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  transport: streamable_http\n",
    )
    .expect("the implemented transport is accepted");
}

/// A typo'd key must fail boot rather than silently un-pinning a server. `deny_unknown_fields`, and
/// this test is what keeps it on.
#[test]
fn an_unknown_key_is_refused_rather_than_ignored() {
    let err =
        parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  tols_allow: {}\n")
            .expect_err("a typo must not be absorbed");
    assert!(err.contains("tols_allow"), "the typo must be named: {err}");
}

/// ONE GRAMMAR, TWO PATHS — the defect `NamedMapSection::parse_def` was written to close.
///
/// The admin write path and the config file must have IDENTICAL reject sets. Asserted as SET
/// EQUALITY over a battery of documents rather than by spot-checking one, so a rule that lands on
/// one path only shows up here as a difference rather than as a test nobody wrote.
#[test]
fn the_admin_write_path_rejects_exactly_what_the_file_rejects() {
    use crate::config::named_map::NamedMapSection;

    // (name, definition document). Half must be accepted, half refused; which is which is decided by
    // the two paths, never by this list — the list only has to COVER every rule.
    let battery: &[(&str, serde_json::Value)] = &[
        (
            "ok-minimal",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" } }),
        ),
        (
            "ok-full",
            serde_json::json!({
                "url": "https://x/",
                "pin": { "mechanism": "cert_spki", "key": "sha256/K=" },
                "tools_allow": { "read": { "schema_hash": "sha256:a" } },
                "prompts_allow": { "greet": { "template": "hi" } },
                "resources_allow": { "file:///a": { "text": "x" } },
                "transport": "streamable_http",
                "aud": "https://up.example/mcp",
                "grants": { "sampling": true },
                "max_input_required_rounds": 1,
                "upstream_credentials": "own"
            }),
        ),
        (
            "bad-no-key",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "mtls" } }),
        ),
        (
            "bad-unpinned-with-key",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned", "key": "k" } }),
        ),
        (
            "bad-scheme",
            serde_json::json!({ "url": "ftp://x/", "pin": { "mechanism": "unpinned" } }),
        ),
        (
            "bad-stdio",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" }, "transport": "stdio" }),
        ),
        (
            "bad-unknown-field",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" }, "nope": 1 }),
        ),
        (
            "bad-aud",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" }, "aud": "urn:x" }),
        ),
        (
            "bad-dotted-hook",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" }, "hooks": ["pools.fast"] }),
        ),
        (
            "ok-separator-in-tool",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" }, "tools_allow": { "read_file": {} } }),
        ),
        (
            "bad_separator_in_id",
            serde_json::json!({ "url": "https://x/", "pin": { "mechanism": "unpinned" } }),
        ),
    ];
    // A floor on the discovered set: an empty or truncated battery would make the set equality below
    // hold vacuously, which is exactly the false green the standing rules name.
    assert!(
        battery.len() >= 11,
        "the battery must actually cover the rules; got {}",
        battery.len()
    );

    let mut file_rejects: Vec<&str> = Vec::new();
    let mut api_rejects: Vec<&str> = Vec::new();
    for (name, def) in battery {
        // THE FILE PATH: the same YAML an operator writes, through the section's own `Deserialize`.
        let yaml = serde_yaml::to_string(&serde_json::json!({ *name: def })).unwrap();
        if parse(&yaml).is_err() {
            file_rejects.push(name);
        }
        // THE ADMIN WRITE PATH: the typed parse the generic handler runs before it persists.
        if NamedMapSection::Tools.validate_def(name, def).is_err() {
            api_rejects.push(name);
        }
    }
    assert_eq!(
        file_rejects, api_rejects,
        "one grammar, two paths: the API must reject EXACTLY what config.yaml rejects"
    );
    // And the two sets are non-trivial in both directions — all-accept or all-reject would satisfy
    // the equality above while proving nothing.
    assert!(
        !file_rejects.is_empty() && file_rejects.len() < battery.len(),
        "the battery must contain both accepted and refused documents; refused: {file_rejects:?}"
    );
}
