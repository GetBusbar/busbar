// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` GRAMMAR'S TYPED READING — the half of the composition root's registry-row battery
//! (`crates/busbar/src/root/tests/linked_tools.rs`) that needs the plane's own types: what the
//! section's custom `Deserialize` reads a document INTO (the values, the pin mechanisms and their
//! root-ness, the deny-by-default grants, the ask lists), the published-name invariant
//! (`validate_published_names`, read off the built `Catalogue`) and the Statement facts the root
//! side reads the plane's words from. The root half judges the same documents through the kernel
//! and the folded row (boot's Ok/Err and its words); this half says what an accepted document
//! means.
//!
//! Every document here goes through `serde_json` into `ToolsCfg` — the carriage the door itself
//! reads its settings by (`door::read_tools_section`) — rather than constructing the struct, because
//! the thing under test IS the grammar: a test that built `McpServerDefCfg` directly would skip the
//! custom `Deserialize` where the reserved keys, the section knobs and the value rules all live.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::SECTION_DECLARING;
use serde_json::{json, Value};

use super::{
    namespaced, validate_published_names, McpPinMechanism, ServerPinCfg, ToolsCfg, SECTION,
    SUBJECT_NOUN, TRUST_KEYS,
};

/// The section read by the grammar alone, as the door reads its settings (no rule spanning
/// registrations): what one server's well-formedness is judged by.
fn grammar(section: Value) -> Result<ToolsCfg, String> {
    serde_json::from_value::<ToolsCfg>(section).map_err(|e| e.to_string())
}

/// The door's own `validate` over the whole section (what boot runs through the folded row).
fn door_validate(section: &Value) -> Result<ToolsCfg, String> {
    crate::door::read_tools_section(&serde_json::to_vec(section).expect("a section serialises"))
}

/// An ABSOLUTE program path AS THIS PLATFORM SPELLS ONE (the check is `Path::is_absolute`; see the
/// root battery's `ABS_PROGRAM` for why a hardcoded unix spelling would pass on the wrong assertion
/// on Windows). Unquoted here: a JSON string carries the backslashes byte for byte. Chosen by
/// `cfg!` rather than a `#[cfg]` item: this crate compiles every item one way (`tests/invariance.rs`).
const ABS_PROGRAM: &str = if cfg!(windows) {
    r"C:\Windows\System32\cmd.exe"
} else {
    "/bin/true"
};

/// THE LOCKED SECTION SHAPE, verbatim: the section knobs, the object pin, the `tools_allow` MAP,
/// the per-server credential mode and the bare-name hook attach. The same document the root
/// battery's `LOCKED_EXAMPLE` writes in YAML.
fn locked_example() -> Value {
    json!({
        "hooks": ["tool-sanitizer"],
        "filesystem": {
            "url": "https://tools.internal/fs",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
            "tools_allow": { "read_file": {} },
            "upstream_credentials": "own",
            "hooks": ["tool-sanitizer", "dispatch-order"]
        }
    })
}

/// The mechanisms declared to the kernel are exactly the grammar's own, each with the root-ness
/// its grammar gives it.
#[test]
fn the_declared_trust_keys_match_the_grammar() {
    let pin = &TRUST_KEYS[0];
    assert_eq!(pin.mechanisms.len(), 4, "every mechanism the grammar has");
    for declared in pin.mechanisms {
        let parsed: ServerPinCfg = serde_json::from_value(json!({ "mechanism": declared.token }))
            .unwrap_or_else(|e| panic!("`{}` is a grammar token: {e}", declared.token));
        assert_eq!(
            parsed.mechanism.is_a_root(),
            declared.root,
            "{}",
            declared.token
        );
    }
}

/// Each mechanism's SERIALIZED token is the token the declared `TRUST_KEYS` spells: the write path
/// judges the serialized definition against the declaration, so a drift between the two would read
/// a keyless root pin as no pin. (The kernel's reading of each declared token — a root takes its
/// material, the no-root spelling refuses it — is the root battery's half.)
#[test]
fn every_serialized_pin_token_is_the_declared_trust_key_token() {
    use McpPinMechanism as M;
    let declared: Vec<&str> = TRUST_KEYS[0].mechanisms.iter().map(|m| m.token).collect();
    let all = [
        M::PinnedPubkey,
        M::CertSpki,
        M::ClientCertBinding,
        M::Unpinned,
    ];
    assert_eq!(declared.len(), all.len());
    for m in all {
        let serialized = serde_json::to_value(m).expect("a mechanism serialises");
        let token = serialized.as_str().expect("a mechanism is a string");
        assert!(declared.contains(&token), "`{token}` is not declared");
        let root = TRUST_KEYS[0]
            .mechanisms
            .iter()
            .find(|d| d.token == token)
            .map(|d| d.root);
        assert_eq!(root, Some(m.is_a_root()), "{token}");
    }
}

#[test]
fn the_locked_section_shape_parses_into_the_values_it_declares() {
    let cfg = grammar(locked_example()).expect("the locked example must parse");
    assert_eq!(cfg.all_server_hooks, vec!["tool-sanitizer".to_string()]);
    assert_eq!(cfg.servers.len(), 1, "one server, and `hooks:` is not one");
    let fs = &cfg.servers["filesystem"];
    assert_eq!(fs.url, "https://tools.internal/fs");
    assert_eq!(fs.pin.mechanism.token(), "cert_spki");
    assert_eq!(fs.pin.key.as_deref(), Some("sha256/PIN=="));
    // THE MAP, not a list: `read_file` has a SLOT, and it is empty, which is "allowed, no hash
    // approved yet". A list could not have expressed the slot at all.
    assert!(fs.tools_allow.contains_key("read_file"));
    assert_eq!(fs.tools_allow["read_file"].schema_hash, None);
    // The two attach lists the kernel's `attach_list` merges (the root battery's half): the
    // section's and the server's own, each read as written.
    assert_eq!(
        fs.hooks,
        vec!["tool-sanitizer".to_string(), "dispatch-order".to_string()]
    );
    // SCALAR ⇒ OVERRIDE.
    assert_eq!(
        cfg.effective_upstream_credentials("filesystem"),
        Some(busbar_contract::config::UpstreamCreds::Own)
    );
    door_validate(&locked_example()).expect("the door's validate accepts it");
}

/// THE SEPARATOR RULE, the grammar's half: a server id carrying the separator is refused and a tool
/// name carrying it is not, and the arithmetic that makes the server-id rule necessary.
#[test]
fn the_namespace_separator_is_refused_in_a_server_id_and_allowed_in_a_tool_name() {
    let err = grammar(json!({
        "my_server": { "url": "https://x/", "pin": { "mechanism": "unpinned" } }
    }))
    .expect_err("a server id carrying the separator is ambiguous");
    assert!(err.contains("namespaced routing key"), "got: {err}");
    assert!(err.contains("my-server"), "a legal spelling: {err}");
    grammar(json!({
        "fs": {
            "url": "https://x/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "read_file": {} }
        }
    }))
    .expect("a tool name may carry the separator — the locked example does");

    // THE COLLISION the server-id rule prevents, stated as the arithmetic it is. `a_b` + `c` and
    // `a` + `b_c` render the SAME grant value; with `a_b` unregistrable, only one of the two pairs
    // can exist, and the key splits exactly one way at the FIRST separator.
    assert_eq!(
        namespaced("a_b", "c"),
        namespaced("a", "b_c"),
        "if this equality ever stops holding, the server-id rule can be relaxed — and not before"
    );
    assert_ne!(
        namespaced("a", "b_c"),
        namespaced("a", "b-c"),
        "and two tools on ONE server never collide, whatever they are called"
    );
}

/// DENY-BY-DEFAULT is the `Default` impl, not a rule written down somewhere else and remembered at
/// each call site. A registry entry that names no grants grants nothing.
#[test]
fn server_initiated_grants_default_to_denied() {
    let cfg = grammar(json!({ "s": { "url": "https://x/", "pin": { "mechanism": "unpinned" } } }))
        .unwrap();
    let g = cfg.servers["s"].grants;
    assert!(!g.sampling && !g.elicitation && !g.roots);
    for kind in ["sampling", "elicitation", "roots", "some_future_ask"] {
        assert!(
            !g.allows(kind),
            "an unwritten grant must deny `{kind}` — including a kind this build has never heard of"
        );
    }
    // And a granted one is granted, so the default is a default and not a hardcoded refusal.
    let cfg = grammar(json!({
        "s": {
            "url": "https://x/",
            "pin": { "mechanism": "unpinned" },
            "grants": { "sampling": true }
        }
    }))
    .unwrap();
    let g = cfg.servers["s"].grants;
    assert!(g.allows("sampling"));
    assert!(!g.allows("elicitation") && !g.allows("roots"));
}

/// BOTH TRANSPORTS BOOT, the typed half: a stdio registration carries its command and arguments and
/// no url (the root battery asserts boot accepts both).
#[test]
fn both_transports_are_accepted_at_parse() {
    grammar(json!({
        "s": {
            "url": "https://x/",
            "pin": { "mechanism": "unpinned" },
            "transport": "streamable_http"
        }
    }))
    .expect("the network transport is accepted");
    let cfg = grammar(json!({
        "s": {
            "pin": { "mechanism": "unpinned" },
            "transport": "stdio",
            "command": ABS_PROGRAM,
            "args": ["--root", "/srv"]
        }
    }))
    .expect("a stdio registration with a command is accepted");
    let s = &cfg.servers["s"];
    assert_eq!(s.command.as_deref(), Some(ABS_PROGRAM));
    assert_eq!(s.args, vec!["--root".to_string(), "/srv".to_string()]);
    assert!(
        s.url.is_empty(),
        "a stdio registration reaches no address, so it carries no url"
    );
}

// ── `publish_as` — the OPTIONAL wire-name override, and the invariant it moves ───────────────────
//
// `{server}_{tool}` protects one property: ONE PUBLISHED NAME RESOLVES TO EXACTLY ONE
// `(server, tool)`. Today it holds by construction. With an override it holds by
// `validate_published_names`, and these tests are what say so — including the case a naive
// implementation misses, which is an override colliding with a name NOBODY TYPED.

/// Every name the catalogue would PUBLISH for `cfg`, sorted — read off the built snapshot (the
/// plane's own catalogue, the one its door serves `tools/list` from) rather than recomputed from
/// the config, so a test cannot agree with a formula the catalogue no longer uses. Asked with every
/// grant admitted: these tests are about which NAMES are published, not who may see them.
fn published_names(cfg: &ToolsCfg) -> Vec<String> {
    let cat = crate::catalogue::Catalogue::build(1, cfg);
    let mut names: Vec<String> = cat
        .tools_for(&|_, _| true)
        .into_iter()
        .map(|t| t.namespaced.clone())
        .collect();
    names.sort();
    names
}

/// THE DEFAULT IS UNCHANGED, and this is the test that has to keep passing forever: a config that
/// writes no `publish_as:` publishes exactly what it published before the field existed. No
/// migration, no grant to re-audit.
#[test]
fn absent_publish_as_publishes_the_namespaced_default_byte_for_byte() {
    let cfg = grammar(locked_example()).expect("the locked example must parse");
    assert_eq!(
        cfg.servers["filesystem"].tools_allow["read_file"].publish_as,
        None
    );
    validate_published_names(&cfg).expect("no override can never collide with itself");

    assert_eq!(
        published_names(&cfg),
        vec!["filesystem_read_file".to_string()],
        "the namespaced default must still be the published name"
    );
}

/// The override is READ, and it is the name the CATALOGUE publishes — which is the same string
/// `tools/call` dispatches on and an `mcp_tool:` grant names.
#[test]
fn publish_as_is_the_published_name_and_the_namespaced_default_is_then_gone() {
    let cfg = grammar(json!({
        "github": {
            "url": "https://tools.internal/gh",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "greet": { "publish_as": "greet" } }
        }
    }))
    .expect("an override must parse");
    validate_published_names(&cfg).expect("one tool cannot collide with itself");

    let cat = crate::catalogue::Catalogue::build(1, &cfg);
    let all = cat.tools_for(&|_, _| true);
    // ONE name, not two: the override REPLACES the default rather than aliasing it. Two names for
    // one tool would mean an `mcp_tool:` grant on one of them silently missing the other, and the
    // uniqueness check would then be validating a set that is not what is published.
    assert_eq!(
        all.len(),
        1,
        "the override replaces the default; it does not alias it"
    );
    assert_eq!(all[0].namespaced, "greet");
    assert_eq!(all[0].server, "github");
    assert_eq!(all[0].tool, "greet");
}

/// RED 1 — TWO OVERRIDES COLLIDING. The obvious case, and the only one a naive check catches.
#[test]
fn two_publish_as_overrides_that_collide_refuse_the_config() {
    let section = json!({
        "alpha": {
            "url": "https://a/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "greet_a": { "publish_as": "greet" } }
        },
        "beta": {
            "url": "https://b/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "greet_b": { "publish_as": "greet" } }
        }
    });
    let cfg = grammar(section.clone())
        .expect("both servers are individually well-formed; the collision is cross-server");
    let err =
        validate_published_names(&cfg).expect_err("two tools published as `greet` must refuse");
    assert!(err.contains("published as `greet`"), "{err}");
    // BOTH sides named, because the operator has to know which two lines to look at.
    assert!(
        err.contains("tools.alpha.tools_allow.greet_a.publish_as"),
        "{err}"
    );
    assert!(
        err.contains("tools.beta.tools_allow.greet_b.publish_as"),
        "{err}"
    );
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section (what boot runs) refuses it in the same words"
    );
}

/// RED 2 — THE SUBTLE CASE, and the reason the check is against the WHOLE PUBLISHED SET rather than
/// override-against-override.
///
/// `publish_as: foo_bar` collides with server `foo`'s tool `bar`, which namespaces to `foo_bar`.
/// NOBODY TYPED `foo_bar` on the `foo` side — it is a name the default MECHANISM produced — so an
/// implementation that compared overrides only to each other finds nothing to compare against,
/// accepts this config, and lets one wire name resolve to two `(server, tool)` pairs. Because
/// `catalogue::granted` keys the `mcp_tool` grant on the published name, that is one grant silently
/// authorizing two upstreams.
#[test]
fn an_override_colliding_with_a_namespaced_default_refuses_the_config() {
    let section = json!({
        "foo": {
            "url": "https://foo/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "bar": {} }
        },
        "other": {
            "url": "https://other/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "anything": { "publish_as": "foo_bar" } }
        }
    });
    let cfg =
        grammar(section.clone()).expect("neither server is individually wrong; only the pair is");
    let err = validate_published_names(&cfg)
        .expect_err("an override must not shadow another server's namespaced default");
    assert!(err.contains("published as `foo_bar`"), "{err}");
    // The DEFAULT side is described as the default, not as a `publish_as:` the operator can go and
    // delete — it is a name nothing typed.
    assert!(
        err.contains("the default `{server}_{tool}` name of `tools.foo.tools_allow.bar`"),
        "{err}"
    );
    assert!(
        err.contains("tools.other.tools_allow.anything.publish_as"),
        "{err}"
    );
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section (what boot runs) refuses it in the same words"
    );
}

/// The same collision in the OTHER declaration order. Config order must not decide whether a
/// config boots: an operator who reorders two server blocks has changed nothing.
#[test]
fn the_default_versus_override_collision_is_refused_in_either_declaration_order() {
    let section = json!({
        "aaa": {
            "url": "https://a/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "anything": { "publish_as": "zzz_bar" } }
        },
        "zzz": {
            "url": "https://z/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "bar": {} }
        }
    });
    let cfg = grammar(section.clone()).expect("parses");
    let err = validate_published_names(&cfg).expect_err("order must not decide this");
    assert!(err.contains("published as `zzz_bar`"), "{err}");
    assert_eq!(
        door_validate(&section).expect_err("the door refuses it"),
        err,
        "the door's validate over the whole section (what boot runs) refuses it in the same words"
    );
}

/// An override that spells the namespaced default is NOT a collision — it publishes the same one
/// name the default would have. Refusing it would refuse a config that changes nothing.
#[test]
fn an_override_equal_to_its_own_namespaced_default_is_not_a_collision() {
    let cfg = grammar(json!({
        "foo": {
            "url": "https://foo/",
            "pin": { "mechanism": "unpinned" },
            "tools_allow": { "bar": { "publish_as": "foo_bar" } }
        }
    }))
    .expect("parses");
    validate_published_names(&cfg).expect("one tool, one name — whichever way it is spelled");
    assert_eq!(published_names(&cfg), vec!["foo_bar".to_string()]);
}

/// The three legal ask methods parse into a three-entry round, read as written: the rule refuses
/// typos, not asks (the refusals themselves are the root battery's, at boot).
#[test]
fn every_ask_list_is_validated_and_the_three_legal_methods_still_parse() {
    let cfg = grammar(json!({
        "filesystem": {
            "url": "https://tools.internal/fs",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
            "prompts_allow": {
                "summarise": {
                    "template": "hi",
                    "ask_caller": [
                        { "a": { "method": "elicitation/create" } },
                        { "b": { "method": "sampling/createMessage" } },
                        { "c": { "method": "roots/list" } }
                    ]
                }
            }
        }
    }))
    .expect("all three legal methods must still parse — the rule refuses typos, not asks");
    assert_eq!(
        cfg.servers["filesystem"].prompts_allow["summarise"]
            .ask_caller
            .len(),
        3
    );
}

/// Whether `stated` is the tail string built from `word` (the tail's strings are constants of this
/// crate, so a word is found by address and length, as `tests/door.rs` reads them).
fn spells(stated: AbiStr, word: &str) -> bool {
    stated.ptr == word.as_ptr() && stated.len == word.len()
}

/// THE WORDS THE ROOT BATTERY READS OFF THE STATEMENT ARE THE GRAMMAR'S: the declaring section is
/// `SECTION`, the owned one the endpoint block, the subject noun `SUBJECT_NOUN`; and the endpoint's
/// fixed mount and
/// its RFC 9728 document are spelled from the endpoint block's name (so the root may build them from
/// the section the Statement owns).
#[test]
fn the_statement_names_the_grammars_section_noun_and_endpoint() {
    let sections = crate::door::SECTIONS;
    assert_eq!(sections.len(), 2);
    assert!(spells(sections[0].name, SECTION), "the declaring section");
    assert_ne!(sections[0].flags & SECTION_DECLARING, 0);
    assert!(
        spells(sections[1].name, crate::door::ENDPOINT_SECTION),
        "the owned endpoint block"
    );
    assert_eq!(sections[1].flags & SECTION_DECLARING, 0);
    assert!(spells(crate::door::TAIL.subject_noun, SUBJECT_NOUN));
    assert_eq!(
        crate::tool_claims::DEFAULT_MOUNT,
        format!("/{}", crate::door::ENDPOINT_SECTION)
    );
    assert_eq!(
        crate::tool_claims::DEFAULT_METADATA,
        format!(
            "/.well-known/oauth-protected-resource/{}",
            crate::door::ENDPOINT_SECTION
        )
    );
    assert_eq!(crate::door::TAIL.dialects_len, 1, "one wire dialect");
}

/// RED (ARCHITECT timeout ruling): a server's `timeout:` is the kernel's reserved per-entry key, and
/// the door reads it — through the kernel's one reading — as the budget of the tool-list fetches it
/// makes itself: `10s` is 10 000 ms; a server that writes none gets the documented `30s`
/// (`docs/mcp.md`). One owner judges it: the door does not refuse a value the kernel refuses (a
/// zero), it never sees one at load.
#[test]
fn a_servers_timeout_bounds_the_doors_own_fetches_and_the_kernel_owns_its_judgement() {
    let server = |extra: Value| {
        let mut s = json!({
            "url": "https://tools.internal/fs",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" },
            "tools_allow": { "read_file": {} },
        });
        if let (Some(s), Some(extra)) = (s.as_object_mut(), extra.as_object()) {
            s.extend(extra.clone());
        }
        s
    };
    let cfg = grammar(json!({
        "timed": server(json!({ "timeout": "10s" })),
        "untimed": server(json!({})),
    }))
    .expect("both read");
    assert_eq!(cfg.servers["timed"].timeout_ms(), 10_000);
    assert_eq!(
        cfg.servers["untimed"].timeout_ms(),
        super::DEFAULT_UPSTREAM_TIMEOUT_MS
    );
    assert_eq!(
        super::DEFAULT_UPSTREAM_TIMEOUT_MS,
        30_000,
        "docs/mcp.md's default"
    );
    assert!(
        door_validate(&json!({ "zero": server(json!({ "timeout": "0s" })) })).is_ok(),
        "the zero timeout is the kernel's to refuse, not the door's"
    );
}
