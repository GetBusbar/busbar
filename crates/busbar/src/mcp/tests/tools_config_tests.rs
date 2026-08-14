// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` GRAMMAR — the named map whose mere existence declares the mcp plane — parsed from
//! the YAML an operator actually writes, and refused for the reasons the locked named-map grammar
//! and the out-of-band pin trust root give.
//!
//! Every test here goes through `serde_yaml` rather than constructing the struct, because the thing
//! under test IS the grammar: a test that built `McpServerDefCfg` directly would skip the custom
//! `Deserialize` where the reserved keys, the section knobs and the value rules all live.

use super::ToolsCfg;

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
    let cfg = parse(LOCKED_EXAMPLE).expect("the locked example must parse");
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

/// The reserved word space does NOT vary per plane, and that is no longer an assertion about two
/// constants — there is ONE constant, `plane::config::RESERVED_SECTION_KEYS`, and this section is
/// read through the shared split that consults it. What remains testable, and what this asserts, is
/// that EVERY word in that set is refused as a server NAME on this plane.
#[test]
fn a_server_may_not_be_named_with_a_reserved_section_word() {
    for reserved in crate::plane::config::RESERVED_SECTION_KEYS {
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
        .expect("a tool name may carry the separator — the locked example does");

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

/// BOTH TRANSPORTS BOOT. `transport: stdio` was refused outright for two releases — first because
/// the supervisor was unreachable, then because it had been deleted — and this is the test that used
/// to pin that refusal. It now pins the opposite, which is the whole unit in one assertion.
#[test]
fn both_transports_are_accepted_at_parse() {
    parse(
        "s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  transport: streamable_http\n",
    )
    .expect("the network transport is accepted");
    // `ABS_PROGRAM`, not a hardcoded unix path: `command:` is validated with `Path::is_absolute`,
    // and `/usr/local/bin/mcp-fs` is DRIVE-RELATIVE on Windows — this test failed on the windows
    // CI runner with the absolute-path refusal while asserting acceptance. See ABS_PROGRAM's doc.
    let cfg = parse(&format!(
        "s:\n  pin: {{ mechanism: unpinned }}\n  transport: stdio\n  command: {ABS_PROGRAM}\n\
         \x20 args: [\"--root\", \"/srv\"]\n",
    ))
    .expect("a stdio registration with a command is accepted");
    let s = &cfg.servers["s"];
    assert_eq!(s.command.as_deref(), Some(ABS_PROGRAM.trim_matches('\'')));
    assert_eq!(s.args, vec!["--root".to_string(), "/srv".to_string()]);
    assert!(
        s.url.is_empty(),
        "a stdio registration reaches no address, so it carries no url"
    );
}

/// An ABSOLUTE program path AS THIS PLATFORM SPELLS ONE.
///
/// The check under test is `Path::is_absolute`, and absoluteness is spelled differently per
/// platform: `/bin/true` is absolute on unix but DRIVE-RELATIVE (therefore refused) on Windows.
/// Hardcoding the unix spelling would make every case below that only wants a VALID command reach
/// the absolute-path refusal first and pass on the wrong assertion — green while testing nothing it
/// names. This constant is what keeps each case failing for the reason it claims.
///
/// SINGLE-QUOTED, and that is load-bearing rather than style. These are interpolated into a YAML
/// document. A Windows path is full of backslashes, and YAML's DOUBLE-quoted style would read `\W`
/// as an escape sequence and fail to parse; the single-quoted style has no backslash escapes at all,
/// so the scalar arrives byte-for-byte. Quoting the unix spelling the same way keeps one form.
#[cfg(unix)]
const ABS_PROGRAM: &str = "'/bin/true'";
#[cfg(windows)]
const ABS_PROGRAM: &str = r"'C:\Windows\System32\cmd.exe'";

/// THE SPAWN SAFETY RULES, refused at BOOT where the operator who typed them is standing.
///
/// Each row is a real way to turn "busbar launches this binary" into something else, and each is a
/// separate assertion so a refusal that stopped firing cannot hide behind one that still does. The
/// SSRF guard is what protects the network transport and it has nothing to say about any of these,
/// which is why they are checked here rather than nowhere.
#[test]
fn a_stdio_registration_is_refused_unless_it_is_safe_to_spawn() {
    let base = "s:\n  pin: { mechanism: unpinned }\n  transport: stdio\n";
    let cases: [(&str, String, &str); 8] = [
        (
            "no command at all",
            String::new(),
            "needs `command:`",
        ),
        // A BARE NAME IS A `PATH` LOOKUP, so whoever controls busbar's environment picks the binary.
        (
            "a PATH-resolved program",
            "  command: mcp-fs\n".to_string(),
            "must be an ABSOLUTE path",
        ),
        (
            "a relative program",
            "  command: ./mcp-fs\n".to_string(),
            "must be an ABSOLUTE path",
        ),
        (
            "a relative working directory",
            format!("  command: {ABS_PROGRAM}\n  cwd: ../srv\n"),
            "must be an ABSOLUTE path",
        ),
        // A registration that names both has said where its server is TWICE, differently.
        (
            "both a url and a command",
            format!("  command: {ABS_PROGRAM}\n  url: \"https://x/\"\n"),
            "reaches no address",
        ),
        // A PIPE HAS NO HEADER BLOCK. Accepting these would drop a credential the operator believes
        // is being applied — silently, on the one path where it cannot be.
        (
            "a token exchange",
            format!("  command: {ABS_PROGRAM}\n  token_exchange: {{ token_url: \"https://as/\", subject_token: {{ env: T }} }}\n"),
            "has no carrier",
        ),
        (
            "an outbound audience",
            format!("  command: {ABS_PROGRAM}\n  aud: \"https://backend/\"\n"),
            "mints none",
        ),
        (
            "an environment variable that is not one",
            format!("  command: {ABS_PROGRAM}\n  env: {{ \"BAD=NAME\": x }}\n"),
            "not a usable environment variable name",
        ),
    ];
    for (what, extra, expected) in cases {
        let err = parse(&format!("{base}{extra}"))
            .err()
            .unwrap_or_else(|| panic!("{what}: SHOULD HAVE BEEN REFUSED, but the config parsed"));
        assert!(
            err.contains(expected),
            "{what}: the refusal must say `{expected}`, got: {err}"
        );
    }
}

/// THE ABSOLUTE-PATH CHECK IS PLATFORM-CORRECT, in both directions.
///
/// The check was `program.starts_with('/')`, which is the unix spelling of "absolute" and only that.
/// On Windows it refused EVERY absolute path an operator there can write, so `transport: stdio` was
/// not merely untested on Windows — it was unconfigurable, while the module's own comments described
/// the gap as test-coverage-only. This test is what stops the unix spelling coming back: it asserts
/// the accepted form for the platform it runs on, and that the foreign spelling — which is
/// drive-relative or root-relative rather than absolute, and so IS decided by the environment — is
/// still refused.
#[test]
fn the_absolute_command_check_uses_this_platforms_spelling_of_absolute() {
    let base = "s:\n  pin: { mechanism: unpinned }\n  transport: stdio\n";

    // The native spelling is ACCEPTED: no absolute-path complaint.
    parse(&format!("{base}  command: {ABS_PROGRAM}\n"))
        .expect("an absolute path in this platform's own spelling must be accepted");

    // The FOREIGN spelling is refused, because on this platform it is not absolute.
    #[cfg(unix)]
    let foreign = r"'C:\Windows\System32\cmd.exe'";
    #[cfg(windows)]
    let foreign = "'/bin/true'"; // root-relative to the CURRENT DRIVE on Windows, not absolute
    let err = parse(&format!("{base}  command: {foreign}\n"))
        .expect_err("a path that is not absolute on THIS platform must be refused");
    assert!(err.contains("must be an ABSOLUTE path"), "{err}");
}

/// The SPAWN keys belong to the spawning transport, and a registration reached over the network may
/// not carry them. A `command:` that is silently ignored is an operator believing busbar launches
/// something it does not.
#[test]
fn the_spawn_keys_are_refused_on_a_network_registration() {
    let err =
        parse("s:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n  command: /bin/true\n")
            .expect_err("a url registration must not carry a command");
    assert!(err.contains("describes a child process to spawn"), "{err}");
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

// ── `publish_as` — the OPTIONAL wire-name override, and the invariant it moves ───────────────────
//
// `{server}_{tool}` protects one property: ONE PUBLISHED NAME RESOLVES TO EXACTLY ONE
// `(server, tool)`. Today it holds by construction. With an override it holds by
// `validate_published_names`, and these tests are what say so — including the case a naive
// implementation misses, which is an override colliding with a name NOBODY TYPED.

use crate::mcp::config::validate_published_names;

/// AN UNGOVERNED CALLER — no principal, so no grant narrows anything. `crate::trust::validate`
/// states that posture once for the whole tree; these two tests are about which NAMES the catalogue
/// publishes, not about who may see them, so they ask as the deployment with governance off.
fn ungoverned() -> crate::catalogue::Caller<'static> {
    crate::catalogue::Caller {
        key: None,
        now: 0,
        generation: crate::trust::validate::Generations::at_admission(1),
    }
}

/// Every name the catalogue would PUBLISH for `cfg`, sorted — read off the built snapshot rather
/// than recomputed from the config, so a test cannot agree with a formula the catalogue no longer
/// uses.
fn published_names(cfg: &ToolsCfg) -> Vec<String> {
    let cat = crate::mcp::catalogue::Catalogue::build(cfg);
    let mut names: Vec<String> = cat
        .tools_for(&ungoverned())
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
    let cfg = parse(LOCKED_EXAMPLE).expect("the locked example must parse");
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
    let cfg = parse(
        r#"
github:
  url: "https://mcp.internal/gh"
  pin: { mechanism: unpinned }
  tools_allow:
    greet:
      publish_as: greet
"#,
    )
    .expect("an override must parse");
    validate_published_names(&cfg).expect("one tool cannot collide with itself");

    let cat = crate::mcp::catalogue::Catalogue::build(&cfg);
    let all = cat.tools_for(&ungoverned());
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
    let cfg = parse(
        r#"
alpha:
  url: "https://a/"
  pin: { mechanism: unpinned }
  tools_allow: { greet_a: { publish_as: greet } }
beta:
  url: "https://b/"
  pin: { mechanism: unpinned }
  tools_allow: { greet_b: { publish_as: greet } }
"#,
    )
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
    let cfg = parse(
        r#"
foo:
  url: "https://foo/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: {} }
other:
  url: "https://other/"
  pin: { mechanism: unpinned }
  tools_allow: { anything: { publish_as: foo_bar } }
"#,
    )
    .expect("neither server is individually wrong; only the pair is");
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
}

/// The same collision in the OTHER declaration order. Config order must not decide whether a
/// config boots: an operator who reorders two server blocks has changed nothing.
#[test]
fn the_default_versus_override_collision_is_refused_in_either_declaration_order() {
    let cfg = parse(
        r#"
aaa:
  url: "https://a/"
  pin: { mechanism: unpinned }
  tools_allow: { anything: { publish_as: zzz_bar } }
zzz:
  url: "https://z/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: {} }
"#,
    )
    .expect("parses");
    let err = validate_published_names(&cfg).expect_err("order must not decide this");
    assert!(err.contains("published as `zzz_bar`"), "{err}");
}

/// An override that spells the namespaced default is NOT a collision — it publishes the same one
/// name the default would have. Refusing it would refuse a config that changes nothing.
#[test]
fn an_override_equal_to_its_own_namespaced_default_is_not_a_collision() {
    let cfg = parse(
        r#"
foo:
  url: "https://foo/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: { publish_as: foo_bar } }
"#,
    )
    .expect("parses");
    validate_published_names(&cfg).expect("one tool, one name — whichever way it is spelled");
    assert_eq!(published_names(&cfg), vec!["foo_bar".to_string()]);
}

/// A published name nothing can call and nothing can grant on is refused where the operator is,
/// per server, rather than at a `tools/call` an hour later that never matches.
#[test]
fn an_empty_or_padded_publish_as_is_refused_by_the_per_server_value_rules() {
    for bad in ["\"\"", "\"   \"", "\" greet\"", "\"greet \""] {
        let yaml = format!(
            "gh:\n  url: \"https://x/\"\n  pin: {{ mechanism: unpinned }}\n  \
             tools_allow: {{ greet: {{ publish_as: {bad} }} }}\n"
        );
        let err = parse(&yaml).expect_err("`publish_as: {bad}` must be refused");
        assert!(err.contains("publish_as"), "{bad}: {err}");
    }
}

/// ONE GRAMMAR, TWO PATHS for the per-server half: the admin write path refuses a malformed
/// `publish_as:` exactly as `config.yaml` does, because both reach `validate_server`.
#[test]
fn the_admin_write_path_refuses_a_malformed_publish_as_exactly_as_the_file_does() {
    let def = serde_json::json!({
        "url": "https://x/",
        "pin": { "mechanism": "unpinned" },
        "tools_allow": { "greet": { "publish_as": "  " } },
    });
    let err = crate::config::named_map::NamedMapSection::Tools
        .validate_def("gh", &def)
        .expect_err("the API must reject exactly what the file rejects");
    assert!(err.contains("publish_as"), "{err}");
}
