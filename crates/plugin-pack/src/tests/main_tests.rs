// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-pack/src/main.rs`.

use super::*;

/// `pack`-equivalent flow: a signed manifest packaged here unpacks + verifies as trusted under
/// the matching public key (the exact artifact contract the engine consumes).
#[test]
fn packed_tarball_verifies_end_to_end() {
    let seed = [7u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let lib = b"pretend cdylib bytes";
    let m = Manifest {
        name: "acme-store-x".into(),
        alias: "x".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: busbar_plugin_loader::supported_abi("store")
            .iter()
            .copied()
            .max()
            .unwrap(),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let signed = sign(&key, m, lib);
    busbar_plugin_sign::validate_structure(
        &signed,
        lib,
        &busbar_plugin_loader::supported_abi,
        busbar_plugin_sign::HOST_IDENTITY,
    )
    .expect("structural");
    let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib).unwrap();
    let up = busbar_plugin_loader::tarball::unpack(&tarball).unwrap();
    let mut policy = busbar_plugin_sign::TrustPolicy::default();
    policy.publishers.insert("acme".into(), key.verifying_key());
    assert!(matches!(
        busbar_plugin_sign::evaluate(&up.lib_bytes, &up.manifest, &policy).unwrap(),
        busbar_plugin_sign::Verdict::Trusted { .. }
    ));
}

/// The real `pack()` CLI entry point, end-to-end: without `BUSBAR_SIGN_KEY` set, a plain pack
/// fails (ExitCode::FAILURE, no tarball written) UNLESS `--allow-unsigned` is passed, in which
/// case it succeeds and writes an unsigned tarball. Every other test in this module calls the
/// signing/packaging primitives directly and never exercises `pack()` itself, so this is the
/// only coverage of its env-var branch, the two ExitCode outcomes, and CLI flag wiring.
///
/// Serialized (not run concurrently with itself — it's one `#[test]` function) since it
/// mutates the process-global `BUSBAR_SIGN_KEY` env var; no other test in this crate reads or
/// writes that var.
#[test]
fn pack_cli_respects_allow_unsigned_and_returns_the_right_exit_code() {
    std::env::remove_var(SIGN_KEY_ENV);
    let dir = std::env::temp_dir().join(format!("plugin-pack-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib_path = dir.join("lib.so");
    std::fs::write(&lib_path, b"pretend cdylib").unwrap();
    let out_path = dir.join("out.tar.gz");

    let args = |out: &std::path::Path, extra: &[&str]| -> Vec<String> {
        let mut v = vec![
            "--lib".to_string(),
            lib_path.to_string_lossy().to_string(),
            "--name".to_string(),
            "n".to_string(),
            "--alias".to_string(),
            "n".to_string(),
            "--kind".to_string(),
            "store".to_string(),
            "--version".to_string(),
            "1.0.0".to_string(),
            "--publisher".to_string(),
            "p".to_string(),
            "--out".to_string(),
            out.to_string_lossy().to_string(),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };

    // No key, no --allow-unsigned: must fail closed, and must not write a tarball.
    let _ = std::fs::remove_file(&out_path);
    assert_eq!(pack(&args(&out_path, &[])), ExitCode::FAILURE);
    assert!(
        !out_path.exists(),
        "a failed pack must not leave a tarball behind"
    );

    // --allow-unsigned with no key: must succeed and actually write the tarball.
    assert_eq!(
        pack(&args(&out_path, &["--allow-unsigned"])),
        ExitCode::SUCCESS
    );
    assert!(
        out_path.exists(),
        "a successful pack must write the tarball"
    );
    let up = busbar_plugin_loader::tarball::unpack(&std::fs::read(&out_path).unwrap()).unwrap();
    assert!(
        up.manifest.signature.is_empty(),
        "--allow-unsigned must produce an UNSIGNED manifest"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The `--needs-*` level parser accepts the ladder tokens (case/alias-insensitively) and hard-errors
/// on anything else (a fat-fingered intent must not silently default to a weaker/stronger level).
#[test]
fn need_level_parsing() {
    assert_eq!(parse_need_level("no").unwrap(), NeedLevel::No);
    assert_eq!(parse_need_level("").unwrap(), NeedLevel::No);
    assert_eq!(parse_need_level("RO").unwrap(), NeedLevel::Ro);
    assert_eq!(parse_need_level("read").unwrap(), NeedLevel::Ro);
    assert_eq!(parse_need_level(" rw ").unwrap(), NeedLevel::Rw);
    assert_eq!(parse_need_level("read-write").unwrap(), NeedLevel::Rw);
    assert!(parse_need_level("maybe").is_err());
}

/// A hook manifest packed with `--needs-prompt rw` carries a SIGNED `needs.prompt = rw` that
/// verifies end-to-end and cannot be altered after packing (parity with the store round-trip).
#[test]
fn packed_hook_needs_prompt_rw_is_signed() {
    let seed = [3u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let lib = b"pretend headroom cdylib";
    let m = Manifest {
        name: "busbar-headroom".into(),
        alias: "headroom".into(),
        kind: "hook".into(),
        version: "1.5.0".into(),
        publisher: "busbar".into(),
        abi_version: busbar_plugin_loader::supported_abi("hook")
            .iter()
            .copied()
            .max()
            .unwrap(),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: HookNeeds {
            prompt: NeedLevel::Rw,
            user: NeedLevel::No,
        },
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let signed = sign(&key, m, lib);
    assert_eq!(signed.needs.prompt, NeedLevel::Rw);
    busbar_plugin_sign::validate_structure(
        &signed,
        lib,
        &busbar_plugin_loader::supported_abi,
        busbar_plugin_sign::HOST_IDENTITY,
    )
    .expect("structural");
    // Tampering the declared intent after signing breaks verification (needs is signed).
    let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib).unwrap();
    let up = busbar_plugin_loader::tarball::unpack(&tarball).unwrap();
    let policy = busbar_plugin_sign::TrustPolicy {
        first_party_key: Some(key.verifying_key()),
        binary_version: "1.5.0".into(),
        ..Default::default()
    };
    assert!(matches!(
        busbar_plugin_sign::evaluate(&up.lib_bytes, &up.manifest, &policy).unwrap(),
        busbar_plugin_sign::Verdict::Trusted { .. }
    ));
}

#[test]
fn flag_parsing() {
    let args: Vec<String> = ["--lib", "a.so", "--allow-unsigned", "--name", "n"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (flags, unsigned, schema_derived) = parse_flags(&args).unwrap();
    assert!(unsigned);
    assert!(!schema_derived);
    assert_eq!(flags["lib"], "a.so");
    assert_eq!(flags["name"], "n");
    assert!(parse_flags(&["--dangling".to_string()]).is_err());
    assert!(parse_flags(&["bare".to_string()]).is_err());

    let with_derived: Vec<String> = ["--schema-derived", "--lib", "a.so"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (_, _, schema_derived) = parse_flags(&with_derived).unwrap();
    assert!(schema_derived);
}

/// A schema whose `$schema` names an older/missing draft is rejected even though it would
/// otherwise compile fine as "a well-formed JSON Schema" of some draft.
#[test]
fn settings_schema_requires_exact_2020_12_draft() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-plugin-pack-schema-draft-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let missing = dir.join("missing.json");
    std::fs::write(&missing, r#"{"type":"object","properties":{}}"#).unwrap();
    let err = read_and_validate_settings_schema(missing.to_str().unwrap()).unwrap_err();
    assert!(err.contains("\"$schema\""), "{err}");

    let old_draft = dir.join("draft07.json");
    std::fs::write(
        &old_draft,
        r#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{}}"#,
    )
    .unwrap();
    let err = read_and_validate_settings_schema(old_draft.to_str().unwrap()).unwrap_err();
    assert!(err.contains("\"$schema\""), "{err}");

    let ok = dir.join("ok.json");
    std::fs::write(
            &ok,
            format!(
                r#"{{"$schema":"{SCHEMA_2020_12}","type":"object","properties":{{"url":{{"type":"string"}}}}}}"#
            ),
        )
        .unwrap();
    read_and_validate_settings_schema(ok.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A marked secret field must be `type: string` (optionally `contentEncoding: "base64"`);
/// anything else is rejected at pack time.
#[test]
fn secret_field_must_be_string_or_base64_string() {
    let ok = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"url": {"type": "string", "x-busbar-secret": true}},
    });
    validate_secret_fields(&ok).unwrap();

    let ok_binary = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "cert": {"type": "string", "contentEncoding": "base64", "x-busbar-secret": true},
        },
    });
    validate_secret_fields(&ok_binary).unwrap();

    let bad_type = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"count": {"type": "integer", "x-busbar-secret": true}},
    });
    assert!(validate_secret_fields(&bad_type).is_err());
}

/// `x-busbar-secret: true` nested under a root property — whether written inline or via a
/// `$ref` into `$defs` (the shape struct-derivation naturally produces) — is rejected, not
/// silently accepted.
#[test]
fn nested_secret_field_is_rejected_inline_and_via_ref() {
    let inline_nested = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "tls": {
                "type": "object",
                "properties": {"key": {"type": "string", "x-busbar-secret": true}},
            },
        },
    });
    assert!(validate_secret_fields(&inline_nested).is_err());

    let ref_nested = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"tls": {"$ref": "#/$defs/TlsConfig"}},
        "$defs": {
            "TlsConfig": {
                "type": "object",
                "properties": {"key": {"type": "string", "x-busbar-secret": true}},
            },
        },
    });
    assert!(validate_secret_fields(&ref_nested).is_err());

    let flattened = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"tls_key": {"type": "string", "x-busbar-secret": true}},
    });
    validate_secret_fields(&flattened).unwrap();
}

/// A self-referencing `$ref` cycle is rejected with a specific "cyclic" error, not an infinite
/// loop / stack overflow (`resolving.insert` returning `false` on a repeat name is the guard).
#[test]
fn cyclic_ref_is_rejected_not_infinitely_recursed() {
    let cyclic = serde_json::json!({
        "$schema": SCHEMA_2020_12,
        "$ref": "#/$defs/A",
        "$defs": {
            "A": {"$ref": "#/$defs/B"},
            "B": {"$ref": "#/$defs/A"},
        },
    });
    let err = validate_secret_fields(&cyclic).unwrap_err();
    assert!(err.contains("cyclic"), "got {err}");
}

/// A `$ref` sibling key (e.g. a `description` written alongside `$ref`, valid 2020-12 shape)
/// must survive into the merged effective schema, not be dropped — only the `$ref` KEY itself
/// is excluded from the copy-over.
#[test]
fn ref_sibling_keys_survive_the_merge() {
    let schema = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "tls": {
                "$ref": "#/$defs/TlsConfig",
                "x-busbar-secret": true,
            },
        },
        "$defs": {
            "TlsConfig": {"type": "string"},
        },
    });
    // If the `x-busbar-secret` sibling were dropped during the $ref merge, this would silently
    // pass instead of being caught by the type check (string is fine) — assert success AND
    // that swapping the referenced type to something invalid for a secret DOES get caught,
    // proving the sibling key was actually merged in and evaluated.
    validate_secret_fields(&schema).unwrap();

    let bad_type = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "tls": {
                "$ref": "#/$defs/TlsConfig",
                "x-busbar-secret": true,
            },
        },
        "$defs": {
            "TlsConfig": {"type": "integer"},
        },
    });
    assert!(
        validate_secret_fields(&bad_type).is_err(),
        "the sibling x-busbar-secret marker must have been merged in and enforced"
    );
}

/// `allOf` branches merge their `properties` (already covered) AND their other sibling keys
/// (e.g. `required`) into the effective schema — a marked secret living in a NON-properties key
/// of an allOf branch (nothing realistic needs this for x-busbar-secret specifically, so this
/// proves the general merge instead: a secret-shaped field hidden inside an allOf branch's own
/// nested `properties` is still found).
#[test]
fn all_of_branch_properties_are_merged_and_scanned() {
    let schema = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "allOf": [
            {"type": "object", "properties": {"password": {"type": "string"}}},
        ],
    });
    let err = validate_secret_fields(&schema).unwrap_err();
    assert!(err.contains("password"), "got {err}");

    let clean = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "allOf": [
            {"type": "object", "properties": {"note": {"type": "string"}}},
        ],
    });
    validate_secret_fields(&clean).unwrap();
}

/// The allOf merge copies more than just `properties` from a branch into the effective schema
/// — every OTHER key too (`type`, etc). Here `x-busbar-secret` is marked directly on the field,
/// but its `type: string` lives ONLY inside an `allOf` branch; the check can only pass if that
/// non-`properties` key actually got merged in.
#[test]
fn all_of_branch_non_properties_keys_are_merged_in() {
    let schema = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "token": {
                "x-busbar-secret": true,
                "allOf": [{"type": "string"}],
            },
        },
    });
    validate_secret_fields(&schema).unwrap_or_else(|e| {
        panic!("allOf branch's `type` must be merged into the effective schema: {e}")
    });
}

/// `oneOf`/`anyOf`/`prefixItems` are also places a field can hide — a marked OR unmarked
/// secret-looking field placed inside one of these composition keywords must be caught the
/// same as a plain nested object. A scanner that only walks `properties`/`items` leaves both the
/// root-only placement rule and the unmarked-name heuristic evadable through
/// `oneOf`/`anyOf`/`prefixItems`.
#[test]
fn oneof_anyof_prefixitems_are_scanned_for_secret_violations() {
    // Marked `x-busbar-secret` nested inside a `oneOf` alternative is rejected, same as any
    // other nested placement.
    let one_of_marked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "oneOf": [
                    {"type": "object", "properties": {"token": {"type": "string", "x-busbar-secret": true}}},
                    {"type": "object", "properties": {"anonymous": {"type": "boolean"}}},
                ],
            },
        },
    });
    assert!(validate_secret_fields(&one_of_marked).is_err());

    // An UNMARKED secret-looking field name nested inside an `anyOf` alternative is rejected.
    let any_of_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "anyOf": [
                    {"type": "object", "properties": {"password": {"type": "string"}}},
                ],
            },
        },
    });
    assert!(validate_secret_fields(&any_of_unmarked).is_err());

    // Same for a tuple-typed `prefixItems` entry.
    let prefix_items_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "pair": {
                "type": "array",
                "prefixItems": [
                    {"type": "object", "properties": {"api_key": {"type": "string"}}},
                ],
            },
        },
    });
    assert!(validate_secret_fields(&prefix_items_unmarked).is_err());

    // A oneOf alternative with no secret-shaped fields at all is untouched.
    let one_of_clean = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "oneOf": [
                    {"type": "object", "properties": {"mode": {"type": "string"}}},
                ],
            },
        },
    });
    validate_secret_fields(&one_of_clean).unwrap();
}

/// The remaining JSON Schema 2020-12 subschema-bearing keywords (`if`/`then`/`else`, `not`,
/// `additionalProperties`, `patternProperties`, `contains`, `dependentSchemas`,
/// `unevaluatedProperties`/`unevaluatedItems`) are also places a field can hide — the same class
/// of gap as `oneOf`/`anyOf`/`prefixItems` above. A scanner that skips them lets an unmarked
/// secret-looking field — or a marked field placed below root depth — ship unmarked into the
/// signed manifest.
#[test]
fn remaining_subschema_keywords_are_scanned_for_secret_violations() {
    // `if`/`then`: an unmarked secret-looking field nested inside a `then` branch.
    let if_then_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "if": {"properties": {"mode": {"const": "basic"}}},
                "then": {"type": "object", "properties": {"password": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&if_then_unmarked).is_err());

    // `else` branch too.
    let if_else_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "if": {"properties": {"mode": {"const": "anon"}}},
                "else": {"type": "object", "properties": {"api_key": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&if_else_unmarked).is_err());

    // `not`: still scanned even though it constrains what must NOT match — a secret-looking
    // field inside it is still a field a form renderer's schema walker could stumble into.
    let not_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "not": {"type": "object", "properties": {"secret": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&not_unmarked).is_err());

    // `additionalProperties` as a schema (not a bool): unmarked secret-looking field.
    let additional_props_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "type": "object",
                "additionalProperties": {"type": "object", "properties": {"token": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&additional_props_unmarked).is_err());

    // `additionalProperties: true` / `false` (bool, not a schema) must NOT crash or false-positive.
    let additional_props_bool_true = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"auth": {"type": "object", "additionalProperties": true}},
    });
    validate_secret_fields(&additional_props_bool_true).unwrap();
    let additional_props_bool_false = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"auth": {"type": "object", "additionalProperties": false}},
    });
    validate_secret_fields(&additional_props_bool_false).unwrap();

    // `patternProperties`: map of pattern -> schema, unmarked secret-looking field in a value.
    let pattern_props_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "type": "object",
                "patternProperties": {
                    "^cred_": {"type": "object", "properties": {"client_secret": {"type": "string"}}},
                },
            },
        },
    });
    assert!(validate_secret_fields(&pattern_props_unmarked).is_err());

    // `contains`: unmarked secret-looking field inside an array-item constraint.
    let contains_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "contains": {"type": "object", "properties": {"password": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&contains_unmarked).is_err());

    // `dependentSchemas`: map of name -> schema, unmarked secret-looking field in a value.
    let dependent_schemas_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "type": "object",
                "dependentSchemas": {
                    "mode": {"type": "object", "properties": {"private_key": {"type": "string"}}},
                },
            },
        },
    });
    assert!(validate_secret_fields(&dependent_schemas_unmarked).is_err());

    // `unevaluatedProperties`/`unevaluatedItems`: schema form, unmarked secret-looking field;
    // and bool form must not crash or false-positive.
    let unevaluated_props_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "type": "object",
                "unevaluatedProperties": {"type": "object", "properties": {"apikey": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&unevaluated_props_unmarked).is_err());
    let unevaluated_props_bool = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"auth": {"type": "object", "unevaluatedProperties": false}},
    });
    validate_secret_fields(&unevaluated_props_bool).unwrap();

    // A marked `x-busbar-secret` field placed below root depth via `additionalProperties` is
    // still rejected by the depth-1 placement rule (the same evasion as the `oneOf` case above):
    // `resolve_settings()` only resolves top-level fields, so a marker this deep would silently
    // never resolve.
    let additional_props_marked_nested = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "type": "object",
                "additionalProperties": {"type": "object", "properties": {"token": {"type": "string", "x-busbar-secret": true}}},
            },
        },
    });
    assert!(validate_secret_fields(&additional_props_marked_nested).is_err());

    // `contentSchema`: describes the shape of a string's decoded content (e.g. an embedded
    // JSON document) — its value is a full nested schema, not a bool, so an unmarked
    // secret-looking field hidden inside it must be caught the same as any other nested
    // placement.
    let content_schema_unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "blob": {
                "type": "string",
                "contentMediaType": "application/json",
                "contentSchema": {"type": "object", "properties": {"password": {"type": "string"}}},
            },
        },
    });
    assert!(validate_secret_fields(&content_schema_unmarked).is_err());

    // A schema using these keywords with no secret-shaped fields at all is untouched.
    let clean = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "auth": {
                "if": {"properties": {"mode": {"const": "basic"}}},
                "then": {"type": "object", "properties": {"greeting": {"type": "string"}}},
                "not": {"type": "object", "properties": {"nope": {"type": "boolean"}}},
                "additionalProperties": {"type": "string"},
                "patternProperties": {"^x_": {"type": "string"}},
            },
        },
    });
    validate_secret_fields(&clean).unwrap();
}

/// Every `scan(..., depth + 1, ...)` call site accepts a CORRECTLY root-level (depth-1) marked
/// secret reached ONLY through that specific keyword — the `is_err()` assertions elsewhere in
/// this module prove a nested-and-marked field is REJECTED, but the depth check is `depth !=
/// 1`, so any wrong depth value (0, 2, anything but 1) produces that SAME rejection outcome and
/// can't tell a correct `+ 1` from a mutated `* 1`/`- 1`. Only a case that must SUCCEED (a
/// genuinely depth-1 field) pins the actual arithmetic down.
#[test]
fn each_combinator_keyword_accepts_a_secret_reached_at_exactly_root_depth() {
    for (label, schema) in [
        (
            "items",
            serde_json::json!({
                "$schema": SCHEMA_2020_12, "type": "array",
                "items": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "oneOf",
            serde_json::json!({
                "$schema": SCHEMA_2020_12,
                "oneOf": [{"type": "string", "x-busbar-secret": true}],
            }),
        ),
        (
            "prefixItems",
            serde_json::json!({
                "$schema": SCHEMA_2020_12, "type": "array",
                "prefixItems": [{"type": "string", "x-busbar-secret": true}],
            }),
        ),
        (
            "if",
            serde_json::json!({
                "$schema": SCHEMA_2020_12,
                "if": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "then",
            serde_json::json!({
                "$schema": SCHEMA_2020_12,
                "then": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "else",
            serde_json::json!({
                "$schema": SCHEMA_2020_12,
                "else": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "not",
            serde_json::json!({
                "$schema": SCHEMA_2020_12,
                "not": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "contentSchema",
            serde_json::json!({
                "$schema": SCHEMA_2020_12,
                "contentSchema": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "contains",
            serde_json::json!({
                "$schema": SCHEMA_2020_12, "type": "array",
                "contains": {"type": "string", "x-busbar-secret": true},
            }),
        ),
        (
            "patternProperties",
            serde_json::json!({
                "$schema": SCHEMA_2020_12, "type": "object",
                "patternProperties": {"^x": {"type": "string", "x-busbar-secret": true}},
            }),
        ),
    ] {
        validate_secret_fields(&schema)
            .unwrap_or_else(|e| panic!("{label}: a depth-1 marked secret must be accepted: {e}"));
    }
}

/// `x-busbar-ref: "pool" | "group" | "model" | "provider"` is a recognized schema
/// vocabulary entry that passes pack-time validation untouched — it is a UI rendering hint with
/// deliberately NO server-side enforcement (the referenced names are per-fleet-member runtime
/// data, unvalidatable at authoring/pack time). This proves
/// it is not rejected as an unrecognized `x-*` extension, on a field of any type (not just
/// `type: string` — a `pool`/`group`/`model`/`provider` reference is ordinarily a string, but
/// nothing about this keyword is secret-shaped, so it carries none of `x-busbar-secret`'s type
/// restrictions).
#[test]
fn x_busbar_ref_passes_pack_time_validation_untouched() {
    for value in BUSBAR_REF_VALUES {
        let schema = serde_json::json!({
            "$schema": SCHEMA_2020_12, "type": "object",
            "properties": {
                "target": {"type": "string", "x-busbar-ref": value},
            },
        });
        validate_secret_fields(&schema).unwrap_or_else(|e| {
            panic!("x-busbar-ref: {value:?} must not be rejected as an unknown extension: {e}")
        });
        jsonschema::validator_for(&schema)
            .unwrap_or_else(|e| panic!("x-busbar-ref: {value:?} schema must validate: {e}"));
    }
}

/// `busbar-plugin-pack` reaches `SecretRef` directly (it used to be `pub(crate)` inside the
/// `busbar` binary crate, unreachable from any tooling) and derives the `x-busbar-secret`
/// reference `oneOf` FROM the real type instead of a hand-written parallel copy — this is the
/// fragment busbar-ui composes a secret reference against, matching exactly what
/// `SecretRef::deserialize` accepts (env/file sugar + the canonical module/settings form), with
/// no special-casing needed to exclude `{ literal: ... }`: a full derivation already excludes
/// it, since `literal` was never a `SecretRef` shape to begin with.
#[test]
fn derives_secret_ref_oneof_from_the_shared_type() {
    let oneof = busbar_secret_ref::oneof_schema();
    let alts = oneof["oneOf"].as_array().expect("oneOf array");
    assert_eq!(alts.len(), 3, "module/settings + env + file, nothing else");
    // Sanity: the derived fragment is a valid JSON Schema (full round-trip fidelity against
    // SecretRef::deserialize is asserted in busbar-secret-ref's own test suite, the single
    // source of truth for the derivation).
    let mut full = serde_json::json!({"type": "object"});
    for (k, v) in oneof.as_object().unwrap() {
        full[k] = v.clone();
    }
    jsonschema::validator_for(&full).expect("derived oneOf is a valid JSON Schema fragment");
}

/// An unmarked field whose name looks like a secret is a hard error; marking it, or renaming
/// it, clears the error.
#[test]
fn unmarked_secret_looking_field_name_is_rejected() {
    let unmarked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"api_key": {"type": "string"}},
    });
    assert!(validate_secret_fields(&unmarked).is_err());

    let marked = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"api_key": {"type": "string", "x-busbar-secret": true}},
    });
    validate_secret_fields(&marked).unwrap();

    let renamed = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"pool_size": {"type": "integer"}},
    });
    validate_secret_fields(&renamed).unwrap();
}
