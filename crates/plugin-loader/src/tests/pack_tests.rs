// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/pack.rs`.

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
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    };
    let signed = sign(&key, m, lib);
    busbar_plugin_loader::sign::validate_structure(
        &signed,
        lib,
        &busbar_plugin_loader::supported_abi,
        busbar_plugin_loader::sign::HOST_IDENTITY,
    )
    .expect("structural");
    let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib).unwrap();
    let up = busbar_plugin_loader::tarball::unpack(&tarball).unwrap();
    let mut policy = busbar_plugin_loader::sign::TrustPolicy::default();
    policy.publishers.insert("acme".into(), key.verifying_key());
    assert!(matches!(
        busbar_plugin_loader::sign::evaluate(&up.lib_bytes, &up.manifest, &policy).unwrap(),
        busbar_plugin_loader::sign::Verdict::Trusted { .. }
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

/// `--declares-file` embeds the plugin's `declares` section into the SIGNED manifest, parsed as the
/// type the loader verifies — so a dropped-in first-party sink ships the declarations its linked
/// twin states. RED arm, in the same test: a file with a key the section does not have is refused
/// at pack time and writes no tarball.
#[test]
fn pack_cli_embeds_the_declares_file() {
    let dir = std::env::temp_dir().join(format!("plugin-pack-declares-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib_path = dir.join("lib.so");
    std::fs::write(&lib_path, b"pretend cdylib").unwrap();
    let declares = serde_json::json!({
        "metrics": [{"name": "busbar_x_total", "type": "counter", "shed": true}],
        "diagnostics": [{"code": 7999, "slug": "x", "title": "X", "severity": "actionable",
                          "summary": "s", "action": "a", "since": "1.6.0"}],
        "destinations": ["path"],
    });
    let pack_with = |file: &str| {
        let path = dir.join("declares.json");
        std::fs::write(&path, file).unwrap();
        let out = dir.join("out.tar.gz");
        let _ = std::fs::remove_file(&out);
        let args: Vec<String> = [
            "--lib",
            &lib_path.to_string_lossy(),
            "--name",
            "n",
            "--alias",
            "n",
            "--kind",
            "export",
            "--version",
            "1.0.0",
            "--publisher",
            "p",
            "--out",
            &out.to_string_lossy(),
            "--declares-file",
            &path.to_string_lossy(),
            "--allow-unsigned",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let code = pack(&args);
        let unpacked = std::fs::read(&out).ok().map(|t| {
            busbar_plugin_loader::tarball::unpack(&t)
                .unwrap()
                .manifest
                .declares
        });
        (code, unpacked)
    };
    let (code, packed) = pack_with(&declares.to_string());
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(
        serde_json::to_value(packed.expect("the tarball was written")).unwrap(),
        declares
    );
    // RED ARM: not a `declares` section — refused, nothing written.
    let (code, packed) = pack_with(r#"{"metrics": [], "series": []}"#);
    assert_eq!(code, ExitCode::FAILURE);
    assert!(packed.is_none(), "a refused pack must not leave a tarball");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A declares file's `needs` (the transport schemes the conformance suite and the fleet render read)
/// is checked and left out of the SIGNED manifest: the needs belong to the Statement. RED ARMS, in
/// the same test: a malformed `needs` (not a list, a non-string, an empty name) is refused, and any
/// other unknown key is still refused beside a well-formed `needs`; each writes no tarball.
#[test]
fn pack_cli_leaves_the_declares_needs_out_of_the_manifest() {
    let dir = std::env::temp_dir().join(format!("plugin-pack-needs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib_path = dir.join("lib.so");
    std::fs::write(&lib_path, b"pretend cdylib").unwrap();
    let pack_with = |file: &str| {
        let path = dir.join("declares.json");
        std::fs::write(&path, file).unwrap();
        let out = dir.join("out.tar.gz");
        let _ = std::fs::remove_file(&out);
        let args: Vec<String> = [
            "--lib",
            &lib_path.to_string_lossy(),
            "--name",
            "n",
            "--alias",
            "n",
            "--kind",
            "export",
            "--version",
            "1.0.0",
            "--publisher",
            "p",
            "--out",
            &out.to_string_lossy(),
            "--declares-file",
            &path.to_string_lossy(),
            "--allow-unsigned",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let code = pack(&args);
        let manifest = std::fs::read(&out)
            .ok()
            .map(|t| busbar_plugin_loader::tarball::unpack(&t).unwrap().manifest);
        (code, manifest)
    };
    let declared = serde_json::json!({"destinations": ["url"]});
    let mut with_needs = declared.clone();
    with_needs["needs"] = serde_json::json!(["scheme-a", "scheme-b"]);
    let (code, manifest) = pack_with(&with_needs.to_string());
    assert_eq!(code, ExitCode::SUCCESS);
    let manifest = manifest.expect("the tarball was written");
    assert_eq!(serde_json::to_value(&manifest.declares).unwrap(), declared);
    let signed = serde_json::to_value(&manifest).unwrap();
    assert!(
        signed["declares"].get("needs").is_none(),
        "the signed manifest carries no needs: {signed}"
    );
    // RED ARMS: a malformed `needs` is refused, nothing written.
    for bad in [
        r#"{"needs": "scheme-a"}"#,
        r#"{"needs": [7]}"#,
        r#"{"needs": [""]}"#,
    ] {
        let (code, manifest) = pack_with(bad);
        assert_eq!(code, ExitCode::FAILURE, "{bad} must be refused");
        assert!(
            manifest.is_none(),
            "{bad}: a refused pack must not leave a tarball"
        );
    }
    // RED ARM: any other unknown key is still refused beside a well-formed `needs`.
    let (code, manifest) = pack_with(r#"{"needs": ["scheme-a"], "series": []}"#);
    assert_eq!(code, ExitCode::FAILURE);
    assert!(
        manifest.is_none(),
        "a refused pack must not leave a tarball"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--former-name` (repeatable) signs the plugin's former manifest names into the manifest, in
/// order, so a tarball released under a new name still answers the name its 1.5.5 release carried.
/// RED ARMS, in the same test: a former name outside the alias charset, or one that repeats the
/// plugin's own name, is refused at pack time and writes no tarball.
#[test]
fn pack_cli_signs_the_former_names() {
    let dir = std::env::temp_dir().join(format!("plugin-pack-former-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib_path = dir.join("lib.so");
    std::fs::write(&lib_path, b"pretend cdylib").unwrap();
    let pack_with = |former: &[&str]| {
        let out = dir.join("out.tar.gz");
        let _ = std::fs::remove_file(&out);
        let mut args: Vec<String> = [
            "--lib",
            &lib_path.to_string_lossy(),
            "--name",
            "busbar-hook-webrequest",
            "--alias",
            "webrequest",
            "--kind",
            "hook",
            "--version",
            "1.0.0",
            "--publisher",
            "p",
            "--out",
            &out.to_string_lossy(),
            "--allow-unsigned",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for f in former {
            args.extend(["--former-name".to_string(), (*f).to_string()]);
        }
        let code = pack(&args);
        let unpacked = std::fs::read(&out)
            .ok()
            .map(|t| busbar_plugin_loader::tarball::unpack(&t).unwrap().manifest);
        (code, unpacked)
    };
    let (code, packed) = pack_with(&["busbar-webrequest", "busbar-webrequest-hook"]);
    assert_eq!(code, ExitCode::SUCCESS);
    let m = packed.expect("the tarball was written");
    assert_eq!(
        m.former_names,
        ["busbar-webrequest", "busbar-webrequest-hook"]
    );
    assert!(m.answers_to("busbar-webrequest") && m.answers_to("webrequest"));
    // With none given the manifest carries none (and its bytes are an old manifest's).
    let (code, packed) = pack_with(&[]);
    assert_eq!(code, ExitCode::SUCCESS);
    let m = packed.expect("the tarball was written");
    assert!(m.former_names.is_empty());
    assert!(
        !String::from_utf8(busbar_plugin_loader::sign::canonical_manifest_bytes(&m))
            .unwrap()
            .contains("former_names")
    );
    // RED ARMS: not the alias charset; the plugin's own name.
    for bad in ["Busbar_WebRequest", "busbar-hook-webrequest", "webrequest"] {
        let (code, packed) = pack_with(&[bad]);
        assert_eq!(code, ExitCode::FAILURE, "{bad}");
        assert!(
            packed.is_none(),
            "a refused pack must not leave a tarball ({bad})"
        );
    }
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
    let lib = b"pretend compress cdylib";
    let m = Manifest {
        name: "busbar-compress".into(),
        alias: "compress".into(),
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
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    };
    let signed = sign(&key, m, lib);
    assert_eq!(signed.needs.prompt, NeedLevel::Rw);
    busbar_plugin_loader::sign::validate_structure(
        &signed,
        lib,
        &busbar_plugin_loader::supported_abi,
        busbar_plugin_loader::sign::HOST_IDENTITY,
    )
    .expect("structural");
    // Tampering the declared intent after signing breaks verification (needs is signed).
    let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib).unwrap();
    let up = busbar_plugin_loader::tarball::unpack(&tarball).unwrap();
    let policy = busbar_plugin_loader::sign::TrustPolicy {
        first_party_keys: vec![busbar_plugin_loader::sign::FirstPartyKey::unnamed(
            key.verifying_key(),
        )],
        binary_version: "1.5.0".into(),
        ..Default::default()
    };
    assert!(matches!(
        busbar_plugin_loader::sign::evaluate(&up.lib_bytes, &up.manifest, &policy).unwrap(),
        busbar_plugin_loader::sign::Verdict::Trusted { .. }
    ));
}

#[test]
fn flag_parsing() {
    let args: Vec<String> = ["--lib", "a.so", "--allow-unsigned", "--name", "n"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let Flags {
        map: flags,
        allow_unsigned: unsigned,
        schema_derived,
        former_names,
    } = parse_flags(&args).unwrap();
    assert!(unsigned);
    assert!(!schema_derived);
    assert!(former_names.is_empty());
    assert_eq!(flags["lib"], "a.so");
    assert_eq!(flags["name"], "n");
    assert!(parse_flags(&["--dangling".to_string()]).is_err());
    assert!(parse_flags(&["bare".to_string()]).is_err());

    let with_derived: Vec<String> = ["--schema-derived", "--lib", "a.so"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(parse_flags(&with_derived).unwrap().schema_derived);

    // `--former-name` is REPEATABLE: every value is kept, in order, and none lands in the map.
    let former: Vec<String> = [
        "--former-name",
        "busbar-webrequest",
        "--name",
        "busbar-hook-webrequest",
        "--former-name",
        "busbar-webrequest-hook",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let f = parse_flags(&former).unwrap();
    assert_eq!(
        f.former_names,
        ["busbar-webrequest", "busbar-webrequest-hook"]
    );
    assert!(!f.map.contains_key(FORMER_NAME));
    assert_eq!(f.map["name"], "busbar-hook-webrequest");
    assert!(parse_flags(&["--former-name".to_string()]).is_err());
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

/// A SECRET MARKER ONE OBJECT DOWN IS REFUSED IN 1.5.5's WORDS (ruling (B), 2026-10-19: pack keeps
/// 1.5.5's refusal of a nested marker; v1.5.5 `crates/plugin-pack/src/main.rs:298-304`). A marked
/// `held.value` sits at nesting depth 2, and the refusal names that depth and says to
/// flatten the field. RED before the fix: the refusal's words were not 1.5.5's.
#[test]
fn a_nested_secret_marker_is_refused_in_1_5_5_words() {
    let nested = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {
            "held": {
                "type": "object",
                "properties": {"value": {"type": "string", "x-busbar-secret": true}},
            },
        },
    });
    assert_eq!(
        validate_secret_fields(&nested).unwrap_err(),
        "x-busbar-secret: true is only allowed on a direct root-level property (found at nesting \
         depth 2) — flatten the field to a root property instead"
    );
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

/// The marker rule is about WHERE a field sits, not how many levels down the walk happened to be.
/// A schema under `patternProperties` is one level from the root and is NOT a root property —
/// `resolve_settings()` will never resolve it, so a secret marked there silently never resolves,
/// which is the whole reason for the rule.
#[test]
fn a_secret_marker_under_pattern_properties_is_rejected() {
    let schema = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "patternProperties": {
            "^backend_": {"type": "string", "x-busbar-secret": true},
        },
    });
    assert!(
        validate_secret_fields(&schema).is_err(),
        "a marker one level down but NOT in the root `properties` map must be rejected"
    );
}

/// And the other side of the same ruling: a root `oneOf` whose alternatives each spell out the root
/// object's own shape declares ROOT properties, however many structural levels down they sit. A
/// depth counter refuses these, and refusing them tells a plugin author to flatten a field that is
/// already as flat as it can be.
#[test]
fn a_root_oneof_alternative_may_mark_its_top_level_property() {
    let schema = serde_json::json!({
        "$schema": SCHEMA_2020_12,
        "oneOf": [
            {
                "type": "object",
                "properties": {"api_key": {"type": "string", "x-busbar-secret": true}},
                "required": ["api_key"],
            },
            {
                "type": "object",
                "properties": {"anonymous": {"type": "boolean"}},
                "required": ["anonymous"],
            },
        ],
    });
    validate_secret_fields(&schema)
        .expect("a root oneOf alternative's own top-level property IS a root property");
}

/// A `$defs` entry that refers to ITSELF is not caught by the cyclic-`$ref` guard: that guard
/// unwinds as each resolution returns, so every individual step resolves cleanly and the walk simply
/// never ends. On operator-supplied input at pack time the result is a stack overflow — an abort with
/// no diagnostic, the one outcome a validator must not have. It returns an error instead.
#[test]
fn a_self_recursive_defs_schema_is_refused_rather_than_overflowing_the_stack() {
    let recursive = serde_json::json!({
        "$schema": SCHEMA_2020_12,
        "$ref": "#/$defs/Node",
        "$defs": {
            "Node": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "child": {"$ref": "#/$defs/Node"},
                },
            },
        },
    });
    let err = validate_secret_fields(&recursive).unwrap_err();
    assert!(
        err.contains("nests deeper"),
        "a self-recursive schema must be refused with a diagnostic, got: {err}"
    );
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

/// None of these keywords is the root `properties` map, so a marker reached through any of them is
/// REFUSED however few levels down it sits. This table used to assert the opposite, because the rule
/// was written as "exactly one level down" and each of these puts a schema exactly one level down —
/// so a secret marked under `items` or `patternProperties` packaged clean while `resolve_settings()`,
/// which resolves the root object's own named fields and nothing else, could never resolve it. The
/// positive control at the end pins the tracking down: a rule that simply refused everything would
/// satisfy a table of `is_err()`s just as well.
#[test]
fn every_keyword_but_the_root_properties_map_refuses_a_marker() {
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
        assert!(
            validate_secret_fields(&schema).is_err(),
            "{label}: a marker reached through this keyword is not on a root property and must be \
             refused"
        );
    }

    // The positive control, in the one place the marker belongs.
    let root_property = serde_json::json!({
        "$schema": SCHEMA_2020_12, "type": "object",
        "properties": {"api_key": {"type": "string", "x-busbar-secret": true}},
    });
    validate_secret_fields(&root_property)
        .expect("a direct member of the root properties map is exactly where a marker belongs");
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
/// `SecretRef::deserialize` accepts (env/file sugar, the canonical module/settings form, and the
/// keyless `none` scalar), with
/// no special-casing needed to exclude `{ literal: ... }`: a full derivation already excludes
/// it, since `literal` was never a `SecretRef` shape to begin with.
#[test]
fn derives_secret_ref_oneof_from_the_shared_type() {
    let oneof = busbar_contract::secret_ref::oneof_schema();
    let alts = oneof["oneOf"].as_array().expect("oneOf array");
    assert_eq!(
        alts.len(),
        4,
        "the `none` scalar + module/settings + env + file, nothing else"
    );
    // Sanity: the derived fragment is a valid JSON Schema (full round-trip fidelity against
    // SecretRef::deserialize is asserted in the contract's `secret_ref` test suite, the single
    // source of truth for the derivation). No `type` constraint of our own: one alternative is a
    // scalar (`none`), the rest are objects.
    let mut full = serde_json::json!({});
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

/// The `$ref`/`allOf` resolver carries its OWN depth cap, and needs to.
///
/// `scan`'s `MAX_SCAN_DEPTH` counts the levels IT descends, and this resolver recurses into itself
/// — once through `$ref`, once per `allOf` member — without ever passing back through `scan`, so a
/// chain that lives entirely inside the resolve step advances that counter not at all. The
/// `resolving` set is not the backstop either: it catches a `$ref` that closes a cycle, and says
/// nothing about a chain that is merely very long. What is left is operator-supplied input at pack
/// time recursing as deep as it likes, and the failure at the end of that is a stack overflow — an
/// abort with no diagnostic, which is the one answer a validator must never give.
#[test]
fn the_ref_resolver_caps_its_own_depth() {
    // A NON-cyclic `allOf` chain, longer than the cap: `L0 -> L1 -> … -> L200`. Every link resolves,
    // nothing repeats, so neither the cycle guard nor `scan`'s counter has anything to say about it.
    const LINKS: usize = 200;
    let mut defs = serde_json::Map::new();
    for i in 0..LINKS {
        let body = if i + 1 == LINKS {
            serde_json::json!({"type": "object", "properties": {"leaf": {"type": "string"}}})
        } else {
            serde_json::json!({"allOf": [{"$ref": format!("#/$defs/L{}", i + 1)}]})
        };
        defs.insert(format!("L{i}"), body);
    }
    let deep = serde_json::json!({
        "$schema": SCHEMA_2020_12,
        "$ref": "#/$defs/L0",
        "$defs": serde_json::Value::Object(defs),
    });
    let err = validate_secret_fields(&deep)
        .expect_err("a chain past the cap must be refused, not resolved");
    assert!(
        err.contains("while resolving"),
        "the RESOLVER's own cap must be what stops this — `scan`'s counter never advances inside a \
         resolve chain, so a refusal from there would mean the test is not exercising this cap at \
         all; got: {err}"
    );

    // NEGATIVE CONTROL: a chain WELL inside the cap still validates — the cap bounds the
    // pathological case, it is not a new limit on schemas people actually write. Without this arm
    // a resolver that refused EVERY chain would pass the red arm above.
    let mut defs = serde_json::Map::new();
    for i in 0..8 {
        let body = if i == 7 {
            serde_json::json!({"type": "object", "properties": {"leaf": {"type": "string"}}})
        } else {
            serde_json::json!({"allOf": [{"$ref": format!("#/$defs/S{}", i + 1)}]})
        };
        defs.insert(format!("S{i}"), body);
    }
    let shallow = serde_json::json!({
        "$schema": SCHEMA_2020_12,
        "$ref": "#/$defs/S0",
        "$defs": serde_json::Value::Object(defs),
    });
    validate_secret_fields(&shallow).expect("an ordinary nested schema still validates");
}

/// ONE VERSION PER PLUGIN: a `--version` the plugin's Statement does not state is refused, naming
/// both (RED); the version it states packs (GREEN).
#[test]
fn pack_refuses_a_version_the_statement_does_not_state() {
    // A plugin's Statement, rendered as its door renders it.
    let st = busbar_contract::abi::sdk::door::statement("pack-version-witness", "1.5.0", 1);
    // SAFETY: `st` is a well-formed Statement of 'static strings and empty lists.
    let stated =
        unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }.expect("it renders");
    let r = busbar_contract::abi::mechanism::rendering::read(&stated).expect("it reads back");
    super::statement_version_is(&stated, &r.version).expect("its own version packs");
    assert_eq!(
        super::stated_version(&stated).as_deref(),
        Ok(r.version.as_str()),
        "an absent --version is the Statement's"
    );
    let refused =
        super::statement_version_is(&stated, "999.0.0").expect_err("another version is refused");
    assert!(
        refused.contains("--version 999.0.0") && refused.contains(&format!("({})", r.version)),
        "names both versions: {refused}"
    );
    assert!(
        super::statement_version_is(b"not a rendering", &r.version).is_err(),
        "an unreadable rendering is refused, never passed"
    );
}

// ── ONE SIGNATURE PER RELEASE: release-manifest -> (signer) -> envelope -> seal -> verify ───────

/// An UNSIGNED first-party tarball, as a release's pack step emits it.
fn unsigned_first_party(name: &str, lib: &[u8]) -> Vec<u8> {
    let m = Manifest {
        name: name.into(),
        alias: name.trim_start_matches("busbar-store-").into(),
        kind: "store".into(),
        version: "1.6.0".into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: busbar_plugin_loader::supported_abi("store")
            .iter()
            .copied()
            .max()
            .unwrap(),
        sha256: busbar_plugin_loader::sign::sha256_hex(lib),
        ..Default::default()
    };
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// A P-256 key the test holds (what KMS, the PIV slot or the interim signer hold).
struct P256(ring::signature::EcdsaKeyPair);

impl P256 {
    fn new() -> Self {
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ALG, &rng).unwrap();
        P256(EcdsaKeyPair::from_pkcs8(&ALG, pkcs8.as_ref(), &rng).unwrap())
    }
    fn spec(&self) -> String {
        use ring::signature::KeyPair as _;
        format!("p256:{}", hex::encode(self.0.public_key().as_ref()))
    }
    fn key(&self) -> ReleaseKey {
        public_key(&self.spec()).unwrap()
    }
    /// What `openssl dgst -sha256 -sign`, `gcloud kms asymmetric-sign` and the PIV slot return: DER.
    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        self.0
            .sign(&ring::rand::SystemRandom::new(), bytes)
            .unwrap()
            .as_ref()
            .to_vec()
    }
    fn root(&self, id: &str) -> FirstPartyKey {
        FirstPartyKey {
            id: id.into(),
            key: self.key(),
        }
    }
}

const TARGET_A: &str = "x86_64-unknown-linux-gnu";
const TARGET_B: &str = "aarch64-apple-darwin";

/// A keys document `root` vouches for, naming `signer`, expiring 2099.
fn keys_envelope(root: &P256, signer: &P256) -> Vec<u8> {
    let spec = format!(
        r#"{{"version": 1, "expires": "2099-01-01T00:00:00Z", "signers": ["{}"]}}"#,
        signer.spec()
    );
    let signed = keys_doc_bytes(spec.as_bytes()).unwrap();
    envelope(&signed, &root.key(), &root.sign(&signed)).unwrap()
}

/// GREEN: one release manifest lists every tarball of the release for its target, one signature
/// covers it, and each tarball sealed with it verifies for its own target and loads as first-party
/// under the engine's own trust evaluation on its own target.
#[test]
fn one_signature_seals_every_tarball_of_a_release() {
    let (kms, piv, signer) = (P256::new(), P256::new(), P256::new());
    let roots = vec![
        kms.root("busbar-plugins-root"),
        piv.root("busbar-plugins-2026a"),
    ];
    let tarballs = [
        (unsigned_first_party("busbar-store-x", b"x on a"), TARGET_A),
        (unsigned_first_party("busbar-store-x", b"x on b"), TARGET_B),
        (unsigned_first_party("busbar-store-y", b"y on a"), TARGET_A),
        (
            unsigned_first_party("busbar-store-y", b"y here"),
            release_trust::PLUGIN_TARGET,
        ),
    ];
    let entries = tarballs
        .iter()
        .map(|(t, target)| release_entry(t, target).unwrap())
        .collect::<Vec<_>>();
    let signed = release_manifest_bytes(
        1,
        wire::parse_time("2099-01-01T00:00:00Z").unwrap(),
        entries,
    )
    .unwrap();
    let release = envelope(&signed, &signer.key(), &signer.sign(&signed)).unwrap();
    let keys = keys_envelope(&kms, &signer);
    for (unsigned, target) in &tarballs {
        let (sealed, root) = seal(unsigned, &keys, &release, target, &roots).unwrap();
        assert_eq!(root, "busbar-plugins-root");
        assert_eq!(verify_first_party(&sealed, &roots, target).unwrap(), root);
        if *target == release_trust::PLUGIN_TARGET {
            let up = busbar_plugin_loader::tarball::unpack(&sealed).unwrap();
            let policy = busbar_plugin_loader::sign::TrustPolicy {
                first_party_keys: roots.clone(),
                ..Default::default()
            };
            assert!(matches!(
                busbar_plugin_loader::sign::evaluate(&up.lib_bytes, &up.manifest, &policy),
                Ok(busbar_plugin_loader::sign::Verdict::Trusted {
                    first_party: true,
                    ..
                })
            ));
        }
    }
}

/// RED: every shape the release tooling must refuse.
#[test]
fn the_release_tooling_refuses_what_would_not_load_as_first_party() {
    let (kms, signer, stranger) = (P256::new(), P256::new(), P256::new());
    let roots = vec![kms.root("busbar-plugins-root")];
    let x = unsigned_first_party("busbar-store-x", b"x");
    let y = unsigned_first_party("busbar-store-y", b"y");
    let far = wire::parse_time("2099-01-01T00:00:00Z").unwrap();
    let signed =
        release_manifest_bytes(1, far, vec![release_entry(&x, TARGET_A).unwrap()]).unwrap();
    let release = envelope(&signed, &signer.key(), &signer.sign(&signed)).unwrap();
    let keys = keys_envelope(&kms, &signer);

    let e = envelope(&signed, &signer.key(), &stranger.sign(&signed)).unwrap_err();
    assert!(
        e.contains("does not verify"),
        "a signature by another key: {e}"
    );

    let e = seal(&y, &keys, &release, TARGET_A, &roots).unwrap_err();
    assert!(
        e.contains("does not list 'busbar-store-y'"),
        "unlisted: {e}"
    );

    let e = seal(&x, &keys, &release, TARGET_B, &roots).unwrap_err();
    assert!(
        e.contains("not for this binary's target"),
        "wrong target: {e}"
    );

    let other = vec![P256::new().root("other-root")];
    let e = seal(&x, &keys, &release, TARGET_A, &other).unwrap_err();
    assert!(
        e.contains("[other-root]"),
        "a keys document no listed root signed: {e}"
    );
    assert!(
        seal(&x, &keys, &release, TARGET_A, &[]).is_err(),
        "no root verifies nothing"
    );

    let (sealed, _) = seal(&x, &keys, &release, TARGET_A, &roots).unwrap();
    assert!(
        seal(&sealed, &keys, &release, TARGET_A, &roots)
            .unwrap_err()
            .contains("already"),
        "an already-sealed tarball is refused"
    );
    let mut third = busbar_plugin_loader::tarball::unpack(&x).unwrap().manifest;
    third.publisher = "acme".into();
    let third = busbar_plugin_loader::tarball::package(&third, "lib.so", b"x").unwrap();
    assert!(
        release_entry(&third, TARGET_A).is_err(),
        "a release lists first-party plugins only"
    );
    assert!(
        release_manifest_bytes(
            1,
            far,
            vec![
                release_entry(&x, TARGET_A).unwrap(),
                release_entry(&x, TARGET_A).unwrap()
            ]
        )
        .is_err(),
        "an entry listed twice is refused"
    );
    assert!(
        keys_doc_bytes(br#"{"version":1,"expires":"2099-01-01T00:00:00Z","signers":[]}"#).is_err()
    );
    assert!(keys_doc_bytes(
        format!(
            r#"{{"version":1,"expires":"2099-01-01T00:00:00Z","signers":["{}"],"threshold":0}}"#,
            signer.spec()
        )
        .as_bytes()
    )
    .is_err());
}

/// VERIFY names the trusted root ids for a per-plugin signature by a key not in the list; the
/// loader's own reason stays 1.5.5's bare "signature does not verify".
#[test]
fn verify_refuses_an_unlisted_key_naming_the_trusted_ids() {
    use ed25519_dalek::Signer as _;
    let stranger = SigningKey::from_bytes(&[13; 32]);
    let roots = vec![P256::new().root("busbar-plugins-root")];
    let unsigned = unsigned_first_party("busbar-store-x", b"cdylib");
    let up = busbar_plugin_loader::tarball::unpack(&unsigned).unwrap();
    let manifest = Manifest {
        signature: hex::encode(
            stranger
                .sign(&canonical_manifest_bytes(&up.manifest))
                .to_bytes(),
        ),
        ..up.manifest
    };
    let signed =
        busbar_plugin_loader::tarball::package(&manifest, "lib.so", &up.lib_bytes).unwrap();
    assert_eq!(
        verify_first_party(&signed, &roots, TARGET_A).unwrap_err(),
        "signature verifies against none of this build's first-party keys [busbar-plugins-root]"
    );
}

/// The CLI contract the release gate drives: `canonical --out`, `keyid`, and an unknown flag
/// refused.
#[test]
fn the_release_cli_names_the_canonical_bytes_and_key_ids() {
    let unsigned = unsigned_first_party("busbar-store-x", b"cdylib");
    let dir = std::env::temp_dir().join(format!("pack-release-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let tgz = dir.join("u.tar.gz");
    std::fs::write(&tgz, &unsigned).unwrap();
    let canon = dir.join("u.canonical");
    let line = canonical_cli(&[
        tgz.display().to_string(),
        "--out".into(),
        canon.display().to_string(),
    ])
    .unwrap();
    let bytes = std::fs::read(&canon).unwrap();
    assert!(
        line.starts_with(&format!("canonical-sha256={} ", sha256_hex(&bytes))),
        "{line}"
    );
    assert!(
        line.contains(" publisher=busbar ") && line.ends_with(" signed=false"),
        "{line}"
    );
    let k = P256::new();
    assert_eq!(keyid_cli(&[k.spec()]).unwrap(), wire::key_id(&k.key()));
    assert!(
        release_args(&["x".into(), "--bogus".into(), "1".into()], &["out"]).is_err(),
        "an unknown flag is refused"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// THE PUBLIC DECLARATION (owner ruling 2026-10-27, sensitive by default): `x-busbar-public: true`
/// on a plainly non-secret root setting packs; one on a credential-looking field, on a field also
/// marked secret, below the root, or with any value but `true` is refused naming the field.
#[test]
fn pack_refuses_a_credential_declared_public() {
    let schema = |properties: serde_json::Value| {
        serde_json::json!({
            "$schema": SCHEMA_2020_12, "type": "object", "properties": properties,
        })
    };
    validate_secret_fields(&schema(serde_json::json!({
        "url": {"type": "string", "x-busbar-public": true},
        "timeout_ms": {"type": "integer", "x-busbar-public": true},
    })))
    .unwrap();
    let refused = |properties: serde_json::Value| {
        validate_secret_fields(&schema(properties)).expect_err("refused")
    };
    assert!(refused(serde_json::json!({
        "api_token": {"type": "string", "x-busbar-public": true}
    }))
    .starts_with("field 'api_token' looks like a credential and cannot be declared"));
    assert!(refused(serde_json::json!({
        "dsn": {"type": "string", "x-busbar-secret": true, "x-busbar-public": true}
    }))
    .starts_with("field 'dsn' looks like a credential"));
    assert!(refused(serde_json::json!({
        "tls": {"type": "object", "properties": {"ca": {"type": "string", "x-busbar-public": true}}}
    }))
    .contains("only allowed on a direct root-level property"));
    assert!(refused(serde_json::json!({
        "url": {"type": "string", "x-busbar-public": "yes"}
    }))
    .contains("is `true` or absent"));
}
