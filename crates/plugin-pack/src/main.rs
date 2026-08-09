// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-plugin-pack` - the packaging + signing tool for busbar plugins.
//!
//! A busbar plugin ships as ONE signed `.tar.gz` containing exactly the cdylib and its signed
//! `manifest.json`. This tool builds that artifact:
//!
//! ```text
//! busbar-plugin-pack pack \
//!     --lib target/release/libbusbar_store_valkey_plugin.so \
//!     --name busbar-store-valkey-plugin --alias valkey --kind store \
//!     --version 1.5.0 --publisher busbar \
//!     --out busbar-store-valkey-1.5.0-x86_64-linux.tar.gz
//! ```
//!
//! The ed25519 SIGNING key is read from the `BUSBAR_SIGN_KEY` environment variable (64 hex chars:
//! the 32-byte seed) - in CI this is the release secret; a third-party publisher uses their own.
//! With no key set, `--allow-unsigned` produces an UNSIGNED tarball (dev only: busbar loads it
//! solely under `plugins.trust.allow_unsigned: true`).
//!
//! `busbar-plugin-pack keygen` generates a fresh keypair and prints both halves (hex). The PUBLIC
//! half goes in `plugins.trust.publishers` (third-party) or is embedded into the busbar binary at
//! build time via `BUSBAR_RELEASE_PUBKEY` (first-party); the PRIVATE half is the signing secret.

use busbar_plugin_sign::{sign, HookNeeds, Manifest, NeedLevel, SigningKey};
use std::collections::{HashMap, HashSet};
use std::process::ExitCode;

const SIGN_KEY_ENV: &str = "BUSBAR_SIGN_KEY";

/// The ONLY `$schema` value `--settings-schema-file` accepts.
/// `jsonschema::validator_for` auto-detects draft from `$schema` and silently falls back to
/// whatever draft it currently defaults to when the field is absent — it does not itself refuse
/// an older draft. busbar-ui ships exactly one 2020-12 form renderer, so a draft-07 document
/// (boolean `exclusiveMinimum`, `definitions` instead of `$defs`, ...) must never ship even
/// though it would compile fine as "a well-formed JSON Schema" of some draft.
const SCHEMA_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

/// Field-name heuristic: an UNMARKED field whose name matches one of these
/// (case-insensitive substring) is hard-rejected at pack time — the only mitigation against a
/// third-party author silently shipping a plaintext-credential text box that doesn't depend on
/// remembering to mark it. Deliberately not exhaustive; it converts a silent security failure
/// into a loud packaging error for the overwhelmingly common case.
const SECRET_NAME_HINTS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "passphrase",
    "private_key",
    "apikey",
    "api_key",
];

/// The `x-busbar-ref` schema vocabulary entry: `x-busbar-ref: "pool" | "group" | "model" |
/// "provider"` on a field tells busbar-ui to render a picker populated from the relevant admin API
/// listing endpoint, not a free-text box. This is a UI-ONLY rendering hint — there is deliberately
/// NO server-side enforcement of it (the values it names are per-fleet-member runtime data, not
/// something a manifest schema or this pack-time tool could ever validate against). The only
/// pack-time requirement is that it not be silently swallowed as an unrecognized `x-*` extension:
/// `jsonschema::validator_for` already tolerates unknown keywords by design (JSON Schema itself is
/// forward-compatible with unrecognized keys), so `x-busbar-ref` passes through pack-time validation
/// with no code change required — this constant exists purely so the accepted value set is named
/// ONE place instead of only in prose, for the (optional, non-blocking) sanity check below.
#[cfg(test)]
const BUSBAR_REF_VALUES: &[&str] = &["pool", "group", "model", "provider"];

/// Parse a `--needs-*` flag value into a [`NeedLevel`] (`no` | `ro` | `rw`). This is the ADVISORY
/// declared-intent a `kind: hook` plugin's manifest carries — it is SIGNED (so it cannot be spoofed)
/// and surfaced to the admin at register/load, but the operator's config grant remains the
/// enforcement. An unknown value is a hard error (a fat-fingered intent must not silently default).
fn parse_need_level(s: &str) -> Result<NeedLevel, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "no" | "none" | "" => Ok(NeedLevel::No),
        "ro" | "read" => Ok(NeedLevel::Ro),
        "rw" | "readwrite" | "read-write" => Ok(NeedLevel::Rw),
        other => Err(format!("need level '{other}' is not one of no|ro|rw")),
    }
}

fn usage() -> &'static str {
    "busbar-plugin-pack - package + sign a busbar plugin tarball

USAGE:
    busbar-plugin-pack pack --lib <cdylib> --name <name> --alias <alias> --kind <store|auth|hook|secret>
                            --version <semver> --publisher <publisher> --out <file.tar.gz>
                            [--description <text>] [--homepage <url>] [--license <spdx>]
                            [--needs-prompt <no|ro|rw>] [--needs-user <no|ro>]
                            [--settings-schema-file <path.json>] [--schema-derived]
                            [--allow-unsigned]
    busbar-plugin-pack keygen

    pack     builds manifest.json over the cdylib (sha256 binding), signs it with the ed25519 seed
             in $BUSBAR_SIGN_KEY (64 hex chars), and writes the {cdylib + manifest.json} .tar.gz.
             --allow-unsigned permits packaging WITHOUT a signature (dev only; busbar loads such a
             tarball only under plugins.trust.allow_unsigned: true).
             --needs-prompt / --needs-user declare a kind:hook plugin's ADVISORY intent (what caller
             content it asks to receive); SIGNED into the manifest. The operator's config grant still
             enforces — a plugin gets prompt/user content only when BOTH the manifest declares the
             need AND the operator grants it. A prompt:rw rewrite gate packs with --needs-prompt rw.
             --settings-schema-file embeds the plugin's `settings` shape as a JSON Schema document
             (generate it from the plugin's own config struct via the busbar-plugin-sdk schema_for!
             build-time macro — this tool only validates and embeds, it never generates and cannot,
             since it has no access to the plugin's Rust source). Rejected at pack time unless:
             `$schema` is exactly \"https://json-schema.org/draft/2020-12/schema\"; every
             `x-busbar-secret: true` field is a direct root-level property (never nested — $ref/
             allOf are resolved first) and is `type: string` (optionally `contentEncoding:
             \"base64\"` for a binary secret); and no UNMARKED field name matches
             password|secret|token|credential|passphrase|private_key|apikey|api_key
             (case-insensitive). Powers GET /plugins/{name}/schema without ever loading the plugin.
             --schema-derived asserts (SELF-ATTESTED, not verified by this tool) that the schema
             file was generated by the busbar-plugin-sdk macro from the same struct `open()`
             parses, not hand-written — copied verbatim into the manifest's schema_derived field.
    keygen   generates a fresh ed25519 keypair and prints both halves as hex. Keep the private half
             secret (it becomes $BUSBAR_SIGN_KEY); publish/allowlist/embed the public half."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(),
        Some("pack") => pack(&args[1..]),
        Some("--help" | "-h") | None => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

/// Generate a fresh ed25519 keypair from the OS RNG and print both halves (hex).
fn keygen() -> ExitCode {
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed) {
        eprintln!("error: OS RNG unavailable: {e}");
        return ExitCode::FAILURE;
    }
    let key = SigningKey::from_bytes(&seed);
    println!(
        "private (BUSBAR_SIGN_KEY, keep secret): {}",
        hex::encode(seed)
    );
    println!(
        "public  (publishers allowlist / BUSBAR_RELEASE_PUBKEY): {}",
        hex::encode(key.verifying_key().to_bytes())
    );
    ExitCode::SUCCESS
}

/// Parse `--flag value` pairs plus the bare `--allow-unsigned` / `--schema-derived` flags.
fn parse_flags(args: &[String]) -> Result<(HashMap<String, String>, bool, bool), String> {
    let mut map = HashMap::new();
    let mut allow_unsigned = false;
    let mut schema_derived = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--allow-unsigned" {
            allow_unsigned = true;
            continue;
        }
        if a == "--schema-derived" {
            schema_derived = true;
            continue;
        }
        let Some(name) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument '{a}'"));
        };
        let Some(v) = it.next() else {
            return Err(format!("--{name} requires a value"));
        };
        map.insert(name.to_string(), v.clone());
    }
    Ok((map, allow_unsigned, schema_derived))
}

/// Read `--settings-schema-file`'s contents and reject them at PACK time if they're not a
/// syntactically valid, DRAFT-2020-12 JSON Schema document, or if they misuse `x-busbar-secret` —
/// a broken/unsafe schema must never ship and only be discovered later when busbar-ui tries to
/// render a form from it. The file's exact
/// bytes (not a re-serialized/reformatted copy) are what get embedded and signed — so an operator
/// or busbar-ui reading the manifest back sees byte-for-byte what the plugin author wrote.
fn read_and_validate_settings_schema(path: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read --settings-schema-file '{path}': {e}"))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("--settings-schema-file '{path}' is not valid JSON: {e}"))?;
    // `jsonschema::validator_for` auto-detects draft from `$schema` and silently falls back to
    // whatever draft it currently defaults to when the field is absent — it does NOT itself
    // refuse an older draft, so the exact-match check is required, not redundant with the line
    // below.
    let schema_uri = value.get("$schema").and_then(|s| s.as_str());
    if schema_uri != Some(SCHEMA_2020_12) {
        return Err(format!(
            "--settings-schema-file '{path}': \"$schema\" must be exactly \"{SCHEMA_2020_12}\" \
             (found {schema_uri:?}) — busbar-ui's form renderer only understands JSON Schema \
             2020-12, an older/missing draft can silently misrender"
        ));
    }
    jsonschema::validator_for(&value).map_err(|e| {
        format!("--settings-schema-file '{path}' is not a valid JSON Schema document: {e}")
    })?;
    validate_secret_fields(&value).map_err(|e| format!("--settings-schema-file '{path}': {e}"))?;
    Ok(text)
}

/// Resolve `$ref`/`allOf` into an effective (locally merged) schema object, so field-depth and
/// `x-busbar-secret` checks see the shape the way a form renderer actually would — not the raw
/// document structure. `schemars`-style struct derivation commonly emits a nested field as a
/// `$ref` into `$defs` rather than an inline nested object; a check that only walked raw
/// `properties` without resolving `$ref` first would never see that nesting at all.
/// Local `#/$defs/<Name>` / `#/definitions/<Name>` pointers only — an
/// external or fragment-shaped `$ref` is left unresolved (its siblings are still merged) since
/// there is nothing local to look up.
fn resolve_effective(
    schema: &serde_json::Value,
    defs: &serde_json::Map<String, serde_json::Value>,
    resolving: &mut HashSet<String>,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let Some(obj) = schema.as_object() else {
        return Ok(serde_json::Map::new());
    };
    let mut merged = obj.clone();
    if let Some(r) = obj.get("$ref").and_then(|v| v.as_str()) {
        let name = r
            .strip_prefix("#/$defs/")
            .or_else(|| r.strip_prefix("#/definitions/"));
        if let Some(name) = name {
            if !resolving.insert(name.to_string()) {
                return Err(format!("cyclic $ref in settings_schema: '{r}'"));
            }
            let target = defs
                .get(name)
                .ok_or_else(|| format!("settings_schema has a dangling $ref: '{r}'"))?;
            let base = resolve_effective(target, defs, resolving)?;
            resolving.remove(name);
            merged = base;
            for (k, v) in obj {
                if k != "$ref" {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
    }
    if let Some(all_of) = merged.get("allOf").and_then(|v| v.as_array()).cloned() {
        for sub in &all_of {
            let sub_eff = resolve_effective(sub, defs, resolving)?;
            if let Some(sub_props) = sub_eff.get("properties").and_then(|v| v.as_object()) {
                let props = merged
                    .entry("properties")
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                    .as_object_mut()
                    .expect("properties is always inserted as an object");
                for (k, v) in sub_props {
                    props.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            for (k, v) in &sub_eff {
                if k != "properties" {
                    merged.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
    }
    Ok(merged)
}

/// Pack-time secret-field validator. Two independent hard-error rules, walked together over the WHOLE resolved
/// document (root `$defs` collected once, `$ref`/`allOf` resolved before any depth or marker
/// decision is made):
///   1. `x-busbar-secret: true` is valid ONLY on a field that is a DIRECT member of the schema's
///      root `properties` (depth 1) — `resolve_settings()` only resolves top-level fields, so a
///      nested marked field would silently never resolve, defeating the whole guarantee. A
///      legitimately nested secret-bearing struct field must be flattened to a root property
///      (`tls_key`, not `tls.key`).
///   2. A marked field must be `type: string`, optionally with `contentEncoding: "base64"` for
///      the binary-secret case — no other type may claim to be a secret.
///   3. An UNMARKED field (at any depth) whose name matches [`SECRET_NAME_HINTS`] is a hard
///      error too — the mitigation against a third-party plugin silently shipping a plaintext-
///      credential field with no marker at all.
fn validate_secret_fields(root: &serde_json::Value) -> Result<(), String> {
    let empty = serde_json::Map::new();
    let defs = root
        .get("$defs")
        .and_then(|v| v.as_object())
        .or_else(|| root.get("definitions").and_then(|v| v.as_object()))
        .unwrap_or(&empty);
    fn scan(
        schema: &serde_json::Value,
        defs: &serde_json::Map<String, serde_json::Value>,
        depth: u32,
        resolving: &mut HashSet<String>,
    ) -> Result<(), String> {
        let eff = resolve_effective(schema, defs, resolving)?;
        if eff.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true)) {
            if depth != 1 {
                return Err(format!(
                    "x-busbar-secret: true is only allowed on a direct root-level property \
                     (found at nesting depth {depth}) — flatten the field to a root property \
                     instead"
                ));
            }
            let ty = eff.get("type").and_then(|t| t.as_str());
            let content_encoding = eff.get("contentEncoding").and_then(|t| t.as_str());
            let ok = ty == Some("string") && matches!(content_encoding, None | Some("base64"));
            if !ok {
                return Err(format!(
                    "x-busbar-secret: true is only valid on a `type: string` field (optionally \
                     with `contentEncoding: \"base64\"` for a binary secret) — found type={ty:?} \
                     contentEncoding={content_encoding:?}"
                ));
            }
        }
        if let Some(props) = eff.get("properties").and_then(|p| p.as_object()) {
            for (name, prop_schema) in props {
                let prop_eff = resolve_effective(prop_schema, defs, resolving)?;
                let marked =
                    prop_eff.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true));
                if !marked {
                    let lower = name.to_ascii_lowercase();
                    if SECRET_NAME_HINTS.iter().any(|hint| lower.contains(hint)) {
                        return Err(format!(
                            "field '{name}' looks like a secret (matches one of {SECRET_NAME_HINTS:?}, \
                             case-insensitive) but is not marked `x-busbar-secret: true` — mark it \
                             or rename the field"
                        ));
                    }
                }
                scan(prop_schema, defs, depth + 1, resolving)?;
            }
        }
        if let Some(items) = eff.get("items") {
            scan(items, defs, depth + 1, resolving)?;
        }
        // `oneOf`/`anyOf`/`prefixItems` are also places a field can hide — walked the same way as
        // `properties`/`items` (one nesting level deeper), or both the root-only placement rule
        // and the unmarked-secret-name heuristic can be evaded by putting the violating field
        // inside one of these composition keywords instead of a plain nested object.
        for combinator in ["oneOf", "anyOf"] {
            if let Some(alts) = eff.get(combinator).and_then(|v| v.as_array()) {
                for alt in alts {
                    scan(alt, defs, depth + 1, resolving)?;
                }
            }
        }
        if let Some(prefix_items) = eff.get("prefixItems").and_then(|v| v.as_array()) {
            for item in prefix_items {
                scan(item, defs, depth + 1, resolving)?;
            }
        }
        // Every other JSON Schema 2020-12 keyword whose value is itself a subschema (or holds one)
        // is walked here too, against the full core+applicator+content vocabulary — `oneOf`/
        // `anyOf`/`prefixItems` above cover one part of this class of gap; the rest is closed here
        // in one pass rather than one keyword at a time. `if`/`then`/`else` and
        // `not` each hold a single nested schema, same shape as `items`. `dependentSchemas` and
        // `patternProperties` are maps of key -> schema, same shape as `properties` (but their keys
        // are property names / regexes, not field names to check against `SECRET_NAME_HINTS`
        // themselves — only the nested schemas are scanned). `additionalProperties`/
        // `unevaluatedProperties`/`unevaluatedItems`/`contains`/`contentSchema` each hold a single
        // nested schema OR (except `contentSchema`) a bare bool (`true`/`false`); a bool is not a
        // schema object and is skipped rather than scanned (`resolve_effective` would just return
        // an empty map for it anyway, but skip explicitly so the intent is clear).
        //
        // `propertyNames` is deliberately NOT walked: it constrains the KEYS of an object (e.g.
        // "must match `^[a-z]+$`"), not the shape or value of any field, so it can never itself
        // carry an `x-busbar-secret` marker or a secret-shaped VALUE for a field — there is nothing
        // for this scan to find there.
        if let Some(sub) = eff.get("if") {
            scan(sub, defs, depth + 1, resolving)?;
        }
        if let Some(sub) = eff.get("then") {
            scan(sub, defs, depth + 1, resolving)?;
        }
        if let Some(sub) = eff.get("else") {
            scan(sub, defs, depth + 1, resolving)?;
        }
        if let Some(sub) = eff.get("not") {
            scan(sub, defs, depth + 1, resolving)?;
        }
        if let Some(sub) = eff.get("contentSchema") {
            scan(sub, defs, depth + 1, resolving)?;
        }
        for keyword in [
            "additionalProperties",
            "unevaluatedProperties",
            "unevaluatedItems",
            "contains",
        ] {
            if let Some(sub) = eff.get(keyword) {
                if sub.is_object() {
                    scan(sub, defs, depth + 1, resolving)?;
                }
            }
        }
        for keyword in ["patternProperties", "dependentSchemas"] {
            if let Some(map) = eff.get(keyword).and_then(|v| v.as_object()) {
                for sub in map.values() {
                    scan(sub, defs, depth + 1, resolving)?;
                }
            }
        }
        Ok(())
    }
    scan(root, defs, 0, &mut HashSet::new())
}

fn pack(args: &[String]) -> ExitCode {
    let (flags, allow_unsigned, schema_derived) = match parse_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let required = |k: &str| -> Result<String, String> {
        flags
            .get(k)
            .cloned()
            .ok_or_else(|| format!("missing required --{k}"))
    };
    let run = || -> Result<String, String> {
        let lib_path = required("lib")?;
        let out = required("out")?;
        let kind = required("kind")?;
        // Default the ABI to the NEWEST version this binary's loader supports for the kind, so a
        // plain `pack` of a store plugin stamps the current store ABI instead of a stale literal.
        // `--abi-version` still overrides for cross-version packaging.
        let default_abi = busbar_plugin_loader::supported_abi(&kind)
            .iter()
            .copied()
            .max()
            .unwrap_or(1);
        let manifest = Manifest {
            name: required("name")?,
            alias: required("alias")?,
            kind,
            version: required("version")?,
            publisher: required("publisher")?,
            abi_version: flags
                .get("abi-version")
                .map(|v| v.parse::<u32>().map_err(|e| format!("--abi-version: {e}")))
                .transpose()?
                .unwrap_or(default_abi),
            sha256: String::new(),
            signature: String::new(),
            description: flags.get("description").cloned().unwrap_or_default(),
            homepage: flags.get("homepage").cloned().unwrap_or_default(),
            license: flags.get("license").cloned().unwrap_or_default(),
            // Declared-intent (`needs:`) for a `kind: hook` plugin: authored at pack time via the
            // OPTIONAL `--needs-prompt`/`--needs-user` flags. Absent → "asks for nothing" (the correct
            // default for every non-hook kind and for a hook that needs no caller content). The value
            // is SIGNED (covered by the manifest signature) so it cannot be spoofed after packing.
            needs: HookNeeds {
                prompt: flags
                    .get("needs-prompt")
                    .map(|v| parse_need_level(v).map_err(|e| format!("--needs-prompt: {e}")))
                    .transpose()?
                    .unwrap_or_default(),
                user: flags
                    .get("needs-user")
                    .map(|v| parse_need_level(v).map_err(|e| format!("--needs-user: {e}")))
                    .transpose()?
                    .unwrap_or_default(),
            },
            // OPTIONAL: the plugin's `settings` shape as a JSON Schema 2020-12 document, read
            // verbatim from a file (the plugin author generates this from their own config
            // struct — e.g. a `schemars::schema_for!` derive — so schema/parser drift becomes a
            // compile error in the plugin's own crate, not a runtime mismatch discovered by an
            // operator; this tool only embeds and validates, it does not generate). Rejected at
            // PACK time if the file isn't syntactically valid JSON Schema, never left to fail at
            // UI-render time on some operator's machine. SIGNED (covered by the manifest
            // signature) alongside everything else.
            settings_schema: flags
                .get("settings-schema-file")
                .map(|path| read_and_validate_settings_schema(path))
                .transpose()?,
            // SELF-ATTESTED by the caller (the plugin's own build/CI, via the `busbar-plugin-sdk`
            // `schema_for!` macro) — this tool has no way to verify derivation itself, it only
            // embeds a schema file it's handed and never sees the plugin's Rust source.
            // `false` unless `--schema-derived` is passed.
            schema_derived,
            host: None,
        };
        let lib_bytes =
            std::fs::read(&lib_path).map_err(|e| format!("cannot read --lib '{lib_path}': {e}"))?;

        // Sign with $BUSBAR_SIGN_KEY, or package unsigned only under the explicit dev flag.
        let manifest = match std::env::var(SIGN_KEY_ENV) {
            Ok(hex_seed) => {
                let seed = hex::decode(hex_seed.trim())
                    .map_err(|e| format!("{SIGN_KEY_ENV} is not valid hex: {e}"))?;
                let seed: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| format!("{SIGN_KEY_ENV} must be 32 bytes (64 hex chars)"))?;
                sign(&SigningKey::from_bytes(&seed), manifest, &lib_bytes)
            }
            Err(_) if allow_unsigned => {
                let mut m = manifest;
                m.sha256 = busbar_plugin_sign::sha256_hex(&lib_bytes);
                m
            }
            Err(_) => {
                return Err(format!(
                    "{SIGN_KEY_ENV} is not set. Set it to the 64-hex ed25519 seed to sign, or pass \
                     --allow-unsigned to package an UNSIGNED tarball (dev only; busbar loads it \
                     only under plugins.trust.allow_unsigned: true)."
                ));
            }
        };

        // Structural self-check: refuse to package a manifest busbar would refuse to load.
        busbar_plugin_sign::validate_structure(
            &manifest,
            &lib_bytes,
            &busbar_plugin_loader::supported_abi,
            busbar_plugin_sign::HOST_IDENTITY,
        )
        .map_err(|e| format!("manifest would fail busbar's structural validation: {e}"))?;

        let lib_file = std::path::Path::new(&lib_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("plugin-lib")
            .to_string();
        let tarball = busbar_plugin_loader::tarball::package(&manifest, &lib_file, &lib_bytes)?;
        std::fs::write(&out, &tarball).map_err(|e| format!("cannot write '{out}': {e}"))?;
        Ok(format!(
            "packaged {} ({} v{}, kind {}, publisher {}, {}) -> {out}",
            manifest.name,
            manifest.alias,
            manifest.version,
            manifest.kind,
            manifest.publisher,
            if manifest.signature.is_empty() {
                "UNSIGNED"
            } else {
                "signed"
            },
        ))
    };
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "tests/main_tests.rs"]
mod tests;
