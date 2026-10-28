// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTINGS-SCHEMA RULES, one set for `busbar-plugin-pack` (a schema file it packs) and for the
//! host (a Statement's `settings_schema`, read at load): where `x-busbar-secret` and
//! `x-busbar-public` may stand, no unmarked credential-looking field, no credential declared
//! public. [`public_settings_of_schema`] is what the host reads: the settings a schema declares
//! public, every other setting sensitive (`busbar_contract::settings_public`).

use std::collections::HashSet;

/// Field-name heuristic: an UNMARKED field whose name matches one of these
/// (case-insensitive substring) is hard-rejected at pack time — the only mitigation against a
/// third-party author silently shipping a plaintext-credential text box that doesn't depend on
/// remembering to mark it. Deliberately not exhaustive; it converts a silent security failure
/// into a loud packaging error for the overwhelmingly common case.
pub const SECRET_NAME_HINTS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "passphrase",
    "private_key",
    "apikey",
    "api_key",
];

/// THE PUBLIC SETTINGS a Statement's `settings_schema` (`bytes`) declares, after the schema rules
/// `plugin pack` holds a schema file to (`x-busbar-secret` and `x-busbar-public` placement, no
/// unmarked credential-looking field, no credential declared public). Empty bytes: no schema, every
/// setting sensitive.
///
/// # Errors
/// Bytes that are not JSON, or a schema the rules refuse.
pub fn public_settings_of_schema(
    bytes: &[u8],
) -> Result<std::collections::BTreeSet<String>, String> {
    if bytes.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("its settings schema is not valid JSON: {e}"))?;
    validate_secret_fields(&value).map_err(|e| format!("its settings schema: {e}"))?;
    Ok(busbar_contract::settings_public::public_settings(&value))
}

/// Resolve `$ref`/`allOf` into an effective (locally merged) schema object, so field-depth and
/// `x-busbar-secret` checks see the shape the way a form renderer actually would — not the raw
/// document structure. `schemars`-style struct derivation commonly emits a nested field as a
/// `$ref` into `$defs` rather than an inline nested object; a check that only walked raw
/// `properties` without resolving `$ref` first would never see that nesting at all.
/// Local `#/$defs/<Name>` / `#/definitions/<Name>` pointers only — an
/// external or fragment-shaped `$ref` is left unresolved (its siblings are still merged) since
/// there is nothing local to look up.
///
/// CARRIES ITS OWN DEPTH CAP, and needs one. `scan`'s `MAX_SCAN_DEPTH` counts the levels SCAN
/// descends, and this function recurses into ITSELF — once through `$ref`, once per `allOf` member
/// — without ever passing back through `scan`, so a chain living entirely inside a resolve advances
/// that counter not at all. The `resolving` set is not the backstop either: it catches a `$ref` that
/// closes a CYCLE and says nothing about a chain that is merely very long, so a non-cyclic
/// 200-link `allOf` chain walks straight past it. This runs on operator-supplied input at pack time,
/// and uncapped the end of that chain is a stack overflow or an unbounded re-resolve that never
/// returns — an abort or a hang with no diagnostic, the one answer a validator must never give.
fn resolve_effective(
    schema: &serde_json::Value,
    defs: &serde_json::Map<String, serde_json::Value>,
    resolving: &mut HashSet<String>,
    depth: u32,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    // Same ceiling as `MAX_SCAN_DEPTH`, and the same one `busbar_contract::json_grammar` holds for
    // wire JSON: deeper than this is not a schema anyone wrote by hand, it is the recursion.
    const MAX_RESOLVE_DEPTH: u32 = 64;
    if depth > MAX_RESOLVE_DEPTH {
        return Err(format!(
            "settings_schema nests deeper than {MAX_RESOLVE_DEPTH} levels while resolving \
             $ref/allOf — a self-referencing $defs entry is the usual cause; the schema cannot be \
             validated"
        ));
    }
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
            let base = resolve_effective(target, defs, resolving, depth + 1)?;
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
            let sub_eff = resolve_effective(sub, defs, resolving, depth + 1)?;
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

/// Where the schema the walk is currently looking at SITS, which is what the secret-marker rule is
/// actually about — `resolve_settings()` resolves the root object's own properties and nothing else.
/// A depth counter answered a different question and got it wrong in both directions: a schema under
/// `patternProperties` (or `items`, or a `$defs` entry reached from anywhere) sits one level down and
/// is NOT a root property, while a root `oneOf` alternative's top-level property sits two levels down
/// and IS.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// The root schema itself, or a composition alternative still describing the root.
    Root,
    /// A direct member of the root object's `properties` — the only place a secret marker belongs.
    RootProperty,
    /// Anywhere else.
    Nested,
}

/// THE PUBLIC DECLARATION (`busbar_contract::settings_public`): every setting is sensitive unless a
/// direct root property is marked `x-busbar-public: true`. Refused: a marker that is not `true`, one
/// below the root (the host reads root properties alone, so a nested one would never take effect),
/// one on a field also marked `x-busbar-secret`, and one on a field whose name looks like a
/// credential ([`SECRET_NAME_HINTS`]) — a credential is never declared public.
fn check_public(
    name: &str,
    prop: &serde_json::Map<String, serde_json::Value>,
    root: bool,
    secret: bool,
) -> Result<(), String> {
    use busbar_contract::settings_public::PUBLIC_MARK;
    let Some(mark) = prop.get(PUBLIC_MARK) else {
        return Ok(());
    };
    if mark != &serde_json::Value::Bool(true) {
        return Err(format!(
            "field '{name}': {PUBLIC_MARK} is `true` or absent (absent: the setting is sensitive)"
        ));
    }
    if !root {
        return Err(format!(
            "field '{name}': {PUBLIC_MARK}: true is only allowed on a direct root-level property"
        ));
    }
    let lower = name.to_ascii_lowercase();
    if secret || SECRET_NAME_HINTS.iter().any(|hint| lower.contains(hint)) {
        return Err(format!(
            "field '{name}' looks like a credential and cannot be declared {PUBLIC_MARK}: a \
             credential is always sensitive"
        ));
    }
    Ok(())
}

/// Pack-time secret-field validator. Two independent hard-error rules, walked together over the WHOLE resolved
/// document (root `$defs` collected once, `$ref`/`allOf` resolved before any depth or marker
/// decision is made):
///   1. `x-busbar-secret: true` is valid ONLY on a field that is a DIRECT member of the schema's
///      root `properties` (see [`Position`]) — `resolve_settings()` only resolves top-level fields, so a
///      nested marked field would silently never resolve, defeating the whole guarantee. A
///      legitimately nested secret-bearing struct field must be flattened to a root property
///      (`tls_key`, not `tls.key`).
///   2. A marked field must be `type: string`, optionally with `contentEncoding: "base64"` for
///      the binary-secret case — no other type may claim to be a secret.
///   3. An UNMARKED field (at any depth) whose name matches [`SECRET_NAME_HINTS`] is a hard
///      error too — the mitigation against a third-party plugin silently shipping a plaintext-
///      credential field with no marker at all.
pub fn validate_secret_fields(root: &serde_json::Value) -> Result<(), String> {
    let empty = serde_json::Map::new();
    let defs = root
        .get("$defs")
        .and_then(|v| v.as_object())
        .or_else(|| root.get("definitions").and_then(|v| v.as_object()))
        .unwrap_or(&empty);
    fn scan(
        schema: &serde_json::Value,
        defs: &serde_json::Map<String, serde_json::Value>,
        at: Position,
        depth: u32,
        resolving: &mut HashSet<String>,
    ) -> Result<(), String> {
        // A schema may nest as deeply as it likes, but a `$defs` entry that refers to ITSELF is not
        // caught by the `resolving` cycle guard: that guard is unwound as each resolution returns,
        // so a `Node -> properties.child -> $ref Node` schema resolves cleanly at every single step
        // and simply never stops. This walk runs on operator-supplied input at pack time, and the
        // failure mode without a cap is a stack overflow — an abort with no diagnostic, which is the
        // one outcome a validator must never have. Deeper than this is not a schema anyone wrote by
        // hand; it is the recursion.
        const MAX_SCAN_DEPTH: u32 = 64;
        if depth > MAX_SCAN_DEPTH {
            return Err(format!(
                "settings_schema nests deeper than {MAX_SCAN_DEPTH} levels — a self-referencing \
                 $defs entry is the usual cause; the schema cannot be validated"
            ));
        }
        let eff = resolve_effective(schema, defs, resolving, depth)?;
        if eff.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true)) {
            if at != Position::RootProperty {
                // 1.5.5's words, naming the nesting depth (v1.5.5
                // `crates/plugin-pack/src/main.rs:298-304`).
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
                let prop_eff = resolve_effective(prop_schema, defs, resolving, depth)?;
                let marked =
                    prop_eff.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true));
                check_public(name, &prop_eff, at == Position::Root, marked)?;
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
                // A property is a ROOT property when the object declaring it is the root schema —
                // which is what `at` tracks, not a depth counter. `patternProperties` and the rest
                // sit one `properties` map deeper than the root even when they are written at the
                // top of the document, and a `oneOf` alternative at the root declares root
                // properties even though it is a level down structurally.
                let child = match at {
                    Position::Root => Position::RootProperty,
                    _ => Position::Nested,
                };
                scan(prop_schema, defs, child, depth + 1, resolving)?;
            }
        }
        if let Some(items) = eff.get("items") {
            scan(items, defs, Position::Nested, depth + 1, resolving)?;
        }
        // `oneOf`/`anyOf`/`prefixItems` are also places a field can hide — walked the same way as
        // `properties`/`items` (one nesting level deeper), or both the root-only placement rule
        // and the unmarked-secret-name heuristic can be evaded by putting the violating field
        // inside one of these composition keywords instead of a plain nested object.
        //
        // A composition keyword does NOT move a field out of the position its parent occupies: a
        // root `oneOf` whose alternatives each declare the same top-level object is still spelling
        // out the ROOT's shape, and its properties are root properties `resolve_settings()` will
        // resolve. So the position is carried through rather than reset.
        for combinator in ["oneOf", "anyOf"] {
            if let Some(alts) = eff.get(combinator).and_then(|v| v.as_array()) {
                for alt in alts {
                    scan(alt, defs, at, depth + 1, resolving)?;
                }
            }
        }
        if let Some(prefix_items) = eff.get("prefixItems").and_then(|v| v.as_array()) {
            for item in prefix_items {
                scan(item, defs, Position::Nested, depth + 1, resolving)?;
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
        // `if`/`then`/`else` constrain the SAME object their parent does (a conditional root branch
        // still describes the root), so they carry the position like `oneOf`/`anyOf`. `not` and
        // `contentSchema` describe something else entirely and are nested.
        for keyword in ["if", "then", "else"] {
            if let Some(sub) = eff.get(keyword) {
                scan(sub, defs, at, depth + 1, resolving)?;
            }
        }
        if let Some(sub) = eff.get("not") {
            scan(sub, defs, Position::Nested, depth + 1, resolving)?;
        }
        if let Some(sub) = eff.get("contentSchema") {
            scan(sub, defs, Position::Nested, depth + 1, resolving)?;
        }
        for keyword in [
            "additionalProperties",
            "unevaluatedProperties",
            "unevaluatedItems",
            "contains",
        ] {
            if let Some(sub) = eff.get(keyword) {
                if sub.is_object() {
                    scan(sub, defs, Position::Nested, depth + 1, resolving)?;
                }
            }
        }
        for keyword in ["patternProperties", "dependentSchemas"] {
            if let Some(map) = eff.get(keyword).and_then(|v| v.as_object()) {
                for sub in map.values() {
                    scan(sub, defs, Position::Nested, depth + 1, resolving)?;
                }
            }
        }
        Ok(())
    }
    scan(root, defs, Position::Root, 0, &mut HashSet::new())
}
