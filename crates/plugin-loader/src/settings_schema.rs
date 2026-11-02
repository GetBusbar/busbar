// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeSet, HashMap, HashSet};

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

struct Resolution<'a> {
    defs: &'a serde_json::Map<String, serde_json::Value>,
    resolving: HashSet<String>,

    memo: HashMap<(serde_json::Value, u32), serde_json::Map<String, serde_json::Value>>,
    scanned: HashSet<(serde_json::Value, Position, u32)>,
}

impl Resolution<'_> {
    fn effective(
        &mut self,
        schema: &serde_json::Value,
        depth: u32,
    ) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        const MAX_RESOLVE_DEPTH: u32 = 64;
        if depth > MAX_RESOLVE_DEPTH {
            return Err(format!(
                "settings_schema nests deeper than {MAX_RESOLVE_DEPTH} levels while resolving \
             $ref/allOf — a self-referencing $defs entry is the usual cause; the schema cannot be \
             validated"
            ));
        }
        let key = (schema.clone(), depth);
        if let Some(effective) = self.memo.get(&key) {
            return Ok(effective.clone());
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
                if !self.resolving.insert(name.to_string()) {
                    return Err(format!("cyclic $ref in settings_schema: '{r}'"));
                }
                let defs = self.defs;
                let target = defs
                    .get(name)
                    .ok_or_else(|| format!("settings_schema has a dangling $ref: '{r}'"))?;
                let base = self.effective(target, depth + 1)?;
                self.resolving.remove(name);
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
                let sub_eff = self.effective(sub, depth + 1)?;
                if let Some(sub_props) = sub_eff.get("properties").and_then(|v| v.as_object()) {
                    let props = merged
                        .entry("properties")
                        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
                        .as_object_mut()
                        .ok_or("settings_schema properties must be an object")?;
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

        self.memo.insert(key, merged.clone());
        Ok(merged)
    }
}

/// Where the schema the walk is currently looking at SITS, which is what the secret-marker rule is
/// actually about — `resolve_settings()` resolves the root object's own properties and nothing else.
/// A depth counter answered a different question and got it wrong in both directions: a schema under
/// `patternProperties` (or `items`, or a `$defs` entry reached from anywhere) sits one level down and
/// is NOT a root property, while a root `oneOf` alternative's top-level property sits two levels down
/// and IS.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Position {
    /// The root schema itself, or a composition alternative still describing the root.
    Root,
    /// A direct member of the root object's `properties` — the only place a secret marker belongs.
    RootProperty,
    /// Anywhere else.
    Nested,
}

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
    let public = busbar_contract::settings_public::public_settings(root);
    let mut resolution = Resolution {
        defs,
        resolving: HashSet::new(),
        memo: HashMap::new(),
        scanned: HashSet::new(),
    };
    fn scan(
        schema: &serde_json::Value,
        resolution: &mut Resolution<'_>,
        public: &BTreeSet<String>,
        at: Position,
        depth: u32,
    ) -> Result<(), String> {
        const MAX_SCAN_DEPTH: u32 = 64;
        if depth > MAX_SCAN_DEPTH {
            return Err(format!(
                "settings_schema nests deeper than {MAX_SCAN_DEPTH} levels — a self-referencing \
                 $defs entry is the usual cause; the schema cannot be validated"
            ));
        }

        let key = (schema.clone(), at, depth);
        if resolution.scanned.contains(&key) {
            return Ok(());
        }
        let eff = resolution.effective(schema, depth)?;
        if eff.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true)) {
            if at != Position::RootProperty {
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
                let prop_eff = resolution.effective(prop_schema, depth)?;
                let marked =
                    prop_eff.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true));
                check_public(
                    name,
                    &prop_eff,
                    at == Position::Root && public.contains(name),
                    marked,
                )?;
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

                let child = match at {
                    Position::Root => Position::RootProperty,
                    _ => Position::Nested,
                };
                scan(prop_schema, resolution, public, child, depth + 1)?;
            }
        }
        if let Some(items) = eff.get("items") {
            scan(items, resolution, public, Position::Nested, depth + 1)?;
        }

        for combinator in ["oneOf", "anyOf"] {
            if let Some(alts) = eff.get(combinator).and_then(|v| v.as_array()) {
                for alt in alts {
                    scan(alt, resolution, public, at, depth + 1)?;
                }
            }
        }
        if let Some(prefix_items) = eff.get("prefixItems").and_then(|v| v.as_array()) {
            for item in prefix_items {
                scan(item, resolution, public, Position::Nested, depth + 1)?;
            }
        }

        for keyword in ["if", "then", "else"] {
            if let Some(sub) = eff.get(keyword) {
                scan(sub, resolution, public, at, depth + 1)?;
            }
        }
        if let Some(sub) = eff.get("not") {
            scan(sub, resolution, public, Position::Nested, depth + 1)?;
        }
        if let Some(sub) = eff.get("contentSchema") {
            scan(sub, resolution, public, Position::Nested, depth + 1)?;
        }
        for keyword in [
            "additionalProperties",
            "unevaluatedProperties",
            "unevaluatedItems",
            "contains",
        ] {
            if let Some(sub) = eff.get(keyword) {
                if sub.is_object() {
                    scan(sub, resolution, public, Position::Nested, depth + 1)?;
                }
            }
        }
        for keyword in ["patternProperties", "dependentSchemas"] {
            if let Some(map) = eff.get(keyword).and_then(|v| v.as_object()) {
                for sub in map.values() {
                    scan(sub, resolution, public, Position::Nested, depth + 1)?;
                }
            }
        }
        resolution.scanned.insert(key);
        Ok(())
    }
    scan(root, &mut resolution, &public, Position::Root, 0)
}
