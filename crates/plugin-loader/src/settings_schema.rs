// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeSet, HashMap, HashSet};

/// Read the public schema from the canonical Statement, without opening a plugin.
/// Absence is allowed; a present but malformed schema is an admission error.
pub fn statement_schema(
    schema: &busbar_contract::abi::mechanism::rendering::ReadBlob,
) -> Result<Option<String>, String> {
    if schema.bytes.is_empty() {
        return Ok(None);
    }
    if schema.fmt != busbar_contract::abi::mechanism::call::BLOB_JSON || schema.flags != 0 {
        return Err("Statement settings_schema must be public JSON".into());
    }
    if schema.bytes.len() > 256 * 1024 {
        return Err("Statement settings_schema exceeds the 262144-byte cap".into());
    }
    let text = std::str::from_utf8(&schema.bytes)
        .map_err(|_| "Statement settings_schema is not UTF-8".to_string())?;
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("Statement settings_schema is not valid JSON: {e}"))?;
    if !value.is_object() && !value.is_boolean() {
        return Err("Statement settings_schema must be a JSON Schema object or boolean".into());
    }
    Ok(Some(text.to_string()))
}

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
    validate_public_fields(&value).map_err(|e| format!("its settings schema: {e}"))?;
    Ok(busbar_contract::settings_public::public_settings(&value))
}

/// Project a Statement schema without exposing any root containing a declared secret path.
pub fn public_settings_of_statement(
    bytes: &[u8],
    secret_refs: &[String],
) -> Result<BTreeSet<String>, String> {
    let public = public_settings_of_schema(bytes)?;
    for name in &public {
        if secret_refs.iter().any(|path| {
            path.split('.')
                .next()
                .is_some_and(|root| root == name || root == "*")
        }) {
            return Err(format!(
                "its settings schema: field '{name}' contains a declared secret path and cannot be public"
            ));
        }
    }
    Ok(public)
}

struct Resolution<'a> {
    defs: &'a serde_json::Map<String, serde_json::Value>,
    definitions: &'a serde_json::Map<String, serde_json::Value>,
    resolving: HashSet<String>,

    memo: HashMap<(serde_json::Value, u32), serde_json::Map<String, serde_json::Value>>,
    scanned: HashSet<(serde_json::Value, Position, u32)>,
}

impl<'a> Resolution<'a> {
    /// The `$ref` target in the table its own prefix names (`#/$defs/` or `#/definitions/`).
    /// `Some(None)` is a local reference whose name is missing; `None` is not a local table reference.
    fn target(&self, reference: &str) -> Option<Option<&'a serde_json::Value>> {
        if let Some(name) = reference.strip_prefix("#/$defs/") {
            return Some(self.defs.get(name));
        }
        reference
            .strip_prefix("#/definitions/")
            .map(|name| self.definitions.get(name))
    }

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
            if let Some(target) = self.target(r) {
                if !self.resolving.insert(r.to_string()) {
                    return Err(format!("cyclic $ref in settings_schema: '{r}'"));
                }
                let target =
                    target.ok_or_else(|| format!("settings_schema has a dangling $ref: '{r}'"))?;
                let base = self.effective(target, depth + 1)?;
                self.resolving.remove(r);
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
///   2. A marked field is `type: string` (optionally `contentEncoding: "base64"`), or an
///      untyped `writeOnly: true` lifecycle slot. The latter preserves parsers accepting opaque
///      JSON, including the host's `{"$secret": index}` placeholder after secret resolution.
///      This schema does not replace config-time `SecretRef` validation.
///   3. An UNMARKED field (at any depth) whose name matches [`SECRET_NAME_HINTS`] is a hard
///      error too — the mitigation against a third-party plugin silently shipping a plaintext-
///      credential field with no marker at all.
pub fn validate_secret_fields(root: &serde_json::Value) -> Result<(), String> {
    let empty = serde_json::Map::new();
    let defs = root
        .get("$defs")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let definitions = root
        .get("definitions")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty);
    let public = busbar_contract::settings_public::public_settings(root);
    let mut resolution = Resolution {
        defs,
        definitions,
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
        // The merged view lets a `$ref` sibling replace the target's `properties` and keeps one
        // value per allOf keyword, so the target and every allOf branch are also walked on their own.
        if let Some(target) = schema
            .as_object()
            .filter(|obj| obj.len() > 1)
            .and_then(|obj| obj.get("$ref"))
            .and_then(|r| r.as_str())
            .and_then(|r| resolution.target(r))
            .flatten()
        {
            scan(target, resolution, public, at, depth + 1)?;
        }
        if let Some(branches) = eff.get("allOf").and_then(|v| v.as_array()) {
            for branch in branches {
                scan(branch, resolution, public, at, depth + 1)?;
            }
        }
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
            let string = ty == Some("string") && matches!(content_encoding, None | Some("base64"));
            let opaque = !eff.contains_key("type")
                && !eff.contains_key("contentEncoding")
                && eff.get("writeOnly") == Some(&serde_json::Value::Bool(true));
            let ok = string || opaque;
            if !ok {
                return Err(format!(
                    "x-busbar-secret: true is only valid on a `type: string` field (optionally \
                     with `contentEncoding: \"base64\"` for a binary secret), or an untyped \
                     `writeOnly: true` lifecycle slot — found type={ty:?} \
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
            // Draft-07 tuple form: `items` is an array of schemas, like `prefixItems`.
            for item in items.as_array().map_or(std::slice::from_ref(items), |a| a) {
                scan(item, resolution, public, Position::Nested, depth + 1)?;
            }
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
    scan(root, &mut resolution, &public, Position::Root, 0)?;
    validate_public_fields(root)
}

// Privacy follows every reachable original branch: schema keyword precedence must never hide a
// secret in another branch. Secret resolution belongs to Statement.secret_refs, not these markers.
fn validate_public_fields(root: &serde_json::Value) -> Result<(), String> {
    struct Walk<'a> {
        root: &'a serde_json::Value,
        public: BTreeSet<String>,
        active: HashSet<usize>,
        seen: HashSet<(usize, Position, bool, bool, u32)>,
    }
    impl Walk<'_> {
        fn scan(
            &mut self,
            node: &serde_json::Value,
            at: Position,
            exposed: bool,
            allow_public: bool,
            depth: u32,
        ) -> Result<(), String> {
            if depth > 64 {
                return Err("settings_schema nests deeper than 64 levels".into());
            }
            let identity = std::ptr::from_ref(node) as usize;
            let key = (identity, at, exposed, allow_public, depth);
            if self.seen.contains(&key) {
                return Ok(());
            }
            if !self.active.insert(identity) {
                return Err("cyclic $ref in settings_schema".into());
            }
            let Some(obj) = node.as_object() else {
                self.active.remove(&identity);
                return if node.is_boolean() {
                    Ok(())
                } else {
                    Err("settings_schema must contain schema objects or booleans".into())
                };
            };
            // Only document-local JSON Pointer references are supported. Reject other
            // reference mechanisms and nested resource scopes rather than inspect the wrong target.
            for keyword in ["$dynamicRef", "$recursiveRef"] {
                if obj.contains_key(keyword) {
                    return Err(format!("settings_schema has an unsupported {keyword}"));
                }
            }
            if !std::ptr::eq(node, self.root) && (obj.contains_key("$id") || obj.contains_key("id"))
            {
                return Err("settings_schema has an unsupported nested resource id".into());
            }
            if let Some(mark) = obj.get(busbar_contract::settings_public::PUBLIC_MARK) {
                if mark != &serde_json::Value::Bool(true) || !allow_public {
                    return Err("x-busbar-public: true is only allowed on an explicitly marked direct root-level property".into());
                }
            }
            if exposed
                && (obj.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true))
                    || obj.get("writeOnly") == Some(&serde_json::Value::Bool(true)))
            {
                return Err("a secret or write-only field is always sensitive, including inside a public ancestor".into());
            }
            if let Some(reference) = obj.get("$ref") {
                let reference = reference
                    .as_str()
                    .ok_or("settings_schema $ref must be a string")?;
                let pointer = reference
                    .strip_prefix('#')
                    .ok_or("settings_schema has an unsupported external $ref")?;
                if pointer.contains('%') {
                    return Err(
                        "settings_schema has an unsupported encoded reference fragment".into(),
                    );
                }
                // A pointer may jump below an unvisited resource declaration. Check every
                // crossed ancestor, not only the final schema, before interpreting its references
                // against this document root. Schema-map entries named `id` are not resource ids.
                let mut target = self.root;
                if !pointer.is_empty() {
                    let path = pointer
                        .strip_prefix('/')
                        .ok_or("settings_schema has an unsupported reference fragment")?;
                    for (index, segment) in path.split('/').enumerate() {
                        if index >= 64 {
                            return Err(
                                "settings_schema reference pointer is deeper than 64 levels".into(),
                            );
                        }
                        target = target
                            .pointer(&format!("/{segment}"))
                            .ok_or("settings_schema has a dangling $ref")?;
                        if ["$id", "id"].iter().any(|keyword| {
                            target
                                .get(*keyword)
                                .is_some_and(serde_json::Value::is_string)
                        }) {
                            return Err("settings_schema reference crosses an unsupported nested resource id".into());
                        }
                    }
                }
                self.scan(target, at, exposed, allow_public, depth + 1)?;
            }
            if let Some(properties) = obj.get("properties") {
                for (name, property) in properties
                    .as_object()
                    .ok_or("settings_schema properties must be an object")?
                {
                    let declared = at == Position::Root && self.public.contains(name);
                    let child_exposed = exposed || declared;
                    if let Some(property) = property.as_object() {
                        check_public(
                            name,
                            property,
                            declared,
                            property.get("x-busbar-secret") == Some(&serde_json::Value::Bool(true)),
                        )?;
                    }
                    if child_exposed
                        && SECRET_NAME_HINTS
                            .iter()
                            .any(|hint| name.to_ascii_lowercase().contains(hint))
                    {
                        return Err(format!(
                            "field '{name}' looks like a credential and is always sensitive"
                        ));
                    }
                    let child = if at == Position::Root {
                        Position::RootProperty
                    } else {
                        Position::Nested
                    };
                    self.scan(property, child, child_exposed, declared, depth + 1)?;
                }
            }
            for keyword in ["allOf", "anyOf", "oneOf"] {
                if let Some(branches) = obj.get(keyword) {
                    for branch in branches
                        .as_array()
                        .ok_or("settings_schema combinator must be an array")?
                    {
                        self.scan(branch, at, exposed, allow_public, depth + 1)?;
                    }
                }
            }
            for keyword in ["if", "then", "else", "not"] {
                if let Some(branch) = obj.get(keyword) {
                    self.scan(branch, at, exposed, allow_public, depth + 1)?;
                }
            }
            for keyword in [
                "items",
                "contains",
                "additionalProperties",
                "unevaluatedProperties",
                "unevaluatedItems",
                "contentSchema",
                "propertyNames",
            ] {
                if let Some(child) = obj.get(keyword) {
                    let child_exposed = exposed
                        || (at == Position::Root
                            && !self.public.is_empty()
                            && matches!(keyword, "additionalProperties" | "unevaluatedProperties"));
                    // Draft-07 tuple form: `items` is an array of schemas.
                    let children = match child.as_array() {
                        Some(tuple) if keyword == "items" => tuple.as_slice(),
                        _ => std::slice::from_ref(child),
                    };
                    for child in children {
                        self.scan(child, Position::Nested, child_exposed, false, depth + 1)?;
                    }
                }
            }
            if let Some(items) = obj.get("prefixItems") {
                for child in items
                    .as_array()
                    .ok_or("settings_schema prefixItems must be an array")?
                {
                    self.scan(child, Position::Nested, exposed, false, depth + 1)?;
                }
            }
            for keyword in ["patternProperties", "dependentSchemas"] {
                if let Some(children) = obj.get(keyword) {
                    for child in children
                        .as_object()
                        .ok_or("settings_schema schema map must be an object")?
                        .values()
                    {
                        if keyword == "dependentSchemas" {
                            self.scan(child, at, exposed, allow_public, depth + 1)?;
                        } else {
                            let child_exposed =
                                exposed || (at == Position::Root && !self.public.is_empty());
                            self.scan(child, Position::Nested, child_exposed, false, depth + 1)?;
                        }
                    }
                }
            }
            // Draft-07 dependencies can carry schemas at the current instance position.
            // Property-name arrays impose requirements only and contain no schema annotations.
            if let Some(dependencies) = obj.get("dependencies") {
                for dependency in dependencies
                    .as_object()
                    .ok_or("settings_schema dependencies must be an object")?
                    .values()
                {
                    if let Some(names) = dependency.as_array() {
                        if !names.iter().all(serde_json::Value::is_string) {
                            return Err(
                                "settings_schema property dependencies must be string arrays"
                                    .into(),
                            );
                        }
                    } else {
                        self.scan(dependency, at, exposed, allow_public, depth + 1)?;
                    }
                }
            }
            self.active.remove(&identity);
            self.seen.insert(key);
            Ok(())
        }
    }
    Walk {
        root,
        public: busbar_contract::settings_public::public_settings(root),
        active: HashSet::new(),
        seen: HashSet::new(),
    }
    .scan(root, Position::Root, false, false, 0)
}
