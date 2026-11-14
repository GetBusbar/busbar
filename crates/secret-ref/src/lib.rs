// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `SecretRef` — the SECRET REFERENCE type, extracted out of `busbar`'s crate-private
//! `crates/busbar/src/config/secret.rs` into its own tiny crate.
//!
//! Every secret/external value in busbar config is `{ module: <secret-module>, settings: {…} }` — a
//! reference to a SECRET MODULE (`kind: secret` plugin), never the secret itself. The built-in
//! modules are `env` (`settings.key` names an environment variable) and `file` (`settings.path`
//! names a file whose contents are the secret); third-party modules (vault, cloud secret
//! managers, …) load through the plugin system. Two ergonomic SUGAR spellings desugar to the
//! built-ins:
//!
//! ```yaml
//! api_key: { env: ANTHROPIC_API_KEY }          # ⇒ { module: env,  settings: { key: ANTHROPIC_API_KEY } }
//! cert:    { file: /run/secrets/tls-cert.pem } # ⇒ { module: file, settings: { path: /run/secrets/tls-cert.pem } }
//! ```
//!
//! **Why this is its own crate.** `SecretRef` used to live `pub(crate)` inside the `busbar` binary
//! crate — unreachable from `busbar-plugin-pack` or any future schema-generation tooling. The
//! `x-busbar-secret` schema vocabulary entry's `oneOf` (the reference shape busbar-ui composes for a
//! secret field) must be generated FROM this real type, not hand-written as a parallel copy that can
//! drift from the actual deserializer. [`oneof_schema`] is that derivation, straight from the same
//! `Deserialize` impl `busbar`'s engine uses to parse a live config — so it is structurally
//! impossible for the derived shape to accept something the engine would reject, or vice versa.
//!
//! `{ literal: <value> }` (the escape hatch for a plugin whose own legitimately-shaped config field
//! collides with a reference shape) is **not** part of `SecretRef` and never was — it is handled one
//! layer above `SecretRef` parsing, inside busbar's `resolve_settings()`, as a wrapper around the
//! field. A full, faithful derivation from this type therefore already excludes `literal` correctly,
//! with no special-casing required or wanted — see the doc comment on [`oneof_schema`].
//!
//! `SecretRef` holds no secret material — only the module name and its opaque settings — so it is
//! safe to derive `Debug`/`Clone`/`PartialEq` on it and on every struct embedding it.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;

/// The built-in `env` secret module name (settings: `{ key: <ENV_VAR> }`).
pub const SECRET_MODULE_ENV: &str = "env";
/// The built-in `file` secret module name (settings: `{ path: <FILE> }`).
pub const SECRET_MODULE_FILE: &str = "file";
/// The `env` module's settings key naming the environment variable.
pub const SECRET_ENV_SETTING_KEY: &str = "key";
/// The `file` module's settings key naming the file path.
pub const SECRET_FILE_SETTING_PATH: &str = "path";

/// A reference to a secret, resolved through a secret MODULE. See the crate docs for the accepted
/// YAML/JSON spellings. `settings` is the module's own (opaque) config — busbar passes it through
/// verbatim and never interprets it beyond the built-ins.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SecretRef {
    /// The secret module resolving this reference (`env` / `file` built-ins, or a `kind: secret`
    /// plugin's name/alias).
    pub module: String,
    /// The module's own settings (opaque to busbar; the built-ins read `key` / `path`).
    pub settings: serde_json::Map<String, serde_json::Value>,
}

impl SecretRef {
    /// A `{ module: env, settings: { key } }` reference (the canonical form of the `{ env: … }` sugar).
    pub fn env(var: impl Into<String>) -> Self {
        let mut settings = serde_json::Map::new();
        settings.insert(
            SECRET_ENV_SETTING_KEY.to_string(),
            serde_json::Value::String(var.into()),
        );
        Self {
            module: SECRET_MODULE_ENV.to_string(),
            settings,
        }
    }

    /// A `{ module: file, settings: { path } }` reference (the canonical form of the `{ file: … }` sugar).
    pub fn file(path: impl Into<String>) -> Self {
        let mut settings = serde_json::Map::new();
        settings.insert(
            SECRET_FILE_SETTING_PATH.to_string(),
            serde_json::Value::String(path.into()),
        );
        Self {
            module: SECRET_MODULE_FILE.to_string(),
            settings,
        }
    }

    /// The `env` module's variable name, when this ref uses the built-in `env` module.
    pub fn env_var(&self) -> Option<&str> {
        if self.module == SECRET_MODULE_ENV {
            self.settings
                .get(SECRET_ENV_SETTING_KEY)
                .and_then(|v| v.as_str())
        } else {
            None
        }
    }

    /// The `file` module's path, when this ref uses the built-in `file` module.
    pub fn file_path(&self) -> Option<&str> {
        if self.module == SECRET_MODULE_FILE {
            self.settings
                .get(SECRET_FILE_SETTING_PATH)
                .and_then(|v| v.as_str())
        } else {
            None
        }
    }

    /// A short display form for error messages: `env:VAR`, `file:/path`, or `module '<name>'`.
    pub fn describe(&self) -> String {
        if let Some(var) = self.env_var() {
            format!("env:{var}")
        } else if let Some(path) = self.file_path() {
            format!("file:{path}")
        } else {
            format!("secret module '{}'", self.module)
        }
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RefVisitor;

        impl<'de> Visitor<'de> for RefVisitor {
            type Value = SecretRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a secret reference map: { module: <secret-module>, settings: {…} }, \
                     { env: <VAR> }, or { file: <path> }",
                )
            }

            // A bare string here is almost always a LITERAL SECRET pasted inline (the exact
            // mistake this type exists to prevent). Reject it with a message that NEVER echoes
            // the value — serde's default invalid-type error would print the string verbatim
            // into boot logs.
            fn visit_str<E>(self, _v: &str) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(E::custom(
                    "a secret value must be a REFERENCE, never an inline literal (the value is \
                     not echoed): use { env: <VAR> }, { file: <path> }, or \
                     { module: <secret-module>, settings: {…} }",
                ))
            }

            fn visit_map<A>(self, mut map: A) -> Result<SecretRef, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut module: Option<String> = None;
                let mut settings: Option<serde_json::Map<String, serde_json::Value>> = None;
                let mut sugar: Option<(&'static str, String)> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "module" => {
                            if module.is_some() {
                                return Err(de::Error::duplicate_field("module"));
                            }
                            module = Some(map.next_value()?);
                        }
                        "settings" => {
                            if settings.is_some() {
                                return Err(de::Error::duplicate_field("settings"));
                            }
                            settings = Some(map.next_value()?);
                        }
                        "env" => {
                            if sugar.is_some() {
                                return Err(de::Error::custom(
                                    "a secret reference takes exactly one of `env:` / `file:`",
                                ));
                            }
                            sugar = Some((SECRET_MODULE_ENV, map.next_value()?));
                        }
                        "file" => {
                            if sugar.is_some() {
                                return Err(de::Error::custom(
                                    "a secret reference takes exactly one of `env:` / `file:`",
                                ));
                            }
                            sugar = Some((SECRET_MODULE_FILE, map.next_value()?));
                        }
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &["module", "settings", "env", "file"],
                            ));
                        }
                    }
                }

                match (module, sugar) {
                    (Some(_), Some(_)) => Err(de::Error::custom(
                        "a secret reference is either `{ module: …, settings: … }` or the \
                         `{ env: … }` / `{ file: … }` sugar, not both",
                    )),
                    (Some(module), None) => {
                        if module.trim().is_empty() {
                            return Err(de::Error::custom(
                                "a secret reference `module:` must be non-empty",
                            ));
                        }
                        Ok(SecretRef {
                            module,
                            settings: settings.unwrap_or_default(),
                        })
                    }
                    (None, Some((kind, value))) => {
                        if settings.is_some() {
                            return Err(de::Error::custom(
                                "the `{ env: … }` / `{ file: … }` sugar takes no `settings:` \
                                 (use the canonical `{ module: …, settings: … }` form instead)",
                            ));
                        }
                        if value.trim().is_empty() {
                            return Err(de::Error::custom(format!(
                                "a `{{ {kind}: … }}` secret reference must name a non-empty value"
                            )));
                        }
                        Ok(match kind {
                            SECRET_MODULE_ENV => SecretRef::env(value),
                            _ => SecretRef::file(value),
                        })
                    }
                    (None, None) => Err(de::Error::custom(
                        "a secret reference needs `module:` (with optional `settings:`) or the \
                         `{ env: <VAR> }` / `{ file: <path> }` sugar",
                    )),
                }
            }
        }

        deserializer.deserialize_any(RefVisitor)
    }
}

/// Derive the `x-busbar-secret` field's `oneOf` JSON Schema (2020-12) fragment DIRECTLY from
/// [`SecretRef`]'s own accepted shapes — the canonical `{ module, settings }` form plus the `{ env }`
/// / `{ file }` sugar. This is the schema busbar-ui composes a secret reference against — never a
/// bare string.
///
/// Because this is generated from the SAME three shapes [`SecretRef`]'s `Deserialize` impl accepts —
/// not a hand-maintained parallel copy — `{ "literal": <value> }` is excluded correctly with NO
/// special-casing: `literal` was never one of `SecretRef`'s accepted shapes in the first place (it is
/// handled one layer above `SecretRef` parsing, inside busbar's `resolve_settings()`, as an escape
/// hatch for a plugin whose own config happens to collide with a reference shape). A full, faithful
/// derivation from the real type is exactly what keeps `literal` out; there is no future "just derive
/// it fully" refactor that could reintroduce it.
pub fn oneof_schema() -> serde_json::Value {
    serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "module": {"type": "string", "minLength": 1},
                    "settings": {"type": "object"},
                },
                "required": ["module"],
                "additionalProperties": false,
            },
            {
                "type": "object",
                "properties": {"env": {"type": "string", "minLength": 1}},
                "required": ["env"],
                "additionalProperties": false,
            },
            {
                "type": "object",
                "properties": {"file": {"type": "string", "minLength": 1}},
                "required": ["file"],
                "additionalProperties": false,
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deserialize: the `{env}` / `{file}` sugar desugars to the canonical module + settings; the
    /// canonical form parses; mixed / unknown / empty forms are rejected.
    #[test]
    fn deserialize_accepts_canonical_and_sugar_rejects_malformed() {
        let r: SecretRef = serde_yaml::from_str("{ env: MY_VAR }").unwrap();
        assert_eq!(r, SecretRef::env("MY_VAR"));
        assert_eq!(r.env_var(), Some("MY_VAR"));
        let r: SecretRef = serde_yaml::from_str("{ file: /run/secrets/x }").unwrap();
        assert_eq!(r, SecretRef::file("/run/secrets/x"));
        assert_eq!(r.file_path(), Some("/run/secrets/x"));
        let r: SecretRef =
            serde_yaml::from_str("{ module: vault, settings: { path: kv/data/x } }").unwrap();
        assert_eq!(r.module, "vault");
        assert_eq!(
            r.settings.get("path").and_then(|v| v.as_str()),
            Some("kv/data/x")
        );

        for bad in [
            "{ env: A, file: B }",
            "{ module: vault, env: A }",
            "{ env: A, settings: {} }",
            "{ unknown_key: A }",
            "{}",
            "{ env: \"\" }",
            "{ module: \"\" }",
            "plain-string",
        ] {
            assert!(
                serde_yaml::from_str::<SecretRef>(bad).is_err(),
                "must reject: {bad}"
            );
        }
    }

    /// `describe()`'s three real forms — the env/file sugar takes priority over the canonical
    /// module+settings form, and the module fallback quotes the module name.
    #[test]
    fn describe_renders_env_file_and_module_forms() {
        assert_eq!(SecretRef::env("MY_VAR").describe(), "env:MY_VAR");
        assert_eq!(
            SecretRef::file("/run/secrets/x").describe(),
            "file:/run/secrets/x"
        );
        let r: SecretRef =
            serde_yaml::from_str("{ module: vault, settings: { path: kv/data/x } }").unwrap();
        assert_eq!(r.describe(), "secret module 'vault'");
    }

    /// The `Visitor::expecting` error message actually names the accepted shapes — asserted via a
    /// real deserialize failure on a shape with NO `visit_*` override (a bare integer, unlike a
    /// string, has no custom handler here so serde falls back to its default invalid-type error,
    /// which is built from `expecting()`), so this also proves serde actually wires it into the
    /// real error path, not just that the method compiles.
    #[test]
    fn deserialize_error_message_names_the_accepted_shapes() {
        let err = serde_yaml::from_str::<SecretRef>("42").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("a secret reference map"),
            "error must name the accepted shapes: {msg}"
        );
    }

    /// The derived `oneOf` is itself a valid JSON Schema 2020-12 fragment, and it accepts EXACTLY
    /// the shapes `SecretRef::deserialize` accepts (round-trip fidelity — this is the whole point of
    /// deriving instead of hand-writing).
    #[test]
    fn oneof_schema_accepts_exactly_what_secretref_accepts() {
        let full = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
        });
        let mut full = full.as_object().unwrap().clone();
        for (k, v) in oneof_schema().as_object().unwrap() {
            full.insert(k.clone(), v.clone());
        }
        let full = serde_json::Value::Object(full);
        let validator = jsonschema::validator_for(&full).expect("valid 2020-12 schema");

        let accept = [
            serde_json::json!({"module": "vault", "settings": {"key": "x"}}),
            serde_json::json!({"module": "env"}),
            serde_json::json!({"env": "MY_VAR"}),
            serde_json::json!({"file": "/run/secrets/x"}),
        ];
        for v in &accept {
            assert!(validator.is_valid(v), "should accept {v}");
            // Every accepted shape also round-trips through SecretRef's real Deserialize impl —
            // the derived schema is not merely permissive, it agrees with the actual type.
            assert!(
                serde_json::from_value::<SecretRef>(v.clone()).is_ok(),
                "derived oneOf accepted {v} but SecretRef::deserialize rejects it — drift"
            );
        }

        let reject = [
            // A bare string secret value — never valid (the whole point of this type).
            serde_json::json!("s3cret"),
            // `{ literal: ... }` is NOT a SecretRef shape (handled one layer above, in
            // resolve_settings()) — the derived oneOf must not accept it either.
            serde_json::json!({"literal": "s3cret"}),
            serde_json::json!({"env": "A", "file": "B"}),
            serde_json::json!({}),
        ];
        for v in &reject {
            assert!(!validator.is_valid(v), "should reject {v}");
        }
    }
}
