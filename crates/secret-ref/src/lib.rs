// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `SecretRef` — the SECRET REFERENCE type, extracted out of `busbar`'s crate-private
//! `crates/busbar-core/src/config/secret.rs` into its own tiny crate.
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
//! `Deserialize` impl `busbar`'s engine uses to parse a live config. The two are written by hand
//! against each other, not generated one from the other, so what actually keeps them in step is the
//! round-trip test that runs the same table of shapes through both and demands the same verdict —
//! the drift it caught first was a whitespace-only value the schema accepted and the visitor did not.
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

/// "At least one non-whitespace character", as [`oneof_schema`] states the non-empty rule. The
/// visitor's own check is `value.trim().is_empty()`, and `minLength: 1` is NOT that: a string of
/// three spaces has length three, so the schema accepted `{ env: "   " }` while the engine refused
/// it — a form that validates in busbar-ui and then fails at boot. This pattern says what the
/// deserializer means.
const NON_BLANK: &str = r"\S";

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

        impl RefVisitor {
            /// The one refusal message every inline-scalar spelling shares. Names the accepted
            /// shapes and NEVER echoes what it was handed — the value it was handed is the secret.
            fn inline_literal<E: de::Error>() -> E {
                E::custom(
                    "a secret value must be a REFERENCE, never an inline literal (the value is \
                     not echoed): use { env: <VAR> }, { file: <path> }, or \
                     { module: <secret-module>, settings: {…} }",
                )
            }
        }

        impl<'de> Visitor<'de> for RefVisitor {
            type Value = SecretRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a secret reference map: { module: <secret-module>, settings: {…} }, \
                     { env: <VAR> }, or { file: <path> }",
                )
            }

            // A bare scalar here is almost always a LITERAL SECRET pasted inline (the exact
            // mistake this type exists to prevent). Reject it with a message that NEVER echoes
            // the value — serde's default invalid-type error would print the value verbatim
            // into boot logs.
            fn visit_str<E>(self, _v: &str) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(Self::inline_literal())
            }

            // Every OTHER scalar form, for the same reason and with the same non-echoing message.
            // A secret is not always quoted: `api_key: 483920175534` and `api_key: true` are
            // perfectly ordinary YAML, and each one landed on serde's default `invalid type`
            // error — which prints the value it received. The one path this type exists to keep a
            // secret off (the boot log) is exactly where it went, and unquoted is the spelling
            // nobody thinks to check.
            fn visit_u64<E>(self, _v: u64) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(Self::inline_literal())
            }

            fn visit_i64<E>(self, _v: i64) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(Self::inline_literal())
            }

            fn visit_f64<E>(self, _v: f64) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(Self::inline_literal())
            }

            fn visit_bool<E>(self, _v: bool) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(Self::inline_literal())
            }

            fn visit_bytes<E>(self, _v: &[u8]) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(Self::inline_literal())
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
/// This fragment is WRITTEN OUT here rather than mechanically generated from the `Deserialize` impl
/// — serde exposes no schema to generate one from — so "it cannot drift" is not something the code
/// makes true on its own. What pins it is the round-trip test in this crate's own suite: one table
/// of shapes, each fed to BOTH the validator built from this fragment and `SecretRef::deserialize`,
/// with the two verdicts asserted equal. Change either side alone and that test says so. It was
/// added because the two HAD drifted: `minLength: 1` accepted a whitespace-only `{ env: "   " }`
/// that the visitor's `trim().is_empty()` check refuses.
///
/// `{ "literal": <value> }` is excluded, and needs no special-casing to be: `literal` was never one
/// of `SecretRef`'s accepted shapes in the first place (it is handled one layer above `SecretRef`
/// parsing, inside busbar's `resolve_settings()`, as an escape hatch for a plugin whose own config
/// happens to collide with a reference shape).
pub fn oneof_schema() -> serde_json::Value {
    serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "module": {"type": "string", "pattern": NON_BLANK},
                    "settings": {"type": "object"},
                },
                "required": ["module"],
                "additionalProperties": false,
            },
            {
                "type": "object",
                "properties": {"env": {"type": "string", "pattern": NON_BLANK}},
                "required": ["env"],
                "additionalProperties": false,
            },
            {
                "type": "object",
                "properties": {"file": {"type": "string", "pattern": NON_BLANK}},
                "required": ["file"],
                "additionalProperties": false,
            },
        ],
    })
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
