// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `json::SchemaCheck`: JSON Schema 2020-12 over bytes (SERDE-JSON-EXIT §2).
//!
//! jsonschema builds a validator only from its own JSON tree, so schema and instance both enter
//! through [`super::parse_foreign`] (binary64); no caller names that tree. Tooling and tests only:
//! the engine's normal graph keeps no jsonschema (feature `schema`).

use jsonschema::{ValidationError, Validator};

use keyword::IntegerToken;

use super::{parse_foreign, parse_value, Error, JsonValueTrait};

/// The settings-profile keyword's name and the one profile busbar defines.
const PROFILE: &str = "x-busbar-settings-profile";
const INTEGER_TOKEN_V1: &str = "integer-token-v1";
const INTEGER_TOKEN: &str = "x-busbar-integer-token";

/// A compiled JSON Schema that checks JSON documents given as bytes.
#[derive(Debug)]
pub struct SchemaCheck(Validator);

impl SchemaCheck {
    /// Compile a standard JSON Schema (the draft its `$schema` names, else 2020-12).
    ///
    /// # Errors
    /// A schema that is not JSON, or not a valid JSON Schema.
    pub fn new(schema: &[u8]) -> Result<Self, Error> {
        let document = parse_foreign(schema)?;
        jsonschema::validator_for(&document)
            .map(Self)
            .map_err(Error::refused)
    }

    /// Compile a schema under busbar's settings profile: when the schema declares
    /// `"x-busbar-settings-profile": "integer-token-v1"`, the keyword
    /// `"x-busbar-integer-token": "signed" | "unsigned"` admits only a JSON integer token that an
    /// `i64` (or `u64`) holds (`1.0` and `1e0` are integers to JSON Schema, not tokens), or `null`
    /// where the keyword's `type` allows it. Without the profile it is standard JSON Schema.
    ///
    /// # Errors
    /// A schema that is not JSON, an unknown profile, the keyword without the profile or on a type
    /// other than `integer` (or `integer`/`null`), a keyword value other than `signed` or
    /// `unsigned`, or a schema that is not a valid JSON Schema.
    pub fn with_settings_profile(schema: &[u8]) -> Result<Self, Error> {
        // Read from a facade parse of the same bytes: the foreign tree's type is not named here, so
        // no method can be called on it before the validator infers it.
        let profile = match parse_value(schema)?.get(PROFILE) {
            None => false,
            Some(value) if value.as_str() == Some(INTEGER_TOKEN_V1) => true,
            Some(_) => return Err(Error::refused("unknown Busbar settings profile")),
        };
        let document = parse_foreign(schema)?;
        jsonschema::options()
            .with_keyword(INTEGER_TOKEN, move |parent, value, _| {
                if !profile {
                    return Err(ValidationError::schema(
                        "x-busbar-integer-token requires integer-token-v1 settings profile",
                    ));
                }
                let kind = parent.get("type");
                let nullable = if kind.and_then(|kind| kind.as_str()) == Some("integer") {
                    false
                } else if let Some(kinds) = kind.and_then(|kind| kind.as_array()).filter(|kinds| {
                    kinds.iter().any(|kind| kind.as_str() == Some("integer"))
                        && kinds
                            .iter()
                            .all(|kind| matches!(kind.as_str(), Some("integer" | "null")))
                }) {
                    kinds.iter().any(|kind| kind.as_str() == Some("null"))
                } else {
                    return Err(ValidationError::schema(
                        "x-busbar-integer-token requires integer or integer/null type",
                    ));
                };
                let signed = match value.as_str() {
                    Some("signed") => true,
                    Some("unsigned") => false,
                    _ => {
                        return Err(ValidationError::schema(
                            "x-busbar-integer-token must be signed or unsigned",
                        ))
                    }
                };
                Ok(Box::new(IntegerToken { signed, nullable }))
            })
            .build(&document)
            .map(Self)
            .map_err(Error::refused)
    }

    /// Whether `instance` is a JSON document the schema accepts (one that does not parse is not).
    pub fn is_valid(&self, instance: &[u8]) -> bool {
        match parse_foreign(instance) {
            Ok(document) => self.0.is_valid(&document),
            Err(_) => false,
        }
    }

    /// Check `instance`; a refusal is jsonschema's text, after the instance path when there is one.
    ///
    /// # Errors
    /// An instance that does not parse, or one the schema refuses.
    pub fn validate(&self, instance: &[u8]) -> Result<(), String> {
        let document = parse_foreign(instance).map_err(|error| error.to_string())?;
        self.0.validate(&document).map_err(|error| {
            let path = error.instance_path().as_str();
            if path.is_empty() {
                error.to_string()
            } else {
                format!("{path}: {error}")
            }
        })
    }
}

/// The keyword, apart from the facade's tree traits: its instance is jsonschema's node.
mod keyword {
    use jsonschema::json::{Json, JsonNumber, Node};
    use jsonschema::{Keyword, ValidationError};

    /// `x-busbar-integer-token`: the instance is an integer token (or an allowed `null`).
    pub(super) struct IntegerToken {
        pub(super) signed: bool,
        pub(super) nullable: bool,
    }

    impl<'i, F: Json> Keyword<'i, F> for IntegerToken {
        fn validate(&self, instance: F::Node<'i>) -> Result<(), ValidationError<'i>> {
            if <Self as Keyword<'i, F>>::is_valid(self, instance) {
                Ok(())
            } else {
                Err(ValidationError::custom("expected a Busbar integer token"))
            }
        }

        fn is_valid(&self, instance: F::Node<'i>) -> bool {
            if self.nullable && instance.is_null() {
                return true;
            }
            instance.as_number().is_some_and(|number| {
                if self.signed {
                    number.as_i64().is_some()
                } else {
                    number.as_u64().is_some()
                }
            })
        }
    }
}
