// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Busbar settings profile, in addition to JSON Schema 2020-12.
//! Compile this helper with the same serde_json number representation as the parser.
//! Validate the original parsed bytes before any numeric conversion or serialization.

use jsonschema::{Keyword, ValidationError, Validator};
use serde_json::Value;

struct IntegerToken {
    signed: bool,
    nullable: bool,
}

impl<'i> Keyword<'i> for IntegerToken {
    fn validate(&self, instance: &'i Value) -> Result<(), ValidationError<'i>> {
        if self.is_valid(instance) {
            Ok(())
        } else {
            Err(ValidationError::custom("expected a Busbar integer token"))
        }
    }

    fn is_valid(&self, instance: &'i Value) -> bool {
        if instance.is_null() && self.nullable {
            return true;
        }
        if self.signed {
            instance.as_i64().is_some()
        } else {
            instance.as_u64().is_some()
        }
    }
}

/// Compile standard JSON Schema and, when declared, Busbar's integer-token profile.
///
/// # Errors
/// Refuses an unknown profile, a malformed keyword, or an invalid JSON Schema.
pub fn validator(schema: &Value) -> Result<Validator, ValidationError<'_>> {
    let profile = match schema.get("x-busbar-settings-profile") {
        None => false,
        Some(value) if value.as_str() == Some("integer-token-v1") => true,
        Some(_) => return Err(ValidationError::schema("unknown Busbar settings profile")),
    };
    jsonschema::options()
        .with_keyword("x-busbar-integer-token", move |parent, value, _| {
            if !profile {
                return Err(ValidationError::schema(
                    "x-busbar-integer-token requires integer-token-v1 settings profile",
                ));
            }
            let nullable = match parent.get("type") {
                Some(Value::String(kind)) if kind == "integer" => false,
                Some(Value::Array(kinds))
                    if kinds.iter().any(|kind| kind.as_str() == Some("integer"))
                        && kinds
                            .iter()
                            .all(|kind| matches!(kind.as_str(), Some("integer" | "null"))) =>
                {
                    kinds.iter().any(|kind| kind.as_str() == Some("null"))
                }
                _ => {
                    return Err(ValidationError::schema(
                        "x-busbar-integer-token requires integer or integer/null type",
                    ))
                }
            };
            let signed = match value.as_str() {
                Some("signed") => true,
                Some("unsigned") => false,
                _ => {
                    return Err(ValidationError::schema(
                        "x-busbar-integer-token must be signed or unsigned",
                    ));
                }
            };
            Ok(Box::new(IntegerToken { signed, nullable }))
        })
        .build(schema)
}

#[cfg(test)]
#[path = "integer_token_tests.rs"]
mod tests;
