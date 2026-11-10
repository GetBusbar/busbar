// SPDX-License-Identifier: Apache-2.0
//! Auth identity-domain metadata admission.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
/// Auth schema annotation naming non-secret identity-domain fields.
pub const DOMAIN_ANNOTATION: &str = "x-busbar-principal-domain-fields";
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainField {
    pointer: String,
    required: bool,
}

/// Commit only the non-secret identity-domain fields admitted by the auth schema.
pub fn domain_fingerprint(
    schema: &serde_json::Value,
    settings: &crate::plugin_settings::Settings,
    secret_paths: &[String],
) -> Result<String, String> {
    let declaration = schema
        .get(DOMAIN_ANNOTATION)
        .ok_or("principal format requires declared non-secret identity domain fields")?;
    let fields: Vec<DomainField> = serde_json::from_value(declaration.clone())
        .map_err(|_| "invalid principal domain field declaration")?;
    if fields.is_empty() || fields.len() > 32 {
        return Err("principal domain declaration requires 1..32 fields".into());
    }
    let mut seen = BTreeSet::new();
    let mut values = Vec::with_capacity(fields.len());
    for field in &fields {
        if !field.pointer.starts_with('/')
            || field.pointer.len() > 256
            || field.pointer.chars().any(char::is_control)
            || !seen.insert(&field.pointer)
        {
            return Err("invalid or duplicate principal domain JSON pointer".into());
        }
        let mut segments = Vec::new();
        for token in field.pointer[1..].split('/') {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(ch) = chars.next() {
                decoded.push(if ch == '~' {
                    match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err("invalid principal domain JSON pointer escape".into()),
                    }
                } else {
                    ch
                });
            }
            segments.push(decoded);
        }
        // Statement secret paths use dot-separated components and '*' wildcards. Either
        // ancestor direction overlaps: hashing a parent object also hashes its secret slot.
        if secret_paths.iter().any(|path| {
            path.split('.')
                .zip(&segments)
                .all(|(secret, selected)| secret == "*" || secret == selected)
        }) {
            return Err(
                "principal domain fields must not overlap declared secret/reference slots".into(),
            );
        }
        let value = settings
            .0
             .0
            .pointer(&field.pointer)
            .unwrap_or(&serde_json::Value::Null);
        if field.required && value.is_null() {
            return Err("required principal domain field is absent or null".into());
        }
        // Admission rejects undeclared SecretRefs; also reject them locally so this helper
        // never fingerprints an unresolved reference if called before that validation.
        if crate::secret_fields::undeclared_reference(value, &[]).is_some() {
            return Err(
                "principal domain fields must contain non-secret configuration values".into(),
            );
        }
        values.push(value.clone());
    }
    let mut value = crate::plugin_settings::Tree(
        serde_json::to_value((fields, values)).map_err(|error| error.to_string())?,
    );
    value.0.sort_all_objects();
    let bytes = value.encode().map_err(|error| error.to_string())?;
    Ok(hex::encode(Sha256::digest(&bytes.0)))
}
