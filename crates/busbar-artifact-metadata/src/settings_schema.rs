// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_json::JsonValueTrait;

/// Read the public schema from the canonical Statement, without opening a plugin.
/// Absence is allowed; a present but malformed schema is an admission error.
pub fn statement_schema(schema: &crate::rendering::ReadBlob) -> Result<Option<String>, String> {
    if schema.bytes.is_empty() {
        return Ok(None);
    }
    if schema.fmt != crate::BLOB_JSON || schema.flags != 0 {
        return Err("Statement settings_schema must be public JSON".into());
    }
    if schema.bytes.len() > 256 * 1024 {
        return Err("Statement settings_schema exceeds the 262144-byte cap".into());
    }
    let text = std::str::from_utf8(&schema.bytes)
        .map_err(|_| "Statement settings_schema is not UTF-8".to_string())?;
    let value = busbar_json::parse_value_bounded(text.as_bytes(), 127)
        .map_err(|e| format!("Statement settings_schema is not valid JSON: {e}"))?;
    if !value.is_object() && !value.is_boolean() {
        return Err("Statement settings_schema must be a JSON Schema object or boolean".into());
    }
    Ok(Some(text.to_string()))
}
