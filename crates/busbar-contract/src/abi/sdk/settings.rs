// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTINGS DOCUMENTS AS CONFIGURE-TIME CODE READS THEM: a kind's settings blob parsed into
//! JSON, once per validate, open, refresh or configure, never per request. Each kind's module
//! re-exports what it states here, under its own path.

use crate::abi::sdk::life::{settings_object, Refusal};
use crate::abi::sdk::secret_bytes::SecretBytes;
use crate::abi::sdk::transport::SettingRow;
use crate::abi::transport::{SETTING_COUNT, SETTING_FLAG, SETTING_TEXT};
use crate::secret::{SecretModuleError, SecretResult};

/// A settings document as an object: what `configure` is handed and `settings_object` answers.
pub type SettingsMap = serde_json::Map<String, serde_json::Value>;

/// An admin-time JSON document: a `status` or `describe` envelope.
pub type AdminJson = serde_json::Value;

/// The refusal of a dealt blob that is JSON but not an object.
pub const NOT_A_MAP: &str = "the dealt settings are not a map of the plane's sections";

/// The section `verb` names in the dealt blob `settings`: `None` when the blob is empty, writes no
pub fn dealt_section(settings: &[u8], verb: &str) -> Result<Option<serde_json::Value>, String> {
    if settings.is_empty() {
        return Ok(None);
    }
    let value =
        crate::abi::sdk::typed_json::parse_typed_value(settings).map_err(|e| e.to_string())?;
    let serde_json::Value::Object(mut verbs) = value else {
        return Err(NOT_A_MAP.to_string());
    };
    Ok(verbs.remove(verb).filter(|section| !section.is_null()))
}

/// A resolve's settings bytes as the JSON object they must be (empty = none).
pub fn settings_of(bytes: &[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        SecretModuleError::invalid(format!("secret settings are not a JSON object: {e}"))
    })
}

/// The instance settings of the source `module`, which takes none: empty bytes or an empty object.
pub fn takes_no_settings(bytes: &[u8], module: &str, names: &str) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Object(m)) => match m.keys().next() {
            None => Ok(()),
            Some(k) => Err(format!(
                "secret module '{module}' takes no settings; remove settings.{} (each reference \
                 names its {names})",
                k.escape_debug()
            )),
        },
        Err(e) => Err(format!("settings: {e}")),
        Ok(_) => Err("settings: must be a JSON object".to_string()),
    }
}

impl SettingRow {
    /// Why `value` is not a value of this setting's kind: [`SETTING_FLAG`] is `true`/`false`,
    fn refuses(&self, value: &serde_json::Value) -> Option<String> {
        let path = self.path;
        match self.kind {
            SETTING_FLAG if !value.is_boolean() => {
                Some(format!("settings: {path} must be true or false"))
            }
            SETTING_COUNT if !value.as_u64().is_some_and(|n| n > 0) => {
                Some(format!("settings: {path} must be a count above 0"))
            }
            SETTING_TEXT if !value.is_string() => Some(format!("settings: {path} must be text")),
            _ => None,
        }
    }
}

/// A transport's `settings` as the JSON object they must be (`{}` when empty), read against the
pub fn settings_reading(
    settings: &[u8],
    reads: &[SettingRow],
) -> Result<serde_json::Map<String, serde_json::Value>, Refusal> {
    let object = settings_object(settings)?;
    for (key, value) in &object {
        let Some(row) = reads.iter().find(|r| r.path == key) else {
            return Err(Refusal::failed(format!(
                "settings: {key} is not a setting this transport reads"
            )));
        };
        if let Some(why) = row.refuses(value) {
            return Err(Refusal::failed(why));
        }
    }
    Ok(object)
}

/// An owned hook settings/reply tree. Only its initialized owned strings and map keys are
pub(crate) struct JsonValue(pub(crate) serde_json::Value);

impl<'de> serde::Deserialize<'de> for JsonValue {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        <serde_json::Value as serde::Deserialize>::deserialize(de).map(Self)
    }
}

impl Drop for JsonValue {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            use zeroize::Zeroize;
            match value {
                serde_json::Value::String(text) => text.zeroize(),
                serde_json::Value::Array(items) => items.iter_mut().for_each(wipe),
                serde_json::Value::Object(items) => {
                    for (mut key, mut value) in std::mem::take(items) {
                        key.zeroize();
                        wipe(&mut value);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

/// An empty admin document, `{}`: a hook's default `status` and `describe`.
#[must_use]
pub(crate) fn empty_admin_json() -> AdminJson {
    serde_json::json!({})
}

/// A `configure` push's settings document, `{}` when empty, wiped when dropped. Its refusal is
/// `settings: not valid JSON: <serde's words>`.
pub(crate) fn configure_settings(bytes: &[u8]) -> Result<JsonValue, Refusal> {
    let bytes = if bytes.is_empty() { &b"{}"[..] } else { bytes };
    crate::abi::sdk::typed_json::parse_typed_value_wiping(bytes)
        .map(JsonValue)
        .map_err(|e| Refusal::failed(format!("settings: not valid JSON: {e}")))
}

/// A hook's `status` envelope as the bytes leased to the host, the tree wiped once written. Its
/// refusal is `status: <serde's words>`.
pub(crate) fn status_bytes(status: AdminJson) -> Result<SecretBytes, Refusal> {
    let status = JsonValue(status);
    let mut bytes = SecretBytes::default();
    serde_json::to_writer(&mut bytes, &status.0)
        .map_err(|e| Refusal::failed(format!("status: {e}")))?;
    Ok(bytes)
}

/// A hook's `describe` envelope as the bytes leased to the host. Its refusal is
/// `describe: <serde's words>`.
pub(crate) fn describe_bytes(describe: &AdminJson) -> Result<Vec<u8>, Refusal> {
    serde_json::to_vec(describe).map_err(|e| Refusal::failed(format!("describe: {e}")))
}
