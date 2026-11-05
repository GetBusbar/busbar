// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit, one-shot conversion of a released version-1 file overlay. Ordinary Store reads do
//! not call this module. The caller owns plugin settings migration, validation and durable commit.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use super::overlay::OverlayDoc;
use super::HookStage;

const FIELDS: &[&str] = &[
    "version",
    "hooks",
    "global_hooks",
    "deleted",
    "groups",
    "deleted_groups",
    "root",
    "plugin_versions",
    "named_maps",
];

/// Validate the original file bytes before any host-side plugin settings conversion, and
/// normalize hook names and stages. Unknown top-level fields, newer overlay documents, duplicate
/// keys and conflicting aliases are refused. No Store or filesystem writes occur here.
pub fn parse_legacy_overlay(bytes: &[u8]) -> Result<Value, String> {
    // Value alone silently replaces duplicate object keys. Check the original stream first,
    // including opaque settings, so reserialization cannot erase conflicting source evidence.
    serde_json::from_slice::<UniqueJson>(bytes).map_err(|_| {
        "legacy overlay must be valid JSON with no duplicate object keys".to_owned()
    })?;
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "legacy overlay must be valid JSON".to_owned())?;
    let root = value
        .as_object_mut()
        .ok_or("legacy overlay must be a JSON object")?;
    if root.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err("legacy overlay has an unsupported top-level field; document and catalog patches cannot be imported as version 1".into());
    }
    if root
        .get("version")
        .is_some_and(|version| version.as_u64() != Some(1))
    {
        return Err("legacy overlay version must be the integer 1".into());
    }
    let Some(hooks) = root.get_mut("hooks") else {
        return Ok(value);
    };
    let hooks = hooks
        .as_object_mut()
        .ok_or("legacy overlay hooks must be an object")?;
    for entry in hooks.values_mut() {
        let hook = entry
            .as_object_mut()
            .ok_or("legacy overlay hook definition must be an object")?;
        if hook.contains_key("plugin") && hook.contains_key("module") {
            return Err("legacy overlay hook cannot specify both plugin and module".into());
        }
        if let Some(plugin) = hook.remove("plugin") {
            hook.insert("module".into(), plugin);
        }
        let phase: Vec<HookStage> = match hook.get("phase") {
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|_| "legacy overlay hook phase must be a list of valid stages")?,
            None => Vec::new(),
        };
        if let Some(at) = hook.remove("at") {
            // Null was a valid absent Option<HookStage>. Every other value must be a valid
            // stage, even when phase takes precedence: malformed state must never disappear.
            if at.is_null() {
                continue;
            }
            let stage = at
                .as_str()
                .ok_or("legacy overlay hook at must be a stage name or null")?;
            let renamed = super::RENAMED_HOOK_STAGES
                .iter()
                .find(|(old, _)| *old == stage)
                .map_or(stage, |(_, new)| *new);
            let stage: HookStage = serde_json::from_value(Value::String(renamed.to_owned()))
                .map_err(|_| "legacy overlay hook at names an unsupported stage")?;
            if phase.is_empty() {
                hook.insert("phase".into(), serde_json::json!([stage]));
            }
        }
    }
    Ok(value)
}

/// Decode an explicitly migrated version-1 overlay. Hosts with plugin-owned settings should
/// first call [`parse_legacy_overlay`] on the original bytes, migrate those settings, then pass
/// the resulting JSON here. The returned version remains 1; the committing importer upgrades it.
pub fn decode_legacy_overlay(bytes: &[u8]) -> Result<OverlayDoc, String> {
    let value = parse_legacy_overlay(bytes)?;
    serde_json::from_value(value)
        .map_err(|_| "legacy overlay fields do not match the current configuration schema".into())
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_any(Self)
    }
}

impl<'de> Visitor<'de> for UniqueJson {
    type Value = Self;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON without duplicate object keys")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self, S::Error> {
        while seq.next_element::<Self>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self, M::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            map.next_value::<Self>()?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_conversion_preserves_controls_tombstones_and_effective_rates() {
        let source = br#"{
            "version":1,
            "hooks":{"guard":{"kind":"tap","plugin":"observer","at":"response",
                "on_error":"reject","groups":["restricted"],"settings":{"secret":{"env":"HOOK_KEY"}}}},
            "global_hooks":["guard"],"deleted":["base-hook"],
            "groups":{"restricted":{"enabled":false}},"deleted_groups":["base-group"],
            "root":{"per_request_fee":7},"plugin_versions":{"observer":"1.5.5"},
            "named_maps":{"export":{"audit":{"module":"file","settings":{"path":"audit.json"}}}}
        }"#;
        let normalized = parse_legacy_overlay(source).unwrap();
        assert_eq!(
            normalized["hooks"]["guard"]["settings"]["secret"]["env"],
            "HOOK_KEY"
        );
        let doc = decode_legacy_overlay(source).unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.document_patch.is_none() && doc.providers_patch.is_none());
        assert_eq!(
            doc.hooks["guard"].resolved_stages(),
            vec![HookStage::Response]
        );
        assert_eq!(doc.hooks["guard"].on_error, "reject");
        assert_eq!(doc.hooks["guard"].groups, vec!["restricted"]);
        assert_eq!(doc.global_hooks, vec!["guard"]);
        assert_eq!(doc.deleted, vec!["base-hook"]);
        assert_eq!(doc.deleted_groups, vec!["base-group"]);
        assert!(!doc.groups["restricted"].enabled);
        assert_eq!(doc.root.unwrap().per_request_fee, Some(7));
        assert_eq!(doc.plugin_versions["observer"], "1.5.5");
        assert_eq!(doc.named_maps["export"]["audit"]["module"], "file");
    }

    #[test]
    fn explicit_conversion_preserves_phase_precedence_and_is_idempotent() {
        let source = br#"{"hooks":{"h":{"kind":"tap","module":"observer","at":"request","phase":["response"]}}}"#;
        let normalized = parse_legacy_overlay(source).unwrap();
        let bytes = serde_json::to_vec(&normalized).unwrap();
        assert_eq!(parse_legacy_overlay(&bytes).unwrap(), normalized);
        let doc = decode_legacy_overlay(&bytes).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.hooks["h"].resolved_stages(), vec![HookStage::Response]);
    }

    #[test]
    fn malformed_or_ambiguous_sources_are_refused_before_reserialization() {
        for source in [
            r#"{"version":2}"#,
            r#"{"version":0}"#,
            r#"{"version":1.0}"#,
            r#"{"version":null}"#,
            r#"{"unknown":true}"#,
            r#"{"document_patch":null}"#,
            r#"{"providers_patch":null}"#,
            r#"{"groups":{},"groups":{}}"#,
            r#"{"hooks":{"h":{"module":"x","settings":{"key":1,"key":2}}}}"#,
            r#"{"hooks":{"h":{"module":"x","plugin":"x"}}}"#,
            r#"{"hooks":{"h":{"at":7,"phase":["response"]}}}"#,
            r#"{"hooks":{"h":{"at":"invalid","phase":["response"]}}}"#,
            r#"{"hooks":{"h":{"at":"request","phase":null}}}"#,
            r#"{"hooks":null}"#,
            r#"{"hooks":{"h":null}}"#,
            r#"[]"#,
        ] {
            assert!(parse_legacy_overlay(source.as_bytes()).is_err(), "{source}");
        }
    }

    #[test]
    fn ordinary_store_reads_never_migrate_hook_spellings() {
        use super::super::overlay::{classify_bytes, OverlayReadState};
        let source = br#"{"hooks":{"h":{"kind":"tap","plugin":"observer","at":"response"}}}"#;
        assert!(matches!(
            classify_bytes(Some(source.to_vec())),
            OverlayReadState::Unreadable
        ));
        let doc = decode_legacy_overlay(source).unwrap();
        assert!(matches!(
            classify_bytes(Some(serde_json::to_vec(&doc).unwrap())),
            OverlayReadState::Loaded(_)
        ));
    }
}
