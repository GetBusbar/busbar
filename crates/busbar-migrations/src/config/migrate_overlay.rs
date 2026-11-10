// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit 1.5.5 file-overlay conversion. Serving never calls this module.
use super::migrate_plugins::MigrateHost;
#[cfg(test)]
use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_contract::abi::sdk::migrate::MigrationAnswer;
use busbar_kernel::config::overlay::OverlayDoc;
use serde_json::{Map, Value};

// Overlay conversion must not rewrite the providers catalog or add a default Store to the
// persisted patch. It borrows only the plugin-owned setting transforms and destination needs.
struct OverlayHost<'a>(&'a dyn MigrateHost);
impl MigrateHost for OverlayHost<'_> {
    fn source_declarations(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
        self.0.source_declarations()
    }
    fn migrate_credential(
        &self,
        module: &str,
        credential: &busbar_contract::secret_ref::SecretRef,
        from: &str,
    ) -> Result<Option<busbar_contract::secret_ref::SecretRef>, String> {
        self.0.migrate_credential(module, credential, from)
    }
    fn migrate_references(
        &self,
        kind: &str,
        module: &str,
        settings: &Value,
        from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        self.0.migrate_references(kind, module, settings, from)
    }

    fn admit_config_profile(&self, proof: &super::HistoricalConfigProof) -> Result<(), String> {
        self.0.admit_config_profile(proof)
    }
    fn validate_migrated(&self, kind: &str, module: &str, settings: &Value) -> Result<(), String> {
        self.0.validate_migrated(kind, module, settings)
    }
    fn migrating_from(&self) -> &str {
        "1.5.5"
    }
    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &Value,
        from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        self.0.migrate(kind, module, settings, from)
    }
    fn externalize_secret(
        &self,
        site: &str,
        path: &[String],
        bytes: &[u8],
    ) -> Result<String, String> {
        self.0
            .externalize_secret(&format!("overlay.{site}"), path, bytes)
    }
    fn repin(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        self.0.resolve(host)
    }
}

pub fn migrate_overlay_with(bytes: &[u8], host: &dyn MigrateHost) -> Result<OverlayDoc, String> {
    let mut source = super::overlay_legacy::parse_legacy_overlay(bytes)?;
    host.admit_config_profile(&super::provenance::HistoricalConfigProof::settings(
        "overlay.v1",
        &source,
    )?)?;
    let mut fragment = Map::new();
    let root = match source.get("root") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(root)) => root.clone(),
        _ => return Err("historical overlay root is not an object".into()),
    };
    let had_store = root.contains_key("store");
    fragment.extend(root.clone());
    for key in ["hooks", "groups", "global_hooks"] {
        if let Some(value) = source.get(key) {
            fragment.insert(key.into(), value.clone());
        }
    }
    let sections = busbar_kernel::config::named_map::NamedMapSection::sections();
    if let Some(maps) = source.get("named_maps") {
        let maps = maps
            .as_object()
            .ok_or("historical overlay named_maps is not an object")?;
        for (key, value) in maps {
            if !sections.iter().any(|section| section.key() == key) {
                return Err(format!(
                    "historical overlay names an unavailable definition section '{key}'"
                ));
            }
            if fragment.insert(key.clone(), value.clone()).is_some() {
                return Err("historical overlay repeats a configuration section".into());
            }
        }
    }
    let fragment = super::migrate_plugins::yaml_value(&Value::Object(fragment))?;
    let raw =
        serde_yaml::to_string(&fragment).map_err(|_| "cannot encode overlay migration input")?;
    let converted = super::migrate::migrate_overlay_fragment(&raw, &OverlayHost(host))?;
    if !converted.todos.is_empty() {
        return Err("overlay migration has unresolved plugin or configuration prerequisites; migrate the affected settings before retrying".into());
    }
    let mut migrated: Map<String, Value> = serde_yaml::from_str(&converted.yaml)
        .map_err(|_| "cannot decode overlay migration result")?;
    let object = source
        .as_object_mut()
        .ok_or("historical overlay is not an object")?;
    for key in ["hooks", "groups", "global_hooks"] {
        if let Some(value) = migrated.remove(key) {
            object.insert(key.into(), value);
        }
    }
    let mut maps = Map::new();
    for section in sections {
        if let Some(value) = migrated.remove(section.key()) {
            maps.insert(section.key().into(), value);
        }
    }
    object.insert("named_maps".into(), Value::Object(maps));
    if !had_store {
        migrated.remove("store");
    }
    // RootSettings' strict schema checks every retained or newly produced root key. No
    // unsupported output is silently discarded, and all original tombstones remain untouched.
    if !migrated.is_empty() {
        object.insert("root".into(), Value::Object(migrated));
    }
    let bytes = serde_json::to_vec(&source).map_err(|_| "cannot encode migrated overlay")?;
    let mut doc = super::overlay_legacy::decode_legacy_overlay(&bytes)?;
    doc.version = busbar_kernel::config::overlay::OVERLAY_VERSION;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Host;
    impl MigrateHost for Host {
        fn source_declarations(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
            use busbar_contract::abi::mechanism::door::{
                REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_PATH,
            };
            let mut sources = busbar_contract::secret_ref::Sugars::default();
            sources.declare(
                "artifact-owner",
                &[
                    (REWRITE_SUGAR, "artifact".into(), "path".into()),
                    (
                        REWRITE_SUGAR_ROLE,
                        "artifact".into(),
                        SUGAR_ROLE_PATH.into(),
                    ),
                ],
            )?;
            Ok(sources)
        }
        fn resolved_authored_scalar(&self, _: &str) -> Result<Option<Value>, String> {
            // A coincident authored YAML placeholder must not reinterpret frozen JSON data.
            Ok(Some(Value::String("unrelated-authored-environment".into())))
        }
        fn migrate(
            &self,
            _: &str,
            module: &str,
            settings: &Value,
            _: &str,
        ) -> Result<Option<(String, MigrationAnswer)>, String> {
            if module != "test-lift" {
                return Ok(None);
            }
            Ok(Some((
                module.into(),
                Migrated {
                    settings: settings.clone(),
                    report: vec!["externalized old credential".into()],
                    needs: vec![
                        busbar_contract::abi::sdk::migrate::MigrateNeed::ExternalizeSecret {
                            path: vec!["token".into()],
                        },
                    ],
                }
                .into(),
            )))
        }
        fn externalize_secret(
            &self,
            site: &str,
            _: &[String],
            bytes: &[u8],
        ) -> Result<String, String> {
            assert!(site.starts_with("overlay."));
            assert_eq!(bytes, b"${UNCHANGED}");
            Ok("/protected/old-token".into())
        }
        fn repin(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
    }
    #[test]
    fn actual_overlay_shape_preserves_tombstones_controls_and_converts_plugin_settings() {
        let bytes = br#"{"version":1,"hooks":{"guard":{"kind":"tap","plugin":"observer","at":"response","groups":["restricted"],"on_error":"reject"}},"global_hooks":["guard"],"deleted":["old-hook"],"groups":{"restricted":{"enabled":false}},"deleted_groups":["old-grant"],"root":{"per_request_fee":7},"named_maps":{"identity-providers":{"corp":{"module":"test-lift","settings":{"token":"${UNCHANGED}"}}}}}"#;
        let doc = migrate_overlay_with(bytes, &Host).unwrap();
        assert_eq!(doc.deleted, ["old-hook"]);
        assert_eq!(doc.deleted_groups, ["old-grant"]);
        assert!(!doc.groups["restricted"].enabled);
        assert_eq!(doc.root.unwrap().per_request_fee, Some(7));
        assert_eq!(
            doc.hooks["guard"].resolved_stages(),
            [busbar_kernel::config::HookStage::Response]
        );
        assert_eq!(
            doc.named_maps["identity-providers"]["corp"]["settings"]["token"]["settings"]["path"],
            "/protected/old-token"
        );
    }
    #[test]
    fn duplicate_overlay_fields_are_refused_before_plugin_conversion() {
        assert!(migrate_overlay_with(br#"{"groups":{},"groups":{}}"#, &Host).is_err());
    }
}
