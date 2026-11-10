// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The released 1.5.5 JWT adapter read a filename from the resolved provider credential.
//! This is a one-shot conversion of that historical binding, not a current auth capability.
//! OAuth has no outbound-binding Migrate entry: the existing plugin migration receives only
//! identity-provider settings, so it cannot replace the deployment's credential reference.

use busbar_contract::secret_ref::SecretRef;
use serde_yaml::{Mapping, Value};

use super::migrate_plugins::MigrateHost;

pub(super) fn migrate(
    root: &mut Mapping,
    host: &dyn MigrateHost,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    // The caller admits the frozen supported native profile. The binding itself is
    // established by authored auth shape plus credential inspection, never by a
    // guessed marketing release string supplied by a host.
    let Some(Value::Mapping(providers)) = root.get_mut("providers") else {
        return;
    };
    // In 1.5.5, deployment auth overrides catalog auth, but api_key always belongs
    // to the deployment. Never import a catalog credential or mutate the catalog.
    let catalog = host.providers_catalog().ok().flatten();
    for (name, provider) in providers {
        let (Some(name), Value::Mapping(provider)) = (name.as_str(), provider) else {
            continue;
        };
        let auth = provider.get("auth").filter(|v| !v.is_null());
        let style = auth.and_then(Value::as_str).or_else(|| {
            auth.is_none()
                .then(|| catalog.as_ref()?.get(name)?.get("auth")?.as_str())
                .flatten()
        });
        let Some(style) = style else {
            if auth.is_none() && catalog.is_none() {
                todos.push(format!("providers.{name}: supply the original providers catalog to check whether its JWT credential needs migration; the reference was preserved"));
            }
            continue;
        };
        if style != "jwt-bearer" {
            continue;
        }
        let reference = provider.get("api_key").cloned().and_then(|v| {
            busbar_contract::secret_ref::context::deserialize::<SecretRef, _>(
                v,
                &host.source_declarations().ok()?,
            )
            .ok()
        });
        let migrated = reference
            .as_ref()
            .ok_or(())
            .and_then(|reference| host.legacy_jwt_credential_file(reference).map_err(|_| ()));
        match migrated {
            Ok(Some(file)) => {
                // Only a reference is serialized. Neither resolved JSON nor a resolver's error
                // is included in the document or report.
                let Ok(file) = serde_yaml::to_value(file) else {
                    todos.push(format!("providers.{name}.api_key: could not encode the migrated file reference; the original was preserved"));
                    continue;
                };
                provider.insert("api_key".into(), file);
                changes.push(format!("providers.{name}.api_key: converted the 1.5.5 JWT credential filename to an explicit file reference, anchored to the migration process working directory"));
            }
            Ok(None) => {}
            Err(()) => todos.push(format!("providers.{name}.api_key: could not resolve and verify the 1.5.5 JWT credential; the original reference was preserved. Run migration with the original secret sources and working directory, or provide an explicit file reference to the service-account JSON")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::sdk::migrate::Migrated;

    fn sources() -> busbar_contract::secret_ref::Sugars {
        use busbar_contract::abi::mechanism::door::{
            REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
        };
        let mut sources = busbar_contract::secret_ref::Sugars::default();
        for (owner, word, role) in [
            ("lookup-owner", "lookup", SUGAR_ROLE_FILL),
            ("artifact-owner", "artifact", SUGAR_ROLE_PATH),
        ] {
            sources
                .declare(
                    owner,
                    &[
                        (REWRITE_SUGAR, word.into(), "slot".into()),
                        (REWRITE_SUGAR_ROLE, word.into(), role.into()),
                    ],
                )
                .unwrap();
        }
        sources
    }
    struct Host;
    impl MigrateHost for Host {
        fn source_declarations(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
            Ok(sources())
        }
        fn migrate(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: &str,
        ) -> Result<Option<(String, Migrated)>, String> {
            Ok(None)
        }
        fn repin(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn providers_catalog(
            &self,
        ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
            Ok(Some(serde_json::from_value(serde_json::json!({"inherited":{"auth":"jwt-bearer"},"override":{"auth":"jwt-bearer"}})).unwrap()))
        }
        fn legacy_jwt_credential_file(
            &self,
            reference: &SecretRef,
        ) -> Result<Option<SecretRef>, String> {
            let source = sources();
            if reference == &source.get("lookup").unwrap().reference("PATH_SOURCE") {
                Ok(Some(
                    source
                        .get("artifact")
                        .unwrap()
                        .reference("/original/workdir/ key.json "),
                ))
            } else if reference == &source.get("lookup").unwrap().reference("INLINE_JSON") {
                Ok(None)
            } else {
                Err("PRIVATE_RESOLVER_ERROR".into())
            }
        }
    }

    #[test]
    fn legacy_jwt_migration_uses_deployment_override_and_catalog_auth_without_secret_values() {
        let mut root: Mapping = serde_yaml::from_str(
            r#"
providers:
  inherited: {api_key: {lookup: PATH_SOURCE}}
  explicit: {auth: jwt-bearer, api_key: {lookup: INLINE_JSON}}
  override: {auth: bearer, api_key: {lookup: PATH_SOURCE}}
  failed: {auth: jwt-bearer, api_key: {lookup: UNAVAILABLE}}
"#,
        )
        .unwrap();
        let before = root.clone();
        let (mut changes, mut todos) = (Vec::new(), Vec::new());
        migrate(&mut root, &Host, &mut changes, &mut todos);
        let migrated: SecretRef =
            serde_yaml::from_value(root["providers"]["inherited"]["api_key"].clone()).unwrap();
        assert_eq!(
            migrated,
            sources()
                .get("artifact")
                .unwrap()
                .reference("/original/workdir/ key.json ")
        );
        for name in ["explicit", "override", "failed"] {
            assert_eq!(root["providers"][name], before["providers"][name]);
        }
        assert_eq!(changes.len(), 1);
        assert_eq!(todos.len(), 1);
        let report = format!("{changes:?} {todos:?}");
        assert!(!report.contains("PRIVATE_RESOLVER_ERROR"));
        assert!(!report.contains("key.json"));
    }
    #[test]
    fn legacy_jwt_migration_without_sources_preserves_config_and_reports_work() {
        let mut root: Mapping = serde_yaml::from_str(
            r#"
providers:
  inherited: {api_key: {lookup: PRIVATE_REFERENCE}}
  explicit: {auth: jwt-bearer, api_key: {lookup: PRIVATE_REFERENCE}}
  other: {auth: bearer, api_key: {lookup: PRIVATE_REFERENCE}}
"#,
        )
        .unwrap();
        let before = root.clone();
        let (mut changes, mut todos) = (Vec::new(), Vec::new());
        migrate(
            &mut root,
            &super::super::migrate_plugins::NoPlugins,
            &mut changes,
            &mut todos,
        );
        assert_eq!(root, before);
        assert!(changes.is_empty());
        assert_eq!(todos.len(), 2);
        assert!(todos.iter().all(|line| !line.contains("PRIVATE_REFERENCE")));
    }
}
