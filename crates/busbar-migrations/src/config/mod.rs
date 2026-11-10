// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Historical authored-config normalization, isolated from the current kernel reader.
mod former_names;
mod provenance;
pub mod templates;
pub use provenance::{
    bootstrap_metadata_projection, recognize_authored_schema, HistoricalConfigProof,
    HistoricalShape,
};
pub mod migrate;
pub mod migrate_catalog;
mod migrate_credentials;
pub mod migrate_export;
pub mod migrate_overlay;
pub mod migrate_plugins;
pub mod migration_table;
pub mod overlay_legacy;
mod retired;

/// The actual default used by supported released configurations that omitted Store.
#[must_use]
pub fn migrated_store_module() -> &'static str {
    migration_table::text("store_1_5_default")
}

/// Normalize authored YAML without reading environment variables or writing the source.
/// Secret references remain authored references. This bootstrap path performs only
/// structural conversions; callers must refuse admission while `todos` is nonempty.
pub fn normalize_authored(
    raw: &str,
    host: &dyn migrate_plugins::MigrateHost,
) -> Result<migrate::MigrateOutput, String> {
    normalize_authored_with_detection(raw, None, host)
}

/// The caller may supply the same document after its own environment interpolation
/// solely for current-reader detection. Only `raw` is ever returned or transformed.
pub fn normalize_authored_with_detection(
    raw: &str,
    detection_yaml: Option<&str>,
    host: &dyn migrate_plugins::MigrateHost,
) -> Result<migrate::MigrateOutput, String> {
    normalize(raw, detection_yaml, host, false)
}

/// A recognized historical config grammar is sufficient even for an ephemeral Store.
/// It does not assert a native dataset format or a marketing product version.
pub fn normalize_historical_config(
    proof: &HistoricalConfigProof,
    raw: &str,
    host: &dyn migrate_plugins::MigrateHost,
) -> Result<migrate::MigrateOutput, String> {
    let expected = recognize_authored_schema(raw)?
        .ok_or("historical configuration grammar was not established")?;
    if proof.shape() != HistoricalShape::RootGrammar || expected.binding() != proof.binding() {
        return Err("historical configuration proof belongs to another authored document".into());
    }
    host.admit_config_profile(proof)?;
    normalize(raw, None, host, true)
}

/// Convert the frozen settings semantics admitted by a supported native source profile.
/// The profile identifies a historical schema/codec family, not a product release.
/// Credential binding conversion additionally inspects the authored reference and
/// resolved credential shape; unresolved field decisions remain required debt.
pub fn normalize_supported_source(
    semantics: busbar_contract::persistence::lifecycle::DocumentSemantics,
    raw: &str,
    host: &dyn migrate_plugins::MigrateHost,
) -> Result<migrate::MigrateOutput, String> {
    use busbar_contract::persistence::lifecycle::DocumentSemantics;
    normalize(raw, None, host, semantics == DocumentSemantics::Historical)
}

fn normalize(
    raw: &str,
    detection_yaml: Option<&str>,
    host: &dyn migrate_plugins::MigrateHost,
    source_specific: bool,
) -> Result<migrate::MigrateOutput, String> {
    // Bound authored input before the YAML parser can allocate its representation.
    const MAX_AUTHORED_BYTES: usize = 16 * 1024 * 1024;
    if raw.len() > MAX_AUTHORED_BYTES {
        return Err("configuration exceeds the 16 MiB normalization input budget".into());
    }
    let before: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|_| "configuration is not valid YAML".to_owned())?;
    if !before.is_mapping() {
        return Err("configuration must be a YAML mapping".into());
    }
    check_tree(&before)?;
    let decisions = required_security_decisions(&before);
    let detection = detection_yaml.unwrap_or(raw);
    if detection.len() > MAX_AUTHORED_BYTES {
        return Err("configuration detection document exceeds normalization input budget".into());
    }
    if !source_specific
        && decisions.is_empty()
        && !former_names::needed(&before)
        && before
            .get("store")
            .and_then(|store| store.get("module"))
            .and_then(serde_yaml::Value::as_str)
            .is_some_and(|module| !module.trim().is_empty())
        && migrate::detect_legacy_markers(&before).is_empty()
        && busbar_kernel::config::deploy_from_yaml_str(detection).is_ok()
    {
        return normalize_recognized_settings(raw, host);
    }
    let mut normalized = if source_specific {
        migrate::migrate_config_with(raw, host)?
    } else {
        migrate::migrate_structure(raw, host)?
    };
    let after: serde_yaml::Value = serde_yaml::from_str(&normalized.yaml)
        .map_err(|_| "normalization did not produce valid YAML".to_owned())?;
    check_tree(&after)?;
    if !source_specific {
        let mut settings = normalize_recognized_settings(&normalized.yaml, host)?;
        normalized.yaml = settings.yaml;
        normalized.changes.append(&mut settings.changes);
        normalized.todos.append(&mut settings.todos);
    }
    normalized.todos.extend(decisions);
    for marker in migrate::detect_legacy_markers(&after) {
        if !normalized.todos.contains(&marker) {
            normalized.todos.push(marker);
        }
    }
    // Preserve comments, authored scalar spellings, and read-only source bytes on no-op.
    if before == after && normalized.todos.is_empty() && normalized.warnings.is_empty() {
        normalized.yaml = raw.to_owned();
    }
    if normalized.yaml != raw {
        normalized.yaml = templates::render_authored(&normalized.yaml, host)?;
    }
    Ok(normalized)
}

fn normalize_recognized_settings(
    raw: &str,
    host: &dyn migrate_plugins::MigrateHost,
) -> Result<migrate::MigrateOutput, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|_| "authored settings document is not YAML")?;
    let root = doc
        .as_mapping_mut()
        .ok_or("authored settings document is not a mapping")?;
    let (mut changes, mut todos, mut failures) = (Vec::new(), Vec::new(), Vec::new());
    migrate_plugins::migrate_recognized(
        root,
        host,
        &mut migrate_plugins::Ledger {
            changes: &mut changes,
            todos: &mut todos,
            failures: &mut failures,
        },
    );
    if !failures.is_empty() {
        return Err("registered historical settings conversion refused".into());
    }
    let yaml = if changes.is_empty() {
        raw.to_owned()
    } else {
        serde_yaml::to_string(&doc).map_err(|_| "converted settings could not be encoded")?
    };
    let yaml = if yaml != raw {
        templates::render_authored(&yaml, host)?
    } else {
        yaml
    };
    Ok(migrate::MigrateOutput {
        yaml,
        changes,
        todos,
        warnings: Vec::new(),
    })
}

// These historical warnings describe choices, rather than lossless rewrites.
// Automatic startup must retain them as admission-blocking debt.
fn required_security_decisions(doc: &serde_yaml::Value) -> Vec<String> {
    use serde_yaml::Value;
    let mut todos = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return todos;
    };
    for (section, check) in [("auth", 0u8), ("tools", 1), ("group_map", 2)] {
        let Some(value) = root.get(section) else {
            continue;
        };
        let mut pending = vec![(value, check)];
        while let Some((value, check)) = pending.pop() {
            match value {
                Value::Mapping(entries) => {
                    for (key, value) in entries {
                        let key = key.as_str().unwrap_or("");
                        if check == 0
                            && matches!(key, "admin_scope" | "max_admin_scope")
                            && matches!(value.as_str(), Some("mint" | "hooks-register"))
                        {
                            todos.push("auth: a retired delegated administrative scope cannot be converted to full authority automatically; choose an explicit current scope".into());
                        }
                        if check == 1 && key == "refresh_ttl" {
                            todos.push("tools: refresh_ttl was a background cadence; choose an explicit verify_ttl freshness limit before admission".into());
                        }
                        if check == 2
                            && key == "allowed_pools"
                            && value.as_sequence().is_some_and(Vec::is_empty)
                        {
                            todos.push("group_map: allowed_pools: [] changed meaning from all pools to none; choose an explicit current access grant".into());
                        }
                        pending.push((
                            value,
                            if check == 0 && key == "group_map" {
                                2
                            } else {
                                check
                            },
                        ));
                    }
                }
                Value::Sequence(items) => pending.extend(items.iter().map(|v| (v, check))),
                _ => {}
            }
        }
    }
    todos.sort();
    todos.dedup();
    todos
}

fn check_tree(root: &serde_yaml::Value) -> Result<(), String> {
    use serde_yaml::Value;
    const MAX_NODES: usize = 262_144;
    const MAX_DEPTH: usize = 128;
    let mut pending = vec![(root, 0usize)];
    let mut nodes = 0usize;
    while let Some((node, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err("configuration exceeds normalization structure budget".into());
        }
        match node {
            Value::Sequence(items) => pending.extend(items.iter().map(|v| (v, depth + 1))),
            Value::Mapping(items) => {
                for (key, value) in items {
                    pending.push((key, depth + 1));
                    pending.push((value, depth + 1));
                }
            }
            Value::Tagged(_) => return Err("configuration YAML tags are not supported".into()),
            _ => {}
        }
        if pending.len() > MAX_NODES {
            return Err("configuration exceeds normalization structure budget".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    #[test]
    fn current_authored_references_and_locked_source_are_preserved() {
        let raw = "# owner comment\nconfig: {locked: true}\nstore: {module: custom}\ncredentials: {at_rest: {key: {env: DO_NOT_EXPAND}}}\n";
        let out = normalize_authored(raw, &migrate_plugins::NoPlugins).unwrap();
        assert_eq!(out.yaml, raw);
        assert!(out.todos.is_empty());
    }

    #[test]
    fn unversioned_provider_does_not_guess_released_jwt_semantics() {
        let raw = "store: {module: custom}\nproviders: {p: {api_key: {env: KEEP_AUTHORED}}}\n";
        let out = normalize_authored(raw, &migrate_plugins::NoPlugins).unwrap();
        assert!(out.todos.is_empty(), "{:?}", out.todos);
        assert_eq!(out.yaml, raw);
    }

    #[test]
    fn caller_detection_preserves_authored_numeric_environment_reference() {
        let raw = "store: {module: custom}\nadvanced: {worker_threads: '${WORKERS}'}\n";
        let detection = "store: {module: custom}\nadvanced: {worker_threads: 4}\n";
        let out =
            normalize_authored_with_detection(raw, Some(detection), &migrate_plugins::NoPlugins)
                .unwrap();
        assert_eq!(out.yaml, raw);
        assert!(out.todos.is_empty());
    }

    #[test]
    fn development_profiles_preserve_current_grants_instead_of_released_defaults() {
        let raw = "store: {module: custom}\nidentity-providers: {corp: {module: header}}\nauth: {chain: [corp], role_bindings: {corp: {eng: {allowed_pools: [fast]}}}}\n";
        let dev = normalize_supported_source(
            busbar_contract::persistence::lifecycle::DocumentSemantics::Current,
            raw,
            &migrate_plugins::NoPlugins,
        )
        .unwrap();
        assert_eq!(dev.yaml, raw);
        let released = normalize_supported_source(
            busbar_contract::persistence::lifecycle::DocumentSemantics::Historical,
            raw,
            &migrate_plugins::NoPlugins,
        )
        .unwrap();
        let released: serde_yaml::Value = serde_yaml::from_str(&released.yaml).unwrap();
        assert!(released["auth"]["role_bindings"]["corp"]["*"].is_mapping());
    }

    #[test]
    fn unsupported_yaml_never_exposes_authored_secret_in_errors() {
        let error = normalize_authored("token: [SECRET_UNFINISHED", &migrate_plugins::NoPlugins)
            .err()
            .unwrap();
        assert!(!error.contains("SECRET_UNFINISHED"));
        assert!(normalize_authored("[]", &migrate_plugins::NoPlugins).is_err());
    }

    #[test]
    fn historical_scope_expansion_and_freshness_are_required_decisions() {
        let source = "store: {module: custom}\nauth: {role_bindings: {sso: {eng: {admin_scope: mint}}}}\ntools: {upstream: {refresh_ttl: 6h}}\n";
        let out = normalize_authored(source, &migrate_plugins::NoPlugins).unwrap();
        assert!(out.todos.iter().any(|todo| todo.contains("full authority")));
        assert!(out.todos.iter().any(|todo| todo.contains("freshness")));
    }

    #[test]
    fn security_decisions_remain_required_debt() {
        let raw = "auth: {mode: token}\nstore: {module: custom}\n";
        let structural = normalize_authored(raw, &migrate_plugins::NoPlugins).unwrap();
        assert!(
            structural
                .todos
                .iter()
                .any(|todo| todo.contains("static-token")),
            "{:?}",
            structural.todos
        );
        let proof = recognize_authored_schema(raw).unwrap().unwrap();
        let historical =
            normalize_historical_config(&proof, raw, &migrate_plugins::NoPlugins).unwrap();
        assert!(
            historical
                .todos
                .iter()
                .any(|todo| todo.contains("static-token")),
            "{:?}",
            historical.todos
        );
    }
}
