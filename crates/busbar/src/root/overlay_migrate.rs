// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Offline import of the overlay selected by an actual 1.5.5 deployment.
use busbar_contract::store_calls::OpenedStore;
use busbar_kernel::config;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const FLAG: &str = "--migrate-overlay";
const MAX_BYTES: u64 = 64 * 1024 * 1024;

pub fn command(args: impl Iterator<Item = String>) -> Result<Option<PathBuf>, &'static str> {
    let args: Vec<_> = args.collect();
    if !args
        .iter()
        .any(|arg| arg == FLAG || arg.starts_with("--migrate-overlay="))
    {
        return Ok(None);
    }
    let mut input = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let (flag, assigned) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(flag, value)| (flag, Some(value)));
        if !matches!(flag, FLAG | "--config" | "-c" | "--providers") {
            return Err("overlay migration accepts only --config and --providers alongside --migrate-overlay");
        }
        let value = assigned
            .or_else(|| args.next().map(String::as_str))
            .filter(|value| !value.is_empty() && !value.starts_with('-'))
            .ok_or("overlay migration path flags require explicit values")?;
        if flag == FLAG && input.replace(PathBuf::from(value)).is_some() {
            return Err("duplicate --migrate-overlay flag");
        }
    }
    Ok(input)
}

fn bounded_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "cannot inspect overlay migration input")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("overlay migration requires bounded regular input files".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open overlay migration input")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect opened overlay migration input")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("overlay migration input changed or exceeds the size limit".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read overlay migration input")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("overlay migration input exceeds the size limit".into());
    }
    Ok(bytes)
}

fn old_document(raw: &str) -> Result<serde_yaml::Value, String> {
    let expanded = zeroize::Zeroizing::new(config::interpolate_env(raw)?);
    serde_yaml::from_str(&expanded).map_err(|_| "old configuration is not valid YAML".into())
}

fn source_path(old_config: &Path, raw: &str, env: Option<&Path>) -> Result<PathBuf, String> {
    // Resolve exactly the historical selector, without opening plugins or serving old config.
    let value = old_document(raw)?;
    let management = &value["config"];
    if management["locked"].as_bool() == Some(true) {
        return Err("the old deployment was locked and did not consume an overlay".into());
    }
    let parent = old_config.parent().unwrap_or_else(|| Path::new("."));
    match management.get("overlay") {
        None | Some(serde_yaml::Value::Null) => Ok(env
            .map(Path::to_path_buf)
            .unwrap_or_else(|| parent.join(config::overlay::DEFAULT_OVERLAY_FILENAME))),
        Some(serde_yaml::Value::Mapping(_)) => {
            let file = management["overlay"]["file"]
                .as_str()
                .filter(|file| !file.is_empty())
                .ok_or("old config.overlay.file is missing or invalid")?;
            let path = PathBuf::from(file);
            Ok(if path.is_absolute() {
                path
            } else {
                parent.join(path)
            })
        }
        _ => Err("old config.overlay does not select a file backend".into()),
    }
}

/// Capture the actual historical Store selection in the newly emitted base YAML. The Store
/// must be known before recovery; the original configuration and overlay remain unchanged.
pub fn capture_store(raw: &str, old_config: &Path) -> Result<(String, bool), String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|_| "old configuration is not valid YAML")?;
    if old_document(raw)?["config"]["locked"].as_bool() == Some(true) {
        return Ok((raw.to_owned(), false));
    }
    let env = std::env::var_os("BUSBAR_CONFIG_OVERLAY").map(PathBuf::from);
    let path = source_path(old_config, raw, env.as_deref())?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((raw.to_owned(), false))
        }
        Err(_) => return Err("cannot inspect the old deployment's overlay".into()),
        Ok(_) => {}
    }
    let bytes = zeroize::Zeroizing::new(bounded_bytes(&path)?);
    let overlay = config::overlay::parse_legacy_overlay(&bytes)?;
    let Some(store) = overlay
        .get("root")
        .and_then(|root| root.get("store"))
        .filter(|store| !store.is_null())
    else {
        return Ok((raw.to_owned(), false));
    };
    let mut value = value;
    let root = value
        .as_mapping_mut()
        .ok_or("old configuration is not a mapping")?;
    root.insert(
        serde_yaml::Value::from("store"),
        config::migrate_plugins::yaml_value(store)
            .map_err(|_| "cannot encode the historical Store selection")?,
    );
    let yaml =
        serde_yaml::to_string(&value).map_err(|_| "cannot encode the new base Store selection")?;
    Ok((yaml, true))
}

pub fn run(
    old_config: &Path,
    current_config: &Path,
    mut deploy: config::DeployCfg,
    defs: &std::collections::HashMap<String, config::ProviderDef>,
    opened: &OpenedStore,
    locked: bool,
) -> Result<(), String> {
    let old_bytes = zeroize::Zeroizing::new(bounded_bytes(old_config)?);
    let old_text = std::str::from_utf8(&old_bytes).map_err(|_| "old configuration is not UTF-8")?;
    let old_document = old_document(old_text)?;
    if old_document["config"]["locked"].as_bool() == Some(true) {
        println!("{{\"schema\":\"busbar.overlay-file-migration/1\",\"status\":\"not_required\",\"source_preserved\":true}}");
        return Ok(());
    }
    let env = std::env::var_os("BUSBAR_CONFIG_OVERLAY").map(PathBuf::from);
    let path = source_path(old_config, old_text, env.as_deref())?;
    if std::fs::symlink_metadata(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        println!("{{\"schema\":\"busbar.overlay-file-migration/1\",\"status\":\"not_required\",\"source_preserved\":true}}");
        return Ok(());
    }
    if locked {
        return Err("migrate the overlay into a mutable current configuration before locking the deployment".into());
    }
    let calls = opened
        .calls
        .as_ref()
        .ok_or("overlay migration requires typed Store calls")?;
    if calls.ephemeral() != Some(false) {
        return Err(
            "overlay migration requires a Store instance that confirms durable persistence".into(),
        );
    }
    let bytes = zeroize::Zeroizing::new(bounded_bytes(&path)?);
    let current = zeroize::Zeroizing::new(bounded_bytes(current_config)?);
    let current =
        std::str::from_utf8(&current).map_err(|_| "current configuration is not UTF-8")?;
    let host = super::config_migrate::RootHost::for_document(current, current_config);
    let doc = config::migrate_overlay::migrate_overlay_with(&bytes, &host)?;
    for (key, entries) in &doc.named_maps {
        let section = config::named_map::NamedMapSection::sections()
            .into_iter()
            .find(|section| section.key() == key)
            .ok_or("overlay names an unavailable definition section")?;
        for (name, value) in entries {
            section
                .validate_def(name, value)
                .map_err(|_| "migrated overlay definition is invalid")?;
        }
    }
    if let Some(store) = doc.root.as_ref().and_then(|root| root.store.as_ref()) {
        let selected = serde_json::to_value(store)
            .map_err(|_| "cannot compare the migrated Store selection")?;
        let anchored = serde_json::to_value(&deploy.store)
            .map_err(|_| "cannot compare the base Store selection")?;
        if selected != anchored {
            return Err("the old overlay selects a different Store; rerun --migrate-config with the original overlay available so the new base YAML anchors the actual historical Store".into());
        }
    }
    config::overlay::apply_root_to_deploy(&mut deploy, &doc);
    let mut effective = config::resolve(&deploy, defs)
        .map_err(|_| "migrated overlay cannot resolve against the current configuration")?;
    config::overlay::merge_into(&mut effective, doc.clone());
    busbar_kernel::config_validate::validate(&effective)
        .map_err(|_| "migrated effective configuration failed validation")?;
    let mut source = zeroize::Zeroizing::new(Vec::new());
    source.extend_from_slice(b"busbar.overlay.source.1.5.5\0");
    source.extend_from_slice(&(old_bytes.len() as u64).to_be_bytes());
    source.extend_from_slice(&old_bytes);
    source.extend_from_slice(&bytes);
    let mut source_sha256 = [0; 32];
    hex::decode_to_slice(busbar_contract::sha256_hex(&source), &mut source_sha256)
        .map_err(|_| "cannot digest overlay migration source")?;
    let store = config::overlay::OverlayStore::new(calls.clone())?;
    let applied = store.import_once(source_sha256, &doc)?;
    println!("{{\"schema\":\"busbar.overlay-file-migration/1\",\"status\":\"{}\",\"source_preserved\":true,\"source_sha256\":\"{}\"}}", if applied { "applied" } else { "already_applied" }, hex::encode(source_sha256));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlay_command_refuses_serving_or_principal_flags() {
        assert!(command(
            [FLAG, "old.yaml", "--safe-mode"]
                .into_iter()
                .map(str::to_owned)
        )
        .is_err());
        assert!(command(
            [FLAG, "old.yaml", "--principal-transition", "plan.json"]
                .into_iter()
                .map(str::to_owned)
        )
        .is_err());
        assert_eq!(
            command(
                ["--config", "new.yaml", FLAG, "old.yaml"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .unwrap(),
            Some("old.yaml".into())
        );
    }
    #[test]
    fn old_overlay_selector_preserves_file_env_default_precedence() {
        let old = Path::new("/deployment/config.yaml");
        assert_eq!(
            source_path(
                old,
                "config: { overlay: { file: state.json } }",
                Some(Path::new("env.json"))
            )
            .unwrap(),
            PathBuf::from("/deployment/state.json")
        );
        assert_eq!(
            source_path(old, "{}", Some(Path::new("env.json"))).unwrap(),
            PathBuf::from("env.json")
        );
        assert_eq!(
            source_path(old, "{}", None).unwrap(),
            PathBuf::from("/deployment/busbar-overlay.json")
        );
        assert!(source_path(old, "config: { locked: true }", None).is_err());
    }
    #[test]
    fn captured_store_numbers_remain_yaml_scalars() {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory =
            std::env::temp_dir().join(format!("busbar-overlay-test-{}", hex::encode(random)));
        std::fs::create_dir(&directory).unwrap();
        let overlay = directory.join("overlay.json");
        std::fs::write(&overlay, r#"{"version":1,"root":{"store":{"backend":"sqlite","max_connections":17,"timeout_secs":1.25}}}"#).unwrap();
        let raw = format!(
            "config: {{ overlay: {{ file: '{}' }} }}\n",
            overlay.display()
        );
        let (yaml, captured) = capture_store(&raw, &directory.join("config.yaml")).unwrap();
        assert!(captured);
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(value["store"]["max_connections"].as_u64(), Some(17));
        assert_eq!(value["store"]["timeout_secs"].as_f64(), Some(1.25));
        assert!(!yaml.contains("$serde_json::private::Number"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn expanded_locked_deployment_requires_no_overlay_capture() {
        const KEY: &str = "BUSBAR_TEST_MIGRATE_OVERLAY_LOCKED_20261105";
        std::env::set_var(KEY, "true");
        let raw =
            format!("config: {{ locked: ${{{KEY}}}, overlay: {{ file: /missing/overlay.json }} }}");
        let result = capture_store(&raw, Path::new("/missing/config.yaml"));
        let locked = old_document(&raw).unwrap()["config"]["locked"].as_bool();
        std::env::remove_var(KEY);
        assert_eq!(locked, Some(true));
        assert_eq!(result.unwrap(), (raw, false));
    }
}
