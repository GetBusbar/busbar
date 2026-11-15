// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Offline import of the overlay selected by an actual 1.5.5 deployment.
use busbar_contract::yaml::{MappingExt, ValueExt};
use busbar_kernel::config;
use busbar_kernel::persistence::facade::CoreStore;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) const FLAG: &str = "--migrate-overlay";
const MAX_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn command(args: impl Iterator<Item = String>) -> Result<Option<PathBuf>, &'static str> {
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
            return Err(
                "overlay migration accepts only --config and --providers alongside --migrate-overlay",
            );
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

fn bounded_bytes(path: &Path) -> Result<busbar_contract::secure::SecureVec, String> {
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
    let mut bytes = busbar_contract::secure::SecureVec::new();
    let mut input = file.take(MAX_BYTES + 1);
    loop {
        let read = bytes
            .read_into(64 * 1024, busbar_contract::secure::Tail::Wipe, |region| {
                input.read(region)
            })
            .map_err(|_| "cannot read overlay migration input")?
            .map_err(|_| "cannot read overlay migration input")?;
        if read == 0 {
            break;
        }
    }
    if bytes.len() as u64 > MAX_BYTES {
        return Err("overlay migration input exceeds the size limit".into());
    }
    Ok(bytes)
}

fn old_document(raw: &str) -> Result<busbar_contract::yaml::Value, String> {
    // Missing credentials elsewhere in the old document must not block overlay discovery.
    // Its management selectors still require their actual values, never placeholders.
    let document: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(raw).map_err(|_| "old configuration is not valid YAML")?;
    if let Some(management) = document.get("config") {
        let selector = busbar_contract::secure::SecureString::from(
            busbar_contract::yaml::to_string(management)
                .map_err(|_| "cannot encode old overlay selector")?,
        );
        let _resolved_selector =
            busbar_contract::secure::SecureString::from(config::interpolate_env(&selector)?);
    }
    // Expand the original text, preserving quoted versus unquoted scalar semantics.
    // This document is used only for selection; the migrator receives the original text.
    let expanded = busbar_contract::secure::SecureString::from(config::interpolate_env_with(
        raw,
        config::EnvSubst::Lenient,
        &mut Vec::new(),
    )?);
    busbar_contract::yaml::from_str(&expanded)
        .map_err(|_| "old configuration is not valid YAML".into())
}

/// How 1.5.5 chose the overlay file it read and wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedBy {
    Selector,
    Env,
    Default,
}

impl SelectedBy {
    fn describe(self) -> &'static str {
        match self {
            Self::Selector => "config.overlay.file",
            Self::Env => "BUSBAR_CONFIG_OVERLAY",
            Self::Default => "the default beside config.yaml",
        }
    }
}

/// The overlay a 1.5.5 deployment consumed, by 1.5.5's own precedence (`resolve_backend`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacySelection {
    /// 1.5.5 consumed no overlay: config.locked, or `overlay: false|true`, or a mapping with no file.
    None,
    /// The path 1.5.5 read and wrote, with how it was chosen (for the message).
    File { path: PathBuf, by: SelectedBy },
}

pub(crate) fn legacy_selection(
    config_path: &Path,
    document: &busbar_contract::yaml::Value,
    env: Option<&Path>,
) -> LegacySelection {
    let management = document.at("config");
    if management.at("locked").as_bool() == Some(true) {
        return LegacySelection::None;
    }
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    match management.get("overlay") {
        None | Some(busbar_contract::yaml::Value::Null) => match env {
            Some(path) => LegacySelection::File {
                path: path.to_path_buf(),
                by: SelectedBy::Env,
            },
            None => LegacySelection::File {
                path: parent.join(config::overlay::DEFAULT_OVERLAY_FILENAME),
                by: SelectedBy::Default,
            },
        },
        Some(busbar_contract::yaml::Value::Map(_)) => {
            match management
                .at("overlay")
                .at("file")
                .as_str()
                .filter(|file| !file.is_empty())
            {
                Some(file) => {
                    let path = PathBuf::from(file);
                    LegacySelection::File {
                        path: if path.is_absolute() {
                            path
                        } else {
                            parent.join(path)
                        },
                        by: SelectedBy::Selector,
                    }
                }
                None => LegacySelection::None,
            }
        }
        _ => LegacySelection::None,
    }
}

fn source_path(old_config: &Path, raw: &str, env: Option<&Path>) -> Result<PathBuf, String> {
    // Resolve exactly the historical selector, without opening plugins or serving old config.
    let value = old_document(raw)?;
    match legacy_selection(old_config, &value, env) {
        LegacySelection::File { path, .. } => Ok(path),
        LegacySelection::None => {
            let management = value.at("config");
            Err(if management.at("locked").as_bool() == Some(true) {
                "the old deployment was locked and did not consume an overlay"
            } else if management.at("overlay").is_mapping() {
                "old config.overlay.file is missing or invalid"
            } else {
                "old config.overlay does not select a file backend"
            }
            .into())
        }
    }
}

/// The historical overlay selection of the deployment being served, captured from its authored
/// text while startup custody is open. Nothing is opened until [`admit_legacy`].
pub(crate) struct Legacy {
    selection: LegacySelection,
    /// For a locked deployment: the env or default file 1.5.5 would have ignored.
    locked_leftover: Option<(PathBuf, SelectedBy)>,
    env_set: bool,
}

impl Legacy {
    pub(crate) fn capture(
        config_path: &Path,
        detection: &str,
        env: Option<&Path>,
    ) -> Result<Self, String> {
        let document: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(detection)
            .map_err(|_| "the authored deployment is not valid YAML")?;
        let selection = legacy_selection(config_path, &document, env);
        let locked_leftover =
            (document.at("config").at("locked").as_bool() == Some(true)).then(|| match env {
                Some(path) => (path.to_path_buf(), SelectedBy::Env),
                None => (
                    config_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(config::overlay::DEFAULT_OVERLAY_FILENAME),
                    SelectedBy::Default,
                ),
            });
        Ok(Self {
            selection,
            locked_leftover,
            env_set: env.is_some(),
        })
    }
}

/// What the selected 1.5.5 overlay file holds.
enum FileState {
    Absent,
    Empty,
    Settings,
    Unreadable(String),
}

fn classify(path: &Path) -> FileState {
    match std::fs::symlink_metadata(path) {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return FileState::Absent;
        }
        Err(_) => return FileState::Unreadable("cannot inspect the file".into()),
        Ok(_) => {}
    }
    let bytes = match bounded_bytes(path) {
        Ok(bytes) => bytes,
        Err(error) => return FileState::Unreadable(error),
    };
    let mut overlay = match busbar_migrations::config::overlay_legacy::parse_legacy_overlay(&bytes)
    {
        Ok(overlay) => overlay,
        Err(error) => return FileState::Unreadable(error),
    };
    let holds = overlay.as_object().is_some_and(|root| {
        root.iter().any(|(key, value)| {
            key != "version"
                && !(value.is_null()
                    || value.as_object().is_some_and(|map| map.is_empty())
                    || value.as_array().is_some_and(|list| list.is_empty()))
        })
    });
    zeroize_json(&mut overlay);
    if holds {
        FileState::Settings
    } else {
        FileState::Empty
    }
}

/// The parsed overlay is never retained: its strings are cleared before it is dropped.
fn zeroize_json(value: &mut serde_json::Value) {
    use zeroize::Zeroize;
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(zeroize_json),
        serde_json::Value::Object(map) => map.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

const ENV_NOTE: &str =
    " BUSBAR_CONFIG_OVERLAY is not read by serving and can be removed from the launcher.";

fn subject(path: &Path, by: SelectedBy) -> String {
    format!(
        "the 1.5.5 config overlay {} (selected by {})",
        path.display(),
        by.describe()
    )
}

fn text_a(subject: &str) -> String {
    format!(
        "{subject} holds admin-API settings that this Store has not imported; 1.6 serving never \
         reads file overlays, so starting would silently drop them. Import them once with \
         `busbar --config <config.yaml> --migrate-overlay <old-config.yaml>` before any admin-API \
         config change is made, or move the file away to abandon them deliberately."
    )
}

fn text_e(subject: &str) -> String {
    format!(
        "{subject} holds admin-API settings that this Store has not imported; 1.6 serving never \
         reads file overlays, so starting would silently drop them. This Store is ephemeral and \
         cannot receive the import: configure a durable Store, then run \
         `busbar --config <config.yaml> --migrate-overlay <old-config.yaml>`, or move the file \
         away to abandon the settings deliberately."
    )
}

fn text_h(subject: &str) -> String {
    format!(
        "{subject} holds admin-API settings that this Store has not imported, and this Store \
         already holds a 1.6 config overlay; `--migrate-overlay` only imports into an empty Store \
         overlay, so it cannot import this file. 1.6 serving never reads file overlays, so \
         starting would silently drop them. Reconcile by hand: move the file away (keep a copy), \
         start, and re-apply through the admin API the settings from the copy that you still \
         want; or move it away to abandon them deliberately."
    )
}

const TEXT_S: &str = " Admin-API config changes made in this safe-mode session create a Store \
     overlay, after which `--migrate-overlay` can no longer import this file; import it first.";

fn warn_not_read(text: &str) {
    eprintln!(
        "[warn] {}: {text}",
        busbar_kernel::diagnostics::CONFIG_LEGACY_OVERLAY_NOT_READ.banner()
    );
}

fn warn_not_imported(text: &str) {
    eprintln!(
        "[warn] {}: {text}",
        busbar_kernel::diagnostics::CONFIG_LEGACY_OVERLAY_NOT_IMPORTED.banner()
    );
}

/// A refusal line, `[error] BUSBAR-3027: …`, for the caller to print before exiting 1.
fn refusal(text: &str) -> String {
    format!(
        "[error] {}: {text}",
        busbar_kernel::diagnostics::CONFIG_LEGACY_OVERLAY_NOT_IMPORTED.banner()
    )
}

/// The serve gate: a 1.5.5 overlay that holds settings this Store has not imported refuses the
/// boot with a remedy that can succeed from this state; every lossless legacy input is warned
/// about. Safe mode never refuses (it never applies an overlay). The settings are never echoed.
/// `Err` is the complete refusal line; the caller prints it and exits 1.
pub(crate) async fn admit_legacy(
    legacy: &Legacy,
    core: &Arc<CoreStore>,
    safe_mode: bool,
) -> Result<(), String> {
    let env_note = if legacy.env_set { ENV_NOTE } else { "" };
    let (path, by) = match &legacy.selection {
        LegacySelection::File { path, by } => (path.as_path(), *by),
        LegacySelection::None => {
            if let Some((path, by)) = legacy.locked_leftover.as_ref() {
                if std::fs::symlink_metadata(path).is_ok() {
                    warn_not_read(&format!(
                        "{} is not read: config.locked is true, and 1.5.5 did not consume it \
                         either.{env_note}",
                        subject(path, *by)
                    ));
                    return Ok(());
                }
            }
            if legacy.env_set {
                warn_not_read(&format!(
                    "BUSBAR_CONFIG_OVERLAY is set, but this deployment selects no 1.5.5 file \
                     overlay and 1.6 serving never reads file overlays.{env_note}"
                ));
            }
            return Ok(());
        }
    };
    let subject = subject(path, by);
    match classify(path) {
        FileState::Absent if by == SelectedBy::Default => Ok(()),
        FileState::Absent => {
            warn_not_read(&format!(
                "{subject} is not read: the file does not exist, 1.6 serving never reads file \
                 overlays, and nothing is there to import.{env_note}"
            ));
            Ok(())
        }
        FileState::Empty => {
            warn_not_read(&format!(
                "{subject} is not read: it holds no settings; nothing to import.{env_note}"
            ));
            Ok(())
        }
        FileState::Unreadable(reason) => {
            let text = format!(
                "{subject} exists but cannot be read as a 1.5.5 overlay ({reason}); 1.6 serving \
                 never reads file overlays and cannot prove that starting would not silently drop \
                 its settings. Make it a readable regular file and import it with \
                 `busbar --config <config.yaml> --migrate-overlay <old-config.yaml>`, or move the \
                 file away to abandon it deliberately.{env_note}"
            );
            if safe_mode {
                warn_not_imported(&text);
                Ok(())
            } else {
                Err(refusal(&text))
            }
        }
        FileState::Settings => {
            use config::overlay::LegacyImportState;
            let state = match config::overlay::OverlayStore::from_core(core.clone()) {
                Ok(store) => store.legacy_import_state_async().await,
                Err(error) => Err(error),
            };
            let durable =
                core.info().durability != busbar_contract::persistence::Durability::Ephemeral;
            let text = match state {
                Ok(LegacyImportState::Imported(source)) => {
                    warn_not_read(&format!(
                        "{subject} is not read: imported (receipt source {}); this file is no \
                         longer read and may be removed.{env_note}",
                        hex::encode(source)
                    ));
                    return Ok(());
                }
                Ok(LegacyImportState::Empty) => {
                    let text = if durable {
                        text_a(&subject)
                    } else {
                        text_e(&subject)
                    };
                    if safe_mode {
                        format!("{text}{TEXT_S}")
                    } else {
                        text
                    }
                }
                Ok(LegacyImportState::StoreOverlayPresent) => text_h(&subject),
                Err(error) => {
                    let text = format!(
                        "{subject} holds admin-API settings, and this Store's 1.5.5 import \
                         state cannot be read ({error}); 1.6 serving never reads file overlays \
                         and cannot prove that starting would not silently drop them. Repair the \
                         Store, or move the file away to abandon the settings deliberately."
                    );
                    if safe_mode {
                        warn_not_imported(&format!("{text}{env_note}"));
                        return Ok(());
                    }
                    return Err(refusal(&format!("{text}{env_note}")));
                }
            };
            if safe_mode {
                warn_not_imported(&format!("{text}{env_note}"));
                Ok(())
            } else {
                Err(refusal(&format!("{text}{env_note}")))
            }
        }
    }
}

/// Capture the actual historical Store selection in the newly emitted base YAML. The Store
/// must be known before recovery; the original configuration and overlay remain unchanged.
pub(crate) fn capture_store(raw: &str, old_config: &Path) -> Result<(String, bool), String> {
    let value: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(raw).map_err(|_| "old configuration is not valid YAML")?;
    if old_document(raw)?.at("config").at("locked").as_bool() == Some(true) {
        return Ok((raw.to_owned(), false));
    }
    let env = std::env::var_os("BUSBAR_CONFIG_OVERLAY").map(PathBuf::from);
    let path = source_path(old_config, raw, env.as_deref())?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((raw.to_owned(), false));
        }
        Err(_) => return Err("cannot inspect the old deployment's overlay".into()),
        Ok(_) => {}
    }
    let bytes = bounded_bytes(&path)?;
    let overlay = busbar_migrations::config::overlay_legacy::parse_legacy_overlay(&bytes)?;
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
    root.insert_key(
        busbar_contract::yaml::Value::from("store"),
        busbar_migrations::config::migrate_plugins::yaml_value(store)
            .map_err(|_| "cannot encode the historical Store selection")?,
    );
    let yaml = busbar_contract::yaml::to_string(&value)
        .map_err(|_| "cannot encode the new base Store selection")?;
    Ok((yaml, true))
}

pub(crate) async fn run(
    old_config: &Path,
    current_config: &Path,
    mut deploy: config::DeployCfg,
    defs: &std::collections::HashMap<String, config::ProviderDef>,
    core: &Arc<CoreStore>,
    locked: bool,
) -> Result<(), String> {
    let old_bytes = bounded_bytes(old_config)?;
    let old_text = std::str::from_utf8(&old_bytes).map_err(|_| "old configuration is not UTF-8")?;
    let old_document = old_document(old_text)?;
    if old_document.at("config").at("locked").as_bool() == Some(true) {
        println!(
            "{{\"schema\":\"busbar.overlay-file-migration/1\",\"status\":\"not_required\",\"source_preserved\":true}}"
        );
        return Ok(());
    }
    let env = std::env::var_os("BUSBAR_CONFIG_OVERLAY").map(PathBuf::from);
    let path = source_path(old_config, old_text, env.as_deref())?;
    if std::fs::symlink_metadata(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        println!(
            "{{\"schema\":\"busbar.overlay-file-migration/1\",\"status\":\"not_required\",\"source_preserved\":true}}"
        );
        return Ok(());
    }
    if locked {
        return Err("migrate the overlay into a mutable current configuration before locking the deployment".into());
    }
    if core.info().durability == busbar_contract::persistence::Durability::Ephemeral {
        return Err(
            "overlay migration requires a Store instance that confirms durable persistence".into(),
        );
    }
    let bytes = bounded_bytes(&path)?;
    let current = bounded_bytes(current_config)?;
    let current =
        std::str::from_utf8(&current).map_err(|_| "current configuration is not UTF-8")?;
    let host = super::config_migrate::RootHost::for_document(current, current_config);
    let busbar_migrations::config::migrate_overlay::OverlayMigration { doc, changes, .. } =
        busbar_migrations::config::migrate_overlay::migrate_overlay_with(&bytes, &host)?;
    let changes = serde_json::to_string(&changes)
        .map_err(|_| "cannot encode the overlay migration changes")?;
    // The migrated definitions are read under the grammar the base document was read under.
    let grammar = deploy.grammar.get().map_err(String::from)?.clone();
    for (key, entries) in &doc.named_maps {
        let section = config::named_map::NamedMapSection::sections()
            .into_iter()
            .find(|section| section.key() == key)
            .ok_or("overlay names an unavailable definition section")?;
        for (name, value) in entries {
            section
                .validate_def(name, value, &grammar)
                .map_err(|_| "migrated overlay definition is invalid")?;
        }
    }
    if let Some(store) = doc.root.as_ref().and_then(|root| root.store.as_ref()) {
        let authoring_seal = busbar_kernel::seal::acquire();
        let selected = serde_json::to_value(store.authoring(&authoring_seal))
            .map_err(|_| "cannot compare the migrated Store selection")?;
        let anchored = serde_json::to_value(
            deploy
                .store
                .as_ref()
                .map(|store| store.authoring(&authoring_seal)),
        )
        .map_err(|_| "cannot compare the base Store selection")?;
        if selected != anchored {
            return Err("the old overlay selects a different Store; rerun --migrate-config with the original overlay available so the new base YAML anchors the actual historical Store".into());
        }
    }
    config::overlay::apply_root_to_deploy(&mut deploy, &doc)?;
    let mut effective = config::resolve(&deploy, defs)
        .map_err(|_| "migrated overlay cannot resolve against the current configuration")?;
    config::overlay::merge_into(&mut effective, doc.clone());
    busbar_kernel::config_validate::validate(&effective)
        .map_err(|_| "migrated effective configuration failed validation")?;
    const SOURCE_TAG: &[u8] = b"busbar.overlay.source.1.5.5\0";
    let mut source = busbar_contract::secure::SecureVec::with_capacity(
        SOURCE_TAG.len() + 8 + old_bytes.len() + bytes.len(),
    )
    .map_err(|_| "cannot digest overlay migration source")?;
    source.extend_from_slice(SOURCE_TAG);
    source.extend_from_slice(&(old_bytes.len() as u64).to_be_bytes());
    source.extend_from_slice(&old_bytes);
    source.extend_from_slice(&bytes);
    let mut source_sha256 = [0; 32];
    hex::decode_to_slice(busbar_contract::sha256_hex(&source), &mut source_sha256)
        .map_err(|_| "cannot digest overlay migration source")?;
    let store = config::overlay::OverlayStore::from_core(core.clone())?;
    let applied = store.import_once_async(source_sha256, &doc).await?;
    println!(
        "{{\"schema\":\"busbar.overlay-file-migration/1\",\"status\":\"{}\",\"source_preserved\":true,\"source_sha256\":\"{}\",\"changes\":{changes}}}",
        if applied {
            "applied"
        } else {
            "already_applied"
        },
        hex::encode(source_sha256)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlay_command_refuses_serving_or_principal_flags() {
        assert!(command(
            [FLAG, "old.yaml", "--ignore-overlay"]
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
    fn legacy_selection_is_the_1_5_5_resolve_backend_outcome() {
        let config = Path::new("/deployment/config.yaml");
        let env = Path::new("/elsewhere/env.json");
        let file = |path: &str, by| LegacySelection::File {
            path: PathBuf::from(path),
            by,
        };
        for (yaml, env, expected) in [
            (
                "config: {locked: true, overlay: {file: x.json}}",
                Some(env),
                LegacySelection::None,
            ),
            ("config: {overlay: false}", Some(env), LegacySelection::None),
            ("config: {overlay: true}", None, LegacySelection::None),
            ("config: {overlay: {}}", Some(env), LegacySelection::None),
            (
                "config: {overlay: {file: state.json}}",
                Some(env),
                file("/deployment/state.json", SelectedBy::Selector),
            ),
            (
                "config: {overlay: {file: /abs/state.json}}",
                None,
                file("/abs/state.json", SelectedBy::Selector),
            ),
            (
                "{}",
                Some(env),
                file("/elsewhere/env.json", SelectedBy::Env),
            ),
            (
                "config: {locked: false}",
                None,
                file("/deployment/busbar-overlay.json", SelectedBy::Default),
            ),
        ] {
            let document: busbar_contract::yaml::Value =
                busbar_contract::yaml::from_str(yaml).unwrap();
            assert_eq!(legacy_selection(config, &document, env), expected, "{yaml}");
        }
        let locked = Legacy::capture(config, "config: {locked: true}", None).unwrap();
        assert_eq!(locked.selection, LegacySelection::None);
        assert_eq!(
            locked.locked_leftover,
            Some((
                PathBuf::from("/deployment/busbar-overlay.json"),
                SelectedBy::Default
            ))
        );
    }

    #[test]
    fn a_legacy_overlay_file_is_classified_by_what_it_holds() {
        let mut random = [0; 16];
        busbar_contract::crypto::fill(&mut random).unwrap();
        let directory =
            std::env::temp_dir().join(format!("busbar-legacy-classify-{}", hex::encode(random)));
        std::fs::create_dir(&directory).unwrap();
        let write = |name: &str, body: &str| {
            let path = directory.join(name);
            std::fs::write(&path, body).unwrap();
            path
        };
        assert!(matches!(
            classify(&directory.join("absent.json")),
            FileState::Absent
        ));
        assert!(matches!(
            classify(Path::new("/dev/null/oracle-overlay.json")),
            FileState::Absent
        ));
        assert!(matches!(
            classify(&write(
                "empty.json",
                r#"{"version":1,"hooks":{},"groups":{}}"#
            )),
            FileState::Empty
        ));
        assert!(matches!(
            classify(&write(
                "settings.json",
                r#"{"version":1,"root":{"advanced":{"response_headers":{"server_timing":true}}}}"#
            )),
            FileState::Settings
        ));
        assert!(matches!(
            classify(&write("broken.json", "{")),
            FileState::Unreadable(_)
        ));
        assert!(matches!(
            classify(&write("duplicate.json", r#"{"root":{},"root":{}}"#)),
            FileState::Unreadable(_)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn captured_store_numbers_remain_yaml_scalars() {
        let mut random = [0; 16];
        busbar_contract::crypto::fill(&mut random).unwrap();
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
        let value: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(&yaml).unwrap();
        assert_eq!(value.at("store").at("max_connections").as_u64(), Some(17));
        assert_eq!(value.at("store").at("timeout_secs").as_f64(), Some(1.25));
        assert!(!yaml.contains("$serde_json::private::Number"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn overlay_discovery_does_not_resolve_unrelated_legacy_credentials() {
        let raw = "auth: {client_tokens: ['${BUSBAR_TEST_ABSENT_LEGACY_TOKEN_20261106}']}\n";
        old_document(raw).unwrap();
        old_document(&format!("{raw}config: {{locked: false}}\n")).unwrap();
        assert_eq!(
            source_path(Path::new("/deployment/config.yaml"), raw, None).unwrap(),
            PathBuf::from("/deployment/busbar-overlay.json")
        );
        assert!(
            source_path(
                Path::new("/deployment/config.yaml"),
                "config: {overlay: {file: '${BUSBAR_TEST_ABSENT_OVERLAY_PATH_20261106}'}}",
                None,
            )
            .is_err(),
            "the selected overlay path must still resolve strictly"
        );
    }

    #[test]
    fn expanded_locked_deployment_requires_no_overlay_capture() {
        const KEY: &str = "BUSBAR_TEST_MIGRATE_OVERLAY_LOCKED_20261105";
        std::env::set_var(KEY, "true");
        // An unquoted interpolation scalar uses block YAML: braces in `${...}` are
        // flow-map syntax before expansion, while migration also reads the raw document.
        let raw =
            format!("config:\n  locked: ${{{KEY}}}\n  overlay:\n    file: /missing/overlay.json\n");
        let result = capture_store(&raw, Path::new("/missing/config.yaml"));
        let locked = old_document(&raw)
            .unwrap()
            .at("config")
            .at("locked")
            .as_bool();
        let quoted = old_document(&format!("config: {{locked: '${{{KEY}}}'}}"))
            .unwrap()
            .at("config")
            .at("locked")
            .clone();
        std::env::remove_var(KEY);
        assert_eq!(quoted.as_str(), Some("true"));
        assert_eq!(locked, Some(true));
        assert_eq!(result.unwrap(), (raw, false));
    }
}
