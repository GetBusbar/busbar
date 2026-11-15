// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The serve gate for the overlay a 1.5.5 deployment selected: serving never reads a file overlay, so a
//! file that still holds settings is refused or warned about, never dropped silently.
use busbar_contract::yaml::ValueExt;
use busbar_kernel::config;
use busbar_kernel::persistence::facade::CoreStore;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_BYTES: u64 = 64 * 1024 * 1024;

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
         reads file overlays, so starting would silently drop them. The upgrade boot folds a 1.5.5 overlay into config.yaml, and this config.yaml is \
         already migrated: re-apply the settings through the admin API, or move the file away to \
         abandon them deliberately."
    )
}

fn text_e(subject: &str) -> String {
    format!(
        "{subject} holds admin-API settings that this Store has not imported; 1.6 serving never \
         reads file overlays, so starting would silently drop them. This Store is ephemeral: \
         re-apply the settings through the admin API on a durable Store, or move the file away to \
         abandon them deliberately."
    )
}

fn text_h(subject: &str) -> String {
    format!(
        "{subject} holds admin-API settings that this Store has not imported, and this Store \
         already holds a 1.6 config overlay, so this file cannot be folded into it. 1.6 serving never reads file overlays, so \
         starting would silently drop them. Reconcile by hand: move the file away (keep a copy), \
         start, and re-apply through the admin API the settings from the copy that you still \
         want; or move it away to abandon them deliberately."
    )
}

const TEXT_S: &str = " Admin-API config changes made in this safe-mode session create a Store \
     overlay; re-apply this file's settings through the admin API.";

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
                 its settings. Make it a readable regular file and re-apply its settings through the \
                 admin API, or move the file away to abandon it deliberately.{env_note}"
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
