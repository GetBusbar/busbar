// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 overlay (MIGRATE-ON-BOOT §A3 1b, 1c and 5c): the file a running 1.5.5 kept its
//! admin-API changes in, folded into config.yaml once, on the upgrade boot.
//!
//! - **1b select** ([`select`], [`read`]): the path exactly as v1.5.5's `resolve_backend` chose it
//!   at boot (`config.locked: true` → none; `config.overlay: false | true | {file: null}` on a
//!   mutable config → refused, as 1.5.5 refused to boot it; else `config.overlay.file`, else
//!   `BUSBAR_CONFIG_OVERLAY`, else `busbar-overlay.json` beside config.yaml), then 1.5.5's
//!   writability rule, both arms (an existing file opens for write; a missing one needs 1.5.5's
//!   own create-and-remove probe in its directory). Not writable means 1.5.5 never read it: no
//!   fold, no guard. Before that rule, the states an interrupted 5c leaves are read back
//!   (recovery): F = `<o>.busbar-folding`, B = `<o>.1.5.5`, P = the poison directory at `<o>`.
//! - **1c fold** ([`fold`]): every `OverlayDoc` field in 1.5.5's own order and meaning, written
//!   into config.yaml through the patch writer. The hooks are `overlay_hooks`'s, the one
//!   overlay-shape pass.
//! - **5c guard** ([`guard`]): P is built off to the side as T and renamed over `<o>`, so P appears
//!   whole in one step; a 1.5.5 write lands before the move to F (caught by the inode check),
//!   between it and the rename (the rename fails), or after it, where it fails (`<o>` is a
//!   directory). No interleaving loses a write.
//!
//! Only an unstamped boot comes here; a stamped boot reads config.yaml's one field and nothing of
//! this module (257c).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::files::sibling;
use crate::{overlay_hooks, patch, Interpolate, OsEnv, Refusal, BACKUP_SUFFIX};

/// The variable 1.5.5 read when `config.overlay` was unset.
pub const ENV: &str = "BUSBAR_CONFIG_OVERLAY";
/// The file beside config.yaml 1.5.5 used when nothing else selected one (the kernel's former
/// constant, moved here: no other production source names it).
pub const DEFAULT_OVERLAY_FILENAME: &str = "busbar-overlay.json";
/// The most overlay bytes the upgrade reads.
pub const MAX_OVERLAY_BYTES: u64 = 64 * 1024 * 1024;
/// F: where 5c holds the 1.5.5 overlay between moving it off `<o>` and keeping it as B.
pub const FOLDING_SUFFIX: &str = ".busbar-folding";
/// The marker file inside P.
pub const MARKER: &str = "busbar-1.6-folded";
const MARKER_TEXT: &str = "folded into config.yaml by busbar 1.6.0; see docs/migration-1.6\n";
/// T, P under construction: `<o>.busbar-p.<pid>.<nonce>`.
const BUILDING: &str = ".busbar-p.";
/// v1.5.5's writability probe name (`overlay.rs` `PROBE_FILE_PREFIX`).
const PROBE_PREFIX: &str = ".busbar-overlay-probe-";
/// The report line of a locked config.
pub(crate) const LOCKED_LINE: &str =
    "overlay: none (`config.locked: true`: 1.5.5 read no overlay file)";

/// v1.5.5's refusal of `config.overlay: true` (`resolve_backend`).
const TRUE_TEXT: &str = "config.overlay: `true` names no backend — use `{ file: <path> }`, or \
     `false` together with `config.locked: true` to run immutable.";
/// v1.5.5's refusal of a mutable config with no overlay backend (`resolve_backend`).
const NO_BACKEND_TEXT: &str = "config is mutable (config.locked: false) but has no writable \
     overlay backend — `config.overlay` is disabled, so an admin-API config change could not be \
     stored and would silently revert on restart. Give it a backend (`config.overlay.file: \
     <path>`), or set `config.locked: true` for an immutable deployment.";

/// The overlay's own top-level fields this module folds (the hook fields are `overlay_hooks`'s).
const FIELDS: [&str; 6] = [
    "version",
    "groups",
    "deleted_groups",
    "root",
    "plugin_versions",
    "named_maps",
];
/// `root` sections 1.5.5 replaced whole (`RootSettings::apply_to_deploy`).
const ROOT_WHOLE: [&str; 8] = [
    "listen",
    "tls",
    "admin_listen",
    "admin_tls",
    "admin_require_mtls",
    "rate_card",
    "per_request_fee",
    "store",
];
/// `root` sections 1.5.5 patched field by field (`config/patch.rs` `section_patch!`), with the
/// fields each patch knew (`deny_unknown_fields`).
const ROOT_PATCHED: [(&str, &[&str]); 5] = [
    (
        "security",
        &[
            "blocked_metadata_hosts",
            "allow_metadata_hosts",
            "allow_all_metadata",
        ],
    ),
    (
        "limits",
        &[
            "upstream_request_timeout_secs",
            "request_body_max_bytes",
            "pool_max_idle_per_host",
            "pool_idle_timeout_secs",
            "max_inbound_concurrent",
            "max_keys_per_principal",
            "max_auto_provisioned_groups",
            "hard_down_cooldown_secs",
            "upstream_error_body_max_bytes",
            "tls_handshake_timeout_secs",
            "request_body_read_timeout_secs",
            "max_honored_retry_after_secs",
            "default_max_tokens",
            "reasoning_effort_budgets",
        ],
    ),
    (
        "advanced",
        &[
            "rate_sweep_interval",
            "usage_flush_interval_ms",
            "response_headers",
        ],
    ),
    (
        "health",
        &["default_probe_interval_secs", "default_probe_timeout_secs"],
    ),
    ("routing", &["default_policy_timeout_ms"]),
];
/// The `named_maps` sections 1.5.5 read (`NamedMapSection::ALL`); any other key it never read.
const NAMED_SECTIONS: [&str; 2] = ["identity-providers", "export"];

/// How 1.5.5 chose the overlay path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedBy {
    /// `config.overlay.file`, relative to config.yaml's directory.
    File,
    /// `BUSBAR_CONFIG_OVERLAY`, honoured only while `config.overlay` is unset.
    Env,
    /// `busbar-overlay.json` beside config.yaml.
    Default,
}

impl SelectedBy {
    fn describe(self) -> &'static str {
        match self {
            Self::File => "`config.overlay.file`",
            Self::Env => ENV,
            Self::Default => "default",
        }
    }
}

/// The path a 1.5.5 with this config read and wrote its overlay at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// Absolute.
    pub path: PathBuf,
    /// How it was chosen.
    pub by: SelectedBy,
}

/// The identity of the file 1b read at `<o>`, checked again after 5c moves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl FileId {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

/// Where the bytes to fold were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    /// The 1.5.5 file at `<o>`, as 1b found it.
    Overlay(FileId),
    /// F, left by an interrupted 5c.
    Folding,
    /// B behind P, left by an interrupted 5c.
    Backup,
}

/// What 1b found at the selected path.
#[derive(Debug)]
enum State {
    /// Not writable as 1.5.5 judged it: 1.5.5 never read it. No fold, no backup, no guard.
    NotWritable,
    /// Writable and nothing to fold: absent, or P without F or B (`poisoned`: an earlier upgrade
    /// boot folded it). 5c guards it.
    Absent { poisoned: bool },
    /// The overlay to fold.
    Fold { bytes: Vec<u8>, at: At },
}

/// 1b's reading of the selected overlay.
#[derive(Debug)]
pub(crate) struct Read {
    selected: Selected,
    state: State,
    /// The parsed overlay (only for [`State::Fold`]).
    doc: Option<json::Value>,
    /// WARN lines besides the report (a probe 1.5.5 could not remove).
    notes: Vec<String>,
}

impl Read {
    /// The folded overlay bytes, `None` when nothing is folded.
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        match &self.state {
            State::Fold { bytes, .. } => Some(bytes),
            _ => None,
        }
    }

    /// 1b's one report line.
    pub(crate) fn line(&self) -> String {
        let found = match &self.state {
            State::NotWritable => "not writable, not folded",
            State::Absent { poisoned: false } => "absent",
            State::Absent { poisoned: true } => {
                "absent (an earlier upgrade boot folded it: nothing to fold)"
            }
            State::Fold { .. } => "folded",
        };
        format!(
            "overlay: `{}` (selected by {}): {found}",
            self.selected.path.display(),
            self.selected.by.describe()
        )
    }

    /// The WARN lines: 1b's line unless the overlay is folded, each dropped plugin pin, and a
    /// probe that could not be removed.
    pub(crate) fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.bytes().is_none() {
            out.push(self.line());
        }
        out.extend(self.notes.iter().cloned());
        let pins = self
            .doc
            .as_ref()
            .and_then(|doc| doc.as_object())
            .and_then(|doc| doc.get(&"plugin_versions"))
            .and_then(|pins| pins.as_object());
        if let Some(pins) = pins {
            for (name, version) in ordered(pins) {
                if let Some(version) = version.as_str() {
                    out.push(pin_line(&self.selected.path, name, version));
                }
            }
        }
        out
    }
}

fn pin_line(o: &Path, name: &str, version: &str) -> String {
    format!(
        "overlay `{}`: the rollback pin `plugin_versions.{name}: {version}` is dropped: it names \
         a 1.5.x artifact version 1.6.0 cannot load, and what it lowered (the plugin's version \
         floor) is not config.yaml input",
        o.display()
    )
}

fn config_refusal(text: &str) -> Refusal {
    Refusal::Config(format!(
        "{text} (1.5.5 refused to boot this config too; fix config.yaml, then boot again; \
         nothing was written)"
    ))
}

fn io_refusal(path: &Path, what: &str, error: &std::io::Error) -> Refusal {
    Refusal::Config(format!(
        "{what} {}: {error}; config.yaml was not stamped",
        path.display()
    ))
}

/// The refusal of an overlay 1.5.5 itself could not read.
pub(crate) fn unparseable(o: &str, why: &str) -> Refusal {
    Refusal::Config(format!(
        "the 1.5.5 overlay {o} does not read as 1.5.5 read it ({why}); 1.5.5 then booted on \
         config.yaml alone, but the upgrade replaces that file, so it is never dropped silently: \
         fix it, or move it aside to drop it, then boot again; nothing was written"
    ))
}

/// A string from the overlay as a YAML scalar: refused when it holds `${` (1.5.5 stored overlay
/// values literally; folded into config.yaml it would become an environment reference).
pub(crate) fn text(value: &str, path: &str, o: &str) -> Result<Value, Refusal> {
    if value.contains("${") {
        return Err(Refusal::Config(format!(
            "the 1.5.5 overlay {o} holds `${{` at `{path}`: 1.5.5 stored overlay values \
             literally and never interpolated them, and folded into config.yaml it would become \
             an environment reference; change it through 1.5.5's admin API or move the overlay \
             aside, then boot again; nothing was written"
        )));
    }
    Ok(Value::Text(value.to_owned()))
}

/// An overlay value as config.yaml's tree (every string through [`text`]).
pub(crate) fn to_yaml(value: &json::Value, path: &str, o: &str) -> Result<Value, Refusal> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    if let Some(flag) = value.as_bool() {
        return Ok(Value::Bool(flag));
    }
    if let Some(number) = value.as_u64() {
        return Ok(Value::from(number));
    }
    if let Some(number) = value.as_i64() {
        return Ok(Value::from(number));
    }
    if let Some(number) = value.as_f64() {
        return Ok(Value::Float(number));
    }
    if let Some(string) = value.as_str() {
        return text(string, path, o);
    }
    if let Some(items) = value.as_array() {
        let mut out = Vec::new();
        for (index, item) in items.into_iter().enumerate() {
            out.push(to_yaml(item, &format!("{path}[{index}]"), o)?);
        }
        return Ok(Value::Array(out));
    }
    if let Some(members) = value.as_object() {
        let mut out: Pairs = Vec::new();
        for (key, member) in ordered(members) {
            let path = format!("{path}.{key}");
            out.push((text(key, &path, o)?, to_yaml(member, &path, o)?));
        }
        return Ok(Value::Map(out));
    }
    Err(unparseable(o, &format!("`{path}` is not a JSON value")))
}

/// Whether a tree holds a `${` token anywhere.
fn holds_template(value: &Value) -> bool {
    match value {
        Value::Text(text) => text.contains("${"),
        Value::Array(items) => items.iter().any(holds_template),
        Value::Map(pairs) => pairs
            .iter()
            .any(|(key, item)| holds_template(key) || holds_template(item)),
        Value::Tag(_, inner) => holds_template(inner),
        _ => false,
    }
}

/// 1b, the path: v1.5.5's `resolve_backend` over config.yaml's `config:` block (its resolved
/// value: 1.5.5 interpolated config.yaml first, so a `${VAR}` there is read through `interpolate`)
/// and `BUSBAR_CONFIG_OVERLAY`. `None` for a locked config.
///
/// # Errors
/// CONFIG with 1.5.5's own text for a mutable config whose `config.overlay` is `false`, `true`
/// or `{file: null}`, or whose `config:` block 1.5.5 could not read; CONFIG with the
/// interpolation's text when a `${VAR}` there does not resolve.
pub(crate) fn select(
    config: &Path,
    source: &str,
    env: OsEnv<'_>,
    interpolate: Interpolate<'_>,
) -> Result<Option<Selected>, Refusal> {
    let tree = patch::document(source)?;
    let mut management = tree.get("config").cloned().unwrap_or(Value::Null);
    if holds_template(&management) {
        let resolved = busbar_contract::secure::SecureString::from(
            interpolate(source).map_err(Refusal::Config)?,
        );
        let tree = patch::document(resolved.as_str())?;
        management = tree.get("config").cloned().unwrap_or(Value::Null);
    }
    let management: Pairs = match management {
        Value::Null => Vec::new(),
        Value::Map(pairs) => pairs,
        _ => return Err(config_refusal("`config` is not a mapping")),
    };
    match management.get_key("locked") {
        None | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => return Ok(None),
        Some(_) => return Err(config_refusal("`config.locked` is not `true` or `false`")),
    }
    let dir = match config.parent() {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    let (path, by) = match management.get_key("overlay") {
        None | Some(Value::Null) => {
            let from_env = env(ENV)
                .and_then(|value| value.into_string().ok())
                .filter(|value| !value.is_empty());
            match from_env {
                Some(value) => (PathBuf::from(value), SelectedBy::Env),
                None => (dir.join(DEFAULT_OVERLAY_FILENAME), SelectedBy::Default),
            }
        }
        Some(Value::Bool(false)) => return Err(config_refusal(NO_BACKEND_TEXT)),
        Some(Value::Bool(true)) => return Err(config_refusal(TRUE_TEXT)),
        Some(Value::Map(backend)) => {
            if backend.iter().any(|(key, _)| key.as_str() != Some("file")) {
                return Err(config_refusal(
                    "`config.overlay` holds a key other than `file`",
                ));
            }
            match backend.get_key("file") {
                Some(Value::Text(file)) => {
                    let file = Path::new(file);
                    let path = if file.is_absolute() {
                        file.to_path_buf()
                    } else {
                        dir.join(file)
                    };
                    (path, SelectedBy::File)
                }
                None | Some(Value::Null) => return Err(config_refusal(NO_BACKEND_TEXT)),
                Some(_) => return Err(config_refusal("`config.overlay.file` is not a path")),
            }
        }
        Some(_) => {
            return Err(config_refusal(
                "`config.overlay` is neither `false` nor `{ file: <path> }`",
            ))
        }
    };
    let path = std::path::absolute(&path)
        .map_err(|error| io_refusal(&path, "cannot resolve the overlay path", &error))?;
    Ok(Some(Selected { path, by }))
}

/// What sits at a path, as 1b reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `stat` fails (1.5.5's `Path::exists` is false for any error).
    Absent,
    /// P: a directory holding the marker.
    Poison,
    /// A directory without the marker: not ours, and not writable to 1.5.5.
    Dir,
    /// Anything else.
    File,
}

fn kind(path: &Path) -> Kind {
    match fs::metadata(path) {
        Err(_) => Kind::Absent,
        Ok(meta) if meta.is_dir() => {
            if path.join(MARKER).is_file() {
                Kind::Poison
            } else {
                Kind::Dir
            }
        }
        Ok(_) => Kind::File,
    }
}

/// 1b, the file: the recovery states first (an interrupted 5c), then 1.5.5's writability rule,
/// then the overlay's bytes, parsed. Nothing is written (1.5.5's probe is removed at once).
///
/// # Errors
/// LIVE_WRITER when F exists beside a file at `<o>` (a 1.5.5 wrote it during an upgrade); CONFIG
/// when an overlay is pending and `--ignore-overlay` is set, or it is too large, unreadable or not
/// JSON; NEWER when its `version` is above 1.
pub(crate) fn read(selected: &Selected, ignore_overlay: bool) -> Result<Read, Refusal> {
    let o = selected.path.as_path();
    let folding = sibling(o, FOLDING_SUFFIX);
    let backup = sibling(o, BACKUP_SUFFIX);
    let here = kind(o);
    let mut notes = Vec::new();
    let state = if folding.is_file() {
        if !matches!(here, Kind::Absent | Kind::Poison) {
            return Err(Refusal::LiveWriter(format!(
                "a 1.5.5 wrote {o} while the upgrade held the previous overlay at {f}; stop every \
                 1.5.5 instance, then either move {o} aside and move {f} back to {o}, re-applying \
                 the change that is in the moved-aside file after the upgrade, or keep {o} and \
                 delete {f}; nothing was written",
                o = o.display(),
                f = folding.display()
            )));
        }
        let (bytes, _) = read_bounded(&folding)?;
        State::Fold {
            bytes,
            at: At::Folding,
        }
    } else if here == Kind::Poison {
        if backup.is_file() {
            let (bytes, _) = read_bounded(&backup)?;
            State::Fold {
                bytes,
                at: At::Backup,
            }
        } else {
            State::Absent { poisoned: true }
        }
    } else if !writable(o, here, &mut notes) {
        State::NotWritable
    } else if here == Kind::Absent {
        State::Absent { poisoned: false }
    } else {
        let (bytes, id) = read_bounded(o)?;
        State::Fold {
            bytes,
            at: At::Overlay(id),
        }
    };
    let doc = match &state {
        State::Fold { bytes, .. } => {
            if ignore_overlay {
                return Err(Refusal::Config(format!(
                    "a 1.5.5 overlay is pending its fold into config.yaml ({}); boot once \
                     without --ignore-overlay, or move the file aside to drop it; nothing was \
                     written",
                    o.display()
                )));
            }
            Some(parse(bytes, selected)?)
        }
        _ => None,
    };
    Ok(Read {
        selected: selected.clone(),
        state,
        doc,
        notes,
    })
}

/// v1.5.5's `is_backend_writable`: an existing file opens for write (no create, no truncate,
/// closed at once); a missing one is writable when `<parent>/.busbar-overlay-probe-<pid>-<nonce>`
/// can be created (and is then removed; a failed remove is one WARN line, as in 1.5.5).
fn writable(o: &Path, here: Kind, notes: &mut Vec<String>) -> bool {
    if here != Kind::Absent {
        return OpenOptions::new().write(true).open(o).is_ok();
    }
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let dir = o
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let probe = dir.join(format!(
        "{PROBE_PREFIX}{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    match File::create(&probe) {
        Ok(file) => {
            drop(file);
            if let Err(error) = fs::remove_file(&probe) {
                notes.push(format!(
                    "could not remove the overlay writability probe {} ({error}); it may be \
                     left behind in that directory",
                    probe.display()
                ));
            }
            true
        }
        Err(_) => false,
    }
}

/// Up to [`MAX_OVERLAY_BYTES`] of `path`, with the identity of the file read.
fn read_bounded(path: &Path) -> Result<(Vec<u8>, FileId), Refusal> {
    let file = File::open(path).map_err(|error| io_refusal(path, "cannot read", &error))?;
    let meta = file
        .metadata()
        .map_err(|error| io_refusal(path, "cannot stat", &error))?;
    let mut bytes = Vec::new();
    file.take(MAX_OVERLAY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_refusal(path, "cannot read", &error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_OVERLAY_BYTES {
        return Err(Refusal::Config(format!(
            "the 1.5.5 overlay {} is larger than {MAX_OVERLAY_BYTES} bytes; nothing was written",
            path.display()
        )));
    }
    Ok((bytes, FileId::of(&meta)))
}

/// The overlay as JSON, its top level an object with a `version` 1.5.5 read.
fn parse(bytes: &[u8], selected: &Selected) -> Result<json::Value, Refusal> {
    let o = selected.path.display().to_string();
    let doc = json::parse_typed(bytes).map_err(|error| {
        Refusal::Config(format!(
            "the 1.5.5 overlay {o} is not valid JSON (at byte {}: {error}); 1.5.5 then booted on \
             config.yaml alone, but the upgrade replaces that file, so it is never dropped \
             silently: fix it, or move it aside to drop it, then boot again; nothing was written",
            error.offset()
        ))
    })?;
    let fields = doc
        .as_object()
        .ok_or_else(|| unparseable(&o, "its top level is not a JSON object"))?;
    if let Some(version) = fields.get(&"version") {
        match version.as_u64() {
            Some(found) if found > 1 && found <= u64::from(u32::MAX) => {
                return Err(Refusal::NewerOverlay { path: o, found });
            }
            Some(found) if found <= 1 => {}
            _ => return Err(unparseable(&o, "`version` is not a schema number")),
        }
    }
    Ok(doc)
}

/// A JSON object's members by name. The parsed object does not keep the document's member order
/// (two reads of the same bytes list them differently), and every fold writes in this order, so the
/// planned document and the re-planned one are the same text.
pub(crate) fn ordered(map: &json::Map) -> Vec<(&str, &json::Value)> {
    let mut members: Vec<(&str, &json::Value)> = map.iter().collect();
    members.sort_by(|a, b| a.0.cmp(b.0));
    members
}

/// 1c: fold the overlay 1b read into config.yaml's text, in 1.5.5's order: `root` (each section
/// replaces or patches the base), `plugin_versions` (dropped, reported), `named_maps` (added by
/// name), then `merge_into`: hooks and their global attachment (`overlay_hooks`), groups, and the
/// tombstones last. Any other top-level key 1.5.5 ignored is dropped with one report line.
///
/// # Errors
/// CONFIG for an overlay 1.5.5 could not read, a `${` in a folded string, a named entry that
/// clashes with config.yaml's, a `default: true` hook that ordered pools, or an edit the patch
/// writer cannot place.
pub(crate) fn fold(text: &str, read: &Read, report: &mut Vec<String>) -> Result<String, Refusal> {
    let Some(doc) = read.doc.as_ref().and_then(|doc| doc.as_object()) else {
        return Ok(text.to_owned());
    };
    let o = read.selected.path.display().to_string();
    let before = patch::document(text)?;
    let mut tree = before.clone();
    let Value::Map(pairs) = &mut tree else {
        return Err(Refusal::Config(
            "config.yaml's top level is not a mapping".to_owned(),
        ));
    };
    for (key, _) in ordered(doc) {
        if !FIELDS.contains(&key) && !overlay_hooks::KEYS.contains(&key) {
            report.push(format!(
                "overlay `{o}`: the top-level key `{key}` is dropped (1.5.5 ignored it)"
            ));
        }
    }
    if let Some(root) = doc.get(&"root") {
        fold_root(pairs, root, &o, report)?;
    }
    if let Some(pins) = doc.get(&"plugin_versions") {
        let pins = pins
            .as_object()
            .ok_or_else(|| unparseable(&o, "`plugin_versions` is not an object"))?;
        for (name, version) in ordered(pins) {
            let version = version.as_str().ok_or_else(|| {
                unparseable(&o, &format!("`plugin_versions.{name}` is not a string"))
            })?;
            report.push(pin_line(&read.selected.path, name, version));
        }
    }
    if let Some(maps) = doc.get(&"named_maps") {
        fold_named(pairs, maps, &o, report)?;
    }
    overlay_hooks::fold(pairs, doc, &o, report)?;
    fold_groups(pairs, doc, &o, report)?;
    patch::rewrite(text, &before, &tree, "config.yaml")
}

/// The `root` overrides, applied as `RootSettings::apply_to_deploy` applied them: a present
/// (non-null) whole section replaces config.yaml's; a patched section sets each present field.
fn fold_root(
    pairs: &mut Pairs,
    root: &json::Value,
    o: &str,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    if root.is_null() {
        return Ok(());
    }
    let root = root
        .as_object()
        .ok_or_else(|| unparseable(o, "`root` is not an object"))?;
    for (key, value) in ordered(root) {
        if value.is_null() {
            continue;
        }
        if ROOT_WHOLE.contains(&key) {
            let value = to_yaml(value, &format!("root.{key}"), o)?;
            pairs.insert_key(key, value);
            report.push(format!(
                "overlay `{o}`: `{key}` is the overlay's `root.{key}` (1.5.5 applied it before \
                 opening anything)"
            ));
            continue;
        }
        let Some((_, fields)) = ROOT_PATCHED.iter().find(|(name, _)| *name == key) else {
            return Err(unparseable(
                o,
                &format!("`root.{key}` is not a section 1.5.5 knew"),
            ));
        };
        let patch = value
            .as_object()
            .ok_or_else(|| unparseable(o, &format!("`root.{key}` is not an object")))?;
        let section = pairs.entry_or_insert_with(key, || Value::Map(Vec::new()));
        if !section.is_mapping() {
            *section = Value::Map(Vec::new());
        }
        let Value::Map(section) = section else {
            continue;
        };
        for (field, value) in ordered(patch) {
            if !fields.contains(&field) {
                return Err(unparseable(
                    o,
                    &format!("`root.{key}.{field}` is not a field 1.5.5 knew"),
                ));
            }
            if value.is_null() {
                continue;
            }
            let value = to_yaml(value, &format!("root.{key}.{field}"), o)?;
            section.insert_key(field, value);
            report.push(format!(
                "overlay `{o}`: `{key}.{field}` is the overlay's `root.{key}.{field}`"
            ));
        }
    }
    Ok(())
}

/// `named_maps`: each `identity-providers` and `export` entry added by name, raw (1.5.5's admin
/// API refused base names, so the two are disjoint; a clash refuses).
fn fold_named(
    pairs: &mut Pairs,
    maps: &json::Value,
    o: &str,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    let maps = maps
        .as_object()
        .ok_or_else(|| unparseable(o, "`named_maps` is not an object"))?;
    for (section, entries) in ordered(maps) {
        let entries = entries
            .as_object()
            .ok_or_else(|| unparseable(o, &format!("`named_maps.{section}` is not an object")))?;
        if !NAMED_SECTIONS.contains(&section) {
            report.push(format!(
                "overlay `{o}`: `named_maps.{section}` is dropped (1.5.5 never read that section)"
            ));
            continue;
        }
        let base = pairs.entry_or_insert_with(section, || Value::Map(Vec::new()));
        if base.is_null() {
            *base = Value::Map(Vec::new());
        }
        let Value::Map(base) = base else {
            return Err(Refusal::Config(format!(
                "config.yaml `{section}` is not a mapping; 1.5.5 did not boot it either"
            )));
        };
        for (name, def) in ordered(entries) {
            if base.contains_key(name) {
                return Err(Refusal::Config(format!(
                    "the 1.5.5 overlay {o} and config.yaml both define `{section}.{name}`; 1.5.5's \
                     admin API never wrote over a config.yaml entry, so one of them was edited by \
                     hand: keep one, then boot again; nothing was written"
                )));
            }
            let def = to_yaml(def, &format!("named_maps.{section}.{name}"), o)?;
            base.insert_key(name, def);
            report.push(format!(
                "overlay `{o}`: `{section}.{name}` is added from the overlay"
            ));
        }
    }
    Ok(())
}

/// `groups` by name (the overlay wins), then `deleted_groups`, as `merge_into` applied them.
fn fold_groups(
    pairs: &mut Pairs,
    doc: &json::Map,
    o: &str,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    let groups = doc.get(&"groups");
    let deleted = doc.get(&"deleted_groups");
    if groups.is_none() && deleted.is_none() {
        return Ok(());
    }
    let existed = pairs.contains_key("groups");
    let mut merged: Pairs = match pairs.get_key("groups") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Map(groups)) => groups.clone(),
        Some(_) => {
            return Err(Refusal::Config(
                "config.yaml `groups` is not a mapping; 1.5.5 did not boot it either".to_owned(),
            ))
        }
    };
    if let Some(groups) = groups {
        let groups = groups
            .as_object()
            .ok_or_else(|| unparseable(o, "`groups` is not an object"))?;
        for (name, group) in ordered(groups) {
            let group = to_yaml(group, &format!("groups.{name}"), o)?;
            merged.insert_key(name, group);
            report.push(format!(
                "overlay `{o}`: group `{name}` is written to `groups`"
            ));
        }
    }
    if let Some(deleted) = deleted {
        let deleted = deleted
            .as_array()
            .ok_or_else(|| unparseable(o, "`deleted_groups` is not a list"))?;
        for name in deleted {
            let name = name
                .as_str()
                .ok_or_else(|| unparseable(o, "`deleted_groups` holds a non-string"))?;
            let before = merged.len();
            merged.retain(|(key, _)| key.as_str() != Some(name));
            if merged.len() != before {
                report.push(format!(
                    "overlay `{o}`: group `{name}` is deleted (an admin-API deletion)"
                ));
            }
        }
    }
    if existed || !merged.is_empty() {
        pairs.insert_key("groups", Value::Map(merged));
    }
    Ok(())
}

/// 5R's precondition for the overlay: B is absent or holds exactly the bytes being folded.
///
/// # Errors
/// CONFIG naming B when it holds other bytes; nothing written.
pub(crate) fn backup_absent_or_equal(read: &Read) -> Result<(), Refusal> {
    let Some(bytes) = read.bytes() else {
        return Ok(());
    };
    let backup = sibling(&read.selected.path, BACKUP_SUFFIX);
    match fs::read(&backup) {
        Ok(held) if held == bytes => Ok(()),
        Ok(_) => Err(Refusal::Config(format!(
            "{} exists and differs from the 1.5.5 overlay being folded (a rollback whose overlay \
             was edited since?); move one of them aside, then boot again; nothing was written",
            backup.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_refusal(&backup, "cannot read", &error)),
    }
}

/// 5L's sweep for the overlay, under the directory lock: a dead holder's `<o>.busbar-p.*`.
pub(crate) fn sweep(selected: &Selected) {
    let o = selected.path.as_path();
    let (Some(dir), Some(name)) = (o.parent(), o.file_name()) else {
        return;
    };
    let prefix = format!("{}{BUILDING}", name.to_string_lossy());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// 5c, the overlay guard, whenever 1b selected a writable path (present or absent): P built as T
/// and renamed over `<o>`; the 1.5.5 file kept as B (by way of F). Every crash point reads back
/// through [`read`] to a fold of the same bytes or "nothing to fold".
///
/// # Errors
/// LIVE_WRITER when a 1.5.5 wrote `<o>` during the guard (nothing it wrote is lost); CONFIG for an
/// I/O failure. config.yaml is not stamped either way.
pub(crate) fn guard(read: &Read) -> Result<(), Refusal> {
    if matches!(read.state, State::NotWritable) {
        return Ok(());
    }
    let o = read.selected.path.as_path();
    let folding = sibling(o, FOLDING_SUFFIX);
    let backup = sibling(o, BACKUP_SUFFIX);
    if kind(o) == Kind::Poison {
        // A re-run after a crash: P is in place.
        return settle(o, &folding, &backup);
    }
    let building = build(o)?;
    crash(1)?;
    if let State::Fold {
        at: At::Overlay(id),
        ..
    } = &read.state
    {
        before_move();
        if let Err(error) = fs::rename(o, &folding) {
            let _ = fs::remove_dir_all(&building);
            return Err(if error.kind() == ErrorKind::NotFound {
                guard_live(o)
            } else {
                io_refusal(o, "cannot move the 1.5.5 overlay", &error)
            });
        }
        crash(2)?;
        let moved = fs::metadata(&folding).ok().map(|meta| FileId::of(&meta));
        if moved != Some(*id) {
            // A 1.5.5 rewrote `<o>` between the re-run's read and the move: put its file back.
            // If a 1.5.5 wrote `<o>` once more since, both are kept and the next boot refuses.
            if fs::hard_link(&folding, o).is_ok() {
                let _ = fs::remove_file(&folding);
            }
            let _ = fs::remove_dir_all(&building);
            return Err(guard_live(o));
        }
    }
    place(&building, o)?;
    crash(3)?;
    sync_parent(o)?;
    settle(o, &folding, &backup)
}

fn guard_live(o: &Path) -> Refusal {
    Refusal::LiveWriter(format!(
        "the 1.5.5 overlay {} was written while the upgrade folded it: a 1.5.5 instance is \
         still running. Stop every 1.5.5 instance and boot again; what it wrote is kept, and \
         config.yaml was not stamped",
        o.display()
    ))
}

/// T: `<o>.busbar-p.<pid>.<nonce>` holding the marker, fsynced.
fn build(o: &Path) -> Result<PathBuf, Refusal> {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let building = sibling(
        o,
        &format!(
            "{BUILDING}{}.{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ),
    );
    fs::create_dir(&building).map_err(|error| io_refusal(&building, "cannot create", &error))?;
    let made = (|| -> std::io::Result<()> {
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(building.join(MARKER))?;
        marker.write_all(MARKER_TEXT.as_bytes())?;
        marker.sync_all()?;
        File::open(&building)?.sync_all()
    })();
    if let Err(error) = made {
        let _ = fs::remove_dir_all(&building);
        return Err(io_refusal(&building, "cannot write", &error));
    }
    Ok(building)
}

/// `rename(T, <o>)`: P appears whole. A file or directory that appeared at `<o>` is a 1.5.5's.
fn place(building: &Path, o: &Path) -> Result<(), Refusal> {
    let Err(error) = fs::rename(building, o) else {
        return Ok(());
    };
    let _ = fs::remove_dir_all(building);
    Err(match error.kind() {
        ErrorKind::NotADirectory
        | ErrorKind::IsADirectory
        | ErrorKind::AlreadyExists
        | ErrorKind::DirectoryNotEmpty => guard_live(o),
        _ => io_refusal(o, "cannot put the folded marker at", &error),
    })
}

/// F becomes B (a link: the same bytes), then F goes.
fn settle(o: &Path, folding: &Path, backup: &Path) -> Result<(), Refusal> {
    if !folding.is_file() {
        return Ok(());
    }
    match fs::hard_link(folding, backup) {
        Ok(()) => {}
        // 5R checked an existing B holds the same bytes.
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_refusal(backup, "cannot keep the overlay as", &error)),
    }
    crash(4)?;
    sync_parent(o)?;
    fs::remove_file(folding).map_err(|error| io_refusal(folding, "cannot remove", &error))?;
    crash(5)?;
    sync_parent(o)
}

fn sync_parent(o: &Path) -> Result<(), Refusal> {
    let dir = o.parent().unwrap_or(Path::new("/"));
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_refusal(dir, "cannot fsync", &error))
}

#[cfg(test)]
thread_local! {
    /// A test kill point inside 5c (1: T built, 2: `<o>` moved to F, 3: P renamed into place,
    /// 4: F linked as B, 5: F removed); 0 = none. The guard stops there with nothing cleaned up.
    pub(crate) static CRASH_AT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// A test writer run just before 5c moves `<o>` (a 1.5.5's admin write).
    pub(crate) static BEFORE_MOVE: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn crash(point: u8) -> Result<(), Refusal> {
    if CRASH_AT.with(std::cell::Cell::get) == point {
        return Err(Refusal::Config(format!("test kill at 5c point {point}")));
    }
    Ok(())
}

#[cfg(not(test))]
fn crash(_point: u8) -> Result<(), Refusal> {
    Ok(())
}

#[cfg(test)]
fn before_move() {
    BEFORE_MOVE.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn before_move() {}

#[cfg(test)]
#[path = "tests/overlay_tests.rs"]
mod tests;
