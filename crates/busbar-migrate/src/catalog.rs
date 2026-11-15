// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1k, the providers catalog (MIGRATE-ON-BOOT §A3 1k, 5a2). The source is exactly 1.5.5's (tag
//! v1.5.5 `main.rs:1587-1596, 1638-1656`): `BUSBAR_PROVIDERS` (non-empty; relative to the working
//! directory) > the document's `providers_file` (its resolved value; relative to config.yaml's
//! directory) > `providers.yaml` beside config.yaml. 1.5.5 refused to boot without it, so a missing
//! or unreadable source refuses with 1.5.5's text. It is read as a template, like config.yaml.
//!
//! The pass removes every entry key 1.5.5's `ProviderDef` ignored and 1.6.0 refuses (the keys the
//! boot's facts list are kept), one report line each. Unchanged, no file is planned and 1.6.0 reads
//! the file 1.5.5 read (a `BUSBAR_PROVIDERS` selection is captured as an absolute `providers_file`,
//! since 1.6.0 no longer reads the variable). Changed, the planned file is
//! `<config dir>/providers.busbar-1.6.yaml`, its bytes the patch writer's over the source, and the
//! document's `providers_file` names it, relative, so the deployment moves as a directory. The 1.5.5
//! catalog stays byte-identical, so `config.yaml.1.5.5` still names a file 1.5.5 reads (rollback).

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::migrate_1_6::remove_kept;
use crate::patch::{rewrite, schema_insert};
use crate::templates::{computed, is_template, Template};
use crate::{files, Facts, Refusal};

/// The planned catalog's file name, beside config.yaml.
pub(crate) const FILE: &str = "providers.busbar-1.6.yaml";
/// The 1.5.5 launch variable that selected the catalog.
const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";
/// The most catalog bytes the upgrade reads.
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;

/// A new catalog, planned in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Planned {
    /// `<config dir>/providers.busbar-1.6.yaml`.
    pub(crate) path: PathBuf,
    /// The catalog 1.5.5 read; the new file takes its mode and owner.
    pub(crate) source: PathBuf,
    /// The new file's bytes (a template, as written).
    pub(crate) text: String,
}

/// Which input selected the catalog.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    Env,
    File,
    Default,
}

/// 1k over the document `root` (R) with its resolved twin.
pub(crate) fn plan(
    config: &Path,
    root: &mut Pairs,
    resolved: &Value,
    facts: &Facts,
    report: &mut Vec<String>,
) -> Result<Option<Planned>, Refusal> {
    let dir = match config.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let from_env = (facts.env)(ENV_PROVIDERS).filter(|value| !value.is_empty());
    let (source, selected) = match (
        &from_env,
        resolved.get("providers_file").and_then(Value::as_str),
    ) {
        (Some(path), _) => (facts.cwd.join(path), Selected::Env),
        (None, Some(file)) => (dir.join(file), Selected::File),
        (None, None) => (dir.join("providers.yaml"), Selected::Default),
    };
    let shown = source.display().to_string();
    let raw = read(&source)?;
    let template = Template::read(&raw, facts.env, &shown)?;
    let mut after = template.tree().clone();
    let changes = strip(&mut after, &facts.catalog_keys, &shown)?;
    if changes.is_empty() {
        if selected == Selected::Env {
            let absolute = source.to_str().ok_or_else(|| {
                Refusal::Config(format!(
                    "{ENV_PROVIDERS} names a catalog whose path is not UTF-8 ({shown}); set \
                     `providers_file:` in config.yaml by hand, then boot again"
                ))
            })?;
            name_catalog(root, absolute)?;
            report.push(format!(
                "providers_file: set to {absolute}, the catalog {ENV_PROVIDERS} selected (1.6.0 \
                 does not read {ENV_PROVIDERS}; remove it from the launcher)"
            ));
        }
        return Ok(None);
    }
    let text = rewrite(&raw, template.tree(), &after, &shown)?;
    template.parity(&text, &after, facts.env, &shown)?;
    name_catalog(root, FILE)?;
    report.extend(changes);
    report.push(format!(
        "providers_file: set to {FILE}, the catalog above with those keys removed, written beside \
         config.yaml; {shown} is kept as it is for a rollback to 1.5.5"
    ));
    Ok(Some(Planned {
        path: dir.join(FILE),
        source,
        text,
    }))
}

/// Point the document's `providers_file` at `file`: in place when present (unless it is a template
/// slot: 1t), else at the schema's position.
fn name_catalog(root: &mut Pairs, file: &str) -> Result<(), Refusal> {
    match root.get_key_mut("providers_file") {
        Some(slot) if is_template(slot) => Err(computed("providers_file")),
        Some(slot) => {
            *slot = Value::from(file);
            Ok(())
        }
        None => {
            schema_insert(root, "providers_file", Value::from(file));
            Ok(())
        }
    }
}

/// Remove, from every catalog entry, each key the 1.6.0 catalog does not read (1.5.5's
/// `ProviderDef` ignored it). One line per removed key.
fn strip(catalog: &mut Value, keys: &[String], shown: &str) -> Result<Vec<String>, Refusal> {
    let Value::Map(entries) = catalog else {
        return Ok(Vec::new());
    };
    if keys.is_empty() && !entries.is_empty() {
        return Err(Refusal::Config(format!(
            "{shown}: the 1.6.0 catalog grammar's keys could not be read, so the upgrade cannot \
             judge this catalog; nothing was written"
        )));
    }
    let mut changes = Vec::new();
    for (name, entry) in entries.iter_mut() {
        let (Some(name), Value::Map(entry)) = (name.as_str(), entry) else {
            continue;
        };
        let stray: Vec<String> = entry
            .keys()
            .filter_map(|key| {
                let known = key
                    .as_str()
                    .is_some_and(|key| keys.iter().any(|k| k == key));
                (!known).then(|| {
                    key.as_str()
                        .map_or_else(|| format!("{key:?}"), str::to_owned)
                })
            })
            .collect();
        for key in stray {
            if remove_kept(entry, &key).is_none() {
                return Err(Refusal::Config(format!(
                    "{shown}: {name} holds a key that is not a string; write it as text, then boot \
                     again"
                )));
            }
            changes.push(format!(
                "{shown}: {name}.{key}: removed (1.5.5 ignored this catalog key; removing it \
                 preserves the legacy behavior)"
            ));
        }
    }
    Ok(changes)
}

/// The catalog's bytes, bounded, as UTF-8; 1.5.5's refusal when it cannot be read.
fn read(source: &Path) -> Result<String, Refusal> {
    let refused = |error: &dyn std::fmt::Display| {
        Refusal::Config(format!(
            "cannot read providers file '{}': {error} (set `providers_file:` in config.yaml, or \
             {ENV_PROVIDERS})",
            source.display()
        ))
    };
    let file = fs::File::open(source).map_err(|error| refused(&error))?;
    let mut bytes = Vec::new();
    file.take(MAX_CATALOG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| refused(&error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CATALOG_BYTES {
        return Err(refused(&format!("larger than {MAX_CATALOG_BYTES} bytes")));
    }
    String::from_utf8(bytes).map_err(|_| refused(&"not UTF-8 text"))
}

/// 5a2: write the planned catalog beside config.yaml with the source catalog's mode and owner,
/// then rename it into place. A file already there with the same bytes (an interrupted upgrade's)
/// is kept; one with other bytes is refused, nothing written.
pub(crate) fn write(planned: &Planned) -> Result<(), Refusal> {
    match fs::read(&planned.path) {
        Ok(bytes) if bytes == planned.text.as_bytes() => return Ok(()),
        Ok(_) => {
            return Err(Refusal::Config(format!(
                "{} is present and holds other bytes than the catalog this upgrade plans; move it \
                 away, then boot again; nothing was written",
                planned.path.display()
            )))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Refusal::Config(format!(
                "cannot read {}: {error}; nothing was written",
                planned.path.display()
            )))
        }
    }
    let fresh = files::create_like_at(&planned.source, &planned.path, planned.text.as_bytes())?;
    files::replace(&fresh, &planned.path)
}

#[cfg(test)]
#[path = "tests/catalog_tests.rs"]
mod tests;
