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
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use busbar_contract::yaml::{Pairs, Value};

use crate::{files, Facts, Refusal};

/// The planned catalog's file name, beside config.yaml.
pub(crate) const FILE: &str = "providers.busbar-1.6.yaml";

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

/// 1k over the document `root` (R) with its resolved twin. Red stub: no catalog is planned.
pub(crate) fn plan(
    config: &Path,
    root: &mut Pairs,
    resolved: &Value,
    facts: &Facts,
    report: &mut Vec<String>,
) -> Result<Option<Planned>, Refusal> {
    let _ = (config, root, resolved, facts, report);
    Ok(None)
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
