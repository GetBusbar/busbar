// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 overlay (MIGRATE-ON-BOOT §A3 1b, 1c and 5c): red. The selection, the recovery read,
//! the fold and the guard land with the next commit; this one carries their tests.

use std::path::{Path, PathBuf};

use busbar_contract::json;
use busbar_contract::yaml::Value;

use crate::{Env, Interpolate, Refusal};

/// The variable 1.5.5 read when `config.overlay` was unset.
pub const ENV: &str = "BUSBAR_CONFIG_OVERLAY";
/// The file beside config.yaml 1.5.5 used when nothing else selected one.
pub const DEFAULT_OVERLAY_FILENAME: &str = "busbar-overlay.json";
/// F: where 5c holds the 1.5.5 overlay while it folds it.
pub const FOLDING_SUFFIX: &str = ".busbar-folding";
/// The marker file inside P.
pub const MARKER: &str = "busbar-1.6-folded";
/// The report line of a locked config.
pub(crate) const LOCKED_LINE: &str =
    "overlay: none (`config.locked: true`: 1.5.5 read no overlay file)";

/// How 1.5.5 chose the overlay path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedBy {
    /// `config.overlay.file`.
    File,
    /// `BUSBAR_CONFIG_OVERLAY`.
    Env,
    /// `busbar-overlay.json` beside config.yaml.
    Default,
}

/// The path a 1.5.5 with this config read and wrote its overlay at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// Absolute.
    pub path: PathBuf,
    /// How it was chosen.
    pub by: SelectedBy,
}

/// 1b's reading of the selected overlay.
#[derive(Debug)]
pub(crate) struct Read {
    selected: Selected,
}

impl Read {
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        None
    }

    pub(crate) fn line(&self) -> String {
        format!("overlay: `{}`", self.selected.path.display())
    }

    pub(crate) fn warnings(&self) -> Vec<String> {
        Vec::new()
    }
}

pub(crate) fn unparseable(o: &str, why: &str) -> Refusal {
    Refusal::Config(format!("{o}: {why}"))
}

pub(crate) fn text(value: &str, _path: &str, _o: &str) -> Result<Value, Refusal> {
    Ok(Value::Text(value.to_owned()))
}

pub(crate) fn to_yaml(_value: &json::Value, path: &str, o: &str) -> Result<Value, Refusal> {
    Err(unparseable(o, path))
}

pub(crate) fn select(
    _config: &Path,
    _source: &str,
    _env: Env<'_>,
    _interpolate: Interpolate<'_>,
) -> Result<Option<Selected>, Refusal> {
    Ok(None)
}

pub(crate) fn read(selected: &Selected, _ignore_overlay: bool) -> Result<Read, Refusal> {
    Ok(Read {
        selected: selected.clone(),
    })
}

pub(crate) fn fold(text: &str, _read: &Read, _report: &mut Vec<String>) -> Result<String, Refusal> {
    Ok(text.to_owned())
}

pub(crate) fn backup_absent_or_equal(_read: &Read) -> Result<(), Refusal> {
    Ok(())
}

pub(crate) fn sweep(_selected: &Selected) {}

pub(crate) fn guard(_read: &Read) -> Result<(), Refusal> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// A test kill point inside 5c; 0 = none.
    pub(crate) static CRASH_AT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// A test writer run just before 5c moves `<o>`.
    pub(crate) static BEFORE_MOVE: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
#[path = "tests/overlay_tests.rs"]
mod tests;
