// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's one-time config migration (MIGRATE-ON-BOOT r42 §3).
//!
//! A config.yaml carries `config_version: N` as its first key. [`CONFIG_FORMAT`] is the format this
//! busbar reads; a file without the key is 1.5.x. The gateway's seam (`root/migrate.rs`) reads that
//! one field on every boot (`busbar_contract::upgrade::config_version`) and decides step 1 itself,
//! so a stamped boot enters no function of this crate. Only an unstamped file reaches its work:
//! [`plan`] reads and converts it in memory, through `STEPS[v..CONFIG_FORMAT]`, and writes
//! nothing; the gateway then opens its instances, and [`write`] rewrites config.yaml in place,
//! once, with `config.yaml.1.5.5` kept byte-identical beside it. The gateway then re-executes
//! itself and boots stamped.
//!
//! Cold code: every entry point is `#[cold] #[inline(never)]` (the `migrate-size` job's anchor is
//! [`plan`]), and a stamped boot enters none of it.
//!
//! Separation (§7): YAML only through `busbar_contract::yaml`, digests only through
//! `busbar_contract::crypto`; no plugin loader, no store driver.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

mod files;
mod lock;
pub mod patch;
mod steps;

pub use busbar_contract::upgrade::{CONFIG_FORMAT, MIGRATED_ENV, STAMP_KEY, UPGRADE_FIRST};

/// The backup beside config.yaml: the 1.5.5 bytes, byte-identical, for a rollback.
pub const BACKUP_SUFFIX: &str = ".1.5.5";
/// The most config.yaml bytes the migration reads.
pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

/// The unstamped `--providers` refusal (§A3 1): 1.5.5 had no such flag, and the upgrade reads the
/// catalog 1.5.5 read.
pub const PROVIDERS_TEXT: &str = "this config predates 1.6.0; the one-time upgrade migrates the \
     providers catalog 1.5.5 read (BUSBAR_PROVIDERS, else `providers_file`, else providers.yaml \
     beside config.yaml); 1.5.5 had no --providers flag: boot once without it";

/// Why the migration refused. Every text starts with its word; nothing was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// config.yaml carries a `config_version` above [`CONFIG_FORMAT`].
    Newer { found: u64 },
    /// The re-executed image found no stamp (no loop).
    Verify,
    /// A shape no release this busbar upgrades from wrote.
    Unsupported(String),
    /// The config, its directory or the environment must change first.
    Config(String),
    /// Something else wrote config.yaml (or holds its directory) during the upgrade.
    LiveWriter(String),
}

impl Refusal {
    /// The precise word the text starts with.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Newer { .. } => "NEWER",
            Self::Verify => "VERIFY",
            Self::Unsupported(_) => "UNSUPPORTED",
            Self::Config(_) => "CONFIG",
            Self::LiveWriter(_) => "LIVE_WRITER",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Newer { found } => write!(
                f,
                "NEWER: config.yaml has `{STAMP_KEY}: {found}`, written by a newer busbar; this \
                 busbar reads `{STAMP_KEY}: {CONFIG_FORMAT}`. Boot the newer busbar, or restore the \
                 config.yaml this one wrote"
            ),
            Self::Verify => write!(
                f,
                "VERIFY: busbar re-executed itself after upgrading config.yaml, but the file it \
                 now reads has no `{STAMP_KEY}: {CONFIG_FORMAT}`; nothing more was written. Find \
                 what rewrote config.yaml during the upgrade, then boot again"
            ),
            Self::Unsupported(text) => write!(f, "UNSUPPORTED: {text}"),
            Self::Config(text) => write!(f, "CONFIG: {text}"),
            Self::LiveWriter(text) => write!(f, "LIVE_WRITER: {text}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// The one field (`busbar_contract::upgrade::config_version`) as this crate's refusal.
pub(crate) fn read_version(text: &str) -> Result<u64, Refusal> {
    busbar_contract::upgrade::config_version(text).map_err(Refusal::Config)
}

/// Read config.yaml, bounded by [`MAX_CONFIG_BYTES`], as UTF-8.
///
/// # Errors
/// CONFIG naming the file when it cannot be read, is too large or is not UTF-8.
pub fn read_config(path: &Path) -> Result<String, Refusal> {
    files::read_bounded(path)
}

/// The backup path beside `config`: `config.yaml.1.5.5`.
#[must_use]
pub fn backup_path(config: &Path) -> PathBuf {
    files::sibling(config, BACKUP_SUFFIX)
}

/// The boot's own strict parse of a planned document: `Err(text)` is the parse's refusal.
pub type Check<'a> = &'a dyn Fn(&str) -> Result<(), String>;

/// What [`plan`] reads.
pub struct Inputs<'a> {
    /// config.yaml.
    pub path: &'a Path,
    /// The boot's own strict parse, run on the planned document.
    pub check: Check<'a>,
}

/// An upgrade planned in memory. Nothing has been written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    path: PathBuf,
    from: u64,
    planned: String,
    digest: [u8; 32],
    report: Vec<String>,
}

impl Plan {
    /// The stamped document [`write`] puts in place of config.yaml.
    #[must_use]
    pub fn planned(&self) -> &str {
        &self.planned
    }

    /// One line per change the chain made, for the boot's log (never a secret value).
    #[must_use]
    pub fn report(&self) -> &[String] {
        &self.report
    }

    /// SHA-256 of the source bytes the plan was made from; [`write`] refuses if they changed.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The format config.yaml was planned from.
    #[must_use]
    pub fn source_format(&self) -> u64 {
        self.from
    }
}

/// Step 1 for an unstamped config (§3, §A3 1): the writable and same-mount probes, then
/// `STEPS[from..CONFIG_FORMAT]` in memory, the stamp, and the boot's own strict parse of the result.
/// Nothing is written; no plugin is loaded and no store opened.
///
/// # Errors
/// CONFIG when config.yaml or its directory cannot be rewritten in place, when a step refuses, or
/// when the strict parse refuses the planned document (its text, then [`UPGRADE_FIRST`]);
/// UNSUPPORTED for a shape older than 1.5.5; NEWER for a stamped file.
#[cold]
#[inline(never)]
pub fn plan(inputs: &Inputs<'_>) -> Result<Plan, Refusal> {
    let source = files::read_bounded(inputs.path)?;
    let from = read_version(&source)?;
    if from > CONFIG_FORMAT {
        return Err(Refusal::Newer { found: from });
    }
    if from == CONFIG_FORMAT {
        return Err(Refusal::Config(format!(
            "{} already carries `{STAMP_KEY}: {CONFIG_FORMAT}`; there is nothing to upgrade",
            inputs.path.display()
        )));
    }
    files::probe_in_place(inputs.path)?;
    let mut report = Vec::new();
    let planned = chain(&source, from, &mut report)?;
    (inputs.check)(&planned).map_err(|text| Refusal::Config(format!("{text}\n{UPGRADE_FIRST}")))?;
    Ok(Plan {
        path: inputs.path.to_path_buf(),
        from,
        planned,
        digest: busbar_contract::crypto::sha256(source.as_bytes()),
        report,
    })
}

/// How [`write`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// This process replaced config.yaml with the stamped document.
    Stamped,
    /// Another busbar stamped it while this one waited on the directory lock; nothing written.
    StampedByPeer,
}

/// Step 5 (§3, §A3 5L-5d): under the directory lock, re-run the plan from disk (same digest, same
/// result, the strict parse again), check the read-only preconditions, then write the stamped
/// document beside config.yaml with config.yaml's mode and owner, keep the original as
/// `config.yaml.1.5.5` (a hard link: the same bytes), and rename the new file over config.yaml.
/// Every step is fsynced. A crash at any point leaves either the original config.yaml (the next
/// boot plans again and converges) or the stamped one.
///
/// # Errors
/// LIVE_WRITER when config.yaml changed since [`plan`]; CONFIG when the lock is not held in time,
/// a backup with other bytes is present, the new file cannot take config.yaml's mode, or the
/// strict parse now refuses; any I/O failure as CONFIG naming the file, with nothing renamed.
#[cold]
#[inline(never)]
pub fn write(plan: &Plan, check: Check<'_>) -> Result<Written, Refusal> {
    let _held = lock::Held::take(&plan.path)?;
    let now = files::read_bounded(&plan.path)?;
    if read_version(&now)? >= CONFIG_FORMAT {
        return Ok(Written::StampedByPeer);
    }
    if busbar_contract::crypto::sha256(now.as_bytes()) != plan.digest {
        return Err(Refusal::LiveWriter(format!(
            "{} changed between the plan and the write: stop every 1.5.5 instance and every \
             other writer of this file, then boot again; nothing was written",
            plan.path.display()
        )));
    }
    let again = chain(&now, plan.from, &mut Vec::new())?;
    if again != plan.planned {
        return Err(Refusal::Config(format!(
            "the upgrade of {} did not plan the same document twice from the same bytes; nothing \
             was written",
            plan.path.display()
        )));
    }
    check(&again).map_err(|text| Refusal::Config(format!("{text}\n{UPGRADE_FIRST}")))?;
    let backup = backup_path(&plan.path);
    files::backup_absent_or_equal(&backup, now.as_bytes())?;
    let fresh = files::create_like(&plan.path, again.as_bytes())?;
    files::keep_backup(&plan.path, &backup)?;
    files::replace(&fresh, &plan.path)?;
    Ok(Written::Stamped)
}

/// `STEPS[from..CONFIG_FORMAT]` over the source text, then the stamp.
fn chain(source: &str, from: u64, report: &mut Vec<String>) -> Result<String, Refusal> {
    let first = usize::try_from(from).unwrap_or(usize::MAX);
    let mut text = source.to_owned();
    for step in steps::STEPS.iter().skip(first) {
        text = step(&text, report)?;
    }
    patch::stamp(&text, CONFIG_FORMAT)
}

#[cfg(test)]
#[path = "tests/scratch.rs"]
mod scratch;

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
