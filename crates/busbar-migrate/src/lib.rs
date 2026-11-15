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

mod absent_store;
mod catalog;
mod files;
mod legacy_markers;
mod lock;
mod migrate_1_6;
pub mod patch;
mod steps;
mod templates;

pub use busbar_contract::upgrade::{CONFIG_FORMAT, MIGRATED_ENV, STAMP_KEY, UPGRADE_FIRST};

/// The backup beside config.yaml: the 1.5.5 bytes, byte-identical, for a rollback.
pub const BACKUP_SUFFIX: &str = ".1.5.5";
/// The most config.yaml bytes the migration reads.
pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
/// The providers catalog the upgrade writes beside config.yaml when the 1.5.5 one must change
/// (§3 1k); config.yaml's `providers_file` then names it.
pub const CATALOG_FILE: &str = catalog::FILE;

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
    /// The patch writer could not keep the operator's text at a path (a proof failed); VERIFY.
    Authored(String),
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
            Self::Verify | Self::Authored(_) => "VERIFY",
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
            Self::Authored(text) => write!(f, "VERIFY: {text}"),
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

/// The boot's own strict parse of a planned document and the providers catalog it reads, both
/// interpolated as the boot interpolates them: `catalog` is the planned new catalog, `None` when
/// the catalog 1.5.5 read is kept as it is. `Err(text)` is the parse's refusal.
pub type Check<'a> = &'a dyn Fn(&str, Option<&str>) -> Result<(), String>;

/// The environment as the boot reads it: a variable's value, `None` when it is unset (or not
/// UTF-8).
pub type Env = fn(&str) -> Option<String>;

/// What the boot knows that config.yaml does not say (§3 1): built once by the seam from the
/// gateway's own installed state (no plugin or plane is named here), and kept in the plan so the
/// re-run at the write plans from the same facts.
#[derive(Clone)]
pub struct Facts {
    /// The fallback plane's billable classes that it does not bill as a fee, without the reserved
    /// units: what a 1.5.5 `rate_card` lane, which billed them at nothing, must price (1d).
    pub open_units: Vec<String>,
    /// Every key the 1.6.0 providers catalog reads: the catalog grammar's and the installed planes'
    /// declared keys (1k).
    pub catalog_keys: Vec<String>,
    /// The environment (1t's interpolation, 1k's `BUSBAR_PROVIDERS`).
    pub env: Env,
    /// The working directory a relative `BUSBAR_PROVIDERS` is read from, as 1.5.5 read it (1k).
    pub cwd: PathBuf,
}

impl Facts {
    /// The facts with this process's environment and working directory.
    #[must_use]
    pub fn of_process(open_units: Vec<String>, catalog_keys: Vec<String>) -> Self {
        fn env(name: &str) -> Option<String> {
            std::env::var(name).ok()
        }
        Self {
            open_units,
            catalog_keys,
            env,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

impl fmt::Debug for Facts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Facts")
            .field("open_units", &self.open_units)
            .field("catalog_keys", &self.catalog_keys)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

/// What [`plan`] reads.
pub struct Inputs<'a> {
    /// config.yaml.
    pub path: &'a Path,
    /// What the boot knows that config.yaml does not say.
    pub facts: &'a Facts,
    /// The boot's own strict parse, run on the planned document and catalog.
    pub check: Check<'a>,
}

/// An upgrade planned in memory. Nothing has been written.
#[derive(Debug, Clone)]
pub struct Plan {
    path: PathBuf,
    from: u64,
    facts: Facts,
    planned: String,
    catalog: Option<catalog::Planned>,
    digest: [u8; 32],
    report: Vec<String>,
}

impl Plan {
    /// The stamped document [`write`] puts in place of config.yaml.
    #[must_use]
    pub fn planned(&self) -> &str {
        &self.planned
    }

    /// The new providers catalog [`write`] puts beside config.yaml, and its bytes; `None` when the
    /// catalog 1.5.5 read is kept as it is (§3 1k).
    #[must_use]
    pub fn catalog(&self) -> Option<(&Path, &str)> {
        self.catalog
            .as_ref()
            .map(|planned| (planned.path.as_path(), planned.text.as_str()))
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
/// UNSUPPORTED for a shape older than 1.5.5; NEWER for a stamped file; VERIFY when the operator's
/// text cannot be kept.
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
    let chained = chain(inputs.path, &source, from, inputs.facts, &mut report)?;
    judge(&chained, inputs.facts, inputs.check)?;
    Ok(Plan {
        path: inputs.path.to_path_buf(),
        from,
        facts: inputs.facts.clone(),
        planned: chained.text,
        catalog: chained.catalog,
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
/// result, the strict parse again), check the read-only preconditions, then write the planned
/// providers catalog (5a2) and the stamped document beside config.yaml with their sources' mode
/// and owner, keep the original as `config.yaml.1.5.5` (a hard link: the same bytes), and rename
/// the new file over config.yaml. Every step is fsynced. A crash at any point leaves either the
/// original config.yaml (the next boot plans again and converges) or the stamped one.
///
/// # Errors
/// LIVE_WRITER when config.yaml changed since [`plan`]; CONFIG when the lock is not held in time,
/// a backup or catalog with other bytes is present, a new file cannot take its source's mode, or
/// the strict parse now refuses; any I/O failure as CONFIG naming the file, with nothing renamed
/// over config.yaml.
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
    let again = chain(&plan.path, &now, plan.from, &plan.facts, &mut Vec::new())?;
    if again.text != plan.planned || again.catalog != plan.catalog {
        return Err(Refusal::Config(format!(
            "the upgrade of {} did not plan the same document twice from the same bytes; nothing \
             was written",
            plan.path.display()
        )));
    }
    judge(&again, &plan.facts, check)?;
    let backup = backup_path(&plan.path);
    files::backup_absent_or_equal(&backup, now.as_bytes())?;
    if let Some(planned) = &again.catalog {
        catalog::write(planned)?;
    }
    let fresh = files::create_like(&plan.path, again.text.as_bytes())?;
    files::keep_backup(&plan.path, &backup)?;
    files::replace(&fresh, &plan.path)?;
    Ok(Written::Stamped)
}

/// What the chain planned: the stamped template text and the new catalog, if any.
struct Chained {
    text: String,
    catalog: Option<catalog::Planned>,
}

/// `STEPS[from..CONFIG_FORMAT]` over the source text, then the stamp.
fn chain(
    path: &Path,
    source: &str,
    from: u64,
    facts: &Facts,
    report: &mut Vec<String>,
) -> Result<Chained, Refusal> {
    let first = usize::try_from(from).unwrap_or(usize::MAX);
    let mut work = steps::Work {
        path,
        facts,
        report,
        catalog: None,
    };
    let mut text = source.to_owned();
    for step in steps::STEPS.iter().skip(first) {
        text = step(&text, &mut work)?;
    }
    Ok(Chained {
        text: patch::stamp(&text, CONFIG_FORMAT)?,
        catalog: work.catalog,
    })
}

/// Proof three (§A7 "Authored text"): the planned document and catalog, interpolated as every later
/// boot interpolates them, pass the boot's own strict parse. The interpolated texts are wiped.
fn judge(chained: &Chained, facts: &Facts, check: Check<'_>) -> Result<(), Refusal> {
    let config = templates::Resolved::of(&chained.text, facts.env, "config.yaml")?;
    let catalog = chained
        .catalog
        .as_ref()
        .map(|planned| {
            templates::Resolved::of(
                &planned.text,
                facts.env,
                &planned.path.display().to_string(),
            )
        })
        .transpose()?;
    check(
        config.text(),
        catalog.as_ref().map(templates::Resolved::text),
    )
    .map_err(|text| Refusal::Config(format!("{text}\n{UPGRADE_FIRST}")))
}

#[cfg(test)]
#[path = "tests/scratch.rs"]
mod scratch;

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
