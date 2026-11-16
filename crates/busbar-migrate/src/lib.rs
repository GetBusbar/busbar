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
#![doc(test(attr(forbid(unsafe_code))))]

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

mod absent_store;
pub mod allow_dest;
mod catalog;
#[cfg(any(test, feature = "counted"))]
pub mod counted;
mod files;
mod legacy_markers;
mod listen;
mod lock;
mod migrate_1_6;
mod overlay;
mod overlay_hooks;
pub mod patch;
pub mod records;
mod settle;
mod steps;
mod styles;
mod templates;

pub use overlay::{Selected, SelectedBy};
pub use settle::{
    apply_settled, section as core_cfg_section, write_secrets, Applied, CoreCfg, SecretFile,
    Settled,
};

/// Count one entry of `$field` in a test build (§9 C1 (sz2)); nothing in a shipped one.
macro_rules! entered {
    ($field:ident) => {
        #[cfg(any(test, feature = "counted"))]
        crate::counted::enter(|entries| entries.$field += 1);
    };
}

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
    /// The 1.5.5 overlay carries a schema `version` above 1 (1.5.5 refused it too).
    NewerOverlay { path: String, found: u64 },
}

impl Refusal {
    /// The precise word the text starts with.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Newer { .. } | Self::NewerOverlay { .. } => "NEWER",
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
            Self::NewerOverlay { path, found } => write!(
                f,
                "NEWER: the 1.5.5 overlay {path} has `version: {found}`, written by a newer \
                 busbar (1.5.5 refused it too); boot the busbar that wrote it, or move the file \
                 aside to drop it; nothing was written"
            ),
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
    entered!(other);
    files::read_bounded(path)
}

/// The backup path beside `config`: `config.yaml.1.5.5`.
#[must_use]
pub fn backup_path(config: &Path) -> PathBuf {
    entered!(other);
    files::sibling(config, BACKUP_SUFFIX)
}

/// The digest [`write_back`] compares: SHA-256 of config.yaml's bytes as step 1 read them.
#[must_use]
pub fn digest(text: &str) -> [u8; 32] {
    entered!(other);
    busbar_contract::crypto::sha256(text.as_bytes())
}

/// 1f (§A3 1f): the listener probe over the plan's resolved `listen` and `admin_listen`. Each
/// address is bound once and released; one another process holds (`EADDRINUSE`, retried every
/// second for 10 s) refuses LIVE_WRITER. Nothing is written.
///
/// # Errors
/// LIVE_WRITER naming the address in use.
#[cold]
#[inline(never)]
pub fn probe_listeners(addresses: &[&str]) -> Result<(), Refusal> {
    entered!(probe);
    listen::probe_within(addresses, listen::BOUND, listen::EVERY)
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
    /// The linked store images declaring `store::FB_EPHEMERAL` (`Registry::ephemeral_stores`), the MIN-3 absent-store
    /// fact (IF §12.10 item 1): `Some` and the document names no store module, exactly one is named, zero or several
    /// refuse CONFIG. `None` on today's ABI, where the 1.5.5-shape constant stands (1d).
    pub ephemeral_stores: Option<Vec<String>>,
    /// How `allow_dest` resolves a provider host name (once, at migrate time).
    pub resolve: allow_dest::Resolve,
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
            ephemeral_stores: None,
            resolve: allow_dest::system_resolve,
        }
    }
}

impl fmt::Debug for Facts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Facts")
            .field("open_units", &self.open_units)
            .field("catalog_keys", &self.catalog_keys)
            .field("cwd", &self.cwd)
            .field("ephemeral_stores", &self.ephemeral_stores)
            .finish_non_exhaustive()
    }
}

/// The process environment as 1.5.5 read it: a variable's value, `None` when unset.
pub type OsEnv<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// v1.5.5's interpolation of config.yaml's text (the kernel's strict `interpolate_env`), for the
/// values 1.5.5 decided on resolved text (1b's `config:` block). `Err` is its refusal text.
pub type Interpolate<'a> = &'a dyn Fn(&str) -> Result<String, String>;

/// What [`plan`] reads.
pub struct Inputs<'a> {
    /// config.yaml.
    pub path: &'a Path,
    /// What the boot knows that config.yaml does not say.
    pub facts: &'a Facts,
    /// The boot's own strict parse, run on the planned document and catalog.
    pub check: Check<'a>,
    /// The environment (`BUSBAR_CONFIG_OVERLAY`, read only for an unstamped config).
    pub env: OsEnv<'a>,
    /// v1.5.5's interpolation of config.yaml.
    pub interpolate: Interpolate<'a>,
    /// `--ignore-overlay` (1.5.5's `--safe-mode`): a pending 1.5.5 overlay then refuses.
    pub ignore_overlay: bool,
}

impl<'a> Inputs<'a> {
    /// `path`, `facts` and `check`, with an empty overlay environment, the text taken as already
    /// resolved, and `--ignore-overlay` unset.
    #[must_use]
    pub fn new(path: &'a Path, facts: &'a Facts, check: Check<'a>) -> Self {
        Self {
            path,
            facts,
            check,
            env: &no_env,
            interpolate: &verbatim,
            ignore_overlay: false,
        }
    }
}

fn no_env(_: &str) -> Option<OsString> {
    None
}

fn verbatim(text: &str) -> Result<String, String> {
    Ok(text.to_owned())
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
    warnings: Vec<String>,
    /// The 1.5.5 overlay path 1b selected (`None`: locked, or not a 1.5.5 source).
    overlay: Option<overlay::Selected>,
    ignore_overlay: bool,
    /// The styles `resolve_styles` resolved the deferred bindings with, re-applied by the write's re-run.
    styles: Vec<(String, Vec<String>)>,
}

impl Plan {
    /// `config::resolve_styles` (IF §12.10 item 3, §12.18): after every image is admitted and before
    /// `boot_plan`, the gateway hands the styles the admitted auth images declared
    /// (`Registry::outbound_styles`); each deferred `{"$style": w}` binding of the plan becomes the
    /// identity of the unique image declaring `w`. The boot then reads the resolved document, and the write
    /// re-applies the same resolution to its re-run. Called directly, in process: no frame.
    ///
    /// # Errors
    /// CONFIG naming the binding and the style when none, or several, declare it.
    #[cold]
    #[inline(never)]
    pub fn resolve_styles(&mut self, styles: &[(&str, &[&str])]) -> Result<(), Refusal> {
        entered!(other);
        let (text, lines) = styles::resolve(&self.planned, styles)?;
        self.planned = text;
        self.report.extend(lines);
        self.styles = styles
            .iter()
            .map(|(identity, words)| {
                (
                    (*identity).to_owned(),
                    words.iter().map(|word| (*word).to_owned()).collect(),
                )
            })
            .collect();
        Ok(())
    }

    /// The resolved styles as `resolve` takes them.
    fn with_styles<T>(&self, then: impl FnOnce(&[(&str, &[&str])]) -> T) -> T {
        let words: Vec<Vec<&str>> = self
            .styles
            .iter()
            .map(|(_, words)| words.iter().map(String::as_str).collect())
            .collect();
        let view: Vec<(&str, &[&str])> = self
            .styles
            .iter()
            .zip(&words)
            .map(|((identity, _), words)| (identity.as_str(), words.as_slice()))
            .collect();
        then(&view)
    }

    /// The lines the boot logs at WARN (an overlay that is not folded, each dropped plugin pin).
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The 1.5.5 overlay path 1b selected, if any.
    #[must_use]
    pub fn overlay(&self) -> Option<&Selected> {
        self.overlay.as_ref()
    }

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

    /// SHA-256 over the source bytes the plan was made from and the 1.5.5 overlay bytes it folds
    /// (or "none"), not over where the overlay sat; [`write`] refuses if either changed.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The format config.yaml was planned from.
    #[must_use]
    pub fn source_format(&self) -> u64 {
        self.from
    }

    /// The text the boot reads in place of the file at `path` (§3 step 2): the planned config.yaml
    /// for config.yaml's own path, the planned providers catalog (§3 1k,
    /// `providers.busbar-1.6.yaml`) for its path, `None` for every other file.
    #[must_use]
    pub fn held(&self, path: &Path) -> Option<&str> {
        if path == self.path.as_path() {
            return Some(self.planned.as_str());
        }
        self.catalog
            .as_ref()
            .filter(|planned| path == planned.path.as_path())
            .map(|planned| planned.text.as_str())
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
    entered!(plan);
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
    let mut warnings = Vec::new();
    // 1b: only a 1.5.5 source had an overlay file.
    let selected = if from == 0 {
        overlay::select(inputs.path, &source, inputs.env, inputs.interpolate)?
    } else {
        None
    };
    let read = match &selected {
        Some(selected) => Some(overlay::read(selected, inputs.ignore_overlay)?),
        None => None,
    };
    match &read {
        Some(read) => {
            report.push(read.line());
            warnings.extend(read.warnings());
        }
        None if from == 0 => report.push(overlay::LOCKED_LINE.to_owned()),
        None => {}
    }
    let chained = chain(
        inputs.path,
        &source,
        from,
        inputs.facts,
        read.as_ref(),
        &mut report,
    )?;
    judge(&chained, inputs.facts, inputs.check)?;
    Ok(Plan {
        path: inputs.path.to_path_buf(),
        from,
        facts: inputs.facts.clone(),
        planned: chained.text,
        catalog: chained.catalog,
        digest: plan_digest(&source, read.as_ref()),
        report,
        warnings,
        overlay: selected,
        ignore_overlay: inputs.ignore_overlay,
        styles: Vec::new(),
    })
}

/// [`Plan::digest`]: the source's length and bytes, then the folded overlay's bytes or none.
fn plan_digest(source: &str, overlay: Option<&overlay::Read>) -> [u8; 32] {
    let length = u64::try_from(source.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    match overlay.and_then(overlay::Read::bytes) {
        Some(folded) => busbar_contract::crypto::sha256_parts(&[
            length.as_slice(),
            source.as_bytes(),
            b"\x01".as_slice(),
            folded,
        ]),
        None => busbar_contract::crypto::sha256_parts(&[
            length.as_slice(),
            source.as_bytes(),
            b"\x00".as_slice(),
        ]),
    }
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
/// and owner, keep the original as `config.yaml.1.5.5` (a byte copy with its own inode), and rename
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
    write_settled(plan, &[], check)
}

/// [`write`] with what each instance's `open` settled (IF §7.2): after the re-run, the answers are
/// applied to the re-run document (the bags, CORE_CFG filed, LIFT pointers lifted: [`apply_settled`]),
/// the boot's strict parse judges that document, and the lifted secret files (5a) are written before
/// the catalog and the stamped document. No settled answer, no change: this is [`write`].
///
/// # Errors
/// As [`write`]; CONFIG naming the instance index for a settled answer core cannot file.
#[cold]
#[inline(never)]
pub fn write_settled(
    plan: &Plan,
    settled: &[Settled],
    check: Check<'_>,
) -> Result<Written, Refusal> {
    entered!(write);
    let _held = lock::Held::take(&plan.path)?;
    if let Some(selected) = &plan.overlay {
        overlay::sweep(selected);
    }
    let now = files::read_bounded(&plan.path)?;
    if read_version(&now)? >= CONFIG_FORMAT {
        return Ok(Written::StampedByPeer);
    }
    // 5R re-runs 1b from disk too: an interrupted 5c reads back to the same bytes.
    let read = match &plan.overlay {
        Some(selected) => Some(overlay::read(selected, plan.ignore_overlay)?),
        None => None,
    };
    if plan_digest(&now, read.as_ref()) != plan.digest {
        return Err(Refusal::LiveWriter(format!(
            "{} or the 1.5.5 overlay changed between the plan and the write: stop every 1.5.5 \
             instance and every other writer of these files, then boot again; nothing was \
             written",
            plan.path.display()
        )));
    }
    let mut again = chain(
        &plan.path,
        &now,
        plan.from,
        &plan.facts,
        read.as_ref(),
        &mut Vec::new(),
    )?;
    if !plan.styles.is_empty() {
        let (resolved, _) = plan.with_styles(|styles| styles::resolve(&again.text, styles))?;
        again.text = resolved;
    }
    if again.text != plan.planned || again.catalog != plan.catalog {
        return Err(Refusal::Config(format!(
            "the upgrade of {} did not plan the same document twice from the same bytes ({}); \
             nothing was written",
            plan.path.display(),
            where_plans_differ(
                &plan.planned,
                &again.text,
                plan.catalog.is_some(),
                again.catalog.is_some()
            )
        )));
    }
    let applied = apply_settled(&again.text, &plan.path, settled, false, plan.facts.env)?;
    again.text = applied.text().to_owned();
    judge(&again, &plan.facts, check)?;
    let backup = files::sibling(&plan.path, BACKUP_SUFFIX);
    files::backup_absent_or_equal(&backup, now.as_bytes())?;
    if let Some(read) = &read {
        overlay::backup_absent_or_equal(read)?;
    }
    write_secrets(applied.secrets())?;
    if let Some(planned) = &again.catalog {
        catalog::write(planned)?;
    }
    let fresh = files::create_like(&plan.path, again.text.as_bytes())?;
    files::keep_backup(&plan.path, &backup, now.as_bytes())?;
    if let Some(read) = &read {
        // 5c: before the stamp, so a 1.5.5 still writing the overlay is caught, never lost.
        if let Err(refusal) = overlay::guard(read) {
            let _ = std::fs::remove_file(&fresh);
            return Err(refusal);
        }
    }
    files::replace(&fresh, &plan.path)?;
    Ok(Written::Stamped)
}

/// How [`write_back`] ended. Every outcome but [`WroteBack::Written`] left config.yaml as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WroteBack {
    /// config.yaml now holds the edited bytes.
    Written,
    /// The edit changed nothing; equal bytes are not written.
    Unchanged,
    /// config.yaml's bytes differ from the ones step 1 read (an operator edit, a peer's
    /// write-back): nothing was written, and the next load converts again.
    Changed,
}

/// 5W (§3, r42), the settled write-back on a stamped boot, also the reload path's: under the
/// config directory lock (5L), re-read config.yaml; when its bytes are no longer the ones `seen`
/// digests ([`digest`]), write nothing; else apply `edit` (the patch writer's edits of the settled
/// bags and CORE_CFG) and, when the bytes changed, replace config.yaml by a new file with its mode
/// and owner, fsynced and renamed over it, the directory fsynced. No backup is kept and the stamp
/// does not change.
///
/// # Errors
/// CONFIG when the lock is not held in time, `edit` refuses, the edited document is not stamped
/// [`CONFIG_FORMAT`], or an I/O step fails (nothing renamed). The caller logs and audits the
/// refusal and boots on.
#[cold]
#[inline(never)]
pub fn write_back(
    config: &Path,
    seen: &[u8; 32],
    edit: &dyn Fn(&str) -> Result<String, Refusal>,
) -> Result<WroteBack, Refusal> {
    entered!(write_back);
    let _held = lock::Held::take(config)?;
    let now = files::read_bounded(config)?;
    if busbar_contract::crypto::sha256(now.as_bytes()) != *seen {
        return Ok(WroteBack::Changed);
    }
    let edited = edit(&now)?;
    if edited == now {
        return Ok(WroteBack::Unchanged);
    }
    if read_version(&edited)? != CONFIG_FORMAT {
        return Err(Refusal::Config(format!(
            "the settled write-back of {} would not keep `{STAMP_KEY}: {CONFIG_FORMAT}`; \
             nothing was written",
            config.display()
        )));
    }
    let fresh = files::create_like(config, edited.as_bytes())?;
    files::replace(&fresh, config)?;
    Ok(WroteBack::Written)
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
    overlay: Option<&overlay::Read>,
    report: &mut Vec<String>,
) -> Result<Chained, Refusal> {
    let first = usize::try_from(from).unwrap_or(usize::MAX);
    let mut work = steps::Work {
        path,
        facts,
        overlay,
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

/// Where two plans of the same bytes part, for the refusal: the first differing line and the lengths
/// (never the text, which may hold a literal secret).
fn where_plans_differ(
    first: &str,
    second: &str,
    first_catalog: bool,
    second_catalog: bool,
) -> String {
    if first == second {
        return format!("the catalog differs: planned {first_catalog}, then {second_catalog}");
    }
    let line = first
        .lines()
        .zip(second.lines())
        .position(|(a, b)| a != b)
        .unwrap_or(first.lines().count().min(second.lines().count()))
        + 1;
    format!(
        "the document differs at line {line}: {} bytes, then {} bytes",
        first.len(),
        second.len()
    )
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
