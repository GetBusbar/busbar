// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migrate-on-boot seam (MIGRATE-ON-BOOT r42 §3): the gateway's only caller of
//! `busbar_migrate`.
//!
//! [`run`] is step 1, from `main` after logging and before the runtime: it reads config.yaml's one
//! field. A stamped config (`config_version: 1`) boots with nothing else read. A newer one is
//! refused NEWER; an unstamped one in the image this seam re-executed is refused VERIFY, so the
//! upgrade never loops. Any other unstamped config is planned in memory (nothing written), its
//! listeners are probed (1f), and the plan is held.
//!
//! Step 2 binds the plan (§3 step 2): while it is held, the boot reads the planned document in
//! place of config.yaml ([`held`], through the composition root's `RootRules::held_document`), so
//! every instance opens on exactly what step 5 writes, never on the 1.5.5 bytes still on disk.
//!
//! [`finish`] is step 5: once every instance has opened, before anything serves, the plan is
//! written in place; then the seam hands an armed first start over (its store still open), closes
//! every instance the boot opened (an instance's descriptors, a plugin's included, must not reach
//! the new image), marks every descriptor >= 3 close-on-exec behind that (a plugin may have left
//! one inheritable), and re-executes itself with the same argv and `BUSBAR_MIGRATED=1` onto the
//! stamped file.

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use busbar_contract::secure::SecureString;
use busbar_contract::upgrade::{config_version, CONFIG_FORMAT, MIGRATED_ENV};
use busbar_migrate::{Inputs, Plan, Refusal, Written};

/// The plan step 1 made for an unstamped config: held for the boot's reads, written by [`finish`].
static PENDING: OnceLock<Plan> = OnceLock::new();

/// The absolute directory of config.yaml, which TEXT_ADD_KEY names. Set by [`run`].
static CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// config.yaml as the boot resolved it: step 4 reads its attempt marker there. Set by [`run`].
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// What step 1 reads from outside the process: the environment and config.yaml (`None`: absent).
/// The boot passes the real ones; a test counts what a stamped boot touches.
pub(crate) struct Probe<'a> {
    pub(crate) env: &'a dyn Fn(&str) -> Option<OsString>,
    pub(crate) read: &'a dyn Fn(&Path) -> Result<Option<String>, String>,
}

/// The boot's strict parse of a planned document (already interpolated by the migration, as the
/// boot's read interpolates it): its resolved listener addresses (`listen`, `admin_listen`) when
/// it accepts the document, else its refusal text.
pub(crate) type Parse<'a> = &'a dyn Fn(&str) -> Result<Vec<String>, String>;

/// The admitted images' pure candidate check, run again inside the guarded writer.
type CandidateCheck = std::sync::Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Step 1. `Ok` when the boot may go on: stamped, absent (the config reader reports that in its own
/// words), or planned and held for the boot's reads and [`finish`]. It first records the config's
/// directory, which the recoverable gate ([`admit_for_host`]) answers from: a stamped config can
/// still meet a 1.5.5 store restored beside it.
///
/// # Errors
/// The migration's refusal text (NEWER, VERIFY, CONFIG, UNSUPPORTED, LIVE_WRITER), nothing written.
#[cold]
#[inline(never)]
pub(crate) fn run(config: &Path, providers_flag: bool, ignore_overlay: bool) -> Result<(), String> {
    let _ = CONFIG_DIR.set(config_dir(config));
    let _ = CONFIG_PATH.set(config.to_path_buf());
    let env = |name: &str| std::env::var_os(name);
    run_in(
        config,
        providers_flag,
        ignore_overlay,
        &Probe {
            env: &env,
            read: &read_config,
        },
    )
}

/// [`run`] over `probe`. A stamped config costs one read of config.yaml and the re-exec marker:
/// no other file and no other variable (257c); the unstamped path hands the environment to the
/// migration, which reads the 1.5.5 overlay's selector there.
pub(crate) fn run_in(
    config: &Path,
    providers_flag: bool,
    ignore_overlay: bool,
    probe: &Probe<'_>,
) -> Result<(), String> {
    let Some(text) = (probe.read)(config)? else {
        return Ok(());
    };
    let migrated = (probe.env)(MIGRATED_ENV).is_some();
    let Some(plan) = plan_text(
        config,
        &text,
        migrated,
        providers_flag,
        ignore_overlay,
        probe.env,
        &parse_planned,
    )?
    else {
        return Ok(());
    };
    for line in plan.report() {
        if warns(line) {
            tracing::warn!(target: "busbar::migrate", "{line}");
        } else {
            tracing::info!(target: "busbar::migrate", "{line}");
        }
    }
    for line in plan.warnings() {
        tracing::warn!(target: "busbar::migrate", "{line}");
    }
    tracing::info!(
        target: "busbar::migrate",
        "{} predates 1.6.0: upgraded in memory, and this boot runs the upgraded document; it is \
         rewritten in place once every instance has opened (the original is kept as {})",
        config.display(),
        busbar_migrate::backup_path(config).display()
    );
    let _ = PENDING.set(plan);
    Ok(())
}

/// Step 1 over the boot's strict parse, with this process's environment and no `--ignore-overlay`:
/// `None` for a stamped or absent config (nothing of `busbar_migrate` is entered), the plan for an
/// unstamped one.
#[cfg(test)]
pub(crate) fn step1(
    config: &Path,
    migrated: bool,
    providers_flag: bool,
    parse: Parse<'_>,
) -> Result<Option<Plan>, String> {
    let Some(text) = read_config(config)? else {
        return Ok(None);
    };
    let env = |name: &str| std::env::var_os(name);
    plan_text(config, &text, migrated, providers_flag, false, &env, parse)
}

/// Step 1 on config.yaml's `text`: the stamp decides; an unstamped config is planned (its check is
/// `parse` plus the planned catalog's strict parse), then the listener probe (§A3 1f) runs on the
/// planned document's resolved `listen` and `admin_listen` (after the overlay fold, so an overlay
/// override counts), still before any plugin loads or any write.
fn plan_text(
    config: &Path,
    text: &str,
    migrated: bool,
    providers_flag: bool,
    ignore_overlay: bool,
    env: &dyn Fn(&str) -> Option<OsString>,
    parse: Parse<'_>,
) -> Result<Option<Plan>, String> {
    let version = config_version(text).map_err(|text| format!("CONFIG: {text}"))?;
    match admit(version, migrated, providers_flag).map_err(text_of)? {
        Stamp::Current => Ok(None),
        Stamp::Older(_) => {
            busbar_contract::upgrade::mark_unstamped();
            let facts = facts();
            let listeners = RefCell::new(Vec::new());
            let check = |text: &str, catalog: Option<&str>| -> Result<(), String> {
                *listeners.borrow_mut() = parse(text)?;
                strict_catalog(catalog)
            };
            let plan = busbar_migrate::plan(&Inputs {
                path: config,
                facts: &facts,
                check: &check,
                env,
                interpolate: &busbar_kernel::config::interpolate_env,
                ignore_overlay,
            })
            .map_err(text_of)?;
            let listeners = listeners.into_inner();
            let addresses: Vec<&str> = listeners.iter().map(String::as_str).collect();
            busbar_migrate::probe_listeners(&addresses).map_err(text_of)?;
            Ok(Some(plan))
        }
    }
}

/// Step 2's binding (§3 step 2): the text the boot reads in place of the file at `path` while a
/// plan is held. `None` on a stamped boot and for every file the plan does not hold.
pub(crate) fn held(path: &Path) -> Option<SecureString> {
    held_in(PENDING.get(), path)
}

pub(crate) fn held_in(plan: Option<&Plan>, path: &Path) -> Option<SecureString> {
    plan.and_then(|plan| plan.held(path))
        .map(SecureString::from)
}

/// Step 5's write. `None` with no pending plan (a stamped boot: nothing is entered). Otherwise the
/// plan is written in place, off the boot's runtime thread (the directory lock may wait), and the
/// boot then calls [`restart`].
///
/// # Errors
/// The write's refusal (LIVE_WRITER, CONFIG); config.yaml is then unchanged, never half written.
#[cold]
#[inline(never)]
pub(crate) async fn finish(
    core: Option<std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>>,
) -> Result<Option<Written>, String> {
    finish_settled(Vec::new(), core).await
}

/// LEGACY-KEYFILE-MARKER r2 §3: the held plan's side-table marks, by auth instance name: the pointers
/// whose slot carries its 1.5.5 value on this one converting open. Never a value. A stamped boot has none.
///
/// # Errors
/// CONFIG when a mark names an instance path other than `auth.<name>`.
pub(crate) fn legacy_marks() -> Result<Vec<(String, Vec<String>)>, String> {
    let Some(plan) = PENDING.get() else {
        return Ok(Vec::new());
    };
    let mut by_name: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for mark in plan.legacy_marks() {
        let [kind, name] = mark.instance.as_slice() else {
            return Err("CONFIG: a 1.5.5 credential mark names no instance".to_owned());
        };
        if kind != "auth" {
            return Err(format!(
                "CONFIG: a 1.5.5 credential mark names `{kind}`, which has no marked settlement"
            ));
        }
        by_name
            .entry(name.clone())
            .or_default()
            .push(mark.pointer.clone());
    }
    Ok(by_name.into_iter().collect())
}

/// Whether this boot runs a stamped config.yaml (or none): no plan is held. Step 4's final records
/// commit then carries MIGRATION_COMPLETED, else RECORDS_MIGRATED (§3 4b).
pub(crate) fn stamped() -> bool {
    PENDING.get().is_none()
}

/// Step 4 using the secrets already resolved by the pre-publication boot stages.
pub(crate) async fn records_with_keys(
    core: std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>,
    keys: crate::root::migrate_records::Keys,
) -> Result<(), String> {
    let config = CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(crate::root::cli::resolve_config_path(None)));
    crate::root::migrate_records::step4_with_keys(core, keys, config, stamped()).await
}

/// Step 5 with what every instance's `open` settled (MIGRATE-ON-BOOT r42 §4, `Registry::take_settled`): the
/// bags and CORE_CFG are filed into the re-run document, the lifted secret files written, then the stamp.
/// A refusal of a settled answer writes nothing.
///
/// # Errors
/// As [`finish`], and CONFIG naming the instance index for an answer core cannot file.
#[cold]
#[inline(never)]
pub(crate) async fn finish_settled(
    settled: Vec<busbar_migrate::Settled>,
    core: Option<std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>>,
) -> Result<Option<Written>, String> {
    finish_settled_checked(settled, core, std::sync::Arc::new(|_| Ok(()))).await
}

/// The admitted images' pure candidate check runs again inside the guarded writer after LIFT.
pub(crate) async fn finish_settled_checked(
    settled: Vec<busbar_migrate::Settled>,
    core: Option<std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>>,
    candidate: CandidateCheck,
) -> Result<Option<Written>, String> {
    let Some(plan) = PENDING.get() else {
        return Ok(None);
    };
    let runtime = tokio::runtime::Handle::current();
    let config = CONFIG_PATH.get().cloned().unwrap_or_default();
    tokio::task::spawn_blocking(move || {
        let check = |text: &str, catalog: Option<&str>| {
            strict_parse(text, catalog)?;
            candidate(text)
        };
        match core {
            // 5S, 5d and 5C over the opened store (§A6 "Attempts").
            Some(core) => busbar_migrate::write_with_attempt(
                &crate::root::migrate_records::Store::new(core, runtime),
                plan,
                &settled,
                &check,
                &config,
            ),
            None => busbar_migrate::write_settled(plan, &settled, &check),
        }
    })
    .await
    .map_err(|error| format!("the config.yaml upgrade did not finish its write: {error}"))?
    .map(Some)
    .map_err(text_of)
}

/// Steps 4 and 5 together for a converting boot: step 5's refusals are judged before the store is
/// converted (#328), then the records are converted and config.yaml is written.
///
/// # Errors
/// The records step's refusal, or CONFIG text for a refused document.
pub(crate) async fn convert_and_finish_checked(
    core: std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>,
    keys: crate::root::migrate_records::Keys,
    settled: Vec<busbar_migrate::Settled>,
    candidate: CandidateCheck,
) -> Result<Option<Written>, String> {
    let Some(plan) = PENDING.get() else {
        return Ok(None);
    };
    let runtime = tokio::runtime::Handle::current();
    let config = CONFIG_PATH.get().cloned().unwrap_or_default();
    tokio::task::spawn_blocking(move || {
        let check = |text: &str, catalog: Option<&str>| {
            strict_parse(text, catalog)?;
            candidate(text)
        };
        let store = crate::root::migrate_records::Store::new(core, runtime);
        crate::root::migrate_records::convert_and_write(
            &store, &keys, plan, &settled, &check, &config, false,
        )
        .map(Some)
    })
    .await
    .map_err(|error| format!("the config.yaml upgrade did not finish its write: {error}"))?
}

/// 5W (MIGRATE-ON-BOOT r42 §3): on a stamped boot and on a reload, write what the instances settled back into
/// config.yaml through the patch writer, under the directory lock. `seen` is the text the boot read; when
/// config.yaml is no longer those bytes (an operator edit, a peer's write-back) nothing is written and the
/// next load converts again; equal bytes are not written. The caller logs and audits an `Err` and boots on,
/// the instance serving.
///
/// # Errors
/// The write-back's refusal text (lock not held, a fragment on a current config, an I/O failure).
#[cfg(test)]
#[cold]
#[inline(never)]
pub(crate) fn write_back_settled(
    config: &Path,
    seen: &str,
    settled: &[busbar_migrate::Settled],
) -> Result<busbar_migrate::WroteBack, String> {
    fn env(name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
    busbar_migrate::write_back(config, &busbar_migrate::digest(seen), &|now| {
        let applied = busbar_migrate::apply_settled(now, config, settled, true, env)?;
        busbar_migrate::write_secrets(applied.secrets())?;
        Ok(applied.text().to_owned())
    })
    .map_err(text_of)
}

/// After step 5 wrote (or found a peer's stamp, (q)): hand an armed first start over while its
/// store is still open, close every instance the boot opened, then re-execute (once). Returns only
/// the re-exec's failure.
pub(crate) fn restart<T>(
    written: Written,
    owned: T,
    close: impl FnOnce(T),
    exec: impl FnOnce() -> String,
) -> String {
    match written {
        Written::Stamped => {
            tracing::info!(target: "busbar::migrate", "config.yaml upgraded and stamped")
        }
        Written::StampedByPeer => tracing::info!(
            target: "busbar::migrate",
            "config.yaml was upgraded by another busbar while this one waited"
        ),
    }
    crate::root::exit::hand_over_before_exec();
    close(owned);
    exec()
}

/// The native Store-open operation's exact core-owned refusal, using its retained resolution verdict.
pub(crate) fn native_admission_refusal(n: u64, verdict: Result<bool, String>) -> String {
    let dir = CONFIG_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
    admit_answer(n, Some(verdict), &dir)
        .err()
        .unwrap_or_else(|| {
            "CONFIG: Store recovery admission refused; nothing was written".to_owned()
        })
}

/// The gate's verdict for `n` rows, from the bootstrap's at-rest verdict `keys` (`None` = no
/// bootstrap resolved one) and the config directory `dir`.
pub(crate) fn admit_answer(
    n: u64,
    keys: Option<Result<bool, String>>,
    dir: &Path,
) -> Result<(), String> {
    if n == 0 {
        return Ok(());
    }
    match keys {
        Some(Ok(true)) => Ok(()),
        Some(Ok(false)) => Err(text_add_key(n, dir)),
        Some(Err(text)) => Err(format!("CONFIG: {text}")),
        None => Err(format!(
            "CONFIG: this 1.5.5 store holds `{n}` recoverable credentials stored in the clear, \
             and this boot resolved no `auth.signing_key` before the store opened, so it \
             cannot seal them; nothing was written"
        )),
    }
}

/// TEXT_ADD_KEY (§3): core's text when a store holds `n` recoverable rows and no signing key is
/// configured, naming the absolute config directory `dir`.
pub(crate) fn text_add_key(n: u64, dir: &Path) -> String {
    let key = dir.join("signing.key");
    let key = key.display();
    format!(
        "CONFIG: this 1.5.5 store holds `{n}` recoverable credentials (SigV4 secret keys) stored \
         in the clear, and 1.6.0 stores them only sealed, under a key derived from \
         `auth.signing_key`. Nothing was written. Set `auth.signing_key`, then boot 1.6.0 \
         again:\n  (1) `openssl rand -hex 32 > {key} && chmod 600 {key}`. Use this same file \
         on every node that shares this store.\n  (2) add to config.yaml: \
         `auth: {{signing_key: {{file: {key}}}}}`."
    )
}

/// The absolute directory holding `config`.
pub(crate) fn config_dir(config: &Path) -> PathBuf {
    let absolute = std::path::absolute(config).unwrap_or_else(|_| config.to_path_buf());
    absolute
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
}

/// What the migration needs from the gateway's installed state (§3 1, kind-level only; no plane
/// or plugin is named): the fallback plane's billable classes it does not bill as fees, without the
/// reserved units (the units a 1.5.5 `rate_card` lane priced at nothing), and every key the 1.6.0
/// providers catalog reads (the catalog grammar's and the installed planes' declared keys).
fn facts() -> busbar_migrate::Facts {
    let planes = busbar_kernel::plane_driver::registry::plane_decls();
    let mut open_units: Vec<String> = Vec::new();
    for plane in planes.iter().filter(|plane| plane.fallback) {
        for billable in plane.billable_classes.iter() {
            let class = billable.class;
            let open = !plane.fee_units.contains(&class)
                && !busbar_contract::records::RESERVED_UNITS.contains(&class);
            if open && !open_units.iter().any(|unit| unit == class) {
                open_units.push(class.to_owned());
            }
        }
    }
    let mut catalog_keys: Vec<String> = busbar_kernel::config::providers::catalog_grammar_keys()
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    if let Some(declared) = busbar_kernel::plane_driver::door::provider_keys(planes) {
        catalog_keys.extend(declared.catalog.keys.iter().map(|key| key.name.clone()));
    }
    busbar_migrate::Facts::of_process(open_units, catalog_keys)
}

/// The boot's own strict parse of a planned document (CHECK, §A3 1), under the start grammar. The
/// migration hands it the document interpolated with the boot's Strict interpolation (an unset
/// variable already refused, as 1.5.5 would not have booted); the listener addresses it resolves
/// feed 1f.
fn parse_planned(text: &str) -> Result<Vec<String>, String> {
    // The boot reads under the image prepare's grammar (native plane sections such as a linked plane's settled block);
    // the upgraded document is read under the same, else the start scan's.
    let grammar = match crate::root::boot::images::start_images_grammar() {
        Some(grammar) => grammar,
        None => crate::root::boot::start_grammar()?,
    };
    let deploy = busbar_kernel::config::deploy_from_yaml_str(text, grammar)
        .map_err(|error| format!("config.yaml: {error}"))?;
    Ok(vec![deploy.listen, deploy.admin_listen])
}

/// The strict parse of the planned providers catalog (§3 1k), when the upgrade plans one.
fn strict_catalog(catalog: Option<&str>) -> Result<(), String> {
    match catalog {
        Some(catalog) => {
            let grammar = match crate::root::boot::images::start_images_grammar() {
                Some(grammar) => grammar,
                None => crate::root::boot::start_grammar()?,
            };
            busbar_kernel::config::providers::catalog_from_str(catalog, grammar)
                .map(drop)
                .map_err(|error| format!("{}: {error}", busbar_migrate::CATALOG_FILE))
        }
        None => Ok(()),
    }
}

/// The write's check (step 5's re-run): the planned document and catalog, strictly parsed.
fn strict_parse(text: &str, catalog: Option<&str>) -> Result<(), String> {
    parse_planned(text)?;
    strict_catalog(catalog)
}

/// Step 1's verdict on the stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stamp {
    /// `config_version` is `CONFIG_FORMAT`: strict parse, nothing else is read (257c).
    Current,
    /// An older format (0 = 1.5.x): plan, then write at step 5.
    Older(u64),
}

/// Step 1 (§3): from the one field, the re-exec marker and whether `--providers` was given.
pub(crate) fn admit(version: u64, migrated: bool, providers_flag: bool) -> Result<Stamp, Refusal> {
    if version > CONFIG_FORMAT {
        return Err(Refusal::Newer { found: version });
    }
    if version == CONFIG_FORMAT {
        return Ok(Stamp::Current);
    }
    if migrated {
        return Err(Refusal::Verify);
    }
    if providers_flag {
        return Err(Refusal::Config(busbar_migrate::PROVIDERS_TEXT.to_owned()));
    }
    Ok(Stamp::Older(version))
}

/// config.yaml, bounded as the migration bounds it, as UTF-8; `None` when it does not exist.
fn read_config(config: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let file = match std::fs::File::open(config) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("CONFIG: cannot read {}: {error}", config.display())),
    };
    let mut bytes = Vec::new();
    file.take(busbar_migrate::MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("CONFIG: cannot read {}: {error}", config.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > busbar_migrate::MAX_CONFIG_BYTES {
        return Err(format!(
            "CONFIG: {} is larger than {} bytes",
            config.display(),
            busbar_migrate::MAX_CONFIG_BYTES
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("CONFIG: {} is not UTF-8 text", config.display()))
}

fn text_of(refusal: Refusal) -> String {
    refusal.to_string()
}

/// After step 5 wrote config.yaml: one audit record per security-relevant change the plan reported
/// under a BUSBAR code (the retired cloud-metadata carve-outs, BUSBAR-3411; the ungoverned binding,
/// BUSBAR-3408). The record names paths and never a value; it is written only for a write this
/// process made, never for a peer's stamp (#293, via the #291 settled write path).
pub(crate) fn record_completed_changes(written: &Written) {
    if !matches!(written, Written::Stamped) {
        return;
    }
    let Some(plan) = PENDING.get() else {
        return;
    };
    for (action, subject) in audit_rows(plan.report()) {
        busbar_kernel::audit_ring::AUDIT.record_by(
            action,
            &subject,
            busbar_kernel::audit_ring::OUTCOME_APPLIED,
            "system",
        );
    }
}

/// A report line that carries a BUSBAR code is one the operator must act on or know about (the
/// retired cloud-metadata carve-outs, BUSBAR-3411; the binding written to keep 1.5.5's ungoverned
/// access, BUSBAR-3408): it is logged as a warning, not information.
fn warns(line: &str) -> bool {
    line.starts_with("BUSBAR-")
}

/// The audit rows a completed step-5 write owes: one `(action, subject)` per security-relevant
/// change the plan reported under a BUSBAR code. A subject names configuration paths, never a
/// value (#293).
fn audit_rows(report: &[String]) -> Vec<(&'static str, String)> {
    report
        .iter()
        .filter_map(|line| {
            let removed = line
                .strip_prefix("BUSBAR-3411: removed the retired cloud-metadata carve-out key(s) ")
                .and_then(|rest| rest.split_once(';'))
                .map(|(paths, _)| ("migrate.metadata_carve_out_removed", paths));
            // The binding written to keep 1.5.5's ungoverned access: a grant of every pool with
            // no budget, audited by its path.
            let granted = || {
                line.strip_prefix("BUSBAR-3408: ")
                    .and_then(|rest| rest.split_once(" was written by the migration"))
                    .map(|(path, _)| ("migrate.ungoverned_binding_added", path))
            };
            removed
                .or_else(granted)
                .map(|(action, subject)| (action, subject.to_owned()))
        })
        .collect()
}

/// Replace this process with a fresh image of itself: the same executable and argv, with
/// `BUSBAR_MIGRATED=1`. Returns only the failure.
pub(crate) fn reexec() -> String {
    let executable: PathBuf = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return format!(
                "config.yaml was upgraded, but busbar cannot find its own executable to restart \
                 onto it ({error}); start busbar again"
            )
        }
    };
    close_on_exec_from_3();
    let error = crate::root::exit::exec(
        std::process::Command::new(&executable)
            .args(std::env::args_os().skip(1))
            .env(busbar_migrate::MIGRATED_ENV, "1"),
    );
    format!(
        "config.yaml was upgraded, but busbar could not restart onto it ({}: {error}); start \
         busbar again",
        executable.display()
    )
}

/// Defence in depth behind the primary rule [`restart`] keeps: every instance the boot opened (a
/// plugin's descriptors included) is closed before the exec. A descriptor a plugin opened without
/// close-on-exec and never closed would still reach the new image, so every descriptor >= 3 is
/// marked close-on-exec here, just before it (0-2 stay the operator's stdio).
///
/// Linux >= 5.11 marks the whole range with one `close_range(CLOSE_RANGE_CLOEXEC)`. Elsewhere
/// (macOS, an older kernel, a seccomp profile that denies `close_range`) it is an `fcntl` loop up
/// to `min(max(sysconf(_SC_OPEN_MAX), 1024), 65536)`: there, a descriptor numbered 65536 or above
/// is NOT covered. `allow_filesystem(false)` keeps close_fds 0.3.2 off its `/dev/fd` and
/// `/proc/self/fd` walk, which is unsound (see its cargo-vet exemption).
fn close_on_exec_from_3() {
    #[cfg(unix)]
    close_fds::CloseFdsBuilder::new()
        .allow_filesystem(false)
        .cloexecfrom(3);
}

#[cfg(test)]
#[path = "tests/migrate_seam.rs"]
mod tests;

/// Read before canonical instances open, so normalization never overwrites a later operator edit.
pub(crate) fn normalization_source() -> Result<Option<(PathBuf, SecureString)>, String> {
    if !stamped() {
        return Ok(None);
    }
    CONFIG_PATH
        .get()
        .map(|path| {
            busbar_migrate::read_config(path)
                .map(|text| (path.clone(), SecureString::from(text)))
                .map_err(text_of)
        })
        .transpose()
}

/// Validate the complete candidate before treating guarded write failure as an optional normalization.
pub(crate) async fn normalize_settled(
    source: Option<(PathBuf, SecureString)>,
    settled: Vec<busbar_migrate::Settled>,
    candidate: CandidateCheck,
) -> Result<(), String> {
    let Some((path, seen)) = source else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || {
        let applied = busbar_migrate::apply_settled(seen.as_str(), &path, &settled, true, |name| {
            std::env::var(name).ok()
        })
        .map_err(text_of)?;
        strict_parse(applied.text(), None)?;
        candidate(applied.text())?;
        let wanted = SecureString::from(applied.text());
        match busbar_migrate::write_back(&path, &busbar_migrate::digest(seen.as_str()), &|_| {
            Ok(wanted.as_str().to_owned())
        }) {
            Ok(_) => {}
            Err(_) => tracing::warn!(
                "the validated normalization could not be written; the authored file is kept"
            ),
        }
        Ok(())
    })
    .await
    .map_err(|_| "the normalization writer did not finish".to_owned())?
}
