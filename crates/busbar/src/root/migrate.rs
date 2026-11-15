// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migrate-on-boot seam (MIGRATE-ON-BOOT r42 §3): the gateway's only caller of
//! `busbar_migrate`.
//!
//! [`run`] is step 1, from `main` after logging and before the runtime: it reads config.yaml's one
//! field. A stamped config (`config_version: 1`) boots with nothing else read. A newer one is
//! refused NEWER; an unstamped one in the image this seam re-executed is refused VERIFY, so the
//! upgrade never loops. Any other unstamped config is planned in memory (nothing written) and the
//! plan is held for [`finish`], step 5: once every instance has opened, just before the first
//! listener serves, the plan is written in place and the process re-executes itself, with the same
//! argv and `BUSBAR_MIGRATED=1`, onto the stamped file.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use busbar_contract::upgrade::{config_version, CONFIG_FORMAT, MIGRATED_ENV};
use busbar_migrate::{Inputs, Plan, Refusal, Written};

/// The plan step 1 made for an unstamped config, written by [`finish`].
static PENDING: OnceLock<Plan> = OnceLock::new();

/// Step 1. `Ok` when the boot may go on: stamped, absent (the config reader reports that in its own
/// words), or planned and held for [`finish`].
///
/// # Errors
/// The migration's refusal text (NEWER, VERIFY, CONFIG, UNSUPPORTED), nothing written.
#[cold]
#[inline(never)]
pub(crate) fn run(config: &Path, providers_flag: bool) -> Result<(), String> {
    if !config.exists() {
        return Ok(());
    }
    let version =
        config_version(&read_bounded(config)?).map_err(|text| format!("CONFIG: {text}"))?;
    let migrated = std::env::var_os(MIGRATED_ENV).is_some();
    match admit(version, migrated, providers_flag).map_err(text_of)? {
        Stamp::Current => Ok(()),
        Stamp::Older(_) => {
            busbar_contract::upgrade::mark_unstamped();
            let facts = facts();
            let plan = busbar_migrate::plan(&Inputs {
                path: config,
                facts: &facts,
                check: &strict_parse,
            })
            .map_err(text_of)?;
            for line in plan.report() {
                tracing::info!(target: "busbar::migrate", "{line}");
            }
            tracing::info!(
                target: "busbar::migrate",
                "{} predates 1.6.0: upgraded in memory; it is rewritten in place once every \
                 instance has opened (the original is kept as {})",
                config.display(),
                busbar_migrate::backup_path(config).display()
            );
            let _ = PENDING.set(plan);
            Ok(())
        }
    }
}

/// Step 5. With no pending plan (a stamped boot) this returns at once. Otherwise the plan is
/// written in place and the process re-executes itself onto the stamped file; it returns only
/// with the refusal.
///
/// # Errors
/// The write's refusal (LIVE_WRITER, CONFIG), or the re-exec's failure; config.yaml is then either
/// unchanged or stamped, never half written.
#[cold]
#[inline(never)]
pub(crate) fn finish() -> Result<(), String> {
    let Some(plan) = PENDING.get() else {
        return Ok(());
    };
    match busbar_migrate::write(plan, &strict_parse).map_err(text_of)? {
        Written::Stamped => {
            tracing::info!(target: "busbar::migrate", "config.yaml upgraded and stamped")
        }
        Written::StampedByPeer => tracing::info!(
            target: "busbar::migrate",
            "config.yaml was upgraded by another busbar while this one waited"
        ),
    }
    Err(reexec())
}

/// The boot's own strict parse of a planned document and of the planned providers catalog (both
/// interpolated by the migration as the boot interpolates them), under the start grammar.
fn strict_parse(text: &str, catalog: Option<&str>) -> Result<(), String> {
    let grammar = crate::root::boot::start_grammar()?;
    busbar_kernel::config::deploy_from_yaml_str(text, grammar)
        .map(drop)
        .map_err(|error| format!("config.yaml: {error}"))?;
    match catalog {
        Some(catalog) => busbar_kernel::config::providers::catalog_from_str(catalog, grammar)
            .map(drop)
            .map_err(|error| format!("{}: {error}", busbar_migrate::CATALOG_FILE)),
        None => Ok(()),
    }
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

/// config.yaml, bounded as the migration bounds it, as UTF-8.
fn read_bounded(config: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(config)
        .and_then(|file| {
            file.take(busbar_migrate::MAX_CONFIG_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(|error| format!("CONFIG: cannot read {}: {error}", config.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > busbar_migrate::MAX_CONFIG_BYTES {
        return Err(format!(
            "CONFIG: {} is larger than {} bytes",
            config.display(),
            busbar_migrate::MAX_CONFIG_BYTES
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("CONFIG: {} is not UTF-8 text", config.display()))
}

fn text_of(refusal: Refusal) -> String {
    refusal.to_string()
}

/// Replace this process with a fresh image of itself: the same executable and argv, with
/// `BUSBAR_MIGRATED=1`. Returns only the failure.
fn reexec() -> String {
    use std::os::unix::process::CommandExt;
    let executable: PathBuf = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return format!(
                "config.yaml was upgraded, but busbar cannot find its own executable to restart \
                 onto it ({error}); start busbar again"
            )
        }
    };
    let error = std::process::Command::new(&executable)
        .args(std::env::args_os().skip(1))
        .env(busbar_migrate::MIGRATED_ENV, "1")
        .exec();
    format!(
        "config.yaml was upgraded, but busbar could not restart onto it ({}: {error}); start \
         busbar again",
        executable.display()
    )
}

#[cfg(test)]
#[path = "tests/migrate_seam.rs"]
mod tests;
