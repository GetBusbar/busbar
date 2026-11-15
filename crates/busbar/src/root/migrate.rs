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

/// The absolute directory of config.yaml, which TEXT_ADD_KEY names. Set by [`run`].
static CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Step 1. `Ok` when the boot may go on: stamped, absent (the config reader reports that in its own
/// words), or planned and held for [`finish`]. On every boot it first installs the recoverable
/// gate's answer for the loader ([`migrate_admit`]): a stamped config can still meet a 1.5.5
/// store restored beside it.
///
/// # Errors
/// The migration's refusal text (NEWER, VERIFY, CONFIG, UNSUPPORTED), nothing written.
#[cold]
#[inline(never)]
pub(crate) fn run(config: &Path, providers_flag: bool) -> Result<(), String> {
    let _ = CONFIG_DIR.set(config_dir(config));
    let _ = busbar_plugin_loader::dispatch::migrate::install_admit(migrate_admit);
    if !config.exists() {
        return Ok(());
    }
    let version =
        config_version(&read_bounded(config)?).map_err(|text| format!("CONFIG: {text}"))?;
    let migrated = std::env::var_os(MIGRATED_ENV).is_some();
    match admit(version, migrated, providers_flag).map_err(text_of)? {
        Stamp::Current => Ok(()),
        Stamp::Older(_) => {
            let plan = busbar_migrate::plan(&Inputs {
                path: config,
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

/// THE RECOVERABLE GATE (§3 step 2 (a); the loader's `migrate.admit` answer): whether this boot
/// can seal the `n` recoverable 1.5.5 credentials a store's data step is about to hand core. Core
/// answers from its own config alone, through the at-rest key the store bootstrap resolved before
/// the store opened, with the resolver it built from the store's secret instances. The text is the
/// process's for its life (the host-service rule): at most one per store per boot.
#[cold]
#[inline(never)]
fn migrate_admit(n: u64) -> Result<(), &'static str> {
    let dir = CONFIG_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
    admit_answer(n, busbar_kernel::appbuild::bootstrap_at_rest(), &dir)
        .map_err(|text| -> &'static str { text.leak() })
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
             and this boot resolved no `credentials.at_rest` before the store opened, so it \
             cannot seal them; nothing was written"
        )),
    }
}

/// TEXT_ADD_KEY (§3): core's text when a store holds `n` recoverable rows and no at-rest key is
/// configured, naming the absolute config directory `dir`.
pub(crate) fn text_add_key(n: u64, dir: &Path) -> String {
    let key = dir.join("at-rest.key");
    let key = key.display();
    format!(
        "CONFIG: this 1.5.5 store holds `{n}` recoverable credentials (SigV4 secret keys) stored \
         in the clear, and 1.6.0 stores them only sealed. Nothing was written. Add an at-rest \
         key, then boot 1.6.0 again:\n  (1) `openssl rand -hex 32 > {key} && chmod 600 {key}`. \
         Use this same file on every node that shares this store.\n  (2) add to config.yaml: \
         `credentials: {{at_rest: {{key: {{file: {key}}}}}}}`.\n1.5.5 does not accept this \
         block, so add it only after every 1.5.5 instance has stopped. To roll back to 1.5.5 \
         later, delete it from `config.yaml.1.5.5` first (docs/migration-1.6, \"At-rest key\")."
    )
}

/// The absolute directory holding `config`.
pub(crate) fn config_dir(config: &Path) -> PathBuf {
    let absolute = std::path::absolute(config).unwrap_or_else(|_| config.to_path_buf());
    absolute
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
}

/// The boot's own strict parse of a planned document, under the start grammar.
fn strict_parse(text: &str) -> Result<(), String> {
    let grammar = crate::root::boot::start_grammar()?;
    busbar_kernel::config::deploy_from_yaml_str(text, grammar)
        .map(drop)
        .map_err(|error| format!("config.yaml: {error}"))
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
