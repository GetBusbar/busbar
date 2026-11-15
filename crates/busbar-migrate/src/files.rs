// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The file side of step 1's probes and step 5's write (MIGRATE-ON-BOOT §A3 1, 5b, 5d): bounded
//! reads, the in-place probes, `create_like` (a new file with the source's mode and owner), the
//! backup copy and the fsynced rename. Temporary names are per process and `O_EXCL`.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::{Refusal, MAX_CONFIG_BYTES};

/// `<file><suffix>` beside `file`.
pub(crate) fn sibling(file: &Path, suffix: &str) -> PathBuf {
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    file.with_file_name(name)
}

fn directory(file: &Path) -> PathBuf {
    match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn io_refusal(path: &Path, what: &str, error: &std::io::Error) -> Refusal {
    Refusal::Config(format!(
        "{what} {}: {error}; nothing was written",
        path.display()
    ))
}

pub(crate) fn read_bounded(path: &Path) -> Result<String, Refusal> {
    let file = File::open(path).map_err(|error| io_refusal(path, "cannot read", &error))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_refusal(path, "cannot read", &error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(Refusal::Config(format!(
            "{} is larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| Refusal::Config(format!("{} is not UTF-8 text", path.display())))
}

/// Step 1's probes, before anything else runs (§A3 1, "writable first" and "same mount"):
/// config.yaml opens for writing (no create, no truncate, closed at once), and in its directory a
/// probe file can be created `O_EXCL`, renamed, and config.yaml hard-linked, on the same device.
/// Every probe name is removed again; nothing else is touched.
pub(crate) fn probe_in_place(config: &Path) -> Result<(), Refusal> {
    let read_only = |error: &std::io::Error| {
        Refusal::Config(format!(
            "{} predates 1.6.0 and is read-only ({error}); the one-time upgrade rewrites it. Boot \
             this deployment once with its config directory writable, in place and in its own \
             environment (the same BUSBAR_CONFIG_OVERLAY, the same paths), then make it \
             read-only again",
            config.display()
        ))
    };
    OpenOptions::new()
        .write(true)
        .open(config)
        .map_err(|error| read_only(&error))?;
    let dir = directory(config);
    let file_dev = fs::metadata(config)
        .map_err(|error| io_refusal(config, "cannot stat", &error))?
        .dev();
    let dir_dev = fs::metadata(&dir)
        .map_err(|error| io_refusal(&dir, "cannot stat", &error))?
        .dev();
    let single_file = |why: &str| {
        Refusal::Config(format!(
            "{} is mounted as a single file (or its directory cannot link/rename it: {why}); the \
             one-time upgrade replaces it by rename and keeps config.yaml.1.5.5 beside it. Mount \
             the config directory instead (for example `-v $PWD/busbar:/etc/busbar`), boot once, \
             then you may mount it read-only again",
            config.display()
        ))
    };
    if file_dev != dir_dev {
        return Err(single_file("it is on another device than its directory"));
    }
    let pid = std::process::id();
    let one = sibling(config, &format!(".busbar-probe.{pid}"));
    let two = sibling(config, &format!(".busbar-probe2.{pid}"));
    let three = sibling(config, &format!(".busbar-probe3.{pid}"));
    for leftover in [&one, &two, &three] {
        let _ = fs::remove_file(leftover);
    }
    let outcome = (|| -> Result<(), Refusal> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&one)
            .map_err(|error| match error.kind() {
                ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => read_only(&error),
                _ => single_file(&error.to_string()),
            })?;
        fs::rename(&one, &two).map_err(|error| single_file(&error.to_string()))?;
        fs::hard_link(config, &three).map_err(|error| single_file(&error.to_string()))?;
        Ok(())
    })();
    for probe in [&one, &two, &three] {
        let _ = fs::remove_file(probe);
    }
    outcome
}

/// 5R's precondition: a backup already present must hold exactly the source bytes (a crash after
/// 5b's link); one with other bytes is refused, nothing written.
pub(crate) fn backup_absent_or_equal(backup: &Path, source: &[u8]) -> Result<(), Refusal> {
    match fs::read(backup) {
        Ok(bytes) if bytes == source => Ok(()),
        Ok(_) => Err(Refusal::Config(format!(
            "{} is present and holds other bytes than config.yaml; it is the 1.5.5 backup this \
             upgrade keeps. Move it away (it may be an earlier rollback's copy), then boot again; \
             nothing was written",
            backup.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_refusal(backup, "cannot read", &error)),
    }
}

/// 5b: write `bytes` to `<config>.busbar-new.<pid>` (`O_EXCL`), with config.yaml's permission bits
/// (set by `fchmod`, not left to the umask) and, where this process may, its owner; fsynced.
pub(crate) fn create_like(config: &Path, bytes: &[u8]) -> Result<PathBuf, Refusal> {
    create_like_at(config, config, bytes)
}

/// 5a2 and 5b: write `bytes` to `<target>.busbar-new.<pid>` (`O_EXCL`) with `model`'s permission
/// bits (set by `fchmod`, not left to the umask) and, where this process may, its owner; fsynced.
/// The caller renames it over `target`.
pub(crate) fn create_like_at(
    model: &Path,
    target: &Path,
    bytes: &[u8],
) -> Result<PathBuf, Refusal> {
    let source = fs::metadata(model).map_err(|error| io_refusal(model, "cannot stat", &error))?;
    let mode = source.permissions().mode() & 0o7777;
    let fresh = sibling(target, &format!(".busbar-new.{}", std::process::id()));
    let _ = fs::remove_file(&fresh);
    let written = (|| -> Result<(), Refusal> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&fresh)
            .map_err(|error| io_refusal(&fresh, "cannot create", &error))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| io_refusal(&fresh, "cannot set the mode of", &error))?;
        // Another owner's file stays this process's when it may not hand it over; the mode is kept.
        let _ = std::os::unix::fs::fchown(&file, Some(source.uid()), Some(source.gid()));
        let set = file
            .metadata()
            .map_err(|error| io_refusal(&fresh, "cannot stat", &error))?
            .permissions()
            .mode()
            & 0o7777;
        if set != mode {
            return Err(Refusal::Config(format!(
                "{} did not take the mode {mode:o} of {} (it has {set:o}); the upgrade keeps \
                 the source's mode. Nothing was renamed",
                fresh.display(),
                model.display()
            )));
        }
        file.write_all(bytes)
            .map_err(|error| io_refusal(&fresh, "cannot write", &error))?;
        file.sync_all()
            .map_err(|error| io_refusal(&fresh, "cannot fsync", &error))?;
        Ok(())
    })();
    match written {
        Ok(()) => Ok(fresh),
        Err(refusal) => {
            let _ = fs::remove_file(&fresh);
            Err(refusal)
        }
    }
}

/// 5b: keep the source bytes as `config.yaml.1.5.5`, a byte copy (its own inode, so no later
/// in-place rewrite of config.yaml can reach the rollback copy): written with config.yaml's mode
/// and owner and fsynced through [`create_like_at`], then linked into place without replacing
/// anything, and the directory fsynced, all before the stamped file is renamed over config.yaml.
/// A backup already present was checked equal by 5R and is kept.
pub(crate) fn keep_backup(config: &Path, backup: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    let copy = create_like_at(config, backup, bytes)?;
    let linked = fs::hard_link(&copy, backup);
    let _ = fs::remove_file(&copy);
    match linked {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_refusal(backup, "cannot keep the backup", &error)),
    }
    sync_dir(config)
}

/// 5d: rename the new file over config.yaml, then fsync the directory.
pub(crate) fn replace(fresh: &Path, config: &Path) -> Result<(), Refusal> {
    if let Err(error) = fs::rename(fresh, config) {
        let _ = fs::remove_file(fresh);
        return Err(io_refusal(config, "cannot replace", &error));
    }
    sync_dir(config)
}

fn sync_dir(config: &Path) -> Result<(), Refusal> {
    let dir = directory(config);
    File::open(&dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_refusal(&dir, "cannot fsync", &error))
}

#[cfg(test)]
#[path = "tests/files_tests.rs"]
mod tests;
