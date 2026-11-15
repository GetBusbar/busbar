// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 5L, the config directory lock (MIGRATE-ON-BOOT §A3 5L): `<config>.busbar-lock` (0600, never
//! removed, never read for content) held with `File::try_lock` (exclusive; flock on Linux and
//! macOS, released by the kernel when the holder dies), retried every 250 ms for at most 120 s.
//! Two busbars upgrading one directory serialise here; the second re-reads the stamp and finds the
//! peer's work. Holding it, a dead holder's leftover temporaries are removed.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::files::sibling;
use crate::Refusal;

const RETRY: Duration = Duration::from_millis(250);
const BOUND: Duration = Duration::from_secs(120);

/// Leftovers only a dead holder leaves: a new file is written only under the lock, so no live
/// process owns one while this one holds it. (Step 1's probes run unlocked; each process removes
/// its own, by pid, before it probes.)
const LEFTOVERS: [&str; 1] = [".busbar-new."];

/// The held lock; dropping it releases the lock.
pub(crate) struct Held {
    _file: File,
}

impl Held {
    pub(crate) fn take(config: &Path) -> Result<Self, Refusal> {
        Self::take_within(config, BOUND)
    }

    pub(crate) fn take_within(config: &Path, bound: Duration) -> Result<Self, Refusal> {
        let path = sibling(config, ".busbar-lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|error| {
                Refusal::Config(format!(
                    "cannot open the upgrade lock {}: {error}; nothing was written",
                    path.display()
                ))
            })?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if started.elapsed() < bound => {
                    std::thread::sleep(RETRY);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(Refusal::Config(format!(
                        "another busbar is upgrading this config directory ({}); if none is, \
                         stop every busbar and boot again; nothing was written",
                        path.display()
                    )));
                }
                Err(TryLockError::Error(error)) => {
                    return Err(Refusal::Config(format!(
                        "cannot lock {} ({error}); the one-time upgrade needs a filesystem with \
                         file locks for config.yaml's directory; nothing was written",
                        path.display()
                    )));
                }
            }
        }
        sweep(config);
        Ok(Self { _file: file })
    }
}

/// Remove a dead holder's temporaries beside config.yaml.
fn sweep(config: &Path) {
    let (Some(dir), Some(name)) = (config.parent(), config.file_name()) else {
        return;
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let name = name.to_string_lossy();
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.file_name();
        let file = file.to_string_lossy();
        let leftover = file
            .strip_prefix(name.as_ref())
            .is_some_and(|rest| LEFTOVERS.iter().any(|tail| rest.starts_with(tail)));
        if leftover {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
#[path = "tests/lock_tests.rs"]
mod tests;
