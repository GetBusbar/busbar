// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S ROTATION BY RENAME: the one home of the request-log file rotation rule the plugin log
//! files ([`crate::dispatch::log_file`]) rotate by — drop the oldest archive, shift the rest up,
//! rename the live file to `<path>.1` — each failed step recorded, never a truncation. A plugin's
//! own destinations are appended to and rotated by the kernel's disk lane (`disk.append`).

use std::path::{Path, PathBuf};

/// The most archives a rotation may keep — a bound on the renames one rotation can cost.
const MAX_KEEP: u32 = 64;

/// A rotation step that failed: `retention` (dropping the oldest archive), `shift` (moving an
/// archive up) or `rename` (the live file to `<path>.1`).
pub(crate) type FailedStep = &'static str;

/// Rotate `path` by rename, keeping `keep` archives: drop the oldest, shift the rest up, rename the
/// live file to `<path>.1`. Whether the live file was renamed, and each failed step: a failed step
/// is recorded and the rest still run; a failed final rename leaves the live file in place to keep
/// being appended to, never truncated.
pub(crate) fn rotate(path: &Path, keep: u32) -> (bool, Vec<FailedStep>) {
    let keep = keep.clamp(1, MAX_KEEP);
    // `<path>.<i>`, appended to the path's own bytes: a name that is not UTF-8 stays itself.
    let archive = |i: u32| {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".{i}"));
        PathBuf::from(name)
    };
    let mut failed = Vec::new();
    let oldest = archive(keep);
    if oldest.exists() && std::fs::remove_file(&oldest).is_err() {
        failed.push("retention");
    }
    for i in (1..keep).rev() {
        let (from, to) = (archive(i), archive(i + 1));
        if from.exists() && std::fs::rename(&from, &to).is_err() {
            failed.push("shift");
        }
    }
    let renamed = std::fs::rename(path, archive(1)).is_ok();
    if !renamed {
        failed.push("rename");
    }
    (renamed, failed)
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
