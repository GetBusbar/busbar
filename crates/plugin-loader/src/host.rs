// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::Path;

const MAX_KEEP: u32 = 64;

pub(crate) type FailedStep = &'static str;

/// `<base>.<i>`, written into `name` (cleared first, its capacity kept).
fn archive<'a>(name: &'a mut OsString, base: &OsStr, i: u32) -> &'a Path {
    name.clear();
    name.push(base);
    let _ = write!(name, ".{i}");
    Path::new(name)
}

pub(crate) fn rotate(path: &Path, keep: u32) -> (bool, Vec<FailedStep>) {
    let keep = keep.clamp(1, MAX_KEEP);
    let base = path.as_os_str();
    // The two archive names a step needs, reused by every step.
    let mut from = OsString::with_capacity(base.len() + 4);
    let mut to = OsString::with_capacity(base.len() + 4);
    // busbar:expect(bp::fresh_buffer, reason = "error: names the rotation steps that failed; empty, never allocated, when none do")
    let mut failed = Vec::new();
    let oldest = archive(&mut from, base, keep);
    if oldest.exists() && std::fs::remove_file(oldest).is_err() {
        failed.push("retention");
    }
    for i in (1..keep).rev() {
        let (from, to) = (archive(&mut from, base, i), archive(&mut to, base, i + 1));
        if from.exists() && std::fs::rename(from, to).is_err() {
            failed.push("shift");
        }
    }
    let renamed = std::fs::rename(path, archive(&mut to, base, 1)).is_ok();
    if !renamed {
        failed.push("rename");
    }
    (renamed, failed)
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
