// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::{Path, PathBuf};

const MAX_KEEP: u32 = 64;

pub(crate) type FailedStep = &'static str;

pub(crate) fn rotate(path: &Path, keep: u32) -> (bool, Vec<FailedStep>) {
    let keep = keep.clamp(1, MAX_KEEP);

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
