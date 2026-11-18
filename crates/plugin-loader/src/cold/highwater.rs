// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::highwater`: the first-party anti-downgrade floor's boot-time load and
//! persist.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::highwater::HIGH_WATER_FILE;
use crate::sign::{valid_name, valid_semver};

/// Reads the floor under `dir`, read once when the plugin registry loads: its file, its usable
/// marks, and a note naming why the floor (or some of its entries) could not be used.
#[cold]
pub(crate) fn load(dir: &Path) -> (PathBuf, BTreeMap<String, String>, Option<String>) {
    let path = dir.join(HIGH_WATER_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (path, BTreeMap::new(), None);
        }
        Err(e) => {
            let note = format!(
                "could not read the first-party anti-downgrade floor at {}: {e}. Booting \
                 with NO first-party floor — an old signed first-party artifact would not \
                 be refused until the floor is re-established by a successful load.",
                path.display()
            );
            return (path, BTreeMap::new(), Some(note));
        }
    };
    let parsed: BTreeMap<String, String> = match busbar_contract::json::parse(&bytes) {
        Ok(m) => m,
        Err(e) => {
            let note = format!(
                "the first-party anti-downgrade floor at {} is not readable JSON ({e}). \
                 Booting with NO first-party floor — an old signed first-party artifact \
                 would not be refused until the floor is re-established by a successful \
                 load.",
                path.display()
            );
            return (path, BTreeMap::new(), Some(note));
        }
    };
    let mut dropped = Vec::new();
    let marks: BTreeMap<String, String> = parsed
        .into_iter()
        .filter(|(name, version)| {
            let ok = valid_name(name) && valid_semver(version);
            if !ok {
                dropped.push(name.clone());
            }
            ok
        })
        .collect();
    let note = (!dropped.is_empty()).then(|| {
        format!(
            "the first-party anti-downgrade floor at {} carried {} unusable entr{} ({}), which \
             were DROPPED: a floor that cannot be parsed cannot be compared against, and \
             keeping it would refuse a good plugin forever.",
            path.display(),
            dropped.len(),
            if dropped.len() == 1 { "y" } else { "ies" },
            dropped.join(", ")
        )
    });
    (path, marks, note)
}

/// The load policy's own copy of the floor, taken once at boot.
#[cold]
pub(crate) fn copy(marks: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    marks.clone()
}

/// The owned entry a first-party plugin load raises its floor to.
#[cold]
pub(crate) fn entry(name: &str, version: &str) -> (String, String) {
    (name.to_string(), version.to_string())
}

/// The floor's file body, persisted after a registry load raises it.
#[cold]
pub(crate) fn body(marks: &BTreeMap<String, String>) -> std::io::Result<Vec<u8>> {
    let mut body = busbar_contract::json::to_vec_pretty(marks)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    body.push(b'\n');
    Ok(body)
}
