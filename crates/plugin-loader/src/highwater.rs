// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::registry::PluginRegistry;
use crate::sign::{valid_name, valid_semver, version_at_least};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const HIGH_WATER_FILE: &str = "plugin-highwater.json";

/// The per-plugin-name high-water marks: `name` -> the highest version of that name this deployment
/// has seen and loaded. Persisted under the fleet data dir when one is configured, memory-only
/// otherwise (see the module docs).
#[derive(Debug, Clone, Default)]
pub struct HighWaterMarks {
    /// The data-dir file backing these marks, or `None` for a memory-only store (no `data_dir`).
    path: Option<PathBuf>,
    marks: BTreeMap<String, String>,
}

impl HighWaterMarks {
    #[must_use]
    pub fn load(data_dir: Option<&Path>) -> (Self, Option<String>) {
        let Some(dir) = data_dir else {
            return (HighWaterMarks::default(), None);
        };
        let path = dir.join(HIGH_WATER_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (
                    HighWaterMarks {
                        path: Some(path),
                        marks: BTreeMap::new(),
                    },
                    None,
                )
            }
            Err(e) => {
                return (
                    HighWaterMarks {
                        path: Some(path.clone()),
                        marks: BTreeMap::new(),
                    },
                    Some(format!(
                        "could not read the first-party anti-downgrade floor at {}: {e}. Booting \
                         with NO first-party floor — an old signed first-party artifact would not \
                         be refused until the floor is re-established by a successful load.",
                        path.display()
                    )),
                )
            }
        };
        let parsed: BTreeMap<String, String> = match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(e) => {
                return (
                    HighWaterMarks {
                        path: Some(path.clone()),
                        marks: BTreeMap::new(),
                    },
                    Some(format!(
                        "the first-party anti-downgrade floor at {} is not readable JSON ({e}). \
                         Booting with NO first-party floor — an old signed first-party artifact \
                         would not be refused until the floor is re-established by a successful \
                         load.",
                        path.display()
                    )),
                )
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
        (
            HighWaterMarks {
                path: Some(path),
                marks,
            },
            note,
        )
    }

    #[must_use]
    pub fn marks(&self) -> BTreeMap<String, String> {
        self.marks.clone()
    }

    pub fn raise(&mut self, name: &str, version: &str) -> bool {
        if !valid_name(name) || !valid_semver(version) {
            return false;
        }
        match self.marks.get(name) {
            Some(current) if version_at_least(current, version) => false,
            _ => {
                self.marks.insert(name.to_string(), version.to_string());
                true
            }
        }
    }

    pub fn record_registry(&mut self, registry: &PluginRegistry) -> bool {
        let mut moved = false;
        for p in registry.loadable() {
            if matches!(
                p.verdict,
                crate::sign::Verdict::Trusted {
                    first_party: true,
                    ..
                }
            ) {
                moved |= self.raise(&p.manifest.name, &p.manifest.version);
            }
        }
        moved
    }

    pub fn persist(&self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let mut body = serde_json::to_vec_pretty(&self.marks)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        body.push(b'\n');
        crate::durable::write_with(
            path,
            &body,
            crate::durable::DurableOpts {
                mode: Some(0o600),
                exclusive: false,
            },
        )
    }
}

#[cfg(test)]
#[path = "tests/highwater_tests.rs"]
mod tests;
