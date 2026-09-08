// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The FIRST-PARTY anti-downgrade floor: per-plugin-name HIGH-WATER MARKS.
//!
//! `docs/plugins.md` security-model item 3 promises that a validly-signed but OLD first-party release
//! cannot be replayed into a newer deployment. It is a real threat and the signing gate is exactly
//! what it is aimed at: an attacker with write access to `plugins.dir` swaps the current tarball for
//! the GENUINE, busbar-signed 1.0.0 carrying a known fixed defect. It verifies against the embedded
//! release key, and with nothing to compare it against it loads as `first-party` with no warning.
//!
//! The thing to compare it against is what this module keeps: for each plugin NAME, the highest
//! `version` of that name this deployment has actually seen and loaded. That is the floor
//! [`busbar_plugin_sign::evaluate`] applies to a verified first-party manifest.
//!
//! ## Why a high-water mark and not the binary's version
//!
//! The pre-1.5.0 control floored first-party plugins at the running binary's version. It was removed
//! because first-party plugins version on their OWN independent lines (the stores/auth/hooks ship
//! 1.0.x under a 1.5.0 engine), so it rejected every correctly-signed current release. A per-name
//! high-water mark couples the floor to the plugin's own line instead, so it closes the replay
//! without that coupling. A name with NO mark carries NO floor: a first install is not a downgrade,
//! and the mark only ever rises through a load this deployment itself performed.
//!
//! ## Where it lives (PB-13/15)
//!
//! With a fleet `data_dir` configured, the marks persist to `plugin-highwater.json` beneath it, so
//! the floor survives a restart — which is what makes it a real anti-replay control rather than a
//! per-process one. WITHOUT a data dir this store writes NO FILE and probes nothing: PB-13 pins that
//! a deployment with no `data_dir` creates no data-dir files, and PB-15 that it never refuses for
//! durability. The marks are then memory-only and bound one process lifetime — still closing a
//! mid-process swap (a config reload / `POST /plugins/reload` after boot), which is the window an
//! attacker with directory write access actually operates in.
//!
//! ## Getting past it
//!
//! Deliberately: `first_party_floors`, the explicit, audited rollback pin, REPLACES the mark for the
//! pinned name (and no other). That is the documented override, and it is why an operator can still
//! roll a first-party plugin back on purpose.

use crate::registry::PluginRegistry;
use busbar_plugin_sign::{valid_name, valid_semver, version_at_least};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The on-disk file name beneath the fleet data dir. Plain JSON `{ "<name>": "<version>" }` — this is
/// an integrity floor, not a secret, and it is not signature-covered: a writer who can edit it can
/// already edit the plugin tarballs the floor is about, so encrypting or signing it would buy
/// nothing. It is written `0600` for the same reason every other data-dir file is.
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
    /// Load the marks for a deployment whose fleet data dir is `data_dir` (`None` = no data dir).
    ///
    /// FAIL-SOFT on a damaged or unreadable file: an empty mark set is the same posture as a first
    /// boot (no floor), whereas refusing the boot would let anyone who can corrupt one JSON file
    /// take the node down — a worse outcome than the replay window this control closes. The
    /// corruption is reported to the caller so it can be logged loudly.
    ///
    /// Entries that are not a valid plugin name or not a valid `MAJOR.MINOR.PATCH` version are
    /// DROPPED rather than trusted: an unparsable floor cannot be compared against, and
    /// `version_at_least` refuses an unparsable floor outright, so keeping one would refuse a good
    /// plugin forever on the strength of a corrupt byte.
    #[must_use]
    pub fn load(data_dir: Option<&Path>) -> (Self, Option<String>) {
        let Some(dir) = data_dir else {
            // PB-13: no data dir, no probe, no files. The marks are memory-only.
            return (HighWaterMarks::default(), None);
        };
        let path = dir.join(HIGH_WATER_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            // A missing file is the normal first-boot state, not a problem.
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

    /// The marks, in the shape `busbar_plugin_sign::TrustPolicy::first_party_high_water` takes.
    #[must_use]
    pub fn marks(&self) -> BTreeMap<String, String> {
        self.marks.clone()
    }

    /// True when these marks are backed by a data-dir file (so they survive a restart).
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// RAISE the mark for `name` to `version` if `version` is above the current mark. Never lowers:
    /// the mark is a high-water mark, so an explicit rollback (which loads an older artifact past
    /// its pin) must not silently erase the floor every other node still enforces. Returns true iff
    /// the mark moved.
    pub fn raise(&mut self, name: &str, version: &str) -> bool {
        if !valid_name(name) || !valid_semver(version) {
            return false;
        }
        match self.marks.get(name) {
            // `version_at_least(version, current)` is true when they are EQUAL, so compare the other
            // way to detect a genuine rise and keep this idempotent.
            Some(current) if version_at_least(current, version) => false,
            _ => {
                self.marks.insert(name.to_string(), version.to_string());
                true
            }
        }
    }

    /// Raise the mark for every FIRST-PARTY plugin this registry proved loadable. Only a verified
    /// first-party verdict counts: a third-party or opted-in-untrusted artifact must never be able
    /// to set the floor the first-party lane is judged against. Returns true iff any mark moved.
    pub fn record_registry(&mut self, registry: &PluginRegistry) -> bool {
        let mut moved = false;
        for p in registry.loadable() {
            if matches!(
                p.verdict,
                busbar_plugin_sign::Verdict::Trusted {
                    first_party: true,
                    ..
                }
            ) {
                moved |= self.raise(&p.manifest.name, &p.manifest.version);
            }
        }
        moved
    }

    /// Persist the marks, if this store has a data dir. A no-op (and `Ok`) when memory-only —
    /// PB-13: a deployment with no `data_dir` writes no data-dir files.
    ///
    /// Routed through the ONE durable-write primitive (`busbar_api::durable::write_with`), which
    /// owns the temp naming, the contents fsync, the atomic rename and the parent fsync. That
    /// matters here for a specific reason: a TRUNCATED floor is a silently disarmed security
    /// control, so a crash mid-write must leave the previous floor intact rather than a shorter one.
    /// `mode: 0600`, like every other data-dir file.
    ///
    /// # Errors
    /// The underlying I/O error. A failure to persist is NOT fatal to the caller: the in-memory
    /// marks still floor this process, and the caller logs it.
    pub fn persist(&self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let mut body = serde_json::to_vec_pretty(&self.marks)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        body.push(b'\n');
        busbar_api::durable::write_with(
            path,
            &body,
            busbar_api::durable::DurableOpts {
                mode: Some(0o600),
                exclusive: false,
            },
        )
    }
}

#[cfg(test)]
#[path = "tests/highwater_tests.rs"]
mod tests;
