// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store side of step 5 (§3 5, §A6 "Attempts") over an opened record store: 5S records the
//! attempt once every read-only precondition of the write held and before its first write; 5d marks
//! this directory's attempt just before the rename over config.yaml. Its refusal stops the write with
//! nothing renamed.

use std::path::{Path, PathBuf};

use crate::records::{attempts, RecordStore};
use crate::{Check, Plan, Refusal, Settled, Written};

/// The file beside config.yaml naming the attempt whose 5d ran in this directory (§A6 "Attempts").
pub const ATTEMPT_SUFFIX: &str = "busbar-attempt";

/// `<config>.busbar-attempt`.
#[must_use]
pub fn attempt_file(config: &Path) -> PathBuf {
    let mut name = config.as_os_str().to_owned();
    name.push(".");
    name.push(ATTEMPT_SUFFIX);
    PathBuf::from(name)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// 5S and 5d over the opened store (§A6 "Attempts"): the attempt recorded under IMPORT before
/// the write's first byte, and `<config>.busbar-attempt` naming it just before the rename.
pub(crate) struct Attempt<'a> {
    store: &'a dyn RecordStore,
    config: &'a Path,
    begun: Option<attempts::Attempt>,
}

impl Attempt<'_> {
    /// 5S: `digest` is the plan's ([`Plan::digest`]), `written_sha256` the SHA-256 of the stamped
    /// document about to be written.
    ///
    /// # Errors
    /// The store's refusal; nothing was written.
    pub(crate) fn begin(
        &mut self,
        digest: [u8; 32],
        written_sha256: [u8; 32],
    ) -> Result<(), Refusal> {
        let mut nonce = [0u8; 16];
        busbar_contract::crypto::fill(&mut nonce).map_err(|_| {
            Refusal::Config(
                "the boot drew no entropy for the upgrade attempt; nothing was written".to_owned(),
            )
        })?;
        let attempt = attempts::Attempt {
            digest,
            nonce,
            expires_at: now().saturating_add(attempts::EXPIRY_SECS),
            written_sha256,
        };
        attempts::begin(self.store, &attempt)
            .map_err(|refusal| Refusal::Config(refusal.to_string()))?;
        self.begun = Some(attempt);
        Ok(())
    }

    /// 5d, just before the rename: this directory names the attempt as its own.
    ///
    /// # Errors
    /// The marker could not be written; config.yaml is not renamed.
    pub(crate) fn before_rename(&self) -> Result<(), Refusal> {
        let Some(attempt) = self.begun.clone() else {
            return Ok(());
        };
        let path = attempt_file(self.config);
        let mark = || -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&path)?;
            file.write_all(attempts::hex(&attempt.nonce).as_bytes())?;
            file.sync_all()
        };
        mark().map_err(|error| {
            Refusal::Config(format!(
                "cannot write {} ({error}); config.yaml was not replaced",
                path.display()
            ))
        })
    }
}

/// Step 5's write with the store side (5S, 5d, then 5C or MIGRATION_REFUSED): the attempt is
/// consumed with MIGRATION_COMPLETED once config.yaml is renamed into place, or with
/// MIGRATION_REFUSED and the write's text. A store fault at 5C leaves the attempt and its marker;
/// the next boot's settle completes it.
///
/// # Errors
/// The write's refusal.
#[cold]
#[inline(never)]
pub fn write_with_attempt(
    store: &dyn RecordStore,
    plan: &Plan,
    settled: &[Settled],
    check: Check<'_>,
    config: &Path,
) -> Result<Written, Refusal> {
    let mut attempt = Attempt {
        store,
        config,
        begun: None,
    };
    let written = crate::write_attempted(plan, settled, check, Some(&mut attempt));
    if let Some(begun) = attempt.begun {
        let settled = match &written {
            Ok(Written::Stamped) => attempts::complete(store, &begun),
            Ok(Written::StampedByPeer) => Ok(false),
            Err(refusal) => attempts::refuse(store, &begun, &refusal.to_string()),
        };
        if matches!(settled, Ok(true)) {
            let _ = std::fs::remove_file(attempt_file(config));
        }
    }
    written
}
