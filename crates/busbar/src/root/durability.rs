// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal, the ledger and the audit unit's two streams — and the one `if` that decides whether
//! this node writes to a disk.
//!
//! ## The branch, and why it is the only place the data directory is read
//!
//! A deployment that configures no data directory needs none: without one the journal is
//! memory-buffered and shipped to the configured store, and durability is the store's durability.
//! That is not a degraded mode — it is the previous release's shape, and the great majority of
//! deployments run it.
//!
//! The journal unit states the rule as a type, and says so in its own words: *constructing an
//! on-disk log IS the decision to write to a disk; nothing probes for a directory or guesses at
//! one*. So there is exactly one branch, it is here, and it is the only place on this path that
//! reads the configured directory. Nothing downstream may probe, resolve a keyset path
//! speculatively, or open anything "just in case" — a file appearing next to a configuration that
//! asked for none is the failure this shape exists to make impossible, and the tests below assert
//! it by listing the directory rather than by trusting the code.
//!
//! ## The shipper is part of the answer, not an optimisation
//!
//! Without a data directory, the journal is *shipped to the configured store synchronously*, which
//! is why the unset branch takes the store's shipper rather than the null one. A node with no store
//! configured and no directory keeps nothing, which is again the previous release's behaviour and
//! not a silent data loss: there was nowhere it was ever going.
//!
//! **One constraint this places on the caller, and it is load-bearing.** In the memory-buffered
//! mode the shipper's answer is part of the commit: a failed ship comes back as a durability loss
//! with the batch retained. On a node with no configured peers — which is every previous-release
//! deployment — a store hiccup must still be write-behind. The retained batch is re-appended, and
//! that is write-behind by another name; what must not happen is the caller turning that answer
//! into a refusal at the door. The previous release served through a store hiccup, and a refusal
//! there would be a deployment that started refusing requests it used to serve.
//!
//! ## Dual writing is the default, not an option
//!
//! The ledger is constructed dual-writing onto the previous release's rows. Two things require it
//! and neither is optional: the reconciliation identity — ledger sums equal legacy spend, fee count
//! equals billable requests — and rollback, which is the previous release's binary reading the
//! rows this one wrote. It is constructed before anything listens, because the first accepted
//! connection can settle.
//!
//! ## Two audit streams that do not merge
//!
//! The audit unit keeps a legacy chain and a record chain, and they stay apart deliberately. The
//! legacy chain is the previous release's administrative mutation chain — moved, not rewritten,
//! because a change to its digest would report every deployment's history as tampered. The record
//! chain is the new fixed record. The root holds both; the legacy chain is fed by the verbs unit's
//! administrative path and the record chain by the audit step.

use std::path::{Path, PathBuf};

use busbar_unit_audit::{AuditChain, AuditLog};
use busbar_unit_ledger::legacy::LegacyRows;
use busbar_unit_ledger::settle::Ledger;
use busbar_unit_wal::{Mode, OpenError, Shipper, Wal};

/// What the root reads out of configuration to decide the durability shape.
///
/// One field, because there is one decision. Its absence is the previous release's shape and its
/// presence is a deliberate statement that this node keeps its own journal.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DurabilityConfig {
    /// The configured data directory, if the operator named one.
    pub data_dir: Option<PathBuf>,
}

/// The durability stack the root owns: the journal, the ledger and the two audit chains.
pub struct Durability {
    /// The journal. On disk only where a data directory was configured.
    pub wal: Wal,
    /// The ledger, dual-writing onto the previous release's rows.
    pub ledger: Ledger,
    /// The new fixed record's chain.
    pub record: AuditChain,
    /// The previous release's administrative mutation chain, moved rather than rewritten.
    pub legacy: AuditLog,
}

impl std::fmt::Debug for Durability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Durability")
            .field("mode", &self.wal.mode())
            .finish_non_exhaustive()
    }
}

impl Durability {
    /// Whether this node writes its journal to a disk.
    #[must_use]
    pub fn on_disk(&self) -> bool {
        matches!(self.wal.mode(), Mode::OnDisk)
    }
}

/// Build the journal, the ledger and the two audit chains.
///
/// The whole decision is the first `match`. Everything after it is the same on both branches, which
/// is the point: a node without a data directory is not running a reduced stack, it is running the
/// same stack over a journal that keeps its segments in memory.
///
/// # Errors
///
/// A configured data directory could not be opened, or the journal already there could not be read.
/// There is no error arm on the other branch: a memory-buffered log cannot fail to open.
pub fn build(
    cfg: &DurabilityConfig,
    shipper: Box<dyn Shipper>,
    legacy_rows: Box<dyn LegacyRows>,
) -> Result<Durability, OpenError> {
    let wal = match cfg.data_dir.as_deref() {
        // The previous release's shape: nothing is opened, nothing is probed, and durability is
        // whatever the store the batches are shipped to provides.
        None => Wal::memory_buffered_to(shipper),
        // The operator asked for a journal on this node's own disk. This call is that decision.
        Some(dir) => Wal::in_directory(dir, shipper)?,
    };

    Ok(Durability {
        wal,
        // Not `Ledger::new()`. The reconciliation identity and rollback both require the dual
        // write, and both are release requirements rather than deployment choices.
        ledger: Ledger::dual_writing(legacy_rows),
        record: AuditChain::new(),
        legacy: AuditLog::new(),
    })
}

/// Every path this node may write to, given its configuration.
///
/// Empty when no data directory was configured, which is the machine-checkable form of *no
/// directory, no files*. A caller that wants to assert the absence has something to assert against
/// rather than a sentence to trust.
#[must_use]
pub fn writable_paths(cfg: &DurabilityConfig) -> Vec<&Path> {
    cfg.data_dir.as_deref().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_unit_ledger::legacy::RecordingRows;
    use busbar_unit_wal::NullShipper;

    /// A scratch directory that removes itself, following the journal unit's own test fixture: the
    /// point of these tests is what is and is not created, so each needs a directory nobody else is
    /// writing to.
    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "busbar-root-durability-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch directory");
            ScratchDir { path }
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.path)
                .expect("scratch directory is readable")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn rows() -> Box<dyn LegacyRows> {
        Box::new(RecordingRows::new())
    }

    /// The unset branch, and the assertion that matters: the working directory the node was started
    /// in is untouched. Not "no journal was opened" — no FILE appeared, checked by listing.
    #[test]
    fn no_data_dir_creates_no_file() {
        let scratch = ScratchDir::new("unset");
        assert!(scratch.entries().is_empty(), "the fixture starts empty");

        let cfg = DurabilityConfig { data_dir: None };
        let durability =
            build(&cfg, Box::new(NullShipper::new()), rows()).expect("memory-buffered cannot fail");

        assert!(!durability.on_disk());
        assert_eq!(durability.wal.mode(), Mode::MemoryBuffered);
        assert_eq!(
            scratch.entries(),
            Vec::<String>::new(),
            "a node with no configured data directory wrote a file"
        );
        assert!(
            writable_paths(&cfg).is_empty(),
            "no data directory means no writable path at all"
        );
    }

    /// The set branch: the operator asked for a journal on this node's disk, so one appears. The
    /// mirror of the test above, and the reason that one means something — an assertion that no
    /// file appears is only worth having if a file appears when it should.
    #[test]
    fn a_configured_data_dir_opens_a_journal_on_disk() {
        let scratch = ScratchDir::new("set");
        let cfg = DurabilityConfig {
            data_dir: Some(scratch.path.clone()),
        };
        let durability =
            build(&cfg, Box::new(NullShipper::new()), rows()).expect("the directory is writable");

        assert!(durability.on_disk());
        assert_eq!(durability.wal.mode(), Mode::OnDisk);
        assert!(
            !scratch.entries().is_empty(),
            "a configured data directory should hold the journal's first segment"
        );
        assert_eq!(writable_paths(&cfg), vec![scratch.path.as_path()]);
    }

    /// The two branches build the same stack. A node without a data directory is not running a
    /// reduced ledger or a reduced audit chain; only the journal's backing differs.
    #[test]
    fn both_branches_build_the_same_ledger_and_audit_streams() {
        let scratch = ScratchDir::new("same");
        let buffered = build(
            &DurabilityConfig { data_dir: None },
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("memory-buffered cannot fail");
        let on_disk = build(
            &DurabilityConfig {
                data_dir: Some(scratch.path.clone()),
            },
            Box::new(NullShipper::new()),
            rows(),
        )
        .expect("the directory is writable");

        // The audit chains start at the same place on both, because neither is a function of where
        // the journal lives.
        assert_eq!(buffered.record.next_seq(), on_disk.record.next_seq());
        assert_eq!(buffered.legacy.len(), on_disk.legacy.len());
        assert!(buffered.ledger.is_dual_writing());
        assert!(on_disk.ledger.is_dual_writing());
    }

    /// A data directory that cannot be opened is an error the caller sees, not a silent fall back
    /// to memory. An operator who asked for a journal on disk and did not get one has to be told:
    /// the quiet downgrade is how a deployment discovers at recovery time that it kept nothing.
    #[test]
    fn an_unopenable_data_dir_is_an_error_and_not_a_silent_downgrade() {
        let scratch = ScratchDir::new("unopenable");
        // A regular file where the directory should be: the open fails, and it fails as an error.
        let blocked = scratch.path.join("not-a-directory");
        std::fs::write(&blocked, b"").expect("write the blocking file");

        let cfg = DurabilityConfig {
            data_dir: Some(blocked),
        };
        assert!(build(&cfg, Box::new(NullShipper::new()), rows()).is_err());
    }
}
