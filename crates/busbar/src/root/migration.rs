// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first boot after an upgrade: what the previous release already holds, sealed as the ledger's
//! opening figures.
//!
//! ## Where this runs in the boot order, and why exactly there
//!
//! Immediately AFTER the durability branch — the step that builds the journal and constructs the
//! ledger dual-writing onto the previous release's rows — and BEFORE the transport-key unit
//! provisions a listener, which is the step before anything binds an address.
//!
//! Both edges are load-bearing.
//!
//! It cannot run earlier: the opening is a checkpoint the ledger seals, and there is no ledger until
//! the durability step has built one. It cannot run later: the first accepted connection can settle,
//! and a settlement posted before the opening was sealed would be measured from a checkpoint that
//! did not exist when it happened — the residual would be off by the whole of the previous release's
//! history, on a deployment where that history is the entire point.
//!
//! The store adapter is already in hand by then, because the durability step took its shipper and
//! its legacy-rows path from it. So this step adds no new dependency to the boot; it adds one read
//! and one seal between two steps that already exist.
//!
//! ## Where the marker goes
//!
//! On the journal, beside the opening checkpoint it is a marker for. It used to go into the store
//! adapter's node-local shim, which was the honest place for it while there was nowhere else — but
//! the shim holds it for the life of a process only, so a node with a data directory re-read the
//! previous release's rows on every single boot and the one record that says "this deployment has
//! already opened its balances" was the one record with nowhere durable to live.
//!
//! It still does not go into the rows that were READ. Those may be on a read-only replica, and a
//! marker written beside somebody else's data is a migration that has quietly taken ownership of a
//! schema it does not own. The journal is this release's own record, which is exactly what the
//! ledger unit's records seam asked for.
//!
//! ## What the root decides and what it does not
//!
//! The root decides WHICH rows are read, because it is the only thing that has both the loaded store
//! and the resolved configuration: the key rows name their own buckets, and the configured group
//! buckets and the metering days come off the config. Everything after that — what an opening figure
//! is, how it folds into a balance, what the marker says — belongs to the ledger unit, and this
//! module does not have an opinion about any of it.
//!
//! ## It does not refuse
//!
//! A store that will not list its key rows costs the migration the buckets it would have discovered
//! there; it is reported and the boot continues over what the configuration named. A store with
//! nothing in it at all seals an opening at zero. The one outcome a migration may not produce is a
//! configuration that worked yesterday failing to boot today, so the only errors that come back here
//! are the ones where continuing would be worse: the opening could not be signed, the ledger's own
//! records could not be read or written, or the figures do not fit in a ledger figure.

use busbar_plugin_loader::store_adapter::{LegacyReadPlan, StoreAdapter};
use busbar_unit_ledger::checkpoint::CheckpointSecret;
use busbar_unit_ledger::migration::{
    migrate, LegacyLedgerRows, MigrationError, MigrationRecords, Outcome,
};

/// What the root reads out of configuration to decide which of the previous release's rows to read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigrationConfig {
    /// Which node is sealing.
    pub node: u64,
    /// The window in force for the key buckets, as its opening instant in whole seconds.
    pub window: u64,
    /// The configured group buckets and the window each is on. Not discoverable from the store —
    /// a budget group is a configuration fact — so the root names them.
    pub group_buckets: Vec<(String, u64)>,
    /// The metering days to read.
    pub metering_days: Vec<u64>,
    /// The card version the opening entries are priced under.
    pub rate_card_version: u64,
}

/// What the migration step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    /// Whether this boot sealed the opening, and what it sealed.
    pub outcome: Outcome,
    /// Why the key rows could not be listed, if they could not. The buckets they would have named
    /// are missing from the opening, so the fact is carried rather than swallowed.
    pub key_rows_unreadable: Option<String>,
}

impl Migration {
    /// Whether this boot did the sealing, as opposed to finding a marker already there.
    #[must_use]
    pub fn sealed_now(&self) -> bool {
        self.outcome.sealed_now()
    }
}

/// Read the previous release's rows through the store adapter and seal the opening.
///
/// # Errors
///
/// The opening could not be signed, the ledger's own records were not usable, or the figures read do
/// not fit. A store that would not answer for some rows is NOT an error — see this module's preamble.
pub fn run(
    adapter: &StoreAdapter,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Migration, MigrationError> {
    let mut records = adapter.migration_records();
    run_with(adapter, &mut records, cfg, wall, secret)
}

/// [`run`] over records the caller names, which is how the marker reaches the journal.
///
/// The rows are still read through the adapter — they are the previous release's and nobody else has
/// them — but WHERE the marker goes is the caller's to decide, and on a node built by
/// [`crate::root::durability::build_for_node`] it goes on the one journal beside the opening
/// checkpoint it is a marker for. That is the difference between a marker that survives a restart
/// on a node with a data directory and one that does not: the adapter's node-local shim never
/// could, so every boot re-read the previous release's rows.
///
/// # Errors
///
/// As [`run`].
pub fn run_with(
    adapter: &StoreAdapter,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Migration, MigrationError> {
    let (plan, key_rows_unreadable) =
        match adapter.key_bucket_plan(cfg.window, &cfg.group_buckets, &cfg.metering_days) {
            Ok(plan) => (plan, None),
            // The key rows are where the per-key buckets come from. Without them the migration
            // opens over what the configuration named and says why the rest is missing, which is
            // strictly better than either refusing to boot or reporting a complete opening that is
            // not one.
            Err(e) => (
                LegacyReadPlan {
                    windows: cfg.group_buckets.clone(),
                    days: cfg.metering_days.clone(),
                },
                Some(e.to_string()),
            ),
        };

    let rows = adapter.legacy_ledger_rows(plan);
    let outcome = seal_opening(&rows, records, cfg, wall, secret)?;
    Ok(Migration {
        outcome,
        key_rows_unreadable,
    })
}

/// The seal itself, over the two seams and nothing else.
///
/// Separate from [`run`] because [`run`]'s job is to decide what gets read and this one's job is to
/// hand two objects to the ledger unit. Splitting them is what lets the ordering rule be tested
/// against the real traits without a loaded store plugin in the way.
///
/// # Errors
///
/// As [`run`].
pub fn seal_opening(
    rows: &dyn LegacyLedgerRows,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Outcome, MigrationError> {
    migrate(rows, records, cfg.node, wall, cfg.rate_card_version, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_unit_ledger::legacy::{LegacyHead, LegacyMigrationSource};
    use busbar_unit_ledger::migration::{
        LegacyFamily, LegacyFigure, LegacyFigures, NodeLocalRecords,
    };
    use busbar_unit_ledger::totals::CapDimension;

    /// Rows a test seeded, counting the reads so "the second boot touched nothing" is an assertion
    /// about the previous release's rows rather than about a return value.
    #[derive(Default)]
    struct SeededRows {
        figures: Vec<LegacyFigure>,
        reads: std::cell::Cell<u32>,
    }

    impl LegacyMigrationSource for SeededRows {
        fn read_head(&self) -> LegacyHead {
            self.reads.set(self.reads.get() + 1);
            LegacyHead {
                seq: Some(90),
                hash: Some("head".to_string()),
                balances: vec![("vk_a".to_string(), 6_000)],
                cells_read: 1,
            }
        }
    }

    impl LegacyLedgerRows for SeededRows {
        fn read_figures(&self) -> LegacyFigures {
            self.reads.set(self.reads.get() + 1);
            LegacyFigures {
                figures: self.figures.clone(),
                unreadable: Vec::new(),
            }
        }
    }

    fn cfg() -> MigrationConfig {
        MigrationConfig {
            node: 1,
            window: 86_400,
            group_buckets: vec![("team".to_string(), 86_400)],
            metering_days: vec![86_400],
            rate_card_version: 3,
        }
    }

    fn rows() -> SeededRows {
        SeededRows {
            figures: vec![LegacyFigure {
                family: LegacyFamily::Window,
                bucket: "vk_a".to_string(),
                window: 86_400,
                lane: "gpt-4".to_string(),
                provider: String::new(),
                dimension: CapDimension::Class("input".to_string()),
                amount: 6_000,
            }],
            reads: std::cell::Cell::new(0),
        }
    }

    /// The first boot seals what was there; the opening entry per bucket carries the card version
    /// the root named.
    #[test]
    fn the_first_boot_seals_the_opening() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let outcome =
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals");
        let Outcome::Sealed(opening) = outcome else {
            panic!("the first boot seals");
        };
        assert_eq!(opening.checkpoint.totals.len(), 1);
        assert_eq!(
            opening
                .checkpoint
                .totals
                .values()
                .next()
                .expect("one")
                .settled,
            6_000
        );
        assert_eq!(opening.balances.len(), 1);
        assert_eq!(opening.balances[0].rate_card_version, 3);
        assert!(records.is_sealed());
    }

    /// The second boot on the same node reads nothing at all: the marker is what makes a restart
    /// free, and it is the ledger's own record rather than anything on the rows that were read.
    #[test]
    fn the_second_boot_reads_nothing() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let first = seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals");
        let after_first = rows.reads.get();
        assert!(after_first > 0);

        let second = seal_opening(&rows, &mut records, &cfg(), 1_700_000_100, None).expect("no-op");
        assert!(!second.sealed_now());
        assert_eq!(rows.reads.get(), after_first);
        assert_eq!(second.marker(), first.marker());
    }

    /// The marker goes on the JOURNAL, and a second boot reading the same journal finds it there and
    /// touches the previous release's rows not at all.
    ///
    /// The same claim as `the_second_boot_reads_nothing` above, made over the seam the root actually
    /// binds: the node-local records that test uses are the ledger unit's own honest default, and
    /// this one proves the root does not settle for it.
    #[test]
    fn the_marker_is_sealed_on_the_journal() {
        use crate::root::durability::{build_for_node, DurabilityConfig};
        use busbar_caps::{DurabilityToken, KernelSeal, StepName};
        use busbar_unit_wal::{NullShipper, RecordClass};

        let rows = rows();
        let token = DurabilityToken::mint(&KernelSeal::acquire_for_kernel());
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            1,
            Box::new(NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");

        let first = {
            let mut records = durability.migration_records(&token, StepName::Meter);
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals")
        };
        assert!(first.sealed_now());
        let after_first = rows.reads.get();
        assert!(after_first > 0);

        // The marker is a record on the chain, of the class the contract names for it.
        let replayed = durability
            .journal
            .replay()
            .expect("the journal reads back")
            .expect("and verifies");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].class, RecordClass::Migration);

        // And the second boot over the same journal reads nothing at all.
        let second = {
            let mut records = durability.migration_records(&token, StepName::Meter);
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_100, None).expect("no-op")
        };
        assert!(!second.sealed_now());
        assert_eq!(rows.reads.get(), after_first);
        assert_eq!(second.marker(), first.marker());
    }

    /// A deployment with nothing behind it seals an opening at zero rather than refusing, and the
    /// node has a point to measure from from its first request onward.
    #[test]
    fn a_deployment_with_nothing_behind_it_still_seals() {
        let rows = SeededRows::default();
        let mut records = NodeLocalRecords::new();
        let Outcome::Sealed(opening) =
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals")
        else {
            panic!("an empty deployment seals an opening at zero");
        };
        assert!(opening.checkpoint.totals.is_empty());
        assert!(opening.checkpoint.body_hash_verifies());
    }
}
