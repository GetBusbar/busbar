//! Tests for `migration.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_unit_ledger::legacy::{LegacyHead, LegacyMigrationSource};
use busbar_unit_ledger::migration::{LegacyFamily, LegacyFigure, LegacyFigures, NodeLocalRecords};
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
    let outcome = seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals");
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

/// A store that will not list its key rows, and answers for everything else.
///
/// The one refusal is the one the preamble says costs the migration the buckets the key rows
/// would have named. Everything else answers, so what the opening seals over is exactly what the
/// CONFIGURATION named — which is the half the boot may not lose.
struct KeyRowsRefused;

impl busbar_api::Store for KeyRowsRefused {
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn get_key(&self, _id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        Ok(None)
    }

    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        Err(busbar_api::StoreError(
            "the key rows are on a replica that is not answering".to_string(),
        ))
    }

    fn delete_key(&self, _id: &str) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn get_usage(
        &self,
        bucket_id: &str,
        _window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        // The configured group bucket has spent; nothing else has. A migration that dropped the
        // configured half along with the discovered one would answer the empty ledger here.
        Ok(busbar_api::UsageLedger {
            requests: u64::from(bucket_id == "team") * 7,
            billable_requests: 0,
            models: Vec::new(),
        })
    }

    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn list_metering(
        &self,
        _bucket: u64,
    ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        Ok(Vec::new())
    }
}

/// THE WHOLE STEP, over the adapter the boot actually hands it, on the one degraded read the
/// preamble names: the key rows will not list, and the boot continues.
///
/// Two things have to be true together and neither is enough alone. The fact that the discovered
/// buckets are missing is CARRIED rather than swallowed, so an operator is not told a complete
/// opening was sealed when it was not; and the buckets the CONFIGURATION named are opened
/// anyway, so the identity measures from the previous release's figures for the half the node
/// could still read rather than from zero.
#[test]
fn a_store_that_will_not_list_its_key_rows_still_opens_the_configured_buckets() {
    let adapter = StoreAdapter::native(std::sync::Arc::new(KeyRowsRefused));
    let mut records = NodeLocalRecords::new();

    let migration =
        run(&adapter, &mut records, &cfg(), 1_700_000_000, None).expect("the boot continues");

    assert!(
        migration
            .key_rows_unreadable
            .as_deref()
            .is_some_and(|why| !why.is_empty()),
        "the key rows would not list, and the reason travels with the answer"
    );
    assert!(migration.sealed_now(), "the opening is sealed anyway");
    let Outcome::Sealed(opening) = &migration.outcome else {
        panic!("the first boot seals");
    };
    assert_eq!(
        opening
            .checkpoint
            .totals
            .keys()
            .map(|(key, _)| key.bucket.as_str().to_string())
            .collect::<Vec<_>>(),
        vec!["team".to_string()],
        "the configured group bucket is opened even though the key rows were unreadable"
    );
}

/// THE BOOT STEP, over the node's one book and the adapter the boot hands it.
///
/// The step this module existed to describe and had no caller for. Two facts, and the second is
/// the one an upgrade turns on: the opening is sealed on the JOURNAL, so it is a record with a
/// position on the same chain the postings that follow it are on; and the next boot over the
/// same book finds the marker there and opens nothing a second time.
#[test]
fn the_boot_step_seals_the_opening_on_the_nodes_one_book() {
    use busbar_caps::{DurabilityToken, KernelSeal};
    use busbar_unit_wal::RecordClass;

    let adapter = StoreAdapter::native(std::sync::Arc::new(KeyRowsRefused));
    let book = crate::root::durability::node_book(
        &crate::root::durability::DurabilityConfig::default(),
        adapter.shipper(),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let token = DurabilityToken::mint(&KernelSeal::acquire_for_kernel());

    let first = at_boot(
        &adapter,
        &book.durability,
        &token,
        &cfg(),
        1_700_000_000,
        None,
    )
    .expect("the boot continues");
    assert!(first.sealed_now(), "the first boot seals the opening");

    let replayed = book
        .durability
        .lock()
        .expect("the node's one book")
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    assert_eq!(
        replayed
            .iter()
            .filter(|r| r.class == RecordClass::Migration)
            .count(),
        1,
        "the marker is a record on the node's own chain"
    );

    let second = at_boot(
        &adapter,
        &book.durability,
        &token,
        &cfg(),
        1_700_000_100,
        None,
    )
    .expect("the second boot continues");
    assert!(
        !second.sealed_now(),
        "the second boot finds the marker and opens nothing again"
    );
    assert_eq!(second.outcome.marker(), first.outcome.marker());
}
