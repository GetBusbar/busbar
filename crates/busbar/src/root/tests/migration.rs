//! Tests for `migration.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_kernel_ledger::legacy::{LegacyHead, LegacyMigrationSource};
use busbar_kernel_ledger::migration::{
    LegacyFamily, LegacyFigure, LegacyFigures, NodeLocalRecords,
};
use busbar_kernel_ledger::totals::CapDimension;

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
    use busbar_contract::caps::{DurableWrite, Grant, KernelSeal, StepName};
    use busbar_kernel_wal::{NullShipper, RecordClass};

    let rows = rows();
    let token = Grant::<DurableWrite>::mint(&KernelSeal::acquire_for_kernel());
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        1,
        Box::new(NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
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

/// THE OPENING IS SIGNED WITH THE CHAIN'S OWN KEY (OWNER Q71(3): one keyset, #82): the signer the
/// boot hands the migration is the audit chain's, so the opening verifies against the audit keyset;
/// a chain given no key offers no signer and the opening goes down unsigned rather than failing.
#[test]
fn the_opening_is_signed_with_the_audit_chains_own_key() {
    use crate::root::durability::{build_for_node, keyset_of, DurabilityConfig, KeySetVerifier};
    use busbar_contract::caps::{DurableWrite, Grant, KernelSeal, StepName};
    use busbar_kernel_ledger::checkpoint::CheckpointSecret;
    use busbar_kernel_wal::NullShipper;

    let token = Grant::<DurableWrite>::mint(&KernelSeal::acquire_for_kernel());
    let open = |keyed: bool| {
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            1,
            Box::new(NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        if keyed {
            durability.record = busbar_kernel_audit::AuditChain::new()
                .signing_with(busbar_kernel_audit::AuditSigningKey::from_seed(&[5u8; 32]));
        }
        let outcome = {
            let (mut records, signer) =
                durability.migration_records_signed(&token, StepName::Meter);
            let signer = signer.as_ref().map(|s| s as &dyn CheckpointSecret);
            seal_opening(&rows(), &mut records, &cfg(), 1_700_000_000, signer).expect("seals")
        };
        let Outcome::Sealed(opening) = outcome else {
            panic!("a first boot seals its opening");
        };
        (opening.checkpoint, keyset_of(&durability.record))
    };

    let (signed, keys) = open(true);
    assert!(
        signed.signature.is_some(),
        "the chain's key signed the opening"
    );
    assert_eq!(signed.verify_seal(&KeySetVerifier::new(keys)), Ok(()));

    let (unsigned, keys) = open(false);
    assert_eq!(
        unsigned
            .verify_seal(&KeySetVerifier::new(keys))
            .expect_err("unsigned")
            .to_string(),
        "checkpoint 0 carries no signature — no key in the keyset can vouch for it"
    );
}
