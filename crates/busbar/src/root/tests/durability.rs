//! Tests for `durability.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::caps::KernelSeal;
use busbar_kernel_audit::{Clock, NoSeam};
use busbar_kernel_ledger::legacy::RecordingRows;
use busbar_kernel_wal::{decode_run, verify_journal, NullShipper};

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
        entries_of(&self.path)
    }
}

/// What is in one directory now, by name and in order.
fn entries_of(path: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .expect("the directory is readable")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The directory the process was started in, watched for anything that appears in it.
///
/// This is the directory the "no file was created" claim has to be made about. A scratch
/// directory the builder was never told the name of is not somewhere a stray journal could
/// land: a journal opened at a RELATIVE path follows the PROCESS, and the process is here. The
/// scratch directory beside it says only that the fixture tidied up after itself, which is a
/// claim about the test rather than about the node.
///
/// Nothing is changed about the process — no directory is entered and none is created — because
/// a test binary runs its cases on one process's threads and moving that process out from under
/// the others is a fixture that breaks its neighbours.
struct WorkingDir {
    path: PathBuf,
    before: Vec<String>,
}

impl WorkingDir {
    fn watch() -> Self {
        let path = std::env::current_dir().expect("the process has a working directory");
        let before = entries_of(&path);
        WorkingDir { path, before }
    }

    /// What is in it now that was not in it when the watch started.
    fn appeared(&self) -> Vec<String> {
        entries_of(&self.path)
            .into_iter()
            .filter(|name| !self.before.contains(name))
            .collect()
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

fn token() -> Grant<DurableWrite> {
    Grant::<DurableWrite>::mint(&KernelSeal::acquire_for_kernel())
}

fn marker(seq: u64, sealed_at: u64) -> MigrationMarker {
    MigrationMarker {
        checkpoint_seq: seq,
        node: 4,
        sealed_at,
        body_hash: [7u8; 32],
        balances: 3,
        cells_read: 11,
        rate_card_version: 5,
    }
}

/// The unset branch, and the assertion that matters: the working directory the node was started
/// in is untouched. Not "no journal was opened" — no FILE appeared, checked by listing.
#[test]
fn no_data_dir_creates_no_file() {
    let scratch = ScratchDir::new("unset");
    let cwd = WorkingDir::watch();
    assert!(scratch.entries().is_empty(), "the fixture starts empty");

    let cfg = DurabilityConfig { data_dir: None };
    let durability =
        build(&cfg, Box::new(NullShipper::new()), rows()).expect("memory-buffered cannot fail");

    assert!(!durability.on_disk());
    assert_eq!(durability.journal.mode(), Mode::MemoryBuffered);
    assert_eq!(
        scratch.entries(),
        Vec::<String>::new(),
        "a node with no configured data directory wrote a file"
    );
    assert_eq!(
        cwd.appeared(),
        Vec::<String>::new(),
        "a node with no configured data directory wrote a file into the directory it was \
         started in"
    );
    assert!(
        writable_paths(&cfg).is_empty(),
        "no data directory means no writable path at all"
    );
}

/// And writing every kind of record to it still creates nothing. The branch above says the
/// journal was built without a disk; this says it stays that way once the units start using it,
/// which is the claim an operator actually cares about.
#[test]
fn no_data_dir_creates_no_file_even_once_every_unit_has_written() {
    let scratch = ScratchDir::new("unset-in-use");
    let cwd = WorkingDir::watch();
    let mut durability = build(
        &DurabilityConfig { data_dir: None },
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();

    durability
        .journal_posting(&posting(), &token, StepName::Meter)
        .expect("the null shipper takes it");
    durability
        .migration_records(&token, StepName::Meter)
        .write_marker(&marker(0, 1_700_000_000))
        .expect("the marker goes on the chain");

    assert_eq!(
        scratch.entries(),
        Vec::<String>::new(),
        "writing to the journal created a file on a node with no data directory"
    );
    assert_eq!(
        cwd.appeared(),
        Vec::<String>::new(),
        "writing to the journal created a file in the directory the node was started in"
    );
    assert!(!durability.on_disk());
}

fn posting() -> Posting {
    use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension};
    Posting {
        key: TotalsKey::new(
            BucketId::new("vk_a"),
            CapDimension::NanoUnits,
            BucketScope::All,
        ),
        window: 86_400,
        reserved: 5_000,
        settled: 4_200,
        overdraft: 0,
        rate_card_version: 3,
        wall: 1_700_000_000,
        mono: 42,
        principal: "vk_a".to_string(),
        kind: PostingKind::Settlement,
        incarnation: 1,
    }
}

/// A sealed audit record for a unit that ran.
fn audit_inputs(unit: u64) -> busbar_kernel_audit::AuditInputs {
    use busbar_contract::caps::{KernelSeal, Origin, OriginKind, Outcome, UnitKey};
    use busbar_kernel_audit::{
        Amount, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, What,
    };
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_000 + unit,
        mono: unit * 1_000,
        origin: Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        amount: Amount {
            lines: Vec::new(),
            pre_tier: 600,
            priced: 540,
            tier_bp: 9_000,
            fee_count: 1,
            currency: "USD".into(),
            rate_card_version: 3,
            bucket_chain_ref: "chain:free>paid".into(),
        },
        controls: Controls {
            lease_epoch: 4,
            policy_epoch: 7,
            ..Controls::default()
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

/// A sealed audit record goes on the journal, carrying the two digests that tie it back to the
/// audit unit's own chain — and the epochs it ran under land in the journal header, which is
/// where a reader asking "under which policy" looks.
#[test]
fn a_sealed_audit_record_goes_on_the_journal() {
    use busbar_contract::caps::{Audit as AuditStep, KernelSeal, Pass};
    use busbar_kernel_audit::Audit as _;

    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();
    let audit_token: Pass<AuditStep> = Pass::mint(&KernelSeal::acquire_for_kernel());

    let sealed = durability.record.seal(audit_inputs(11), &audit_token);
    let ack = durability
        .journal_audit(&sealed, &token, StepName::Meter)
        .expect("the record goes on the chain");

    let record = &ack.sealed[0];
    assert_eq!(record.class, RecordClass::Transaction);
    assert_eq!(record.wall, sealed.wall);
    assert_eq!(record.mono, sealed.mono);
    assert_eq!(record.lease_epoch, 4);
    assert_eq!(record.policy_epoch, 7);
    assert_eq!(
        record.body,
        audit_body(&sealed),
        "the body is the sealed record's, digests first"
    );
    // The tie back to the audit unit's chain: the journal body opens with that chain's two
    // hashes, so a reader holding one can find the other.
    assert!(String::from_utf8_lossy(&record.body).contains(&sealed.hash));
    assert_eq!(durability.record.sealed(), 1);
    assert_eq!(
        durability.legacy.len(),
        0,
        "journalling a sealed record must not touch the previous release's chain"
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
    assert_eq!(durability.journal.mode(), Mode::OnDisk);
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
    // And the journal starts at genesis on both.
    assert_eq!(buffered.journal.head(), on_disk.journal.head());
    assert_eq!(buffered.journal.next_seq(), 1);
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

/// Every unit's records are on ONE chain, in the order they happened, and the chain verifies.
/// This is the whole row: an audit record, a posting, a checkpoint and a migration marker, with
/// one numbering across all four.
#[test]
fn one_journal_carries_every_unit_in_one_order() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();

    durability
        .migration_records(&token, StepName::Meter)
        .write_marker(&marker(0, 1_700_000_000))
        .expect("the marker goes on the chain");
    durability
        .journal_posting(&posting(), &token, StepName::Meter)
        .expect("the posting goes on the chain");
    let checkpoint = Checkpoint::seal(
        1,
        4,
        1_700_000_100,
        Vec::new(),
        Default::default(),
        0,
        0,
        None,
    )
    .expect("an unsigned checkpoint seals");
    durability
        .journal_checkpoint(&checkpoint, &token, StepName::Meter)
        .expect("the checkpoint goes on the chain");

    let replayed = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    let classes: Vec<RecordClass> = replayed.iter().map(|r| r.class).collect();
    assert_eq!(
        classes,
        vec![
            RecordClass::Migration,
            RecordClass::Transaction,
            RecordClass::Checkpoint
        ]
    );
    let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
    assert_eq!(seqs, vec![1, 2, 3], "one numbering across every unit");
    assert!(replayed.iter().all(|r| r.node == 4));
    verify_journal(&replayed).expect("the whole chain verifies");
}

/// The migration marker lives on the journal, and reading it back is what makes a second boot
/// free. Where it used to live — the store adapter's node-local shim — it could not be read back
/// by anything else and did not survive a restart even on a node with a disk.
#[test]
fn the_migration_marker_is_a_journal_record_and_reads_back() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();

    assert_eq!(
        durability
            .migration_records(&token, StepName::Meter)
            .read_marker()
            .expect("readable"),
        None,
        "a deployment that has not migrated has no marker"
    );

    let sealed = marker(0, 1_700_000_000);
    durability
        .migration_records(&token, StepName::Meter)
        .write_marker(&sealed)
        .expect("the marker goes on the chain");

    assert_eq!(
        durability
            .migration_records(&token, StepName::Meter)
            .read_marker()
            .expect("readable"),
        Some(sealed),
        "the marker read back off the chain is the marker that was sealed"
    );
}

/// And it survives a restart when there is a disk to keep it on — which is the improvement the
/// binding buys, and the one the node-local shim could never make.
#[test]
fn with_a_data_dir_the_marker_survives_a_restart() {
    let scratch = ScratchDir::new("marker-restart");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let token = token();
    let sealed = marker(0, 1_700_000_000);

    {
        let mut durability = build_for_node(&cfg, 4, Box::new(NullShipper::new()), rows())
            .expect("the directory is writable");
        durability
            .migration_records(&token, StepName::Meter)
            .write_marker(&sealed)
            .expect("the marker goes on the chain");
    }

    let mut restarted = build_for_node(&cfg, 4, Box::new(NullShipper::new()), rows())
        .expect("the journal reopens onto what it wrote");
    assert_eq!(
        restarted
            .migration_records(&token, StepName::Meter)
            .read_marker()
            .expect("readable"),
        Some(sealed),
        "a second boot found the marker its first boot sealed"
    );
}

/// The previous release's administrative chain is UNTOUCHED by any of this.
///
/// Said by building two logs and driving one of them through a node that is also journalling:
/// every entry, including the digest that a deployment's whole history verifies against, is
/// identical. A journal that had quietly become an input to that digest would report every
/// deployed chain as tampered at the next boot, and that is the one change this release may not
/// make.
#[test]
fn journalling_does_not_touch_the_legacy_admin_chain() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();
    // The digest covers the timestamp, so the two logs are put on one fixed clock: the claim is
    // about what journalling does to the chain, and a wall clock ticking between two writes
    // would make the comparison say nothing.
    durability.legacy = AuditLog::with(Box::new(PinnedClock), Box::new(NoSeam));
    let alone = AuditLog::with(Box::new(PinnedClock), Box::new(NoSeam));

    let mutations = [
        ("key.create", "vk_a"),
        ("key.rotate", "vk_a"),
        ("key.delete", "vk_b"),
    ];

    for (action, resource) in mutations {
        // The node is journalling between administrative writes, exactly as it would be.
        durability
            .journal_posting(&posting(), &token, StepName::Meter)
            .expect("the posting goes on the chain");
        durability.legacy.record_by(
            action,
            resource,
            busbar_kernel_audit::OUTCOME_APPLIED,
            "admin",
        );
        alone.record_by(
            action,
            resource,
            busbar_kernel_audit::OUTCOME_APPLIED,
            "admin",
        );
    }

    // The WIRE, field for field, digest included: what an administrative read returns is what a
    // node with no journal at all would have returned.
    let on_the_wire = |log: &AuditLog| {
        serde_json::to_string(&log.export()).expect("the previous release's record encodes")
    };
    assert_eq!(durability.legacy.len(), 3);
    assert_eq!(
        on_the_wire(&durability.legacy),
        on_the_wire(&alone),
        "the administrative chain differs from one written on a node with no journal at all"
    );
    assert!(durability.legacy.verify());
    // And the journal has only its own records on it — the administrative entries did not leak
    // onto it either, which is the other half of "the two do not merge".
    let replayed = durability
        .journal
        .replay()
        .expect("readable")
        .expect("verifies");
    assert_eq!(replayed.len(), 3);
    assert!(replayed.iter().all(|r| r.class == RecordClass::Transaction));
}

/// A clock that does not move, so two chains written independently are comparable.
#[derive(Debug)]
struct PinnedClock;

impl Clock for PinnedClock {
    fn now(&self) -> u64 {
        1_700_000_000
    }
}

/// The shipped batches ARE the chain, so a node with no data directory that shipped everything
/// has lost nothing it shipped.
#[test]
fn what_the_store_took_is_the_chain() {
    let shipper = busbar_kernel_wal::BufferShipper::new();
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(shipper.clone()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();

    durability
        .migration_records(&token, StepName::Meter)
        .write_marker(&marker(0, 1_700_000_000))
        .expect("the marker ships");
    for _ in 0..3 {
        durability
            .journal_posting(&posting(), &token, StepName::Meter)
            .expect("the posting ships");
    }

    let shipped = decode_run(&shipper.records()).expect("the store took journal records");
    verify_journal(&shipped).expect("what the store holds is a chain that verifies");
    assert_eq!(shipped.len(), 4);
    assert_eq!(
        shipped.last().expect("a record").hash,
        durability.journal.head(),
        "the store's head is the node's head"
    );
}

// ---------------------------------------------------------------------------------------
// Settlement, bound to the journal
// ---------------------------------------------------------------------------------------

fn memory_node() -> Durability {
    build(
        &DurabilityConfig { data_dir: None },
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail")
}

fn totals_key(bucket: &str) -> TotalsKey {
    use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension};
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

fn stamp() -> PostingStamp {
    PostingStamp {
        rate_card_version: 3,
        wall: 1_700_000_000,
        mono: 42,
    }
}

fn settling<'a>(key: &'a TotalsKey, durability: &'a Grant<DurableWrite>) -> Settling<'a> {
    Settling {
        key,
        window: 86_400,
        durability,
        step: StepName::Meter,
        stamp: stamp(),
    }
}

/// One hold, one settlement, one journal record — and the books moved. Before this binding the
/// ledger moved figures that nothing put in the one order, which is the gap the journal exists
/// to close.
#[test]
fn settling_a_hold_moves_the_books_and_puts_the_posting_on_the_chain() {
    use busbar_contract::caps::{
        Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, PrincipalId,
        QuantitySource, Usage, UsageLine, WriteMoney,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let mut durability = memory_node();
    let key = totals_key("vk_settle");
    durability.ledger.record_hold_opened(&key, 86_400, 5_000);

    let hold = Hold::open(
        &Grant::<Admittance>::mint(&seal),
        PrincipalId::new("vk_settle"),
        5_000,
    );
    let usage = Usage::report(
        &Grant::<Consumption>::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: 4_200,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");

    let durability_token = token();
    let settled = durability
        .settle(
            &settling(&key, &durability_token),
            hold,
            4_200,
            &usage,
            &Grant::<WriteMoney>::mint(&seal),
        )
        .expect("the null shipper takes it");

    assert_eq!(settled.settlement.posted.settled(), 4_200);
    assert_eq!(settled.settlement.released, 800);
    assert!(settled.overdraft.is_none());
    let figures = durability.ledger.book().get(&key, 86_400);
    assert_eq!(figures.open_holds, 0);
    assert_eq!(figures.settled, 4_200);

    let replayed = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    assert_eq!(replayed.len(), 1, "one posting, one record");
    assert_eq!(replayed[0].class, RecordClass::Transaction);
    assert_eq!(replayed[0].body, settled.posting.body());
}

/// A unit that ran past everything reservable leaves TWO records: the settlement, and the carry.
/// The overdraft record's reserved and settled are zero on purpose — the settlement beside it
/// already carries both, and a replay that added them twice would double the window.
#[test]
fn an_overdraft_is_its_own_record_beside_the_posting_it_came_out_of() {
    use busbar_contract::caps::{
        Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, PrincipalId,
        QuantitySource, Usage, UsageLine, WriteMoney,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let mut durability = memory_node();
    let key = totals_key("vk_over");
    durability.ledger.record_hold_opened(&key, 86_400, 1_000);

    let mut hold = Hold::open(
        &Grant::<Admittance>::mint(&seal),
        PrincipalId::new("vk_over"),
        1_000,
    );
    // Nothing left in the slice to grow the reservation into: the spend lands anyway.
    let spend = hold.spend(4_000, 0);
    assert_eq!(spend.overdraft, 3_000);
    let usage = Usage::report(
        &Grant::<Consumption>::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: 4_000,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");

    let durability_token = token();
    let settled = durability
        .settle(
            &settling(&key, &durability_token),
            hold,
            4_000,
            &usage,
            &Grant::<WriteMoney>::mint(&seal),
        )
        .expect("the null shipper takes it");

    let note = settled
        .settlement
        .overdraft
        .as_ref()
        .expect("the ledger noted it");
    assert_eq!(note.principal, "vk_over");
    assert_eq!(note.amount, 3_000);
    let record = settled.overdraft.as_ref().expect("and journalled it");
    assert_eq!(record.reserved, 0);
    assert_eq!(record.settled, 0);
    assert_eq!(record.overdraft, 3_000);

    let replayed = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    assert_eq!(replayed.len(), 2, "the posting, then the carry");
    assert_eq!(replayed[0].body, settled.posting.body());
    assert_eq!(replayed[1].body, record.body());
    let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
    assert_eq!(
        seqs,
        vec![1, 2],
        "the carry comes after the posting it is of"
    );
    verify_journal(&replayed).expect("the chain verifies");
}

/// A shipper that takes every batch and remembers how many records each one carried.
///
/// The batch is the unit of durability: memory-buffered it is what the store is offered, on
/// disk it is what one fsync covers. So a count of batches is a count of round trips, which is
/// what the test below is about.
#[derive(Clone, Default)]
struct CountingShipper(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);

impl busbar_kernel_wal::Shipper for CountingShipper {
    fn ship(
        &mut self,
        records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(records.len());
        Ok(())
    }
}

/// ONE SETTLEMENT IS ONE BATCH, carry and all.
///
/// The posting and the overdraft record are two entries of one settlement, written on the
/// settle path every priced unit takes. Appending them separately is two batches for one act:
/// two store round trips memory-buffered, two fsyncs on disk, and a window in between where the
/// chain holds a settlement whose carry is not there yet. They go in one call, which is also
/// what makes the pair atomic against a crash rather than merely adjacent.
#[test]
fn a_settlement_and_its_carry_reach_the_journal_in_one_batch() {
    use busbar_contract::caps::{
        Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, PrincipalId,
        QuantitySource, Usage, UsageLine, WriteMoney,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let batches = CountingShipper::default();
    let mut durability = build(
        &DurabilityConfig { data_dir: None },
        Box::new(batches.clone()),
        rows(),
    )
    .expect("memory-buffered cannot fail");

    let key = totals_key("vk_batch");
    durability.ledger.record_hold_opened(&key, 86_400, 1_000);
    let mut hold = Hold::open(
        &Grant::<Admittance>::mint(&seal),
        PrincipalId::new("vk_batch"),
        1_000,
    );
    assert_eq!(hold.spend(4_000, 0).overdraft, 3_000);
    let usage = Usage::report(
        &Grant::<Consumption>::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: 4_000,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");

    let durability_token = token();
    let settled = durability
        .settle(
            &settling(&key, &durability_token),
            hold,
            4_000,
            &usage,
            &Grant::<WriteMoney>::mint(&seal),
        )
        .expect("the counting shipper takes it");
    assert!(settled.overdraft.is_some(), "the fixture overdrafts");

    let offered = batches
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        offered,
        vec![2],
        "one settlement is one batch of two records, not two batches of one"
    );

    // And the chain says exactly what it said when the two records were appended separately.
    let replayed = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].body, settled.posting.body());
    assert_eq!(
        replayed[1].body,
        settled.overdraft.as_ref().expect("the carry").body()
    );
    let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
    assert_eq!(seqs, vec![1, 2], "the carry still comes after its posting");
    verify_journal(&replayed).expect("the chain verifies");
}

/// The exit path consumes the hold, so the root can only hand over a posting. It has to reach
/// the same books and the same chain, or a unit's record would depend on which door it came
/// through.
#[test]
fn a_posting_the_exit_path_built_settles_exactly_as_a_hold_does() {
    use busbar_contract::caps::{
        Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, Posted, PrincipalId,
        QuantitySource, Usage, UsageLine, WriteMoney,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let admit = Grant::<Admittance>::mint(&seal);
    let key = totals_key("vk_both");
    let usage = |q: u64| {
        Usage::report(
            &Grant::<Consumption>::mint(&seal),
            vec![UsageLine {
                class: MeterClassId::new("nano_units"),
                quantity: q,
                source: QuantitySource::Count,
                estimated: false,
            }],
        )
        .expect("one line")
    };

    let durability_token = token();
    let at = settling(&key, &durability_token);

    let mut through_hold = memory_node();
    through_hold.ledger.record_hold_opened(&key, 86_400, 5_000);
    let a = through_hold
        .settle(
            &at,
            Hold::open(&admit, PrincipalId::new("vk_both"), 5_000),
            4_200,
            &usage(4_200),
            &Grant::<WriteMoney>::mint(&seal),
        )
        .expect("settles");

    let mut through_posting = memory_node();
    through_posting
        .ledger
        .record_hold_opened(&key, 86_400, 5_000);
    let posted = Posted::settle(
        Hold::open(&admit, PrincipalId::new("vk_both"), 5_000),
        4_200,
        &usage(4_200),
        &Grant::<WriteMoney>::mint(&seal),
    );
    let b = through_posting.settle_posted(&at, posted).expect("settles");

    assert_eq!(a.posting, b.posting);
    assert_eq!(
        through_hold.ledger.book().get(&key, 86_400),
        through_posting.ledger.book().get(&key, 86_400)
    );
    assert_eq!(through_hold.journal.head(), through_posting.journal.head());
}

/// Settle one hold of `reserved` at `used` onto `durability`, through the one settle path, with a
/// journal record — the arrival reading `mono` naming the unit.
fn settle_one(durability: &mut Durability, key: &TotalsKey, reserved: u64, used: u64, mono: u64) {
    use busbar_contract::caps::{
        Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, PrincipalId,
        QuantitySource, Usage, UsageLine, WriteMoney,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let principal = PrincipalId::new(key.bucket.as_str());
    let durability_token = token();
    let mut at = settling(key, &durability_token);
    at.stamp.mono = mono;
    durability
        .open_hold(&at, &principal, reserved)
        .expect("the journal takes the hold");
    let hold = Hold::open(&Grant::<Admittance>::mint(&seal), principal, reserved);
    let usage = Usage::report(
        &Grant::<Consumption>::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: used,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    durability
        .settle(
            &at,
            hold,
            u128::from(used),
            &usage,
            &Grant::<WriteMoney>::mint(&seal),
        )
        .expect("the journal takes the posting");
}

/// ITEM 128: THE RESTART RECONCILIATION COMPARES THE REAL BOOK, and goes RED on a book that lost a
/// row.
///
/// The restart used to open `Ledger::dual_writing` over NOTHING with no checkpoints, so the money
/// view reset to zero on every boot and the reconciliation passed because both sides were zero.
/// Here two units settle on a node with a data directory, the node restarts, and the book it comes
/// back with is the book it had — and the reconciliation, which now compares the book with what the
/// journal rebuilds, is clean over it and RED the moment a row goes missing.
#[test]
fn the_restart_reconciliation_goes_red_on_a_book_that_lost_a_row() {
    let scratch = ScratchDir::new("restart-reconcile");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_restart");
    let other = totals_key("vk_other");
    let before = {
        let mut durability = build_for_node(&cfg, 7, Box::new(NullShipper::new()), rows())
            .expect("the directory is writable");
        settle_one(&mut durability, &key, 5_000, 4_200, 1);
        settle_one(&mut durability, &other, 1_000, 1_500, 2);
        durability.ledger.book().snapshot()
    };
    assert_eq!(before.len(), 2);

    let mut restarted = build_for_node(&cfg, 7, Box::new(NullShipper::new()), rows())
        .expect("the journal reopens onto what it wrote");
    assert_eq!(
        restarted.ledger.book().snapshot(),
        before,
        "the restarted book is the book the node had, not an empty one"
    );
    let figures = restarted.ledger.book().get(&key, 86_400);
    assert_eq!(figures.settled, 4_200);
    assert_eq!(figures.drawn, 5_000);
    assert_eq!(figures.open_holds, 0);
    assert_eq!(
        restarted
            .ledger
            .book()
            .get(&other, 86_400)
            .overdraft_carried_out,
        500,
        "the overdraft is replayed once, not once per record of the settlement"
    );
    assert!(
        restarted.restart_findings.is_empty(),
        "a clean restart reconciles clean: {:?}",
        restarted.restart_findings
    );
    assert_eq!(restarted.recovered_holds, 0, "every hold was closed");
    assert_eq!(restarted.incarnation, 2, "the second boot of this journal");

    // A book that lost a row.
    restarted.ledger.book_mut().retain_from(86_401);
    let findings = restarted.reconcile_with_journal();
    assert_eq!(
        findings.len(),
        2,
        "both balances left the book: {findings:?}"
    );
    assert!(
        findings.iter().any(|f| matches!(
            f,
            JournalDisagreement::Balance { key: k, window: 86_400, journal, book }
                if *k == key && journal.settled == 4_200 && book.settled == 0
        )),
        "the finding names the balance and both readings: {findings:?}"
    );
    assert!(findings[0]
        .to_string()
        .contains("the journal rebuilds settled"));
}

/// And a single figure edited in memory, with no record behind it, is named too.
#[test]
fn the_reconciliation_names_a_figure_the_book_moved_without_a_record() {
    let mut durability = memory_node();
    let key = totals_key("vk_edit");
    settle_one(&mut durability, &key, 1_000, 900, 3);
    assert!(durability.reconcile_with_journal().is_empty());
    durability
        .ledger
        .book_mut()
        .entry(key.clone(), 86_400)
        .settled += 1;
    assert_eq!(durability.reconcile_with_journal().len(), 1);
}

/// ITEM 127: A HOLD SURVIVES A KILL -9.
///
/// Every production journal write used to happen at or after settle time, so a hold existed only in
/// memory and a node killed mid-unit took it with it: nothing on the chain said it was ever opened,
/// and `recovery::recover_all` — the code that settles what a dead incarnation left open — had no
/// production caller. Here a hold is opened on a node with a data directory and the process is
/// killed without settling it or running a single destructor. The next boot reads the hold back,
/// recovers it through the recovery table, and posts it; the boot after that finds nothing open.
#[test]
fn a_hold_survives_a_kill_9() {
    let scratch = ScratchDir::new("hold-kill9");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_killed");
    {
        let mut durability = build_for_node(&cfg, 9, Box::new(NullShipper::new()), rows())
            .expect("the directory is writable");
        let durability_token = token();
        let mut at = settling(&key, &durability_token);
        at.stamp.mono = 77;
        durability
            .open_hold(
                &at,
                &busbar_contract::caps::PrincipalId::new("vk_killed"),
                2_000,
            )
            .expect("the hold goes on the chain");
        assert_eq!(durability.ledger.book().get(&key, 86_400).open_holds, 2_000);
        // kill -9: no settle, no destructor, nothing flushed on the way out.
        std::mem::forget(durability);
    }

    let restarted = build_for_node(&cfg, 9, Box::new(NullShipper::new()), rows())
        .expect("the journal reopens onto what it wrote");
    assert_eq!(
        restarted.recovered_holds, 1,
        "the hold survived the kill and was recovered"
    );
    let figures = restarted.ledger.book().get(&key, 86_400);
    assert_eq!(figures.open_holds, 0, "the recovered hold is closed");
    assert_eq!(figures.drawn, 2_000);
    assert_eq!(
        figures.settled, 0,
        "a crash is not evidence of consumption: the recovery table posts the lower figure"
    );
    assert_eq!(
        figures.open_slice_remainders, 2_000,
        "the reservation went back to the slice"
    );
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
    let replayed = restarted
        .journal
        .replay()
        .expect("reads")
        .expect("verifies");
    let posting = replayed
        .iter()
        .filter_map(Posting::from_record)
        .find(|p| p.kind == PostingKind::Settlement)
        .expect("the recovery posted onto the chain");
    assert_eq!(posting.key, key);
    assert_eq!(
        posting.incarnation, 1,
        "closed under the incarnation that opened it"
    );
    assert_eq!(posting.mono, 77, "and under the unit's own arrival reading");
    drop(restarted);

    let third = build_for_node(&cfg, 9, Box::new(NullShipper::new()), rows())
        .expect("the journal reopens again");
    assert_eq!(
        third.recovered_holds, 0,
        "a recovered hold is not recovered twice"
    );
    // The second boot wrote nothing under its own number — the recovery closed the hold under the
    // number that opened it — so no record carries a 2 and the third boot may take it again. What
    // an incarnation has to be is distinct from every number already on the chain, and it is.
    assert_eq!(third.incarnation, 2);
    assert!(
        third.restart_findings.is_empty(),
        "{:?}",
        third.restart_findings
    );
}

/// ITEM 26: a settled figure the journal could not confirm is moved to `unreconciled`, and moves back
/// once a later append succeeds — `drawn` and `unreconciled` are written by the protocol now, not
/// structurally zero.
#[test]
fn a_posting_the_journal_lost_is_unreconciled_until_the_log_confirms_it() {
    struct Flaky(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl busbar_kernel_wal::Shipper for Flaky {
        fn ship(
            &mut self,
            _records: &[busbar_kernel_wal::Record],
        ) -> Result<(), busbar_kernel_wal::ShipError> {
            if self.0.load(std::sync::atomic::Ordering::Acquire) {
                Err(busbar_kernel_wal::ShipError::Unavailable(
                    "store down".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut durability = build(
        &DurabilityConfig { data_dir: None },
        Box::new(Flaky(std::sync::Arc::clone(&down))),
        rows(),
    )
    .expect("memory-buffered");
    let key = totals_key("vk_flaky");
    settle_one(&mut durability, &key, 1_000, 600, 1);
    assert_eq!(
        durability.ledger.book().get(&key, 86_400).drawn,
        1_000,
        "drawn is written"
    );

    down.store(true, std::sync::atomic::Ordering::Release);
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    let principal = busbar_contract::caps::PrincipalId::new("vk_flaky");
    let durability_token = token();
    let hold = busbar_contract::caps::Hold::open(
        &busbar_contract::caps::Grant::<busbar_contract::caps::Admittance>::mint(&seal),
        principal,
        0,
    );
    let usage = busbar_contract::caps::Usage::report(
        &busbar_contract::caps::Grant::<busbar_contract::caps::Consumption>::mint(&seal),
        Vec::new(),
    )
    .expect("empty");
    let lost = durability.settle(
        &settling(&key, &durability_token),
        hold,
        250,
        &usage,
        &busbar_contract::caps::Grant::<busbar_contract::caps::WriteMoney>::mint(&seal),
    );
    assert!(lost.is_err(), "the store refused the batch");
    let figures = durability.ledger.book().get(&key, 86_400);
    assert_eq!(
        figures.unreconciled, 250,
        "not reported as settled until the store confirms it"
    );
    assert_eq!(figures.settled, 600);
    assert!(busbar_kernel_ledger::identity::holds(
        &Totals::zero(),
        &figures
    ));

    down.store(false, std::sync::atomic::Ordering::Release);
    settle_one(&mut durability, &key, 0, 0, 3);
    let figures = durability.ledger.book().get(&key, 86_400);
    assert_eq!(
        figures.unreconciled, 0,
        "the next append re-offered it and it was confirmed"
    );
    assert_eq!(figures.settled, 850);
}
