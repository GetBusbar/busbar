//! Tests for `durability.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::caps::KernelSeal;
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

/// The instant the test units arrive at, in milliseconds: the card epoch their counts price at.
const ARRIVED_MS: u64 = 1_700_000_000_000;

/// The lane the test card prices.
const LANE: &str = "lane";

/// A card pricing every reserved class on [`LANE`] at ONE nano-unit per unit — so a count of `n`
/// derives a figure of `n` and a test can state both in one number.
fn one_nano_card() -> busbar_kernel_ledger::cost::RateCard {
    busbar_kernel_ledger::cost::RateCard::from_config(
        Some([(
            LANE,
            busbar_kernel_ledger::cost::TierRates {
                input: 0.001,
                output: 0.001,
                cache_read: 0.001,
                cache_write: 0.001,
            },
        )]),
        0,
    )
}

/// A dated history holding `card` from instant zero, pinned at its head.
fn pinned_history(
    card: busbar_kernel_ledger::cost::RateCard,
) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    let seq = history.append(busbar_kernel_ledger::cost::CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card,
        appended_at: 0,
        author: busbar_kernel_ledger::cost::Author::Opening,
    });
    crate::root::kernel::PinnedHistory::for_test(std::sync::Arc::new(history), seq)
}

/// The history source every money test's book prices its chain against: [`one_nano_card`].
fn priced() -> HistorySource {
    let pinned = pinned_history(one_nano_card());
    Box::new(move || Some(pinned.clone()))
}

/// A book over `cfg` as node `node`, pricing against [`priced`].
fn boot(cfg: &DurabilityConfig, node: u64) -> Result<Durability, OpenError> {
    build_priced(cfg, node, Box::new(NullShipper::new()), rows(), priced())
}

/// `n` input units on [`LANE`] — `n` nano-units under [`one_nano_card`].
fn inputs(n: u64) -> UnitCounts {
    UnitCounts {
        lane: LANE.to_string(),
        fee_count: 0,
        classes: std::collections::BTreeMap::from([("input".to_string(), n)]),
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
        arrived_ms: 0,
        flags: PostingFlags::NONE,
        principal: "vk_a".to_string(),
        kind: PostingKind::Settlement,
        incarnation: 1,
        counts: None,
        refusal: None,
        era: RecordEra::Counts,
    }
}

/// A sealed audit record for a unit that ran.
fn audit_inputs(unit: u64) -> busbar_kernel_audit::AuditInputs {
    use busbar_contract::caps::{KernelSeal, Origin, OriginKind, Outcome, UnitKey};
    use busbar_kernel_audit::{
        AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage, What,
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
        usage: Usage {
            lines: Vec::new(),
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

/// Journalling carries no administrative row, and the root holds no administrative ring (item 237).
///
/// There is ONE administrative audit ring: the kernel's durable one, written by the core-admin
/// handlers and served by `GET /api/v1/admin/audit`. The root used to hold a second, RAM-only copy
/// behind a seam that persisted nothing and that no endpoint read. Two halves:
///
/// - a node journalling postings has only its own records on the journal — an administrative row
///   never leaks onto it;
/// - the durability stack's own source constructs no administrative ring: no `AuditLog`, no
///   `NoSeam`. The end-to-end cell `the_served_audit_body_is_byte_identical_with_and_without_the_root`
///   pins that the served body did not move.
#[test]
fn journalling_carries_no_admin_row_and_the_root_holds_no_second_admin_ring() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();
    for _ in 0..3 {
        durability
            .journal_posting(&posting(), &token, StepName::Meter)
            .expect("the posting goes on the chain");
    }
    let replayed = durability
        .journal
        .replay()
        .expect("readable")
        .expect("verifies");
    assert_eq!(replayed.len(), 3);
    assert!(replayed.iter().all(|r| r.class == RecordClass::Transaction));

    let source = include_str!("../durability.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in ["AuditLog", "NoSeam"] {
        assert!(
            !code.contains(needle),
            "root/durability.rs builds a second administrative ring again: `{needle}`"
        );
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
    boot(&DurabilityConfig { data_dir: None }, 0).expect("memory-buffered cannot fail")
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

/// Settle one hold sized for `reserved` input units at `used` of them onto `durability`, through
/// the one settle path, with a journal record — the arrival reading `mono` naming the unit. Under
/// [`one_nano_card`] the figures are the counts.
fn settle_one(durability: &mut Durability, key: &TotalsKey, reserved: u64, used: u64, mono: u64) {
    use busbar_contract::caps::{
        Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, Posted, PrincipalId,
        QuantitySource, Usage, UsageLine, WriteMoney,
    };
    let seal = KernelSeal::acquire_for_kernel();
    let principal = PrincipalId::new(key.bucket.as_str());
    let durability_token = token();
    let mut at = settling(key, &durability_token);
    at.stamp.mono = mono;
    durability
        .open_hold(&at, &principal, &inputs(reserved), ARRIVED_MS)
        .expect("the journal takes the hold");
    let hold = Hold::open(&Grant::<Admittance>::mint(&seal), principal, reserved);
    let usage = Usage::report(
        &Grant::<Consumption>::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("input"),
            quantity: used,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    let posted = Posted::settle(
        hold,
        u128::from(used),
        &usage,
        &Grant::<WriteMoney>::mint(&seal),
    );
    durability
        .settle_counted(&at, posted, &inputs(used), ARRIVED_MS)
        .expect("the journal takes the posting");
}

/// PB-58: A SPEND PAST THE RESERVATION IS CARRIED OUT AS AN OVERDRAFT — the unit runs to its end
/// and settles, and the part nothing reserved is carried, DERIVED AT READ (#71, Q9).
///
/// A unit reserved 1,000 and spent 1,500. It is not ended for money: its hold closes by a
/// settlement, like any other. The chain holds that settlement's counts and epoch and no figure,
/// and the carry beside it holds no figure either. The node restarts, and the book it rebuilds
/// from those counts carries 500 out as an overdraft — settled 1,500 against 1,000 reserved —
/// and the chain read back through the one spend function says the same of the posting.
#[test]
fn a_spend_past_the_reservation_is_carried_out_as_an_overdraft() {
    let scratch = ScratchDir::new("overdraft-carried-out");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_overdraft");
    {
        let mut durability = boot(&cfg, 8).expect("the directory is writable");
        settle_one(&mut durability, &key, 1_000, 1_500, 1);
        let records = durability
            .journal
            .replay()
            .expect("reads")
            .expect("verifies");
        let on_chain: Vec<Posting> = records.iter().filter_map(Posting::from_record).collect();
        assert_eq!(
            on_chain.iter().map(|p| p.kind).collect::<Vec<_>>(),
            vec![PostingKind::Settlement, PostingKind::Carry],
            "the unit settled, and the carry sits beside its settlement"
        );
        for posting in &on_chain {
            assert_eq!(
                (posting.reserved, posting.settled, posting.overdraft),
                (0, 0, 0),
                "no record holds the overdraft: it is a derivation, not a fact on the chain"
            );
        }
    }

    let restarted = boot(&cfg, 8).expect("the journal reopens onto what it wrote");
    let figures = restarted.ledger.book().get(&key, 86_400);
    assert_eq!(figures.settled, 1_500, "the whole spend is posted");
    assert_eq!(figures.open_holds, 0, "the hold closed by settling");
    assert_eq!(
        figures.overdraft_carried_out, 500,
        "the part past the reservation is carried out, derived from the counts at read"
    );
    assert_eq!(restarted.recovered_holds, 0, "no unit was left unsettled");
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );

    let settlement = restarted
        .read_back()
        .into_iter()
        .find(|p| p.kind == PostingKind::Settlement)
        .expect("the settlement reads back");
    assert_eq!(
        (
            settlement.reserved,
            settlement.settled,
            settlement.overdraft
        ),
        (1_000, 1_500, 500),
        "read through the one spend function, the posting carries the overdraft out"
    );
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
        let mut durability = boot(&cfg, 7).expect("the directory is writable");
        settle_one(&mut durability, &key, 5_000, 4_200, 1);
        settle_one(&mut durability, &other, 1_000, 1_500, 2);
        durability.ledger.book().snapshot()
    };
    assert_eq!(before.len(), 2);

    let mut restarted = boot(&cfg, 7).expect("the journal reopens onto what it wrote");
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
        let mut durability = boot(&cfg, 9).expect("the directory is writable");
        let durability_token = token();
        let mut at = settling(&key, &durability_token);
        at.stamp.mono = 77;
        durability
            .open_hold(
                &at,
                &busbar_contract::caps::PrincipalId::new("vk_killed"),
                &inputs(2_000),
                ARRIVED_MS,
            )
            .expect("the hold goes on the chain");
        assert_eq!(durability.ledger.book().get(&key, 86_400).open_holds, 2_000);
        // kill -9: no settle, no destructor, nothing flushed on the way out.
        std::mem::forget(durability);
    }

    let restarted = boot(&cfg, 9).expect("the journal reopens onto what it wrote");
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

    let third = boot(&cfg, 9).expect("the journal reopens again");
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
    let mut durability = build_priced(
        &DurabilityConfig { data_dir: None },
        0,
        Box::new(Flaky(std::sync::Arc::clone(&down))),
        rows(),
        priced(),
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

// ---------------------------------------------------------------------------------------------
// P2A-books (#71/#43/#42): THE POSTING RECORD CARRIES THE UNIT'S RAW COUNTS
// ---------------------------------------------------------------------------------------------

/// A unit's counts on lane `"lane"`: a reserved class and an OPEN one.
fn unit_counts() -> UnitCounts {
    UnitCounts {
        lane: "lane".to_string(),
        fee_count: 1,
        classes: std::collections::BTreeMap::from([
            ("input".to_string(), 1_000),
            ("search_units".to_string(), 50),
        ]),
    }
}

/// THE BODY A POSTING HAD WHILE THE CHAIN CARRIED FIGURES — spelled out field by field, not by
/// calling [`Posting::body`], so the replay below is judged against the bytes an earlier build
/// wrote: the balance display, the window, reserved / settled / overdraft as figures, the card
/// version, and the tail that places it.
fn figures_era_body(p: &Posting) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.text(&p.key.to_string());
    body.num(p.window);
    body.figure(p.reserved);
    body.figure(p.settled);
    body.figure(p.overdraft);
    body.num(p.rate_card_version);
    body.text("posting.v2");
    body.num(1);
    body.num(p.incarnation);
    body.text(&p.principal);
    write_key(&mut body, &p.key);
    body.finish()
}

/// THE BODY A HOLD HAD WHILE THE CHAIN CARRIED FIGURES: the reserved figure itself.
fn figures_era_hold(p: &Posting, reserved: u64) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.text("hold.open");
    body.num(p.incarnation);
    body.text(&p.principal);
    write_key(&mut body, &p.key);
    body.num(p.window);
    body.num(reserved);
    body.finish()
}

/// MIGRATE ON READ: a chain written while postings carried money figures still loads, and rebuilds
/// the book those records describe — no finding, no recovered hold, no counts invented.
///
/// The chain is written with the FIGURES-ERA bodies (a hold holding its reserved figure, and the
/// settlement that closes it holding its three figures), the node restarts over it, and the book is
/// the book those records say. Nothing is rewritten: the figure is the fact that record holds, and
/// there are no counts to derive another from.
#[test]
fn a_chain_written_while_postings_carried_figures_still_loads() {
    let scratch = ScratchDir::new("figures-era-replay");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_a");
    let old = posting();
    // The record this build writes is not the figures-era body, and carries no figure at all.
    assert_ne!(old.body(), figures_era_body(&old));
    {
        let mut durability = boot(&cfg, 5).expect("the directory is writable");
        let token = token();
        let entries = [
            Entry::new(RecordClass::Transaction, figures_era_hold(&old, 5_000))
                .at(old.wall, old.mono),
            Entry::new(RecordClass::Transaction, figures_era_body(&old)).at(old.wall, old.mono),
        ];
        durability
            .journal
            .append(&token, StepName::Meter, &entries)
            .expect("the journal takes the figures-era records");
    }
    let restarted = boot(&cfg, 5).expect("the journal reopens");
    assert!(
        restarted.restart_findings.is_empty(),
        "a figures-era chain reconciles clean: {:?}",
        restarted.restart_findings
    );
    assert_eq!(
        restarted.recovered_holds, 0,
        "the figures-era posting closed its figures-era hold"
    );
    let figures = restarted.ledger.book().get(&key, 86_400);
    assert_eq!(figures.settled, 4_200);
    assert_eq!(figures.drawn, 5_000);
    assert_eq!(figures.open_holds, 0);
    assert!(restarted.refused_rows().is_empty());
    let read_back = restarted
        .journal
        .replay()
        .expect("reads")
        .expect("verifies")
        .iter()
        .find_map(Posting::from_record)
        .expect("the figures-era posting reads back");
    assert_eq!(read_back.era, RecordEra::Figures);
    assert_eq!(
        read_back.counts, None,
        "no counts are invented for an old record"
    );
    assert_eq!(read_back.settled, 4_200);
    drop(restarted);

    // The SAME unit written through the counted path, and its record re-spelled as the figures-era
    // body: the two chains rebuild the same book — one from the figure it holds, the other from the
    // counts it holds, priced at their epoch.
    let scratch_counted = ScratchDir::new("counted-replay");
    let scratch_old = ScratchDir::new("counted-replay-old");
    let counted_cfg = DurabilityConfig {
        data_dir: Some(scratch_counted.path.clone()),
    };
    let old_cfg = DurabilityConfig {
        data_dir: Some(scratch_old.path.clone()),
    };
    let written = {
        let mut durability = boot(&counted_cfg, 5).expect("the directory is writable");
        late_counted(&mut durability, &key, 4_200, &inputs(4_200))
    };
    assert_eq!(written.counts, Some(inputs(4_200)));
    {
        let mut durability = boot(&old_cfg, 5).expect("the directory is writable");
        let entry = Entry::new(RecordClass::Transaction, figures_era_body(&written))
            .at(written.wall, written.mono);
        durability
            .journal
            .append(&token(), StepName::Meter, &[entry])
            .expect("the journal takes the figures-era record");
    }
    let counted = boot(&counted_cfg, 5).expect("the journal reopens");
    let old_chain = boot(&old_cfg, 5).expect("the journal reopens");
    assert!(
        counted.restart_findings.is_empty(),
        "{:?}",
        counted.restart_findings
    );
    assert!(
        old_chain.restart_findings.is_empty(),
        "{:?}",
        old_chain.restart_findings
    );
    assert_eq!(
        counted.ledger.book().snapshot(),
        old_chain.ledger.book().snapshot(),
        "a figures-era body rebuilds the same book as the counted one"
    );
    assert_eq!(counted.ledger.book().get(&key, 86_400).settled, 4_200);
    let read = |d: &Durability| {
        d.read_back()
            .into_iter()
            .find(|p| p.kind == PostingKind::Settlement)
            .expect("the settlement reads back")
    };
    assert_eq!(read(&counted).counts, Some(inputs(4_200)));
    assert_eq!(read(&counted).era, RecordEra::Counts);
    assert_eq!(read(&counted).settled, 4_200, "derived, at the epoch");
    assert_eq!(read(&old_chain).counts, None);
    assert_eq!(read(&old_chain).settled, 4_200, "read as written");
}

/// **THE CHAIN STORES COUNTS AND THE CARD EPOCH, NEVER MONEY — the money is a view (#71, #79).**
///
/// A counted unit settles at 4,200 nano-units under the card in force at its arrival. Its record
/// carries its counts and that instant and NO figure: read straight off the chain it holds nothing
/// priced. Then the operator's sanctioned repair for "the ratecard was wrong" lands — a back-dated
/// correction whose window covers the unit's arrival, doubling the rate — and the node restarts.
/// The rebuilt book prices the SAME counts at the card now in force for that instant: 8,400. A
/// chain that stored the settled figure would rebuild 4,200 forever, which is a stored price.
///
/// And where the card did not change, the figure does not move: a unit arriving outside the
/// correction's window rebuilds at exactly what it settled at.
#[test]
fn the_chain_holds_counts_and_an_epoch_and_the_rebuilt_book_prices_them() {
    let scratch = ScratchDir::new("counts-are-the-record");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let inside = totals_key("vk_inside");
    let outside = totals_key("vk_outside");
    const CORRECTED_FROM: u64 = ARRIVED_MS - 1_000;
    const CORRECTED_UNTIL: u64 = ARRIVED_MS + 1_000;
    {
        let mut durability = boot(&cfg, 3).expect("the directory is writable");
        late_counted(&mut durability, &inside, 4_200, &inputs(4_200));
        late_counted_at(
            &mut durability,
            &outside,
            700,
            &inputs(700),
            CORRECTED_UNTIL + 1,
        );
        let records = durability
            .journal
            .replay()
            .expect("reads")
            .expect("verifies");
        let on_chain: Vec<Posting> = records
            .iter()
            .filter_map(Posting::from_record)
            .filter(|p| p.kind == PostingKind::Settlement)
            .collect();
        assert_eq!(on_chain.len(), 2);
        for posting in &on_chain {
            assert_eq!(posting.era, RecordEra::Counts);
            assert!(posting.counts.is_some(), "the record carries the counts");
            assert_ne!(posting.arrived_ms, 0, "and the instant they price at");
            assert_eq!(
                (posting.reserved, posting.settled, posting.overdraft),
                (0, 0, 0),
                "and no figure: nothing priced is read off the chain"
            );
        }
    }

    // THE CORRECTION: the same lane at TWO nano-units per unit, over a window covering `inside`.
    let doubled = busbar_kernel_ledger::cost::RateCard::from_config(
        Some([(
            LANE,
            busbar_kernel_ledger::cost::TierRates {
                input: 0.002,
                output: 0.002,
                cache_read: 0.002,
                cache_write: 0.002,
            },
        )]),
        0,
    );
    let mut history = busbar_kernel_ledger::cost::History::new();
    history.append(busbar_kernel_ledger::cost::CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: one_nano_card(),
        appended_at: 0,
        author: busbar_kernel_ledger::cost::Author::Opening,
    });
    let head = history.append(busbar_kernel_ledger::cost::CardEntryDraft {
        effective_from: CORRECTED_FROM,
        effective_until: Some(CORRECTED_UNTIL),
        card: doubled,
        appended_at: ARRIVED_MS + 10_000,
        author: busbar_kernel_ledger::cost::Author::Amend {
            operator_fingerprint: "op".to_string(),
            reason_hash: [0; 32],
        },
    });
    let corrected =
        crate::root::kernel::PinnedHistory::for_test(std::sync::Arc::new(history), head);
    let restarted = build_priced(
        &cfg,
        3,
        Box::new(NullShipper::new()),
        rows(),
        Box::new(move || Some(corrected.clone())),
    )
    .expect("the journal reopens");
    assert_eq!(
        restarted.ledger.book().get(&inside, 86_400).settled,
        8_400,
        "the rebuilt book prices the unit's counts at the card in force for its arrival"
    );
    assert_eq!(
        restarted.ledger.book().get(&outside, 86_400).settled,
        700,
        "where the card did not change, the figure does not move"
    );
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
}

/// A late settlement of `amount` (no hold behind it, as the LLM late arm posts), with its counts,
/// arriving at [`ARRIVED_MS`].
fn late_counted(
    durability: &mut Durability,
    key: &TotalsKey,
    amount: u64,
    counts: &UnitCounts,
) -> Posting {
    late_counted_at(durability, key, amount, counts, ARRIVED_MS)
}

/// [`late_counted`], arriving at `arrived_ms`.
fn late_counted_at(
    durability: &mut Durability,
    key: &TotalsKey,
    amount: u64,
    counts: &UnitCounts,
    arrived_ms: u64,
) -> Posting {
    use busbar_contract::caps::{Grant, HoldAccrual, KernelSeal, Posted, PrincipalId, WriteMoney};
    let seal = KernelSeal::acquire_for_kernel();
    let ledger = Grant::<WriteMoney>::mint(&seal);
    let accrual =
        HoldAccrual::after_terminal(PrincipalId::new(key.bucket.as_str()), amount, &ledger);
    let posted = Posted::settle_late(accrual, &ledger);
    let durability_token = token();
    durability
        .settle_counted(
            &settling(key, &durability_token),
            posted,
            counts,
            arrived_ms,
        )
        .expect("the journal takes the posting")
        .posting
}

/// A REFUSED COUNTS ROW IS DURABLE, MOVES NO BALANCE, AND EVERY READ OVER IT REFUSES (#42/#43) —
/// before a restart and after one.
#[test]
fn a_refused_counts_row_survives_a_restart_and_the_read_refuses() {
    let scratch = ScratchDir::new("refused-row");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_refused");
    let principal = busbar_contract::caps::PrincipalId::new("vk_refused");
    {
        let mut durability = boot(&cfg, 6).expect("the directory is writable");
        let durability_token = token();
        let row = durability
            .post_counts(
                &settling(&key, &durability_token),
                &principal,
                &unit_counts(),
                ARRIVED_MS,
                Some("ClassUnpriced search_units".to_string()),
            )
            .expect("the journal takes the counts row");
        assert_eq!(row.kind, PostingKind::Counted);
        assert_eq!((row.reserved, row.settled, row.overdraft), (0, 0, 0));
        assert_eq!(
            durability.ledger.book().get(&key, 86_400),
            Totals::zero(),
            "a refused row moves no balance"
        );
        let refused = durability
            .settled_read(&key, 86_400)
            .expect_err("a read over a refused row refuses");
        assert_eq!(refused.lane, "lane");
        assert!(durability.reconcile_with_journal().is_empty());
    }
    let restarted = boot(&cfg, 6).expect("the journal reopens");
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
    assert_eq!(
        restarted.refused_rows().len(),
        1,
        "the refused row survived the restart"
    );
    assert_eq!(restarted.refused_rows()[0].counts, Some(unit_counts()));
    assert!(
        restarted.settled_read(&key, 86_400).is_err(),
        "the read still refuses after a restart"
    );
    assert_eq!(
        restarted.settled_read(&totals_key("vk_other"), 86_400),
        Ok(0),
        "a balance with no refused row still reads"
    );
    assert_eq!(restarted.ledger.book().get(&key, 86_400), Totals::zero());
}

/// A node that lost a refused row from memory is named by the restart reconciliation.
#[test]
fn the_reconciliation_names_a_refused_row_the_node_lost() {
    let mut durability = memory_node();
    let key = totals_key("vk_lost_row");
    let durability_token = token();
    durability
        .post_counts(
            &settling(&key, &durability_token),
            &busbar_contract::caps::PrincipalId::new("vk_lost_row"),
            &unit_counts(),
            ARRIVED_MS,
            Some("LaneUnpriced".to_string()),
        )
        .expect("taken");
    assert!(durability.reconcile_with_journal().is_empty());
    durability.refused.clear();
    assert_eq!(
        durability.reconcile_with_journal(),
        vec![JournalDisagreement::RefusedRows {
            journal: 1,
            book: 0
        }]
    );
}

/// A HOLD WHOSE UNIT DISPATCHED IS RECOVERED AT ITS LAST ACCRUAL CHECKPOINT, MARKED RECOVERED — and
/// one whose unit never dispatched is recovered at nothing, marked VOIDED.
///
/// Two units open holds on a node with a data directory. The first records that it dispatched and
/// checkpoints an accrual of 300 input units; the second dispatches nothing. The process is killed
/// with both holds open. The next boot reads the dispatch and the checkpoint back off the chain,
/// and the recovery table posts what they support: 300 for the unit that sent something, marked
/// recovered, and zero for the one that did not, marked void. Before the dispatch and the checkpoint
/// were on the chain the boot could only ever post zero, marked void, for a unit killed after its
/// answer was relayed.
#[test]
fn a_unit_killed_after_it_dispatched_is_recovered_at_its_checkpoint_and_not_voided() {
    use busbar_contract::caps::PrincipalId;
    let scratch = ScratchDir::new("recovered-not-voided");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let sent = totals_key("vk_sent");
    let idle = totals_key("vk_idle");
    {
        let mut durability = boot(&cfg, 11).expect("the directory is writable");
        let durability_token = token();
        let mut at = settling(&sent, &durability_token);
        at.stamp.mono = 77;
        durability
            .open_hold(
                &at,
                &PrincipalId::new("vk_sent"),
                &inputs(2_000),
                ARRIVED_MS,
            )
            .expect("the hold goes on the chain");
        durability
            .journal_dispatch(&at)
            .expect("the dispatch goes on the chain");
        durability
            .checkpoint_accrual(&at, &inputs(300), ARRIVED_MS)
            .expect("the checkpoint goes on the chain");
        let mut quiet = settling(&idle, &durability_token);
        quiet.stamp.mono = 78;
        durability
            .open_hold(
                &quiet,
                &PrincipalId::new("vk_idle"),
                &inputs(500),
                ARRIVED_MS,
            )
            .expect("the hold goes on the chain");
        // kill -9: no settle, no destructor, nothing flushed on the way out.
        std::mem::forget(durability);
    }

    let restarted = boot(&cfg, 11).expect("the journal reopens");
    assert_eq!(restarted.recovered_holds, 2);
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
    let posted = restarted.read_back();
    let of = |key: &TotalsKey| {
        posted
            .iter()
            .find(|p| p.kind == PostingKind::Settlement && p.key == *key)
            .cloned()
            .expect("the recovery posted onto the chain")
    };
    let recovered = of(&sent);
    assert!(
        recovered.flags.contains(PostingFlags::RECOVERED),
        "a unit that dispatched is recovered, not voided: {:?}",
        recovered.flags
    );
    assert!(!recovered.flags.contains(PostingFlags::VOIDED));
    assert_eq!(
        recovered.settled, 300,
        "the last checkpoint, priced at its epoch"
    );
    assert_eq!(recovered.counts, Some(inputs(300)));
    let voided = of(&idle);
    assert!(
        voided.flags.contains(PostingFlags::VOIDED),
        "a unit that never dispatched owes nothing: {:?}",
        voided.flags
    );
    assert_eq!(voided.settled, 0);

    let figures = restarted.ledger.book().get(&sent, 86_400);
    assert_eq!(figures.settled, 300);
    assert_eq!(figures.open_holds, 0, "the recovered hold is closed");
    assert_eq!(
        figures.open_slice_remainders, 1_700,
        "the unconsumed reservation went back"
    );
    assert_eq!(restarted.ledger.book().get(&idle, 86_400).settled, 0);
    let before = restarted.ledger.book().snapshot();
    drop(restarted);

    let third = boot(&cfg, 11).expect("the journal reopens again");
    assert_eq!(
        third.recovered_holds, 0,
        "a recovered hold is not recovered twice"
    );
    assert_eq!(
        third.ledger.book().snapshot(),
        before,
        "the recovered postings rebuild the same book"
    );
    assert!(
        third.restart_findings.is_empty(),
        "{:?}",
        third.restart_findings
    );
}

/// AN IDEMPOTENCY CLAIM TAKEN WITH NO HOLD MADE DURABLE BEHIND IT IS VOIDED AT RECOVERY — once — and
/// a claim whose hold was made durable is not.
///
/// The kill point between the claim and the hold is the one at which the recovery table voids the
/// claim: kept, it is a key that would answer the client's retry with a unit that never ran. The
/// void goes on the chain, so the boot after does not void it again.
#[test]
fn an_idempotency_claim_with_no_hold_behind_it_is_voided_at_recovery() {
    use busbar_contract::caps::PrincipalId;
    let scratch = ScratchDir::new("claim-voided");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_claims");
    {
        let mut durability = boot(&cfg, 12).expect("the directory is writable");
        let durability_token = token();
        let mut orphan = settling(&key, &durability_token);
        orphan.stamp.mono = 5;
        durability
            .journal_claim(&orphan, "idem-orphan")
            .expect("the claim goes on the chain");
        let mut backed = settling(&key, &durability_token);
        backed.stamp.mono = 6;
        durability
            .journal_claim(&backed, "idem-backed")
            .expect("the claim goes on the chain");
        durability
            .open_hold(
                &backed,
                &PrincipalId::new("vk_claims"),
                &inputs(10),
                ARRIVED_MS,
            )
            .expect("the hold goes on the chain");
        std::mem::forget(durability);
    }

    let restarted = boot(&cfg, 12).expect("the journal reopens");
    assert_eq!(
        restarted.voided_claims,
        vec!["idem-orphan".to_string()],
        "the claim with no hold behind it is voided; the backed one is not"
    );
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
    drop(restarted);

    let third = boot(&cfg, 12).expect("the journal reopens again");
    assert!(
        third.voided_claims.is_empty(),
        "a voided claim is not voided twice: {:?}",
        third.voided_claims
    );
}

/// A JOURNAL SEGMENT CORRUPTED MID-LOG DOES NOT STOP THE BOOT, AND IS NOT SILENT: the book opens over
/// the records before the damage, the damaged remainder is in a quarantine file beside the segment,
/// the verdict names the file, the offset and the byte count, and a durable `ChainBreak` record of
/// it goes on the chain.
#[test]
fn a_mid_log_corrupt_journal_boots_quarantines_and_records_it() {
    use busbar_kernel_wal::{Entry, Journal, QuarantineKept, RecordClass, FRAME_BYTES};

    let dir = ScratchDir::new("quarantine");
    {
        let mut journal =
            Journal::in_directory(0, &dir.path, Box::new(NullShipper::new())).expect("opens");
        for i in 0..4u8 {
            journal
                .append(
                    &token(),
                    StepName::Meter,
                    &[Entry::new(RecordClass::Load, vec![i; 8]).at(1, 0)],
                )
                .expect("appends");
        }
    }
    let segment = dir.path.join("0000000000000000.wal");
    let mut bytes = std::fs::read(&segment).expect("the segment is there");
    bytes[FRAME_BYTES + 200] ^= 0xFF;
    std::fs::write(&segment, &bytes).expect("damaged");

    let mut durability = build_for_node(
        &DurabilityConfig {
            data_dir: Some(dir.path.clone()),
        },
        0,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("a corrupt journal does not stop the boot");

    assert_eq!(durability.quarantined.len(), 1);
    let q = durability.quarantined[0].clone();
    assert_eq!(q.segment_file.as_deref(), Some(segment.as_path()));
    assert_eq!(q.offset, FRAME_BYTES as u64);
    assert_eq!(q.bytes, 3 * FRAME_BYTES as u64);
    let QuarantineKept::File(file) = &q.kept else {
        panic!("an on-disk journal quarantines to a file");
    };
    assert_eq!(
        std::fs::read(file).expect("the quarantine file is there"),
        bytes[FRAME_BYTES..4 * FRAME_BYTES].to_vec()
    );

    let ack = durability
        .journal_quarantines(&token(), StepName::Meter, 1_758_700_000)
        .expect("appends")
        .expect("a quarantine is recorded");
    assert_eq!(ack.sealed.len(), 1);
    assert_eq!(ack.sealed[0].class, RecordClass::ChainBreak);
}
