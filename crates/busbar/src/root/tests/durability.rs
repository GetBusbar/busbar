//! Tests for `durability.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_kernel_audit::{Recipe, UsageLine};
use busbar_kernel_ledger::legacy::RecordingRows;
use busbar_kernel_wal::{decode_run, verify_journal, NullShipper, FRAME_BYTES};

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
    busbar_kernel::test_support::tokens::grant::<DurableWrite>()
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
                input: busbar_kernel_ledger::cost::representable_nano_rate(0.001),
                output: busbar_kernel_ledger::cost::representable_nano_rate(0.001),
                cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.001),
                cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.001),
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
fn audit_inputs(unit: u64) -> AuditInputs {
    use busbar_contract::caps::{OriginKind, Outcome, UnitKey};
    use busbar_kernel_audit::{
        AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage, What,
    };
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_000 + unit,
        mono: unit * 1_000,
        origin: busbar_kernel::test_support::tokens::origin(OriginKind::Client),
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

/// A pass the audit step was lent, as the loop hands it back with the unit's facts.
fn audit_pass() -> busbar_contract::caps::Pass<busbar_contract::caps::Audit> {
    busbar_kernel::test_support::tokens::pass()
}

/// A UNIT'S RECORD GOES ON THE JOURNAL WHOLE (`audit.v4`): the record read back off the chain is the
/// record sealed, stamped with this boot's incarnation — and the epochs it ran under land in the
/// journal header, which is where a reader asking "under which policy" looks.
#[test]
fn a_sealed_audit_record_goes_on_the_journal_whole() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    let token = token();
    let sealed = durability
        .seal_unit(audit_inputs(11), audit_pass(), &token)
        .expect("the record goes on the chain");
    assert_eq!(sealed.what.incarnation, durability.incarnation);
    assert_eq!(sealed.recipe, Recipe::V4);

    let records = durability.journal.replay().unwrap().unwrap();
    let on_chain: Vec<_> = records
        .iter()
        .filter_map(|r| decode_audit(r).expect("it decodes").map(|a| (r, a)))
        .collect();
    assert_eq!(on_chain.len(), 1);
    let (record, back) = &on_chain[0];
    assert_eq!(record.class, RecordClass::Transaction);
    assert_eq!(record.wall, sealed.wall);
    assert_eq!(record.mono, sealed.mono);
    assert_eq!(record.lease_epoch, 4);
    assert_eq!(record.policy_epoch, 7);
    assert_eq!(*back, sealed, "the journal keeps the whole record");
    assert_eq!(durability.record.sealed(), 1);
    assert_eq!(durability.audit_records, vec![sealed]);
}

/// TWO BOOTS THAT MINT THE SAME UNIT KEY SEAL TWO DIFFERENT, VERIFIED RECORDS. The unit key restarts
/// with the process; the incarnation does not. The second boot's record continues the first boot's
/// chain (its link names the first record), and the whole chain read back verifies from genesis.
#[test]
fn two_boots_minting_the_same_unit_key_seal_distinct_verified_records() {
    let scratch = ScratchDir::new("audit-two-boots");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let first = {
        let mut durability = boot(&cfg, 7).expect("the directory is writable");
        durability
            .seal_unit(audit_inputs(1), audit_pass(), &token())
            .expect("sealed")
    };
    let mut restarted = boot(&cfg, 7).expect("the journal reopens");
    let second = restarted
        .seal_unit(audit_inputs(1), audit_pass(), &token())
        .expect("sealed");
    assert_eq!(first.what.unit_key, second.what.unit_key);
    assert_ne!(first.what.incarnation, second.what.incarnation);
    assert_ne!(first.hash, second.hash, "the boot is in the digest");
    assert_eq!(
        second.prev_hash, first.hash,
        "the chain continues across the boot"
    );
    assert_eq!(second.seq, first.seq + 1);

    let reread = boot(&cfg, 7).expect("the journal reopens");
    let whole = reread
        .audit_window(1, u64::MAX)
        .expect("the journal reads back");
    assert_eq!(whole, vec![first, second]);
    assert!(AuditChain::verify_chain(&whole).is_ok());
    assert!(reread.retained_audit_findings().is_empty());
}

/// A WINDOW OLDER THAN THE CACHE IS READ BACK OFF THE JOURNAL after a restart — never answered as
/// empty because the in-memory ring let it go.
#[test]
fn a_range_older_than_the_ring_is_read_back_after_a_restart() {
    let scratch = ScratchDir::new("audit-older-than-ring");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let total = (AUDIT_RING + 5) as u64;
    {
        let mut durability = boot(&cfg, 7).expect("the directory is writable");
        for unit in 1..=total {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert_eq!(durability.audit_records.len(), AUDIT_RING);
    }
    let restarted = boot(&cfg, 7).expect("the journal reopens");
    assert_eq!(restarted.audit_records.len(), AUDIT_RING);
    assert_eq!(
        restarted.audit_records[0].seq, 6,
        "the cache holds the newest"
    );
    let old = restarted
        .audit_window(1, 3)
        .expect("the journal reads back");
    assert_eq!(
        old.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the journal answers for what the cache let go"
    );
    assert!(AuditChain::verify_window(&old).is_ok());
    let newest = restarted
        .audit_window(total, total)
        .expect("the cache answers");
    assert_eq!(newest[0].seq, total);
}

/// A RETAINED RECORD EDITED AFTER IT WAS SEALED IS A `/verify` FINDING.
#[test]
fn a_tampered_retained_record_is_a_verify_finding() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
        rows(),
    )
    .expect("memory-buffered cannot fail");
    for unit in 1..=3 {
        durability
            .seal_unit(audit_inputs(unit), audit_pass(), &token())
            .expect("sealed");
    }
    assert!(durability.retained_audit_findings().is_empty());
    durability.audit_records[1].usage.fee_count += 1;
    let findings = durability.retained_audit_findings();
    assert!(
        findings.iter().any(|f| f.contains("DigestMismatch")),
        "{findings:?}"
    );
}

/// Bind the deployment keyset over `dir`, as the boot does.
fn bind_keyset(durability: &mut Durability, dir: &std::path::Path) {
    crate::root::keyset::bind(
        durability,
        Some(dir),
        &token(),
        StepName::Meter,
        1_700_000_000,
    )
    .expect("the keyset binds");
}

/// Strip a retained record's signature. The signature is not in the digest, so the chain stays
/// whole: only the unsigned rule can see it.
fn strip_signature(record: &mut AuditRecord) {
    record.signature = None;
    record.key_id = None;
}

/// AN UNSIGNED RECORD SEALED WHILE THE KEYSET WAS BOUND IS A `/verify` FINDING (MONEY-AUDIT E5):
/// in the boot that sealed it, and after a restart, where the `Bootstrap` on the chain says the key
/// was bound before it. RED arm: the walk skipped every record naming no key, so a record whose
/// signature was stripped verified clean.
#[test]
fn an_unsigned_record_sealed_under_a_bound_keyset_is_a_verify_finding() {
    let scratch = ScratchDir::new("audit-unsigned-under-key");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut durability = boot(&cfg, 7).expect("the directory is writable");
        bind_keyset(&mut durability, &scratch.path);
        for unit in 1..=2 {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert!(durability.retained_audit_findings().is_empty());
        strip_signature(&mut durability.audit_records[1]);
        let findings = durability.retained_audit_findings();
        assert_eq!(
            findings,
            vec!["record 2 is unsigned, sealed after the keyset was bound".to_string()]
        );
    }
    let mut restarted = boot(&cfg, 7).expect("the journal reopens");
    bind_keyset(&mut restarted, &scratch.path);
    assert!(restarted.retained_audit_findings().is_empty());
    strip_signature(&mut restarted.audit_records[0]);
    assert_eq!(
        restarted.retained_audit_findings(),
        vec!["record 1 is unsigned, sealed after the keyset was bound".to_string()]
    );
}

/// A RECORD SEALED BEFORE THE KEYSET WAS BOUND IS UNSIGNED, AND THAT IS NOT A FINDING: a chain a
/// keyless boot began, continued by a boot that binds a key, verifies clean across both — before
/// and after a restart.
#[test]
fn records_sealed_before_the_keyset_was_bound_are_not_findings() {
    let scratch = ScratchDir::new("audit-unsigned-before-key");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut keyless = boot(&cfg, 7).expect("the directory is writable");
        for unit in 1..=2 {
            keyless
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert!(keyless.retained_audit_findings().is_empty());
    }
    {
        let mut keyed = boot(&cfg, 7).expect("the journal reopens");
        bind_keyset(&mut keyed, &scratch.path);
        let third = keyed
            .seal_unit(audit_inputs(3), audit_pass(), &token())
            .expect("sealed");
        assert!(third.key_id.is_some(), "sealed under the bound key");
        assert!(keyed.retained_audit_findings().is_empty());
    }
    let mut reread = boot(&cfg, 7).expect("the journal reopens");
    bind_keyset(&mut reread, &scratch.path);
    assert!(reread.retained_audit_findings().is_empty());
    strip_signature(&mut reread.audit_records[2]);
    assert_eq!(
        reread.retained_audit_findings(),
        vec!["record 3 is unsigned, sealed after the keyset was bound".to_string()]
    );
}

/// A JOURNALLED RECORD NAMING A CLASS NOBODY DECLARES HERE IS A RESTART FINDING, never a record
/// silently skipped or a line silently dropped.
#[test]
fn an_audit_record_naming_an_undeclared_class_is_a_restart_finding() {
    let scratch = ScratchDir::new("audit-undeclared-class");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut durability = boot(&cfg, 7).expect("the directory is writable");
        let mut inputs = audit_inputs(1);
        inputs.usage.lines.push(UsageLine {
            class: busbar_contract::MeterClassId::new("a_class_this_node_never_registered"),
            quantity: 3,
            source: busbar_contract::caps::QuantitySource::Count,
            estimated: false,
        });
        durability
            .seal_unit(inputs, audit_pass(), &token())
            .expect("sealed");
    }
    let restarted = boot(&cfg, 7).expect("the journal reopens");
    assert!(
        restarted.restart_findings.iter().any(|f| {
            let f = f.to_string();
            f.contains("audit chain") && f.contains("a_class_this_node_never_registered")
        }),
        "{:?}",
        restarted.restart_findings
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
}

/// The two branches build the same stack. A node without a data directory is not running a
/// reduced ledger or a reduced audit chain; only the journal's backing differs.
#[test]
fn both_branches_build_the_same_ledger_and_audit_records() {
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

    let source = include_str!("../durability/mod.rs");
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

/// A store that keeps every record it was handed, in order, behind a shared handle.
#[derive(Default, Clone)]
struct KeepingShipper(std::sync::Arc<std::sync::Mutex<Vec<busbar_kernel_wal::Record>>>);

impl KeepingShipper {
    fn records(&self) -> Vec<busbar_kernel_wal::Record> {
        self.0.lock().expect("the kept records").clone()
    }
}

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for KeepingShipper {
    fn ship(
        &mut self,
        records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        self.0
            .lock()
            .expect("the kept records")
            .extend_from_slice(records);
        Ok(())
    }
}

/// The shipped batches ARE the chain, so a node with no data directory that shipped everything
/// has lost nothing it shipped.
#[test]
fn what_the_store_took_is_the_chain() {
    let shipper = KeepingShipper::default();
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
        Admittance, Consumption, Hold, MeterClassId, PrincipalId, QuantitySource, Usage, UsageLine,
        WriteMoney,
    };
    let mut durability = memory_node();
    let key = totals_key("vk_settle");
    durability.ledger.record_hold_opened(&key, 86_400, 5_000);

    let hold = Hold::open(
        &busbar_kernel::test_support::tokens::grant::<Admittance>(),
        PrincipalId::new("vk_settle"),
        5_000,
    );
    let usage = Usage::report(
        &busbar_kernel::test_support::tokens::grant::<Consumption>(),
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
            &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
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
        Admittance, Consumption, Hold, MeterClassId, PrincipalId, QuantitySource, Usage, UsageLine,
        WriteMoney,
    };
    let mut durability = memory_node();
    let key = totals_key("vk_over");
    durability.ledger.record_hold_opened(&key, 86_400, 1_000);

    let mut hold = Hold::open(
        &busbar_kernel::test_support::tokens::grant::<Admittance>(),
        PrincipalId::new("vk_over"),
        1_000,
    );
    // Nothing left in the slice to grow the reservation into: the spend lands anyway.
    let spend = hold.spend(4_000, 0);
    assert_eq!(spend.overdraft, 3_000);
    let usage = Usage::report(
        &busbar_kernel::test_support::tokens::grant::<Consumption>(),
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
            &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
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

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for CountingShipper {
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
        Admittance, Consumption, Hold, MeterClassId, PrincipalId, QuantitySource, Usage, UsageLine,
        WriteMoney,
    };
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
        &busbar_kernel::test_support::tokens::grant::<Admittance>(),
        PrincipalId::new("vk_batch"),
        1_000,
    );
    assert_eq!(hold.spend(4_000, 0).overdraft, 3_000);
    let usage = Usage::report(
        &busbar_kernel::test_support::tokens::grant::<Consumption>(),
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
            &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
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
        Admittance, Consumption, Hold, MeterClassId, Posted, PrincipalId, QuantitySource, Usage,
        UsageLine, WriteMoney,
    };
    let admit = busbar_kernel::test_support::tokens::grant::<Admittance>();
    let key = totals_key("vk_both");
    let usage = |q: u64| {
        Usage::report(
            &busbar_kernel::test_support::tokens::grant::<Consumption>(),
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
            &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
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
        &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
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
        Admittance, Consumption, Hold, MeterClassId, Posted, PrincipalId, QuantitySource, Usage,
        UsageLine, WriteMoney,
    };
    let principal = PrincipalId::new(key.bucket.as_str());
    let durability_token = token();
    let mut at = settling(key, &durability_token);
    at.stamp.mono = mono;
    durability
        .open_hold(&at, &principal, &inputs(reserved), ARRIVED_MS)
        .expect("the journal takes the hold");
    let hold = Hold::open(
        &busbar_kernel::test_support::tokens::grant::<Admittance>(),
        principal,
        reserved,
    );
    let usage = Usage::report(
        &busbar_kernel::test_support::tokens::grant::<Consumption>(),
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
        &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
    );
    durability
        .settle_counted(&at, posted, &inputs(used), ARRIVED_MS)
        .expect("the journal takes the posting");
}

/// **1.5.5'S 31-DAY SWEEP, PINNED.** A window that opened 31 days and one day ago is gone from
/// everything the totals read answers from — the book's balance and the counted lines the
/// read-time totals price — once the seal after the one that holds it is taken, while a window
/// inside the horizon reads exactly what it read before. The journal is not swept: the posting is
/// still on the chain, and a restart rebuilds it.
///
/// The boundary is 1.5.5's: `v1.5.5:crates/store-memory/src/lib.rs` keeps a row while
/// `window_start + MAX_RETENTION_SECS > now` (line 256, `MAX_RETENTION_SECS = 31 * 86_400` at line
/// 23), and `v1.5.5:crates/busbar/src/governance/state.rs:1713-1716` keeps a budget cell on the same
/// rule.
#[test]
fn a_window_a_day_past_the_31_day_horizon_leaves_the_totals_and_stays_on_the_journal() {
    use busbar_kernel_ledger::totals::WINDOW_RETENTION_SECS;

    let mut durability = memory_node();
    let old_key = totals_key("vk_old");
    let new_key = totals_key("vk_new");
    let old = 86_400;
    let now = old + WINDOW_RETENTION_SECS + 86_400;
    let recent = now / 86_400 * 86_400;
    settle_one(&mut durability, &old_key, 1_000, 900, 1);
    settle_in(&mut durability, &new_key, recent, 1_000, 700, 2);

    let lines_in = |durability: &Durability, window: u64| -> usize {
        durability
            .booked_lines()
            .expect("every line carries counts")
            .iter()
            .filter(|line| line.window_start == window)
            .count()
    };
    let recent_before = durability.ledger.book().get(&new_key, recent);
    assert_eq!(lines_in(&durability, old), 1);
    assert_eq!(lines_in(&durability, recent), 1);
    assert_eq!(durability.ledger.book().get(&old_key, old).settled, 900);

    let token = token();
    durability
        .seal_checkpoint(&token, StepName::Meter, now)
        .expect("the first seal goes down");
    assert_eq!(
        lines_in(&durability, old),
        1,
        "no seal before it: nothing is retired yet"
    );
    durability
        .seal_checkpoint(&token, StepName::Meter, now + 1)
        .expect("the second seal goes down");

    assert_eq!(
        lines_in(&durability, old),
        0,
        "the old window left the totals"
    );
    assert_eq!(
        durability.ledger.book().get(&old_key, old),
        Totals::zero(),
        "and the book"
    );
    assert_eq!(lines_in(&durability, recent), 1);
    assert_eq!(
        durability.ledger.book().get(&new_key, recent),
        recent_before,
        "a window inside the horizon is unchanged"
    );
    assert!(
        durability
            .read_back()
            .iter()
            .any(|posting| posting.window == old && posting.kind == PostingKind::Settlement),
        "the journal still holds the old window's posting"
    );
    assert!(durability
        .read_back()
        .iter()
        .any(|posting| posting.window == recent && posting.kind == PostingKind::Settlement));
}

/// A shipper the test can take down: while `down` is set every batch is refused, so the journal
/// append it backs fails as a durability loss.
struct DownShipper(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for DownShipper {
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

/// A memory-buffered node whose shipper `down` takes down.
fn node_with_switch(down: &std::sync::Arc<std::sync::atomic::AtomicBool>) -> Durability {
    build_priced(
        &DurabilityConfig { data_dir: None },
        0,
        Box::new(DownShipper(std::sync::Arc::clone(down))),
        rows(),
        priced(),
    )
    .expect("memory-buffered")
}

/// The window 86,400 is past 1.5.5's horizon at this instant, by a day.
fn a_day_past_the_horizon() -> u64 {
    86_400 + busbar_kernel_ledger::totals::WINDOW_RETENTION_SECS + 86_400
}

/// **A SEAL THAT FAILS RETIRES NOTHING.** The windows a seal leaves out leave the book only once
/// that seal is signed and on the journal. A seal the journal refused is not a checkpoint anybody
/// holds, so the book keeps every window, and `/verify` — which measures the book against the last
/// KEPT seal — finds nothing. Retiring before the seal had landed would leave the book short of a
/// window the kept seal still holds, and verify would name it.
#[test]
fn a_seal_that_fails_retires_nothing_and_verify_stays_clean() {
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut durability = node_with_switch(&down);
    let key = totals_key("vk_failed_seal");
    settle_one(&mut durability, &key, 1_000, 900, 1);
    let now = a_day_past_the_horizon();
    let token = token();
    durability
        .seal_checkpoint(&token, StepName::Meter, now)
        .expect("the first seal goes down");

    down.store(true, std::sync::atomic::Ordering::Release);
    assert!(
        durability
            .seal_checkpoint(&token, StepName::Meter, now + 1)
            .is_err(),
        "the store refused the seal"
    );
    assert_eq!(
        durability.ledger.book().get(&key, 86_400).settled,
        900,
        "a seal that failed retired the window anyway"
    );
    // The ring keeps heads (A1); the newest kept seal, whole, is the one the retirement measures
    // against.
    let kept = durability
        .last_sealed
        .as_ref()
        .expect("the first seal is kept");
    assert_eq!(
        durability.checkpoints.last(),
        Some(&kept.head()),
        "and it is the ring's newest"
    );
    assert!(
        busbar_kernel_ledger::verify::verify(kept, &durability.ledger.book().snapshot(), None)
            .is_empty(),
        "verify against the kept seal is clean"
    );

    // The store comes back: the next seal lands, and only then does the window go.
    down.store(false, std::sync::atomic::Ordering::Release);
    durability
        .seal_checkpoint(&token, StepName::Meter, now + 2)
        .expect("the seal goes down");
    assert_eq!(
        durability.ledger.book().get(&key, 86_400),
        Totals::zero(),
        "retired once a seal without it is durable"
    );
}

/// **A WINDOW IS NOT RETIRED WHILE A SETTLED FIGURE WAITS ON THE LOG.** A posting the journal lost
/// is moved to `unreconciled` and moves back when the next append succeeds; retiring a window under
/// it would land that move on a balance the book had let go. So while any figure is unconfirmed,
/// no seal retires anything — and once the log confirms it, the next seal does.
#[test]
fn no_window_is_retired_while_a_settled_figure_is_unconfirmed() {
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut durability = node_with_switch(&down);
    let old_key = totals_key("vk_old_window");
    let new_key = totals_key("vk_unconfirmed");
    settle_one(&mut durability, &old_key, 1_000, 900, 1);
    let now = a_day_past_the_horizon();
    let recent = now / 86_400 * 86_400;
    let token = token();
    durability
        .seal_checkpoint(&token, StepName::Meter, now)
        .expect("the first seal goes down");

    // A settlement in a recent window the store refuses: its figure is unconfirmed.
    down.store(true, std::sync::atomic::Ordering::Release);
    let mut at = settling(&new_key, &token);
    at.window = recent;
    let hold = busbar_contract::caps::Hold::open(
        &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::Admittance>(),
        busbar_contract::caps::PrincipalId::new("vk_unconfirmed"),
        0,
    );
    let usage = busbar_contract::caps::Usage::report(
        &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::Consumption>(),
        Vec::new(),
    )
    .expect("empty");
    let lost = durability.settle(
        &at,
        hold,
        250,
        &usage,
        &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::WriteMoney>(),
    );
    assert!(lost.is_err(), "the store refused the batch");
    assert_eq!(
        durability.ledger.book().get(&new_key, recent).unreconciled,
        250
    );

    // The store is back and a seal lands, but the figure is still unconfirmed: nothing goes.
    down.store(false, std::sync::atomic::Ordering::Release);
    durability
        .seal_checkpoint(&token, StepName::Meter, now + 1)
        .expect("the seal goes down");
    assert_eq!(
        durability.ledger.book().get(&old_key, 86_400).settled,
        900,
        "a window was retired while a settled figure was unconfirmed"
    );

    // A serving append confirms it; the next seal retires the old window.
    settle_in(&mut durability, &new_key, recent, 1_000, 700, 2);
    assert_eq!(
        durability.ledger.book().get(&new_key, recent).unreconciled,
        0,
        "the log confirmed the figure"
    );
    durability
        .seal_checkpoint(&token, StepName::Meter, now + 2)
        .expect("the seal goes down");
    assert_eq!(
        durability.ledger.book().get(&old_key, 86_400),
        Totals::zero()
    );
}

/// [`settle_one`] in a named window.
fn settle_in(
    durability: &mut Durability,
    key: &TotalsKey,
    window: u64,
    reserved: u64,
    used: u64,
    mono: u64,
) {
    use busbar_contract::caps::{
        Admittance, Consumption, Hold, MeterClassId, Posted, PrincipalId, QuantitySource, Usage,
        UsageLine, WriteMoney,
    };
    let principal = PrincipalId::new(key.bucket.as_str());
    let durability_token = token();
    let mut at = settling(key, &durability_token);
    at.window = window;
    at.stamp.mono = mono;
    durability
        .open_hold(&at, &principal, &inputs(reserved), ARRIVED_MS)
        .expect("the journal takes the hold");
    let hold = Hold::open(
        &busbar_kernel::test_support::tokens::grant::<Admittance>(),
        principal,
        reserved,
    );
    let usage = Usage::report(
        &busbar_kernel::test_support::tokens::grant::<Consumption>(),
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
        &busbar_kernel::test_support::tokens::grant::<WriteMoney>(),
    );
    durability
        .settle_counted(&at, posted, &inputs(used), ARRIVED_MS)
        .expect("the journal takes the posting");
}

/// PB-58: A SPEND PAST THE RESERVATION IS CARRIED OUT AS AN OVERDRAFT — the unit runs to its end
/// and settles, and the part nothing reserved is carried, DERIVED AT READ (#71).
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

    // A book that lost a row: its window let go past the horizon, which the chain still carries.
    let sealed = Checkpoint::seal(
        1,
        7,
        1_700_000_000,
        Vec::new(),
        restarted.ledger.book().snapshot(),
        0,
        0,
        None,
    )
    .expect("an unsigned checkpoint seals");
    let retired = restarted.ledger.retirable(&sealed, u64::MAX);
    assert_eq!(retired.iter().copied().collect::<Vec<_>>(), vec![86_400]);
    restarted.ledger.retire_windows(&retired);
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

/// And a single figure moved in memory, with no record behind it, is named too.
#[test]
fn the_reconciliation_names_a_figure_the_book_moved_without_a_record() {
    let mut durability = memory_node();
    let key = totals_key("vk_edit");
    settle_one(&mut durability, &key, 1_000, 900, 3);
    assert!(durability.reconcile_with_journal().is_empty());
    // A draw the ledger booked and the journal never recorded.
    durability.ledger.record_draw(&key, 86_400, 1);
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
    impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for Flaky {
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
    let principal = busbar_contract::caps::PrincipalId::new("vk_flaky");
    let durability_token = token();
    let hold = busbar_contract::caps::Hold::open(
        &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::Admittance>(),
        principal,
        0,
    );
    let usage = busbar_contract::caps::Usage::report(
        &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::Consumption>(),
        Vec::new(),
    )
    .expect("empty");
    let lost = durability.settle(
        &settling(&key, &durability_token),
        hold,
        250,
        &usage,
        &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::WriteMoney>(),
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

/// A HOLD THIS BUILD WRITES CARRIES COUNTS, NEVER A FIGURE (money-shape hardening, #71/#77): the
/// book's one hold writer journals the counts-era body, and the only way to hold a figure at all is
/// to decode a figures-era record — `FiguresEra` has no constructor outside the durability module.
#[test]
fn a_hold_the_book_writes_carries_counts_never_a_figure() {
    let scratch = ScratchDir::new("hold-counts-only");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_a");
    let mut durability = boot(&cfg, 5).expect("the directory is writable");
    let token = token();
    let at = settling(&key, &token);
    durability
        .open_hold(
            &at,
            &busbar_contract::caps::PrincipalId::new(key.bucket.as_str()),
            &inputs(7),
            ARRIVED_MS,
        )
        .expect("the journal takes the hold");
    let records = durability
        .journal
        .replay()
        .expect("reads")
        .expect("verifies");
    let holds: Vec<HoldOpened> = records.iter().filter_map(HoldOpened::from_record).collect();
    assert_eq!(holds.len(), 1);
    assert!(
        matches!(holds[0].held, Held::Counts { .. }),
        "the book wrote a hold that is not counts: {:?}",
        holds[0].held
    );
    let body = holds[0].body();
    let mut tag = BodyReader::new(&body);
    assert_eq!(tag.text(), Some("hold.open.v2"));
}

/// A FIGURES-ERA HOLD DECODES READ-ONLY AND THE BOOK EQUALS ITS CHAIN: the old record's figure is
/// read exactly, re-spelled to the very bytes it was read from, and the book rebuilt from the chain
/// draws exactly that figure.
#[test]
fn a_figures_era_hold_decodes_read_only_and_the_book_equals_the_chain() {
    let scratch = ScratchDir::new("figures-era-hold-read-only");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_a");
    let old = posting();
    {
        let mut durability = boot(&cfg, 5).expect("the directory is writable");
        let entries = [
            Entry::new(RecordClass::Transaction, figures_era_hold(&old, 5_000))
                .at(old.wall, old.mono),
            Entry::new(RecordClass::Transaction, figures_era_body(&old)).at(old.wall, old.mono),
        ];
        durability
            .journal
            .append(&token(), StepName::Meter, &entries)
            .expect("the journal takes the figures-era records");
    }
    let restarted = boot(&cfg, 5).expect("the journal reopens");
    let records = restarted
        .journal
        .replay()
        .expect("reads")
        .expect("verifies");
    let hold = records
        .iter()
        .find_map(HoldOpened::from_record)
        .expect("the figures-era hold reads back");
    let Held::FiguresEra(era) = &hold.held else {
        panic!("a figures-era record decoded as {:?}", hold.held);
    };
    assert_eq!(era.nanos(), 5_000, "the old figure reads exactly");
    assert_eq!(hold.reserved(None), 5_000);
    assert_eq!(
        hold.body(),
        figures_era_hold(&old, 5_000),
        "a decoded figures-era hold re-spells exactly the bytes it was read from"
    );
    // The book equals its chain: what the chain's holds reserved is what the book drew, and what
    // its postings settled is what the book settled.
    let book = restarted.ledger.book().get(&key, 86_400);
    let chain_reserved: u64 = records
        .iter()
        .filter_map(HoldOpened::from_record)
        .filter(|h| h.key == key)
        .map(|h| h.reserved(None))
        .sum();
    let chain_settled: i128 = records
        .iter()
        .filter_map(Posting::from_record)
        .filter(|p| p.key == key)
        .map(|p| p.settled)
        .sum();
    assert_eq!(book.drawn, i128::from(chain_reserved));
    assert_eq!(book.settled, chain_settled);
    assert_eq!(
        book.open_holds, 0,
        "the figures-era posting closed its hold"
    );
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
                input: busbar_kernel_ledger::cost::representable_nano_rate(0.002),
                output: busbar_kernel_ledger::cost::representable_nano_rate(0.002),
                cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.002),
                cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.002),
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

/// A late settlement of `amount` (no hold behind it, as the node's late arm posts), with its counts,
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
    use busbar_contract::caps::{HoldAccrual, Posted, PrincipalId, WriteMoney};
    let ledger = busbar_kernel::test_support::tokens::grant::<WriteMoney>();
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
/// every record that verifies, those behind the damage included, the damaged record is in a
/// quarantine file beside the segment, the verdict names the file, the offset and the byte count, a
/// durable `ChainBreak` record of it goes on the chain, and the chain still verifies across it.
#[test]
fn a_mid_log_corrupt_journal_boots_quarantines_and_records_it() {
    use busbar_kernel_wal::{Entry, Journal, QuarantineKept, RecordClass, FRAME_BYTES};

    let dir = ScratchDir::new("quarantine");
    {
        let mut journal = Journal::in_directory(
            0,
            &dir.path,
            Box::new(NullShipper::new()),
            busbar_kernel::store::now_ms,
        )
        .expect("opens");
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
    assert_eq!(q.bytes, FRAME_BYTES as u64, "the damaged record alone");
    let QuarantineKept::File(file) = &q.kept else {
        panic!("an on-disk journal quarantines to a file");
    };
    assert_eq!(
        std::fs::read(file).expect("the quarantine file is there"),
        bytes[FRAME_BYTES..2 * FRAME_BYTES].to_vec()
    );

    let ack = durability
        .journal_quarantines(&token(), StepName::Meter, 1_758_700_000)
        .expect("appends")
        .expect("a quarantine is recorded");
    assert_eq!(ack.sealed.len(), 1);
    assert_eq!(ack.sealed[0].class, RecordClass::ChainBreak);
    let seqs: Vec<u64> = durability
        .journal
        .replay()
        .expect("reads")
        .expect("the chain verifies across the quarantine")
        .iter()
        .map(|r| r.node_seq)
        .collect();
    assert_eq!(seqs[..3], [1, 3, 4], "every kept record: {seqs:?}");
    assert!(seqs.len() > 3, "and the break after them: {seqs:?}");
}

/// **ONE DAMAGED SETTLEMENT COSTS ITS OWN UNIT AND NOTHING ELSE, ON EVERY BOOT** (arch-audit u44:
/// THE DESIGN, MONEY-CHAIN, BUSBAR-1.6.0.md l.1056-1059; one sealed facts line per unit, written
/// once, never edited, #77 l.2279). Three units settle; the middle one's settlement is altered on
/// the medium while the node is down.
///
/// RED before the fix, twice over. On the boot that found the damage, the scan stopped at it for
/// good, so the third unit's settlement — whole and acknowledged — was cut off the log with it and
/// left the book. And once that boot sealed the quarantine's `ChainBreak`, the chain never verified
/// again: every later boot rebuilt an EMPTY book. Now the damaged settlement alone is set aside;
/// every other unit's line is on the book at every boot; and the unit the damaged record names
/// stays OPEN-QUARANTINED at every boot, never settled at 0.
#[test]
fn one_damaged_settlement_costs_its_own_unit_and_nothing_else_on_every_boot() {
    let scratch = ScratchDir::new("one-damaged-settlement");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let (a, b, c, d) = (
        totals_key("vk_a"),
        totals_key("vk_b"),
        totals_key("vk_c"),
        totals_key("vk_d"),
    );
    {
        let mut durability = boot(&cfg, 26).expect("the directory is writable");
        settle_one(&mut durability, &a, 5_000, 1_111, 31);
        settle_one(&mut durability, &b, 5_000, 4_321, 32);
        settle_one(&mut durability, &c, 5_000, 2_222, 33);
    }
    assert!(
        edit_segment(&scratch.path, &4_321u64.to_le_bytes(), |bytes, i| {
            bytes[i..i + 8].copy_from_slice(&4_322u64.to_le_bytes());
        }),
        "the fixture found the middle settlement on disk"
    );

    let check = |durability: &Durability, boot: &str| {
        let book = durability.ledger.book();
        assert_eq!(book.get(&a, 86_400).settled, 1_111, "{boot}: unit a");
        assert_eq!(
            book.get(&c, 86_400).settled,
            2_222,
            "{boot}: the unit settled BEHIND the damage is on the book"
        );
        let damaged = book.get(&b, 86_400);
        assert_eq!(
            damaged.settled, 0,
            "{boot}: the altered figure is not taken"
        );
        assert_eq!(
            damaged.open_holds, 5_000,
            "{boot}: and its hold is NOT settled at its checkpoint"
        );
        assert_eq!(durability.recovered_holds, 0, "{boot}: nothing on a guess");
        let findings: Vec<String> = durability
            .restart_findings
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(
            findings
                .iter()
                .any(|f| f.starts_with("journal quarantine:"))
                && findings
                    .iter()
                    .any(|f| f.contains("unit 32 is left OPEN-QUARANTINED")),
            "{boot}: the findings name the quarantine and the unit: {findings:?}"
        );
        assert!(
            !findings.iter().any(|f| f.contains("does not verify")),
            "{boot}: the chain verifies across the quarantine: {findings:?}"
        );
    };

    {
        let mut restarted = boot(&cfg, 26).expect("a corrupt journal does not stop the boot");
        assert_eq!(
            restarted.quarantined.len(),
            1,
            "the damaged record is set aside"
        );
        check(&restarted, "the boot that found it");
        restarted
            .journal_quarantines(&token(), StepName::Meter, 1_758_700_000)
            .expect("appends")
            .expect("the quarantine goes on the chain");
        settle_one(&mut restarted, &d, 5_000, 3_333, 34);
    }
    for later in ["the next boot", "the one after"] {
        let mut again = boot(&cfg, 26).expect("reopens");
        check(&again, later);
        assert_eq!(
            again.ledger.book().get(&d, 86_400).settled,
            3_333,
            "{later}: a unit settled after the quarantine is on the book"
        );
        assert!(
            again
                .journal_quarantines(&token(), StepName::Meter, 1_758_700_001)
                .expect("appends")
                .is_none(),
            "{later}: the hole is on the chain once"
        );
    }
}

/// A SETTLED FIGURE TAMPERED ON DISK IS CAUGHT AT BOOT (the boot reconciliation is the check a stored
/// price would otherwise need). A settlement's counts (the figure it prices to) are edited in the journal segment while the
/// node is down; the next boot does not take the edited figure onto its book silently — the
/// restart findings name the journal that no longer verifies. (A booked line carries no stored price
/// to recompute, #71; this is the check that re-derives every settled figure from the counts.)
#[test]
fn a_settled_figure_tampered_on_disk_is_caught_at_boot() {
    let scratch = ScratchDir::new("tampered-figure");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_tampered");
    {
        let mut durability = boot(&cfg, 21).expect("the directory is writable");
        settle_one(&mut durability, &key, 5_000, 4_321, 1);
        // A later settlement, so the edited record is inside the chain rather than its torn tail.
        settle_one(&mut durability, &totals_key("vk_after"), 1_000, 700, 2);
    }
    let clean = boot(&cfg, 21).expect("reopens");
    assert!(
        clean.restart_findings.is_empty(),
        "{:?}",
        clean.restart_findings
    );
    assert_eq!(clean.ledger.book().get(&key, 86_400).settled, 4_321);
    drop(clean);
    // Edit the settled counts in place: 4,321 input units become 4,322, on disk.
    let needle = 4_321u64.to_le_bytes();
    let forged = 4_322u64.to_le_bytes();
    let mut edited = 0;
    for entry in std::fs::read_dir(&scratch.path).expect("the data directory lists") {
        let path = entry.expect("an entry").path();
        let Ok(mut bytes) = std::fs::read(&path) else {
            continue;
        };
        let mut at = 0;
        while let Some(i) = bytes[at..].windows(8).position(|w| w == needle) {
            bytes[at + i..at + i + 8].copy_from_slice(&forged);
            at += i + 8;
            edited += 1;
        }
        if edited > 0 {
            std::fs::write(&path, &bytes).expect("the segment rewrites");
            break;
        }
    }
    assert!(edited > 0, "the fixture found the settled counts on disk");
    let restarted = boot(&cfg, 21).expect("a corrupt journal does not stop the boot");
    assert!(
        !restarted.restart_findings.is_empty(),
        "a figure edited on disk must be a restart finding, never taken silently onto the book"
    );
}

/// Find the segment holding `needle` and apply `edit` at its first occurrence. Answers whether it did.
fn edit_segment(dir: &std::path::Path, needle: &[u8], edit: impl Fn(&mut Vec<u8>, usize)) -> bool {
    for entry in std::fs::read_dir(dir).expect("the data directory lists") {
        let path = entry.expect("an entry").path();
        let Ok(mut bytes) = std::fs::read(&path) else {
            continue;
        };
        if let Some(i) = bytes.windows(needle.len()).position(|w| w == needle) {
            edit(&mut bytes, i);
            std::fs::write(&path, &bytes).expect("the segment rewrites");
            return true;
        }
    }
    false
}

/// A COMPLETED SETTLEMENT ALTERED AT THE JOURNAL'S TAIL IS NEVER A SILENT ZERO. The unit's
/// settlement is the last record on the journal and its counts are edited on disk while the node is
/// down. Before the WAL's header check this read as a torn tail: the record was cut silently, the
/// hold looked open, and recovery settled the unit at its checkpoint — 4,321 became 0 with no
/// alarm. Now the record is quarantined, the finding names it, and the hold is left
/// OPEN-QUARANTINED: nothing settles it on a guess.
#[test]
fn a_settlement_altered_at_the_tail_is_quarantined_and_never_settles_at_zero() {
    let scratch = ScratchDir::new("tampered-tail");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_tail");
    {
        let mut durability = boot(&cfg, 22).expect("the directory is writable");
        settle_one(&mut durability, &key, 5_000, 4_321, 9);
    }
    let clean = boot(&cfg, 22).expect("reopens");
    assert_eq!(clean.ledger.book().get(&key, 86_400).settled, 4_321);
    assert!(
        clean.restart_findings.is_empty(),
        "{:?}",
        clean.restart_findings
    );
    drop(clean);
    assert!(
        edit_segment(&scratch.path, &4_321u64.to_le_bytes(), |bytes, i| {
            bytes[i..i + 8].copy_from_slice(&4_322u64.to_le_bytes());
        }),
        "the fixture found the settled counts on disk"
    );
    let restarted = boot(&cfg, 22).expect("a corrupt journal does not stop the boot");
    assert_eq!(
        restarted.quarantined.len(),
        1,
        "the altered tail record is set aside"
    );
    let figures = restarted.ledger.book().get(&key, 86_400);
    assert_eq!(
        figures.settled, 0,
        "the altered figure is not taken onto the book"
    );
    assert_eq!(
        figures.open_holds, 5_000,
        "and the hold is NOT settled at its checkpoint: it stays open"
    );
    assert_eq!(
        restarted.recovered_holds, 0,
        "nothing was recovered on a guess"
    );
    let findings: Vec<String> = restarted
        .restart_findings
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        findings
            .iter()
            .any(|f| f.starts_with("journal quarantine:"))
            && findings
                .iter()
                .any(|f| f.contains("unit 9 is left OPEN-QUARANTINED")),
        "the findings name the quarantine and the unit: {findings:?}"
    );
}

/// A SETTLEMENT WHOSE FRAME HEADER IS ALTERED AT THE TAIL IS A QUARANTINE, NEVER A TORN TAIL
/// (MONEY-AUDIT E4). One byte of the final frame's header — its payload length — is changed while
/// the node is down. The frame is whole (its digest and payload are all there), so the write that
/// made it completed and the settlement was acknowledged. Read as a torn tail it was cut silently and
/// the hold recovered at its checkpoint: a settled unit settled again, with no alarm.
#[test]
fn a_settlement_whose_header_is_altered_at_the_tail_is_quarantined_not_cut() {
    let scratch = ScratchDir::new("altered-header-tail");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_header");
    {
        let mut durability = boot(&cfg, 24).expect("the directory is writable");
        settle_one(&mut durability, &key, 5_000, 4_321, 13);
    }
    assert!(
        edit_segment(&scratch.path, &4_321u64.to_le_bytes(), |bytes, _| {
            let last = bytes
                .iter()
                .rposition(|&b| b != 0)
                .expect("a written segment");
            bytes[(last / FRAME_BYTES) * FRAME_BYTES + 33] ^= 0xFF;
        }),
        "the fixture found the settlement on disk"
    );
    let restarted = boot(&cfg, 24).expect("a corrupt journal does not stop the boot");
    assert_eq!(
        restarted.quarantined.len(),
        1,
        "the whole final frame whose header was altered is set aside"
    );
    assert_eq!(
        restarted.recovered_holds, 0,
        "nothing was recovered on a guess"
    );
    let figures = restarted.ledger.book().get(&key, 86_400);
    assert_eq!(figures.settled, 0);
    assert_eq!(
        figures.open_holds, 5_000,
        "the hold stays open, OPEN-QUARANTINED"
    );
}

/// A TRUE TORN TAIL STILL TRUNCATES AND RECOVERS. The settlement's write stopped inside its frame's
/// header (a crash mid-append): the header check fails, the tail is cut silently, and the unit's
/// hold is recovered as it always was — nothing was acknowledged past the tear.
#[test]
fn a_torn_settlement_is_cut_and_its_hold_recovers() {
    let scratch = ScratchDir::new("torn-settlement");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let key = totals_key("vk_torn");
    {
        let mut durability = boot(&cfg, 23).expect("the directory is writable");
        settle_one(&mut durability, &key, 5_000, 4_321, 11);
    }
    // Tear the frame that carries the settlement: zero from inside its header to the end.
    assert!(
        edit_segment(&scratch.path, &4_321u64.to_le_bytes(), |bytes, i| {
            let frame = FRAME_BYTES;
            let start = (i / frame) * frame + 20;
            for b in &mut bytes[start..] {
                *b = 0;
            }
        }),
        "the fixture found the settlement on disk"
    );
    let restarted = boot(&cfg, 23).expect("reopens");
    assert!(
        restarted.quarantined.is_empty(),
        "a torn write is not a quarantine"
    );
    assert_eq!(
        restarted.recovered_holds, 1,
        "the open hold is recovered as before"
    );
    assert!(
        restarted.open_quarantined.is_empty(),
        "{:?}",
        restarted.open_quarantined
    );
}

/// **EVERY OPEN CLASS THE FALLBACK PLANE DECLARES PRICES AT THE CARD AND REPLAYS IDEMPOTENTLY** (owner
/// LEDGER-100, 2026-10-03: every reported unit is a ledger line under its meter class; money =
/// f(ledger, ratecard)). The classes are read off the plane's own declaration, never spelled here,
/// and the plane off the linked table by its `fallback` flag (the plane a `models:` lane falls
/// through to), never by name:
/// for each, one unit reporting 7 of it settles as ONE record carrying `{class: 7}` and no figure;
/// a restart over a card pricing the class at 3,000 nano-units rebuilds 21,000; a second restart
/// rebuilds the identical book (replay is idempotent); and a restart over the card with no cell for
/// the class (the absent-rate rule, #42) refuses the read rather than pricing it at 0.
#[cfg(linked_every_plane)]
#[test]
fn every_fallback_open_class_prices_at_the_card_and_replays_idempotently() {
    use busbar_kernel_ledger::cost::LaneClass;
    const RATE: u64 = 3_000;
    // The plane rows the linked doors fold to, as the composition root folds them: the fallback
    // plane is a door row, so its declaration is its door's Statement.
    let fallback = {
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        let mut fallbacks: Vec<_> = crate::LINKED
            .plane_doors
            .iter()
            .map(|door| registration(linked_probe(*door, "fallback-classes")).expect("binds"))
            .filter(|reg| reg.fallback)
            .collect();
        assert_eq!(
            fallbacks.len(),
            1,
            "every plane linked: one declares itself the fallback"
        );
        busbar_kernel::plane::door::fold(fallbacks.remove(0)).expect("the door folds")
    };
    let open: Vec<&str> = fallback
        .billable_classes
        .iter()
        .map(|c| c.class)
        .filter(|c| !busbar_contract::records::RESERVED_UNITS.contains(c))
        .collect();
    assert!(
        open.len() > 1,
        "the plane declares its open classes: {open:?}"
    );
    let mut registration = crate::root::kernel::new_registration();
    for class in &open {
        let _ = registration.key(class);
    }
    for class in open {
        let scratch = ScratchDir::new(&format!("ledger-100-{class}"));
        let cfg = DurabilityConfig {
            data_dir: Some(scratch.path.clone()),
        };
        let key = totals_key(&format!("vk_{class}"));
        let counts = UnitCounts {
            lane: LANE.to_string(),
            fee_count: 0,
            classes: std::collections::BTreeMap::from([(class.to_string(), 7)]),
        };
        {
            let mut durability = boot(&cfg, 7).expect("the directory is writable");
            let written = late_counted(&mut durability, &key, 7 * RATE, &counts);
            assert_eq!(written.counts, Some(counts.clone()), "{class}");
        }
        let card =
            pinned_history(one_nano_card().with_unit_rates([(LaneClass::new(LANE, class), RATE)]));
        let reopen = || {
            let card = card.clone();
            build_priced(
                &cfg,
                7,
                Box::new(NullShipper::new()),
                rows(),
                Box::new(move || Some(card.clone())),
            )
            .expect("the journal reopens")
        };
        let first = reopen();
        assert!(
            first.restart_findings.is_empty(),
            "{class}: {:?}",
            first.restart_findings
        );
        assert_eq!(
            first.ledger.book().get(&key, 86_400).settled,
            i128::from(7 * RATE),
            "{class}: the rebuilt book prices the counts at the card"
        );
        let settlements: Vec<Posting> = first
            .read_back()
            .into_iter()
            .filter(|p| p.kind == PostingKind::Settlement)
            .collect();
        assert_eq!(settlements.len(), 1, "{class}: one ledger line");
        assert_eq!(settlements[0].counts, Some(counts.clone()), "{class}");
        let snapshot = first.ledger.book().snapshot();
        drop(first);
        let second = reopen();
        assert_eq!(
            second.ledger.book().snapshot(),
            snapshot,
            "{class}: a second replay rebuilds the identical book"
        );
        drop(second);
        // The absent-rate rule (#42): a present card with no cell for the class refuses the read.
        let silent = build_priced(&cfg, 7, Box::new(NullShipper::new()), rows(), priced())
            .expect("the journal reopens");
        assert!(
            silent.settled_read(&key, 86_400).is_err(),
            "{class}: a card silent about the class refuses, never prices it at 0"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// H3: THE JOURNAL KEPT BY THE CONFIGURED STORE
// ---------------------------------------------------------------------------------------------

/// A book over `slots` with no data directory, as node `node`: the production boot's shape.
fn store_book(slots: &crate::root::store_double::RecordSlots, node: u64) -> Durability {
    store_book_bounded(slots, node, busbar_kernel_wal::MEMORY_BUFFER_RECORDS)
}

/// [`store_book`], its lane to the store bounded at `capacity` records.
fn store_book_bounded(
    slots: &crate::root::store_double::RecordSlots,
    node: u64,
    capacity: usize,
) -> Durability {
    let lane =
        JournalLane::with_capacity(slots.calls(), "test-store", capacity).expect("the lane starts");
    build_on_store(
        &DurabilityConfig { data_dir: None },
        node,
        lane,
        rows(),
        priced(),
        None,
    )
    .expect("the store reads back")
}

/// Wait until the store took everything the book's lane holds.
fn drained(durability: &Durability) {
    assert!(
        durability
            .lane()
            .expect("a book over the store")
            .drain(std::time::Duration::from_secs(5)),
        "the store takes the journal's records"
    );
}

/// **A NODE WITH NO DATA DIRECTORY KEEPS ITS CHAIN IN ITS STORE ACROSS A RESTART**. Sealed audit records, an open hold killed with the
/// node (kill -9) and a settled posting go on the chain; a second book over the SAME store resumes
/// that chain: the audit cache is rebuilt from it, the hold a predecessor left is recovered, the
/// settled figure is on the book, and the numbering continues past every stored record.
///
/// RED before the fix: the store adapter's shipper acknowledged every batch and kept a count, and a
/// memory-buffered journal opened empty, so the restarted book had no audit record, no hold and no
/// money, and numbered from one again.
#[test]
fn a_restart_over_the_same_store_keeps_the_chain_the_audit_records_and_the_holds() {
    let slots = crate::root::store_double::RecordSlots::new();
    let key = totals_key("vk_store_restart");
    let held = totals_key("vk_store_held");
    let (head, next) = {
        let mut durability = store_book(&slots, 11);
        for unit in 1..=3 {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        settle_one(&mut durability, &key, 1_000, 600, 1);
        let durability_token = token();
        let mut at = settling(&held, &durability_token);
        at.stamp.mono = 77;
        durability
            .open_hold(
                &at,
                &busbar_contract::caps::PrincipalId::new("vk_store_held"),
                &inputs(2_000),
                ARRIVED_MS,
            )
            .expect("the hold goes on the chain");
        drained(&durability);
        let out = (durability.journal.head(), durability.journal.next_seq());
        // kill -9: no settle, no destructor of the book, nothing flushed on the way out.
        std::mem::forget(durability);
        out
    };
    assert!(
        slots.rows_under(JOURNAL_SCHEMA) > 0,
        "the store keeps the records"
    );

    let restarted = store_book(&slots, 11);
    assert!(
        restarted.keeps_chain(),
        "the chain was resumed from the store"
    );
    assert_eq!(
        restarted.audit_records.len(),
        3,
        "the audit records survive the restart"
    );
    assert_eq!(
        restarted.recovered_holds, 1,
        "the hold a predecessor left open is recovered"
    );
    assert_eq!(
        restarted.ledger.book().get(&key, 86_400).settled,
        600,
        "the settled money survives the restart"
    );
    assert!(
        restarted.journal.next_seq() > next,
        "the numbering continues past the stored chain (and the recovery's own record)"
    );
    let replayed = restarted
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert!(
        replayed.iter().any(|r| r.hash == head),
        "the stored chain is the restarted node's chain"
    );
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
}

/// **A STORE THAT REFUSES DOES NOT REFUSE A DATA UNIT**: the
/// unit settles, its record waits in the lane and is re-offered, and it lands once the store
/// recovers — read back by the next boot. Meanwhile the lane is unhealthy, which is what a durable
/// verb refuses on.
#[test]
fn a_data_unit_rides_a_refusing_store_and_its_record_lands_once_it_recovers() {
    let slots = crate::root::store_double::RecordSlots::new();
    let key = totals_key("vk_refused");
    let mut durability = store_book(&slots, 12);
    slots.refuse(true);
    settle_one(&mut durability, &key, 1_000, 400, 1);
    assert_eq!(
        durability.ledger.book().get(&key, 86_400).settled,
        400,
        "the unit is served and settled"
    );
    let lane = durability.lane().expect("a lane").clone();
    assert!(lane.pending() > 0, "its records wait for the store");
    assert!(
        lane.wait_acked(
            12,
            durability.journal.next_seq() - 1,
            std::time::Duration::from_secs(5)
        )
        .is_err(),
        "the store refused them"
    );
    assert!(lane.healthy().is_err(), "a durable verb refuses meanwhile");
    assert!(
        durability.refuses_money().is_none(),
        "the lane has room: money is admitted"
    );

    slots.refuse(false);
    drained(&durability);
    drop(durability);
    let restarted = store_book(&slots, 12);
    assert_eq!(
        restarted.ledger.book().get(&key, 86_400).settled,
        400,
        "the re-offered records landed and read back"
    );
}

/// **A FULL LANE FAILS CLOSED AND DROPS NOTHING**: with the store
/// refusing, the lane fills; the book then refuses new money-bearing work with its reason, the
/// journal keeps every record it is handed (no `ChainBreak`, nothing dropped), and once the store
/// recovers everything lands and the book admits again.
#[test]
fn a_full_lane_refuses_new_money_and_drops_no_record() {
    let slots = crate::root::store_double::RecordSlots::new();
    let key = totals_key("vk_full");
    let mut durability = store_book_bounded(&slots, 13, 4);
    slots.refuse(true);
    assert!(durability.refuses_money().is_none());
    // Holds past the lane's bound: each is one record.
    let mut lost = 0;
    for mono in 1..=6 {
        let durability_token = token();
        let mut at = settling(&key, &durability_token);
        at.stamp.mono = mono;
        if durability
            .open_hold(
                &at,
                &busbar_contract::caps::PrincipalId::new("vk_full"),
                &inputs(10),
                ARRIVED_MS,
            )
            .is_err()
        {
            lost += 1;
        }
    }
    assert!(
        lost > 0,
        "past the lane's bound the store's answer is a durability loss"
    );
    let why = durability
        .refuses_money()
        .expect("a full lane refuses new money-bearing work");
    assert!(why.contains("journal is full"), "{why}");
    assert_eq!(
        durability.journal.dropped_total(),
        0,
        "no record is dropped"
    );
    assert!(
        durability.journal.overflows().is_empty(),
        "no ChainBreak: the bound is the caller's refusal"
    );
    let written = durability.journal.next_seq() - 1;

    slots.refuse(false);
    drained(&durability);
    // The journal's retained batch is re-offered on its next append.
    durability
        .journal
        .append(
            &token(),
            StepName::Meter,
            &[busbar_kernel_wal::Entry::new(RecordClass::Load, Vec::new())],
        )
        .expect("the store takes the retained batch and the new record");
    drained(&durability);
    assert!(
        durability.refuses_money().is_none(),
        "the node admits again"
    );
    let kept = read_chain(slots.calls().as_ref(), 13).expect("reads back");
    assert_eq!(
        kept.len() as u64,
        written + 1,
        "every record the journal sealed is in the store, once"
    );
}

/// **A LONG OUTAGE DOES NOT WEDGE THE BOOK** (a full lane fails closed "until the
/// store takes what waits" and "no record is dropped"). With the store refusing, the journal
/// keeps appending past the lane's bound — what a fail-closed node still writes (admin units, the
/// checkpoint cadence, accruals) — so the batch it retains grows past the bound too. Once the store
/// recovers and the lane drains, the next append's re-offer is taken whole: every record reaches the
/// store and the book admits money again.
///
/// RED before the fix: the lane took a batch only if it fit beside what waits, so the retained
/// batch, over the bound, was turned away even by an empty lane on every re-offer: the book refused
/// new money-bearing work until a restart, and the retained records, only in memory, were lost by
/// it.
#[test]
fn a_retained_batch_past_the_lanes_bound_drains_once_the_store_recovers() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut durability = store_book_bounded(&slots, 15, 4);
    drained(&durability);
    slots.refuse(true);
    // Past the lane's bound and then some: the lane holds four, the journal retains six.
    for _ in 0..10 {
        let _ = durability.journal.append(
            &token(),
            StepName::Meter,
            &[busbar_kernel_wal::Entry::new(RecordClass::Load, Vec::new())],
        );
    }
    assert!(
        durability.journal.buffered() > 4,
        "the journal retains more than the lane's bound"
    );
    assert!(
        durability.refuses_money().is_some(),
        "the node fails closed"
    );
    assert_eq!(
        durability.journal.dropped_total(),
        0,
        "no record is dropped"
    );
    let written = durability.journal.next_seq() - 1;

    slots.refuse(false);
    drained(&durability);
    durability
        .journal
        .append(
            &token(),
            StepName::Meter,
            &[busbar_kernel_wal::Entry::new(RecordClass::Load, Vec::new())],
        )
        .expect("the empty lane takes the retained batch and the new record");
    drained(&durability);
    assert_eq!(durability.journal.buffered(), 0, "the journal owes nothing");
    assert!(
        durability.refuses_money().is_none(),
        "the node admits again"
    );
    let kept = read_chain(slots.calls().as_ref(), 15).expect("reads back");
    assert_eq!(
        kept.len() as u64,
        written + 1,
        "every record the journal sealed is in the store, once"
    );
}

/// **A CHAIN READ WHILE THE LANE IS BETWEEN TWO PARTS OF A RECORD IS NOT A TORN RECORD.** A slot
/// carries 510 bytes of a record, so a journal record past that (a 160-byte header and its body)
/// crosses to the store as two or more puts, and the lane's worker runs beside the book. A chain read
/// that lands between two of them (the boot's own `arm_checkpoints` and the keyset's sealed
/// Bootstrap read do, right after the opening seal ships) finds the record's first part in the store
/// and the whole record still in the lane. The record is read whole from the lane and nothing is
/// reported: a record the lane still holds was never torn, it is being put. Posed here as a store
/// that takes the first part and answers no more, which holds that moment still.
///
/// RED before the fix: the read warned "the stored journal holds a record whose parts are not all
/// there" on a clean boot (oracle cells boot.warning|BOOT-W21, BOOT-W34, neutrality|boot-lines),
/// a line 1.5.5 never printed.
#[test]
fn a_chain_read_between_two_parts_of_a_queued_record_warns_nothing() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let slots = crate::root::store_double::RecordSlots::new();
    let node = 23;
    let mut durability = store_book(&slots, node);
    durability
        .seal_unit(audit_inputs(1), audit_pass(), &token())
        .expect("sealed");
    drained(&durability);

    // A body past one slot's bound: two parts at the least.
    slots.take_then_refuse(1);
    durability
        .journal
        .append(
            &token(),
            StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                RecordClass::Load,
                vec![7u8; 1_000],
            )],
        )
        .expect("handed to the lane");
    let newest = durability.journal.next_seq() - 1;
    let lane = durability.lane().expect("a book over the store");
    assert!(
        lane.wait_acked(node, newest, std::time::Duration::from_secs(5))
            .is_err(),
        "the store took the first part and refused the next"
    );
    assert_eq!(lane.pending(), 1, "the record is still the lane's");

    let cap = busbar_kernel::test_support::warn_capture::WarnCapture::default();
    let chain =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(cap.clone()), || {
            durability.chain()
        })
        .expect("the chain reads back")
        .expect("and verifies");
    assert_eq!(
        chain.last().map(|r| r.node_seq),
        Some(newest),
        "the half-put record is on the chain, read whole from the lane"
    );
    assert!(
        !cap.contains("parts are not all there"),
        "a record the lane still holds is not torn: {:?}",
        cap.messages()
    );

    slots.refuse(false);
    drained(&durability);
    assert_eq!(
        read_chain(slots.calls().as_ref(), node)
            .expect("reads back")
            .last()
            .map(|r| r.node_seq),
        Some(newest),
        "and the store holds it whole once it takes the rest"
    );
}

// ---------------------------------------------------------------------------------------------
// H3 follow-up: THE DEPLOYMENT KEYSET AND THE NODE'S IDENTITY IN THE STORE
// ---------------------------------------------------------------------------------------------

/// A book over `slots` as node `node`, its deployment keyset bound the way the boot binds it.
fn keyed_store_book(slots: &crate::root::store_double::RecordSlots, node: u64) -> Durability {
    let mut durability = store_book(slots, node);
    crate::root::keyset::bind(
        &mut durability,
        None,
        &token(),
        StepName::Meter,
        1_700_000_000,
    )
    .expect("the keyset binds over the store");
    durability
}

/// **A RESTART OVER THE SAME STORE VERIFIES THE PRIOR BOOT'S RECORDS**: with no data directory the deployment keyset is kept in the store and
/// read back, so the audit records a predecessor signed verify under the key this boot holds, and
/// `/admin/verify`'s walks find nothing.
///
/// RED before the follow-up: the keyset was minted per process, so the resumed records named a key
/// this boot did not hold and every one was a finding.
#[test]
fn a_restart_over_the_same_store_verifies_the_prior_boots_records() {
    let slots = crate::root::store_double::RecordSlots::new();
    {
        let mut durability = keyed_store_book(&slots, 21);
        for unit in 1..=3 {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert!(durability.audit_records.iter().all(|r| r.key_id.is_some()));
        drained(&durability);
    }
    let restarted = keyed_store_book(&slots, 21);
    assert_eq!(restarted.audit_records.len(), 3, "the prior boot's records");
    assert_eq!(
        restarted.retained_audit_findings(),
        Vec::<String>::new(),
        "the prior boot's records verify under the key the store kept"
    );
    let (lane, own, keys) = restarted
        .stored_walk_inputs()
        .expect("a book over the store");
    let walk = walk_stored_chains(&lane, own, &keys);
    assert_eq!(walk.findings, Vec::<String>::new());
}

/// **THE WALK OF EVERY STORED CHAIN DOES NOT CALL THIS NODE'S RECORD MID-PUT TORN.** The walk
/// (`/admin/verify`) reads the store without the book's lock while the lane's worker puts this
/// node's records part by part. A record whose first part is in the store and which the lane still
/// holds is being put, not torn, and the walk says nothing about it. A record missing a part that
/// the node does not hold is torn, and the walk still says so.
///
/// RED before the fix: the walk read this node's chain with the plain stored read and warned "the
/// stored journal holds a record whose parts are not all there" for the lane's record mid-put.
#[test]
fn the_stored_walk_does_not_call_this_nodes_record_mid_put_torn() {
    use tracing_subscriber::layer::SubscriberExt as _;
    const TORN: &str = "parts are not all there";
    let slots = crate::root::store_double::RecordSlots::new();
    let mut durability = keyed_store_book(&slots, 27);
    durability
        .seal_unit(audit_inputs(1), audit_pass(), &token())
        .expect("sealed");
    drained(&durability);

    // A body past one slot's bound: two parts at the least. The store takes the first, no more.
    slots.take_then_refuse(1);
    durability
        .journal
        .append(
            &token(),
            StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                RecordClass::Load,
                vec![7u8; 1_000],
            )],
        )
        .expect("handed to the lane");
    let newest = durability.journal.next_seq() - 1;
    let lane = durability.lane().expect("a book over the store");
    assert!(
        lane.wait_acked(
            durability.journal.node(),
            newest,
            std::time::Duration::from_secs(5)
        )
        .is_err(),
        "the store took the first part and refused the next"
    );
    assert_eq!(lane.pending(), 1, "the record is still the lane's");

    let (lane, own, keys) = durability
        .stored_walk_inputs()
        .expect("a book over the store");
    let cap = busbar_kernel::test_support::warn_capture::WarnCapture::default();
    let walk =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(cap.clone()), || {
            walk_stored_chains(&lane, own, &keys)
        });
    assert_eq!(walk.findings, Vec::<String>::new(), "the chain verifies");
    assert!(
        !cap.contains(TORN),
        "a record the lane still holds is not torn: {:?}",
        cap.messages()
    );

    // A part with no first part, past anything the node holds: torn, and said so.
    let stray = newest + 10;
    slots.put_row(JOURNAL_SCHEMA, &part_key(own, stray, 1), &[0, 2, 9]);
    let cap = busbar_kernel::test_support::warn_capture::WarnCapture::default();
    let _ =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(cap.clone()), || {
            walk_stored_chains(&lane, own, &keys)
        });
    assert_eq!(cap.count(TORN), 1, "a torn record is still reported");
}

/// **ON A CHAIN THE STORE KEEPS, EVERY RECORD NAMES THE NODE THE STORE ASSIGNED** (THE DESIGN §1:
/// "when (wall + monotonic, node)"; H3 with #662): an audit record's `node` is the id its chain is
/// keyed by and `/admin/verify` walks it under, the same before a restart and after it — not the
/// per-process draw that is the node half of this process's op ids.
///
/// RED before the fix: the book sealed as `busbar_kernel::door::node()`, a fresh draw per process,
/// so the records on one host's stored chain named a node the store never assigned.
#[test]
fn a_store_kept_chain_seals_every_record_as_the_store_assigned_node() {
    let slots = crate::root::store_double::RecordSlots::new();
    let node = node_id(slots.calls().as_ref(), "host-sealing").expect("an id");
    {
        let mut durability = keyed_store_book(&slots, node);
        assert_eq!(
            durability.record.node(),
            node,
            "the book seals as the store's id"
        );
        for unit in 1..=2 {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert!(
            durability.audit_records.iter().all(|r| r.node == node),
            "{:?}",
            durability.audit_records
        );
        drained(&durability);
    }
    let mut restarted = keyed_store_book(&slots, node);
    assert_eq!(
        restarted.record.node(),
        node,
        "a restart seals as the node the store assigned, not as this process"
    );
    restarted
        .seal_unit(audit_inputs(3), audit_pass(), &token())
        .expect("sealed");
    assert_eq!(restarted.audit_records.len(), 3);
    assert!(
        restarted.audit_records.iter().all(|r| r.node == node),
        "one node across the restart: {:?}",
        restarted.audit_records
    );
    drained(&restarted);
    assert_eq!(restarted.retained_audit_findings(), Vec::<String>::new());
    let (lane, own, keys) = restarted
        .stored_walk_inputs()
        .expect("a book over the store");
    assert_eq!(own, node);
    let walk = walk_stored_chains(&lane, own, &keys);
    assert_eq!(walk.chains, vec![node]);
    assert_eq!(
        walk.findings,
        Vec::<String>::new(),
        "the walk accepts the records under the node the store assigned"
    );
}

/// **THE WALK OF EVERY STORED CHAIN FINDS AN UNSIGNED RECORD SEALED AFTER THAT CHAIN'S
/// `Bootstrap`** (BUSBAR-1.6.0.md l.193, "integrity (prev hash)"; l.2285, #82(a) "sign at seal
/// time, in the process that sealed it"): the signature is not in the digest and the journal's
/// links are unkeyed, so an edit to a stored record that strips its signature and recomputes its
/// digest and the links leaves a chain that verifies whole, and only the unsigned rule sees it. The
/// stored walk keeps that rule per chain, as the retained walk keeps it for this node: every record
/// from the first one journalled after the chain's `Bootstrap` on is signed. The peer's chain here
/// is sealed unsigned past its `Bootstrap`, the bytes such an edit leaves, and the node walking it
/// never held that record in its own retained cache.
///
/// RED before the fix: the walk skipped every record naming no key, and found nothing.
#[test]
fn the_stored_walk_finds_an_unsigned_record_after_a_chains_bootstrap() {
    let slots = crate::root::store_double::RecordSlots::new();
    let walking = node_id(slots.calls().as_ref(), "host-walking").expect("an id");
    let peer = node_id(slots.calls().as_ref(), "host-stripped").expect("an id");
    {
        let mut durability = keyed_store_book(&slots, peer);
        durability
            .seal_unit(audit_inputs(1), audit_pass(), &token())
            .expect("sealed");
        // From here on the peer's chain seals unsigned, past its Bootstrap.
        durability.record = AuditChain::resume(&durability.audit_records).sealing_as(peer);
        let stripped = durability
            .seal_unit(audit_inputs(2), audit_pass(), &token())
            .expect("sealed");
        assert!(stripped.key_id.is_none() && stripped.signature.is_none());
        drained(&durability);
    }
    let durability = keyed_store_book(&slots, walking);
    assert_eq!(
        durability.retained_audit_findings(),
        Vec::<String>::new(),
        "this node's own retained records hold nothing of the peer's"
    );
    let (lane, own, keys) = durability
        .stored_walk_inputs()
        .expect("a book over the store");
    let walk = walk_stored_chains(&lane, own, &keys);
    assert_eq!(
        walk.findings,
        vec![format!(
            "node {peer}: audit record 2 is unsigned, sealed after the keyset was bound"
        )]
    );
}

/// **A STORED RECORD SEALED BEFORE ITS CHAIN'S `Bootstrap` IS UNSIGNED, AND THAT IS NOT A FINDING**
/// (the green twin of the test above; BUSBAR-1.6.0.md l.2285, #82(a): "records sealed before"
/// a key was bound stay unsigned, which is the truth about them): a chain a keyless boot began over
/// the store, continued by a boot that binds the deployment keyset, walks clean.
///
/// Green before the fix and after it: the rule starts at the chain's `Bootstrap`, never before.
#[test]
fn the_stored_walk_accepts_records_sealed_before_a_chains_bootstrap() {
    let slots = crate::root::store_double::RecordSlots::new();
    let node = node_id(slots.calls().as_ref(), "host-keyless-first").expect("an id");
    {
        let mut keyless = store_book(&slots, node);
        for unit in 1..=2 {
            keyless
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        drained(&keyless);
    }
    let mut keyed = keyed_store_book(&slots, node);
    let third = keyed
        .seal_unit(audit_inputs(3), audit_pass(), &token())
        .expect("sealed");
    assert!(third.key_id.is_some(), "sealed under the bound key");
    drained(&keyed);
    let (lane, own, keys) = keyed.stored_walk_inputs().expect("a book over the store");
    let walk = walk_stored_chains(&lane, own, &keys);
    assert_eq!(walk.chains, vec![node]);
    assert_eq!(walk.findings, Vec::<String>::new());
}

/// **AN AUDIT BODY ON A STORED CHAIN THAT DOES NOT DECODE IS A FINDING OF THE WALK**, never a
/// record silently dropped (BUSBAR-1.6.0.md l.193, "integrity"; the boot's resume reports the same
/// record as a restart finding): a record the walk cannot read is one it cannot verify, so its
/// digest, its link and its signature go unchecked, and the walk says so.
///
/// RED before the fix: the walk filtered the record out, and found nothing.
#[test]
fn the_stored_walk_reports_an_audit_body_that_does_not_decode() {
    let slots = crate::root::store_double::RecordSlots::new();
    let node = node_id(slots.calls().as_ref(), "host-undecodable").expect("an id");
    let mut durability = keyed_store_book(&slots, node);
    durability
        .seal_unit(audit_inputs(1), audit_pass(), &token())
        .expect("sealed");
    let mut inputs = audit_inputs(2);
    inputs.usage.lines.push(UsageLine {
        class: busbar_contract::MeterClassId::new("a_class_this_node_never_registered"),
        quantity: 3,
        source: busbar_contract::caps::QuantitySource::Count,
        estimated: false,
    });
    durability
        .seal_unit(inputs, audit_pass(), &token())
        .expect("sealed");
    drained(&durability);
    let (lane, own, keys) = durability
        .stored_walk_inputs()
        .expect("a book over the store");
    let walk = walk_stored_chains(&lane, own, &keys);
    assert_eq!(walk.findings.len(), 1, "{:?}", walk.findings);
    assert!(
        walk.findings[0].starts_with(&format!("node {node}: record "))
            && walk.findings[0].contains("a_class_this_node_never_registered"),
        "{:?}",
        walk.findings
    );
}

/// **A RUNNING DRIVEN UNIT'S CHECKPOINT IS KEPT BY THE STORE, AND A KILL RECOVERS IT THERE** (THE
/// DESIGN §7: "a checkpoint is a durability `unit.accrued` record"; H3 with K2-H1): on a node with
/// no data directory, the checkpoint the root's flush tick journals for a running unit rides the
/// lane to the store like every other record, and a boot over the same store recovers the unit's
/// hold at those counts, priced, marked RECOVERED.
///
/// RED with the resume neutralised (a book over the store opening an empty memory journal): the
/// restarted book has no hold to recover and no posting.
#[test]
fn a_driven_unit_killed_mid_stream_over_the_store_is_recovered_at_its_flushed_checkpoint() {
    use busbar_contract::abi::plane::{UnitCount, UNITS_REPORTED};
    use busbar_contract::caps::{OriginKind, PrincipalId};
    use busbar_kernel::plane_driver::{
        EndPost, FeeRefund, FlushEpoch, MoneySeam, PlaneMoney, UnitMoney,
    };
    use busbar_kernel_egress::ports::Journal as _;
    use std::sync::Arc;

    let slots = crate::root::store_double::RecordSlots::new();
    let principal = PrincipalId::new("vk_driven_unit_store");
    let balance = totals_key("vk_driven_unit_store");
    let unit = busbar_contract::UnitKey::new(9);
    let arrived = crate::root::plane_node::Arrived::at(ARRIVED_MS, 91);
    {
        let book = Arc::new(std::sync::Mutex::new(store_book(&slots, 13)));
        let node = Arc::new(crate::root::plane_node::Node::new());
        node.bind_book(Arc::clone(&book));
        // The unit's hold, opened as the node opens it at admission (`Node::open_on_book`).
        {
            let durability_token = token();
            let at = Settling {
                key: &balance,
                window: busbar_kernel::governance::budget_window(
                    busbar_kernel::governance::WINDOW_DAY,
                    arrived.secs(),
                ),
                durability: &durability_token,
                step: StepName::Admit,
                stamp: PostingStamp {
                    rate_card_version: 0,
                    wall: arrived.secs(),
                    mono: arrived.mono(),
                },
            };
            book.lock()
                .expect("book")
                .open_hold(&at, &principal, &UnitCounts::default(), arrived.ms())
                .expect("the hold goes on the chain");
        }
        let post = Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::clone(&node)));
        post.open(unit, principal.clone(), arrived, None);
        post.dispatched(&busbar_kernel_egress::ports::Dispatched {
            leg: 0,
            attempt: 1,
            pool: String::new(),
            destination: busbar_contract::DestinationId::new(0),
            lane: None,
            unit,
        })
        .expect("the dispatch goes on the chain");
        let gov = Arc::new(
            busbar_kernel::governance::GovState::new(
                Arc::new(busbar_kernel::governance::MemoryStore::new()),
                None,
            )
            .expect("gov"),
        );
        let epoch = FlushEpoch::new();
        let money =
            PlaneMoney::new(gov, Arc::clone(&post) as Arc<dyn EndPost>).with_epoch(epoch.clone());
        money.open(
            unit,
            UnitMoney {
                key: Arc::new(busbar_contract::records::VirtualKey::default()),
                cost: Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
                    None,
                    0,
                    &std::collections::BTreeMap::new(),
                )),
                pool: String::new(),
                lane: LANE.to_string(),
                classes: Arc::from(vec!["input".to_string()]),
                arrived: arrived.secs(),
                mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                fee: FeeRefund::CallerStatus,
                charge: Default::default(),
            },
        );
        let ctx = busbar_kernel::teller::UnitCtx {
            call: busbar_contract::caps::CallId::UNBOUND,
            key: unit,
            origin: OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        money.checkpoint(
            &ctx,
            &[UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: 300,
            }],
        );
        // THE ROOT'S FLUSH TICK: the epoch moves, and the running unit's counts are journaled.
        epoch.bump();
        assert_eq!(
            money.flush_checkpoints(&*post),
            1,
            "one checkpoint journaled"
        );
        drained(&book.lock().expect("book"));
        // kill -9 mid-stream: no end, no settle, and the book's destructor never runs.
        drop((money, post, node));
        std::mem::forget(book);
    }

    let restarted = store_book(&slots, 13);
    assert!(
        restarted.keeps_chain(),
        "the chain was resumed from the store"
    );
    assert_eq!(restarted.recovered_holds, 1);
    let recovered = restarted
        .read_back()
        .into_iter()
        .find(|p| p.kind == PostingKind::Settlement && p.key == balance)
        .expect("the recovery posted onto the chain");
    assert!(
        recovered.flags.contains(PostingFlags::RECOVERED),
        "a unit that dispatched is recovered: {:?}",
        recovered.flags
    );
    assert_eq!(
        recovered.counts,
        Some(inputs(300)),
        "the checkpoint the store kept, not zero"
    );
    assert_eq!(recovered.settled, 300, "priced at its epoch, above zero");
}

/// **TWO NODES ON ONE STORE NEVER COLLIDE, AND VERIFY WALKS BOTH CHAINS**: each host takes its own stable id from the store's node registry, a
/// restart on the same host takes the same one back, each node resumes exactly its own chain, and
/// the walk `/admin/verify` makes reads and verifies both — and names an edit made to the other
/// node's chain in the store.
///
/// RED before the follow-up: every node wrote as node 0, so the second node's records overwrote the
/// first's in the store.
#[test]
fn two_nodes_on_one_store_never_collide_and_verify_walks_both_chains() {
    let slots = crate::root::store_double::RecordSlots::new();
    let a = node_id(slots.calls().as_ref(), "host-a").expect("an id for host-a");
    let b = node_id(slots.calls().as_ref(), "host-b").expect("an id for host-b");
    assert_ne!(a, b, "two hosts, two identities");
    assert_ne!(a, 0);
    assert_eq!(
        node_id(slots.calls().as_ref(), "host-a").expect("again"),
        a,
        "a restart on the same host takes the same id back"
    );
    {
        let mut first = keyed_store_book(&slots, a);
        let mut second = keyed_store_book(&slots, b);
        for unit in 1..=2 {
            first
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        for unit in 1..=5 {
            second
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        drained(&first);
        drained(&second);
    }
    let first = keyed_store_book(&slots, a);
    let second = keyed_store_book(&slots, b);
    assert_eq!(first.audit_records.len(), 2, "node a resumes its own chain");
    assert_eq!(
        second.audit_records.len(),
        5,
        "node b resumes its own chain"
    );
    assert!(
        first.restart_findings.is_empty(),
        "{:?}",
        first.restart_findings
    );
    assert!(
        second.restart_findings.is_empty(),
        "{:?}",
        second.restart_findings
    );

    let (lane, own, keys) = first.stored_walk_inputs().expect("a book over the store");
    let walk = walk_stored_chains(&lane, own, &keys);
    let mut both = vec![a, b];
    both.sort_unstable();
    assert_eq!(walk.chains, both, "the walk reads both chains");
    assert_eq!(walk.findings, Vec::<String>::new(), "and both verify");

    slots.corrupt(JOURNAL_SCHEMA, &part_key(b, 2, 0));
    let walk = walk_stored_chains(&lane, own, &keys);
    assert!(
        walk.findings
            .iter()
            .any(|f| f.starts_with(&format!("node {b}:"))),
        "an edit to the other node's stored chain is a finding on this node's verify: {:?}",
        walk.findings
    );
}

/// **RACING FIRST BOOTS KEEP ONE DEPLOYMENT KEYSET**: minting the
/// keyset redeems the store's single-use claim first, so a boot that lost it takes the key the
/// winner keeps rather than keeping its own over it.
///
/// RED before the claim: the losing boot put its own seed and read its own back, and the two nodes
/// signed with two keys.
#[test]
fn a_first_boot_that_lost_the_keyset_claim_takes_the_winners_key() {
    use store_identity::{keyset_claim, KEYSET_SCHEMA, MINT_CLAIM_KIND};
    let slots = crate::root::store_double::RecordSlots::new();
    let winners = "a".repeat(64);
    let mine = "b".repeat(64);
    // The other boot won this period's claim (and the next one's, so the test never straddles a
    // period boundary) and keeps its key a moment later.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    for at in [now, now + store_identity::MINT_CLAIM_SECS] {
        assert!(slots.redeem(MINT_CLAIM_KIND, &keyset_claim(at), u64::MAX, 0));
    }
    let writer = {
        let slots = slots.clone();
        let winners = winners.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            slots.put_row(KEYSET_SCHEMA, b"deployment", winners.as_bytes());
        })
    };
    let kept = keep_keyset(slots.calls().as_ref(), &mine).expect("the winner's keyset");
    writer.join().expect("the winner kept its key");
    assert_eq!(
        kept, winners,
        "the boot that lost the claim takes the winner's key"
    );
    assert_eq!(
        stored_keyset(slots.calls().as_ref()).expect("read"),
        Some(winners),
        "and never keeps its own over it"
    );
}

/// A boot that lost the keyset claim and finds nothing kept in time REFUSES rather than mint a
/// second key; once the claim lapses, a later boot claims it and mints.
#[test]
fn a_lost_keyset_claim_with_nothing_kept_refuses_until_the_claim_lapses() {
    use store_identity::{keyset_claim, MINT_CLAIM_KIND, MINT_CLAIM_SECS};
    let slots = crate::root::store_double::RecordSlots::new();
    let secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
    };
    // Start at the beginning of a period, so the refused boot below runs well inside it.
    let start = secs();
    while secs() / MINT_CLAIM_SECS == start / MINT_CLAIM_SECS {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let now = secs();
    // A winner that died before it kept anything: this period's claim is redeemed, nothing kept.
    assert!(slots.redeem(MINT_CLAIM_KIND, &keyset_claim(now), u64::MAX, now));
    let mine = "d".repeat(64);
    let refused = keep_keyset(slots.calls().as_ref(), &mine).expect_err("no second key");
    assert!(refused.contains("claim"), "{refused}");
    assert_eq!(stored_keyset(slots.calls().as_ref()).expect("read"), None);
    // Retried in the same period, the boot still refuses: its losing redemption bought nothing.
    keep_keyset(slots.calls().as_ref(), &mine).expect_err("still no second key");
    // The period ends; the next boot claims the next period's token and mints.
    while secs() / MINT_CLAIM_SECS == now / MINT_CLAIM_SECS {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        keep_keyset(slots.calls().as_ref(), &mine).expect("minted"),
        mine
    );
}

/// **RACING FIRST BOOTS OF ONE HOST TAKE ONE NODE ID**: minting a
/// host's id redeems the store's claim on that host first, so the boot that lost it takes the id
/// the winner keeps.
///
/// RED before the claim: the losing boot minted and kept an id of its own over the winner's, and
/// the two boots wrote two chains for one host.
#[test]
fn a_first_boot_that_lost_the_host_claim_takes_the_winners_node_id() {
    use store_identity::{host_claim, MINT_CLAIM_KIND, NODE_SCHEMA};
    let slots = crate::root::store_double::RecordSlots::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    for at in [now, now + store_identity::MINT_CLAIM_SECS] {
        assert!(slots.redeem(MINT_CLAIM_KIND, &host_claim("host-r", at), u64::MAX, 0));
    }
    let writer = {
        let slots = slots.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            slots.put_row(NODE_SCHEMA, b"host:host-r", &77u64.to_be_bytes());
        })
    };
    let id = node_id(slots.calls().as_ref(), "host-r").expect("the winner's id");
    writer.join().expect("the winner kept its id");
    assert_eq!(id, 77, "the boot that lost the claim takes the winner's id");
    assert_eq!(slots.rows_under(NODE_SCHEMA), 1, "and keeps no second row");
}

/// A minted node id is claimed for good before it is kept: every id the registry gives a host is
/// one the store's id claims hold, so no second host can be handed it.
#[test]
fn every_minted_node_id_is_held_by_its_claim() {
    use store_identity::MINT_CLAIM_KIND;
    let slots = crate::root::store_double::RecordSlots::new();
    let a = node_id(slots.calls().as_ref(), "host-x").expect("an id");
    assert!(
        !slots.redeem(MINT_CLAIM_KIND, &format!("node-id:{a:016x}"), u64::MAX, 0),
        "the id's claim is already redeemed"
    );
    assert_eq!(node_id(slots.calls().as_ref(), "host-x").expect("again"), a);
}

/// A RUNNING DRIVEN UNIT'S CHECKPOINT REACHES THE CHAIN, AND A KILL RECOVERS IT THERE (THE DESIGN
/// §7: "a checkpoint is a durability `unit.accrued` record"; K2-H1, R1-M9).
///
/// A unit is admitted onto a node whose book has a data directory (its hold opened, its facts on
/// the posting site), its egress walk records that it dispatched, and its plane reports 300 input
/// units on a piece. The piece path only marks the unit; the root's flush tick bumps the epoch and
/// journals the checkpoint. The process is then killed with the unit running. The next boot
/// recovers the hold at those 300 units, priced, marked RECOVERED. Before the flush tick journaled
/// the plane's running counts nothing durable carried them, and the same kill recovered it at 0.
#[test]
fn a_driven_unit_killed_mid_stream_is_recovered_at_its_flushed_checkpoint() {
    use busbar_contract::abi::plane::{UnitCount, UNITS_REPORTED};
    use busbar_contract::caps::{OriginKind, PrincipalId};
    use busbar_kernel::plane_driver::{
        EndPost, FeeRefund, FlushEpoch, MoneySeam, PlaneMoney, UnitMoney,
    };
    use busbar_kernel_egress::ports::Journal as _;
    use std::sync::Arc;

    let scratch = ScratchDir::new("checkpoint-flushed");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let principal = PrincipalId::new("vk_session");
    let balance = totals_key("vk_session");
    let unit = busbar_contract::UnitKey::new(9);
    let arrived = crate::root::plane_node::Arrived::at(ARRIVED_MS, 91);
    {
        let book = Arc::new(std::sync::Mutex::new(
            boot(&cfg, 12).expect("the directory is writable"),
        ));
        let node = Arc::new(crate::root::plane_node::Node::new());
        node.bind_book(Arc::clone(&book));
        // The unit's hold, opened as the node opens it at admission (`Node::open_on_book`).
        {
            let durability_token = token();
            let at = Settling {
                key: &balance,
                window: busbar_kernel::governance::budget_window(
                    busbar_kernel::governance::WINDOW_DAY,
                    arrived.secs(),
                ),
                durability: &durability_token,
                step: StepName::Admit,
                stamp: PostingStamp {
                    rate_card_version: 0,
                    wall: arrived.secs(),
                    mono: arrived.mono(),
                },
            };
            book.lock()
                .expect("book")
                .open_hold(&at, &principal, &UnitCounts::default(), arrived.ms())
                .expect("the hold goes on the chain");
        }
        let post = Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::clone(&node)));
        post.open(unit, principal.clone(), arrived, None);
        post.dispatched(&busbar_kernel_egress::ports::Dispatched {
            leg: 0,
            attempt: 1,
            pool: String::new(),
            destination: busbar_contract::DestinationId::new(0),
            lane: None,
            unit,
        })
        .expect("the dispatch goes on the chain");
        let gov = Arc::new(
            busbar_kernel::governance::GovState::new(
                Arc::new(busbar_kernel::governance::MemoryStore::new()),
                None,
            )
            .expect("gov"),
        );
        let epoch = FlushEpoch::new();
        let money =
            PlaneMoney::new(gov, Arc::clone(&post) as Arc<dyn EndPost>).with_epoch(epoch.clone());
        money.open(
            unit,
            UnitMoney {
                key: Arc::new(busbar_contract::records::VirtualKey::default()),
                cost: Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
                    None,
                    0,
                    &std::collections::BTreeMap::new(),
                )),
                pool: String::new(),
                lane: LANE.to_string(),
                classes: Arc::from(vec!["input".to_string()]),
                arrived: arrived.secs(),
                mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                fee: FeeRefund::CallerStatus,
                charge: Default::default(),
            },
        );
        let ctx = busbar_kernel::teller::UnitCtx {
            call: busbar_contract::caps::CallId::UNBOUND,
            key: unit,
            origin: OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        money.checkpoint(
            &ctx,
            &[UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: 300,
            }],
        );
        // THE ROOT'S FLUSH TICK: the epoch moves, and the running unit's counts are journaled.
        epoch.bump();
        assert_eq!(
            money.flush_checkpoints(&*post),
            1,
            "one checkpoint journaled"
        );
        // kill -9 mid-stream: no end, no settle, and the book's destructor never runs.
        drop((money, post, node));
        std::mem::forget(book);
    }

    let restarted = boot(&cfg, 12).expect("the journal reopens");
    assert_eq!(restarted.recovered_holds, 1);
    let recovered = restarted
        .read_back()
        .into_iter()
        .find(|p| p.kind == PostingKind::Settlement && p.key == balance)
        .expect("the recovery posted onto the chain");
    assert!(
        recovered.flags.contains(PostingFlags::RECOVERED),
        "a unit that dispatched is recovered: {:?}",
        recovered.flags
    );
    assert_eq!(
        recovered.counts,
        Some(inputs(300)),
        "the flushed checkpoint's counts, not zero"
    );
    assert_eq!(recovered.settled, 300, "priced at its epoch, above zero");
}

/// A RECOVERED POSTING NAMES THE CARD IN FORCE AT ITS UNIT'S ARRIVAL (#79; R1-L14), as the exit
/// arm's does — not the opening entry, and not the head of the history.
#[test]
fn a_recovered_posting_names_the_card_in_force_at_its_arrival() {
    use busbar_contract::caps::PrincipalId;
    let scratch = ScratchDir::new("recovered-card");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let mut history = busbar_kernel_ledger::cost::History::new();
    let entry = |from: u64| busbar_kernel_ledger::cost::CardEntryDraft {
        effective_from: from,
        effective_until: None,
        card: one_nano_card(),
        appended_at: 0,
        author: busbar_kernel_ledger::cost::Author::Opening,
    };
    history.append(entry(0));
    let in_force = history.append(entry(ARRIVED_MS - 1_000));
    let head = history.append(entry(ARRIVED_MS + 60_000));
    let pinned = crate::root::kernel::PinnedHistory::for_test(std::sync::Arc::new(history), head);
    let source = || -> HistorySource {
        let pinned = pinned.clone();
        Box::new(move || Some(pinned.clone()))
    };
    let key = totals_key("vk_carded");
    {
        let mut durability = build_priced(&cfg, 13, Box::new(NullShipper::new()), rows(), source())
            .expect("the directory is writable");
        let durability_token = token();
        let mut at = settling(&key, &durability_token);
        at.stamp.mono = 5;
        durability
            .open_hold(&at, &PrincipalId::new("vk_carded"), &inputs(0), ARRIVED_MS)
            .expect("the hold goes on the chain");
        durability.journal_dispatch(&at).expect("dispatched");
        durability
            .checkpoint_accrual(&at, &inputs(120), ARRIVED_MS)
            .expect("checkpointed");
        std::mem::forget(durability);
    }
    let restarted = build_priced(&cfg, 13, Box::new(NullShipper::new()), rows(), source())
        .expect("the journal reopens");
    let recovered = restarted
        .read_back()
        .into_iter()
        .find(|p| p.kind == PostingKind::Settlement && p.key == key)
        .expect("the recovery posted onto the chain");
    assert!(recovered.flags.contains(PostingFlags::RECOVERED));
    assert_eq!(
        recovered.rate_card_version,
        in_force.get(),
        "the card in force at the unit's arrival, not the opening entry nor the head"
    );
    assert_ne!(in_force, busbar_kernel_ledger::cost::HistorySeq::OPENING);
}

/// A LIVE HOLDER: `lease` refreshed on every lease poll until the guard drops, as a running node's
/// flush tick refreshes it.
struct Refreshing(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    Option<std::thread::JoinHandle<()>>,
);

impl Refreshing {
    fn new(
        slots: &crate::root::store_double::RecordSlots,
        lease: Option<&store_identity::NodeLease>,
    ) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = lease.cloned().map(|lease| {
            let (calls, stop) = (slots.calls(), std::sync::Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = lease.refresh(calls.as_ref());
                    std::thread::sleep(std::time::Duration::from_millis(
                        store_identity::LEASE_TTL_MS / 9,
                    ));
                }
            })
        });
        Refreshing(stop, handle)
    }
}

impl Drop for Refreshing {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.1.take() {
            let _ = handle.join();
        }
    }
}

/// Two LIVE nodes that share one host name — `host`, or none at all — on one store: each takes its
/// identity, seals its own audit records and settles its own money, and each restarted book over
/// the store reads back exactly its own.
fn two_live_nodes_keep_their_own_records(host: &str) {
    let slots = crate::root::store_double::RecordSlots::new();
    let a = take_node(slots.calls().as_ref(), host).expect("the first node's identity");
    let _live = Refreshing::new(&slots, a.lease.as_ref());
    let b = take_node(slots.calls().as_ref(), host).expect("the second node's identity");
    assert_ne!(
        a.id, b.id,
        "two live nodes named {host:?} journal under one identity"
    );
    let (ka, kb) = (totals_key("vk_same_a"), totals_key("vk_same_b"));
    {
        let mut first = store_book(&slots, a.id);
        let mut second = store_book(&slots, b.id);
        for unit in 1..=2 {
            first
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        settle_one(&mut first, &ka, 1_000, 600, 1);
        for unit in 1..=5 {
            second
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        settle_one(&mut second, &kb, 1_000, 900, 1);
        drained(&first);
        drained(&second);
    }
    let first = store_book(&slots, a.id);
    let second = store_book(&slots, b.id);
    assert_eq!(
        first.audit_records.len(),
        2,
        "the first node's audit records"
    );
    assert_eq!(
        second.audit_records.len(),
        5,
        "the second node's audit records"
    );
    assert_eq!(first.ledger.book().get(&ka, 86_400).settled, 600);
    assert_eq!(first.ledger.book().get(&kb, 86_400).settled, 0);
    assert_eq!(second.ledger.book().get(&kb, 86_400).settled, 900);
    assert_eq!(second.ledger.book().get(&ka, 86_400).settled, 0);
    assert!(
        first.restart_findings.is_empty(),
        "{:?}",
        first.restart_findings
    );
    assert!(
        second.restart_findings.is_empty(),
        "{:?}",
        second.restart_findings
    );
}

/// **TWO LIVE NODES WITH ONE HOST NAME KEEP SEPARATE MONEY AND AUDIT RECORDS**: the second takes a fresh id because the first holds the name's lease.
///
/// RED before the fix: the identity was the host name's alone, so both nodes journaled under one
/// id and overwrote each other's records in the store.
#[test]
fn two_live_nodes_with_one_host_name_keep_separate_money_and_audit_records() {
    two_live_nodes_keep_their_own_records("host-same");
}

/// **TWO LIVE NAMELESS NODES KEEP SEPARATE MONEY AND AUDIT RECORDS**: no host name is one
/// name, held under one lease like any other.
///
/// RED before the fix: every nameless host shared the empty name's one identity.
#[test]
fn two_live_nameless_nodes_keep_separate_money_and_audit_records() {
    two_live_nodes_keep_their_own_records("");
}

/// **A CRASH-RESTART RESUMES THE SAME CHAIN AND RECOVERS ITS HOLDS**: a node with no data
/// directory killed with a hold open (its lease neither released nor refreshed again) restarts at
/// once; the new boot watches the lease, sees it lapse unrefreshed, takes the host's id back under
/// a lease of its own and resumes its chain. (The in-process sweep never sees a dead process's
/// holds; resuming the chain is what recovers them.)
///
/// RED before the fix: no lease was taken, so the restart held nothing a second process would see.
#[test]
fn a_restart_after_the_lease_lapsed_resumes_the_chain_and_recovers_the_holds() {
    let slots = crate::root::store_double::RecordSlots::new();
    let held = totals_key("vk_lease_held");
    let first = take_node(slots.calls().as_ref(), "host-lapse").expect("an identity");
    assert!(
        first.lease.is_some(),
        "the first boot holds the name's lease"
    );
    {
        let mut durability = store_book(&slots, first.id);
        durability
            .seal_unit(audit_inputs(1), audit_pass(), &token())
            .expect("sealed");
        let durability_token = token();
        let mut at = settling(&held, &durability_token);
        at.stamp.mono = 77;
        durability
            .open_hold(
                &at,
                &busbar_contract::caps::PrincipalId::new("vk_lease_held"),
                &inputs(2_000),
                ARRIVED_MS,
            )
            .expect("the hold goes on the chain");
        drained(&durability);
        // kill -9: no release of the lease, nothing flushed on the way out.
        std::mem::forget(durability);
        std::mem::forget(first.lease);
    }
    let again = take_node(slots.calls().as_ref(), "host-lapse").expect("an identity");
    assert_eq!(again.id, first.id, "the restart takes the host's id back");
    assert!(again.lease.is_some(), "under a lease of its own");
    let restarted = store_book(&slots, again.id);
    assert_eq!(restarted.audit_records.len(), 1, "the chain is resumed");
    assert_eq!(
        restarted.recovered_holds, 1,
        "the hold the dead process left open is recovered"
    );
    // A clean shutdown releases the lease: the next boot resumes at once.
    again
        .lease
        .as_ref()
        .expect("held")
        .release(slots.calls().as_ref())
        .expect("released");
    let next = take_node(slots.calls().as_ref(), "host-lapse").expect("an identity");
    assert_eq!(next.id, first.id, "a released lease is taken at once");
}

/// **A BOOT WHILE ITS PREDECESSOR STILL REFRESHES THE LEASE TAKES A FRESH ID**: the lease is refreshed while the second process watches it, so its holder is live, and
/// the second journals under an id of its own and leaves the host's chain untouched.
///
/// RED before the fix: the second process took the host's id and wrote over the first's chain.
#[test]
fn a_restart_while_the_old_lease_is_live_takes_a_fresh_id() {
    let slots = crate::root::store_double::RecordSlots::new();
    let first = take_node(slots.calls().as_ref(), "host-overlap").expect("an identity");
    let live = Refreshing::new(&slots, first.lease.as_ref());
    {
        let mut durability = store_book(&slots, first.id);
        for unit in 1..=3 {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        drained(&durability);
        std::mem::forget(durability);
    }
    let second = take_node(slots.calls().as_ref(), "host-overlap").expect("an identity");
    drop(live);
    assert_ne!(second.id, first.id, "a live lease is never shared");
    assert!(second.lease.is_none(), "and the second holds none");
    {
        let mut durability = store_book(&slots, second.id);
        assert!(durability.audit_records.is_empty(), "a chain of its own");
        durability
            .seal_unit(audit_inputs(9), audit_pass(), &token())
            .expect("sealed");
        drained(&durability);
    }
    assert_eq!(
        store_book(&slots, first.id).audit_records.len(),
        3,
        "the first process's chain is untouched"
    );
    let (lane, own, keys) = keyed_store_book(&slots, second.id)
        .stored_walk_inputs()
        .expect("a book over the store");
    let walk = walk_stored_chains(&lane, own, &keys);
    assert!(walk.chains.contains(&first.id) && walk.chains.contains(&second.id));
}

/// A book over the store whose journal is on `dir`.
fn dir_store_book(
    slots: &crate::root::store_double::RecordSlots,
    dir: &std::path::Path,
    node: u64,
) -> Durability {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    build_on_store(
        &DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        node,
        lane,
        rows(),
        priced(),
        None,
    )
    .expect("the directory opens")
}

/// **A NODE WITH A DATA DIRECTORY KEEPS ITS ID IN IT, AND A RESTART READS IT BACK**: the id
/// is the directory's own, so two directories on one host name are two identities.
///
/// RED before the fix: the id came from the host name in the store, and nothing was kept in the
/// directory.
#[test]
fn a_restart_over_the_same_data_dir_keeps_its_id() {
    let slots = crate::root::store_double::RecordSlots::new();
    let one = ScratchDir::new("node-id-one");
    let two = ScratchDir::new("node-id-two");
    let id = persisted_node(slots.calls().as_ref(), &one.path, "host-dir")
        .expect("an id")
        .id;
    assert!(
        one.entries()
            .contains(&store_identity::NODE_ID_FILE.to_string()),
        "the id is kept in the node's own data directory: {:?}",
        one.entries()
    );
    assert_eq!(
        persisted_node(slots.calls().as_ref(), &one.path, "host-dir")
            .expect("again")
            .id,
        id,
        "a restart reads the same id back"
    );
    assert_ne!(
        persisted_node(slots.calls().as_ref(), &two.path, "host-dir")
            .expect("another")
            .id,
        id,
        "another directory on the same host name is another node"
    );
    let full = std::fs::read_to_string(one.path.join(store_identity::NODE_ID_FILE)).expect("kept");
    assert_eq!(full.trim().len(), 32, "a 128-bit id: {full:?}");
}

/// **MIGRATION: THE HOST NAME'S OLD REGISTRY ID IS ADOPTED, AND THE CHAIN KEEPS READING**:
/// a data directory written by a build that keyed the node by its host name has no id file; its
/// first boot on this build adopts the id the registry holds under that name, keeps it in the
/// directory, and the chain written under it reads back whole.
///
/// RED before the fix: nothing was kept in the directory.
#[test]
fn the_first_boot_adopts_the_host_names_registry_id_and_the_chain_keeps_reading() {
    use store_identity::NODE_SCHEMA;
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = ScratchDir::new("node-id-migrate");
    slots.put_row(NODE_SCHEMA, b"host:host-old", &77u64.to_be_bytes());
    {
        // The old build's boot: the journal written under the registry's id.
        let mut durability = dir_store_book(&slots, &dir.path, 77);
        for unit in 1..=2 {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        drained(&durability);
    }
    let taken = persisted_node(slots.calls().as_ref(), &dir.path, "host-old").expect("adopted");
    let id = taken.id;
    assert_eq!(id, 77, "the registry's id is adopted");
    let full = std::fs::read_to_string(dir.path.join(store_identity::NODE_ID_FILE))
        .expect("the adopted id is kept in the directory");
    assert_eq!(
        u128::from_str_radix(full.trim(), 16).expect("hex") & u128::from(u64::MAX),
        77,
        "its low 64 bits are the journal key"
    );
    let restarted = dir_store_book(&slots, &dir.path, id);
    assert_eq!(restarted.journal.node(), 77, "the chain keeps its identity");
    assert_eq!(restarted.audit_records.len(), 2, "and keeps reading");
    assert!(
        restarted.restart_findings.is_empty(),
        "{:?}",
        restarted.restart_findings
    );
    // A clean shutdown releases the adopted id's lease; a later boot reads the kept id back.
    if let Some(lease) = &taken.lease {
        lease.release(slots.calls().as_ref()).expect("released");
    }
    assert_eq!(
        persisted_node(slots.calls().as_ref(), &dir.path, "host-old")
            .expect("again")
            .id,
        77,
        "later boots read the kept id"
    );
}

/// **A DATA-DIRECTORY NODE THAT ADOPTED ITS HOST NAME'S ID HOLDS THAT NAME'S LEASE**: a live node with no data directory and the same name then takes a fresh id, so the
/// two never journal under one identity.
///
/// RED before the fix: both took the host name's registry id.
#[test]
fn a_data_dir_node_that_adopted_the_host_id_holds_its_lease_against_a_no_data_dir_peer() {
    use store_identity::NODE_SCHEMA;
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = ScratchDir::new("node-id-mixed");
    slots.put_row(NODE_SCHEMA, b"host:host-mix", &77u64.to_be_bytes());
    let adopted = persisted_node(slots.calls().as_ref(), &dir.path, "host-mix").expect("adopted");
    assert_eq!(
        adopted.id, 77,
        "the data-dir node adopts the host name's id"
    );
    let _live = Refreshing::new(&slots, adopted.lease.as_ref());
    let peer = take_node(slots.calls().as_ref(), "host-mix").expect("an identity");
    assert_ne!(
        peer.id, adopted.id,
        "a live no-data-dir node with the same name takes the adopted id"
    );
    assert!(
        adopted.lease.is_some(),
        "the adopted id is held under the lease"
    );
    assert!(peer.lease.is_none(), "and the peer holds none");
}

/// THE HELD CHECKPOINTS ARE RE-DERIVED FROM THE CHAIN, AS THEY WERE SEALED: the node keeps each seal's head and not its balances, and one
/// ordered walk of its journal hands every held checkpoint back with the very figures it sealed,
/// oldest first, the same set the ring holds.
#[test]
fn every_held_checkpoint_is_re_derived_from_the_chain_as_it_was_sealed() {
    let token = token();
    let mut durability = memory_node();
    let key = totals_key("vk_held");
    let mut sealed = Vec::new();
    for n in 1..=3u64 {
        settle_one(&mut durability, &key, 1_000, 100 * n, n);
        sealed.push(
            durability
                .seal_checkpoint(&token, StepName::Meter, 1_700_000_000 + n)
                .expect("the seal goes down"),
        );
    }
    assert!(
        sealed
            .windows(2)
            .all(|pair| pair[0].totals != pair[1].totals),
        "each seal holds figures the one before it did not"
    );
    let mut served = Vec::new();
    durability
        .each_held_checkpoint(&mut |checkpoint| served.push(checkpoint.clone()))
        .expect("every held checkpoint re-derives");
    // The set the ring holds (the cadence may have sealed beside the explicit seals), in order,
    // and every explicit seal among them with the very figures it sealed.
    assert_eq!(
        served.iter().map(Checkpoint::head).collect::<Vec<_>>(),
        durability.checkpoints
    );
    for seal in &sealed {
        assert!(
            served.contains(seal),
            "checkpoint {} is served as it was sealed",
            seal.checkpoint_seq
        );
    }
}

/// RED: A HELD CHECKPOINT THE CHAIN DOES NOT REPRODUCE IS REFUSED BY ITS SEQUENCE
/// NUMBER, never served with numbers. A figure the book moved with no record behind it is sealed
/// into the second checkpoint, so the chain re-derives figures that are not the sealed ones; and a
/// held head no record on the chain carries is refused as not on the chain.
#[test]
fn a_held_checkpoint_the_chain_does_not_reproduce_is_refused_by_its_seq() {
    use crate::root::durability::CheckpointUnreadable;

    let token = token();
    let mut durability = memory_node();
    settle_one(&mut durability, &totals_key("vk_held"), 1_000, 400, 1);
    let first = durability
        .seal_checkpoint(&token, StepName::Meter, 1_700_000_001)
        .expect("the seal goes down");
    durability
        .ledger
        .book_mut()
        .entry(totals_key("vk_unrecorded"), 86_400)
        .settled = 1;
    let second = durability
        .seal_checkpoint(&token, StepName::Meter, 1_700_000_002)
        .expect("the seal goes down");

    let mut served = Vec::new();
    let refused = durability
        .each_held_checkpoint(&mut |checkpoint| served.push(checkpoint.checkpoint_seq))
        .expect_err("a figure no record carries cannot be re-derived");
    assert_eq!(
        refused,
        CheckpointUnreadable::Diverged {
            checkpoint_seq: second.checkpoint_seq
        }
    );
    assert!(served.contains(&first.checkpoint_seq), "{served:?}");
    assert!(
        served.iter().all(|seq| *seq < second.checkpoint_seq),
        "no figure past the refusal: {served:?}"
    );

    let mut stray = first.head();
    stray.checkpoint_seq = 99;
    durability.checkpoints = vec![stray];
    assert_eq!(
        durability.each_held_checkpoint(&mut |_| {}),
        Err(CheckpointUnreadable::NotOnChain { checkpoint_seq: 99 })
    );
}

/// RED: ON A NODE RESUMED FROM THE STORE WHOSE
/// CHAIN OUTGREW ONE MEMORY SEGMENT, EVERY HELD CHECKPOINT STILL RE-DERIVES. The memory log keeps only
/// its newest segment resident (`Wal::memory_seeded`); the rest of the chain is the store's. A walk
/// of the journal's own replay starts mid-chain, misses the settlement sealed before the roll, and
/// reads every held checkpoint as diverged; the walk has to read the whole chain, store copy plus
/// the resident segment, as `/verify`'s chain reader does ([`Durability::chain`]).
///
/// The segment is the shipped [`busbar_kernel_wal::SEGMENT_BYTES`]: the log has no smaller one to
/// ask for, so the first boot pads the chain past it, as the amendment journal's `store` phase does.
#[test]
fn a_store_resumed_chain_past_one_segment_re_derives_every_held_checkpoint() {
    /// One padding record's body: a few hundred roll the log past a segment, and 256 of them (one
    /// block of the store's scan) stay inside one scan.
    const PAD_BODY: usize = 100_000;
    const NODE: u64 = 41;

    let token = token();
    let slots = crate::root::store_double::RecordSlots::new();
    let early = totals_key("vk_before_the_roll");
    let late = totals_key("vk_after_the_roll");
    {
        let mut durability = store_book(&slots, NODE);
        settle_one(&mut durability, &early, 1_000, 300, 1);
        let pads = usize::try_from(busbar_kernel_wal::SEGMENT_BYTES).expect("fits") / PAD_BODY + 1;
        for _ in 0..pads {
            durability
                .journal
                .append(
                    &token,
                    StepName::Meter,
                    &[Entry::new(RecordClass::Load, vec![0x5a; PAD_BODY]).at(1_700_000_000, 0)],
                )
                .expect("the padding goes on the chain");
        }
        assert!(
            durability
                .lane()
                .expect("a book over the store")
                .drain(std::time::Duration::from_secs(120)),
            "the store takes the journal's records"
        );
    }

    let mut restarted = store_book(&slots, NODE);
    assert!(
        restarted.keeps_chain(),
        "the chain was resumed from the store"
    );
    assert!(
        restarted.journal.log().segments_used() >= 2,
        "the resumed memory journal rolled past one segment"
    );
    assert_eq!(
        restarted.ledger.book().get(&early, 86_400).settled,
        300,
        "the boot read the whole chain"
    );
    let mut sealed = Vec::new();
    for n in 1..=2u64 {
        settle_one(&mut restarted, &late, 1_000, 100 * n, 10 + n);
        sealed.push(
            restarted
                .seal_checkpoint(&token, StepName::Meter, 1_700_000_100 + n)
                .expect("the seal goes down"),
        );
    }

    let mut served = Vec::new();
    restarted
        .each_held_checkpoint(&mut |checkpoint| served.push(checkpoint.clone()))
        .expect("every held checkpoint re-derives from the whole chain");
    assert_eq!(
        served.iter().map(Checkpoint::head).collect::<Vec<_>>(),
        restarted.checkpoints,
        "the set the ring holds, in order"
    );
    for seal in &sealed {
        assert!(
            served.contains(seal),
            "checkpoint {} is served as it was sealed",
            seal.checkpoint_seq
        );
        assert_eq!(
            seal.totals_for(&early, 86_400).settled,
            300,
            "the seal holds the settlement made before the roll"
        );
    }
}

/// THE HELD CHECKPOINTS RE-DERIVE ACROSS A RETIREMENT. The chain keeps every window the book let go; the seal that left a window out
/// was taken from a book that no longer held it. The walk drops every window retired at or before
/// each held seal, so the seal before the retirement is served WITH the window, the seal that left
/// it out WITHOUT it, and both as they were sealed. RED with the walk folding the whole chain into
/// the scratch book unfiltered: the second seal read as diverged.
#[test]
fn a_held_checkpoint_sealed_without_a_retired_window_still_re_derives() {
    use busbar_kernel_ledger::totals::WINDOW_RETENTION_SECS;

    let token = token();
    let mut durability = memory_node();
    let key = totals_key("vk_retired_held");
    settle_one(&mut durability, &key, 1_000, 250, 1);
    let window = 86_400;
    assert_eq!(durability.ledger.book().get(&key, window).settled, 250);
    let now = window + WINDOW_RETENTION_SECS + 10;

    let first = durability
        .seal_checkpoint(&token, StepName::Meter, now)
        .expect("the seal goes down");
    assert!(
        first.totals.contains_key(&(key.clone(), window)),
        "the first seal has no kept seal before it, so it retires nothing"
    );
    let second = durability
        .seal_checkpoint(&token, StepName::Meter, now + 1)
        .expect("the seal goes down");
    assert!(
        !second.totals.contains_key(&(key.clone(), window)),
        "the second seal leaves out the window the first holds past the horizon"
    );
    assert_eq!(durability.ledger.book().get(&key, window), Totals::zero());

    let mut served = Vec::new();
    durability
        .each_held_checkpoint(&mut |checkpoint| served.push(checkpoint.clone()))
        .expect("every held checkpoint re-derives across the retirement");
    assert_eq!(served, vec![first, second], "each as it was sealed");
    // ONE resident sealed copy: the newest seal's balances and no other's. The ring holds two seals
    // here, the first with a balance the second left out, so a copy per held seal would count it.
    assert_eq!(durability.checkpoints.len(), 2);
    assert_eq!(
        durability.sealed_balances_held(),
        durability.checkpoints.last().expect("a held seal").balances,
        "the node holds the newest seal's balances and no other seal's"
    );
}

/// RED: WHAT THE NODE KEEPS TO RE-DERIVE ITS HELD CHECKPOINTS ACROSS
/// RETIREMENTS IS BOUNDED BY THE 31-DAY HORIZON, not by how many windows it ever retired. Forty
/// windows are sealed while young; each seal after it carries one more past the horizon, and the
/// seal leaves it out. Once every one of them is retired, no held seal kept a window past its
/// horizon, so nothing is kept. RED with a per-seal record of every retired window: forty instants,
/// one more per retirement for the life of the process.
#[test]
fn many_retirements_across_seals_keep_only_what_the_horizon_requires() {
    use busbar_kernel_ledger::totals::WINDOW_RETENTION_SECS;
    const DAY: u64 = 86_400;
    const WINDOWS: u64 = 40;

    let token = token();
    let mut durability = memory_node();
    let key = totals_key("vk_bounded_retirement");
    for day in 1..=WINDOWS {
        durability
            .ledger
            .book_mut()
            .entry(key.clone(), day * DAY)
            .settled = 1;
    }
    durability
        .seal_checkpoint(&token, StepName::Meter, DAY)
        .expect("the seal goes down");
    for day in 1..=WINDOWS {
        durability
            .seal_checkpoint(&token, StepName::Meter, day * DAY + WINDOW_RETENTION_SECS)
            .expect("the seal goes down");
        assert_eq!(
            durability.ledger.book().get(&key, day * DAY),
            Totals::zero(),
            "window {day} leaves the book at the seal that carries it past the horizon"
        );
    }
    assert!(durability.ledger.book().is_empty(), "every window retired");
    assert_eq!(
        durability.retirement_windows_held(),
        0,
        "no held seal kept a window past its horizon, so nothing is kept to re-derive them"
    );
}

/// RED: A WINDOW POSTED AGAIN AFTER ITS RETIREMENT STILL RE-DERIVES.
/// The second seal leaves the window out and the book lets it go; a late posting then lands on that
/// window, so the book holds it again with only the new figure, and the third seal carries it. The
/// walk drops the retired window from its scratch book when it passes the seal that left it out, so
/// the posting after the retirement rebuilds exactly what the book holds. RED with the walk
/// filtering every snapshot by the windows retired so far: the third seal reads as diverged, the
/// window it holds filtered away.
#[test]
fn a_window_posted_again_after_its_retirement_still_re_derives() {
    use busbar_kernel_ledger::totals::WINDOW_RETENTION_SECS;

    let token = token();
    let mut durability = memory_node();
    let key = totals_key("vk_reposted");
    let window = 86_400;
    settle_one(&mut durability, &key, 1_000, 250, 1);
    let now = window + WINDOW_RETENTION_SECS + 10;
    let first = durability
        .seal_checkpoint(&token, StepName::Meter, now)
        .expect("the seal goes down");
    let second = durability
        .seal_checkpoint(&token, StepName::Meter, now + 1)
        .expect("the seal goes down");
    assert!(!second.totals.contains_key(&(key.clone(), window)));
    assert_eq!(durability.ledger.book().get(&key, window), Totals::zero());

    settle_one(&mut durability, &key, 1_000, 70, 2);
    assert_eq!(
        durability.ledger.book().get(&key, window).settled,
        70,
        "the late posting rebuilds the window with its own figure only"
    );
    let third = durability
        .seal_checkpoint(&token, StepName::Meter, now + 2)
        .expect("the seal goes down");
    assert_eq!(third.totals_for(&key, window).settled, 70);

    let mut served = Vec::new();
    durability
        .each_held_checkpoint(&mut |checkpoint| served.push(checkpoint.clone()))
        .expect("every held checkpoint re-derives, the reposted window included");
    // The set the ring holds (the cadence may have sealed beside the explicit seals), in order,
    // and every explicit seal among them with the very figures it sealed.
    assert_eq!(
        served.iter().map(Checkpoint::head).collect::<Vec<_>>(),
        durability.checkpoints
    );
    for seal in [&first, &second, &third] {
        assert!(
            served.contains(seal),
            "checkpoint {} is served as it was sealed",
            seal.checkpoint_seq
        );
    }
}

/// RED (#1492 review BLOCKER): A SEAL'S HORIZON LEAVES WITH IT WHEN THE RING DROPS IT. One window
/// past the horizon can never retire (its figures move before every seal), so every seal keeps it;
/// after more seals than the ring holds, the node keeps a horizon for each seal the ring holds and
/// no more, and the windows kept across them are bounded the same way. RED with the ring's prune of
/// the horizons removed: one horizon, and one kept window, per seal ever made.
#[test]
fn the_horizons_kept_are_bounded_by_the_ring_when_a_window_can_never_retire() {
    use super::CHECKPOINT_RING;
    use busbar_kernel_ledger::totals::WINDOW_RETENTION_SECS;

    let token = token();
    let mut durability = memory_node();
    let key = totals_key("vk_never_retires");
    let window = 86_400;
    let now = window + WINDOW_RETENTION_SECS + 10;
    let seals = CHECKPOINT_RING as u64 + 8;
    for n in 0..seals {
        // The figures move before every seal, so the window is never held by the last seal at the
        // book's own figures, and never retires.
        durability
            .ledger
            .book_mut()
            .entry(key.clone(), window)
            .settled += 1;
        durability
            .seal_checkpoint(&token, StepName::Meter, now + n)
            .expect("the seal goes down");
    }
    assert_eq!(
        durability.ledger.book().get(&key, window).settled,
        i128::from(u32::try_from(seals).expect("fits")),
        "the window never retired"
    );
    assert_eq!(durability.checkpoints.len(), CHECKPOINT_RING);
    assert!(
        durability.seal_horizons_held() <= CHECKPOINT_RING,
        "{} seal horizons kept beside a ring of {CHECKPOINT_RING}",
        durability.seal_horizons_held()
    );
    assert!(
        durability.retirement_windows_held() <= CHECKPOINT_RING,
        "{} kept windows across a ring of {CHECKPOINT_RING} held seals",
        durability.retirement_windows_held()
    );
}
