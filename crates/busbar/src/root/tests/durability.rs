//! Tests for `durability.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_kernel_audit::{Recipe, UsageLine};
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

fn token() -> Grant<DurableWrite> {
    busbar_kernel::test_support::tokens::grant::<DurableWrite>()
}

/// A journal over `cfg` as node `node`, with no card holder to rebuild.
fn boot(cfg: &DurabilityConfig, node: u64) -> Result<Durability, OpenError> {
    build_with_cards(cfg, node, Box::new(NullShipper::new()), None)
}

/// Seal one unit's audit record onto `durability`'s journal: the record every unit leaves.
fn seal(durability: &mut Durability, unit: u64) {
    durability
        .seal_unit(audit_inputs(unit), audit_pass(), &token())
        .expect("the record goes on the chain");
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
        build(&cfg, Box::new(NullShipper::new())).expect("memory-buffered cannot fail");

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
    )
    .expect("memory-buffered cannot fail");
    seal(&mut durability, 1);

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
    let durability = build(&cfg, Box::new(NullShipper::new())).expect("the directory is writable");

    assert!(durability.on_disk());
    assert_eq!(durability.journal.mode(), Mode::OnDisk);
    assert!(
        !scratch.entries().is_empty(),
        "a configured data directory should hold the journal's first segment"
    );
}

/// The two branches build the same stack. A node without a data directory is not running a
/// reduced audit chain; only the journal's backing differs.
#[test]
fn both_branches_build_the_same_audit_records() {
    let scratch = ScratchDir::new("same");
    let buffered = build(
        &DurabilityConfig { data_dir: None },
        Box::new(NullShipper::new()),
    )
    .expect("memory-buffered cannot fail");
    let on_disk = build(
        &DurabilityConfig {
            data_dir: Some(scratch.path.clone()),
        },
        Box::new(NullShipper::new()),
    )
    .expect("the directory is writable");

    // The audit chains start at the same place on both, because neither is a function of where
    // the journal lives.
    assert_eq!(buffered.record.next_seq(), on_disk.record.next_seq());
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
    assert!(build(&cfg, Box::new(NullShipper::new())).is_err());
}

/// A node journalling its units has only its own records on the journal: an administrative row
/// never leaks onto it.
#[test]
fn journalling_carries_no_admin_row() {
    let mut durability = build_for_node(
        &DurabilityConfig { data_dir: None },
        4,
        Box::new(NullShipper::new()),
    )
    .expect("memory-buffered cannot fail");
    for unit in 1..=3 {
        seal(&mut durability, unit);
    }
    let replayed = durability
        .journal
        .replay()
        .expect("readable")
        .expect("verifies");
    assert_eq!(replayed.len(), 3);
    assert!(replayed.iter().all(|r| r.class == RecordClass::Transaction));
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
    )
    .expect("memory-buffered cannot fail");
    for unit in 1..=4 {
        seal(&mut durability, unit);
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

/// A claim's balance as the admin claim journal writes it.
fn claim(claim: &str) -> ClaimBalance {
    ClaimBalance {
        claim: claim.to_string(),
        key: ClaimKey {
            bucket: "admin-idempotency".to_string(),
            dimension: (1, String::new()),
            scope: (1, "actor".to_string()),
        },
        window: u64::MAX,
    }
}

/// EVERY IDEMPOTENCY CLAIM A PREDECESSOR TOOK IS VOIDED AT THE NEXT BOOT — once. No unit's state
/// outlives its process here (there are no holds on the journal), so a kept claim would answer a
/// client's retry with a unit that never ran on this boot.
#[test]
fn every_idempotency_claim_a_predecessor_took_is_voided_once_at_boot() {
    let scratch = ScratchDir::new("claim-voided");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut durability = boot(&cfg, 12).expect("the directory is writable");
        for (name, mono) in [("idem-a", 5), ("idem-b", 6)] {
            durability
                .journal_claim(
                    claim(name),
                    ClaimStamp { wall: 1, mono },
                    &token(),
                    StepName::Route,
                )
                .expect("the claim goes on the chain");
        }
        std::mem::forget(durability);
    }

    let restarted = boot(&cfg, 12).expect("the journal reopens");
    assert_eq!(
        restarted.voided_claims,
        vec!["idem-a".to_string(), "idem-b".to_string()],
        "every claim a predecessor took is voided"
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
    build_on_store(&DurabilityConfig { data_dir: None }, node, lane, None)
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

/// **A NODE WITH NO DATA DIRECTORY KEEPS ITS CHAIN IN ITS STORE ACROSS A RESTART** (ARCHITECT
/// 2026-10-07 H3 ruling (a)-(b); THE DESIGN §7). Sealed audit records go on the chain and the node
/// is killed (kill -9); a second journal over the SAME store resumes that chain: the audit cache is
/// rebuilt from it and the numbering continues past every stored record.
///
/// RED before the fix: the store adapter's shipper acknowledged every batch and kept a count, and a
/// memory-buffered journal opened empty, so the restarted node had no audit record and numbered
/// from one again.
#[test]
fn a_restart_over_the_same_store_keeps_the_chain_and_the_audit_records() {
    let slots = crate::root::store_double::RecordSlots::new();
    let (head, next) = {
        let mut durability = store_book(&slots, 11);
        for unit in 1..=3 {
            seal(&mut durability, unit);
        }
        drained(&durability);
        let out = (durability.journal.head(), durability.journal.next_seq());
        // kill -9: no destructor of the journal, nothing flushed on the way out.
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
    assert!(
        restarted.journal.next_seq() >= next,
        "the numbering continues past the stored chain"
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

/// **A STORE THAT REFUSES DOES NOT REFUSE A DATA UNIT** (ARCHITECT 2026-10-07 H3 ruling (c)): the
/// unit's record waits in the lane and is re-offered, and it lands once the store recovers — read
/// back by the next boot. Meanwhile the lane is unhealthy, which is what a durable verb refuses on.
#[test]
fn a_data_unit_rides_a_refusing_store_and_its_record_lands_once_it_recovers() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut durability = store_book(&slots, 12);
    slots.refuse(true);
    seal(&mut durability, 1);
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
        restarted.audit_records.len(),
        1,
        "the re-offered record landed and read back"
    );
}

/// **A FULL LANE FAILS CLOSED AND DROPS NOTHING** (ARCHITECT 2026-10-07 H3 ruling): with the store
/// refusing, the lane fills; the node then refuses new work with its reason, the
/// journal keeps every record it is handed (no `ChainBreak`, nothing dropped), and once the store
/// recovers everything lands and the book admits again.
#[test]
fn a_full_lane_refuses_new_money_and_drops_no_record() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut durability = store_book_bounded(&slots, 13, 4);
    slots.refuse(true);
    assert!(durability.refuses_money().is_none());
    // Records past the lane's bound: each unit's audit record is one.
    let mut lost = 0;
    for unit in 1..=6 {
        if durability
            .seal_unit(audit_inputs(unit), audit_pass(), &token())
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

/// **TWO NODES ON ONE STORE NEVER COLLIDE, AND VERIFY WALKS BOTH CHAINS** (ARCHITECT 2026-10-07 H3
/// ruling, follow-up (2)): each host takes its own stable id from the store's node registry, a
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
/// identity and seals its own audit records, and each restarted journal over the store reads back
/// exactly its own (Q128 root part 12 HIGH 2).
fn two_live_nodes_keep_their_own_records(host: &str) {
    let slots = crate::root::store_double::RecordSlots::new();
    let a = take_node(slots.calls().as_ref(), host).expect("the first node's identity");
    let _live = Refreshing::new(&slots, a.lease.as_ref());
    let b = take_node(slots.calls().as_ref(), host).expect("the second node's identity");
    assert_ne!(
        a.id, b.id,
        "two live nodes named {host:?} journal under one identity"
    );
    {
        let mut first = store_book(&slots, a.id);
        let mut second = store_book(&slots, b.id);
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

/// **TWO LIVE NODES WITH ONE HOST NAME KEEP SEPARATE AUDIT RECORDS** (Q128 root part 12
/// HIGH 2): the second takes a fresh id because the first holds the name's lease.
///
/// RED before the fix: the identity was the host name's alone, so both nodes journaled under one
/// id and overwrote each other's records in the store.
#[test]
fn two_live_nodes_with_one_host_name_keep_separate_audit_records() {
    two_live_nodes_keep_their_own_records("host-same");
}

/// **TWO LIVE NAMELESS NODES KEEP SEPARATE AUDIT RECORDS** (Q128): no host name is one
/// name, held under one lease like any other.
///
/// RED before the fix: every nameless host shared the empty name's one identity.
#[test]
fn two_live_nameless_nodes_keep_separate_audit_records() {
    two_live_nodes_keep_their_own_records("");
}

/// **A CRASH-RESTART RESUMES THE SAME CHAIN** (Q128): a node with no data directory killed (its
/// lease neither released nor refreshed again) restarts at once; the new boot watches the lease,
/// sees it lapse unrefreshed, takes the host's id back under a lease of its own and resumes its
/// chain.
///
/// RED before the fix: no lease was taken, so the restart held nothing a second process would see.
#[test]
fn a_restart_after_the_lease_lapsed_resumes_the_chain() {
    let slots = crate::root::store_double::RecordSlots::new();
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
