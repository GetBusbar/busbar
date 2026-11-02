use super::*;
use busbar_kernel_audit::{Recipe, UsageLine};
use busbar_kernel_wal::{decode_run, verify_journal, NullShipper};

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

fn entries_of(path: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .expect("the directory is readable")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

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
    busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>()
}

fn boot(
    slots: &crate::root::store_double::RecordSlots,
    cfg: &DurabilityConfig,
    node: u64,
) -> Result<Durability, OpenError> {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    build_on_store(cfg, node, lane, None)
}

fn seal(durability: &mut Durability, unit: u64) {
    durability
        .seal_unit(audit_inputs(unit), audit_pass(), &token())
        .expect("the record goes on the chain");
}

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
        origin: busbar_kernel_testkit::test_support::tokens::origin(OriginKind::Client),
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

fn audit_pass() -> busbar_contract::caps::Pass<busbar_contract::caps::Audit> {
    busbar_kernel_testkit::test_support::tokens::pass()
}

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

#[test]
fn two_boots_minting_the_same_unit_key_seal_distinct_verified_records() {
    let slots = crate::root::store_double::RecordSlots::new();
    let scratch = ScratchDir::new("audit-two-boots");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let first = {
        let mut durability = boot(&slots, &cfg, 7).expect("the Store reads back");
        durability
            .seal_unit(audit_inputs(1), audit_pass(), &token())
            .expect("sealed");
        drained(&durability);
        durability.audit_records.last().unwrap().clone()
    };
    let mut restarted = boot(&slots, &cfg, 7).expect("the journal reopens");
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

    drained(&restarted);
    let reread = boot(&slots, &cfg, 7).expect("the journal reopens");
    let whole = reread
        .audit_window(1, u64::MAX)
        .expect("the journal reads back");
    assert_eq!(whole, vec![first, second]);
    assert!(AuditChain::verify_chain(&whole).is_ok());
    assert!(reread.retained_audit_findings().is_empty());
}

#[test]
fn a_range_older_than_the_ring_is_read_back_after_a_restart() {
    let slots = crate::root::store_double::RecordSlots::new();
    let scratch = ScratchDir::new("audit-older-than-ring");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let total = (AUDIT_RING + 5) as u64;
    {
        let mut durability = boot(&slots, &cfg, 7).expect("the Store reads back");
        for unit in 1..=total {
            durability
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert_eq!(durability.audit_records.len(), AUDIT_RING);
        drained(&durability);
    }
    let restarted = boot(&slots, &cfg, 7).expect("the journal reopens");
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

fn strip_signature(record: &mut AuditRecord) {
    record.signature = None;
    record.key_id = None;
}

#[test]
fn an_unsigned_record_sealed_under_a_bound_keyset_is_a_verify_finding() {
    let slots = crate::root::store_double::RecordSlots::new();
    let scratch = ScratchDir::new("audit-unsigned-under-key");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut durability = boot(&slots, &cfg, 7).expect("the Store reads back");
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
        drained(&durability);
    }
    let mut restarted = boot(&slots, &cfg, 7).expect("the journal reopens");
    bind_keyset(&mut restarted, &scratch.path);
    assert!(restarted.retained_audit_findings().is_empty());
    strip_signature(&mut restarted.audit_records[0]);
    assert_eq!(
        restarted.retained_audit_findings(),
        vec!["record 1 is unsigned, sealed after the keyset was bound".to_string()]
    );
}

#[test]
fn records_sealed_before_the_keyset_was_bound_are_not_findings() {
    let slots = crate::root::store_double::RecordSlots::new();
    let scratch = ScratchDir::new("audit-unsigned-before-key");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut keyless = boot(&slots, &cfg, 7).expect("the Store reads back");
        for unit in 1..=2 {
            keyless
                .seal_unit(audit_inputs(unit), audit_pass(), &token())
                .expect("sealed");
        }
        assert!(keyless.retained_audit_findings().is_empty());
        drained(&keyless);
    }
    {
        let mut keyed = boot(&slots, &cfg, 7).expect("the journal reopens");
        bind_keyset(&mut keyed, &scratch.path);
        let third = keyed
            .seal_unit(audit_inputs(3), audit_pass(), &token())
            .expect("sealed");
        assert!(third.key_id.is_some(), "sealed under the bound key");
        assert!(keyed.retained_audit_findings().is_empty());
        drained(&keyed);
    }
    let mut reread = boot(&slots, &cfg, 7).expect("the journal reopens");
    bind_keyset(&mut reread, &scratch.path);
    assert!(reread.retained_audit_findings().is_empty());
    strip_signature(&mut reread.audit_records[2]);
    assert_eq!(
        reread.retained_audit_findings(),
        vec!["record 3 is unsigned, sealed after the keyset was bound".to_string()]
    );
}

#[test]
fn an_audit_record_naming_an_undeclared_class_is_a_restart_finding() {
    let slots = crate::root::store_double::RecordSlots::new();
    let scratch = ScratchDir::new("audit-undeclared-class");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut durability = boot(&slots, &cfg, 7).expect("the Store reads back");
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
        drained(&durability);
    }
    let restarted = boot(&slots, &cfg, 7).expect("the journal reopens");
    assert!(
        restarted.restart_findings.iter().any(|f| {
            let f = f.to_string();
            f.contains("audit chain") && f.contains("a_class_this_node_never_registered")
        }),
        "{:?}",
        restarted.restart_findings
    );
}

#[test]
fn a_bare_shipper_with_a_data_dir_keeps_only_ram() {
    let scratch = ScratchDir::new("set");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    let durability = build(&cfg, Box::new(NullShipper::new())).expect("a RAM helper opens");

    assert!(!durability.on_disk());
    assert!(
        !durability.keeps_chain(),
        "a bare shipper cannot prove restart durability"
    );
    assert!(!durability.durable_in_store());
    assert_eq!(durability.journal.mode(), Mode::MemoryBuffered);
    assert!(scratch.entries().is_empty());
}

#[test]
fn both_legacy_config_shapes_build_the_same_helper_audit_records() {
    let scratch = ScratchDir::new("same");
    let buffered = build(
        &DurabilityConfig { data_dir: None },
        Box::new(NullShipper::new()),
    )
    .expect("memory-buffered cannot fail");
    let configured = build(
        &DurabilityConfig {
            data_dir: Some(scratch.path.clone()),
        },
        Box::new(NullShipper::new()),
    )
    .expect("the Store reads back");

    assert_eq!(buffered.record.next_seq(), configured.record.next_seq());

    assert_eq!(buffered.journal.head(), configured.journal.head());
    assert_eq!(buffered.journal.next_seq(), 1);
}

#[test]
fn a_bare_shipper_never_opens_even_an_unusable_data_dir() {
    let scratch = ScratchDir::new("unopenable");

    let blocked = scratch.path.join("not-a-directory");
    std::fs::write(&blocked, b"").expect("write the blocking file");

    let cfg = DurabilityConfig {
        data_dir: Some(blocked),
    };
    let book = build(&cfg, Box::new(NullShipper::new())).expect("the path is never opened");
    assert!(!book.keeps_chain());
    assert!(!book.on_disk());
    assert_eq!(std::fs::read(cfg.data_dir.unwrap()).unwrap(), b"");
}

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

#[test]
fn every_idempotency_claim_a_predecessor_took_is_voided_once_at_boot() {
    let slots = crate::root::store_double::RecordSlots::new();
    let scratch = ScratchDir::new("claim-voided");
    let cfg = DurabilityConfig {
        data_dir: Some(scratch.path.clone()),
    };
    {
        let mut durability = boot(&slots, &cfg, 12).expect("the Store reads back");
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
        drained(&durability);
        drop(durability);
    }

    let restarted = boot(&slots, &cfg, 12).expect("the journal reopens");
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
    drained(&restarted);
    drop(restarted);

    let third = boot(&slots, &cfg, 12).expect("the journal reopens again");
    assert!(
        third.voided_claims.is_empty(),
        "a voided claim is not voided twice: {:?}",
        third.voided_claims
    );
}

#[test]
fn a_corrupt_legacy_segment_is_preserved_without_local_quarantine() {
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = ScratchDir::new("legacy-quarantine");
    let segment = dir.path.join("0000000000000000.wal");
    let bytes = b"corrupt legacy segment";
    std::fs::write(&segment, bytes).expect("legacy fixture");
    let mut durability = dir_store_book(&slots, &dir.path, 7);
    assert!(durability.quarantined.is_empty());
    assert!(durability.restart_findings.is_empty());
    assert!(durability
        .journal_quarantines(&token(), StepName::Meter, 1)
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read(&segment).unwrap(), bytes);
    assert_eq!(dir.entries(), vec!["0000000000000000.wal"]);
}

fn store_book(slots: &crate::root::store_double::RecordSlots, node: u64) -> Durability {
    store_book_bounded(slots, node, busbar_kernel_wal::MEMORY_BUFFER_RECORDS)
}

fn store_book_bounded(
    slots: &crate::root::store_double::RecordSlots,
    node: u64,
    capacity: usize,
) -> Durability {
    let lane =
        JournalLane::with_capacity(slots.calls(), "test-store", capacity).expect("the lane starts");
    build_on_store(
        &DurabilityConfig {
            data_dir: Some(PathBuf::from("/dev/null/legacy-journal")),
        },
        node,
        lane,
        None,
    )
    .expect("the store reads back")
}

fn drained(durability: &Durability) {
    assert!(
        durability
            .lane()
            .expect("a book over the store")
            .drain(std::time::Duration::from_secs(5)),
        "the store takes the journal's records"
    );
}

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

#[test]
fn a_full_lane_refuses_new_money_and_drops_no_record() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut durability = store_book_bounded(&slots, 13, 4);
    slots.refuse(true);
    assert!(durability.refuses_money().is_none());

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

#[test]
fn a_retained_batch_past_the_lanes_bound_drains_once_the_store_recovers() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut durability = store_book_bounded(&slots, 15, 4);
    drained(&durability);
    slots.refuse(true);

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

    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
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
    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
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

    let stray = newest + 10;
    slots.put_row(JOURNAL_SCHEMA, &part_key(own, stray, 1), &[0, 2, 9]);
    let cap = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let _ =
        tracing::subscriber::with_default(tracing_subscriber::registry().with(cap.clone()), || {
            walk_stored_chains(&lane, own, &keys)
        });
    assert_eq!(cap.count(TORN), 1, "a torn record is still reported");
}

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

#[test]
fn a_delayed_first_keyset_candidate_reads_the_atomic_winner() {
    use busbar_contract::abi::sdk::store::conditional::Mutation;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    let slots = crate::root::store_double::RecordSlots::new();
    let mine = "a".repeat(64);
    let winner = "b".repeat(64);
    let (entered, waiting) = std::sync::mpsc::sync_channel(1);
    let (release, resumed) = std::sync::mpsc::sync_channel(1);
    let resumed = Arc::new(Mutex::new(resumed));
    let once = Arc::new(AtomicBool::new(true));
    let selected = mine.clone();
    slots.on_transaction(move |request| {
        if request.mutations.iter().any(|m| {
            matches!(m, Mutation::Put { schema, value, .. }
            if schema == store_identity::KEYSET_SCHEMA && value == selected.as_bytes())
        }) && once.swap(false, Ordering::SeqCst)
        {
            entered.send(()).unwrap();
            resumed.lock().unwrap().recv().unwrap();
        }
        None
    });
    let delayed = {
        let slots = slots.clone();
        std::thread::spawn(move || keep_keyset(slots.calls().as_ref(), &mine))
    };
    waiting
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        keep_keyset(slots.calls().as_ref(), &winner).unwrap(),
        winner
    );
    release.send(()).unwrap();
    assert_eq!(delayed.join().unwrap().unwrap(), winner);
    assert_eq!(stored_keyset(slots.calls().as_ref()).unwrap(), Some(winner));
    assert_eq!(slots.puts(), 1, "one immutable key was published");
}

#[test]
fn an_unreadable_stored_keyset_is_not_absent_or_replaced() {
    use store_identity::KEYSET_SCHEMA;
    let slots = crate::root::store_double::RecordSlots::new();
    let corrupt = b"private-key-material\xff";
    slots.put_row(KEYSET_SCHEMA, b"deployment", corrupt);
    let calls = slots.calls();
    let error = stored_keyset(calls.as_ref()).expect_err("corrupt bytes are not absence");
    assert!(!error.contains("private-key-material"));
    keep_keyset(calls.as_ref(), &"bb".repeat(32)).expect_err("never replace corrupt state");
    let kept = wait_for(calls.record_get(KEYSET_SCHEMA, b"deployment"))
        .expect("read")
        .expect("the original row remains");
    assert_eq!(kept.as_slice(), corrupt);
}

#[test]
fn a_legacy_keyset_cache_is_ignored_and_preserved() {
    use crate::root::keyset::{bind, KeysetSource};
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = ScratchDir::new("keyset-legacy-cache");
    let file = dir.path.join("deployment-keyset");
    std::fs::write(&file, b"unusable legacy keyset").unwrap();
    let mut first = dir_store_book(&slots, &dir.path, 91);
    assert_eq!(
        bind(&mut first, Some(&dir.path), &token(), StepName::Meter, 1),
        Ok(KeysetSource::Stored)
    );
    seal(&mut first, 1);
    let key_id = first.record.signing_key_id().unwrap().to_string();
    drained(&first);
    drop(first);
    let mut restarted = dir_store_book(&slots, &dir.path, 91);
    let next_seq = restarted.journal.next_seq();
    assert_eq!(
        bind(
            &mut restarted,
            Some(&dir.path),
            &token(),
            StepName::Meter,
            2
        ),
        Ok(KeysetSource::Stored)
    );
    assert_eq!(restarted.record.signing_key_id(), Some(key_id.as_str()));
    assert_eq!(
        restarted.journal.next_seq(),
        next_seq,
        "no replacement Bootstrap"
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"unusable legacy keyset");
    assert_eq!(dir.entries(), vec!["deployment-keyset"]);
    assert!(restarted.retained_audit_findings().is_empty());
}

#[test]
fn a_legacy_keyset_cache_never_repairs_corrupt_or_mismatched_store_state() {
    use crate::root::keyset::bind;
    use store_identity::KEYSET_SCHEMA;
    for bad_store in [
        b"broken-store".as_slice(),
        b"secret\xff".as_slice(),
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".as_slice(),
    ] {
        let slots = crate::root::store_double::RecordSlots::new();
        let dir = ScratchDir::new("keyset-store-refusal");
        let mut first = dir_store_book(&slots, &dir.path, 92);
        bind(&mut first, Some(&dir.path), &token(), StepName::Meter, 1).unwrap();
        let seed = stored_keyset(slots.calls().as_ref()).unwrap().unwrap();
        let file = dir.path.join("deployment-keyset");
        std::fs::write(&file, seed.as_bytes()).unwrap();
        drained(&first);
        drop(first);
        slots.put_row(KEYSET_SCHEMA, b"deployment", bad_store);
        let mut restarted = dir_store_book(&slots, &dir.path, 92);
        let next_seq = restarted.journal.next_seq();
        assert!(bind(
            &mut restarted,
            Some(&dir.path),
            &token(),
            StepName::Meter,
            2
        )
        .is_err());
        assert!(restarted.record.signing_key_id().is_none());
        assert_eq!(restarted.journal.next_seq(), next_seq);
        assert_eq!(std::fs::read(&file).unwrap(), seed.as_bytes());
        assert_eq!(
            wait_for(slots.calls().record_get(KEYSET_SCHEMA, b"deployment"))
                .unwrap()
                .unwrap()
                .as_slice(),
            bad_store
        );
    }
}

#[test]
fn an_unknown_keyset_commit_replays_its_exact_candidate() {
    use std::sync::{Arc, Mutex};
    let slots = crate::root::store_double::RecordSlots::new();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&attempts);
    slots.on_transaction(move |request| {
        seen.lock().unwrap().push(request.clone());
        None
    });
    slots.lose_acks(true);
    let seed = "d".repeat(64);
    assert_eq!(keep_keyset(slots.calls().as_ref(), &seed).unwrap(), seed);
    assert_eq!(slots.puts(), 1);
    let attempts = attempts.lock().unwrap();
    assert!(attempts.len() >= 2);
    assert!(attempts.iter().all(|request| request == &attempts[0]));
}

#[test]
fn racing_first_host_candidates_keep_one_stable_registry_pointer() {
    use busbar_contract::abi::sdk::store::conditional::Mutation;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    let slots = crate::root::store_double::RecordSlots::new();
    let (entered, waiting) = std::sync::mpsc::sync_channel(1);
    let (release, resumed) = std::sync::mpsc::sync_channel(1);
    let resumed = Arc::new(Mutex::new(resumed));
    let once = Arc::new(AtomicBool::new(true));
    slots.on_transaction(move |request| {
        if request.mutations.iter().any(|m| {
            matches!(m, Mutation::Put { schema, key, .. }
            if schema == store_identity::NODE_SCHEMA && key == b"host:host-r")
        }) && once.swap(false, Ordering::SeqCst)
        {
            entered.send(()).unwrap();
            resumed.lock().unwrap().recv().unwrap();
        }
        None
    });
    let delayed = {
        let slots = slots.clone();
        std::thread::spawn(move || node_id(slots.calls().as_ref(), "host-r"))
    };
    waiting
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let winner = node_id(slots.calls().as_ref(), "host-r").unwrap();
    release.send(()).unwrap();
    assert_eq!(delayed.join().unwrap().unwrap(), winner);
    assert_eq!(slots.rows_under(store_identity::NODE_SCHEMA), 1);
}

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

#[test]
fn a_saturated_registry_reads_the_late_peer_for_migration_and_verification() {
    let slots = crate::root::store_double::RecordSlots::new();
    let (own, late) = (7_u64, 8_u64);
    for index in 0..=65_536 {
        let node = if index == 65_536 { late } else { own };
        slots.put_row(
            store_identity::NODE_SCHEMA,
            format!("host:{index:05}").as_bytes(),
            &node.to_be_bytes(),
        );
    }
    let mut first = keyed_store_book(&slots, own);
    let mut peer = keyed_store_book(&slots, late);
    first
        .seal_unit(audit_inputs(1), audit_pass(), &token())
        .unwrap();
    peer.seal_unit(audit_inputs(1), audit_pass(), &token())
        .unwrap();
    drained(&first);
    drained(&peer);
    let migrated = store_identity::stored_chains(slots.calls().as_ref(), own).unwrap();
    assert!(migrated
        .iter()
        .any(|(node, records)| *node == late && !records.is_empty()));
    slots.corrupt(JOURNAL_SCHEMA, &part_key(late, 2, 0));
    let (lane, own, keys) = first.stored_walk_inputs().unwrap();
    let walk = walk_stored_chains(&lane, own, &keys);
    assert!(walk.chains.contains(&late));
    assert!(walk
        .findings
        .iter()
        .any(|why| why.starts_with(&format!("node {late}:"))));
}

#[test]
fn a_malformed_registry_row_cannot_make_stored_verification_report_complete() {
    use store_identity::NODE_SCHEMA;
    use tracing_subscriber::layer::SubscriberExt as _;
    let slots = crate::root::store_double::RecordSlots::new();
    let own = node_id(slots.calls().as_ref(), "registry-reader").unwrap();
    let other = node_id(slots.calls().as_ref(), "registry-other").unwrap();
    let healthy = node_id(slots.calls().as_ref(), "registry-healthy").unwrap();
    let mut book = keyed_store_book(&slots, own);
    book.seal_unit(audit_inputs(1), audit_pass(), &token())
        .unwrap();
    let mut other_book = keyed_store_book(&slots, other);
    other_book
        .seal_unit(audit_inputs(1), audit_pass(), &token())
        .unwrap();
    drained(&book);
    drained(&other_book);
    let (lane, node, keys) = book.stored_walk_inputs().unwrap();
    let clean = walk_stored_chains(&lane, node, &keys);
    assert!(clean.findings.is_empty());
    assert!(clean.chains.contains(&other));

    slots.put_row(NODE_SCHEMA, b"host:registry-other", b"private-invalid-id");
    slots.put_row(NODE_SCHEMA, b"host:\xff", &other.to_be_bytes());
    let broken = walk_stored_chains(&lane, node, &keys);
    assert!(
        broken.chains.contains(&own),
        "the own chain is still verified"
    );
    assert!(
        broken.chains.contains(&healthy),
        "other readable registry rows remain in the walk"
    );
    assert!(
        !broken.findings.is_empty(),
        "an omitted chain must be reported"
    );
    assert!(broken
        .findings
        .iter()
        .all(|why| !why.contains("private-invalid-id")));
    let captured = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let migrated = tracing::subscriber::with_default(
        tracing_subscriber::registry().with(captured.clone()),
        || store_identity::stored_chains(slots.calls().as_ref(), own),
    )
    .expect("migration retains its existing skip policy");
    assert!(migrated.iter().any(|(node, _)| *node == healthy));
    assert!(!migrated.iter().any(|(node, _)| *node == other));
    assert!(captured.contains("node registry"));
    assert!(!captured.contains("private-invalid-id"));
    assert!(
        node_id(slots.calls().as_ref(), "registry-new").is_ok(),
        "mint behavior is unchanged"
    );
}

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

#[test]
fn two_live_nodes_with_one_host_name_keep_separate_audit_records() {
    two_live_nodes_keep_their_own_records("host-same");
}

#[test]
fn two_live_nameless_nodes_keep_separate_audit_records() {
    two_live_nodes_keep_their_own_records("");
}

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

        std::mem::forget(durability);
        std::mem::forget(first.lease);
    }
    let again = take_node(slots.calls().as_ref(), "host-lapse").expect("an identity");
    assert_eq!(again.id, first.id, "the restart takes the host's id back");
    assert!(again.lease.is_some(), "under a lease of its own");
    let restarted = store_book(&slots, again.id);
    assert_eq!(restarted.audit_records.len(), 1, "the chain is resumed");

    again
        .lease
        .as_ref()
        .expect("held")
        .release(slots.calls().as_ref())
        .expect("released");
    let next = take_node(slots.calls().as_ref(), "host-lapse").expect("an identity");
    assert_eq!(next.id, first.id, "a released lease is taken at once");
}

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

#[test]
fn a_legacy_node_id_does_not_override_the_store_identity() {
    use store_identity::NODE_SCHEMA;
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = ScratchDir::new("node-id-legacy");
    let file = dir.path.join("node_id");
    std::fs::write(&file, b"00000000000000000000000000000063\n").unwrap();
    slots.put_row(NODE_SCHEMA, b"host:host-old", &77u64.to_be_bytes());
    let taken = take_node(slots.calls().as_ref(), "host-old").expect("Store identity");
    assert_eq!(taken.id, 77);
    let mut first = dir_store_book(&slots, &dir.path, taken.id);
    seal(&mut first, 1);
    drained(&first);
    drop(first);
    taken
        .lease
        .unwrap()
        .release(slots.calls().as_ref())
        .unwrap();
    let restarted_id = take_node(slots.calls().as_ref(), "host-old").unwrap();
    assert_eq!(restarted_id.id, 77);
    let restarted = dir_store_book(&slots, &dir.path, restarted_id.id);
    assert_eq!(restarted.audit_records.len(), 1);
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"00000000000000000000000000000063\n"
    );
    assert_eq!(dir.entries(), vec!["node_id"]);
}

#[test]
fn every_legacy_data_dir_shape_resumes_the_store_without_creating_files() {
    let dir = ScratchDir::new("store-only-paths");
    let blocked = dir.path.join("blocked");
    std::fs::write(&blocked, b"operator input").unwrap();
    let missing = dir.path.join("missing").join("nested");
    let before = dir.entries();
    for path in [dir.path.clone(), missing.clone(), blocked.join("unusable")] {
        let slots = crate::root::store_double::RecordSlots::new();
        let cfg = DurabilityConfig {
            data_dir: Some(path),
        };
        let mut first = boot(&slots, &cfg, 71).expect("Store boot ignores local paths");
        bind_keyset(&mut first, cfg.data_dir.as_deref().unwrap());
        let first_audit = first
            .seal_unit(audit_inputs(1), audit_pass(), &token())
            .unwrap();
        assert_eq!(first_audit.node, 71);
        drained(&first);
        let head = first.journal.head();
        let next = first.journal.next_seq();
        drop(first);
        let mut restarted = boot(&slots, &cfg, 71).unwrap();
        bind_keyset(&mut restarted, cfg.data_dir.as_deref().unwrap());
        assert!(!restarted.on_disk());
        assert!(restarted.keeps_chain() && restarted.durable_in_store());
        assert_eq!(restarted.journal.head(), head);
        assert_eq!(restarted.journal.next_seq(), next);
        assert_eq!(restarted.audit_records, vec![first_audit.clone()]);
        assert!(restarted.retained_audit_findings().is_empty());
        let second = restarted
            .seal_unit(audit_inputs(1), audit_pass(), &token())
            .unwrap();
        assert_eq!(second.prev_hash, first_audit.hash);
        assert_eq!(second.seq, first_audit.seq + 1);
        assert_eq!(second.what.incarnation, first_audit.what.incarnation + 1);
        drained(&restarted);
        assert_eq!(dir.entries(), before);
        assert!(!missing.exists());
        assert_eq!(std::fs::read(&blocked).unwrap(), b"operator input");
    }
}

struct PausedStore(crate::root::store_double::RecordSlots);

impl PausedStore {
    fn new(slots: &crate::root::store_double::RecordSlots) -> Self {
        slots.pause(true);
        Self(slots.clone())
    }

    fn wait_pending(&self) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while self.0.waiting() == 0 && std::time::Instant::now() < until {
            std::thread::yield_now();
        }
        assert!(self.0.waiting() > 0, "a real Store future reached Pending");
    }
}

impl Drop for PausedStore {
    fn drop(&mut self) {
        self.0.pause(false);
    }
}

#[test]
fn a_pending_store_read_never_boots_an_empty_local_journal() {
    let slots = crate::root::store_double::RecordSlots::new();
    {
        let mut first = store_book(&slots, 72);
        seal(&mut first, 1);
        drained(&first);
    }
    let paused = PausedStore::new(&slots);
    let (done, recv) = std::sync::mpsc::channel();
    let reader = {
        let slots = slots.clone();
        std::thread::spawn(move || {
            let result = store_book(&slots, 72);
            done.send(result.audit_records.len()).unwrap();
        })
    };
    paused.wait_pending();
    assert!(matches!(
        recv.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    drop(paused);
    assert_eq!(
        recv.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap(),
        1
    );
    reader.join().unwrap();
}

#[test]
fn pending_store_puts_keep_lane_and_journal_custody_and_fail_closed_at_the_bound() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut book = store_book_bounded(&slots, 73, 2);
    let paused = PausedStore::new(&slots);
    for i in 0..3 {
        let result = book.journal.append(
            &token(),
            StepName::Meter,
            &[Entry::new(RecordClass::Load, vec![i])],
        );
        assert_eq!(result.is_ok(), i < 2);
    }
    paused.wait_pending();
    assert_eq!(
        slots.rows_under(JOURNAL_SCHEMA),
        0,
        "Pending did not commit"
    );
    assert_eq!(book.lane().unwrap().pending(), 2);
    assert_eq!(book.journal.buffered(), 1);
    assert!(book.refuses_money().is_some());
    assert_eq!(book.journal.dropped_total(), 0);
    let held = book.chain_at();
    drop(paused);
    assert_eq!(
        held.read().unwrap().unwrap().len(),
        3,
        "every custody owner contributes to the chain"
    );
    drained(&book);
    assert_eq!(book.offer_held_back(), 0);
    drained(&book);
    assert!(book.refuses_money().is_none());
    drop(book);
    let restarted = store_book(&slots, 73);
    assert_eq!(restarted.chain().unwrap().unwrap().len(), 3);
    assert_eq!(restarted.journal.next_seq(), 4);
}

#[test]
fn an_unknown_store_commit_stays_queued_and_restart_resumes_the_committed_chain() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut first = store_book_bounded(&slots, 74, 1);
    slots.lose_acks(true);
    seal(&mut first, 1);
    let lane = first.lane().unwrap().clone();
    assert!(lane
        .wait_acked(
            74,
            first.journal.next_seq() - 1,
            std::time::Duration::from_secs(5)
        )
        .is_err());
    assert_eq!(lane.pending(), 1, "unknown commit keeps custody");
    assert!(first.refuses_money().is_some());
    let head = first.journal.head();

    let restarted = store_book(&slots, 74);
    assert_eq!(restarted.journal.head(), head);
    assert_eq!(restarted.audit_records.len(), 1);
    slots.lose_acks(false);
    drained(&first);
    assert!(first.refuses_money().is_none());
    assert_eq!(
        restarted.chain().unwrap().unwrap().len(),
        1,
        "retrying the same key cannot duplicate a record"
    );
}

#[test]
fn dropping_a_book_with_a_pending_put_keeps_the_accepted_batch_in_the_store_lane() {
    let slots = crate::root::store_double::RecordSlots::new();
    let mut book = store_book(&slots, 75);
    let paused = PausedStore::new(&slots);
    seal(&mut book, 1);
    let head = book.journal.head();
    paused.wait_pending();
    drop(book);
    drop(paused);
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while slots.rows_under(JOURNAL_SCHEMA) == 0 && std::time::Instant::now() < until {
        std::thread::yield_now();
    }

    let mut kept = read_chain(slots.calls().as_ref(), 75).unwrap();
    while kept.is_empty() && std::time::Instant::now() < until {
        std::thread::yield_now();
        kept = read_chain(slots.calls().as_ref(), 75).unwrap();
    }
    assert_eq!(kept.len(), 1);
    let restarted = store_book(&slots, 75);
    assert_eq!(restarted.journal.head(), head);
    assert_eq!(restarted.audit_records.len(), 1);
}
