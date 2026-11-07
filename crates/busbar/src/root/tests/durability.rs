// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::persistence::facade::CoreStore;
use busbar_kernel::persistence::journal::RuntimeError;
use busbar_kernel_audit::Recipe;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct Warnings(Arc<Mutex<Vec<String>>>);

impl Warnings {
    pub(super) fn messages(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    pub(super) fn contains(&self, text: &str) -> bool {
        self.messages().iter().any(|message| message.contains(text))
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() > tracing::Level::WARN {
            return;
        }
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

pub(crate) const BUDGET: BufferBudget = BufferBudget {
    records: 8192,
    bytes: 32 * 1024 * 1024,
};

pub(crate) struct NativeFixture {
    pub(crate) faults: Arc<crate::root::store_double::NativeFaults>,
    pub(crate) core: Arc<CoreStore>,
    pub(crate) journal: Arc<RuntimeJournal>,
}
impl NativeFixture {
    pub(crate) async fn new(node: u64) -> Self {
        let faults = crate::root::store_double::NativeFaults::open().await;
        let core = crate::root::real_store::core_over(faults.clone()).await;
        let journal = RuntimeJournal::open(core.clone(), node, BUDGET)
            .await
            .unwrap();
        Self {
            faults,
            core,
            journal,
        }
    }
    pub(crate) async fn book(&self) -> Durability {
        self.build(&DurabilityConfig::default()).await.unwrap()
    }
    pub(crate) async fn build(&self, cfg: &DurabilityConfig) -> Result<Durability, OpenError> {
        build_on_store(cfg, self.journal.node(), self.journal.clone(), None, BUDGET).await
    }
    pub(crate) async fn reopen(&self) -> Durability {
        let journal = RuntimeJournal::open(self.core.clone(), self.journal.node(), BUDGET)
            .await
            .unwrap();
        build_on_store(
            &DurabilityConfig::default(),
            journal.node(),
            journal,
            None,
            BUDGET,
        )
        .await
        .unwrap()
    }
    pub(crate) async fn corrupt_original(&self, ordinal: u64) {
        use busbar_contract::persistence::{Candidate, Decision, Mutation, PreparedCandidate};
        let records = self.journal.read_records(BUDGET).await.unwrap();
        let mut bytes = records[ordinal as usize - 1].encode();
        *bytes.last_mut().unwrap() ^= 1;
        let (mut id, address) = {
            let requests = self.faults.requests.lock().unwrap();
            requests
                .iter()
                .find_map(|request| {
                    request.candidate().mutations.iter().find_map(|mutation| {
                        let Mutation::Put { address, .. } = mutation else {
                            return None;
                        };
                        (address.key.get(24) == Some(&b'R')
                            && address.key.get(16..24)
                                == Some(self.journal.node().to_be_bytes().as_slice())
                            && address.key.get(25..) == Some(ordinal.to_be_bytes().as_slice()))
                        .then(|| (request.candidate().id, address.clone()))
                    })
                })
                .expect("journal commit contains the original address")
        };
        id.operation = busbar_kernel::door::op_id().0;
        let candidate = PreparedCandidate::new(Candidate {
            id,
            codec: 1,
            predicates: vec![],
            mutations: vec![Mutation::Put {
                address,
                value: busbar_contract::Secret::new(bytes),
            }],
            time: None,
            result: busbar_contract::Secret::new(vec![]),
        })
        .unwrap();
        assert!(matches!(
            self.faults.actual.commit(candidate).await.unwrap(),
            Decision::Applied(_)
        ));
    }
    pub(crate) async fn identity(&self) -> BootIdentity {
        BootIdentity::new(self.core.clone()).unwrap()
    }
}
pub(crate) fn token() -> Grant<DurableWrite> {
    crate::root::kernel::new_kernel().durability_token()
}
pub(crate) fn audit_pass() -> busbar_contract::caps::Pass<busbar_contract::caps::Audit> {
    busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel())
}
pub(crate) async fn seal(book: &Arc<Mutex<Durability>>, unit: u64) -> AuditRecord {
    Durability::seal_unit(book, audit_inputs(unit), audit_pass(), &token())
        .await
        .unwrap()
}
pub(crate) async fn bind(book: &mut Durability, fixture: &NativeFixture) {
    crate::root::keyset::bind(
        book,
        &fixture.identity().await,
        &token(),
        StepName::Meter,
        1_700_000_000,
    )
    .await
    .unwrap();
}
pub(crate) fn audit_inputs(unit: u64) -> AuditInputs {
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
        origin: crate::root::kernel::new_kernel().origin(OriginKind::Client),
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
            rate_card_version: Some([3; 20]),
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

#[tokio::test]
async fn legacy_data_dir_shapes_never_create_or_change_files() {
    let scratch = Scratch::new("native-no-files");
    let legacy = scratch.0.join("journal");
    std::fs::write(&legacy, b"historical bytes must remain untouched").unwrap();
    let fixture = NativeFixture::new(7).await;
    for path in [
        None,
        Some(scratch.0.clone()),
        Some(legacy.clone()),
        Some(legacy.join("unusable")),
    ] {
        let book = Arc::new(Mutex::new(
            fixture
                .build(&DurabilityConfig { data_dir: path })
                .await
                .unwrap(),
        ));
        seal(&book, 1).await;
        assert!(!book.lock().unwrap().on_disk());
        assert!(book.lock().unwrap().durable_in_store());
        assert_eq!(
            std::fs::read(&legacy).unwrap(),
            b"historical bytes must remain untouched"
        );
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn a_sealed_audit_record_goes_on_the_journal_whole() {
    let fixture = NativeFixture::new(4).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let sealed = seal(&book, 11).await;
    assert_eq!(sealed.what.incarnation, book.lock().unwrap().incarnation);
    assert_eq!(sealed.recipe, Recipe::V5);
    let records = fixture.journal.read_records(BUDGET).await.unwrap();
    let audits: Vec<_> = records
        .iter()
        .filter_map(|r| decode_audit(r).unwrap().map(|a| (r, a)))
        .collect();
    assert_eq!(audits.len(), 1);
    let (record, decoded) = &audits[0];
    assert_eq!(record.node, 4);
    assert_eq!(record.class, RecordClass::Transaction);
    assert_eq!((record.wall, record.mono), (sealed.wall, sealed.mono));
    assert_eq!(*decoded, sealed);
    assert_eq!(book.lock().unwrap().record.sealed(), 1);
    assert_eq!(book.lock().unwrap().audit_records, vec![sealed]);
}

#[tokio::test]
async fn two_boots_minting_same_unit_keep_distinct_verified_records() {
    let fixture = NativeFixture::new(7).await;
    let first = seal(&Arc::new(Mutex::new(fixture.book().await)), 1).await;
    let reopened = Arc::new(Mutex::new(fixture.reopen().await));
    let second = seal(&reopened, 1).await;
    assert_eq!(first.what.unit_key, second.what.unit_key);
    assert_ne!(first.what.incarnation, second.what.incarnation);
    assert_ne!(first.hash, second.hash);
    assert_eq!(second.prev_hash, first.hash);
    assert_eq!(second.seq, first.seq + 1);
    let reread = fixture.reopen().await;
    assert_eq!(
        reread.audit_window(1, u64::MAX).await.unwrap(),
        vec![first, second]
    );
    assert!(reread.retained_audit_findings().is_empty());
}

#[tokio::test]
async fn range_older_than_ring_is_read_back_after_restart() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let total = (AUDIT_RING + 5) as u64;
    for unit in 1..=total {
        seal(&book, unit).await;
    }
    assert_eq!(book.lock().unwrap().audit_records.len(), AUDIT_RING);
    let reopened = fixture.reopen().await;
    assert_eq!(reopened.audit_records.len(), AUDIT_RING);
    assert_eq!(reopened.audit_records[0].seq, 6);
    let old = reopened.audit_window(1, 3).await.unwrap();
    assert_eq!(old.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert!(AuditChain::verify_window(&old).is_ok());
    assert_eq!(
        reopened.audit_window(total, total).await.unwrap()[0].seq,
        total
    );
}

#[tokio::test]
async fn retained_tamper_and_unsigned_post_bootstrap_are_findings() {
    let fixture = NativeFixture::new(7).await;
    let mut initial = fixture.book().await;
    bind(&mut initial, &fixture).await;
    let book = Arc::new(Mutex::new(initial));
    for unit in 1..=3 {
        seal(&book, unit).await;
    }
    assert!(book.lock().unwrap().retained_audit_findings().is_empty());
    {
        let mut held = book.lock().unwrap();
        held.audit_records[1].usage.fee_count += 1;
        assert!(held
            .retained_audit_findings()
            .iter()
            .any(|f| f.contains("DigestMismatch")));
    }
    let mut reopened = fixture.reopen().await;
    bind(&mut reopened, &fixture).await;
    assert!(reopened.retained_audit_findings().is_empty());
    reopened.audit_records[0].signature = None;
    reopened.audit_records[0].key_id = None;
    assert_eq!(
        reopened.retained_audit_findings(),
        vec!["record 1 is unsigned, sealed after the keyset was bound"]
    );
}

#[tokio::test]
async fn records_before_bootstrap_remain_valid_and_signed_records_verify_after_restart() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal(&book, 1).await;
    let mut keyed = fixture.reopen().await;
    bind(&mut keyed, &fixture).await;
    let book = Arc::new(Mutex::new(keyed));
    let second = seal(&book, 2).await;
    assert!(second.key_id.is_some());
    let mut reopened = fixture.reopen().await;
    bind(&mut reopened, &fixture).await;
    assert!(reopened.retained_audit_findings().is_empty());
    reopened.audit_records[1].signature = None;
    reopened.audit_records[1].key_id = None;
    assert_eq!(
        reopened.retained_audit_findings(),
        vec!["record 2 is unsigned, sealed after the keyset was bound"]
    );
}

#[tokio::test]
async fn every_predecessor_idempotency_claim_is_voided_once_at_boot() {
    let fixture = NativeFixture::new(12).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    for (name, mono) in [("idem-a", 5), ("idem-b", 6)] {
        let claim = ClaimBalance {
            claim: name.into(),
            key: ClaimKey {
                bucket: "admin-idempotency".into(),
                dimension: (1, String::new()),
                scope: (1, "actor".into()),
            },
            window: u64::MAX,
        };
        Durability::journal_claim(
            &book,
            claim,
            ClaimStamp { wall: 1, mono },
            &token(),
            StepName::Route,
        )
        .await
        .unwrap();
    }
    let restarted = fixture.reopen().await;
    assert_eq!(restarted.voided_claims, vec!["idem-a", "idem-b"]);
    assert!(restarted.restart_findings.is_empty());
    assert!(fixture.reopen().await.voided_claims.is_empty());
}

#[tokio::test]
async fn pending_commit_retains_original_and_refuses_at_bound_without_dropping_records() {
    let fixture = NativeFixture::new(7).await;
    let lane = RuntimeJournal::open(
        fixture.core.clone(),
        7,
        BufferBudget {
            records: 1,
            bytes: 4096,
        },
    )
    .await
    .unwrap();
    let original = lane
        .stage_run(&[Entry::new(RecordClass::Load, vec![1; 64])])
        .unwrap();
    fixture.faults.pause(true);
    {
        let future = lane.confirm(&original);
        tokio::pin!(future);
        assert!(futures::poll!(&mut future).is_pending());
    }
    assert_eq!(lane.pending_records(), 1);
    let sequence = lane.next_seq();
    assert!(matches!(
        lane.stage_run(&[Entry::new(RecordClass::Load, vec![2])]),
        Err(RuntimeError::Budget)
    ));
    assert_eq!(lane.next_seq(), sequence);
    assert!(lane.refuses_money().is_some());
    fixture.faults.pause(false);
    lane.confirm(&original).await.unwrap();
    assert_eq!(lane.pending_records(), 0);
    let records = lane.read_records(BUDGET).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, vec![1; 64]);
}

#[tokio::test]
async fn lost_ack_keeps_exact_candidate_and_restart_resumes_committed_chain() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let (_, run) = book
        .lock()
        .unwrap()
        .stage_unit(audit_inputs(1), audit_pass(), &token())
        .unwrap();
    fixture.faults.clear_observations();
    fixture.faults.lose_acks.store(true, Ordering::Release);
    assert!(fixture.journal.confirm(&run).await.is_err());
    assert_eq!(fixture.journal.pending_records(), 1);
    fixture.faults.lose_acks.store(false, Ordering::Release);
    fixture.journal.confirm(&run).await.unwrap();
    {
        let sent = fixture.faults.requests.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].candidate().id, sent[1].candidate().id);
        assert_eq!(sent[0].fingerprint(), sent[1].fingerprint());
    }
    assert_eq!(fixture.reopen().await.audit_records.len(), 1);
}

#[tokio::test]
async fn pending_read_never_builds_an_empty_local_journal() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal(&book, 1).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    let parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (held, observed) = (gate.clone(), parked.clone());
    *fixture.faults.on_read.lock().unwrap() = Some(Arc::new(move |_| {
        let (held, observed) = (held.clone(), observed.clone());
        Box::pin(async move {
            observed.store(true, Ordering::Release);
            held.notified().await;
            Ok(())
        })
    }));
    let config = DurabilityConfig::default();
    let rebuilt = fixture.build(&config);
    tokio::pin!(rebuilt);
    assert!(futures::poll!(&mut rebuilt).is_pending());
    assert!(parked.load(Ordering::Acquire));
    *fixture.faults.on_read.lock().unwrap() = None;
    gate.notify_one();
    assert_eq!(rebuilt.await.unwrap().audit_records.len(), 1);
}

#[tokio::test]
async fn registered_peers_keep_separate_records_and_walk_checks_every_original() {
    let fixture = NativeFixture::new(7).await;
    let identity = Arc::new(fixture.identity().await);
    let first = identity.take_node("host-a").await.unwrap();
    let second = identity.take_node("host-b").await.unwrap();
    assert_ne!(first.id, second.id);
    assert_ne!(first.id, 0);
    assert_eq!(identity.take_node("host-a").await.unwrap().id, first.id);
    let first_fixture = NativeFixture {
        faults: fixture.faults.clone(),
        core: fixture.core.clone(),
        journal: RuntimeJournal::open(fixture.core.clone(), first.id, BUDGET)
            .await
            .unwrap(),
    };
    let second_fixture = NativeFixture {
        faults: fixture.faults.clone(),
        core: fixture.core.clone(),
        journal: RuntimeJournal::open(fixture.core.clone(), second.id, BUDGET)
            .await
            .unwrap(),
    };
    let mut first_book = first_fixture.book().await;
    bind(&mut first_book, &first_fixture).await;
    let first_book = Arc::new(Mutex::new(first_book));
    let mut second_book = second_fixture.book().await;
    bind(&mut second_book, &second_fixture).await;
    let second_book = Arc::new(Mutex::new(second_book));
    for unit in 1..=2 {
        seal(&first_book, unit).await;
    }
    for unit in 1..=5 {
        seal(&second_book, unit).await;
    }
    let mut resumed = first_fixture.reopen().await;
    bind(&mut resumed, &first_fixture).await;
    assert_eq!(resumed.audit_records.len(), 2);
    assert_eq!(second_fixture.reopen().await.audit_records.len(), 5);
    let (lane, own, keys, budget) = resumed.stored_walk_inputs();
    let walk = walk_stored_chains(&lane, own, &keys, budget).await;
    let mut both = vec![first.id, second.id];
    both.sort_unstable();
    assert_eq!(walk.chains, both);
    assert!(walk.findings.is_empty(), "{:?}", walk.findings);
    second_fixture.corrupt_original(2).await;
    let walk = walk_stored_chains(&lane, own, &keys, budget).await;
    assert!(
        walk.findings
            .iter()
            .any(|finding| finding.starts_with(&format!("node {}:", second.id))),
        "{:?}",
        walk.findings
    );
}

#[tokio::test]
async fn stored_walk_preserves_unsigned_prebootstrap_and_reports_unsigned_postbootstrap() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    seal(&book, 1).await;
    let mut keyed = fixture.reopen().await;
    bind(&mut keyed, &fixture).await;
    let book = Arc::new(Mutex::new(keyed));
    seal(&book, 2).await;
    let (lane, own, keys, budget) = book.lock().unwrap().stored_walk_inputs();
    assert!(walk_stored_chains(&lane, own, &keys, budget)
        .await
        .findings
        .is_empty());
    {
        let mut held = book.lock().unwrap();
        held.record = AuditChain::resume(&held.audit_records).sealing_as(7);
    }
    let unsigned = seal(&book, 3).await;
    assert!(unsigned.key_id.is_none() && unsigned.signature.is_none());
    let walk = walk_stored_chains(&lane, own, &keys, budget).await;
    assert_eq!(
        walk.findings,
        vec!["node 7: audit record 3 is unsigned, sealed after the keyset was bound"]
    );
}

#[tokio::test]
async fn unreadable_or_malformed_registry_cannot_report_complete_verification() {
    use busbar_kernel::persistence::boot_identity::{INSTANCE, NODE_SCHEMA};
    use busbar_kernel::persistence::scoped::{Outcome, ScopedStore};
    let fixture = NativeFixture::new(7).await;
    let book = fixture.book().await;
    let (lane, own, keys, budget) = book.stored_walk_inputs();
    fixture.faults.unreadable.store(true, Ordering::Release);
    assert!(!walk_stored_chains(&lane, own, &keys, budget)
        .await
        .findings
        .is_empty());
    fixture.faults.unreadable.store(false, Ordering::Release);
    let rows =
        ScopedStore::host_private(fixture.core.clone(), INSTANCE, [NODE_SCHEMA.into()]).unwrap();
    assert!(matches!(
        rows.put(
            NODE_SCHEMA,
            b"host:unreadable",
            busbar_contract::Secret::new(vec![0])
        )
        .await
        .unwrap(),
        Outcome::Applied
    ));
    let walk = walk_stored_chains(&lane, own, &keys, budget).await;
    assert!(
        walk.findings
            .iter()
            .any(|finding| finding.contains("node registry")),
        "{:?}",
        walk.findings
    );
}
