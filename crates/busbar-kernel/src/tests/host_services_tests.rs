// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::persistence::{
    facade::CoreStore,
    host_records::tests::{attach as native_attach, Backend as NativeBackend},
    scoped::{Outcome as RecordOutcome, ScopedStore},
};
use futures::FutureExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    future
        .now_or_never()
        .expect("the native in-memory fixture finishes in one poll")
}
trait TestAdmission {
    fn admit_sync(&self, instance: &str, facts: InstanceFacts) -> Result<(), AdmitRefused>;
}
impl TestAdmission for KernelServices {
    fn admit_sync(&self, instance: &str, facts: InstanceFacts) -> Result<(), AdmitRefused> {
        ready(self.admit(instance, facts))
    }
}

use super::*;

pub(crate) fn verdict_now(r: Ran) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => panic!("the answer pended"),
    }
}

fn recorder() -> (Arc<Mutex<Option<Stored>>>, Later) {
    let slot = Arc::new(Mutex::new(None));
    let mine = Arc::clone(&slot);
    (
        slot,
        Box::new(move |s| {
            *mine.lock().unwrap() = Some(s);
        }),
    )
}

#[test]
fn the_clock_reads_wall_time_and_a_monotonic_origin() {
    let s = KernelServices::new();
    let a = s.now();
    let b = s.now();
    assert!(a.wall_ns > 1_600_000_000_000_000_000);
    assert!(b.mono_ns >= a.mono_ns);
}

#[test]
fn random_fill_draws_fresh_bytes_every_call_and_refuses_outside_its_cap() {
    let s = KernelServices::new();
    let a = s.random_fill(32);
    let b = s.random_fill(32);
    assert_eq!((a.outcome, a.bytes.len()), (Outcome::Ready, 32));
    assert_eq!((b.outcome, b.bytes.len()), (Outcome::Ready, 32));
    assert!(a.spans.is_empty() && b.spans.is_empty());
    assert_ne!(a.bytes, b.bytes, "two fills are never equal");
    assert_ne!(a.bytes, [0; 32], "a fill is drawn");
    let top = s.random_fill(svc::MAX_RANDOM_FILL);
    assert_eq!(top.bytes.len() as u64, svc::MAX_RANDOM_FILL);
    for len in [0, svc::MAX_RANDOM_FILL + 1, u64::MAX] {
        let r = s.random_fill(len);
        assert_eq!((r.outcome, r.error), (Outcome::Refused, FILL_OUT_OF_RANGE));
        assert!(r.bytes.is_empty(), "len {len}");
    }
}

use std::sync::atomic::AtomicU64;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::kinds::RecordBytes;

use crate::host_records::{WRITE_DROPPED, WRITE_FAILED};
use crate::trust::reverify::Policy;
use crate::trust::section::{DeclaredPin, TrustEntry};

struct Inline;

impl Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
    fn run_async(&self, job: AsyncJob) {
        ready(job);
    }
}

struct FixedKey;

impl SignKey for FixedKey {
    fn sign(&self, domain: &str, data: &[u8]) -> Option<(String, Vec<u8>)> {
        Some(("K1".into(), [domain.as_bytes(), b":", data].concat()))
    }
}

const KIND: RecordSchemaId = RecordSchemaId::new("approval");

const SECTION_KEY: &str = "tools";

pub(crate) fn caller(instance: &str) -> Caller {
    Caller::for_test(Arc::from(instance), KindCode::Plane)
}

struct Rig {
    s: KernelServices,
    store: Arc<CoreStore>,
    backend: Arc<NativeBackend>,
    clock: Arc<AtomicU64>,
}

fn rig() -> Rig {
    let backend = Arc::new(NativeBackend::default());
    let now = crate::store::now();
    backend.now.store(now, Ordering::SeqCst);
    let store = Arc::new(ready(native_attach(Arc::clone(&backend))));
    let clock = Arc::new(AtomicU64::new(now * 1000));
    let c = Arc::clone(&clock);
    let s = KernelServices::new()
        .with_pool(Arc::new(Inline))
        .with_signer(Arc::new(FixedKey))
        .with_demotions(demotions(&store), SECTION_KEY)
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    assert!(s.attach_persistence(Arc::clone(&store)));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            record_collections: Vec::new(),
            conditional_record_kinds: Vec::new(),
            signing: Some(Signing {
                domain: "dom".into(),
                kid_prefix: "p-".into(),
            }),
            trust: vec![(
                "cp".into(),
                TrustEntry {
                    pin: Some(DeclaredPin {
                        mechanism: "fingerprint".into(),
                        root: false,
                        peer_key: false,
                        key: None,
                        fingerprint: Some("fp".into()),
                    }),
                    policy: Policy {
                        ttl_ms: 100,
                        recovery_backoff_ms: 0,
                    },
                    approved: Default::default(),
                },
            )],
            scope_kinds: vec!["group".into(), "item".into()],
            record_chains: Vec::new(),
            record_retentions: Vec::new(),
            ticket_prefix: None,
        },
    )
    .unwrap();
    Rig {
        s,
        store,
        backend,
        clock,
    }
}

fn demotions(store: &Arc<CoreStore>) -> Arc<DemotionRecord> {
    let demotions = DemotionRecord::default();
    demotions.set_store(Arc::clone(store)).unwrap();
    Arc::new(demotions)
}

fn run(f: impl FnOnce(Later) -> Ran) -> Stored {
    let (slot, later) = recorder();
    match f(later) {
        Ran::Now(s) => s,
        Ran::Later => slot.lock().unwrap().take().expect("the later was answered"),
    }
}

fn attach_backend(
    backend: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
) -> Arc<CoreStore> {
    Arc::new(
        ready(CoreStore::attach(
            backend,
            crate::persistence::facade::WriterAuthority {
                writer_epoch: 2,
                writer: [4; 16],
                execution_epoch: 3,
            },
            crate::persistence::facade::Limits {
                pending_operations: 4096,
                conflict_retries: 2,
                scan_items: 16,
                scan_bytes: 8192,
            },
        ))
        .unwrap(),
    )
}
fn native_store() -> Arc<CoreStore> {
    Arc::new(ready(native_attach(Arc::new(NativeBackend::default()))))
}
fn native_rows(store: &Arc<CoreStore>, instance: &str) -> ScopedStore {
    ScopedStore::authorized(Arc::clone(store), instance, [KIND.as_str().to_string()]).unwrap()
}
fn put(into: &Arc<CoreStore>, key: &str, value: &str) {
    let rows = native_rows(into, "inst");
    let outcome = if value.is_empty() {
        ready(rows.delete(KIND.as_str(), key.as_bytes()))
    } else {
        ready(rows.put(
            KIND.as_str(),
            key.as_bytes(),
            busbar_contract::Secret::new(value.as_bytes().to_vec()),
        ))
    };
    assert_eq!(outcome.unwrap(), RecordOutcome::Applied);
}
fn stored(store: &Arc<CoreStore>, instance: &str, key: &[u8]) -> Option<Vec<u8>> {
    ready(native_rows(store, instance).get(KIND.as_str(), key))
        .unwrap()
        .map(|value| value.expose(&crate::seal::lend()).clone())
}

#[test]
fn every_caller_scoped_service_refuses_an_instance_never_admitted() {
    let r = rig();
    let who = caller("stranger");
    let refused = |s: Stored| {
        assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
    };
    refused(run(|l| r.s.records_get(&who, "approval", b"k", l)));
    refused(run(|l| {
        r.s.records_list(
            &who,
            RecordsList {
                kind: "approval".into(),
                prefix: Vec::new(),
                after: None,
                limit: 0,
            },
            l,
        )
    }));
    refused(run(|l| r.s.records_claim(&who, "approval", b"k", 1000, l)));
    refused(r.s.sign(&who, b"x"));
    refused(run(|l| r.s.trust_sight(&who, "cp", "fp", l)));
    refused(r.s.trust_due(&who));
}

#[test]
fn a_record_kind_the_instance_did_not_declare_is_refused() {
    let r = rig();
    let s = run(|l| r.s.records_get(&caller("inst"), "other", b"k", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_KIND));
}

#[test]
fn records_get_reads_the_store_and_the_instances_own_queued_writes_first() {
    let r = rig();
    let me = caller("inst");
    put(&r.store, "k", "stored");
    let s = run(|l| r.s.records_get(&me, "approval", b"k", l));
    assert_eq!((s.value, s.bytes.as_slice()), (svc::FOUND, &b"stored"[..]));
    let seq =
        r.s.pending()
            .enqueue("inst", "approval", b"k", b"mine".to_vec());
    let s = run(|l| r.s.records_get(&me, "approval", b"k", l));
    assert_eq!(s.bytes, b"mine");
    r.s.pending().acked("inst", "approval", b"k", seq);
    assert_eq!(
        run(|l| r.s.records_get(&me, "approval", b"k", l)).bytes,
        b"stored"
    );
    assert_eq!(
        run(|l| r.s.records_get(&me, "approval", b"absent", l)).value,
        svc::ABSENT
    );
}

#[test]
fn records_list_merges_queued_writes_in_key_order_after_the_cursor() {
    let r = rig();
    let me = caller("inst");
    put(&r.store, "a1", "s");
    put(&r.store, "a2", "s");
    put(&r.store, "b1", "s");
    r.s.pending()
        .enqueue("inst", "approval", b"a2", b"r".to_vec());
    r.s.pending()
        .enqueue("inst", "approval", b"a3", b"q".to_vec());
    let list = |after: Option<&str>, limit| {
        run(|l| {
            r.s.records_list(
                &me,
                RecordsList {
                    kind: "approval".into(),
                    prefix: b"a".to_vec(),
                    after: after.map(|a| a.as_bytes().to_vec()),
                    limit,
                },
                l,
            )
        })
    };
    let s = list(None, 0);
    assert_eq!(s.bytes, b"a1sa2ra3q");
    assert_eq!(s.spans.len(), 3);
    assert_eq!((s.spans[1].key.offset, s.spans[1].value.offset), (3, 5));
    assert_eq!(list(Some("a1"), 0).bytes, b"a2ra3q");
    assert_eq!(list(None, 1).bytes, b"a1s");
}

#[test]
fn a_queued_tombstone_hides_the_stored_record_from_get_and_list() {
    let r = rig();
    let me = caller("inst");
    put(&r.store, "a", "stored");
    put(&r.store, "b", "");
    r.s.pending().enqueue("inst", "approval", b"a", Vec::new());
    let all = RecordsList {
        kind: "approval".into(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    for key in [&b"a"[..], &b"b"[..]] {
        let s = run(|l| r.s.records_get(&me, "approval", key, l));
        assert_eq!(s.value, svc::ABSENT, "{key:?}");
    }
    let s = run(|l| r.s.records_list(&me, all, l));
    assert!(s.bytes.is_empty() && s.spans.is_empty());
}

#[test]
fn a_claim_is_won_once_and_taken_after_until_it_lapses() {
    let r = rig();
    let me = caller("inst");
    let claim = |who: &Caller| run(|l| r.s.records_claim(who, "approval", b"nonce", 2_000, l));
    assert_eq!(claim(&me).value, svc::CLAIM_WON);
    assert_eq!(claim(&me).value, svc::CLAIM_TAKEN);

    r.s.admit_sync(
        "other",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    assert_eq!(claim(&caller("other")).value, svc::CLAIM_WON);
    r.clock.fetch_add(3_000, Ordering::SeqCst);
    let until = r.clock.load(Ordering::SeqCst) / 1_000;
    r.backend.now.store(until + 1, Ordering::SeqCst);
    assert_eq!(claim(&me).value, svc::CLAIM_WON);
}

#[test]
fn a_claim_spends_the_minted_digest_never_the_callers_key() {
    let t = claim_token("inst", "approval", b"nonce");
    assert_eq!(t.len(), 64);
    assert!(!t.contains("nonce"));
    assert_ne!(t, claim_token("other", "approval", b"nonce"));
    assert_ne!(t, claim_token("inst", "approvaln", b"once"));
}

#[test]
fn a_claim_with_no_time_to_live_or_an_expiry_past_the_clock_is_refused() {
    let r = rig();
    let me = caller("inst");
    let s = run(|l| r.s.records_claim(&me, "approval", b"k", 0, l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NO_TTL));
    let s = run(|l| r.s.records_claim(&me, "approval", b"k", u64::MAX, l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, EXPIRY_OVERFLOW));
}

#[test]
fn records_are_refused_on_a_host_with_no_store() {
    let s = KernelServices::new();
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    let a = run(|l| s.records_claim(&caller("inst"), "approval", b"k", 1, l));
    assert_eq!((a.outcome, a.error), (Outcome::Refused, NO_STORE));
}

#[test]
fn sign_signs_under_the_declared_domain_with_the_prefixed_key_id() {
    let r = rig();
    let s = r.s.sign(&caller("inst"), b"data");
    assert_eq!(s.outcome, Outcome::Ready);
    assert_eq!(s.bytes, b"p-K1dom:data");
    assert_eq!((s.spans[0].key.offset, s.spans[0].key.len), (0, 4));
    assert_eq!((s.spans[0].value.offset, s.spans[0].value.len), (4, 8));
}

#[test]
fn sign_is_refused_without_a_declared_domain_or_a_key() {
    let r = rig();
    r.s.admit_sync("plain", InstanceFacts::default()).unwrap();
    let s = r.s.sign(&caller("plain"), b"x");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NO_DOMAIN));
    let keyless = KernelServices::new();
    keyless
        .admit_sync(
            "inst",
            InstanceFacts {
                signing: Some(Signing {
                    domain: "d".into(),
                    kid_prefix: String::new(),
                }),
                ..InstanceFacts::default()
            },
        )
        .unwrap();
    let s = keyless.sign(&caller("inst"), b"x");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NO_KEY));
}

#[test]
fn trust_sight_judges_from_the_admitted_entries_and_writes_the_demotion() {
    let r = rig();
    let me = caller("inst");
    let sight = |h: &str| run(|l| r.s.trust_sight(&me, "cp", h, l));

    assert_eq!(sight("moved").value, svc::TRUST_NEW);
    assert!(ready(r.s.demotions.get().unwrap().record.list()).is_empty());
    assert_eq!(sight("fp").value, svc::TRUST_NEW);
    ready(r.s.trust_rule("inst/cp", crate::trust::book::Ruling::Approve)).unwrap();
    assert_eq!(sight("fp").value, svc::TRUST_SAME, "approved");
    assert_eq!(sight("moved").value, svc::TRUST_DRIFTED);
    let demoted = ready(r.s.demotions.get().unwrap().record.list());
    assert_eq!(demoted.len(), 1);
    assert_eq!(demoted[0].upstream, demotion_key("inst", "cp"));
    assert_eq!(sight("moved").value, svc::TRUST_QUARANTINED);
    assert_eq!(sight("fp").value, svc::TRUST_SAME);
    assert!(ready(r.s.demotions.get().unwrap().record.list()).is_empty());
    let s = run(|l| r.s.trust_sight(&me, "nobody", "fp", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_COUNTERPARTY));
}

#[test]
fn the_operators_trust_decisions_are_kept_and_replayed_at_a_restart() {
    use crate::trust::book::Ruling;
    let r = rig();
    let me = caller("inst");

    assert_eq!(r.s.trust_unreached(&me, "cp").value, svc::TRUST_NEW);
    ready(r.s.trust_rule("inst/cp", Ruling::Approve)).unwrap();
    assert_eq!(
        run(|l| r.s.trust_sight(&me, "cp", "moved", l)).value,
        svc::TRUST_DRIFTED
    );
    assert_eq!(r.s.trust_unreached(&me, "cp").value, svc::TRUST_QUARANTINED);
    let row = ready(r.s.trust_rule("inst/cp", Ruling::Approve)).unwrap();
    assert_eq!(row.approved.as_deref(), Some("moved"));
    assert!(
        ready(r.s.demotions.get().unwrap().record.list()).is_empty(),
        "the approval clears the demotion"
    );
    assert_eq!(r.s.trust_unreached(&me, "cp").value, svc::TRUST_SAME);
    let fresh = restarted(&r);
    fresh.admit_sync("inst", trusting(Some("fp"))).unwrap();
    assert_eq!(
        run(|l| fresh.trust_sight(&me, "cp", "moved", l)).value,
        svc::TRUST_SAME,
        "the kept approval, over the declared pin"
    );
    assert_eq!(
        ready(fresh.trust_rule("inst/nobody", Ruling::Revoke)),
        Err(TrustRefused::NoSuchKey)
    );
    let s = fresh.trust_unreached(&caller("nowhere"), "cp");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
}

#[test]
fn an_approval_outlives_a_restart_and_a_moved_counterparty_is_drift_not_a_first_sighting() {
    use crate::trust::book::Ruling;
    let r = rig();
    let me = caller("inst");
    assert_eq!(
        run(|l| r.s.trust_sight(&me, "cp", "c1", l)).value,
        svc::TRUST_NEW,
        "a first sighting"
    );
    let row = ready(r.s.trust_rule("inst/cp", Ruling::Approve)).unwrap();
    assert_eq!(row.approved.as_deref(), Some("c1"));
    let fresh = restarted(&r);
    fresh.admit_sync("inst", trusting(Some("fp"))).unwrap();
    assert_eq!(
        run(|l| fresh.trust_sight(&me, "cp", "c2", l)).value,
        svc::TRUST_DRIFTED,
        "the moved document is judged against the kept approval"
    );
    assert_eq!(
        fresh.trust_unreached(&me, "cp").value,
        svc::TRUST_QUARANTINED,
        "and held out of service until the operator rules"
    );
}

#[test]
fn trust_decide_is_the_one_decide_path_for_a_planes_own_verb() {
    use busbar_contract::services::TrustKeyRef;
    let r = rig();
    let me = caller("inst");
    let ticket = busbar_contract::abi::mechanism::ticket::Ticket {
        slot: 9,
        generation: 1,
    };
    let _grant =
        r.s.grant_trust_decision(&me, ticket, "cp")
            .expect("gated admin grant");
    let tool = TrustKeyRef {
        counterparty: "cp",
        item: Some("t"),
    };
    let serves = |item| r.s.trust_serves(&me, "cp", Some(item), None).value;
    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, tool, Some("d1"), true, later)).value,
        svc::UNDECIDED_UNPINNED,
        "nothing sighted yet"
    );
    assert_eq!(
        run(|later| r.s.trust_sight_item(&me, "cp", "t", "d1", later)).value,
        svc::TRUST_NEW
    );
    assert_eq!(serves("t"), svc::DISTRUST_NOT_APPROVED);
    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, tool, Some("d0"), true, later)).value,
        svc::UNDECIDED_STALE,
        "approve what you saw"
    );

    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, tool, Some("d1"), true, later)).value,
        svc::TRUST_DECIDED_PENDING
    );
    assert_eq!(
        serves("t"),
        svc::DISTRUST_NOT_APPROVED,
        "the counterparty is pending"
    );
    let whole = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    run(|l| r.s.trust_sight(&me, "cp", "fp", l));
    assert_eq!(
        run(|later| r
            .s
            .trust_decide(&me, ticket, whole, Some("fp"), true, later))
        .value,
        svc::TRUST_DECIDED_SERVING
    );
    assert_eq!(serves("t"), svc::DISTRUST_NONE, "approved, it serves");
    assert_eq!(
        run(|later| r.s.trust_sight_item(&me, "cp", "t", "d2", later)).value,
        svc::TRUST_DRIFTED
    );
    assert_eq!(
        serves("t"),
        svc::DISTRUST_CHANGED,
        "a changed sighting refuses"
    );
    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, tool, None, true, later)).value,
        svc::TRUST_DECIDED_SERVING,
        "re-approved at its current sighting"
    );
    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, tool, None, false, later)).value,
        svc::TRUST_DECIDED_PENDING
    );
    assert_eq!(
        serves("t"),
        svc::DISTRUST_NOT_APPROVED,
        "revoked, it is refused"
    );

    run(|l| r.s.trust_sight(&me, "cp", "moved", l));
    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, tool, None, false, later)).value,
        svc::TRUST_DECIDED_QUARANTINED
    );
    assert_eq!(
        run(|later| r
            .s
            .trust_decide(&me, ticket, whole, Some("moved"), true, later))
        .value,
        svc::TRUST_DECIDED_SERVING
    );
    let stranger = TrustKeyRef {
        counterparty: "nobody",
        item: None,
    };
    assert_eq!(
        run(|later| r.s.trust_decide(&me, ticket, stranger, None, true, later)).outcome,
        Outcome::Refused
    );
    let s = run(|later| {
        r.s.trust_decide(&caller("nowhere"), ticket, whole, None, true, later)
    });
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
}

#[test]
fn trust_state_answers_the_counterparty_and_its_items_as_the_admin_list_does() {
    use crate::trust::book::Ruling;
    let r = rig();
    let me = caller("inst");

    assert_eq!(
        r.s.trust_state(&me, "cp").value,
        svc::KEY_NEW,
        "declared pin"
    );
    run(|l| r.s.trust_sight(&me, "cp", "fp", l));
    assert_eq!(r.s.trust_state(&me, "cp").value, svc::KEY_NEW, "sighted");
    ready(r.s.trust_rule("inst/cp", Ruling::Approve)).unwrap();
    assert_eq!(
        run(|later| r.s.trust_sight_item(&me, "cp", "t", "d1", later)).value,
        svc::TRUST_NEW
    );
    ready(r.s.trust_rule("inst/cp/t", Ruling::Approve)).unwrap();
    assert_eq!(
        run(|later| r.s.trust_sight_item(&me, "cp", "u", "e1", later)).value,
        svc::TRUST_NEW
    );
    let state = r.s.trust_state(&me, "cp");
    assert_eq!(state.value, svc::KEY_SAME);
    let items: Vec<(String, String)> = state
        .spans
        .iter()
        .map(|s| {
            let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                String::from_utf8(
                    state.bytes[sp.offset as usize..(sp.offset + sp.len) as usize].to_vec(),
                )
                .unwrap()
            };
            (at(s.key), at(s.value))
        })
        .collect();
    assert_eq!(
        items,
        vec![
            ("t".to_string(), "same\0d1\0d1".to_string()),
            ("u".to_string(), "new\0\0e1".to_string()),
        ]
    );
    let s = r.s.trust_state(&me, "nobody");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_COUNTERPARTY));
    let s = r.s.trust_state(&caller("nowhere"), "cp");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
}

#[test]
fn a_durable_demotion_is_replayed_at_admit() {
    let r = rig();
    let me = caller("inst");
    ready(r.s.trust_rule("inst/cp", crate::trust::book::Ruling::Approve)).unwrap();
    assert_eq!(
        run(|l| r.s.trust_sight(&me, "cp", "moved", l)).value,
        svc::TRUST_DRIFTED
    );

    let fresh = restarted(&r);
    fresh
        .admit_sync(
            "inst",
            InstanceFacts {
                trust: vec![(
                    "cp".into(),
                    TrustEntry {
                        pin: None,
                        policy: Policy {
                            ttl_ms: 0,
                            recovery_backoff_ms: 0,
                        },
                        approved: Default::default(),
                    },
                )],
                ..InstanceFacts::default()
            },
        )
        .unwrap();
    assert_eq!(
        run(|l| fresh.trust_sight(&me, "cp", "anything", l)).value,
        svc::TRUST_QUARANTINED
    );
}

#[test]
fn trust_due_answers_no_counterparty_as_the_clock_moves() {
    let r = rig();
    let me = caller("inst");
    assert!(r.s.trust_due(&me).spans.is_empty());
    r.clock.fetch_add(1_000_000, Ordering::SeqCst);
    let s = r.s.trust_due(&me);
    assert_eq!(s.outcome, Outcome::Ready);
    assert!(s.spans.is_empty() && s.bytes.is_empty());
}

#[test]
fn two_instances_of_one_plugin_have_distinct_registries() {
    let r = rig();

    r.s.admit_sync(
        "second",
        InstanceFacts {
            record_kinds: vec![RecordSchemaId::new("other")],
            conditional_record_kinds: Vec::new(),
            signing: Some(Signing {
                domain: "dom2".into(),
                kid_prefix: "q-".into(),
            }),
            trust: Vec::new(),
            scope_kinds: Vec::new(),
            record_chains: Vec::new(),
            record_collections: Vec::new(),
            record_retentions: Vec::new(),
            ticket_prefix: None,
        },
    )
    .unwrap();
    let (first, second) = (caller("inst"), caller("second"));
    assert_eq!(first.kind(), second.kind());
    assert!(!first.same_incarnation(&second));
    let s = run(|l| r.s.records_get(&second, "approval", b"k", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_KIND));
    assert_eq!(r.s.sign(&second, b"x").bytes, b"q-K1dom2:x");

    assert_eq!(r.s.sign(&first, b"x").bytes, b"p-K1dom:x");
    let s = run(|l| r.s.records_get(&first, "approval", b"k", l));
    assert_eq!((s.outcome, s.value), (Outcome::Ready, svc::ABSENT));
    let s = run(|l| r.s.trust_sight(&second, "cp", "fp", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_COUNTERPARTY));

    r.s.admit_sync(
        "third",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    r.s.pending()
        .enqueue("inst", "approval", b"k", b"mine".to_vec());
    let s = run(|l| r.s.records_get(&caller("third"), "approval", b"k", l));
    assert_eq!(s.value, svc::ABSENT);
}

#[test]
fn an_items_drift_demotion_outlives_a_restart() {
    use crate::trust::book::Ruling;
    let r = rig();
    let me = caller("inst");
    run(|l| r.s.trust_sight(&me, "cp", "fp", l));
    ready(r.s.trust_rule("inst/cp", Ruling::Approve)).unwrap();
    run(|later| r.s.trust_sight_item(&me, "cp", "t", "d1", later));
    ready(r.s.trust_rule("inst/cp/t", Ruling::Approve)).unwrap();
    let serves = |s: &KernelServices| s.trust_serves(&me, "cp", Some("t"), None).value;
    assert_eq!(serves(&r.s), svc::DISTRUST_NONE);
    run(|later| r.s.trust_sight_item(&me, "cp", "t", "d2", later));
    assert_eq!(serves(&r.s), svc::DISTRUST_CHANGED);
    let fresh = restarted(&r);
    fresh.admit_sync("inst", trusting(Some("fp"))).unwrap();
    run(|l| fresh.trust_sight(&me, "cp", "fp", l));
    run(|later| fresh.trust_sight_item(&me, "cp", "t", "d1", later));
    assert_ne!(
        serves(&fresh),
        svc::DISTRUST_NONE,
        "reverted after a restart, it stays refused"
    );
    ready(fresh.trust_rule("inst/cp/t", Ruling::Approve)).unwrap();
    assert_eq!(serves(&fresh), svc::DISTRUST_NONE, "re-approved");
}

fn restarted(r: &Rig) -> KernelServices {
    let demotions = r.s.demotions.get().unwrap();
    let host = KernelServices::new()
        .with_demotions(Arc::clone(&demotions.record), &demotions.default_instance)
        .with_pool(Arc::new(Inline));
    assert!(host.attach_persistence(Arc::clone(&r.store)));
    host
}

fn trusting(pin: Option<&str>) -> InstanceFacts {
    InstanceFacts {
        trust: vec![(
            "cp".into(),
            TrustEntry {
                pin: pin.map(|fp| DeclaredPin {
                    mechanism: "fingerprint".into(),
                    root: false,
                    peer_key: false,
                    key: None,
                    fingerprint: Some(fp.into()),
                }),
                policy: Policy {
                    ttl_ms: 0,
                    recovery_backoff_ms: 0,
                },
                approved: Default::default(),
            },
        )],
        ..InstanceFacts::default()
    }
}

#[test]
fn a_demotion_in_one_instance_is_never_replayed_into_another_with_the_same_counterparty() {
    let r = rig();
    ready(r.s.trust_rule("inst/cp", crate::trust::book::Ruling::Approve)).unwrap();
    assert_eq!(
        run(|l| r.s.trust_sight(&caller("inst"), "cp", "moved", l)).value,
        svc::TRUST_DRIFTED
    );
    let fresh = restarted(&r);
    fresh.admit_sync("inst", trusting(None)).unwrap();
    fresh.admit_sync("second", trusting(None)).unwrap();
    assert_eq!(
        run(|l| fresh.trust_sight(&caller("inst"), "cp", "x", l)).value,
        svc::TRUST_QUARANTINED
    );
    assert_eq!(
        run(|l| fresh.trust_sight(&caller("second"), "cp", "x", l)).value,
        svc::TRUST_NEW
    );
}

#[test]
fn an_unprefixed_row_replays_into_the_default_instance_only_and_it_clears_it() {
    let r = rig();
    ready(
        r.s.demotions
            .get()
            .unwrap()
            .record
            .record("cp", "quarantined", 1),
    )
    .unwrap();
    let fresh = restarted(&r);
    fresh.admit_sync(SECTION_KEY, trusting(None)).unwrap();
    fresh.admit_sync("inst", trusting(None)).unwrap();
    assert_eq!(
        run(|l| fresh.trust_sight(&caller(SECTION_KEY), "cp", "x", l)).value,
        svc::TRUST_QUARANTINED
    );
    assert_eq!(
        run(|l| fresh.trust_sight(&caller("inst"), "cp", "x", l)).value,
        svc::TRUST_NEW
    );

    let pinned = restarted(&r);
    pinned
        .admit_sync(SECTION_KEY, trusting(Some("fp")))
        .unwrap();

    assert_eq!(
        run(|l| pinned.trust_sight(&caller(SECTION_KEY), "cp", "fp", l)).value,
        svc::TRUST_NEW
    );
    assert!(ready(r.s.demotions.get().unwrap().record.list()).is_empty());
}

#[test]
fn another_instance_declaring_the_same_kind_never_reaches_the_records_of_this_one() {
    let r = rig();
    put(&r.store, "k", "mine");
    let declares = || InstanceFacts {
        record_kinds: vec![KIND],
        ..InstanceFacts::default()
    };
    r.s.admit_sync("other", declares()).unwrap();
    r.s.admit_sync("elsewhere", declares()).unwrap();

    let elsewhere = Caller::for_test(
        (caller("elsewhere")).namespace().clone(),
        (caller("elsewhere")).kind(),
    );
    let everything = RecordsList {
        kind: "approval".into(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    for who in [caller("other"), elsewhere] {
        let s = run(|l| r.s.records_get(&who, "approval", b"k", l));
        assert_eq!((s.outcome, s.value), (Outcome::Ready, svc::ABSENT));
        assert!(run(|l| r.s.records_list(&who, everything.clone(), l))
            .spans
            .is_empty());
        let won = run(|l| r.s.records_claim(&who, "approval", b"k", 1_000, l));
        assert_eq!(won.value, svc::CLAIM_WON);
    }

    let me = caller("inst");
    let won = run(|l| r.s.records_claim(&me, "approval", b"k", 1_000, l));
    assert_eq!(won.value, svc::CLAIM_WON);
    assert_eq!(
        run(|l| r.s.records_get(&me, "approval", b"k", l)).bytes,
        b"mine"
    );
    assert_eq!(
        run(|l| r.s.records_list(&me, everything.clone(), l)).bytes,
        b"kmine"
    );
}

/// Record reads that hold each call a while and count how many run at once.
#[derive(Default)]
struct Gauge {
    now: AtomicUsize,
    most: AtomicUsize,
    backend: NativeBackend,
}

impl busbar_contract::persistence::PersistenceBackend for Gauge {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.backend.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        Box::pin(async move {
            let data = request.addresses.iter().any(|address| {
                address.namespace != busbar_contract::persistence::control::NAMESPACE.0
            });
            if data {
                let running = self.now.fetch_add(1, Ordering::SeqCst) + 1;
                self.most.fetch_max(running, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                self.now.fetch_sub(1, Ordering::SeqCst);
            }
            self.backend.read(request).await
        })
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.backend.scan(request)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        self.backend.commit(candidate)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.backend.clock(dataset)
    }
}

fn noop() -> Acked {
    Box::new(|_| {})
}

fn pooled(
    rt: &tokio::runtime::Runtime,
    backend: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
) -> KernelServices {
    let host =
        KernelServices::new().with_pool(Arc::new(BlockingPool::new(rt.handle().clone(), 64)));
    assert!(host.attach_persistence(attach_backend(backend)));
    host.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    host
}

#[test]
fn a_burst_of_reads_never_runs_on_more_threads_than_the_pool_bound() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(2)
        .build()
        .unwrap();
    let gauge = Arc::new(Gauge::default());
    let s = pooled(&rt, gauge.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..40 {
        let tx = tx.clone();
        let ran = s.records_get(
            &caller("inst"),
            "approval",
            b"k",
            Box::new(move |a| tx.send(a.value).unwrap()),
        );
        assert!(matches!(ran, Ran::Later));
    }
    for _ in 0..40 {
        let answered = rx.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(answered, Ok(svc::ABSENT));
    }
    assert!(gauge.most.load(Ordering::SeqCst) <= 2);
}

#[test]
fn a_store_call_the_pool_refuses_answers_failed_and_never_runs_inline() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let gauge = Arc::new(Gauge::default());
    let s = pooled(&rt, gauge.clone());
    rt.shutdown_background();
    let (tx, rx) = std::sync::mpsc::channel();
    let ran = s.records_get(
        &caller("inst"),
        "approval",
        b"k",
        Box::new(move |answer| tx.send(answer).unwrap()),
    );
    assert!(matches!(ran, Ran::Later));
    let answered = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    assert_eq!(
        (answered.outcome, answered.error),
        (Outcome::Failed, POOL_REFUSED)
    );
    assert_eq!(gauge.most.load(Ordering::SeqCst), 0);
}

/// Holds every job until the test runs it.
#[derive(Default)]
struct Held(Mutex<Vec<Box<dyn FnOnce() + Send>>>);

impl Held {
    fn drain(&self) -> usize {
        let jobs = std::mem::take(&mut *self.0.lock().unwrap());
        let n = jobs.len();
        jobs.into_iter().for_each(|job| job());
        n
    }
}

impl Offload for Arc<Held> {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        self.0.lock().unwrap().push(job);
    }
    fn run_async(&self, job: AsyncJob) {
        self.run(Box::new(move || ready(job)));
    }
}

#[test]
fn a_demotion_is_written_on_the_pool_and_the_sighting_answers_after_it() {
    let r = rig();
    let held = Arc::new(Held::default());
    let s = restarted(&r).with_pool(Arc::new(Arc::clone(&held)));
    s.admit_sync("inst", trusting(Some("fp"))).unwrap();
    ready(s.trust_rule("inst/cp", crate::trust::book::Ruling::Approve)).unwrap();
    let (slot, later) = recorder();
    let ran = s.trust_sight(&caller("inst"), "cp", "moved", later);

    assert!(matches!(ran, Ran::Later));
    assert!(slot.lock().unwrap().is_none());
    assert!(ready(r.s.demotions.get().unwrap().record.list()).is_empty());
    assert_eq!(held.drain(), 1);
    assert_eq!(
        slot.lock().unwrap().take().unwrap().value,
        svc::TRUST_DRIFTED
    );
    assert_eq!(ready(r.s.demotions.get().unwrap().record.list()).len(), 1);

    let s2 = run(|l| s.trust_sight(&caller("inst"), "cp", "moved", l));
    assert_eq!(s2.value, svc::TRUST_QUARANTINED);
    assert_eq!(held.drain(), 0);
}

#[test]
fn a_durable_record_with_no_pool_judges_nothing() {
    let r = rig();
    let d = r.s.demotions.get().unwrap();
    let s = KernelServices::new().with_demotions(Arc::clone(&d.record), SECTION_KEY);
    s.admit_sync("inst", trusting(Some("fp"))).unwrap();
    let a = run(|l| s.trust_sight(&caller("inst"), "cp", "moved", l));
    assert_eq!((a.outcome, a.error), (Outcome::Refused, NO_POOL));
}

#[test]
fn an_instance_declaring_a_signing_domain_another_holds_is_refused() {
    let r = rig();
    let taker = InstanceFacts {
        signing: Some(Signing {
            domain: "dom".into(),
            kid_prefix: "x-".into(),
        }),
        ..InstanceFacts::default()
    };
    let refused = r.s.admit_sync("taker", taker.clone()).unwrap_err();
    assert_eq!(
        refused,
        AdmitRefused::DomainHeld {
            domain: "dom".into(),
            held_by: "inst".into(),
            asked_by: "taker".into(),
        }
    );
    let said = refused.to_string();
    assert!(said.contains("`inst`") && said.contains("`taker`"));

    let s = r.s.sign(&caller("taker"), b"x");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));

    r.s.admit_sync(
        "inst",
        InstanceFacts {
            signing: taker.signing,
            ..InstanceFacts::default()
        },
    )
    .unwrap();
}

#[test]
fn a_burst_of_writes_is_one_batch_and_the_writer_reads_it_at_once() {
    let r = rig();
    let held = Arc::new(Held::default());
    let s = writer(&r.store, Arc::new(Arc::clone(&held)));
    let declares = || InstanceFacts {
        record_kinds: vec![KIND],
        ..InstanceFacts::default()
    };
    s.admit_sync("inst", declares()).unwrap();
    s.admit_sync("other", declares()).unwrap();
    let me = caller("inst");
    let bytes = |v: String| RecordBytes::new(v.into_bytes()).unwrap();
    for i in 0..50 {
        let key = format!("k{i:02}");
        s.record_write(
            &me,
            "approval",
            key.as_bytes(),
            bytes(format!("v{i}")),
            noop(),
        )
        .unwrap();
    }

    assert_eq!(
        run(|l| s.records_get(&me, "approval", b"k07", l)).bytes,
        b"v7"
    );
    let stored = |who: &str, key: &[u8]| stored(&r.store, who, key);
    assert_eq!(stored("inst", b"k07"), None);

    s.record_write(
        &caller("other"),
        "approval",
        b"k07",
        bytes("theirs".into()),
        noop(),
    )
    .unwrap();

    assert_eq!(held.drain(), 1);
    assert_eq!(s.pending().queued(), 0);
    assert_eq!(stored("inst", b"k07"), Some(b"v7".to_vec()));
    assert_eq!(stored("inst", b"k49"), Some(b"v49".to_vec()));
    assert_eq!(stored("other", b"k07"), Some(b"theirs".to_vec()));

    s.record_write(&me, "approval", b"k50", bytes("v50".into()), noop())
        .unwrap();
    assert_eq!(held.drain(), 1);
    assert_eq!(stored("inst", b"k50"), Some(b"v50".to_vec()));
}

#[test]
fn a_flush_the_pool_refuses_leaves_the_writes_readable_and_queued_for_the_next() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let store = native_store();
    let s = KernelServices::new().with_pool(Arc::new(BlockingPool::new(rt.handle().clone(), 64)));
    assert!(s.attach_persistence(store));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    rt.shutdown_background();
    let me = caller("inst");
    let v = RecordBytes::new(b"v".to_vec()).unwrap();
    s.record_write(&me, "approval", b"k", v.clone(), noop())
        .unwrap();
    assert_eq!(run(|l| s.records_get(&me, "approval", b"k", l)).bytes, b"v");

    s.record_write(&me, "approval", b"k2", v, noop()).unwrap();
    assert_eq!(s.pending().queued(), 2);
}

#[test]
fn a_row_without_a_label_is_read_back_under_the_section_key_instance_and_no_other() {
    let r = rig();

    let d = r.s.demotions.get().unwrap();
    ready(d.record.record("cp", "quarantined", 1)).unwrap();
    let fresh = restarted(&r);
    for label in [SECTION_KEY, "inst", "tools-2"] {
        fresh.admit_sync(label, trusting(None)).unwrap();
    }
    let sight = |label: &str| run(|l| fresh.trust_sight(&caller(label), "cp", "x", l)).value;
    assert_eq!(sight(SECTION_KEY), svc::TRUST_QUARANTINED);
    assert_eq!(sight("inst"), svc::TRUST_NEW);
    assert_eq!(sight("tools-2"), svc::TRUST_NEW);
}

#[test]
fn a_label_too_long_or_holding_a_control_character_is_refused_at_admit() {
    let r = rig();
    for label in [
        "a\u{1f}b".to_string(),
        "x\ny".to_string(),
        "l".repeat(65_536),
    ] {
        let refused =
            r.s.admit_sync(&label, InstanceFacts::default())
                .unwrap_err();
        assert_eq!(refused, AdmitRefused::LabelUnfit { len: label.len() });
        let s = r.s.sign(&caller(&label), b"x");
        assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
    }
    r.s.admit_sync(&"l".repeat(65_535), InstanceFacts::default())
        .unwrap();
}

/// Record reads that hold every call until the test opens the gate.
#[derive(Default)]
struct GateState {
    open: bool,
    wakers: Vec<std::task::Waker>,
}
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    backend: NativeBackend,
}
impl Gate {
    fn open(&self) {
        let wakers = {
            let mut state = self.state.lock().unwrap();
            state.open = true;
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}
impl busbar_contract::persistence::PersistenceBackend for Gate {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.backend.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        Box::pin(async move {
            if request.addresses.iter().any(|address| {
                address.namespace != busbar_contract::persistence::control::NAMESPACE.0
            }) {
                std::future::poll_fn(|context| {
                    let mut state = self.state.lock().unwrap();
                    if state.open {
                        std::task::Poll::Ready(())
                    } else {
                        state.wakers.push(context.waker().clone());
                        std::task::Poll::Pending
                    }
                })
                .await;
            }
            self.backend.read(request).await
        })
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.backend.scan(request)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        self.backend.commit(candidate)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.backend.clock(dataset)
    }
}

#[test]
fn a_call_past_the_pools_bound_answers_failed_at_once() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let gate = Arc::new(Gate::default());
    let s = KernelServices::new().with_pool(Arc::new(BlockingPool::new(rt.handle().clone(), 2)));
    assert!(s.attach_persistence(attach_backend(gate.clone())));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..5 {
        let tx = tx.clone();
        let ran = s.records_get(
            &caller("inst"),
            "approval",
            b"k",
            Box::new(move |a| tx.send((a.outcome, a.error)).unwrap()),
        );
        assert!(matches!(ran, Ran::Later));
    }

    for _ in 0..3 {
        let a = rx.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(a, Ok((Outcome::Failed, POOL_REFUSED)));
    }
    gate.open();
    for _ in 0..2 {
        let a = rx.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(a, Ok((Outcome::Ready, "")));
    }
}

struct Refusing {
    backend: NativeBackend,
}
impl busbar_contract::persistence::PersistenceBackend for Refusing {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.backend.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.backend.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.backend.scan(request)
    }
    fn commit(
        &self,
        _candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        Box::pin(async { Err(busbar_contract::persistence::Failure::Refused) })
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.backend.clock(dataset)
    }
}

type Answers = Arc<Mutex<Vec<Result<(), &'static str>>>>;

fn answers() -> (Answers, impl Fn() -> Acked) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = Arc::clone(&got);
    (got, move || {
        let g = Arc::clone(&g);
        Box::new(move |r| g.lock().unwrap().push(r)) as Acked
    })
}

#[test]
fn a_write_is_answered_only_once_the_store_took_it() {
    let r = rig();
    let held = Arc::new(Held::default());
    let s = writer(&r.store, Arc::new(Arc::clone(&held)));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    let (got, acked) = answers();
    let v = RecordBytes::new(b"v".to_vec()).unwrap();
    s.record_write(&caller("inst"), "approval", b"k", v, acked())
        .unwrap();

    assert!(got.lock().unwrap().is_empty());
    assert_eq!(held.drain(), 1);
    assert_eq!(*got.lock().unwrap(), vec![Ok(())]);
    let stored = stored(&r.store, "inst", b"k");
    assert!(stored.is_some());
}

#[test]
fn a_write_the_store_refuses_answers_failed_and_leaves_the_overlay() {
    let store = attach_backend(Arc::new(Refusing {
        backend: NativeBackend::default(),
    }));
    let held = Arc::new(Held::default());
    let s = KernelServices::new().with_pool(Arc::new(Arc::clone(&held)));
    assert!(s.attach_persistence(store));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    let (got, acked) = answers();
    let v = RecordBytes::new(b"v".to_vec()).unwrap();
    s.record_write(&caller("inst"), "approval", b"k", v, acked())
        .unwrap();
    assert_eq!(held.drain(), 1);
    assert_eq!(*got.lock().unwrap(), vec![Err(WRITE_FAILED)]);
    assert_eq!(s.pending().queued(), 0);
}

#[test]
fn a_write_dropped_before_any_flush_answers_dropped() {
    let (got, acked) = answers();
    drop(crate::host_records::Owed::new(acked()));
    assert_eq!(*got.lock().unwrap(), vec![Err(WRITE_DROPPED)]);
}

fn writer(store: &Arc<CoreStore>, pool: Arc<dyn Offload>) -> KernelServices {
    let s = KernelServices::new().with_pool(pool);
    assert!(s.attach_persistence(Arc::clone(store)));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    s
}

fn record(v: &str) -> RecordBytes {
    RecordBytes::new(v.as_bytes().to_vec()).unwrap()
}

#[test]
fn every_answered_write_is_durable_once_across_a_graceful_restart() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(2)
        .build()
        .unwrap();
    let pool = || -> Arc<dyn Offload> { Arc::new(BlockingPool::new(rt.handle().clone(), 64)) };
    let backing = native_store();
    let s = writer(&backing, pool());
    let me = caller("inst");
    let (got, acked) = answers();
    for round in ["first", "last"] {
        for i in 0..100 {
            let key = format!("k{i:03}");
            let v = record(&format!("{round}{i}"));
            s.record_write(&me, "approval", key.as_bytes(), v, acked())
                .unwrap();
        }
    }
    assert!(s.drain(std::time::Duration::from_secs(10)));
    assert_eq!(got.lock().unwrap().len(), 200);
    assert!(got.lock().unwrap().iter().all(Result::is_ok));
    drop(s);

    let fresh = writer(&backing, pool());
    let everything = RecordsList {
        kind: "approval".into(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let ran = fresh.records_list(&me, everything, Box::new(move |a| tx.send(a).unwrap()));
    assert!(matches!(ran, Ran::Later));
    let listed = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    assert_eq!(listed.spans.len(), 100);
    let value = |n: usize| {
        let sp = listed.spans[n];
        let at = sp.value.offset as usize;
        listed.bytes[at..at + sp.value.len as usize].to_vec()
    };
    assert_eq!(value(0), b"last0");
    assert_eq!(value(99), b"last99");
}

#[test]
fn a_write_past_the_queue_bound_is_refused_and_leaves_the_queued_value() {
    let backing = native_store();
    let held = Arc::new(Held::default());
    let s = writer(&backing, Arc::new(Arc::clone(&held)));
    let me = caller("inst");
    s.record_write(&me, "approval", b"k", record("v1"), noop())
        .unwrap();
    for i in 1..crate::host_records::QUEUE_CAP {
        s.record_write(
            &me,
            "approval",
            format!("f{i}").as_bytes(),
            record("v"),
            noop(),
        )
        .unwrap();
    }
    let refused = s.record_write(&me, "approval", b"k", record("v2"), noop());
    assert_eq!(refused, Err(QUEUE_FULL));

    assert_eq!(
        run(|l| s.records_get(&me, "approval", b"k", l)).bytes,
        b"v1"
    );

    assert_eq!(held.drain(), 1);
    assert_eq!(s.pending().queued(), 0);
    assert_eq!(stored(&backing, "inst", b"k"), Some(b"v1".to_vec()));
}

#[test]
fn the_tick_restarts_a_flush_the_pool_did_not_run() {
    let backing = native_store();
    let held = Arc::new(Held::default());
    let s = writer(&backing, Arc::new(Arc::clone(&held)));
    let (got, acked) = answers();
    s.record_write(&caller("inst"), "approval", b"k", record("v"), acked())
        .unwrap();

    drop(std::mem::take(&mut *held.0.lock().unwrap()));
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(s.pending().queued(), 1);
    s.flush_tick();
    assert_eq!(held.drain(), 1);
    assert_eq!(*got.lock().unwrap(), vec![Ok(())]);
}

#[test]
fn a_claim_is_durable_when_it_answers_whatever_happens_to_the_overlay() {
    let r = rig();
    let me = caller("inst");
    let claim = |s: &KernelServices| run(|l| s.records_claim(&me, "approval", b"nonce", 60_000, l));
    assert_eq!(claim(&r.s).value, svc::CLAIM_WON);

    let c = Arc::clone(&r.clock);
    let fresh = writer(&r.store, Arc::new(Inline))
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    assert_eq!(fresh.pending().queued(), 0);
    assert_eq!(claim(&fresh).value, svc::CLAIM_TAKEN);
}

use crate::host_units::UnitRecord;
use busbar_contract::records::{ScopeRef, VirtualKey};

fn key_granting(grants: &[(&str, &str)]) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "k".into(),
        name: "k".into(),
        enabled: true,
        allowed_scopes: Some(
            grants
                .iter()
                .map(|(kind, value)| ScopeRef {
                    kind: (*kind).into(),
                    value: (*value).into(),
                })
                .collect(),
        ),
        ..VirtualKey::default()
    })
}

fn entitled(r: &Rig, unit: u64, principal: Option<Arc<VirtualKey>>, target: &str) -> u64 {
    r.s.units().admitted(
        unit,
        UnitRecord {
            principal,
            depth: 0,
        },
    );
    r.s.entitlement_check(&caller("inst"), Some(unit), target)
        .value
}

fn sees(r: &Rig, unit: u64, principal: &Arc<VirtualKey>) -> Vec<&'static str> {
    ["one", "two"]
        .into_iter()
        .filter(|item| {
            entitled(
                r,
                unit,
                Some(Arc::clone(principal)),
                &format!("item:{item}"),
            ) == svc::ENTITLED
        })
        .collect()
}

#[test]
fn two_grants_see_two_catalogues_and_a_third_sees_none() {
    let r = rig();
    assert_eq!(sees(&r, 1, &key_granting(&[("item", "one")])), vec!["one"]);
    assert_eq!(sees(&r, 2, &key_granting(&[("item", "two")])), vec!["two"]);
    assert!(sees(&r, 3, &key_granting(&[("item", "three")])).is_empty());
}

#[test]
fn a_group_grant_without_the_item_grant_sees_nothing() {
    let r = rig();
    let key = key_granting(&[("group", "g")]);
    assert_eq!(
        entitled(&r, 1, Some(Arc::clone(&key)), "group:g"),
        svc::ENTITLED
    );
    assert_eq!(entitled(&r, 1, Some(key), "item:one"), svc::NOT_ENTITLED);
}

#[test]
fn a_dead_or_expired_key_sees_nothing() {
    let r = rig();
    let now_s = r.clock.load(Ordering::SeqCst) / 1000;
    let live = key_granting(&[("item", "one")]);
    assert_eq!(
        entitled(&r, 1, Some(Arc::clone(&live)), "item:one"),
        svc::ENTITLED
    );
    let dead = |f: &dyn Fn(&mut VirtualKey)| {
        let mut k = (*live).clone();
        f(&mut k);
        Arc::new(k)
    };
    for k in [
        dead(&|k| k.enabled = false),
        dead(&|k| k.deleted_at = Some(1)),
        dead(&|k| k.expires_at = Some(now_s)),
    ] {
        assert_eq!(entitled(&r, 2, Some(k), "item:one"), svc::NOT_ENTITLED);
    }
}

#[test]
fn entitlement_is_judged_against_the_principal_as_it_stands_now() {
    let r = rig();
    let admitted = key_granting(&[("item", "one"), ("item", "two")]);
    assert_eq!(
        entitled(
            &r,
            1,
            Some(Arc::clone(&admitted)),
            svc::ENTITLEMENT_STANDING
        ),
        svc::ENTITLED,
        "unattached, the admitted principal stands"
    );
    let now: Arc<std::sync::Mutex<Option<Arc<VirtualKey>>>> = Arc::new(std::sync::Mutex::new(
        Some(key_granting(&[("item", "one")])),
    ));
    let live = Arc::clone(&now);
    assert!(r
        .s
        .attach_standing(Arc::new(move |_, _| live.lock().unwrap().clone())));
    assert_eq!(
        entitled(&r, 1, Some(Arc::clone(&admitted)), "item:two"),
        svc::NOT_ENTITLED,
        "the narrowed grant is the one judged"
    );
    assert_eq!(
        entitled(&r, 1, Some(Arc::clone(&admitted)), "item:one"),
        svc::ENTITLED
    );
    *now.lock().unwrap() = None;
    assert_eq!(
        entitled(
            &r,
            1,
            Some(Arc::clone(&admitted)),
            svc::ENTITLEMENT_STANDING
        ),
        svc::NOT_ENTITLED,
        "a revoked principal no longer stands"
    );
    assert_eq!(
        entitled(&r, 1, Some(admitted), "item:one"),
        svc::NOT_ENTITLED
    );
    assert_eq!(
        entitled(&r, 2, None, svc::ENTITLEMENT_STANDING),
        svc::ENTITLED,
        "an ungoverned unit stands"
    );
}

#[test]
fn an_undeclared_scope_kind_is_not_entitled() {
    let r = rig();

    assert_eq!(entitled(&r, 1, None, "other:one"), svc::NOT_ENTITLED);
    assert_eq!(entitled(&r, 1, None, "no-kind-at-all"), svc::NOT_ENTITLED);
    assert_eq!(entitled(&r, 1, None, "item:one"), svc::ENTITLED);
}

#[test]
fn a_unit_not_in_flight_or_no_unit_is_not_entitled_and_ungoverned_is() {
    let r = rig();
    let me = caller("inst");
    assert_eq!(
        r.s.entitlement_check(&me, None, "item:one").value,
        svc::NOT_ENTITLED
    );
    assert_eq!(
        r.s.entitlement_check(&me, Some(9), "item:one").value,
        svc::NOT_ENTITLED
    );
    assert_eq!(entitled(&r, 9, None, "item:one:with:colons"), svc::ENTITLED);
    r.s.units().ended(9);
    assert_eq!(
        r.s.entitlement_check(&me, Some(9), "item:one").value,
        svc::NOT_ENTITLED
    );
    let stranger =
        r.s.entitlement_check(&caller("stranger"), Some(9), "item:one");
    assert_eq!(stranger.value, svc::NOT_ENTITLED);
}

#[derive(Debug, PartialEq, Eq)]
struct TargetJudgement {
    authority: String,
    secure: bool,
    class: u32,
    refuse_private: bool,
    reach: bool,
}

/// Records every question, refuses the private fixture host and plaintext targets,
/// and pins admitted destinations to the fixture's public address.
#[derive(Default)]
struct FakeGuard {
    names: Mutex<Vec<String>>,
    targets: Mutex<Vec<TargetJudgement>>,
}

impl DestJudge for FakeGuard {
    fn judge_target(
        &self,
        target: Destination<'_>,
        refuse_private: bool,
        reach: bool,
        done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        self.targets.lock().unwrap().push(TargetJudgement {
            authority: target.authority.to_owned(),
            secure: target.secure,
            class: target.egress_class,
            refuse_private,
            reach,
        });
        // Keep the production open-web rule: a bare authority conveys no TLS intent.
        if !target.secure {
            return Some(Err(svc::DEST_PLAINTEXT.into()));
        }
        self.judge(target.authority, target.egress_class, refuse_private, done)
    }

    fn judge_name(&self, dest: &str, _class: u32, _refuse_private: bool) -> Result<(), u64> {
        self.names.lock().unwrap().push(dest.to_owned());
        if dest.contains("10.0.0.5") {
            Err(svc::DEST_INTERNAL)
        } else {
            Ok(())
        }
    }
    fn judge(
        &self,
        dest: &str,
        class: u32,
        refuse_private: bool,
        _done: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        Some(
            self.judge_name(dest, class, refuse_private)
                .map(|()| {
                    let at: SocketAddr = "93.184.216.34:443".parse().unwrap();
                    (at, vec![at.ip()])
                })
                .map_err(|verdict| Refused {
                    verdict,
                    detail: Some("10.0.0.5".into()),
                }),
        )
    }
    fn judge_answer(&self, _: &str, _: &[IpAddr], _: u32) -> Result<(), DestRefusal> {
        Ok(())
    }
}

#[test]
fn dest_judge_answers_the_installed_guard_refusal() {
    let guard = Arc::new(FakeGuard::default());
    let s = KernelServices::new().with_dest_judge(guard.clone());
    for class in [0, 4] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge("http://10.0.0.5:80/x", class, 0, Some(later)));
        assert_eq!(got.value, svc::DEST_INTERNAL, "class {class}");
    }
    assert_eq!(
        s.judge_destination(
            Destination {
                authority: "10.0.0.5:443",
                secure: true,
                egress_class: 4,
            },
            Box::new(|_| panic!("the fixture answers immediately")),
        ),
        Some(Err(svc::DEST_INTERNAL))
    );
    assert_eq!(
        *guard.targets.lock().unwrap(),
        vec![TargetJudgement {
            authority: "10.0.0.5:443".into(),
            secure: true,
            class: 4,
            refuse_private: false,
            reach: false,
        }]
    );
    assert_eq!(guard.names.lock().unwrap().len(), 3);
}

#[test]
fn dest_judge_answers_the_installed_guard_admission() {
    let guard = Arc::new(FakeGuard::default());
    let s = KernelServices::new().with_dest_judge(guard.clone());
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge(
        "https://api.example.com/",
        0,
        svc::DEST_RESOLVE,
        Some(later),
    ));
    assert_eq!(got.value, svc::DEST_ALLOWED);
    assert_eq!(got.bytes, b"93.184.216.34");
    assert_eq!(
        s.judge_destination(
            Destination {
                authority: "api.example.com:443",
                secure: true,
                egress_class: 0,
            },
            Box::new(|_| panic!("the fixture answers immediately")),
        ),
        Some(Ok("93.184.216.34:443".parse().unwrap()))
    );
    assert_eq!(
        s.judge_dial("api.example.com:443", 0, Box::new(|_| panic!("no pend"))),
        Some(Err(svc::DEST_PLAINTEXT)),
        "a bare authority must not acquire secure intent from its port"
    );
    assert_eq!(
        *guard.targets.lock().unwrap(),
        [true, false].map(|secure| TargetJudgement {
            authority: "api.example.com:443".into(),
            secure,
            class: 0,
            refuse_private: false,
            reach: false,
        })
    );
}

#[test]
fn an_emit_reaches_only_its_own_open_session() {
    let services = KernelServices::new();
    let me = caller("door");
    let written: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = {
        let written = Arc::clone(&written);
        Arc::new(move |b: &[u8]| {
            written.lock().unwrap().push(b.to_vec());
            true
        }) as CarrierSink
    };
    let session = services.open_carrier_session(&me, "key-1", sink);
    assert_eq!(
        services
            .session_emit(&me, session, b"{\"ping\":1}\n")
            .outcome,
        Outcome::Ready
    );

    assert_eq!(
        services
            .session_emit(&caller("elsewhere"), session, b"x")
            .outcome,
        Outcome::Refused
    );

    assert_eq!(
        services.session_emit(&me, session + 1000, b"x").outcome,
        Outcome::Refused
    );

    assert_eq!(
        services
            .session_emit(&caller("door"), session, b"replacement")
            .outcome,
        Outcome::Refused,
        "a reopened plane with equal namespace cannot use the earlier incarnation's session"
    );
    services.close_carrier_session(session);
    assert_eq!(
        services.session_emit(&me, session, b"x").outcome,
        Outcome::Refused
    );
    assert_eq!(*written.lock().unwrap(), vec![b"{\"ping\":1}\n".to_vec()]);

    let gone = services.open_carrier_session(&me, "key-1", Arc::new(|_: &[u8]| false));
    assert_eq!(
        services.session_emit(&me, gone, b"x").outcome,
        Outcome::Refused
    );
    assert_eq!(
        services.session_emit(&me, gone, b"x").outcome,
        Outcome::Refused
    );
}

#[test]
fn a_declared_chain_the_host_cannot_keep_refuses_the_admit() {
    let r = rig();
    for (kind, framing) in [
        (0, 99),
        (7, busbar_contract::abi::plane::CHAIN_LENGTH_PREFIXED),
    ] {
        let refused =
            r.s.admit_sync(
                "chained",
                InstanceFacts {
                    record_kinds: vec![KIND],
                    record_chains: vec![busbar_contract::abi::plane::RecordChain {
                        kind,
                        framing,
                        flags: 0,
                        _reserved: 0,
                    }],
                    ..InstanceFacts::default()
                },
            )
            .unwrap_err();
        assert_eq!(refused, AdmitRefused::ChainUnknown { kind, framing });
        let s = r.s.sign(&caller("chained"), b"x");
        assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
    }
}

#[test]
fn an_instance_declaring_a_kernel_record_kind_is_refused_at_admit() {
    let r = rig();
    for kind in [
        crate::governance::TICKET_RECORD_KIND,
        crate::host_work::WORK_SCHEMA.as_str(),
        crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
    ] {
        let refused =
            r.s.admit_sync(
                "squatter",
                InstanceFacts {
                    record_kinds: vec![KIND, RecordSchemaId::new(kind)],
                    conditional_record_kinds: vec![1],
                    record_retentions: vec![busbar_contract::abi::plane::RecordRetention {
                        kind: 1,
                        rule: busbar_contract::host_records::RETENTION_TERMINAL_ONLY,
                    }],
                    ..InstanceFacts::default()
                },
            )
            .expect_err("kernel record schemas cannot be declared by an instance");
        assert_eq!(
            refused,
            AdmitRefused::KindReserved {
                instance: "squatter".to_string(),
                kind: kind.to_string(),
            }
        );
        let words = refused.to_string();
        assert!(
            words.contains("`squatter`") && words.contains(kind) && words.contains("kernel"),
            "the refusal names the instance, the kind and why: {words}"
        );
        assert_eq!(r.s.sign(&caller("squatter"), b"x").error, NOT_ADMITTED);
        assert_eq!(r.s.record_retention("squatter", kind), Retention::Age);
        let value = RecordBytes::new(b"forged host state".to_vec()).unwrap();
        assert_eq!(
            r.s.record_write(
                &caller("squatter"),
                kind,
                b"key",
                value,
                Box::new(|_| panic!("an unadmitted instance queued a write"))
            ),
            Err(NOT_ADMITTED)
        );
    }
}

#[tokio::test]
async fn an_admit_parked_in_the_store_never_stalls_another_instances_host_service() {
    use trust_ordering_tests::native::*;
    let r = Rig::new().await;
    r.backend.park_scan.store(true, Ordering::SeqCst);
    let node = r.node.clone();
    let admission = tokio::spawn(async move { node.admit("other", facts()).await });
    entered(&r.backend).await;
    assert_eq!(
        r.node.trust_unreached(&caller(), PEER).value,
        svc::TRUST_NEW
    );
    assert!(r.node.instances.try_lock().is_ok());
    r.backend.release.notify_one();
    admission.await.unwrap().unwrap();
}

#[test]
fn a_purge_runs_under_the_rule_the_instance_declared_for_the_kind() {
    use crate::host_records_async::{AsyncHistory, HistoryOutcome};
    use busbar_contract::abi::plane::RecordRetention;
    use busbar_contract::abi::plane::{CollectionMode, RecordCollection};
    use busbar_contract::ids::RecordSchemaId;
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, Retention};
    let store = native_store();
    let s = KernelServices::new();
    assert!(s.attach_persistence(Arc::clone(&store)));
    s.admit_sync(
        "inst",
        InstanceFacts {
            record_kinds: vec![RecordSchemaId::new("kept"), RecordSchemaId::new("aged")],
            record_collections: vec![
                RecordCollection {
                    kind: 0,
                    mode: CollectionMode::Upsert,
                    parent: None,
                },
                RecordCollection {
                    kind: 1,
                    mode: CollectionMode::Upsert,
                    parent: None,
                },
            ],
            record_retentions: vec![RecordRetention {
                kind: 0,
                rule: Retention::TerminalOnly.code(),
            }],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    assert_eq!(s.record_retention("inst", "kept"), Retention::TerminalOnly);
    assert_eq!(s.record_retention("inst", "aged"), Retention::Age);
    assert_eq!(s.record_retention("other", "kept"), Retention::Age);

    let facts = s.lock_instances().get("inst").cloned().unwrap();
    let history = AsyncHistory::admitted(Arc::clone(&store), "inst", &facts).unwrap();
    let rows = [
        ("old-active", 10, PlaneDisposition::Active),
        ("old-terminal", 10, PlaneDisposition::Terminal),
        ("new-terminal", 200, PlaneDisposition::Terminal),
    ];
    for kind in ["kept", "aged"] {
        for (id, ts, disposition) in rows {
            let row = PlaneRecord {
                kind: kind.into(),
                id: id.into(),
                parent: None,
                seq: 0,
                ts,
                disposition,
                body: b"{}".to_vec(),
            };
            assert_eq!(
                ready(history.upsert(row.view())).unwrap(),
                HistoryOutcome::Applied
            );
        }
    }
    let held = |kind: &str, id: &str| ready(history.get(kind, id)).unwrap().is_some();

    assert_eq!(
        ready(s.purge_records_before("inst", "kept", 100)).unwrap(),
        (HistoryOutcome::Applied, 1)
    );
    assert!(
        held("kept", "old-active"),
        "an active row outlives the cutoff"
    );
    assert!(!held("kept", "old-terminal"), "an older terminal row goes");
    assert!(held("kept", "new-terminal"), "a row after the cutoff stays");

    assert_eq!(
        ready(s.purge_records_before("inst", "aged", 100)).unwrap(),
        (HistoryOutcome::Applied, 2)
    );
    assert!(
        !held("aged", "old-active"),
        "by age, an older active row goes"
    );
    assert!(!held("aged", "old-terminal"));
    assert!(held("aged", "new-terminal"));
}

#[test]
fn a_replayed_approval_is_refused_through_records_claim() {
    let r = rig();
    let me = caller("inst");
    let redeem = || {
        run(|l| {
            r.s.records_claim(&me, "approval", b"approval-nonce", 60_000, l)
        })
    };
    assert_eq!(
        redeem().value,
        svc::CLAIM_WON,
        "the first redemption is the one that counts"
    );
    assert_eq!(
        redeem().value,
        svc::CLAIM_TAKEN,
        "the same approval presented again is refused"
    );
}

#[tokio::test]
async fn a_trust_decision_the_store_refused_never_takes_effect() {
    use trust_ordering_tests::native::*;
    let r = Rig::new().await;
    r.observe(ORIGINAL).await;
    r.backend.refuse_commit.store(true, Ordering::SeqCst);
    assert!(matches!(
        r.node.trust_rule(KEY, Ruling::Approve).await,
        Err(TrustRefused::Store(_))
    ));
    assert_eq!(judged(&r.node, None), Err(Distrust::NotApproved));
    r.backend.refuse_commit.store(false, Ordering::SeqCst);
    r.node.trust_rule(KEY, Ruling::Approve).await.unwrap();
    assert_eq!(judged(&r.node, None), Ok(()));
}

async fn ticket_result(
    services: &KernelServices,
    caller: Caller,
    unit: Option<u64>,
    ttl: u64,
    record: &[u8],
) -> Stored {
    let (send, receive) = tokio::sync::oneshot::channel();
    match services.ticket_mint(
        &caller,
        unit,
        ttl,
        record,
        Box::new(move |answer| {
            let _ = send.send(answer);
        }),
    ) {
        Ran::Now(answer) => answer,
        Ran::Later => receive.await.expect("native ticket mint answers"),
    }
}

type Minted = (String, String, u64, Vec<u8>);

/// A press that mints `<prefix><key>:<ttl>` and expires at `now + ttl`, keeping what it was handed.
#[derive(Default)]
struct Press(Mutex<Vec<Minted>>);

#[async_trait::async_trait]
impl TicketPress for Press {
    async fn mint(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), &'static str> {
        self.0.lock().unwrap().push((
            key_id.to_string(),
            prefix.to_string(),
            ttl_secs,
            record.to_vec(),
        ));
        Ok((format!("{prefix}{key_id}:{ttl_secs}"), now + ttl_secs))
    }
}

#[test]
fn a_credential_consumer_prefix_has_one_instance_owner() {
    let r = rig();
    let facts = || InstanceFacts {
        ticket_prefix: Some("delegated_".into()),
        ..InstanceFacts::default()
    };
    r.s.admit_sync("first-consumer", facts())
        .expect("first owner");
    r.s.admit_sync("first-consumer", facts())
        .expect("same owner re-admission");
    assert!(
        r.s.admit_sync("other-consumer", facts()).is_err(),
        "two instances cannot redeem credentials from the same consumer namespace"
    );
    assert_eq!(
        r.s.ticket_prefix_of("first-consumer").as_deref(),
        Some("delegated_")
    );
    assert_eq!(r.s.ticket_prefix_of("other-consumer"), None);
    assert!(
        r.s.admit_sync("first-consumer", InstanceFacts::default())
            .is_err(),
        "re-admission cannot release a namespace while its signed credentials may still exist"
    );
    assert_eq!(
        r.s.ticket_prefix_of("first-consumer").as_deref(),
        Some("delegated_")
    );
    r.s.admit_sync(
        "separate-consumer",
        InstanceFacts {
            ticket_prefix: Some("separate_".into()),
            ..InstanceFacts::default()
        },
    )
    .expect("an independent namespace is admitted");
}

#[tokio::test]
async fn a_ticket_is_minted_for_the_units_principal_under_the_declared_prefix() {
    let r = rig();
    r.s.admit(
        "minter",
        InstanceFacts {
            ticket_prefix: Some("tk_".into()),
            ..InstanceFacts::default()
        },
    )
    .await
    .unwrap();
    let principal = Arc::new(VirtualKey {
        id: "vk_caller".into(),
        ..VirtualKey::default()
    });
    r.s.units().admitted(
        7,
        UnitRecord {
            principal: Some(Arc::clone(&principal)),
            depth: 0,
        },
    );

    let no_press = ticket_result(&r.s, caller("minter"), Some(7), 600, b"{}").await;
    assert_eq!(
        (no_press.outcome, no_press.error),
        (Outcome::Refused, TICKET_NO_PRESS)
    );
    let press = Arc::new(Press::default());
    assert!(r
        .s
        .attach_tickets(Arc::clone(&press) as Arc<dyn TicketPress>));
    let minted = ticket_result(&r.s, caller("minter"), Some(7), 600, b"{\"m\":1}").await;
    assert_eq!(minted.outcome, Outcome::Ready);
    assert_eq!(minted.bytes, b"tk_vk_caller:600");
    assert_eq!(
        minted.value,
        r.clock.load(Ordering::SeqCst) / 1_000 + 600,
        "the wall clock's seconds plus the lifetime"
    );
    assert_eq!(
        press.0.lock().unwrap().as_slice(),
        &[(
            "vk_caller".to_string(),
            "tk_".to_string(),
            600,
            b"{\"m\":1}".to_vec()
        )]
    );

    let none = ticket_result(&r.s, caller("minter"), None, 600, b"{}").await;
    assert_eq!(none.error, TICKET_NO_PRINCIPAL);
    r.s.units().admitted(
        8,
        UnitRecord {
            principal: None,
            depth: 0,
        },
    );
    let anonymous = ticket_result(&r.s, caller("minter"), Some(8), 600, b"{}").await;
    assert_eq!(anonymous.error, TICKET_NO_PRINCIPAL);
    let unprefixed = ticket_result(&r.s, caller("inst"), Some(7), 600, b"{}").await;
    assert_eq!(unprefixed.error, TICKET_NO_PREFIX);
    assert_eq!(
        press.0.lock().unwrap().len(),
        1,
        "a refused mint never reaches the press"
    );
    assert_eq!(r.s.ticket_prefix_of("minter").as_deref(), Some("tk_"));
    assert_eq!(r.s.ticket_prefix_of("inst"), None);
}

#[test]
fn a_take_hands_back_what_admitted_the_unit_once() {
    let r = rig();
    let admit = |unit: u64| {
        r.s.units().admitted(
            unit,
            UnitRecord {
                principal: None,
                depth: 0,
            },
        );
    };
    admit(7);
    assert!(r.s.units().ticketed(7, Some(b"record".to_vec())));
    admit(8);
    assert!(r.s.units().ticketed(8, None));
    let taken = r.s.ticket_take(&caller("inst"), Some(7));
    assert_eq!(
        (taken.outcome, taken.value, taken.bytes.as_slice()),
        (Outcome::Ready, svc::TICKET_TAKEN, &b"record"[..])
    );
    let keyed = r.s.ticket_take(&caller("inst"), Some(8));
    assert_eq!(
        (keyed.outcome, keyed.value, keyed.bytes.len()),
        (Outcome::Ready, svc::TICKET_NONE, 0)
    );

    for unit in [Some(7), Some(8), Some(9), None] {
        let again = r.s.ticket_take(&caller("inst"), unit);
        assert_eq!(
            (again.outcome, again.error),
            (Outcome::Refused, TICKET_NOT_HELD),
            "unit {unit:?}"
        );
    }

    assert!(!r.s.units().ticketed(9, Some(b"x".to_vec())));
    admit(10);
    assert!(r.s.units().ticketed(10, Some(b"x".to_vec())));
    r.s.units().ended(10);
    assert_eq!(
        r.s.ticket_take(&caller("inst"), Some(10)).error,
        TICKET_NOT_HELD
    );
}

#[test]
fn a_trust_decision_made_through_another_node_takes_effect_within_one_window() {
    use crate::trust::book::Ruling;
    let r = rig();
    let me = caller("inst");
    let b = restarted(&r);
    b.admit_sync("inst", trusting(Some("fp"))).unwrap();
    assert_eq!(
        run(|l| r.s.trust_sight(&me, "cp", "c1", l)).value,
        svc::TRUST_NEW,
        "a first sighting on node a"
    );
    ready(r.s.trust_rule("inst/cp", Ruling::Approve)).unwrap();
    assert_eq!(
        b.trust_unreached(&me, "cp").value,
        svc::TRUST_NEW,
        "node b has not re-synced yet"
    );
    b.trust_resync_tick();
    assert_eq!(
        b.trust_unreached(&me, "cp").value,
        svc::TRUST_SAME,
        "node b applies the approval node a kept"
    );
}

#[path = "trust_resync_tests.rs"]
mod trust_resync_tests;

#[path = "trust_ordering_tests.rs"]
mod trust_ordering_tests;

#[tokio::test]
async fn an_instance_whose_trust_records_cannot_be_read_is_not_admitted() {
    use trust_ordering_tests::native::*;
    let r = Rig::new().await;
    r.backend.refuse_scan.store(true, Ordering::SeqCst);
    assert!(matches!(
        r.node.admit("unread", facts()).await,
        Err(AdmitRefused::TrustUnread(_))
    ));
    assert!(r
        .node
        .facts(&Caller::for_test("unread".into(), (caller()).kind()))
        .is_none());
}

#[test]
fn record_claim_replay_uses_store_time_when_the_host_clock_runs_ahead() {
    const CLAIM_TTL_MS: u64 = 2_000;
    const HOST_SKEW_MS: u64 = 3_000;
    let r = rig();
    let me = caller("inst");
    let claim = || {
        run(|l| {
            r.s.records_claim(&me, "approval", b"clock-skew", CLAIM_TTL_MS, l)
        })
    };
    assert_eq!(claim().value, svc::CLAIM_WON);

    r.clock.fetch_add(HOST_SKEW_MS, Ordering::SeqCst);
    assert_eq!(claim().value, svc::CLAIM_TAKEN);

    let until = r.clock.load(Ordering::SeqCst) / 1_000;
    r.backend.now.store(until + 1, Ordering::SeqCst);
    assert_eq!(claim().value, svc::CLAIM_WON);
}

#[tokio::test]
async fn ticket_press_receives_the_exact_host_unit_caller_and_principal() {
    struct BoundPress {
        principal: Arc<VirtualKey>,
    }
    #[async_trait::async_trait]
    impl TicketPress for BoundPress {
        async fn mint(
            &self,
            _: &str,
            _: &str,
            _: u64,
            _: &[u8],
            _: u64,
        ) -> Result<(String, u64), &'static str> {
            panic!("the host must use unit-aware minting")
        }
        async fn mint_for_unit(
            &self,
            unit: u64,
            caller: &Caller,
            principal: &Arc<VirtualKey>,
            prefix: &str,
            ttl_secs: u64,
            record: &[u8],
            now: u64,
        ) -> Result<(String, u64), &'static str> {
            assert_eq!(unit, 71);
            assert_eq!(caller.namespace().as_ref(), "minter");
            assert!(Arc::ptr_eq(principal, &self.principal));
            assert_eq!(principal.generation_hash, "full-generation-binding");
            assert_eq!(prefix, "tk_");
            assert_eq!(record, b"opaque");
            Ok(("published".into(), now + ttl_secs))
        }
    }
    let r = rig();
    r.s.admit(
        "minter",
        InstanceFacts {
            ticket_prefix: Some("tk_".into()),
            ..InstanceFacts::default()
        },
    )
    .await
    .unwrap();
    let principal = Arc::new(VirtualKey {
        id: "vk_caller".into(),
        generation_hash: "full-generation-binding".into(),
        ..VirtualKey::default()
    });
    r.s.units().admitted(
        71,
        UnitRecord {
            principal: Some(Arc::clone(&principal)),
            depth: 0,
        },
    );
    assert!(r.s.attach_tickets(Arc::new(BoundPress { principal })));
    let result = ticket_result(&r.s, caller("minter"), Some(71), 600, b"opaque").await;
    assert_eq!(result.outcome, Outcome::Ready);
    assert_eq!(result.bytes, b"published");
}

#[test]
fn trust_decision_authority_is_scoped_to_incarnation_ticket_counterparty_and_lifetime() {
    use busbar_contract::{abi::mechanism::ticket::Ticket, services::TrustKeyRef};
    let r = rig();
    let me = caller("inst");
    let clone = me.clone();
    let replacement = caller("inst");
    let ticket = Ticket {
        slot: 9,
        generation: 1,
    };
    let other_ticket = Ticket {
        slot: 9,
        generation: 2,
    };
    let key = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    let decide = |who: &Caller, ticket, key| {
        run(|later| r.s.trust_decide(who, ticket, key, Some("fp"), true, later))
    };
    run(|later| r.s.trust_sight(&me, "cp", "fp", later));
    assert_eq!(decide(&me, ticket, key).error, NO_TRUST_DECISION_GRANT);
    assert!(r.s.grant_trust_decision(&me, Ticket::NONE, "cp").is_none());
    assert!(r.s.grant_trust_decision(&me, ticket, "foreign").is_none());
    let grant =
        r.s.grant_trust_decision(&me, ticket, "cp")
            .expect("admin call owns this grant");
    assert!(
        r.s.grant_trust_decision(&me, ticket, "cp").is_none(),
        "cannot replace an outstanding grant"
    );
    assert_eq!(
        decide(&replacement, ticket, key).error,
        NO_TRUST_DECISION_GRANT
    );
    assert_eq!(
        decide(&me, other_ticket, key).error,
        NO_TRUST_DECISION_GRANT
    );
    assert_eq!(
        decide(
            &me,
            ticket,
            TrustKeyRef {
                counterparty: "foreign",
                item: None
            }
        )
        .error,
        NO_TRUST_DECISION_GRANT
    );
    assert_eq!(
        r.s.trust_serves(&me, "cp", None, None).value,
        svc::DISTRUST_NOT_APPROVED
    );
    assert_eq!(
        decide(&clone, ticket, key).value,
        svc::TRUST_DECIDED_SERVING
    );
    drop(grant);
    assert_eq!(decide(&me, ticket, key).error, NO_TRUST_DECISION_GRANT);
}
