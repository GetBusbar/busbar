// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's host services: `clock.now`, and `dest.judge` over the destination judge the root
//! installs (the connector's guard; its rules are tested there, `busbar-core-connector`
//! `dest_judge_tests`).

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

fn verdict_now(r: Ran) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => panic!("the answer pended"),
    }
}

/// A later that records what it was answered.
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

// ── records, sign, trust ─────────────────────────────────────────────────────────────────────

use std::sync::atomic::AtomicU64;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::kinds::{RecordBytes, StoreError};

use crate::governance::MemoryStore;
use crate::host_records::{WRITE_DROPPED, WRITE_FAILED};
use crate::trust::reverify::Policy;
use crate::trust::section::{DeclaredPin, TrustEntry};

/// The memory store's typed record reads.
struct Mem(Arc<MemoryStore>);

impl RecordRows for Mem {
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        self.0.record_put(schema, key, value)
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        self.0.record_get(schema, key)
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        self.0.record_scan(schema, prefix, limit)
    }
}

/// Runs every job at once, on the caller's thread.
struct Inline;

impl Offload for Inline {
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

/// A signer with a fixed key id that "signs" by prefixing the domain.
struct FixedKey;

impl SignKey for FixedKey {
    fn sign(&self, domain: &str, data: &[u8]) -> Option<(String, Vec<u8>)> {
        Some(("K1".into(), [domain.as_bytes(), b":", data].concat()))
    }
}

const KIND: RecordSchemaId = RecordSchemaId::new("approval");

/// The plane's declared section key: the label of its implicit first instance, the one a
/// single-instance configuration describes.
const SECTION_KEY: &str = "tools";

/// An instance of the one test plugin, by its label.
fn caller(instance: &str) -> Caller {
    Caller {
        instance: Arc::from(instance),
        plugin: Arc::from("the-plugin"),
        kind: KindCode::Plane,
    }
}

struct Rig {
    s: KernelServices,
    store: Arc<MemoryStore>,
    clock: Arc<AtomicU64>,
}

fn rig() -> Rig {
    let store = Arc::new(MemoryStore::new());
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let c = Arc::clone(&clock);
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&store))), store.clone())
        .with_pool(Arc::new(Inline))
        .with_signer(Arc::new(FixedKey))
        .with_demotions(demotions(&store), SECTION_KEY)
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    s.admit(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
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
                        key: None,
                        fingerprint: Some("fp".into()),
                    }),
                    policy: Policy {
                        ttl_ms: 100,
                        recovery_backoff_ms: 0,
                    },
                },
            )],
            scope_kinds: vec!["group".into(), "item".into()],
            record_chains: Vec::new(),
        },
    )
    .unwrap();
    Rig { s, store, clock }
}

/// A durable demotion record over `store`.
fn demotions(store: &Arc<MemoryStore>) -> Arc<DemotionRecord> {
    let d = DemotionRecord::default();
    d.set_sink(crate::plane::store::PlaneStoreView::narrow(store.clone()));
    Arc::new(d)
}

/// Run a may-pend service and take what it answered, now or through its `Later`.
fn run(f: impl FnOnce(Later) -> Ran) -> Stored {
    let (slot, later) = recorder();
    match f(later) {
        Ran::Now(s) => s,
        Ran::Later => slot.lock().unwrap().take().expect("the later was answered"),
    }
}

/// Store `value` under `key` as the instance labelled "inst" keeps it.
fn put(into: &MemoryStore, key: &str, value: &str) {
    into.record_put(
        KIND,
        &record_key("inst", key.as_bytes()),
        &RecordBytes::new(value.as_bytes().to_vec()).unwrap(),
    )
    .unwrap();
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
    // Another instance's key of the same name is its own.
    r.s.admit(
        "other",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    assert_eq!(claim(&caller("other")).value, svc::CLAIM_WON);
    r.clock.fetch_add(3_000, Ordering::SeqCst);
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
    s.admit(
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
    r.s.admit("plain", InstanceFacts::default()).unwrap();
    let s = r.s.sign(&caller("plain"), b"x");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NO_DOMAIN));
    let keyless = KernelServices::new();
    keyless
        .admit(
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
    assert_eq!(sight("fp").value, svc::TRUST_SAME);
    assert_eq!(sight("moved").value, svc::TRUST_DRIFTED);
    let demoted = r.s.demotions.get().unwrap().record.list();
    assert_eq!(demoted.len(), 1);
    assert_eq!(demoted[0].server, demotion_key("inst", "cp"));
    assert_eq!(sight("moved").value, svc::TRUST_QUARANTINED);
    assert_eq!(sight("fp").value, svc::TRUST_SAME);
    assert!(r.s.demotions.get().unwrap().record.list().is_empty());
    let s = run(|l| r.s.trust_sight(&me, "nobody", "fp", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_COUNTERPARTY));
}

#[test]
fn a_durable_demotion_is_replayed_at_admit() {
    let r = rig();
    let me = caller("inst");
    assert_eq!(
        run(|l| r.s.trust_sight(&me, "cp", "moved", l)).value,
        svc::TRUST_DRIFTED
    );
    // A re-admit (a restart re-registering the instance) keeps the demotion from the record.
    let fresh = restarted(&r);
    fresh
        .admit(
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
fn trust_due_answers_the_ticks_marks_one_span_each() {
    let r = rig();
    let me = caller("inst");
    assert!(r.s.trust_due(&me).spans.is_empty());
    r.s.mark_due();
    let s = r.s.trust_due(&me);
    assert_eq!(s.bytes, b"cp");
    assert_eq!((s.spans[0].key.offset, s.spans[0].key.len), (0, 2));
    assert_eq!(
        s.spans[0].value.offset,
        busbar_contract::abi::mechanism::check::SPAN_ABSENT
    );
}

#[test]
fn two_instances_of_one_plugin_have_distinct_registries() {
    let r = rig();
    // A second instance of the same plugin, declaring another record kind and another domain.
    r.s.admit(
        "second",
        InstanceFacts {
            record_kinds: vec![RecordSchemaId::new("other")],
            signing: Some(Signing {
                domain: "dom2".into(),
                kid_prefix: "q-".into(),
            }),
            trust: Vec::new(),
            scope_kinds: Vec::new(),
            record_chains: Vec::new(),
        },
    )
    .unwrap();
    let (first, second) = (caller("inst"), caller("second"));
    assert_eq!(first.plugin, second.plugin);
    let s = run(|l| r.s.records_get(&second, "approval", b"k", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_KIND));
    assert_eq!(r.s.sign(&second, b"x").bytes, b"q-K1dom2:x");
    // The first instance keeps its own.
    assert_eq!(r.s.sign(&first, b"x").bytes, b"p-K1dom:x");
    let s = run(|l| r.s.records_get(&first, "approval", b"k", l));
    assert_eq!((s.outcome, s.value), (Outcome::Ready, svc::ABSENT));
    let s = run(|l| r.s.trust_sight(&second, "cp", "fp", l));
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_A_COUNTERPARTY));
    // One instance's queued write is not the other's.
    r.s.admit(
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

/// The rig's kernel after a restart: the same durable demotion record, nothing else.
fn restarted(r: &Rig) -> KernelServices {
    let d = r.s.demotions.get().unwrap();
    KernelServices::new()
        .with_demotions(Arc::clone(&d.record), &d.default_instance)
        .with_pool(Arc::new(Inline))
}

/// One trust entry for `cp`, pinned to `fp` or unpinned.
fn trusting(pin: Option<&str>) -> InstanceFacts {
    InstanceFacts {
        trust: vec![(
            "cp".into(),
            TrustEntry {
                pin: pin.map(|fp| DeclaredPin {
                    mechanism: "fingerprint".into(),
                    root: false,
                    key: None,
                    fingerprint: Some(fp.into()),
                }),
                policy: Policy {
                    ttl_ms: 0,
                    recovery_backoff_ms: 0,
                },
            },
        )],
        ..InstanceFacts::default()
    }
}

#[test]
fn a_demotion_in_one_instance_is_never_replayed_into_another_with_the_same_counterparty() {
    let r = rig();
    assert_eq!(
        run(|l| r.s.trust_sight(&caller("inst"), "cp", "moved", l)).value,
        svc::TRUST_DRIFTED
    );
    let fresh = restarted(&r);
    fresh.admit("inst", trusting(None)).unwrap();
    fresh.admit("second", trusting(None)).unwrap();
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
    // A row a single-instance deployment wrote: keyed by the counterparty alone.
    r.s.demotions
        .get()
        .unwrap()
        .record
        .record("cp", "quarantined", 1);
    let fresh = restarted(&r);
    fresh.admit(SECTION_KEY, trusting(None)).unwrap();
    fresh.admit("inst", trusting(None)).unwrap();
    assert_eq!(
        run(|l| fresh.trust_sight(&caller(SECTION_KEY), "cp", "x", l)).value,
        svc::TRUST_QUARANTINED
    );
    assert_eq!(
        run(|l| fresh.trust_sight(&caller("inst"), "cp", "x", l)).value,
        svc::TRUST_NEW
    );
    // Re-admitted with a pin, the default instance's clean sighting clears the unprefixed row.
    let pinned = restarted(&r);
    pinned.admit(SECTION_KEY, trusting(Some("fp"))).unwrap();
    assert_eq!(
        run(|l| pinned.trust_sight(&caller(SECTION_KEY), "cp", "fp", l)).value,
        svc::TRUST_SAME
    );
    assert!(r.s.demotions.get().unwrap().record.list().is_empty());
}

#[test]
fn another_instance_declaring_the_same_kind_never_reaches_the_records_of_this_one() {
    let r = rig();
    put(&r.store, "k", "mine");
    let declares = || InstanceFacts {
        record_kinds: vec![KIND],
        ..InstanceFacts::default()
    };
    r.s.admit("other", declares()).unwrap();
    r.s.admit("elsewhere", declares()).unwrap();
    // "other" is another instance of the same plugin; "elsewhere" is an instance of another.
    let elsewhere = Caller {
        plugin: Arc::from("another-plugin"),
        ..caller("elsewhere")
    };
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
    // Their claims spent nothing of "inst"'s, and its record is its own.
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
}

impl RecordRows for Gauge {
    fn record_put(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
        _value: &RecordBytes,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    fn record_get(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.most.fetch_max(n, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(5));
        self.now.fetch_sub(1, Ordering::SeqCst);
        Ok(None)
    }

    fn record_scan(
        &self,
        _schema: RecordSchemaId,
        _prefix: &[u8],
        _limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        Ok(Vec::new())
    }
}

/// A write's answer nobody waits for.
fn noop() -> Acked {
    Box::new(|_| {})
}

/// Kernel services over `reads`, on the blocking pool of `rt`, with "inst" admitted.
fn pooled(rt: &tokio::runtime::Runtime, reads: Arc<dyn RecordRows>) -> KernelServices {
    let s = KernelServices::new()
        .with_records(reads, Arc::new(MemoryStore::new()))
        .with_pool(Arc::new(BlockingPool::new(rt.handle().clone(), 64)));
    s.admit(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    s
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
    let s = run(|l| s.records_get(&caller("inst"), "approval", b"k", l));
    assert_eq!((s.outcome, s.error), (Outcome::Failed, POOL_REFUSED));
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
}

#[test]
fn a_demotion_is_written_on_the_pool_and_the_sighting_answers_after_it() {
    let r = rig();
    let held = Arc::new(Held::default());
    let s = restarted(&r).with_pool(Arc::new(Arc::clone(&held)));
    s.admit("inst", trusting(Some("fp"))).unwrap();
    let (slot, later) = recorder();
    let ran = s.trust_sight(&caller("inst"), "cp", "moved", later);
    // Nothing is written, nor answered, on the calling thread.
    assert!(matches!(ran, Ran::Later));
    assert!(slot.lock().unwrap().is_none());
    assert!(r.s.demotions.get().unwrap().record.list().is_empty());
    assert_eq!(held.drain(), 1);
    assert_eq!(
        slot.lock().unwrap().take().unwrap().value,
        svc::TRUST_DRIFTED
    );
    assert_eq!(r.s.demotions.get().unwrap().record.list().len(), 1);
    // A sighting with nothing to write answers at once.
    let s2 = run(|l| s.trust_sight(&caller("inst"), "cp", "moved", l));
    assert_eq!(s2.value, svc::TRUST_QUARANTINED);
    assert_eq!(held.drain(), 0);
}

#[test]
fn a_durable_record_with_no_pool_judges_nothing() {
    let r = rig();
    let d = r.s.demotions.get().unwrap();
    let s = KernelServices::new().with_demotions(Arc::clone(&d.record), SECTION_KEY);
    s.admit("inst", trusting(Some("fp"))).unwrap();
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
    let refused = r.s.admit("taker", taker.clone()).unwrap_err();
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
    // Nothing was registered: the taker is not admitted and cannot sign.
    let s = r.s.sign(&caller("taker"), b"x");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
    // The holder re-admitting its own domain is not a collision.
    r.s.admit(
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
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&r.store))), r.store.clone())
        .with_pool(Arc::new(Arc::clone(&held)));
    let declares = || InstanceFacts {
        record_kinds: vec![KIND],
        ..InstanceFacts::default()
    };
    s.admit("inst", declares()).unwrap();
    s.admit("other", declares()).unwrap();
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
    // The writer reads its writes before the store has any of them.
    assert_eq!(
        run(|l| s.records_get(&me, "approval", b"k07", l)).bytes,
        b"v7"
    );
    let stored = |who: &str, key: &[u8]| {
        r.store
            .record_get(KIND, &record_key(who, key))
            .unwrap()
            .map(|v| v.as_slice().to_vec())
    };
    assert_eq!(stored("inst", b"k07"), None);
    // Another instance writing the same key writes its own record.
    s.record_write(
        &caller("other"),
        "approval",
        b"k07",
        bytes("theirs".into()),
        noop(),
    )
    .unwrap();
    // One flush carried the whole burst.
    assert_eq!(held.drain(), 1);
    assert_eq!(s.pending().queued(), 0);
    assert_eq!(stored("inst", b"k07"), Some(b"v7".to_vec()));
    assert_eq!(stored("inst", b"k49"), Some(b"v49".to_vec()));
    assert_eq!(stored("other", b"k07"), Some(b"theirs".to_vec()));
    // The next write starts the next flush.
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
    let store = Arc::new(MemoryStore::new());
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&store))), store.clone())
        .with_pool(Arc::new(BlockingPool::new(rt.handle().clone(), 64)));
    s.admit(
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
    // The refused flush was abandoned: the next write starts one again (refused too, here).
    s.record_write(&me, "approval", b"k2", v, noop()).unwrap();
    assert_eq!(s.pending().queued(), 2);
}

#[test]
fn a_row_without_a_label_is_read_back_under_the_section_key_instance_and_no_other() {
    let r = rig();
    // A row as a single-instance deployment wrote it: the counterparty's name alone.
    let d = r.s.demotions.get().unwrap();
    d.record.record("cp", "quarantined", 1);
    let fresh = restarted(&r);
    for label in [SECTION_KEY, "inst", "tools-2"] {
        fresh.admit(label, trusting(None)).unwrap();
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
        let refused = r.s.admit(&label, InstanceFacts::default()).unwrap_err();
        assert_eq!(refused, AdmitRefused::LabelUnfit { len: label.len() });
        let s = r.s.sign(&caller(&label), b"x");
        assert_eq!((s.outcome, s.error), (Outcome::Refused, NOT_ADMITTED));
    }
    r.s.admit(&"l".repeat(65_535), InstanceFacts::default())
        .unwrap();
}

/// Record reads that hold every call until the test opens the gate.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    opened: std::sync::Condvar,
}

impl Gate {
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
}

impl RecordRows for Gate {
    fn record_put(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
        _value: &RecordBytes,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    fn record_get(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        let open = self.open.lock().unwrap();
        drop(self.opened.wait_while(open, |o| !*o).unwrap());
        Ok(None)
    }

    fn record_scan(
        &self,
        _schema: RecordSchemaId,
        _prefix: &[u8],
        _limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        Ok(Vec::new())
    }
}

#[test]
fn a_call_past_the_pools_bound_answers_failed_at_once() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let gate = Arc::new(Gate::default());
    let s = KernelServices::new()
        .with_records(gate.clone(), Arc::new(MemoryStore::new()))
        .with_pool(Arc::new(BlockingPool::new(rt.handle().clone(), 2)));
    s.admit(
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
    // The three past the bound answered FAILED before any store call ended.
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

/// Record rows that refuse every put.
struct Refusing(Mem);

impl RecordRows for Refusing {
    fn record_put(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
        _value: &RecordBytes,
    ) -> Result<(), StoreError> {
        Err(StoreError::Unavailable)
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        self.0.record_get(schema, key)
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        self.0.record_scan(schema, prefix, limit)
    }
}

/// The answers writes got, in order.
type Answers = Arc<Mutex<Vec<Result<(), &'static str>>>>;

/// The answers of writes, in the order they came.
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
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&r.store))), r.store.clone())
        .with_pool(Arc::new(Arc::clone(&held)));
    s.admit(
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
    // Queued, readable, and NOT answered: the store has not taken it.
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(held.drain(), 1);
    assert_eq!(*got.lock().unwrap(), vec![Ok(())]);
    let stored = r.store.record_get(KIND, &record_key("inst", b"k")).unwrap();
    assert!(stored.is_some());
}

#[test]
fn a_write_the_store_refuses_answers_failed_and_leaves_the_overlay() {
    let store = Arc::new(MemoryStore::new());
    let held = Arc::new(Held::default());
    let s = KernelServices::new()
        .with_records(Arc::new(Refusing(Mem(Arc::clone(&store)))), store.clone())
        .with_pool(Arc::new(Arc::clone(&held)));
    s.admit(
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

/// Kernel services over `store`, on `pool`, with "inst" declaring the one kind.
fn writer(store: &Arc<MemoryStore>, pool: Arc<dyn Offload>) -> KernelServices {
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(store))), store.clone())
        .with_pool(pool);
    s.admit(
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
    let backing = Arc::new(MemoryStore::new());
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
    // After the restart: nothing queued, every key once, with its last value.
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
    let backing = Arc::new(MemoryStore::new());
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
    // The refused write never touched the overlay: the queued v1 still reads.
    assert_eq!(
        run(|l| s.records_get(&me, "approval", b"k", l)).bytes,
        b"v1"
    );
    // One flush, in batches of at most the cap, carries the whole queue, v1 included.
    assert_eq!(held.drain(), 1);
    assert_eq!(s.pending().queued(), 0);
    let stored = backing.record_get(KIND, &record_key("inst", b"k")).unwrap();
    assert_eq!(stored.map(|v| v.as_slice().to_vec()), Some(b"v1".to_vec()));
}

#[test]
fn the_tick_restarts_a_flush_the_pool_did_not_run() {
    let backing = Arc::new(MemoryStore::new());
    let held = Arc::new(Held::default());
    let s = writer(&backing, Arc::new(Arc::clone(&held)));
    let (got, acked) = answers();
    s.record_write(&caller("inst"), "approval", b"k", record("v"), acked())
        .unwrap();
    // The pool drops the flush unrun: the write stays queued and unanswered.
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
    // A crash: every in-memory structure gone, only the store survives.
    let c = Arc::clone(&r.clock);
    let fresh = writer(&r.store, Arc::new(Inline))
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    assert_eq!(fresh.pending().queued(), 0);
    assert_eq!(claim(&fresh).value, svc::CLAIM_TAKEN);
}

use crate::host_claims::{Answer as ClaimAnswer, Claim, ClaimLater};

/// A claim's answers, in the order they came.
type Claims = Arc<Mutex<Vec<Claim>>>;

fn claim_sink() -> (Claims, impl Fn() -> ClaimLater) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = Arc::clone(&got);
    (got, move || {
        let g = Arc::clone(&g);
        Box::new(move |c| g.lock().unwrap().push(c)) as ClaimLater
    })
}

/// One claim on the rig's inline pool, answered at once.
fn claim_now(s: &KernelServices, who: &str, ttl_ms: u64, held: Option<u64>) -> Claim {
    let (got, later) = claim_sink();
    let ran = s.claim_own(who, "auth-replay", b"k", ttl_ms, held, u64::MAX, later());
    assert_eq!(ran, ClaimAnswer::Later);
    let c = got.lock().unwrap().pop();
    c.expect("the inline pool answered")
}

fn admitted(r: &Rig, label: &str) {
    r.s.admit(label, InstanceFacts::default()).unwrap();
}

#[test]
fn two_claimants_of_one_key_get_one_won() {
    let r = rig();
    let first = claim_now(&r.s, "inst", 2_000, None);
    assert!(matches!(first, Claim::Won { epoch: 1, .. }));
    let second = claim_now(&r.s, "inst", 2_000, None);
    assert!(matches!(second, Claim::Taken { until_ns } if until_ns > 0));
}

#[test]
fn expiry_hands_the_claim_over_with_a_higher_epoch() {
    let r = rig();
    assert!(matches!(
        claim_now(&r.s, "inst", 2_000, None),
        Claim::Won { epoch: 1, .. }
    ));
    // Past the hold and its one-second guard band.
    r.clock.fetch_add(3_000, Ordering::SeqCst);
    assert!(matches!(
        claim_now(&r.s, "inst", 2_000, None),
        Claim::Won { epoch: 2, .. }
    ));
}

#[test]
fn another_instances_claim_on_the_same_key_is_its_own() {
    let r = rig();
    admitted(&r, "other");
    assert!(matches!(
        claim_now(&r.s, "inst", 2_000, None),
        Claim::Won { epoch: 1, .. }
    ));
    assert!(matches!(
        claim_now(&r.s, "other", 2_000, None),
        Claim::Won { epoch: 1, .. }
    ));
    // An instance never admitted is Taken at once, never pended.
    let (_, later) = claim_sink();
    let ran = r.s.claim_own(
        "stranger",
        "auth-replay",
        b"k",
        2_000,
        None,
        u64::MAX,
        later(),
    );
    assert_eq!(ran, ClaimAnswer::Now(Claim::Taken { until_ns: 0 }));
}

#[test]
fn claims_left_pending_on_the_pool_never_both_win() {
    let r = rig();
    let held = Arc::new(Held::default());
    let c = Arc::clone(&r.clock);
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&r.store))), r.store.clone())
        .with_pool(Arc::new(Arc::clone(&held)))
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    s.admit("inst", InstanceFacts::default()).unwrap();
    let (got, later) = claim_sink();
    for _ in 0..2 {
        let ran = s.claim_own("inst", "auth-replay", b"k", 2_000, None, u64::MAX, later());
        assert_eq!(ran, ClaimAnswer::Later);
    }
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(held.drain(), 2);
    let answers = got.lock().unwrap().clone();
    let won = answers
        .iter()
        .filter(|c| matches!(c, Claim::Won { .. }))
        .count();
    assert_eq!((answers.len(), won), (2, 1));
}

#[test]
fn a_won_answer_past_the_callers_deadline_is_taken() {
    let r = rig();
    let held = Arc::new(Held::default());
    let c = Arc::clone(&r.clock);
    let s = KernelServices::new()
        .with_records(Arc::new(Mem(Arc::clone(&r.store))), r.store.clone())
        .with_pool(Arc::new(Arc::clone(&held)))
        .with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    s.admit("inst", InstanceFacts::default()).unwrap();
    let (got, later) = claim_sink();
    let deadline_ns = r.clock.load(Ordering::SeqCst) * 1_000_000 + 1;
    s.claim_own(
        "inst",
        "auth-replay",
        b"k",
        2_000,
        None,
        deadline_ns,
        later(),
    );
    r.clock.fetch_add(1, Ordering::SeqCst);
    held.drain();
    assert!(matches!(got.lock().unwrap()[0], Claim::Taken { .. }));
}

#[test]
fn the_holder_extends_but_a_stale_holder_after_handover_is_refused() {
    let r = rig();
    let Claim::Won { epoch: 1, until_ns } = claim_now(&r.s, "inst", 2_000, None) else {
        panic!("the first claim wins");
    };
    // The holder, well before its guard band, extends and keeps its epoch.
    let extended = claim_now(&r.s, "inst", 20_000, Some(1));
    assert!(matches!(extended, Claim::Won { epoch: 1, until_ns: u } if u > until_ns));
    // Past the extended hold and its guard: a new claimant wins epoch 2.
    r.clock.fetch_add(20_000 + 2_000, Ordering::SeqCst);
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, None),
        Claim::Won { epoch: 2, .. }
    ));
    // The old holder's extend of epoch 1 is refused.
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, Some(1)),
        Claim::Taken { .. }
    ));
    // The new holder extends.
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, Some(2)),
        Claim::Won { epoch: 2, .. }
    ));
}

#[test]
fn inside_the_guard_band_neither_an_extend_nor_a_claim_holds() {
    let r = rig();
    // A 20 s hold has a 2 s guard band.
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, None),
        Claim::Won { epoch: 1, .. }
    ));
    // 19 s in: past until - guard, so the holder may not extend.
    r.clock.fetch_add(19_000, Ordering::SeqCst);
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, Some(1)),
        Claim::Taken { .. }
    ));
    // 21 s in: past until, but not until + guard, so no claimant may win.
    r.clock.fetch_add(2_000, Ordering::SeqCst);
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, None),
        Claim::Taken { .. }
    ));
    // 22 s in: the band is over.
    r.clock.fetch_add(1_000, Ordering::SeqCst);
    assert!(matches!(
        claim_now(&r.s, "inst", 20_000, None),
        Claim::Won { epoch: 2, .. }
    ));
}

#[test]
fn an_empty_key_or_a_zero_ttl_is_taken_at_once() {
    let r = rig();
    let (got, later) = claim_sink();
    let refused = ClaimAnswer::Now(Claim::Taken { until_ns: 0 });
    assert_eq!(
        r.s.claim_own("inst", "auth-replay", b"", 1_000, None, u64::MAX, later()),
        refused
    );
    assert_eq!(
        r.s.claim_own("inst", "auth-replay", b"k", 0, None, u64::MAX, later()),
        refused
    );
    assert!(got.lock().unwrap().is_empty());
}

use crate::host_units::UnitRecord;
use busbar_contract::records::{ScopeRef, VirtualKey};

/// A live key granted `grants`, each `(kind, name)`.
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

/// Admit `unit` with `principal` and ask whether it is entitled to `target`.
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

/// The items of a two-item catalogue the principal sees.
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
fn an_undeclared_scope_kind_is_not_entitled() {
    let r = rig();
    // Even an ungoverned unit is entitled to nothing of a kind its plane does not declare.
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

// ── THE DESTINATION GUARD AS THE KERNEL'S JUDGE (OWNER DESTINATION GUARD): the kernel asks the
// judge the root installed; its rules are the connector's, never the kernel's ──

/// A judge that refuses `10.0.0.5` as internal and admits every other literal, recording what it
/// was asked.
#[derive(Default)]
struct FakeGuard(Mutex<Vec<String>>);

impl DestJudge for FakeGuard {
    fn judge_name(&self, dest: &str, _class: u32, _refuse_private: bool) -> Result<(), u64> {
        self.0.lock().unwrap().push(dest.to_owned());
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

/// RED: with a judge installed, `dest.judge` answers the judge's refusal; the kernel's own
/// (permissive) class rules are never consulted, under any class.
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
        s.judge_dial("10.0.0.5:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_INTERNAL))
    );
    assert!(guard.0.lock().unwrap().len() >= 3);
}

/// RED: the judge's admission is `dest.judge`'s answer too, with the addresses it judged.
#[test]
fn dest_judge_answers_the_installed_guard_admission() {
    let s = KernelServices::new().with_dest_judge(Arc::new(FakeGuard::default()));
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
        s.judge_dial("api.example.com:443", 0, Box::new(|_| {})),
        Some(Ok("93.184.216.34:443".parse().unwrap()))
    );
}
