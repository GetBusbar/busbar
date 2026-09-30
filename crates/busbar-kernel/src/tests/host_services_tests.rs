// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's host services: `clock.now`, and `dest.judge` over the one destination judge, with a
//! resolver the test answers by hand.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A resolver that holds every resolution for the test to answer.
#[derive(Default)]
struct HandResolver {
    asked: AtomicUsize,
    held: Mutex<Vec<Resolved>>,
}

impl Resolve for HandResolver {
    fn resolve(&self, _host: &str, done: Resolved) {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.held.lock().unwrap().push(done);
    }
}

fn services(resolver: Arc<HandResolver>) -> KernelServices {
    let rules = DestRules {
        policy: GuardPolicy::default(),
        denylist: Arc::new(Denylist::new(&[], &[], false)),
    };
    KernelServices::new(HashMap::from([(0, rules)]), resolver)
}

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
    let s = services(Arc::default());
    let a = s.now();
    let b = s.now();
    assert!(a.wall_ns > 1_600_000_000_000_000_000);
    assert!(b.mono_ns >= a.mono_ns);
}

/// 1.5.5 REFUSAL TIMING: a refusal the name decides answers at once, before any resolution, with the
/// verdict the one judge gives.
#[test]
fn dest_judge_refuses_what_the_name_decides_at_once() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    for (dest, want) in [
        (
            "https://169.254.169.254/latest/meta-data/",
            svc::DEST_METADATA,
        ),
        ("https://metadata.google.internal/", svc::DEST_METADATA),
        ("https://[fd00:ec2::254]/", svc::DEST_METADATA),
        ("https://0x7f000001/", svc::DEST_OBFUSCATED),
        ("ftp://files.example/", svc::DEST_SCHEME),
        ("https://10.0.0.7/", svc::DEST_INTERNAL),
        ("https://93.184.216.34/", svc::DEST_ALLOWED),
    ] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge(dest, 0, true, Some(later)));
        assert_eq!(
            (got.outcome, got.value),
            (Stored::ready(0).outcome, want),
            "{dest}"
        );
    }
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
}

/// Every loopback and private SPELLING is refused without resolving, for a class without private
/// addressing: `?`, `#` and `\` end the authority, a trailing root dot and a percent-encoded name are
/// read the way the dialling stack reads them. RED on the reader that ended the authority only at
/// `/`, which judged each of these an unresolved name and allowed it.
#[test]
fn dest_judge_refuses_every_loopback_spelling_without_resolving() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    for dest in [
        "https://127.0.0.1?x",
        "https://localhost#a",
        "https://127.0.0.1./",
        "https://%6c%6fcalhost/",
        "https://10.0.0.5\\x/",
    ] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge(dest, 0, false, Some(later)));
        assert_eq!(
            (got.outcome, got.value),
            (Stored::ready(0).outcome, svc::DEST_INTERNAL),
            "{dest}"
        );
    }
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
}

/// Asked to resolve, a name pends and the address judgement decides the answer; not asked, the
/// name's own judgement is the verdict and nothing resolves.
#[test]
fn dest_judge_resolves_only_when_asked_and_judges_what_answered() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge("https://api.example.com/v1", 0, true, Some(later)),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec!["10.1.2.3".parse().unwrap()]));
    assert_eq!(
        slot.lock().unwrap().as_ref().unwrap().value,
        svc::DEST_INTERNAL
    );

    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge("https://api.example.com/v1", 0, true, Some(later)),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Err("NXDOMAIN".into()));
    assert_eq!(
        slot.lock().unwrap().as_ref().unwrap().value,
        svc::DEST_UNRESOLVABLE
    );

    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://api.example.com/v1", 0, false, Some(later)));
    assert_eq!(got.value, svc::DEST_ALLOWED);
    assert_eq!(r.asked.load(Ordering::SeqCst), 2);
}

#[test]
fn an_egress_class_the_kernel_did_not_map_is_refused() {
    let s = services(Arc::default());
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://a.example/", 7, true, Some(later)));
    assert_eq!(got, Stored::refused("no such egress class"));
}

/// THE JUDGE A DIAL READS: the address it answers is exactly the one the judgement pinned. A name
/// pends and the pin arrives with the answer; an IP literal is its own pin and asks no resolver; a
/// refusal the name decides answers at once; an answered address the rules refuse is refused with
/// the verdict `dest.judge` gives.
#[test]
fn judge_dial_answers_the_pinned_address_the_verdict_judged() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    let pinned = Arc::new(Mutex::new(None));
    let got = Arc::clone(&pinned);
    let now = s.judge_dial(
        "api.example.com:8443",
        0,
        Box::new(move |v| *got.lock().unwrap() = Some(v)),
    );
    assert_eq!(now, None, "a name pends");
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec![
        "93.184.216.34".parse().unwrap(),
        "93.184.216.35".parse().unwrap(),
    ]));
    assert_eq!(
        *pinned.lock().unwrap(),
        Some(Ok("93.184.216.34:8443".parse().unwrap())),
        "the first admissible address, at the named port"
    );

    let got = s.judge_dial("93.184.216.34:443", 0, Box::new(|_| panic!("no pend")));
    assert_eq!(got, Some(Ok("93.184.216.34:443".parse().unwrap())));
    let got = s.judge_dial(
        "metadata.google.internal:80",
        0,
        Box::new(|_| panic!("no pend")),
    );
    assert_eq!(got, Some(Err(svc::DEST_METADATA)));
    assert_eq!(
        r.asked.load(Ordering::SeqCst),
        1,
        "only the name asked the resolver"
    );

    let refused = Arc::new(Mutex::new(None));
    let got = Arc::clone(&refused);
    assert_eq!(
        s.judge_dial(
            "rebind.example:80",
            0,
            Box::new(move |v| *got.lock().unwrap() = Some(v))
        ),
        None
    );
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec!["169.254.169.254".parse().unwrap()]));
    assert_eq!(*refused.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
    assert_eq!(
        s.judge_dial("a.example:1", 7, Box::new(|_| {})),
        Some(Err(svc::DEST_NO_HOST)),
        "an unmapped class dials nothing"
    );
}

fn services_under(resolver: Arc<HandResolver>, denylist: Denylist) -> KernelServices {
    let rules = DestRules {
        policy: GuardPolicy::default(),
        denylist: Arc::new(denylist),
    };
    KernelServices::new(HashMap::from([(0, rules)]), resolver)
}

/// 1.5.5's OVERRIDES, ON THE ONE JUDGE: under `security.allow_all_metadata` the metadata guard is
/// off for `dest.judge` and for the connector's dial alike (both are `judge_dial`): a metadata
/// literal is admitted and pinned, a metadata name is resolved and its metadata answer pinned.
/// RED on the judge that lifted only the denylist and kept the address guard's own metadata refusal.
#[test]
fn allow_all_metadata_admits_metadata_on_the_dial_and_on_dest_judge() {
    let r = Arc::new(HandResolver::default());
    let s = services_under(Arc::clone(&r), Denylist::new(&[], &[], true));
    let imds: SocketAddr = "169.254.169.254:80".parse().unwrap();
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Ok(imds))
    );
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://169.254.169.254/latest", 0, true, Some(later)));
    assert_eq!(got.value, svc::DEST_ALLOWED);

    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "metadata.google.internal:80",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v)),
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("the name was resolved");
    done(Ok(vec![imds.ip()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Ok(imds)));
}

/// A CARVE-OUT lifts exactly what it names: `allow_metadata_hosts: [169.254.169.254]` admits that
/// address (literal, or answered for a name) and nothing else on the list.
#[test]
fn a_metadata_carve_out_admits_only_what_it_names() {
    let r = Arc::new(HandResolver::default());
    let s = services_under(
        Arc::clone(&r),
        Denylist::new(&[], &["169.254.169.254".to_string()], false),
    );
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Ok("169.254.169.254:80".parse().unwrap()))
    );
    assert_eq!(
        s.judge_dial("100.100.100.200:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "rebind.example:80",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v))
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["100.100.100.200".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

/// With no override nothing changes: metadata is refused on the dial, by literal and by answer.
#[test]
fn without_an_override_metadata_stays_refused_on_the_dial() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "rebind.example:80",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v))
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["169.254.169.254".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

/// RULING A ON THE DIAL: every resolved address is judged by the same lists the configuration check
/// reads, operator-blocked addresses included. A name answering an address in
/// `security.blocked_metadata_hosts` is refused on the dial, exactly as the literal is.
#[test]
fn an_operator_blocked_answer_is_refused_on_the_dial() {
    let r = Arc::new(HandResolver::default());
    let s = services_under(
        Arc::clone(&r),
        Denylist::new(&["93.184.216.34".to_string()], &[], false),
    );
    assert_eq!(
        s.judge_dial("93.184.216.34:443", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "blocked.example:443",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v))
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["93.184.216.34".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

// ── records, sign, trust ─────────────────────────────────────────────────────────────────────

use std::sync::atomic::AtomicU64;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::kinds::{RecordBytes, StoreError};

use crate::governance::MemoryStore;
use crate::trust::reverify::Policy;
use crate::trust::section::{DeclaredPin, TrustEntry};

/// The memory store's typed record reads.
struct Mem(Arc<MemoryStore>);

impl RecordReads for Mem {
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
    let s = services(Arc::default())
        .with_records(
            Arc::new(Mem(Arc::clone(&store))),
            store.clone(),
            Arc::new(Inline),
        )
        .with_signer(Arc::new(FixedKey))
        .with_demotions(demotions(&store))
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
        },
    );
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

fn put(store: &MemoryStore, key: &str, value: &str) {
    store
        .record_put(
            KIND,
            key.as_bytes(),
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
    r.s.pending()
        .enqueue("inst", "approval", b"k", Some(b"mine".to_vec()));
    let s = run(|l| r.s.records_get(&me, "approval", b"k", l));
    assert_eq!(s.bytes, b"mine");
    let seq = r.s.pending().enqueue("inst", "approval", b"k", None);
    assert_eq!(
        run(|l| r.s.records_get(&me, "approval", b"k", l)).value,
        svc::ABSENT
    );
    r.s.pending().acked("inst", seq);
    assert_eq!(
        run(|l| r.s.records_get(&me, "approval", b"k", l)).bytes,
        b"stored"
    );
    assert_eq!(
        run(|l| r.s.records_get(&me, "approval", b"none", l)).value,
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
    r.s.pending().enqueue("inst", "approval", b"a2", None);
    r.s.pending()
        .enqueue("inst", "approval", b"a3", Some(b"q".to_vec()));
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
    assert_eq!(s.bytes, b"a1sa3q");
    assert_eq!(s.spans.len(), 2);
    assert_eq!((s.spans[1].key_off, s.spans[1].value_off), (3, 5));
    assert_eq!(list(Some("a1"), 0).bytes, b"a3q");
    assert_eq!(list(None, 1).bytes, b"a1s");
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
    );
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
    let s = services(Arc::default());
    s.admit(
        "inst",
        InstanceFacts {
            record_kinds: vec![KIND],
            ..InstanceFacts::default()
        },
    );
    let a = run(|l| s.records_claim(&caller("inst"), "approval", b"k", 1, l));
    assert_eq!((a.outcome, a.error), (Outcome::Refused, NO_STORE));
}

#[test]
fn sign_signs_under_the_declared_domain_with_the_prefixed_key_id() {
    let r = rig();
    let s = r.s.sign(&caller("inst"), b"data");
    assert_eq!(s.outcome, Outcome::Ready);
    assert_eq!(s.bytes, b"p-K1dom:data");
    assert_eq!((s.spans[0].key_off, s.spans[0].key_len), (0, 4));
    assert_eq!((s.spans[0].value_off, s.spans[0].value_len), (4, 8));
}

#[test]
fn sign_is_refused_without_a_declared_domain_or_a_key() {
    let r = rig();
    r.s.admit("plain", InstanceFacts::default());
    let s = r.s.sign(&caller("plain"), b"x");
    assert_eq!((s.outcome, s.error), (Outcome::Refused, NO_DOMAIN));
    let keyless = services(Arc::default());
    keyless.admit(
        "inst",
        InstanceFacts {
            signing: Some(Signing {
                domain: "d".into(),
                kid_prefix: String::new(),
            }),
            ..InstanceFacts::default()
        },
    );
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
    let demoted = r.s.demotions.as_ref().unwrap().list();
    assert_eq!(demoted.len(), 1);
    assert_eq!(demoted[0].server, "cp");
    assert_eq!(sight("moved").value, svc::TRUST_QUARANTINED);
    assert_eq!(sight("fp").value, svc::TRUST_SAME);
    assert!(r.s.demotions.as_ref().unwrap().list().is_empty());
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
    let fresh =
        services(Arc::default()).with_demotions(Arc::clone(r.s.demotions.as_ref().unwrap()));
    fresh.admit(
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
    );
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
    assert_eq!((s.spans[0].key_off, s.spans[0].key_len), (0, 2));
    assert_eq!(
        s.spans[0].value_off,
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
        },
    );
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
    );
    r.s.pending()
        .enqueue("inst", "approval", b"k", Some(b"mine".to_vec()));
    let s = run(|l| r.s.records_get(&caller("third"), "approval", b"k", l));
    assert_eq!(s.value, svc::ABSENT);
}
