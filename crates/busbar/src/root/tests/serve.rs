// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::host::service as svc;
use busbar_contract::abi::mechanism::call::Outcome;

use super::*;

/// A kernel stand-in whose `dest.judge` answers READY, so an installed service is told apart from
/// the late refusal.
struct Judges;

impl HostServices for Judges {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 7,
            mono_ns: 7,
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        Ran::Now(Stored::ready(1))
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(2))
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(Stored::ready(3))
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(Stored::ready(4))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::ready(5)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::ready(6))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::ready(7)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::ready(10)
    }
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        Stored::ready(8)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::ready(9)
    }
    fn records_secret(&self, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::ready(11))
    }
    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        Ran::Now(Stored::ready(12))
    }
    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(13))
    }
    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(14))
    }
    fn work_settle(&self, _: &Caller, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(15))
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        Ran::Now(Stored::ready(16))
    }
}

fn judged(s: &LateServices) -> Stored {
    match s.dest_judge("https://example.test/", 0, 0, None) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("the late services never pend"),
    }
}

#[test]
fn a_service_called_before_the_install_answers_refused_and_never_panics() {
    let late = LateServices::new();
    assert_eq!(judged(&late), Stored::refused(NOT_INSTALLED));
    let a = late.now();
    let b = late.now();
    assert!(a.wall_ns > 1_600_000_000_000_000_000, "the system clock");
    assert!(b.mono_ns >= a.mono_ns);
}

#[test]
fn the_installed_services_answer_and_a_second_install_is_refused() {
    let late = LateServices::new();
    late.install(Arc::new(Judges)).expect("the first install");
    assert_eq!(
        judged(&late),
        Stored::ready(1),
        "the installed services answer"
    );
    assert_eq!(late.now().wall_ns, 7);
    assert_eq!(
        late.install(Arc::new(Judges)),
        Err(AlreadyInstalled),
        "a second install is refused"
    );
    assert!(late.is_installed());
}

/// Every caller-scoped service's answer, in the order [`Judges`] numbers them.
fn every_service(s: &LateServices) -> Vec<Stored> {
    let caller = Caller {
        instance: Arc::from("the-instance"),
        plugin: Arc::from("the-plugin"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    };
    let now = |ran| match ran {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("the late services never pend"),
    };
    let list = RecordsList {
        kind: "k".to_string(),
        prefix: Vec::new(),
        after: None,
        limit: 0,
    };
    vec![
        now(s.records_get(&caller, "k", b"key", Box::new(|_| {}))),
        now(s.records_list(&caller, list, Box::new(|_| {}))),
        now(s.records_claim(&caller, "k", b"key", 1, Box::new(|_| {}))),
        s.sign(&caller, b"data"),
        now(s.trust_sight(&caller, "peer", "hash", Box::new(|_| {}))),
        s.trust_due(&caller),
        s.entitlement_check(&caller, None, "model:m"),
        s.random_fill(16),
        s.trust_verify(&caller, "peer", b"payload", b"[]"),
        now(s.records_secret("sigv4", "AKID", Box::new(|_| {}))),
    ]
}

/// The late services are the installed services for every service the host table serves, not
/// `clock.now` and `dest.judge` alone; before the install each answers REFUSED.
#[test]
fn every_service_is_the_installed_services_answer() {
    let late = LateServices::new();
    let before = every_service(&late);
    assert!(before.iter().all(|s| *s == Stored::refused(NOT_INSTALLED)));
    late.install(Arc::new(Judges)).expect("the install");
    let after = every_service(&late);
    assert!(after.iter().all(|s| s.outcome == Outcome::Ready));
    let values: Vec<u64> = after.iter().map(|s| s.value).collect();
    assert_eq!(values, (2..=11).collect::<Vec<u64>>());
}

fn kernel(blocked: &[&str], allow_all: bool) -> KernelServices {
    let d = busbar_kernel::config::Destinations {
        block_private_addresses: true,
        blocked: blocked.iter().map(|h| (*h).to_string()).collect(),
        allow_all_metadata: allow_all,
        ..Default::default()
    };
    kernel_services(crate::root::connector::guard_for(&d).expect("the guard"))
}

fn verdict(s: &dyn HostServices, dest: &str, class: u32) -> Stored {
    match s.dest_judge(dest, class, 0, None) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("an unresolved judgement answers at once"),
    }
}

/// `dest.judge` asks the deployment's one destination guard: the metadata denylist with the
/// operator's additions and override, private addresses refused by default, plaintext to a public
/// host judged by its host (the default class takes its target's scheme); a class the guard does
/// not know is refused.
#[test]
fn dest_judge_asks_the_deployments_one_guard() {
    let late = LateServices::new();
    late.install(Arc::new(kernel(&["metadata.corp.example"], false)))
        .expect("the install");
    let judged = |dest| verdict(late.as_ref(), dest, DEFAULT_EGRESS_CLASS).value;
    assert_eq!(
        judged("https://169.254.169.254/latest/meta-data/"),
        svc::DEST_METADATA
    );
    assert_eq!(
        judged("https://metadata.corp.example/"),
        svc::DEST_METADATA,
        "the operator's own addition to the denylist"
    );
    assert_eq!(judged("https://10.0.0.7/"), svc::DEST_INTERNAL);
    assert_eq!(judged("http://93.184.216.34/"), svc::DEST_ALLOWED);
    assert_eq!(
        verdict(late.as_ref(), "https://93.184.216.34/", 9).value,
        svc::DEST_NO_HOST,
        "a class the guard does not know dials nothing"
    );
    // `allow_all_metadata` is 1.5.5's nuclear override: for a provider dial the metadata guard is
    // fully disabled, the operator's additions and the metadata address alike; every other class
    // still refuses; with it off the address stays refused.
    let open = kernel(&["metadata.corp.example"], true);
    let provider = busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER;
    let admitted = |dest| verdict(&open, dest, provider).value;
    assert_eq!(
        verdict(
            &open,
            "https://169.254.169.254/latest/meta-data/",
            DEFAULT_EGRESS_CLASS
        )
        .value,
        svc::DEST_METADATA,
        "allow_all_metadata speaks for provider dials only"
    );
    assert_eq!(
        admitted("https://metadata.corp.example/"),
        svc::DEST_ALLOWED
    );
    assert_eq!(
        admitted("https://169.254.169.254/latest/meta-data/"),
        svc::DEST_ALLOWED,
        "allow_all_metadata admits the metadata address, as 1.5.5 did"
    );
    let shut = kernel(&[], false);
    assert_eq!(
        verdict(
            &shut,
            "https://169.254.169.254/latest/meta-data/",
            DEFAULT_EGRESS_CLASS
        )
        .value,
        svc::DEST_METADATA,
        "without the override the metadata address is refused"
    );
}

// ── the caller side over today's ingress (TRANSITIONAL) ──────────────────────────────────────────

/// The head becomes the response's status and fields; the writes become its body, in order.
#[tokio::test]
async fn the_ingress_caller_answers_with_the_units_head_and_bytes() {
    let (caller, reply) = IngressCaller::new();
    let unit = async {
        caller.head(201, vec![(b"x-plane".to_vec(), b"one".to_vec())]);
        assert!(caller.write(b"hello ").await);
        assert!(caller.write(b"world").await);
        drop(caller);
    };
    let handler = async {
        let response = reply.response().await.expect("a head");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-plane"], "one");
        axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body")
    };
    let ((), body) = tokio::join!(unit, handler);
    assert_eq!(&body[..], b"hello world");
}

/// A WHOLE ANSWER STATES ITS LENGTH (1.5.5 parity: a buffered answer went out under
/// `content-length`, never chunked): a head that states its length (one the plane rendered in full)
/// is collected to its end and sent under the length of what was written; an event stream, and an
/// answer that states no length, go out piece by piece. RED before: every answer streamed.
#[tokio::test]
async fn a_whole_answer_is_sent_under_its_length_and_a_stream_piece_by_piece() {
    use http_body::Body as _;
    let cases: [(HeadFields, Option<u64>); 3] = [
        (
            vec![
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"content-length".to_vec(), b"99".to_vec()),
            ],
            Some(11),
        ),
        (
            vec![
                (b"content-type".to_vec(), b"text/event-stream".to_vec()),
                (b"content-length".to_vec(), b"11".to_vec()),
            ],
            None,
        ),
        (
            vec![(b"content-type".to_vec(), b"application/json".to_vec())],
            None,
        ),
    ];
    for (fields, length) in cases {
        let (caller, reply) = IngressCaller::new();
        let caller = Arc::new(caller);
        let writer = Arc::clone(&caller);
        let unit: DrivenUnit = Box::pin(async move {
            writer.head(200, fields);
            assert!(writer.write(b"hello ").await);
            assert!(writer.write(b"world").await);
            None
        });
        drop(caller);
        let response = reply.answer(unit).await;
        assert_eq!(
            response.body().size_hint().exact(),
            length,
            "the length stated, or none"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        assert_eq!(&body[..], b"hello world");
    }
}

/// A write resolves only once the body has taken the piece before it: one piece in flight.
#[tokio::test]
async fn an_ingress_write_waits_for_the_body_to_take_the_piece_before_it() {
    use http_body_util::BodyExt;
    let (caller, reply) = IngressCaller::new();
    caller.head(200, Vec::new());
    let mut body = reply.response().await.expect("a head").into_body();
    assert!(caller.write(b"a").await, "the first piece fits the window");
    let second = caller.write(b"b");
    tokio::pin!(second);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut second)
            .await
            .is_err(),
        "the second write waits while the first piece is untaken"
    );
    let first = body.frame().await.expect("a frame").expect("data");
    assert_eq!(first.into_data().expect("bytes").as_ref(), b"a");
    assert!(second.await, "taken: the second write resolves");
}

/// A caller that went away: every write answers `false` (the driver's ClientGone), and a head
/// after it, or a unit that ends without one, panics nowhere.
#[tokio::test]
async fn an_ingress_caller_whose_handler_went_away_answers_false() {
    let (caller, reply) = IngressCaller::new();
    drop(reply);
    caller.head(200, Vec::new());
    assert!(!caller.write(b"x").await);
    let (caller, reply) = IngressCaller::new();
    drop(caller);
    assert!(reply.response().await.is_none(), "no head, no response");
}

/// A status the wire cannot carry is answered as the driver answers a plane fault; a field the
/// wire cannot carry is not sent.
#[tokio::test]
async fn an_ingress_head_the_wire_cannot_carry_is_a_plane_fault() {
    let (caller, reply) = IngressCaller::new();
    caller.head(0, vec![(b"bad name".to_vec(), b"v".to_vec())]);
    drop(caller);
    let response = reply.response().await.expect("a head");
    assert_eq!(
        u32::from(response.status().as_u16()),
        refusal_status(ReasonCode::PlanePanic)
    );
    assert!(response.headers().is_empty());
}

// ── the late attach (ARCHITECT S7-TICK 2026-10-01, ruling A) ─────────────────────────────────────

/// The composed kernel services are kept whole for the plane driver, installed once.
#[test]
fn the_composed_kernel_services_are_kept_for_the_driver() {
    let late = LateServices::new();
    assert!(late.kernel().is_none(), "nothing before the compose");
    let composed = Arc::new(kernel(&[], false));
    late.install_kernel(Arc::clone(&composed), composed.clone())
        .expect("the install");
    assert!(Arc::ptr_eq(&late.kernel().expect("kept"), &composed));
    assert!(late.is_installed());
    assert_eq!(
        late.install_kernel(Arc::new(kernel(&[], false)), Arc::new(kernel(&[], false))),
        Err(AlreadyInstalled)
    );
}

/// A signer that signs every domain: the key id `kid`, the bytes back as the signature.
struct Signs;

impl SignKey for Signs {
    fn sign(&self, _: &str, data: &[u8]) -> Option<(String, Vec<u8>)> {
        Some(("kid".to_string(), data.to_vec()))
    }
}

fn plane(section: &'static str, record_kinds: &'static [&'static str]) -> PlaneDeclaration {
    PlaneDeclaration {
        key: section,
        fallback: false,
        config_section: section,
        scope_kinds: &[],
        subject_noun: section,
        admin_noun: section,
        audit_kind: section,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds,
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    }
}

/// The unprefixed demotion rows belong to the ONE plane declaring the demotion record kind.
#[test]
fn the_demotion_owner_is_the_one_plane_declaring_the_demotion_kind() {
    let (owner, other) = (plane("owner", &[KIND_DEMOTION]), plane("other", &["call"]));
    let twin = plane("twin", &[KIND_DEMOTION]);
    assert_eq!(demotion_owner(&[&other, &owner]), Some("owner"));
    assert_eq!(demotion_owner(&[&other]), None);
    assert_eq!(demotion_owner(&[&owner, &twin]), None, "two owners: none");
}

/// Before the attach an admitted instance's `sign` is REFUSED and its trust state changes are not
/// written down; after it, `sign` is READY under the instance's prefix and a cleared quarantine
/// is written through the pool before it answers. A second attach changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_late_attach_serves_sign_and_writes_trust_changes_down() {
    use busbar_kernel::host_services::{InstanceFacts, Signing};
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;
    let late = LateServices::new();
    let k = Arc::new(kernel(&[], false));
    late.install_kernel(Arc::clone(&k), k).expect("the install");
    let k = late.kernel().expect("kept");
    let entry = TrustEntry {
        pin: None,
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
    };
    let facts = InstanceFacts {
        signing: Some(Signing {
            domain: "cards".to_string(),
            kid_prefix: "k:".to_string(),
        }),
        trust: vec![("peer".to_string(), entry)],
        ..InstanceFacts::default()
    };
    k.admit("owner", facts).expect("admitted");
    let caller = Caller {
        instance: Arc::from("owner"),
        plugin: Arc::from("the-plugin"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    };
    let sight = |hash| {
        let (tx, rx) = std::sync::mpsc::channel();
        match late.trust_sight(
            &caller,
            "peer",
            hash,
            Box::new(move |s| tx.send(s).unwrap()),
        ) {
            Ran::Now(s) => (s.value, false),
            Ran::Later => (
                rx.recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap()
                    .value,
                true,
            ),
        }
    };
    assert_eq!(late.sign(&caller, b"data").outcome, Outcome::Refused);
    assert_eq!(sight("h1"), (svc::TRUST_NEW, false));
    assert_eq!(sight("h2"), (svc::TRUST_DRIFTED, false), "not written down");
    let demotions = Arc::new(DemotionRecord::default());
    attach(
        &late,
        None,
        Some(Arc::new(Signs)),
        &demotions,
        &[&plane("owner", &[KIND_DEMOTION])],
    );
    let signed = late.sign(&caller, b"data");
    assert_eq!(
        (signed.outcome, signed.bytes),
        (Outcome::Ready, b"k:kiddata".to_vec())
    );
    assert_eq!(
        sight("h1"),
        (svc::TRUST_SAME, true),
        "the clearing is written first"
    );
    assert!(
        !k.attach_signer(Arc::new(Signs)),
        "a second attach is refused"
    );
}

/// THE RECORD STORE (ARCHITECT Q-L3B-RECORDS): the late attach binds the configured governance
/// store — opened through its door on the store axis, as boot opens it — as the kernel's record
/// store, its typed records served over its store v3 slots ([`busbar_kernel::host_records::StoreRows`]).
/// A governance store with no door binds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_late_attach_binds_the_governance_store_as_the_record_store() {
    use busbar_contract::kinds::RecordBytes;
    use busbar_contract::store_calls::{StoreAxis as _, StoreDoor};
    use busbar_kernel::host_records::RecordRows as _;
    let axis = crate::root::loader::store_v3::DoorStoreAxis {
        dispatcher: Arc::new(crate::root::loader::dispatch::Dispatcher::new(
            crate::root::loader::dispatch::DispatchConfig::default(),
        )),
        logs: crate::root::boot::plugin_logs().clone(),
        conns: None,
        mint: busbar_kernel::door::op_id,
    };
    let opened = axis
        .open(
            // The build's one linked store, as boot opens the store a config names (no row is a
            // default since Q-STORE (B)).
            StoreDoor::Linked(
                crate::LINKED
                    .stores
                    .first()
                    .expect("the build links a store")
                    .3,
            ),
            "records-attach",
            b"{}",
        )
        .expect("the default store opens through its door");
    let calls = opened.calls.expect("a door-opened store has its v3 slots");

    // The adapter reads back what it wrote, through the store's own record slots.
    let rows = busbar_kernel::host_records::StoreRows(Arc::clone(&calls));
    let schema = busbar_contract::ids::RecordSchemaId::new("attach-probe");
    let value = RecordBytes::new(b"v".to_vec()).expect("a small record");
    let written = tokio::task::spawn_blocking(move || {
        rows.record_put(schema, b"k", &value).expect("put");
        rows.record_get(schema, b"k").expect("get")
    })
    .await
    .expect("the blocking call ran");
    assert_eq!(written.map(|v| v.as_slice().to_vec()), Some(b"v".to_vec()));

    // With the governance store's slots kept, the attach binds it; a second bind is refused.
    let gov = busbar_kernel::governance::GovState::new(Arc::clone(&opened.records), None)
        .expect("governance");
    assert!(gov.attach_store_calls(calls));
    let late = LateServices::new();
    let k = Arc::new(KernelServices::new());
    late.install_kernel(Arc::clone(&k), Arc::clone(&k) as Arc<dyn HostServices>)
        .expect("installed once");
    attach(
        &late,
        Some(&gov),
        None,
        &Arc::new(DemotionRecord::default()),
        &[],
    );
    assert!(
        !k.attach_records(
            Arc::new(busbar_kernel::host_records::StoreRows(
                gov.store_calls().expect("kept")
            )),
            gov.store()
        ),
        "the governance store is already the record store"
    );

    // No door, no slots: nothing is bound.
    let bare = busbar_kernel::governance::GovState::new(
        Arc::new(busbar_kernel::governance::MemoryStore::new()),
        None,
    )
    .expect("governance");
    let late = LateServices::new();
    let k = Arc::new(KernelServices::new());
    late.install_kernel(Arc::clone(&k), Arc::clone(&k) as Arc<dyn HostServices>)
        .expect("installed once");
    attach(
        &late,
        Some(&bare),
        None,
        &Arc::new(DemotionRecord::default()),
        &[],
    );
    assert!(
        k.attach_records(
            Arc::new(busbar_kernel::host_records::StoreRows(Arc::clone(
                &gov.store_calls().expect("kept")
            ))),
            bare.store()
        ),
        "a store with no slots bound nothing"
    );
}
