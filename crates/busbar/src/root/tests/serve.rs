// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::services::codes::service as svc;

use super::*;

#[test]
fn recovery_work_header_cannot_be_supplied_by_an_external_caller() {
    assert!(!keep_arrival_field(b"x-busbar-recovery-work"));
    assert!(!keep_arrival_field(b"X-Busbar-Recovery-Work"));
    assert!(keep_arrival_field(b"content-type"));
}

#[test]
fn duplicate_plane_routes_fail_with_the_listener_method_and_resolution() {
    use busbar_contract::abi::{
        auth::AuthPoints,
        transport::route::{METHOD_GET, PATH_EXACT},
    };
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
    let line = |plane: &str| Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: "/v1/models".into(),
            fields: vec![],
            rung: 0,
        },
        claimant: Claimant::Plane(plane.into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: AuthPoints::HEAD,
    };
    let refusal = GuestList::seal(vec![line("one"), line("two")])
        .expect_err("same listener must refuse ambiguous ownership");
    let error = guest_refusal("listen (127.0.0.1:8080)", refusal);
    for required in [
        "127.0.0.1:8080",
        "one",
        "two",
        "GET /v1/models",
        "ingress.listen",
    ] {
        assert!(error.contains(required), "missing {required}: {error}");
    }
    assert!(GuestList::seal(vec![line("one")]).is_ok());
    assert!(
        GuestList::seal(vec![line("two")]).is_ok(),
        "separate listeners admit the two inventories independently"
    );
}

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
    fn trust_unreached(&self, _: &Caller, _: &str) -> Stored {
        Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn trust_sight_item(&self, _: &Caller, _: &str, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::refused(busbar_contract::services::UNSERVED))
    }
    fn trust_decide(
        &self,
        _: &Caller,
        _ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        _: busbar_contract::services::TrustKeyRef<'_>,
        _: Option<&str>,
        _: bool,
        _: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(busbar_contract::services::UNSERVED))
    }
    fn trust_state(&self, _: &Caller, _: &str) -> Stored {
        Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn session_emit(&self, _: &Caller, _: u64, _: &[u8]) -> Stored {
        Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn ticket_mint(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused(busbar_contract::services::UNSERVED))
    }
    fn ticket_take(&self, _: &Caller, _: Option<u64>) -> Stored {
        Stored::refused(busbar_contract::services::UNSERVED)
    }
    fn trust_serves(&self, _: &Caller, _: &str, _: Option<&str>, _: Option<&str>) -> Stored {
        Stored::refused(busbar_contract::services::UNSERVED)
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
    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(15))
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        Ran::Now(Stored::ready(16))
    }
    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(17))
    }
    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        Stored::ready(18)
    }
    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::ready(19))
    }
    fn hook_call(
        &self,
        _: &Caller,
        _: Option<u64>,
        _: busbar_contract::services::HookAsk,
        _: Later,
    ) -> Ran {
        Ran::Now(Stored::ready(20))
    }

    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Later) -> Ran {
        Ran::Now(Stored::ready(12))
    }

    fn snapshot_read(&self, _: &Caller, _: u32, _: Later) -> Ran {
        Ran::Now(Stored::refused(busbar_contract::services::UNSERVED))
    }
}

fn judged(s: &Services) -> Stored {
    match s.served().dest_judge("https://example.test/", 0, 0, None) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("the late services never pend"),
    }
}

#[test]
fn bootstrap_services_answer_refused_and_never_panic() {
    let late = Services::bootstrap();
    assert_eq!(judged(&late), Stored::refused(NOT_INSTALLED));
    let a = late.served().now();
    let b = late.served().now();
    assert!(a.wall_ns > 1_600_000_000_000_000_000, "the system clock");
    assert!(b.mono_ns >= a.mono_ns);
}

#[test]
fn constructed_services_keep_their_provider_when_another_source_is_built() {
    let late = Services::fixture(Arc::new(Judges));
    assert_eq!(
        judged(&late),
        Stored::ready(1),
        "the installed services answer"
    );
    assert_eq!(late.served().now().wall_ns, 7);
    let original = late.served();
    let other = Services::bootstrap();
    assert_eq!(judged(&other), Stored::refused(NOT_INSTALLED));
    assert!(Arc::ptr_eq(&original, &late.served()));
    assert_eq!(judged(&late), Stored::ready(1));
}

fn every_service(late: &Services) -> Vec<Stored> {
    let s = late.served();
    let caller = Caller::for_test(
        Arc::from("the-instance"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
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
        s.random_fill(16),
        s.trust_verify(&caller, "peer", b"payload", b"[]"),
        now(s.records_secret("planted-scheme", "AKID", Box::new(|_| {}))),
    ]
}

#[test]
fn every_service_is_the_installed_services_answer() {
    let late = Services::bootstrap();
    let before = every_service(&late);
    assert!(before.iter().all(|s| *s == Stored::refused(NOT_INSTALLED)));
    let serving = Services::fixture(Arc::new(Judges));
    let after = every_service(&serving);
    assert_eq!(every_service(&late), before, "bootstrap stays restricted");
    assert!(after.iter().all(|s| s.outcome == Outcome::Ready));
    let values: Vec<u64> = after.iter().map(|s| s.value).collect();
    assert_eq!(values, (2..=11).collect::<Vec<u64>>());
}

fn kernel(blocked: &[&str]) -> KernelServices {
    let d = busbar_kernel::config::Destinations {
        block_private_addresses: true,
        blocked: blocked.iter().map(|h| (*h).to_string()).collect(),
        listens: Vec::new(),
    };
    kernel_services(crate::root::connector::guard_for(&d).expect("the guard"))
}

fn verdict(s: &dyn HostServices, dest: &str, class: u32) -> Stored {
    match s.dest_judge(dest, class, 0, None) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("an unresolved judgement answers at once"),
    }
}

#[test]
fn dest_judge_asks_the_deployments_one_guard() {
    let late = Services::serving(Arc::new(kernel(&["metadata.corp.example"])));
    let served = late.served();
    let judged = |dest| verdict(&*served, dest, DEFAULT_EGRESS_CLASS).value;
    assert_eq!(
        judged("https://169.254.169.254/latest/meta-data/"),
        svc::DEST_METADATA
    );
    assert_eq!(
        judged("https://metadata.corp.example/"),
        svc::DEST_METADATA,
        "the operator's own addition to the denylist"
    );
    assert_eq!(judged("https://\x310.0.0.7/"), svc::DEST_INTERNAL);
    assert_eq!(judged("http://93.184.216.34/"), svc::DEST_ALLOWED);
    assert_eq!(
        verdict(&*served, "https://93.184.216.34/", 9).value,
        svc::DEST_NO_HOST,
        "a class the guard does not know dials nothing"
    );

    let provider = busbar_contract::conn::codes::EGRESS_PROVIDER;
    let shut = kernel(&["metadata.corp.example"]);
    for class in [DEFAULT_EGRESS_CLASS, provider] {
        for dest in [
            "https://169.254.169.254/latest/meta-data/",
            "https://metadata.corp.example/",
        ] {
            assert_eq!(
                verdict(&shut, dest, class).value,
                svc::DEST_METADATA,
                "no carve-out exists: {dest} is refused in class {class}"
            );
        }
    }
}

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

#[tokio::test]
async fn after_its_head_the_unit_runs_whether_or_not_its_body_is_read() {
    let (caller, reply) = IngressCaller::new();
    let (ended, told) = tokio::sync::oneshot::channel();
    let unit: DrivenUnit = Box::pin(async move {
        caller.head(
            200,
            vec![(b"content-type".to_vec(), b"text/event-stream".to_vec())],
        );
        assert!(
            caller.write(b"one").await,
            "the first piece fits the window"
        );
        let stalled =
            tokio::time::timeout(std::time::Duration::from_millis(50), caller.write(b"two")).await;
        let _ = ended.send(stalled.is_err());
        None
    });
    let response = reply.answer(unit).await;
    let stalled = tokio::time::timeout(std::time::Duration::from_secs(5), told)
        .await
        .expect("the unit ran on with its body unread")
        .expect("the unit said how its write went");
    assert!(
        stalled,
        "the second write waited on the unread body until the unit's own timer"
    );
    drop(response);
}

#[tokio::test]
async fn dropping_the_body_drops_the_unit_and_a_read_body_carries_every_piece() {
    struct Gone(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Gone {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let (caller, reply) = IngressCaller::new();
    let (tx, dropped) = tokio::sync::oneshot::channel();
    let unit: DrivenUnit = Box::pin(async move {
        let _gone = Gone(Some(tx));
        caller.head(200, Vec::new());
        assert!(caller.write(b"one").await);
        std::future::pending::<()>().await;
        None
    });
    let response = reply.answer(unit).await;
    drop(response);
    tokio::time::timeout(std::time::Duration::from_secs(5), dropped)
        .await
        .expect("the unit was dropped with its body")
        .expect("dropped, not leaked");

    let (caller, reply) = IngressCaller::new();
    let unit: DrivenUnit = Box::pin(async move {
        caller.head(200, Vec::new());
        for piece in [&b"a"[..], b"b", b"d"] {
            assert!(caller.write(piece).await);
        }
        None
    });
    let response = reply.answer(unit).await;
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body");
    assert_eq!(&body[..], b"abd");
}

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

#[test]
fn the_composed_kernel_services_are_kept_for_the_driver() {
    let bootstrap = Services::bootstrap();
    assert!(
        bootstrap.kernel().is_none(),
        "bootstrap has no serving kernel"
    );
    let composed = Arc::new(kernel(&[]));
    let serving = Services::serving(Arc::clone(&composed));
    assert!(Arc::ptr_eq(&serving.kernel().expect("kept"), &composed));
    let other = Services::serving(Arc::new(kernel(&[])));
    assert!(!Arc::ptr_eq(&other.kernel().expect("other"), &composed));
    assert!(Arc::ptr_eq(
        &serving.kernel().expect("still kept"),
        &composed
    ));
    assert!(
        bootstrap.kernel().is_none(),
        "construction grants bootstrap no authority"
    );
}

struct Signs;

impl SignKey for Signs {
    fn sign(&self, _: &str, data: &[u8], out: &mut Vec<u8>) -> Option<usize> {
        out.extend_from_slice(data);
        out.extend_from_slice(b"kid");
        Some(data.len())
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
        class_parents: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds,
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    }
}

#[test]
fn the_demotion_owner_is_the_one_plane_declaring_the_demotion_kind() {
    let (owner, other) = (plane("owner", &[KIND_DEMOTION]), plane("other", &["call"]));
    let twin = plane("twin", &[KIND_DEMOTION]);
    assert_eq!(demotion_owner(&[&other, &owner]), Some("owner"));
    assert_eq!(demotion_owner(&[&other]), None);
    assert_eq!(demotion_owner(&[&owner, &twin]), None, "two owners: none");
}

#[tokio::test(flavor = "multi_thread")]
async fn constructed_services_sign_and_write_trust_changes_down() {
    use busbar_kernel::host_services::{InstanceFacts, Signing};
    use busbar_kernel::trust::book::{Reviewed, Ruling};
    use busbar_kernel::trust::reverify::Policy;
    use busbar_kernel::trust::section::TrustEntry;
    // The operator reviews the key's current `seen` and then decides (r3 §10.1 (R)).
    let current_seen = |k: &KernelServices| {
        k.trust_rows()
            .into_iter()
            .find(|row| row.key() == "owner/peer")
            .and_then(|row| row.seen)
    };
    // Decisions need bound custody (r3 §10.1 (F), A-C1): a record over an in-memory Store whose
    // owner is not this caller, so this source's drift is still not written down.
    let custody = Arc::new(busbar_kernel::trust::DemotionRecord::default());
    custody
        .set_store(crate::root::real_store::core().await)
        .expect("a fresh record attaches");
    let late = Services::serving(Arc::new(kernel(&[]).with_demotions(custody, "")));
    let k = late.kernel().expect("kept");

    let entry = TrustEntry {
        pin: Some(busbar_kernel::trust::section::DeclaredPin {
            mechanism: "fingerprint".into(),
            root: false,
            peer_key: false,
            key: None,
            fingerprint: Some("h1".into()),
        }),
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved: Default::default(),
    };
    let facts = InstanceFacts {
        signing: Some(Signing {
            domain: "cards".to_string(),
            kid_prefix: "k:".to_string(),
        }),
        trust: vec![("peer".to_string(), entry)],
        ..InstanceFacts::default()
    };
    k.admit(&"owner".into(), facts.clone())
        .await
        .expect("admitted");
    let caller = Caller::for_test(
        Arc::from("owner"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    let sight = |hash| {
        let (tx, rx) = std::sync::mpsc::channel();
        match late.served().trust_sight(
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
    assert_eq!(
        late.served().sign(&caller, b"data").outcome,
        Outcome::Refused
    );

    assert_eq!(sight("h1"), (svc::TRUST_NEW, false));
    let seen = current_seen(&k);
    k.trust_rule_by(
        "owner/peer",
        Ruling::Approve,
        seen.as_deref().map_or(Reviewed::Unsighted, Reviewed::Seen),
        "op",
        None,
    )
    .await
    .result
    .expect("approved");
    assert_eq!(sight("h1"), (svc::TRUST_SAME, false));
    assert_eq!(sight("h2"), (svc::TRUST_DRIFTED, false), "not written down");
    let demotions = Arc::new(busbar_kernel::trust::DemotionRecord::default());
    demotions
        .set_store(crate::root::real_store::core().await)
        .expect("the native Store owns trust changes");
    let complete = Services::serving(Arc::new(
        kernel(&[])
            .with_signer(Arc::new(Signs))
            .with_demotions(Arc::clone(&demotions), "owner")
            .with_pool(Arc::new(BlockingPool::new(
                tokio::runtime::Handle::current(),
                QUEUE_CAP,
            ))),
    ));
    let complete_kernel = complete.kernel().expect("complete kernel");
    complete_kernel
        .admit(&"owner".into(), facts)
        .await
        .expect("complete admission");
    let complete_sight = |hash| {
        let (tx, rx) = std::sync::mpsc::channel();
        match complete.served().trust_sight(
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
    assert_eq!(complete_sight("h1"), (svc::TRUST_NEW, false));
    let seen = current_seen(&complete_kernel);
    complete_kernel
        .trust_rule_by(
            "owner/peer",
            Ruling::Approve,
            seen.as_deref().map_or(Reviewed::Unsighted, Reviewed::Seen),
            "op",
            None,
        )
        .await
        .result
        .expect("complete approved");
    assert_eq!(complete_sight("h1"), (svc::TRUST_SAME, false));
    assert_eq!(
        complete_sight("h2"),
        (svc::TRUST_DRIFTED, true),
        "drift is written down"
    );
    let signed = complete.served().sign(&caller, b"data");
    assert_eq!(
        (signed.outcome, signed.bytes.as_slice()),
        (Outcome::Ready, b"k:kiddata".as_slice())
    );
    assert_eq!(
        complete_sight("h1"),
        (svc::TRUST_SAME, true),
        "the clearing is written first"
    );
    assert!(Arc::ptr_eq(&late.kernel().expect("original"), &k));
    assert_eq!(
        late.served().sign(&caller, b"data").outcome,
        Outcome::Refused,
        "another source cannot grant signing authority to the original"
    );
    assert_eq!(
        sight("h1"),
        (svc::TRUST_SAME, false),
        "original source remains non-durable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn constructed_services_keep_their_governance_record_store() {
    use busbar_kernel::persistence::scoped::ClaimOutcome;
    use busbar_kernel::persistence::scoped::{Outcome, ScopedStore};
    let core = crate::root::real_store::core().await;
    let rows =
        ScopedStore::host_private(core.clone(), "busbar.attach-probe", ["attach-probe"]).unwrap();
    assert_eq!(
        rows.put(
            "attach-probe",
            b"k",
            busbar_contract::Secret::new(b"v".to_vec())
        )
        .await
        .unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        rows.get("attach-probe", b"k")
            .await
            .unwrap()
            .map(|value| value.expose(&busbar_kernel::seal::lend()).clone()),
        Some(b"v".to_vec())
    );
    let now = busbar_kernel::store::now();
    let claims = [
        rows.redeem("attach-claim", "t", now + 60).await.unwrap(),
        rows.redeem("attach-claim", "t", now + 60).await.unwrap(),
        rows.redeem("attach-other", "t", now + 60).await.unwrap(),
    ];
    assert!(matches!(
        claims,
        [
            ClaimOutcome::Claimed,
            ClaimOutcome::AlreadyClaimed,
            ClaimOutcome::Claimed
        ]
    ));
    let gov = busbar_kernel::governance::GovState::new_with_core(core.clone(), None, None)
        .await
        .expect("governance");
    let k = Arc::new(
        KernelServices::new()
            .with_persistence(gov.core_store_handle().expect("governance owns the core"))
            .with_pool(Arc::new(BlockingPool::new(
                tokio::runtime::Handle::current(),
                QUEUE_CAP,
            ))),
    );
    let late = Services::serving(Arc::clone(&k));
    let caller = Caller::for_test(
        Arc::from("record-owner"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    k.admit(
        &"record-owner".into(),
        busbar_kernel::host_services::InstanceFacts {
            record_kinds: vec![busbar_contract::ids::RecordSchemaId::new("attach-probe")],
            ..Default::default()
        },
    )
    .await
    .expect("the real store accepts declared records");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let read = match late.served().records_get(
        &caller,
        "attach-probe",
        b"missing",
        Box::new(move |answer| {
            let _ = tx.send(answer);
        }),
    ) {
        Ran::Now(answer) => answer,
        Ran::Later => rx.await.expect("native record read finishes"),
    };
    assert_eq!(read, Stored::ready(svc::ABSENT));
    let other = Services::serving(Arc::new(KernelServices::new()));
    assert!(!Arc::ptr_eq(&other.kernel().expect("other"), &k));
    assert!(Arc::ptr_eq(&late.kernel().expect("original retained"), &k));
    let another_store_owner =
        Services::serving(Arc::new(KernelServices::new().with_persistence(core)));
    assert!(Arc::ptr_eq(&late.kernel().expect("still original"), &k));
    assert!(!Arc::ptr_eq(
        &other.kernel().expect("separate"),
        &another_store_owner.kernel().expect("new source")
    ));
}

#[tokio::test]
async fn a_framed_claims_caller_reads_the_deframed_messages() {
    use busbar_kernel::plane_driver::SessionCaller as _;
    let framed = Arrival {
        claim: 0,
        method: b"POST".to_vec(),
        target: b"/framed".to_vec(),
        fields: Default::default(),
        body: bytes::Bytes::from_static(b"\x02ab\x02cd"),
        carrier: 0,
    };
    let messages = vec![b"ab".to_vec(), b"cd".to_vec()];
    let request = busbar_kernel::limits::process_admission::ProcessAdmission::new(0)
        .try_enter(busbar_kernel::limits::process_admission::AdmissionClass::Data)
        .unwrap();
    let (arrival, caller, _reply) = deframed_arrival(framed, messages, &request).unwrap();
    assert_eq!(
        &arrival.body[..],
        b"abcd",
        "the unit arrives with the messages"
    );
    assert_eq!(
        caller.read().await.as_deref(),
        Some(&b"abcd"[..]),
        "the caller leg reads the messages, never the framing"
    );
}

#[tokio::test]
async fn a_budgeted_pipe_moves_custody_through_owned_reads_only() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use busbar_kernel::plane_driver::SessionCaller as _;
    let budget = ProcessAdmission::new(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let (from, received) = mpsc::channel(1);
    let (to, _) = mpsc::channel(1);
    let caller = super::money_tests::PipeEnd {
        from: tokio::sync::Mutex::new(received),
        to,
    };
    let input = request
        .adopt_input(b"owned".to_vec())
        .unwrap()
        .into_session_input();
    assert!(from.send(input).await.is_ok());
    assert!(
        caller.read().await.is_none(),
        "a bare read cannot strip or dequeue ownership"
    );
    let input = caller.read_owned().await.unwrap();
    assert_eq!(input.bytes, b"owned");
    drop(caller);
    drop(from);
    drop(request);
    assert!(
        budget.try_enter(AdmissionClass::Data).is_err(),
        "the detached input still owns its request slot"
    );
    assert!(budget.try_enter(AdmissionClass::Operator).is_ok());
    drop(input);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn a_failed_decoded_gather_retires_every_partial_payload_credit() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let budget = ProcessAdmission::new(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let full = request.try_reserve(224 * 1024 * 1024 - 3).unwrap();
    assert!(gathered_input(vec![b"ab".to_vec(), b"cd".to_vec()], &request).is_err());
    assert!(
        request.try_reserve(3).is_ok(),
        "the refused gather keeps no partial credit"
    );
    drop(full);
}

#[test]
fn an_applied_door_section_carries_its_pools_and_hands_the_plane_no_work_key() {
    let key = "mcp";
    let written: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str("fs: { url: \"http://fs\" }\nwork: { max_live: 4 }\n")
            .expect("a section");
    let pool = busbar_kernel::config::pools::CandidatePoolCfg {
        members: vec!["fs".to_string()],
        ..Default::default()
    };
    let pools = door_pools(&BTreeMap::from([(
        key,
        BTreeMap::from([("files".to_string(), pool)]),
    )]));

    let applied = section_with_pools(key, &written, &pools);
    assert_eq!(
        crate::root::door_steps::DoorPools::of(
            &applied,
            busbar_contract::section::TOOL_CALL_SECTION_KEY
        )
        .expect("the pools")
        .pools()
        .get("files")
        .cloned(),
        Some(vec!["fs".to_string()]),
        "the apply dropped the door's pools"
    );

    assert!(applied.get("work").is_some());
    let handed: serde_json::Value =
        serde_json::from_slice(&handed_settings(&[key], &applied).expect("settings"))
            .expect("json");
    assert!(
        handed.get("work").is_none(),
        "the plane was handed the core-owned work: key: {handed}"
    );
    assert!(handed.get("fs").is_some(), "the plane's own entry is kept");
}

#[cfg(linked_section_pools)]
#[test]
fn an_open_claims_line_takes_no_auth_whatever_the_data_chain() {
    use busbar_contract::route::AuthPoints;
    use busbar_kernel::guest::LineAuth;
    let chain = vec![("keys".to_string(), AuthPoints(0))];
    assert_eq!(line_auth(CLAIM_OPEN, &chain), LineAuth::None);
    assert_eq!(line_auth(CLAIM_OPEN, &[]), LineAuth::None);
    assert_eq!(
        line_auth(CLAIM_OPEN | CLAIM_EXACT, &chain),
        LineAuth::None,
        "openness is a flag of its own, beside the claim's match shape"
    );
}

#[cfg(linked_section_pools)]
#[test]
fn a_claim_that_is_not_open_owes_the_data_chain_configured_or_empty() {
    use busbar_contract::route::AuthPoints;
    use busbar_kernel::guest::LineAuth;
    let chain = vec![("keys".to_string(), AuthPoints(0))];
    let owed = LineAuth::Chain(vec!["keys".to_string()], AuthPoints(0));
    assert_eq!(line_auth(CLAIM_EXACT, &chain), owed);
    assert_eq!(line_auth(CLAIM_PATTERN, &chain), owed);
    assert_eq!(line_auth(0, &chain), owed);
    assert_eq!(
        line_auth(CLAIM_EXACT, &[]),
        LineAuth::Chain(Vec::new(), AuthPoints(0)),
        "an empty chain admits none on a credentialed line; it never opens it"
    );
}

#[tokio::test]
async fn every_declared_stream_type_goes_piece_by_piece() {
    use http_body::Body as _;
    let declared = std::iter::once(busbar_contract::protocol::TEXT_EVENT_STREAM)
        .chain(declared_stream_media());
    for media in declared {
        let fields: HeadFields = vec![
            (b"content-type".to_vec(), media.as_bytes().to_vec()),
            (b"content-length".to_vec(), b"11".to_vec()),
        ];
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
            None,
            "a `{media}` answer goes out piece by piece"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        assert_eq!(&body[..], b"hello world", "the bytes as written");
    }
}

#[test]
fn a_planes_inbound_need_binds_at_the_listen_its_block_states() {
    use crate::root::loader::boot::BindOwner;
    use busbar_contract::conn::codes::{DIRECTION_INBOUND, DIRECTION_OUTBOUND};
    use busbar_contract::rendering::ReadNeed;
    fn need(direction: u32, transport: &str, target_from: &str) -> ReadNeed {
        ReadNeed {
            direction,
            egress_class: 0,
            transport: transport.into(),
            auth: String::new(),
            target_from: target_from.into(),
            trust_from: String::new(),
            details: busbar_contract::rendering::ReadBlob {
                fmt: 0,
                flags: 0,
                bytes: Vec::new(),
            },
            timeout_ms: 0,
            keep_mode: busbar_contract::conn::codes::KEEP_NAMED,
            keep_response_headers: Vec::new(),
            deny_response_headers: Vec::new(),
        }
    }
    let needs = vec![
        need(DIRECTION_OUTBOUND, "out-t", "far"),
        need(DIRECTION_INBOUND, "in-t", "media"),
    ];
    let doc = |yaml: &str| -> BTreeMap<&'static str, busbar_contract::yaml::Value> {
        BTreeMap::from([(
            "a-section",
            busbar_contract::yaml::from_str(yaml).expect("yaml"),
        )])
    };
    let sections =
        doc("far: {listen: \"127.0.0.1:7000\"}\nmedia: {listen: \"127.0.0.1:7001\"}\nquiet: {}\n");
    let binds = super::need_binds("inst", "a-section", &needs, &sections).expect("binds");
    assert_eq!(
        binds.len(),
        1,
        "only the inbound need whose block states a listen"
    );
    let b = &binds[0];
    assert_eq!(b.transport, "in-t");
    assert_eq!(b.at, "a-section.media");
    assert_eq!(b.listen_setting(), "a-section.media.listen");
    assert_eq!(b.listen, "127.0.0.1:7001".parse().unwrap());
    assert!(matches!(
        &b.owner,
        BindOwner::Need { instance, need: 1, .. } if instance == "inst"
    ));
    assert!(
        super::need_binds("inst", "a-section", &needs, &BTreeMap::new())
            .expect("no section")
            .is_empty(),
        "a plane whose section is absent binds nothing"
    );
    assert_eq!(
        super::need_binds(
            "inst",
            "a-section",
            &needs,
            &doc("media: {listen: \"nowhere\"}\n")
        )
        .unwrap_err(),
        "a-section.media.listen: not an ip:port address"
    );
    let mut incomplete = needs.clone();
    incomplete.push(need(DIRECTION_INBOUND, "quiet-t", "quiet"));
    assert_eq!(
        super::need_binds("inst", "a-section", &incomplete, &sections).unwrap_err(),
        "a-section.quiet.listen: not set"
    );
    let undeclared = [need(DIRECTION_INBOUND, "bare-t", "")];
    assert!(
        super::need_binds("inst", "a-section", &undeclared, &sections)
            .unwrap_err()
            .contains("names no settings block")
    );
}

/// THE UNIT ID IS THE REQUEST ID (ADMIN-API-1.6 §3.4, C5): the data plane stamps every answer,
/// whole, streamed or refused, with the node-qualified id its sealed record carries as `unit`;
/// an upstream `x-request-id` a plane forwards is replaced, and two nodes or a restart never
/// share one id.
#[tokio::test]
async fn record_unit_is_request_id() {
    let id = busbar_kernel_audit::UnitId::of(0x0123_4567_89ab_cdef, [0x5f; 16], 42).unwrap();
    let canonical = format!("node_0123456789abcdef.{}.42", "5f".repeat(16));
    assert_eq!(id.to_string(), canonical);

    for streamed in [false, true] {
        let (caller, reply) = IngressCaller::new();
        caller.minted(id);
        let caller = Arc::new(caller);
        let writer = Arc::clone(&caller);
        let content_type: &[u8] = if streamed {
            b"text/event-stream"
        } else {
            b"application/json"
        };
        let unit: DrivenUnit = Box::pin(async move {
            writer.head(
                200,
                vec![
                    (b"content-type".to_vec(), content_type.to_vec()),
                    (b"x-request-id".to_vec(), b"upstream-forwarded".to_vec()),
                ],
            );
            assert!(writer.write(b"ok").await);
            None
        });
        drop(caller);
        let response = reply.answer(unit).await;
        let stamped: Vec<_> = response.headers().get_all("x-request-id").iter().collect();
        assert_eq!(stamped, vec![canonical.as_str()], "streamed: {streamed}");
    }

    let (caller, reply) = IngressCaller::new();
    caller.minted(id);
    let refused: DrivenUnit = Box::pin(async move {
        drop(caller);
        Some(Rendered {
            status: 429,
            fields: Vec::new(),
            body: b"refused".to_vec(),
        })
    });
    let response = reply.answer(refused).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["x-request-id"], canonical.as_str());

    let (_, unminted) = IngressCaller::new();
    let quiet: DrivenUnit = Box::pin(async { None });
    assert!(
        unminted
            .answer(quiet)
            .await
            .headers()
            .get("x-request-id")
            .is_none(),
        "no id is stamped for a unit that was never minted"
    );

    let other_node = busbar_kernel_audit::UnitId::of(0x0123_4567_89ab_cdee, [0x5f; 16], 42);
    let restarted = busbar_kernel_audit::UnitId::of(0x0123_4567_89ab_cdef, [0x60; 16], 42);
    for other in [other_node, restarted] {
        assert_ne!(other.map(|o| o.to_string()), Some(canonical.clone()));
    }
}

#[test]
fn admin_trust_binds_one_kernel() {
    let kernel = Arc::new(KernelServices::new());
    let services = Services::serving(Arc::clone(&kernel));
    let (decide, read) = admin_trust(&services);
    assert!(decide.as_ref().is_some_and(|k| Arc::ptr_eq(k, &kernel)));
    assert!(read.as_ref().is_some_and(|r| r.same_kernel(&kernel)));
    let (decide, read) = admin_trust(&Services::bootstrap());
    assert!(decide.is_none() && read.is_none());
}
