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

    fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
        busbar_contract::services::Snapshot::NotReady
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
        now(s.records_secret("planted-scheme", "AKID", Box::new(|_| {}))),
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

/// AFTER ITS HEAD THE UNIT RUNS ON ITS OWN TASK: a
/// caller that stops reading a streamed answer with its socket open leaves the body unpolled, and
/// the unit still runs, so its own deadline can fire. Here the unit's second write waits on the
/// unread body under a timer of the unit's own, which fires and lets the unit end. RED: the unit was
/// driven only from inside the body's poll, so with the body unread nothing drove its timer and it
/// never ended.
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

/// DROPPING THE BODY TELLS THE UNIT ITS CALLER IS GONE: a unit still running on its own task when
/// the reply's body is dropped is dropped too (the driver's client-drop path), and a streamed body
/// read to its end still carries every piece, in order, then ends with the unit.
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

// ── the late attach ─────────────────────────────────────

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
    // A declared pin: a first sighting pins nothing.
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
    // A declared fingerprint is pending until the operator approves it (coordinator 2026-10-07,
    // #555): nothing drifts before the approval.
    assert_eq!(sight("h1"), (svc::TRUST_NEW, false));
    k.trust_rule("owner/peer", busbar_kernel::trust::book::Ruling::Approve)
        .expect("approved");
    assert_eq!(sight("h1"), (svc::TRUST_SAME, false));
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

/// THE RECORD STORE: the late attach binds the configured governance
/// store — opened through its door on the store axis, as boot opens it — as the kernel's record
/// store, its typed records served over its store v3 slots ([`busbar_kernel::host_records::StoreRows`]).
/// A governance store with no door binds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_late_attach_binds_the_governance_store_as_the_record_store() {
    use busbar_contract::kinds::RecordBytes;
    use busbar_contract::store_calls::{StoreAxis as _, StoreDoor};
    use busbar_kernel::host_records::RecordRows as _;
    let axis = crate::root::loader::store_v3::DoorStoreAxis {
        dispatcher: {
            let d = Arc::new(crate::root::loader::dispatch::Dispatcher::new(
                crate::root::loader::dispatch::DispatchConfig::default(),
            ));
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = d.lend_seal(busbar_kernel::seal::lend());
            d
        },
        logs: crate::root::boot::plugin_logs().clone(),
        // The build's ephemeral store declares no need: it serves with no connection table.
        conns: crate::root::loader::dispatch::ConnTable::NoNeeds,
        mint: busbar_kernel::door::op_id,
    };
    let opened = axis
        .open(
            // The build's ephemeral linked store, picked by its flag (the row's `(name, ephemeral,
            // door)`), as boot opens it.
            StoreDoor::Linked(
                crate::LINKED
                    .stores
                    .iter()
                    .find(|s| s.1)
                    .expect("the build links an ephemeral store")
                    .2,
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

    // A claim is redeemed through the same slots, under the kind it names: the first redemption of
    // a token wins, a second loses, and the same token under another kind is its own claim.
    let rows = busbar_kernel::host_records::StoreRows(Arc::clone(&calls));
    let claims = tokio::task::spawn_blocking(move || {
        let now = 1_000;
        [
            rows.claim("attach-claim", "t", now + 60, now),
            rows.claim("attach-claim", "t", now + 60, now),
            rows.claim("attach-other", "t", now + 60, now),
        ]
    })
    .await
    .expect("the blocking call ran");
    assert_eq!(claims, [Ok(true), Ok(false), Ok(true)]);

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
        !k.attach_records(Arc::new(busbar_kernel::host_records::StoreRows(
            gov.store_calls().expect("kept")
        ))),
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
        k.attach_records(Arc::new(busbar_kernel::host_records::StoreRows(
            Arc::clone(&gov.store_calls().expect("kept"))
        ))),
        "a store with no slots bound nothing"
    );
}

/// A FRAMED CLAIM'S CALLER LEG READS THE MESSAGES, NOT THE FRAMING (audit root-R1 L15): the unit
/// arrives with the messages its claim's framer read out of the request body, and a unit that reads
/// its caller leg (a session) is handed the same messages, never the bytes the host strips.
#[tokio::test]
async fn a_framed_claims_caller_reads_the_deframed_messages() {
    use busbar_kernel::plane_driver::SessionCaller as _;
    let framed = Arrival {
        claim: 0,
        method: b"POST".to_vec(),
        target: b"/framed".to_vec(),
        fields: Default::default(),
        body: bytes::Bytes::from_static(b"\x02ab\x02cd"),
    };
    let messages = vec![b"ab".to_vec(), b"cd".to_vec()];
    let (arrival, caller, _reply) = deframed_arrival(framed, &messages);
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

/// A CONFIG APPLY BUILDS A DOOR PLANE'S SECTION AS BOOT DOES (audit root-R1 leftover C1): the
/// section as written gains the generation's unified pools at its reserved `pools` key, so the
/// door's pools survive the apply, and the plane is handed it with the core-owned `work:` struck.
#[test]
fn an_applied_door_section_carries_its_pools_and_hands_the_plane_no_work_key() {
    let key = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2];
    let written: serde_yaml::Value =
        serde_yaml::from_str("fs: { url: \"http://fs\" }\nwork: { max_live: 4 }\n")
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
        crate::root::door_steps::DoorPools::of(&applied)
            .expect("the pools")
            .pools()
            .get("files")
            .cloned(),
        Some(vec!["fs".to_string()]),
        "the apply dropped the door's pools"
    );
    // The kernel still reads its `work:` bounds off the section; the plane is never handed them.
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

/// AN OPEN CLAIM'S LINE TAKES NO AUTH, WHATEVER THE CHAIN: a plane's
/// discovery documents answer a caller who holds no credential yet, with the operator's data chain
/// configured exactly as without one.
#[cfg(linked_section_pools)]
#[test]
fn an_open_claims_line_takes_no_auth_whatever_the_data_chain() {
    use busbar_contract::abi::auth::AuthPoints;
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

/// THE RED ARM: a claim that is NOT open owes the operator's chain, configured or empty — the open
/// exception never widens to a line a credential is owed on.
#[cfg(linked_section_pools)]
#[test]
fn a_claim_that_is_not_open_owes_the_data_chain_configured_or_empty() {
    use busbar_contract::abi::auth::AuthPoints;
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

/// THE SERVE PATH NAMES NO STREAM MEDIA TYPE OF ITS OWN (audit R1#4; Law 1, BUSBAR-1.6.0.md l.1895
/// "Dialects are internal to their plane"): whether an answer that states its length still goes out
/// piece by piece is read off the declared rows — the event stream the contract names, and the
/// stream `Content-Type` each declared protocol states on its `ProtocolDecl` row — never off a
/// dialect's media type spelled here. Every one of them goes out piece by piece, byte for byte as
/// written. RED before: the root spelled a vendor framing's media type beside the event stream.
#[tokio::test]
async fn every_declared_stream_type_goes_piece_by_piece_and_the_serve_path_spells_none() {
    use busbar_kernel::ingress::protocols::streaming_content_types as declared_stream_media;
    use http_body::Body as _;
    // The answer-shaping rules live in `accepted.rs` (`accepted::Reply::shape`), which the serve
    // path answers through: neither spells a dialect's media type.
    for source in [include_str!("../serve.rs"), include_str!("../accepted.rs")] {
        assert!(
            !source.contains("application/vnd."),
            "the serve path spells a dialect's stream media type: it must read the declared rows"
        );
    }
    let declared = std::iter::once(busbar_contract::protocol::TEXT_EVENT_STREAM)
        .chain(declared_stream_media().iter().copied());
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

/// The plane instance the guest-line cells claim for.
const LINES_PLANE: &str = "lines-plane";

/// One claim of the guest-line cells' plane, over a carrier no linked row states (no upgrade, the
/// unstated offer).
fn lines_claim(
    verb: &str,
    target: &str,
    flags: u32,
) -> crate::root::loader::dispatch::kinds::plane::OwnedClaim {
    crate::root::loader::dispatch::kinds::plane::OwnedClaim {
        verb: verb.to_string(),
        target: target.to_string(),
        carrier: "lines-carrier".to_string(),
        flags,
        refusal_dialect: 0,
        arrival_span: String::new(),
    }
}

/// The guest-line cells' plane: an exact chat claim, an exact catalog claim, a subtree claim with
/// a public route of its own under it.
fn lines_snapshot() -> OwnedSnapshot {
    OwnedSnapshot {
        generation: 1,
        claims: vec![
            lines_claim("POST", "/v1/chat/completions", CLAIM_EXACT),
            lines_claim("GET", "/v1/models", CLAIM_EXACT),
            lines_claim("GET", "/files", 0),
            lines_claim("POST", "/files", 0),
        ],
        admin_routes: vec![
            crate::root::loader::dispatch::kinds::plane::OwnedAdminRoute {
                verb: "GET".to_string(),
                target: "/files/.well-known/document".to_string(),
                flags: busbar_contract::abi::plane::ROUTE_PUBLIC,
                audit_verb: String::new(),
            },
        ],
        openapi: None,
        audience: None,
        resource_metadata: None,
        resource_facts: None,
        listed: Vec::new(),
    }
}

/// The plugin routes the cells' data router mounts beside the kernel's own: the app's, and a scrape
/// sink's two.
fn lines_plugin_routes(app: &busbar_kernel::state::App) -> Vec<(String, RouteMethod)> {
    let mut routes = busbar_kernel::base_data_plugin_lines(app);
    for path in ["/metrics", "/metrics/hooks"] {
        if !routes.iter().any(|(p, _)| p == path) {
            routes.push((path.to_string(), RouteMethod::Get));
        }
    }
    routes
}

/// The data listener's lines for the cells' plane, over `app`'s own data routes.
fn lines_for(app: &busbar_kernel::state::App) -> DataLines {
    let snapshot = lines_snapshot();
    data_lines(
        &[(LINES_PLANE, &snapshot)],
        &[],
        &busbar_kernel::base_data_core_lines(app),
        &lines_plugin_routes(app),
        &[],
        &[],
    )
    .expect("the cells' lines seal")
}

/// Whether `line` is the residual line: every method on every path, the core's claimant running
/// the chain itself.
fn is_residual(line: &busbar_kernel::guest::Line) -> bool {
    use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
    line.route.methods == METHOD_ANY
        && line.route.path_form == PATH_CONTAINS
        && line.route.path == "/"
        && line.claimant == busbar_kernel::guest::Claimant::Clean(CORE_CLAIMANT.to_string())
        && line.auth == busbar_kernel::guest::LineAuth::Claimant
}

/// THE DATA LISTENER'S LINES ROUTE AS 1.5.5's ROUTER DID (row 192 D1; THE DESIGN §6 step 3,
/// l.902-904; v1.5.5 `main.rs:3864-3874`, auth around the router and its fallback). `HEAD` rides
/// `GET` on every `GET` line, a claim's and the kernel's own (axum's `get()`); the residual line,
/// every method on every path with the core's claimant running the chain itself, is placed LAST;
/// an `OPTIONS` on the chat claim, the `/api` prefix on a data listener and an unknown path each
/// match the residual line, never a method miss or no route, so the router answers them with the
/// bytes it answers today (the 401 of its auth, then its 404, 405 or 400).
#[test]
fn door_mounts_lines_route_like_1_5_5() {
    use busbar_kernel::guest::{Claimant, Matched};
    let app = busbar_kernel::test_support::TestApp::new().build();
    let DataLines { guests, .. } = lines_for(&app);
    let plane = Claimant::Plane(LINES_PLANE.to_string());
    // HEAD rides GET: on a claim's line and on the kernel's own.
    for (path, claimant) in [
        ("/v1/models", plane.clone()),
        ("/files/a/b", plane.clone()),
        (
            busbar_kernel::auth::HEALTHZ_PATH,
            Claimant::Clean(CORE_CLAIMANT.to_string()),
        ),
    ] {
        let Matched::Line(get) = guests.matched("GET", path, &[]) else {
            panic!("GET {path} matches no line");
        };
        assert!(!is_residual(get), "GET {path} has a line of its own");
        assert_eq!(get.claimant, claimant, "GET {path}");
        assert_eq!(
            guests.matched("HEAD", path, &[]),
            Matched::Line(get),
            "HEAD {path} rides the GET line, as the router serves it"
        );
    }
    // The residual line is placed last.
    let last = guests.lines().last().expect("a line");
    assert!(is_residual(last), "the last line is the residual: {last:?}");
    assert_eq!(
        guests.lines().iter().filter(|l| is_residual(l)).count(),
        1,
        "one residual line"
    );
    // A method miss on a claim's path, the admin prefix and an unknown path reach the router.
    for (method, path) in [
        ("OPTIONS", "/v1/chat/completions"),
        ("GET", "/v1/chat/completions"),
        ("GET", "/api"),
        ("GET", "/api/v1/admin/keys"),
        ("POST", "/api/v1/admin/keys"),
        ("GET", "/v1/unknown/suffix"),
        ("PATCH", "/"),
        ("TRACE", "/files/a"),
    ] {
        match guests.matched(method, path, &[]) {
            Matched::Line(line) if is_residual(line) => {}
            other => panic!("{method} {path} matched {other:?}, not the residual line"),
        }
    }
}

/// A route path as a concrete request path: each `{…}` segment one segment of its own.
fn concrete(path: &str) -> String {
    path.split('/')
        .map(|s| if s.starts_with('{') { "seg" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

/// EVERY ROUTE THE DATA ROUTER SERVES HAS A GUEST LINE (row 192 D1): a door claim's route matches
/// its plane's line; each of the kernel's own data routes, each public route and each plugin route
/// (`/metrics` among them) matches a line of its own at its own path, never a plane's subtree
/// claim and never only the residual line; `HEAD` beside each `GET` matches the same line.
#[test]
fn every_data_router_route_has_a_guest_line() {
    use busbar_kernel::guest::{Claimant, Matched};
    let app = busbar_kernel::test_support::TestApp::new().build();
    let DataLines { guests, doors, .. } = lines_for(&app);
    let snapshot = lines_snapshot();
    let core_claimant = Claimant::Clean(CORE_CLAIMANT.to_string());
    let plane = Claimant::Plane(LINES_PLANE.to_string());
    // The door claims as the router mounts them: an exact claim at its target, a subtree claim at
    // its target and under it.
    let mut routes: Vec<(String, RouteMethod, Claimant, bool)> = Vec::new();
    for (line, method, _) in &doors {
        let path = line.route.path.clone();
        if let Some(target) = path.strip_suffix("/{*rest}") {
            routes.push((target.to_string(), *method, plane.clone(), false));
        }
        routes.push((path, *method, plane.clone(), false));
    }
    assert_eq!(
        doors.len(),
        snapshot.claims.len(),
        "every claim is a door line"
    );
    // The kernel's own data routes, the public routes and the plugin routes: each its own line.
    for (path, method, _) in busbar_kernel::base_data_core_lines(&app) {
        routes.push((path, method, core_claimant.clone(), true));
    }
    for r in &snapshot.admin_routes {
        let method = METHODS
            .into_iter()
            .find(|m| m.as_str() == r.verb)
            .expect("a mounted verb");
        routes.push((r.target.clone(), method, core_claimant.clone(), true));
    }
    for (path, method) in lines_plugin_routes(&app) {
        routes.push((path, method, core_claimant.clone(), true));
    }
    assert!(
        routes.iter().any(|(p, ..)| p == "/metrics"),
        "the plugin routes are among the router's"
    );
    for (path, method, claimant, own) in routes {
        let at = concrete(&path);
        let mut methods = vec![method.as_str()];
        if method == RouteMethod::Get {
            methods.push("HEAD");
        }
        for m in methods {
            let Matched::Line(line) = guests.matched(m, &at, &[]) else {
                panic!("{m} {at} (the router's {path}) matches no line");
            };
            assert_eq!(
                line.claimant, claimant,
                "{m} {at}: the line of the route's owner"
            );
            assert!(!is_residual(line), "{m} {at} rides only the residual line");
            if own {
                assert_eq!(line.route.path, path, "{m} {at} has a line at its own path");
            }
        }
    }
}

/// A 1.5.5 golden cell (`testing/shadow-oracle/golden/1.5.5/cells`, read only).
fn golden_cell(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/../../testing/shadow-oracle/golden/1.5.5/cells/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("a golden cell is JSON")
}

/// A DATA-PORT `/api` REQUEST ANSWERS 1.5.5's ADMIN REFUSAL (row 192 C; v1.5.5
/// `config/mod.rs:2432-2439`, the admin API always on its own listener; `auth/mod.rs:32-38, :1250`,
/// the `/api` root classified admin, fail-closed). The data listener's guest list carries no admin
/// line: `/api` and `/api/...` match the residual line, and the kernel's router answers them, with
/// no credential, byte for byte as the golden cells `http.crosscut|api|data` and
/// `http.crosscut|api-prefix|data` pin: status, content-type, content-length and body.
#[tokio::test]
async fn a_data_port_api_request_answers_the_1_5_5_admin_refusal() {
    use busbar_kernel::guest::{Claimant, Matched};
    use tower::ServiceExt as _;
    let app = busbar_kernel::test_support::TestApp::new().build();
    let DataLines { guests, .. } = lines_for(&app);
    for line in guests.lines() {
        if let Claimant::Clean(key) = &line.claimant {
            assert_eq!(
                key, CORE_CLAIMANT,
                "a cleanliness line on the data list: {line:?}"
            );
        }
        let admin_root = busbar_kernel::auth::ADMIN_PATH;
        assert!(
            line.route.path != admin_root
                && !line.route.path.starts_with(&format!("{admin_root}/")),
            "an admin line on the data list: {line:?}"
        );
    }
    let (router, _admin, _handle) = busbar_kernel::build_split_routers_serving_doors(
        Arc::clone(&app),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        1 << 20,
        0,
        false,
    );
    for (path, cell) in [
        ("/api", "http.crosscut__api__data"),
        ("/api/v1/admin/keys", "http.crosscut__api-prefix__data"),
    ] {
        match guests.matched("GET", path, &[]) {
            Matched::Line(line) if is_residual(line) => {}
            other => panic!("GET {path} matched {other:?}, not the residual line"),
        }
        let golden = golden_cell(cell);
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = router.clone().oneshot(request).await.expect("an answer");
        assert_eq!(
            Some(u64::from(response.status().as_u16())),
            golden["status"].as_u64(),
            "GET {path}: the status"
        );
        for name in ["content-type", "content-length"] {
            assert_eq!(
                response.headers().get(name).and_then(|v| v.to_str().ok()),
                golden["headers"][name].as_str(),
                "GET {path}: {name}"
            );
        }
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        let expected = serde_json::to_vec(&golden["body"]["json"]).expect("the golden body");
        assert_eq!(
            String::from_utf8_lossy(&body),
            String::from_utf8_lossy(&expected),
            "GET {path}: the body, byte for byte"
        );
    }
}

/// THE CLAIM DOORS' BINDS: a served plane's INBOUND need whose `target_from` block in its
/// section states a `listen` is bound there, under the need's transport and its own index, and the
/// setting is named as the operator spells it. An outbound need, a need with no `target_from`, a
/// block that states no `listen` and a plane whose section is absent bind nothing; an address that
/// is not `ip:port` refuses the composition, naming the setting.
#[test]
fn a_planes_inbound_need_binds_at_the_listen_its_block_states() {
    use crate::root::loader::boot::BindOwner;
    use busbar_contract::abi::host::conn::connector::{DIRECTION_INBOUND, DIRECTION_OUTBOUND};
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        section: "a-section",
        need_auths: vec![
            (DIRECTION_OUTBOUND, "none"),
            (DIRECTION_INBOUND, "none"),
            (DIRECTION_INBOUND, "none"),
            (DIRECTION_INBOUND, "none"),
        ],
        need_targets: vec!["far", "media", "", "quiet"],
        need_transports: vec!["out-t", "in-t", "bare-t", "quiet-t"],
        ..Default::default()
    };
    let doc = |yaml: &str| -> BTreeMap<&'static str, serde_yaml::Value> {
        BTreeMap::from([("a-section", serde_yaml::from_str(yaml).expect("yaml"))])
    };
    let sections =
        doc("far: {listen: \"127.0.0.1:7000\"}\nmedia: {listen: \"127.0.0.1:7001\"}\nquiet: {}\n");
    let binds = super::need_binds("inst", &facts, &sections).expect("binds");
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
        super::need_binds("inst", &facts, &BTreeMap::new())
            .expect("no section")
            .is_empty(),
        "a plane whose section is absent binds nothing"
    );
    assert_eq!(
        super::need_binds("inst", &facts, &doc("media: {listen: \"nowhere\"}\n")).unwrap_err(),
        "a-section.media.listen: `nowhere` is not an ip:port address"
    );
}
