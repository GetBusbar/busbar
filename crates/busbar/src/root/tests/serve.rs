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
            StoreDoor::Linked(busbar_store_memory::linked::STORE.4),
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

/// THE A2A PLANE'S ROOT LEG, through its door (the fold's switch, `a2a-on-driver`): the a2a plane's
/// root cells are units driven on the root's door path: the door linked and bound
/// through the loader's one load, opened with its `agents:` section and the deployment's public
/// base URL, its claims mounted on the data router at its construction, a keyed caller's request
/// admitted and charged by the door steps and answered by the door.
#[cfg(all(linked_axis_node, feature = "a2a-on-driver"))]
mod a2a_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::conn::DeclaredConns;
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
    use busbar_plane_a2a::plane_door::door as a2a_door;

    use super::super::planes_tests::{Published, PUBLISHING};
    use super::super::{compose_planes, door_routes};
    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{load_linked, Bind, LinkedRow, NoSink};
    use crate::root::plane_node::{Node, NodeEndPost};

    /// The deployment's dated card history, billing off (one entry, no price).
    static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
        std::sync::LazyLock::new(|| {
            let holder = crate::root::kernel::RootHistory::default();
            holder.apply(
                crate::root::kernel::card_from_config(
                    std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                    0,
                    true,
                ),
                1_000,
            );
            holder
        });

    /// The governance book's admin token.
    const ADMIN_TOKEN: &str = "admintok";

    /// One a2a door served on a data router, as production composes it, and the admin router the
    /// door's stated admin routes mount on.
    struct Served {
        router: axum::Router,
        admin: axum::Router,
        gov: Arc<GovState>,
        app: Arc<busbar_kernel::state::App>,
        key: busbar_contract::records::VirtualKey,
        token: String,
        /// The handle a config apply swaps the serving generation on.
        handle: Arc<busbar_kernel::state::AppHandle>,
    }

    /// The a2a door linked and bound through the loader's one load (its host services and the
    /// process's connector, whose destination guard keeps the deployment's default private-address
    /// stance and refuses loopback outright when `block_loopback`), its egress sealed by the composition itself (each registered agent a member
    /// route at its own `url`), opened with
    /// `section` as its `agents:` section and a public base URL, its claims mounted on the data
    /// router at its construction, with one keyed caller minted on a signing governance book (its
    /// grant `allowed_pools`: `None` = every scope, a list = those pools and no agent).
    fn served(
        instance: &'static str,
        section: &str,
        block_loopback: bool,
        allowed_pools: Option<Vec<String>>,
    ) -> Served {
        served_trusting(instance, section, block_loopback, allowed_pools, None)
    }

    /// [`served`], its connector also trusting `root` (a test root's DER) beside the platform
    /// roots, so a loopback TLS agent whose certificate it issued completes the chain check.
    fn served_trusting(
        instance: &'static str,
        section: &str,
        block_loopback: bool,
        allowed_pools: Option<Vec<String>>,
        root: Option<Vec<u8>>,
    ) -> Served {
        // The deployment's default stance (`advanced.block_private_addresses: true`); with
        // `block_loopback`, loopback is refused outright as well.
        served_under(
            instance,
            section,
            busbar_kernel::config::Destinations {
                block_private_addresses: true,
                blocked: if block_loopback {
                    vec!["127.0.0.1".to_string()]
                } else {
                    Vec::new()
                },
                ..Default::default()
            },
            allowed_pools,
            root,
        )
    }

    /// [`served`] under the deployment's destination settings `destinations`, its connector also
    /// trusting `root` when given ([`served_trusting`]).
    fn served_under(
        instance: &'static str,
        section: &str,
        destinations: busbar_kernel::config::Destinations,
        allowed_pools: Option<Vec<String>>,
        root: Option<Vec<u8>>,
    ) -> Served {
        let judge = crate::root::connector::guard_for(&destinations).expect("the guard");
        // THE GOVERNANCE BOOK over a store opened through its door, so its record slots are the
        // kernel's record store (ARCHITECT Q-L3B-RECORDS): the door's task rows are kept there.
        let axis = crate::root::loader::store_v3::DoorStoreAxis {
            dispatcher: Arc::new(crate::root::loader::dispatch::Dispatcher::new(
                crate::root::loader::dispatch::DispatchConfig::default(),
            )),
            logs: crate::root::boot::plugin_logs().clone(),
            conns: None,
            mint: busbar_kernel::door::op_id,
        };
        let opened = busbar_contract::store_calls::StoreAxis::open(
            &axis,
            busbar_contract::store_calls::StoreDoor::Linked(busbar_store_memory::linked::STORE.4),
            instance,
            b"{}",
        )
        .expect("the default store opens through its door");
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let gov = Arc::new(
            GovState::new_with_signer(
                Arc::clone(&opened.records),
                Some(ADMIN_TOKEN.to_string()),
                Some(signer),
            )
            .expect("governance"),
        );
        assert!(gov.attach_store_calls(
            opened
                .calls
                .expect("a door-opened store has its record slots")
        ));
        let services = super::super::LateServices::new();
        // The kernel's services judge every destination by the deployment's one guard, as boot
        // composes them (`dest.judge`: the card fetch's per-hop guard reads it).
        let kernel = Arc::new(super::super::kernel_services(
            Arc::clone(&judge) as Arc<dyn busbar_kernel::host_services::DestJudge>
        ));
        services
            .install_kernel(
                Arc::clone(&kernel),
                Arc::clone(&kernel) as Arc<dyn busbar_contract::services::HostServices>,
            )
            .expect("installed once");
        // THE LATE ATTACH, as the first app build runs it: the runtime's blocking pool and the
        // governance store as the record store.
        super::super::attach(
            &services,
            Some(&gov),
            None,
            &Arc::new(super::super::DemotionRecord::default()),
            &[],
        );
        let dispatcher = Arc::new(crate::root::dispatch::build(
            1,
            Arc::clone(&services) as Arc<dyn busbar_contract::services::HostServices>,
        ));
        // Its connection reads through a ticket (a trust verb's card fetch) wake on the dispatcher.
        let settings = busbar_contract::transport::TransportSettings::default();
        let connector = match root {
            None => busbar_core_connector::process::build(
                || crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings),
                judge,
                &[],
                dispatcher.conn_waker(),
                crate::root::connector::pool_posture(&settings),
            )
            .expect("the connector builds"),
            Some(root) => {
                let tls = busbar_core_connector::tls::client::build_client_config(
                    &busbar_contract::transport::trust::EgressTrust {
                        extra_anchors: vec![root],
                        ..Default::default()
                    },
                )
                .expect("the client config");
                let view = busbar_core_connector::registry::Transports::new(
                    crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings)
                        .expect("the entries"),
                )
                .expect("the view");
                Arc::new(busbar_core_connector::Connector::serving(
                    view,
                    busbar_core_connector::process::judge(judge, &[]),
                    Some(Arc::new(tls)),
                    dispatcher.conn_waker(),
                ))
            }
        };
        let row = LinkedRow::of(a2a_door).expect("the door states its Statement");
        let plane = load_linked::<Plane>(
            &row,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: Some(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
            },
        )
        .expect("the linked door binds");
        let section_key = plane.served().section;

        let (key, token) = gov
            .mint_signed(
                NewKeySpec {
                    name: "delegator".to_string(),
                    allowed_pools,
                    ..Default::default()
                },
                4_000_000_000,
                1_700_000_000,
            )
            .expect("mint");
        gov.hydrate_budgets(&CostModel::flat(1), 0)
            .expect("hydrate");
        let node = Arc::new(Node::new());
        let book = crate::root::durability::node_book_over(Box::new(|| CARD.pin()));
        node.bind_book(Arc::clone(&book.durability));
        let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
        let site = Arc::clone(&post);
        let book_money = Arc::clone(&gov);
        let plane_money = move || {
            Arc::new(PlaneMoney::new(
                Arc::clone(&book_money),
                Arc::clone(&site) as Arc<dyn EndPost>,
            ))
        };
        let mut sections = BTreeMap::new();
        sections.insert(
            section_key,
            serde_yaml::from_str(section).expect("a section"),
        );
        // THE EGRESS, AS PRODUCTION SEALS IT: no provider (an agent is reached at its own `url`),
        // the process's connector, the node's journal.
        let providers = std::collections::BTreeMap::new();
        let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
        let auths = crate::root::door_steps::OutboundAuths::new(
            Arc::clone(&dispatcher),
            crate::LINKED.auths,
            None,
            Some(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
        );
        let reach = crate::root::door_steps::DoorReach {
            providers: &providers,
            secrets: &secrets,
            auths: Arc::new(auths),
            conns: Arc::clone(&connector) as Arc<dyn busbar_contract::conn::PollConns>,
            stream_ceiling_secs: 600,
        };
        let mut composed = compose_planes(
            &[(instance.to_string(), plane)],
            &dispatcher,
            &services,
            &sections,
            Some("https://gw.example"),
            &plane_money,
            Some(&super::super::DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            }),
        )
        .expect("the a2a door composes");
        composed.post = Some(post);
        // THE ADMIN SURFACE, as boot mounts it: the admin mount, and the operator credential's row
        // on the auth axis the admin chain authenticates `x-admin-token` with.
        busbar_core_admin::install();
        // THE DOOR'S REGISTRY ROW, folded from its Statement and installed as the composition root
        // installs it (DECL-FOLD): the admin router mounts the door's stated admin routes off it.
        let folded = {
            use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
            busbar_kernel::plane::door::fold(
                registration(linked_probe(a2a_door, "serve-a2a-row")).expect("the door binds"),
            )
            .expect("the door folds")
        };
        busbar_kernel::plane::registry::register_test_plane(folded);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::preflight::install_auth_axis(crate::root::dispatch::auth_axis);
        let app = busbar_kernel::test_support::TestApp::new()
            .keys_chain()
            .admin_chain(vec![busbar_kernel::config::operator_provider().to_string()])
            .governance(Arc::clone(&gov))
            .cost(CostModel::flat(1))
            .build();
        let appliers = composed.appliers();
        let doors = door_routes(composed, || CARD.pin(), &[], &[]).expect("its claims mount");
        let (router, admin, handle) =
            busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);
        // Every config apply refreshes the door, as production binds it.
        handle.on_apply(Box::new(move |app| appliers.apply(app)));
        Served {
            router,
            admin,
            gov,
            app,
            key,
            token: token.expose_secret().to_string(),
            handle,
        }
    }

    /// A JSON-RPC `method` POSTed to the agent `agent`'s claim (`""` = the plane's own unaddressed
    /// endpoint, `/a2a`), bearing `token` or none.
    fn rpc(
        agent: &str,
        method: &str,
        params: &str,
        token: Option<&str>,
    ) -> axum::http::Request<axum::body::Body> {
        let path = if agent.is_empty() {
            "/a2a".to_string()
        } else {
            format!("/a2a/agents/{agent}")
        };
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        req.body(axum::body::Body::from(format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#
        )))
        .expect("a request")
    }

    /// The response's status and body text.
    async fn answered(
        router: &axum::Router,
        req: axum::http::Request<axum::body::Body>,
    ) -> (StatusCode, String) {
        use tower::ServiceExt as _;
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// The root cell `governance-budget × a2a-server`: a keyed caller's unit addressed to one
    /// approved agent (the task list, which the door answers from host records with no far end,
    /// routed over the addressed agent's entry) is SERVED through the door, 200, and the governance
    /// ledger holds its one admitted request on the presenting key; an unkeyed caller on the same
    /// claim is refused before the door and charges nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_a2a_unit_served_through_its_door_charges_the_presenting_key() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, _) = answered(&s.router, rpc("planner", "tasks/list", "{}", None)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an unkeyed caller is refused at the door's claim"
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "tasks/list", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served through the door: {body}");
        let usage = s
            .gov
            .usage_for(&s.app.cost, &s.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists");
        assert_eq!(
            usage.requests, 1,
            "one admitted request, on the presenting key"
        );
    }

    /// The far agent's healthy answer: one JSON-RPC message result.
    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"message","messageId":"m-far","role":"agent","parts":[{"kind":"text","text":"done"}]}}"#;

    /// A far agent on loopback answering every request with one JSON-RPC message result; each
    /// request it was sent comes back on the channel, whole.
    async fn far_agent() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end(200, ANSWER).await
    }

    /// A far end on loopback answering every request `status` with `answer`; each request it was
    /// sent comes back on the channel, whole.
    async fn far_end(
        status: u16,
        answer: &'static str,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end_answering(Arc::new(move |_| {
            Some(FarReply::of(status, answer.to_string()))
        }))
        .await
    }

    /// What a far end answers one request: its status, its extra head fields, its body, and how
    /// long it takes to answer.
    struct FarReply {
        status: u16,
        fields: Vec<(&'static str, String)>,
        body: String,
        delay_ms: u64,
    }

    impl FarReply {
        fn of(status: u16, body: String) -> Self {
            Self {
                status,
                fields: Vec::new(),
                body,
                delay_ms: 0,
            }
        }
    }

    /// What a far end answers one request (the request whole), or `None` to close the connection
    /// unanswered (an agent that is down).
    type Answering = Arc<dyn Fn(&str) -> Option<FarReply> + Send + Sync>;

    /// The path an agent serves its card at, on its origin.
    const CARD_PATH: &str = "GET /.well-known/agent-card.json ";

    /// A far end on loopback answering each request as `answering` says; each request it was sent,
    /// but a `GET` (a fetch of its card), comes back on the channel, whole.
    async fn far_end_answering(
        answering: Answering,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end_over(answering, None).await
    }

    /// One accepted far-end connection, in the clear or under TLS.
    trait FarSocket: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> FarSocket for T {}

    /// [`far_end_answering`], each connection secured by `tls` when given (a handshake that fails
    /// is dropped unanswered).
    async fn far_end_over(
        answering: Answering,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((plain, _)) = listener.accept().await {
                let sent = sent.clone();
                let answering = Arc::clone(&answering);
                let tls = tls.clone();
                tokio::spawn(async move {
                    let mut socket: Box<dyn FarSocket> = match tls {
                        None => Box::new(plain),
                        Some(tls) => match tls.accept(plain).await {
                            Ok(secured) => Box::new(secured),
                            Err(_) => return,
                        },
                    };
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut got = Vec::new();
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let length = text[..at]
                                .lines()
                                .find_map(|l| {
                                    let (name, value) = l.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if got.len() >= at + 4 + length {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&got).to_string();
                    let answered = answering(&text);
                    if !text.starts_with("GET ") {
                        let _ = sent.send(text);
                    }
                    let Some(FarReply {
                        status,
                        fields,
                        body: answer,
                        delay_ms,
                    }) = answered
                    else {
                        return;
                    };
                    if delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                    let extra: String = fields
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}\r\n"))
                        .collect();
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\n\
                         connection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (port, heard)
    }

    /// The agents section registering `planner` (and, given, `scout`) at loopback `port`.
    fn agents(port: u16, scout: bool) -> String {
        let mut section = format!(
            "planner: {{url: 'http://127.0.0.1:{port}/planner', pin: {{mechanism: unpinned}}}}"
        );
        if scout {
            section.push_str(&format!(
                "\nscout: {{url: 'http://127.0.0.1:{port}/scout', pin: {{mechanism: unpinned}}}}"
            ));
        }
        section
    }

    /// The presenting key's admitted requests on the governance ledger.
    fn admitted(s: &Served) -> u64 {
        s.gov
            .usage_for(&s.app.cost, &s.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists")
            .requests
    }

    /// The `message/send` the relayed cells send.
    const SEND: &str = r#"{"message":{"kind":"message","messageId":"m-1","role":"user","parts":[{"kind":"text","text":"plan"}]}}"#;

    /// The root cell `net-guard × a2a-client`: an agent is reached over its member route (its own
    /// `url`) only where the deployment's destination guard admits its address: with private
    /// addresses refused, its card cannot be fetched (`connect` reports the refusal, the agent never
    /// hears it), it can never be approved, and a relayed unit to it never dials; with loopback
    /// admitted it is approved, dialled at its own path, and its answer relayed whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_a2a_unit_dials_only_the_address_the_guard_admits() {
        let _one = PUBLISHING.lock().await;
        let mut agent = Agent::start(200, ANSWER).await;
        let section = agent.entry("planner", "1h");

        let blocked = "serve-a2a-door-guarded";
        let published = Published(blocked);
        let s = served(blocked, &section, true, None);
        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(
            preview["state"], "error",
            "the guard refused the card fetch: {preview}"
        );
        assert_eq!(agent.fetches(), 0, "the agent never heard the card fetch");
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a refused address is never served: {body}"
        );
        assert!(!agent.relayed(), "the far agent was never dialled");
        drop(published);

        let open = "serve-a2a-door-open";
        let _published = Published(open);
        let s = served(open, &section, false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        assert!(
            body.contains("m-far"),
            "the far agent's answer, relayed: {body}"
        );
        let head = agent.heard.recv().await.expect("the far agent was dialled");
        assert!(head.starts_with("POST /planner "), "{head}");
    }

    /// The root cell `governance-budget × a2a-client`: a relayed unit addressed to one agent is
    /// served at that agent and its one admitted request is attributed to the presenting key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_a2a_unit_charges_the_presenting_key() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-charged";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        agent.heard.recv().await.expect("the far agent was dialled");
        assert_eq!(
            admitted(&s),
            1,
            "one admitted request, on the presenting key"
        );
    }

    /// SELECT, ONE REACHES (ARCHITECT Q-DEL-A2A-SELECT): an unaddressed unit on the plane's own
    /// endpoint is routed by the caller's scope to the one agent its grant reaches, as 1.5.5 chose
    /// it, and relayed to that agent's own path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_a2a_unit_is_routed_to_the_one_agent_the_grant_reaches() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-select-one";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "routed by scope and relayed: {body}"
        );
        assert!(body.contains("m-far"), "the far agent's answer: {body}");
        let head = agent.heard.recv().await.expect("the one agent was dialled");
        assert!(head.starts_with("POST /planner "), "{head}");
    }

    /// SELECT, SEVERAL REACH: with two approved agents in the caller's grant, the unaddressed unit
    /// is refused before any dial, in 1.5.5's words (`-32602`, 400), naming the agents it reaches so
    /// it can address one; while neither is approved, none serves, and it is 1.5.5's none-refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_a2a_unit_several_agents_reach_is_refused_naming_them() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-select-several";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\n{}",
            agent.entry("planner", "1h"),
            agent.entry("scout", "1h")
        );
        let s = served(instance, &section, false, None);
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
        assert_eq!(
            (
                doc["error"]["code"].clone(),
                doc["error"]["message"].clone()
            ),
            (
                (-32004).into(),
                "no agent this key may reach can serve this shape of task".into()
            ),
            "neither is approved, so none serves: {body}"
        );
        approve(&s, "planner").await;
        approve(&s, "scout").await;
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
        assert_eq!(doc["error"]["code"], -32602, "{body}");
        assert_eq!(
            doc["error"]["message"],
            "2 agents this key may reach can serve this shape of task, so this endpoint cannot \
             choose one for you. Address the agent directly at `/a2a/agents/{id}` — the ids are: \
             planner, scout",
            "{body}"
        );
        assert!(!agent.relayed(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// SELECT, NONE REACHES: a caller whose grant names no agent gets, on the unaddressed endpoint,
    /// 1.5.5's answer (`-32004`, 400), the same a caller with no grant gets for a named agent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_a2a_unit_no_agent_reaches_is_refused_in_its_1_5_5_words() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-select-none";
        let _published = Published(instance);
        let (port, mut heard) = far_agent().await;
        let s = served(instance, &agents(port, true), false, Some(Vec::new()));
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "no agent this key may reach can serve this shape of task",
            "{body}"
        );
        assert!(heard.try_recv().is_err(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// The root cell `catalogue × a2a-server`: a unit addressed to an agent outside the caller's
    /// grant is refused before it dials, and charges nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_a2a_unit_outside_the_callers_grant_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-ungranted";
        let _published = Published(instance);
        let (port, mut heard) = far_agent().await;
        let s = served(instance, &agents(port, false), false, Some(Vec::new()));
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "refused: {body}");
        assert!(
            body.contains("scope_denied"),
            "the kernel's refusal, in the plane's words: {body}"
        );
        assert!(heard.try_recv().is_err(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// The root cell `disposition × a2a-client`: a relayed unit to an approved agent that has gone
    /// down (its verification still fresh, so the hop is sent) ends inside its unit — the caller
    /// answered in the plane's own envelope, not left hanging.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_a2a_unit_to_an_agent_that_is_down_ends_inside_its_unit() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-down";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
        agent.go_down();
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            status.is_server_error(),
            "a down agent is the far end's failure: {status} {body}"
        );
        let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
        assert_eq!(doc["jsonrpc"], "2.0", "{body}");
        assert!(doc["error"]["code"].is_i64(), "{body}");
    }

    /// The root cells `breaker-trip` and `breaker-fastfail × a2a-client`: an approved agent that
    /// keeps failing records into its member's breaker until it opens, and the next unit is refused
    /// `breaker_open` before it dials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_agent_trips_its_breaker_and_the_next_unit_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-breaker";
        let _published = Published(instance);
        let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let mut dials = 0usize;
        let mut tripped = None;
        for call in 0..32 {
            let (_, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            while agent.heard.try_recv().is_ok() {
                dials += 1;
            }
            if body.contains("breaker_open") {
                tripped = Some((call, dials));
                break;
            }
        }
        let (_, dialled) = tripped.expect("the breaker opened within 32 failing calls");
        assert!(
            dialled > 0,
            "it tripped on failures the agent answered: {dialled}"
        );
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            body.contains("breaker_open"),
            "a tripped agent fast-fails: {body}"
        );
        assert!(!agent.relayed(), "the fast-failed unit never dialled");
    }

    /// The root cell `egress-auth × a2a-client`: the agent is handed only the credential the egress
    /// plans for its member — none is configured here — and never the caller's own token, which
    /// authenticated the caller to busbar and stops there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_a2a_unit_never_hands_the_agent_the_callers_token() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-egress-auth";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        let head = agent.heard.recv().await.expect("the far agent was dialled");
        assert!(
            !head.contains(&s.token),
            "the caller's token never leaves busbar: {head}"
        );
        assert!(
            !head
                .lines()
                .any(|l| l.to_ascii_lowercase().starts_with("authorization:")),
            "no credential is planned for this member, so none is presented: {head}"
        );
    }

    // ── THE TRUST VERBS (ARCHITECT Q-L3B-VERBS) ──────────────────────────────────────────────────

    /// One admin request on `s`'s admin router: `POST /api/v1/admin{path}` with `body` (JSON): its
    /// status and JSON body.
    async fn admin(s: &Served, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let (status, text) = answered(&s.admin, req).await;
        let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, body)
    }

    /// The agent card `port` serves, its one skill described as `description`.
    fn card(port: u16, description: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "planner",
            "description": "plans the work it is given",
            "url": format!("http://127.0.0.1:{port}/planner"),
            "version": "1.0.0",
            "capabilities": {},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "plan", "name": "Plan", "description": description, "tags": ["plan"]}],
        })
    }

    /// `card` signed by `issuer` as an A2A card is signed: one detached EdDSA signature over the
    /// canonical card with its `signatures` member removed.
    fn signed(card: &serde_json::Value, issuer: &ed25519_dalek::SigningKey) -> serde_json::Value {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = busbar_plane_a2a::a2a::card::signing_payload(card).expect("a canonical card");
        let protected = b64.encode(br#"{"alg":"EdDSA"}"#);
        let signature = issuer.sign(format!("{protected}.{}", b64.encode(payload)).as_bytes());
        let mut signed = card.clone();
        signed["signatures"] = serde_json::json!([
            {"protected": protected, "signature": b64.encode(signature.to_bytes())}
        ]);
        signed
    }

    /// `issuer`'s public key as the operator pins it: base64 Ed25519 SubjectPublicKeyInfo.
    fn key_info(issuer: &ed25519_dalek::SigningKey) -> String {
        use base64::Engine as _;
        // The DER head of an Ed25519 SubjectPublicKeyInfo (RFC 8410 section 4).
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(issuer.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// AN AGENT ON LOOPBACK PINNED BY ITS SIGNING KEY: it serves the card `card` holds (signed by
    /// `issuer` when it is asked, so the card may change under it) at its origin's well-known path,
    /// counting each fetch, and answers anything else `status` with `answer` — or nothing at all
    /// while it is `down`. Each request but a card fetch comes back on `heard`, whole.
    struct Agent {
        port: u16,
        heard: tokio::sync::mpsc::UnboundedReceiver<String>,
        card: Arc<std::sync::Mutex<serde_json::Value>>,
        issuer: ed25519_dalek::SigningKey,
        fetches: Arc<std::sync::atomic::AtomicUsize>,
        down: Arc<std::sync::atomic::AtomicBool>,
        /// `0`: the card is served at the well-known path; `1`: the well-known path redirects to
        /// `/cards/card.json`, which serves it; `2`: every `GET` redirects, forever.
        redirect: Arc<std::sync::atomic::AtomicU8>,
        /// How long the next card fetch takes to answer (the ones after it answer at once).
        card_delay_ms: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Agent {
        /// An agent answering every relayed request `status` with `answer`, its card describing
        /// its one skill as "plans the work".
        async fn start(status: u16, answer: &'static str) -> Self {
            Self::start_over(status, answer, None).await
        }

        /// [`Agent::start`], its connections secured by `tls` when given.
        async fn start_over(
            status: u16,
            answer: &'static str,
            tls: Option<tokio_rustls::TlsAcceptor>,
        ) -> Self {
            use std::sync::atomic::Ordering;
            let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let card = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
            let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let redirect = Arc::new(std::sync::atomic::AtomicU8::new(0));
            let card_delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (served, signer, counted, off, moved, slow) = (
                Arc::clone(&card),
                issuer.clone(),
                Arc::clone(&fetches),
                Arc::clone(&down),
                Arc::clone(&redirect),
                Arc::clone(&card_delay_ms),
            );
            let (port, heard) = far_end_over(
                Arc::new(move |request: &str| {
                    if off.load(Ordering::SeqCst) {
                        return None;
                    }
                    if request.starts_with("GET ") {
                        let to = |location: &str| FarReply {
                            status: 302,
                            fields: vec![("location", location.to_string())],
                            body: String::new(),
                            delay_ms: 0,
                        };
                        match moved.load(Ordering::SeqCst) {
                            2 => return Some(to("/loop")),
                            1 if request.starts_with(CARD_PATH) => {
                                return Some(to("/cards/card.json"))
                            }
                            _ => {}
                        }
                        counted.fetch_add(1, Ordering::SeqCst);
                        let card = served.lock().map(|c| c.clone()).unwrap_or_default();
                        return Some(FarReply {
                            delay_ms: slow.swap(0, Ordering::SeqCst),
                            ..FarReply::of(200, signed(&card, &signer).to_string())
                        });
                    }
                    Some(FarReply::of(status, answer.to_string()))
                }),
                tls,
            )
            .await;
            *card.lock().expect("the card") = self::card(port, "plans the work");
            Self {
                port,
                heard,
                card,
                issuer,
                fetches,
                down,
                redirect,
                card_delay_ms,
            }
        }

        /// The card it serves now, as the operator's `connect` reads it: its fingerprint.
        fn fingerprint(&self) -> String {
            let card = self.card.lock().expect("the card").clone();
            busbar_plane_a2a::a2a::card::fingerprint(&signed(&card, &self.issuer))
                .expect("a card fingerprint")
        }

        /// Its card re-issued under the same key with its one skill described as `description`.
        fn reissue(&self, description: &str) {
            *self.card.lock().expect("the card") = card(self.port, description);
        }

        /// How many times its card was fetched.
        fn fetches(&self) -> usize {
            self.fetches.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// It stops answering.
        fn go_down(&self) {
            self.down.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        /// Whether it was sent a relayed request since it was last asked.
        fn relayed(&mut self) -> bool {
            let mut relayed = false;
            while self.heard.try_recv().is_ok() {
                relayed = true;
            }
            relayed
        }

        /// The `agents:` entry registering `name` at this agent's path `/<name>`, pinned by its
        /// signing key, re-verified within `reverify_ttl`.
        fn entry(&self, name: &str, reverify_ttl: &str) -> String {
            format!(
                "{name}: {{url: 'http://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
                 '{reverify_ttl}', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
                self.port,
                key_info(&self.issuer)
            )
        }
    }

    impl Agent {
        /// The `agents:` entry registering `name` at this agent's SECURE path `/<name>`, pinned at
        /// the transport by `mechanism` to the far end's key `key`, re-verified within an hour.
        fn entry_pinned(&self, name: &str, mechanism: &str, key: &str) -> String {
            format!(
                "{name}: {{url: 'https://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
                 '1h', pin: {{mechanism: {mechanism}, key: '{key}'}}}}",
                self.port
            )
        }
    }

    /// The server key a TLS agent presents, swappable under it.
    type ServingKey = Arc<std::sync::Mutex<Arc<rustls::sign::CertifiedKey>>>;

    /// A TLS agent's server certificate resolver: whatever key it is serving now.
    #[derive(Debug)]
    struct Serving(ServingKey);

    impl rustls::server::ResolvesServerCert for Serving {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0.lock().expect("the key")))
        }
    }

    /// A TEST ROOT FOR LOOPBACK TLS AGENTS: the root's DER (the connector is told to trust it), the
    /// issuer of each leaf, and the key the agent serves now.
    struct AgentTls {
        root: Vec<u8>,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        serving: ServingKey,
    }

    impl AgentTls {
        fn new() -> Self {
            busbar_core_connector::tls::install_crypto_provider();
            let kp = rcgen::KeyPair::generate().expect("a key");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let root = params.self_signed(&kp).expect("the root").der().to_vec();
            let issuer = rcgen::Issuer::new(params, kp);
            let (first, _) = Self::issue(&issuer);
            Self {
                root,
                issuer,
                serving: Arc::new(std::sync::Mutex::new(first)),
            }
        }

        /// A fresh leaf for `127.0.0.1` under the root: the key it is served with, and its key's
        /// pin, taken off the key pair itself.
        fn issue(
            issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
        ) -> (Arc<rustls::sign::CertifiedKey>, String) {
            use rcgen::PublicKeyData as _;
            let kp = rcgen::KeyPair::generate().expect("a key");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
            params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::V4(
                std::net::Ipv4Addr::LOCALHOST,
            ))];
            let leaf = params.signed_by(&kp, issuer).expect("the leaf");
            let key = rustls::sign::CertifiedKey::from_der(
                vec![leaf.der().clone()],
                rustls_pki_types::PrivateKeyDer::try_from(kp.serialize_der()).expect("a key"),
                &rustls::crypto::ring::default_provider(),
            )
            .expect("a certified key");
            (
                Arc::new(key),
                busbar_contract::transport::trust::key_pin(&kp.subject_public_key_info()),
            )
        }

        /// A new key under the root, served from now on: its pin.
        fn rekey(&self) -> String {
            let (key, pin) = Self::issue(&self.issuer);
            *self.serving.lock().expect("the key") = key;
            pin
        }

        /// The acceptor serving whatever key is current.
        fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Serving(Arc::clone(&self.serving))));
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        }
    }

    /// THE TRANSPORT PIN THROUGH THE DOOR (ARCHITECT 2026-10-03, L3B round-4 TRANSPORT PIN:
    /// "the connector enforces pins itself"): an agent served over TLS on loopback and registered
    /// `pin: {mechanism: cert_spki, key: <its key's pin>}` has that pin sealed into its member
    /// route, and the connector holds every connection to it to the key.
    ///
    /// * `connect` fetches its card over the agent's own need; the connector observed the far end's
    ///   key, it is the pinned one, so the card is observed: `pending`, `cert_spki`, the card's
    ///   fingerprint to approve, no failure;
    /// * `approve` locks it, and a relayed unit is served, dialled at the agent;
    /// * the agent's key changes (the same root, the same name): the next relayed unit is refused by
    ///   the connector before a request byte reaches the agent, and `connect` reports the mismatch
    ///   in the served engine's words, naming the key it served and the key pinned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cert_spki_agent_is_observed_approved_served_and_refused_once_its_key_changes() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-spki";
        let _published = Published(instance);
        let tls = AgentTls::new();
        let pin = tls.rekey();
        let mut agent = Agent::start_over(200, ANSWER, Some(tls.acceptor())).await;
        let section = agent.entry_pinned("planner", "cert_spki", &pin);
        let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["state"], "pending", "{preview}");
        assert_eq!(preview["pin_mechanism"], "cert_spki", "{preview}");
        assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
        assert_eq!(
            preview["fingerprint"],
            agent.fingerprint().as_str(),
            "{preview}"
        );
        approve(&s, "planner").await;
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::OK, "the pinned agent is served: {body}");
        assert!(body.contains("m-far"), "the far agent's answer: {body}");
        assert!(agent.relayed(), "the pinned agent was dialled");

        let served_now = tls.rekey();
        let (status, body) = answered(&s.router, send()).await;
        assert_ne!(status, StatusCode::OK, "another key is refused: {body}");
        assert!(
            !agent.relayed(),
            "no request byte reached the agent serving another key"
        );
        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["state"], "error", "{preview}");
        assert_eq!(
            preview["failure"],
            format!(
                "`pin.mechanism: cert_spki`: the card endpoint served a certificate whose \
                 subject-public-key-info is `{served_now}`, and the operator pinned `{pin}`. The \
                 endpoint answered and it is not the endpoint the operator supplied a root for."
            )
            .as_str(),
            "{preview}"
        );
    }

    /// THE OPERATOR'S CEREMONY for agent `name` (ARCHITECT Q-L3B-VERBS): `connect` to see its card,
    /// `approve` the fingerprint seen. Its standing is then `approved`.
    async fn approve(s: &Served, name: &str) {
        let (status, preview) = admin(s, &format!("/agents/{name}/connect"), "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let fingerprint = preview["fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("connect reported no fingerprint: {preview}"))
            .to_string();
        let (status, approved) = admin(
            s,
            &format!("/agents/{name}/approve"),
            &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["state"], "approved", "{approved}");
    }

    /// The root cells `trust-pinning × a2a-client` and `trust-pinning × a2a-server`: the door's
    /// trust verbs, served by its `serve` op over the admin router (ARCHITECT Q-L3B-VERBS), pin an
    /// agent's card identity, and the relay serves only the identity pinned, re-verified on call.
    ///
    /// * an agent registered with an out-of-band issuer key and nothing approved is refused at
    ///   admission (`503`, `-32004`, "fronted agent `planner` is not serving (Pending)") and never
    ///   dialled;
    /// * `connect` fetches the card at the agent origin's well-known path, has the kernel verify
    ///   its signature against the pinned key, and previews it: `pending`, the fingerprint a human
    ///   is asked to approve; it grants nothing, so the relay is still refused;
    /// * `approve` naming that fingerprint locks it: `approved`, and the relay is served;
    /// * the card is re-issued under the right key with a skill the operator never read (the
    ///   rug-pull): the next relay re-verifies the card on call (`reverify_ttl: 0s`), finds it
    ///   drifted, and is refused at the hop's gate (`503`, "this agent is not currently serving",
    ///   naming its task) without dialling; restoring the approved card does not lift it (the
    ///   admission refuses on what is recorded: "... is not serving (Quarantined)"); `connect`
    ///   reports the drift `quarantined`; an `approve` of the old fingerprint is refused (`400`);
    /// * an `unpinned` registration is captured by `connect` with no fingerprint, refused approval,
    ///   and never served; an unregistered name is `404`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_trust_verbs_pin_an_agent_card_and_the_relay_serves_only_the_approved_one() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-trust";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let fingerprint = agent.fingerprint();
        let scout = "allow_private: true, pin: {mechanism: unpinned}";
        let section = format!(
            "{}\nscout: {{url: 'http://127.0.0.1:{}/scout', {scout}}}",
            agent.entry("planner", "0s"),
            agent.port
        );
        let s = served(instance, &section, false, None);
        let send = |to: &str| rpc(to, "message/send", SEND, Some(&s.token));
        let unadmitted = |status: StatusCode, body: &str, agent: &str, state: &str| {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            let doc: serde_json::Value = serde_json::from_str(body).expect("an envelope");
            assert_eq!(doc["error"]["code"], -32004, "{body}");
            assert_eq!(
                doc["error"]["message"],
                format!("fronted agent `{agent}` is not serving ({state})"),
                "{body}"
            );
        };

        let (status, body) = answered(&s.router, send("planner")).await;
        unadmitted(status, &body, "planner", "Pending");
        assert!(!agent.relayed(), "a refused unit is never dialled");

        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(
            preview["state"], "pending",
            "a preview grants nothing: {preview}"
        );
        assert_eq!(preview["pin_mechanism"], "jws_issuer_key", "{preview}");
        assert_eq!(preview["fingerprint"], fingerprint.as_str(), "{preview}");
        assert_eq!(preview["added"], serde_json::json!(["plan"]), "{preview}");
        assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
        assert_eq!(
            agent.fetches(),
            1,
            "the card was fetched at the well-known path"
        );
        let (status, body) = answered(&s.router, send("planner")).await;
        unadmitted(status, &body, "planner", "Pending");
        assert!(!agent.relayed(), "a refused unit is never dialled");

        let (status, approved) = admin(
            &s,
            "/agents/planner/approve",
            &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["state"], "approved", "{approved}");
        assert_eq!(approved["fingerprint"], fingerprint.as_str(), "{approved}");
        let fetched = agent.fetches();
        let (status, body) = answered(&s.router, send("planner")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the approved agent is served: {body}"
        );
        assert!(body.contains("m-far"), "the far agent's answer: {body}");
        assert!(agent.relayed(), "the approved agent was dialled");
        assert!(
            agent.fetches() > fetched,
            "its card was re-verified on call"
        );

        // THE RUG-PULL: the right issuer key, a skill the operator never read.
        agent.reissue("plans the work and forwards it on");
        let fetched = agent.fetches();
        let (status, body) = answered(&s.router, send("planner")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "this agent is not currently serving",
            "{body}"
        );
        assert!(
            doc["error"]["data"]
                .as_array()
                .is_some_and(|d| d.iter().any(|e| e["resourceType"] == "a2a.busbar/task")),
            "the refusal names its task: {body}"
        );
        assert!(
            agent.fetches() > fetched,
            "the drift was found by a live re-fetch"
        );
        assert!(!agent.relayed(), "a demoted agent is never dialled");
        // Restored, the agent stays out of service: admission refuses on what is recorded.
        agent.reissue("plans the work");
        let (status, body) = answered(&s.router, send("planner")).await;
        unadmitted(status, &body, "planner", "Quarantined");
        assert!(!agent.relayed(), "a quarantined agent is never dialled");
        agent.reissue("plans the work and forwards it on");
        let (status, drifted) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{drifted}");
        assert_eq!(drifted["state"], "quarantined", "{drifted}");
        assert_eq!(drifted["pin_changed"], true, "{drifted}");
        assert_eq!(drifted["changed"], serde_json::json!(["plan"]), "{drifted}");
        assert_ne!(drifted["fingerprint"], fingerprint.as_str(), "{drifted}");
        let (status, stale) = admin(
            &s,
            "/agents/planner/approve",
            &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{stale}");
        assert_eq!(stale["error"]["code"], "invalid_request", "{stale}");

        // AN UNPINNED REGISTRATION: captured, never approved, never served.
        let (status, captured) = admin(&s, "/agents/scout/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{captured}");
        assert_eq!(captured["state"], "pending", "{captured}");
        assert_eq!(captured["pin_mechanism"], "unpinned", "{captured}");
        assert_eq!(
            captured["fingerprint"],
            serde_json::Value::Null,
            "{captured}"
        );
        let (status, capped) = admin(
            &s,
            "/agents/scout/approve",
            r#"{"fingerprint": "sha256:any"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{capped}");
        assert!(
            capped["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("no authenticity root")),
            "{capped}"
        );
        let (status, body) = answered(&s.router, send("scout")).await;
        unadmitted(status, &body, "scout", "Pending");
        assert!(!agent.relayed(), "an unpinned agent is never dialled");

        let (status, unknown) = admin(&s, "/agents/nobody/connect", "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}");
        assert_eq!(unknown["error"]["code"], "not_found", "{unknown}");
    }

    /// SINGLE-FLIGHT VERIFY-ON-CALL (the engine's `VerifyGate`): two units due on one agent at once
    /// (`reverify_ttl: 0s`, its card slow to answer) share ONE look at its card and its verdict, and
    /// both are served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_units_due_on_one_agent_share_one_card_look() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-single-flight";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "0s"), false, None);
        approve(&s, "planner").await;
        agent
            .card_delay_ms
            .store(300, std::sync::atomic::Ordering::SeqCst);
        let fetched = agent.fetches();
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let ((first, a), (second, b)) =
            tokio::join!(answered(&s.router, send()), answered(&s.router, send()));
        assert_eq!(first, StatusCode::OK, "{a}");
        assert_eq!(second, StatusCode::OK, "{b}");
        assert_eq!(
            agent.fetches() - fetched,
            1,
            "the two due units shared one look at the card"
        );
    }

    /// THE CARD FETCH'S GUARD AND REDIRECTS, as 1.5.5 fetched a card: a card behind a redirect is
    /// followed and approved; a chain past three redirects is refused in 1.5.5's words; a
    /// registration that does not allow private addresses has its loopback card refused by the
    /// guard in 1.5.5's words, and the agent never hears the fetch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_follows_redirects_and_is_guarded_in_its_1_5_5_words() {
        use std::sync::atomic::Ordering;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-card-fetch";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\nscout: {{url: 'https://127.0.0.1:{}/scout', pin: {{mechanism: jws_issuer_key, \
             key: '{}'}}}}",
            agent.entry("planner", "1h"),
            agent.port,
            key_info(&agent.issuer)
        );
        let s = served(instance, &section, false, None);

        agent.redirect.store(1, Ordering::SeqCst);
        approve(&s, "planner").await;

        agent.redirect.store(2, Ordering::SeqCst);
        let (status, looped) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{looped}");
        assert_eq!(looped["state"], "error", "{looped}");
        assert_eq!(
            looped["failure"],
            format!(
                "agent card fetch exceeded 3 redirect(s), still redirecting at \
                 `http://127.0.0.1:{}/loop`",
                agent.port
            ),
            "{looped}"
        );

        agent.redirect.store(0, Ordering::SeqCst);
        let fetched = agent.fetches();
        let (status, guarded) = admin(&s, "/agents/scout/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{guarded}");
        assert_eq!(
            guarded["failure"],
            "SSRF guard refused the agent card fetch: host `127.0.0.1` resolved to the internal \
             address 127.0.0.1; set this registration's `allow_private: true` if reaching it is \
             deliberate. A cloud-metadata address is refused whatever that is set to.",
            "{guarded}"
        );
        assert_eq!(
            agent.fetches(),
            fetched,
            "the agent never heard the refused fetch"
        );
    }

    /// THE CHECK ORDER, as 1.5.5's admission kept it: the caller's grant, then the agent's trust,
    /// then its card's fit. A request naming a skill the card does not declare is refused as
    /// not-serving while the agent is unapproved, and by the catalogue (`403`,
    /// `SkillNotDeclared("fly")`) once it is approved — never dialled either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_the_card_does_not_fit_is_judged_after_the_trust_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-fit-order";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        let fly = r#"{"message":{"kind":"message","messageId":"m-2","role":"user","parts":[{"kind":"text","text":"go"}]},"metadata":{"skill":"fly"}}"#;
        let send = || rpc("planner", "message/send", fly, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "trust first: {body}"
        );
        approve(&s, "planner").await;
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "then the card's fit: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "SkillNotDeclared(\"fly\")",
            "{body}"
        );
        assert_eq!(doc["id"], serde_json::Value::Null, "{body}");
        assert!(!agent.relayed(), "an unfit request is never dialled");
    }

    /// THE GATE (ARCHITECT Q-DEL-A2A-GATE: refused -> audits the refusal; nothing was charged): a
    /// unit addressed to an agent that is not serving is judged by the caller's grant first (`403`
    /// for a caller the agent is not granted to), then refused in predev's admission words (`503`,
    /// "fronted agent `planner` is not serving (Pending)") — a relayed call and a locally answered
    /// one alike — and the key is charged for neither.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_unit_to_an_agent_that_is_not_serving_is_refused_after_its_grant_and_charges_nothing()
    {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-gate";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        for (method, params) in [("message/send", SEND), ("tasks/list", "{}")] {
            let (status, body) =
                answered(&s.router, rpc("planner", method, params, Some(&s.token))).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method}: {body}");
            let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
            assert_eq!(doc["error"]["code"], -32004, "{body}");
            assert_eq!(
                doc["error"]["message"], "fronted agent `planner` is not serving (Pending)",
                "{body}"
            );
        }
        assert!(!agent.relayed(), "never dialled");
        assert_eq!(admitted(&s), 0, "a refused unit is charged nothing");
        drop(s);
        drop(_published);

        let ungranted = "serve-a2a-door-gate-ungranted";
        let _published = Published(ungranted);
        let s = served(
            ungranted,
            &agent.entry("planner", "1h"),
            false,
            Some(Vec::new()),
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the grant is judged first: {body}"
        );
        assert!(body.contains("scope_denied"), "{body}");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// SCOPE AND STANDING (ARCHITECT Q-DEL-A2A-SCOPE-TRUST): an unaddressed unit is routed over the
    /// caller's grant intersected with the agents that would serve it — two agents granted, one of
    /// them approved, is routed to the approved one (as predev's trust-gated catalogue chose it),
    /// not refused as several.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_unit_is_routed_to_the_one_granted_agent_that_serves() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-scope-trust";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\n{}",
            agent.entry("planner", "1h"),
            agent.entry("scout", "1h")
        );
        let s = served(instance, &section, false, None);
        approve(&s, "planner").await;
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "routed to the one that serves: {body}"
        );
        assert!(body.contains("m-far"), "{body}");
        assert!(agent.relayed(), "the approved agent was dialled");
    }

    /// A CONFIG APPLY (ARCHITECT Q-DEL-A2A-APPLY): an apply bumps the door's refresh generation;
    /// the door re-reads its section and every approval resets, exactly as predev rebuilt the
    /// agents plane on every apply — an approved agent is refused again after it ("... is not
    /// serving (Pending)") until it is re-approved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_config_apply_resets_every_approval() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-apply";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::OK, "approved, served: {body}");
        assert!(agent.relayed());

        s.handle.swap(Arc::clone(&s.app));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the apply reset it: {body}"
        );
        assert!(
            body.contains("fronted agent `planner` is not serving (Pending)"),
            "{body}"
        );
        assert!(!agent.relayed(), "never dialled");
        approve(&s, "planner").await;
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::OK, "re-approved, served: {body}");
    }

    /// THE CARD FETCH'S GUARD WORDS, as 1.5.5 printed them (ARCHITECT Q-DEL-A2A-GUARD-WORDS): a
    /// registration without `allow_private` is refused a private card host whatever the
    /// deployment's `block_private_addresses` says (here `false`), the address or loopback name
    /// named; a host that does not resolve is refused with the resolver's reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_is_refused_in_1_5_5_words_whatever_the_deployment_private_stance() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-guard-words";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let pin = format!(
            "pin: {{mechanism: jws_issuer_key, key: '{}'}}",
            key_info(&agent.issuer)
        );
        let section = format!(
            "literal: {{url: 'https://127.0.0.1:{port}/literal', {pin}}}\n\
             named: {{url: 'https://localhost:{port}/named', {pin}}}\n\
             nowhere: {{url: 'https://card-host.invalid/nowhere', {pin}}}",
            port = agent.port
        );
        let s = served_under(
            instance,
            &section,
            busbar_kernel::config::Destinations {
                block_private_addresses: false,
                ..Default::default()
            },
            None,
            None,
        );
        let failure = |name: &'static str| {
            let s = &s;
            async move {
                let (status, view) = admin(s, &format!("/agents/{name}/connect"), "").await;
                assert_eq!(status, StatusCode::OK, "{view}");
                assert_eq!(view["state"], "error", "{view}");
                view["failure"].as_str().unwrap_or_default().to_string()
            }
        };
        assert_eq!(
            failure("literal").await,
            "SSRF guard refused the agent card fetch: host `127.0.0.1` resolved to the internal \
             address 127.0.0.1; set this registration's `allow_private: true` if reaching it is \
             deliberate. A cloud-metadata address is refused whatever that is set to."
        );
        assert_eq!(
            failure("named").await,
            "SSRF guard refused the agent card fetch: host `localhost` is a loopback name; set \
             this registration's `allow_private: true` if that is deliberate"
        );
        assert_eq!(agent.fetches(), 0, "the agent never heard a refused fetch");
        // PREDEV'S RESOLVER WORDS, byte for byte: its card fetch resolved through tokio's
        // `lookup_host("{host}:0")` and printed that error's text.
        let predev = match tokio::net::lookup_host("card-host.invalid:0").await {
            Ok(_) => panic!("a `.invalid` name never resolves"),
            Err(e) => e.to_string(),
        };
        assert_eq!(
            failure("nowhere").await,
            format!("agent card host `card-host.invalid` did not resolve: {predev}")
        );
    }

    /// A CARD FETCH WHOSE FAR END CLOSES BEFORE REPLYING, in predev's exact words: its engine's
    /// HTTP client named it `client error (SendRequest): connection closed before message
    /// completed` (hyper's incomplete message) — here a far end that accepts, reads the request
    /// and closes without a byte of reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_whose_far_end_closes_unanswered_fails_in_predev_words() {
        use tokio::io::AsyncReadExt;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-closed-unanswered";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut heard = Vec::new();
                let mut buf = [0_u8; 1024];
                while !heard.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => heard.extend_from_slice(&buf[..n]),
                    }
                }
                drop(socket);
            }
        });
        let section = format!(
            "silent: {{url: 'http://127.0.0.1:{port}/silent', allow_private: true, pin: \
             {{mechanism: jws_issuer_key, key: '{}'}}}}",
            key_info(&agent.issuer)
        );
        let s = served(instance, &section, false, None);
        let (status, view) = admin(&s, "/agents/silent/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], "error", "{view}");
        assert_eq!(
            view["failure"],
            format!(
                "agent card fetch of `http://127.0.0.1:{port}/.well-known/agent.json` failed: \
                 client error (SendRequest): connection closed before message completed"
            ),
            "{view}"
        );
    }

    /// A CARD FETCH THE CONNECTION FAILS, in predev's exact words (ARCHITECT
    /// Q-DEL-A2A-GUARD-WORDS): "agent card fetch of `{url}` failed: {err}", the err the engine's
    /// HTTP client rendered with its cause chain (`client error (Connect): tcp connect error:
    /// <the socket's own error>`) — here a closed loopback port, the socket's error the one this
    /// host's own connect to that port answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_to_a_closed_port_fails_in_predev_words() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-closed-port";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a port")
            .local_addr()
            .expect("its address")
            .port();
        let refused_here = std::net::TcpStream::connect(("127.0.0.1", closed))
            .expect_err("nothing listens on the closed port")
            .to_string();
        let section = format!(
            "closed: {{url: 'https://127.0.0.1:{closed}/closed', allow_private: true, pin: \
             {{mechanism: jws_issuer_key, key: '{}'}}}}",
            key_info(&agent.issuer)
        );
        let s = served(instance, &section, false, None);
        let (status, view) = admin(&s, "/agents/closed/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], "error", "{view}");
        assert_eq!(
            view["failure"],
            format!(
                "agent card fetch of `https://127.0.0.1:{closed}/.well-known/agent.json` failed: \
                 client error (Connect): tcp connect error: {refused_here}"
            ),
            "{view}"
        );
    }

    /// CANCELLATION IS A WAKE (ARCHITECT Q-DEL-A2A-TIMED-WAKE): the unit holding an agent's card
    /// look is abandoned mid-look (its caller goes away while the card is slow), and the unit
    /// waiting on that look proceeds at once — it takes the flight over, looks for itself and is
    /// served — rather than stalling on a look that will never land.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_abandoned_card_look_wakes_its_waiters_at_once() {
        use std::time::Duration;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-a2a-door-abandoned-look";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "0s"), false, None);
        approve(&s, "planner").await;
        agent
            .card_delay_ms
            .store(30_000, std::sync::atomic::Ordering::SeqCst);
        let fetched = agent.fetches();
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let abandoned =
            tokio::time::timeout(Duration::from_millis(400), answered(&s.router, send()));
        let waiting = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tokio::time::timeout(Duration::from_secs(5), answered(&s.router, send())).await
        };
        let (gone, waited) = tokio::join!(abandoned, waiting);
        assert!(gone.is_err(), "the first caller went away mid-look");
        let (status, body) = waited.expect("the waiter proceeded without stalling on the look");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            agent.fetches() - fetched,
            2,
            "the waiter took the abandoned flight over and looked for itself"
        );
    }
}
