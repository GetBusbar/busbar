// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The production [`UsageObservations`] over the kernel's observation custody (IF §12.4): scopes and observations
//! of the unit a verified principal has in flight, under the operator's policy.

use std::collections::BTreeMap;

use busbar_contract::observation::Receipt;
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;
use busbar_plugin_abi::plane::{
    OBS_ACCEPTED, OBS_ATTACH, OBS_CLOSE, OBS_CLOSED, OBS_CREATE, OBS_FINAL, OBS_PENDING,
    OBS_PROVISIONAL, OBS_READY, OBS_REFUSED,
};

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::cost::CostModel;
use crate::governance::GovState;
use crate::persistence::host_records::tests::{attach, Backend};
use crate::plane_driver::port_auth::subject_identity;
use crate::plane_driver::port_intents::Namespace;
use crate::plane_driver::{EndPost, FeeRefund, ObservationPolicy, PlaneMoney, UnitMoney};

struct Post;
impl EndPost for Post {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}

fn cost(rate: u64) -> Arc<CostModel> {
    let rates = BTreeMap::from([(
        "serving".to_owned(),
        crate::config::RateEntryCfg {
            units: BTreeMap::from([
                (
                    "work_units".to_owned(),
                    busbar_kernel_ledger::cost::UnitRate::from_whole_micros(rate).unwrap(),
                ),
                (
                    "other_units".to_owned(),
                    busbar_kernel_ledger::cost::UnitRate::from_whole_micros(rate).unwrap(),
                ),
            ]),
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "group".to_owned(),
        GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Budget,
                amount: 1,
                per: Some(LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    Arc::new(CostModel::resolve_parts(Some(&rates), 0, &groups))
}

fn who() -> Namespace {
    Namespace {
        plugin: "plane-fixture".into(),
        name: "fixture".into(),
        instance: 1,
        slot: 0,
    }
}

fn policy() -> ObservationPolicy {
    ObservationPolicy {
        instance: "fixture".into(),
        destination: "member".into(),
        serving_subject: "serving".into(),
        accounting_namespace: "account".into(),
        // Only class 0 (`work_units`) is priced under the operator's policy.
        classes: vec![0],
        rated_subjects: vec![],
        reserve_nanos: 10_000_000,
        ordered_revisions: true,
    }
}

struct Fixture {
    custody: ObsCustody,
    money: Arc<PlaneMoney>,
    registration: Registration,
}

async fn fixture() -> Fixture {
    let core = Arc::new(attach(Arc::new(Backend::default())).await);
    let gov = Arc::new(GovState::new_with_core(core, None, None).await.unwrap());
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Post)));
    let key = Arc::new(VirtualKey {
        id: "owner".into(),
        enabled: true,
        group: Some("group".into()),
        ..Default::default()
    });
    let cost = cost(1);
    let grant = Arc::new(gov.try_admit(&cost, &key, "", 100).unwrap());
    money.open_admitted(
        UnitKey::new(1),
        UnitMoney {
            key,
            cost,
            pool: String::new(),
            lane: "serving".into(),
            classes: Arc::from(vec!["work_units".into(), "other_units".into()]),
            arrived: 100,
            mode: crate::config::groups::ExhaustionMode::FinishUnit,
            fee: FeeRefund::CallerStatus,
            charge: grant.charge().clone(),
        },
        grant,
    );
    let custody = ObsCustody::new(Arc::new(|| 100_000));
    let registration = custody
        .register(
            &Arc::from("fixture"),
            &Arc::from("owner"),
            ActiveUnit {
                money: money.clone(),
                unit: UnitKey::new(1),
                policy: Arc::new(policy()),
                classes: Arc::from(vec!["work_units".to_owned(), "other_units".to_owned()]),
            },
        )
        .unwrap();
    Fixture {
        custody,
        money,
        registration,
    }
}

fn observation<'a>(
    scope: [u8; 32],
    state: u32,
    counts: &'a [(&'a str, u64, u32)],
) -> ObservationIn<'a> {
    ObservationIn {
        scope,
        event: b"event",
        component: b"part",
        revision: Some((&[1u8][..], 1)),
        state,
        counts,
        rated_subject: 0,
        evidence: b"",
    }
}

#[tokio::test]
async fn a_principal_with_no_unit_in_flight_has_no_custody() {
    let custody = ObsCustody::new(Arc::new(|| 1));
    let who = who();
    let owner = subject_identity("owner");
    assert_eq!(
        custody
            .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
    let counts = [("work_units", 20, 0)];
    let (status, receipt) = custody
        .observe(
            &who.caller(),
            &owner,
            &observation([7; 32], OBS_FINAL, &counts),
        )
        .await;
    assert_eq!(status, OBS_REFUSED);
    assert!(receipt.is_empty());
}

#[tokio::test]
async fn create_requires_the_classes_priced_then_observe_settles_once_and_close_closes() {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    // `other_units` is not priced in the operator's policy: refused before any money is reserved.
    assert_eq!(
        f.custody
            .scope(
                &who.caller(),
                &owner,
                OBS_CREATE,
                None,
                &["work_units", "other_units"]
            )
            .await,
        (OBS_REFUSED, None)
    );
    assert!(f.money.observation_scope(UnitKey::new(1)).is_none());
    let (status, id) = f
        .custody
        .scope(&who.caller(), &owner, OBS_CREATE, None, &["work_units"])
        .await;
    assert_eq!(status, OBS_READY);
    let id = id.expect("a READY answer names the scope");
    assert_eq!(f.money.observation_scope(UnitKey::new(1)), Some(id));

    let counts = [("work_units", 20, 0)];
    let first = f
        .custody
        .observe(&who.caller(), &owner, &observation(id, OBS_FINAL, &counts))
        .await;
    assert_eq!(first.0, OBS_ACCEPTED);
    let receipt: Receipt = busbar_contract::json::parse(&first.1).unwrap();
    assert!(!receipt.duplicate);
    let again = f
        .custody
        .observe(&who.caller(), &owner, &observation(id, OBS_FINAL, &counts))
        .await;
    assert_eq!(again.0, OBS_ACCEPTED);
    assert!(
        busbar_contract::json::parse::<Receipt>(&again.1)
            .unwrap()
            .duplicate
    );

    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_CLOSE, Some(id), &[])
            .await,
        (OBS_CLOSED, Some(id))
    );
}

#[tokio::test]
async fn attach_answers_the_bound_scope_and_another_scope_is_refused() {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    let (_, id) = f
        .custody
        .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
        .await;
    let id = id.unwrap();
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_ATTACH, Some(id), &[])
            .await,
        (OBS_READY, Some(id))
    );
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_ATTACH, Some([9; 32]), &[])
            .await,
        (OBS_REFUSED, None)
    );
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_ATTACH, None, &[])
            .await,
        (OBS_REFUSED, None),
        "an attach names its scope"
    );
}

#[tokio::test]
async fn custody_is_the_verified_principals_and_the_instances_only() {
    let f = fixture().await;
    let who = who();
    let counts = [("work_units", 1, 0)];
    // Another principal does not reach the owner's unit.
    let mallory = subject_identity("mallory");
    assert_eq!(
        f.custody
            .scope(&who.caller(), &mallory, OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
    assert_eq!(
        f.custody
            .observe(
                &who.caller(),
                &mallory,
                &observation([1; 32], OBS_PROVISIONAL, &counts)
            )
            .await
            .0,
        OBS_REFUSED
    );
    // Nor does another plane instance, nor a request with no subject.
    let other = Namespace {
        name: "other".into(),
        ..who
    };
    assert_eq!(
        f.custody
            .scope(
                &other.caller(),
                &subject_identity("owner"),
                OBS_CREATE,
                None,
                &[]
            )
            .await,
        (OBS_REFUSED, None)
    );
    assert_eq!(
        f.custody
            .scope(&self::who().caller(), &[], OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
}

#[tokio::test]
async fn a_class_the_unit_does_not_name_is_refused_and_so_is_an_unknown_state() {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    assert_eq!(
        f.custody
            .scope(&who.caller(), &owner, OBS_CREATE, None, &["nope"])
            .await,
        (OBS_REFUSED, None)
    );
    let (_, id) = f
        .custody
        .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
        .await;
    let id = id.unwrap();
    let nope = [("nope", 1, 0)];
    assert_eq!(
        f.custody
            .observe(&who.caller(), &owner, &observation(id, OBS_FINAL, &nope))
            .await
            .0,
        OBS_REFUSED
    );
    let counts = [("work_units", 1, 0)];
    assert_eq!(
        f.custody
            .observe(&who.caller(), &owner, &observation(id, 99, &counts))
            .await
            .0,
        OBS_REFUSED
    );
    assert_ne!(OBS_PENDING, OBS_REFUSED);
}

/// Every slot is made at boot: the 4,096th live registration is admitted, the next is refused, and one given back
/// admits again.
#[tokio::test]
async fn the_register_holds_its_stated_units_and_refuses_the_next() {
    let f = fixture().await;
    let (instance, policy) = (Arc::from("fixture"), Arc::new(policy()));
    let mut held = Vec::with_capacity(MAX_UNITS);
    // The fixture holds one; fill the rest over many principals.
    for n in 1..MAX_UNITS {
        let subject: Arc<str> = Arc::from(format!("owner-{}", n % 97));
        held.push(
            f.custody
                .register(&instance, &subject, cost_unit(&f.money, &policy))
                .expect("a slot is free"),
        );
    }
    let book_len = || f.custody.book.lock().unwrap().len;
    assert_eq!(book_len(), MAX_UNITS);
    let late: Arc<str> = Arc::from("late");
    assert_eq!(
        f.custody
            .register(&instance, &late, cost_unit(&f.money, &policy))
            .err(),
        Some("usage observation refused")
    );
    drop(held.pop());
    let again = f
        .custody
        .register(&instance, &late, cost_unit(&f.money, &policy))
        .expect("a slot given back is claimed again");
    assert_eq!(book_len(), MAX_UNITS);
    drop((again, held));
    assert_eq!(book_len(), 1, "only the fixture's unit is left");
}

/// Register and drop in a churn of principals: the book ends empty, with no principal entry left (each entry goes
/// with its principal's last unit), and nothing was reserved before the first registration.
#[tokio::test]
async fn registrations_churned_leave_the_book_empty() {
    let f = fixture().await;
    drop(f.registration);
    let (instance, policy) = (Arc::from("fixture"), Arc::new(policy()));
    let subjects: Vec<Arc<str>> = (0..64).map(|n| Arc::from(format!("owner-{n}"))).collect();
    assert_eq!(
        ObsCustody::new(Arc::new(|| 1))
            .book
            .lock()
            .unwrap()
            .by_principal
            .capacity(),
        0,
        "a new custody reserves nothing"
    );
    let mut live: std::collections::VecDeque<Registration> =
        std::collections::VecDeque::with_capacity(MAX_UNITS);
    for round in 0..100_000usize {
        let subject = &subjects[round.wrapping_mul(31) % subjects.len()];
        live.push_back(
            f.custody
                .register(&instance, subject, cost_unit(&f.money, &policy))
                .expect("churn stays under the slot count"),
        );
        // Hold up to 3,000 at once, released oldest first and, every seventh round, newest first.
        if live.len() > 3_000 || round % 7 == 0 {
            if round % 7 == 0 {
                drop(live.pop_back());
            } else {
                drop(live.pop_front());
            }
        }
    }
    drop(live);
    let book = f.custody.book.lock().unwrap();
    assert_eq!(book.len, 0);
    assert!(
        book.by_principal.is_empty(),
        "every principal's entry went with its last unit"
    );
}

/// A principal's units are told apart after others of its chain are released from the middle.
#[tokio::test]
async fn a_unit_released_from_the_middle_of_its_principals_chain_keeps_the_rest_reachable() {
    let f = fixture().await;
    let (instance, owner) = (Arc::from("fixture"), Arc::from("owner"));
    let policy = Arc::new(policy());
    let middle = f
        .custody
        .register(&instance, &owner, cost_unit(&f.money, &policy))
        .unwrap();
    let newest = f
        .custody
        .register(&instance, &owner, cost_unit(&f.money, &policy))
        .unwrap();
    let identity = subject_identity("owner");
    assert!(
        f.custody.resolve("fixture", &identity, None).is_none(),
        "three unattached units cannot be told apart"
    );
    drop(middle);
    drop(newest);
    assert!(
        f.custody.resolve("fixture", &identity, None).is_some(),
        "the fixture's unit is the one left"
    );
    drop(f.registration);
    assert!(f.custody.resolve("fixture", &identity, None).is_none());
    assert!(f.custody.book.lock().unwrap().by_principal.is_empty());
}

/// B-OBSERVE, the register's cost (GROUP-storage step 4): one round is `register`, `resolve` and the
/// registration's drop, each thread on its own principal of one instance, 1 and 8 threads; median and p99 ns per
/// round over `B_OBSERVE_ROUNDS` rounds a thread (default 100,000). The units are built before the clock starts.
/// Run explicitly on the build machine: `--run-ignored only`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run explicitly on the build machine for observation register cost qualification"]
async fn observation_register_cost() {
    let f = fixture().await;
    let rounds = std::env::var("B_OBSERVE_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000usize);
    for threads in [1usize, 8] {
        let started = std::sync::Barrier::new(threads);
        let started = &started;
        let mut samples: Vec<u64> = std::thread::scope(|scope| {
            let (custody, money) = (&f.custody, &f.money);
            let workers: Vec<_> = (0..threads)
                .map(|t| {
                    scope.spawn(move || {
                        let instance: Arc<str> = Arc::from("fixture");
                        let subject: Arc<str> = Arc::from(format!("owner-{t}"));
                        let identity = subject_identity(&subject);
                        let policy = Arc::new(policy());
                        let mut units: Vec<ActiveUnit> =
                            (0..rounds).map(|_| cost_unit(money, &policy)).collect();
                        let mut taken = Vec::with_capacity(rounds);
                        started.wait();
                        for unit in units.drain(..) {
                            let at = std::time::Instant::now();
                            let held = register_for_cost(custody, &instance, &subject, unit);
                            std::hint::black_box(custody.resolve("fixture", &identity, None));
                            drop(held);
                            taken.push(u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX));
                        }
                        taken
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|w| w.join().expect("a cost worker"))
                .collect()
        });
        samples.sort();
        let median = samples[samples.len() / 2];
        let p99 = samples[samples.len() * 99 / 100];
        eprintln!(
            "B-OBSERVE register+resolve+drop threads={threads} rounds={rounds} median_ns={median} p99_ns={p99}"
        );
    }
    drop(f.registration);
}

fn cost_unit(money: &Arc<PlaneMoney>, policy: &Arc<ObservationPolicy>) -> ActiveUnit {
    ActiveUnit {
        money: money.clone(),
        unit: UnitKey::new(1),
        policy: Arc::clone(policy),
        classes: Arc::from(vec!["work_units".to_owned()]),
    }
}

fn register_for_cost(
    custody: &ObsCustody,
    instance: &Arc<str>,
    subject: &Arc<str>,
    unit: ActiveUnit,
) -> Registration {
    custody
        .register(instance, subject, unit)
        .expect("a cost round registers")
}

#[tokio::test]
async fn ending_the_request_releases_the_unit_and_a_policy_naming_another_instance_is_not_registered(
) {
    let f = fixture().await;
    let who = who();
    let owner = subject_identity("owner");
    let Fixture {
        custody,
        money,
        registration,
    } = f;
    drop(registration);
    assert_eq!(
        custody
            .scope(&who.caller(), &owner, OBS_CREATE, None, &[])
            .await,
        (OBS_REFUSED, None)
    );
    let mut foreign = policy();
    foreign.instance = "elsewhere".into();
    assert!(custody
        .register(
            &Arc::from("fixture"),
            &Arc::from("owner"),
            ActiveUnit {
                money,
                unit: UnitKey::new(1),
                policy: Arc::new(foreign),
                classes: Arc::from(vec!["work_units".to_owned()]),
            },
        )
        .is_err());
}
