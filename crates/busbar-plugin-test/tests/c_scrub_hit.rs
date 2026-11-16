// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB-HIT (ABI-MIN3-INTERFACE §14 rounds 5, 7, 18, 19): one register per value change. The scrub-set arm
//! (rotation keeps the previous generation, a second rotation drops the oldest, an unchanged value is not a
//! rotation) is W1-H0's (merged); the custody arms are W1-K2's (registration on the miss path, publish order).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_kernel::custody::{CustodyKey, Probe, SecretCustody};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use tokio::sync::Notify;

use self::fixture::{caller, source, Fixture, Vault};

const V1: &str = "alpha-7Q2x-secret";
const V2: &str = "bravo-9K4m-secret";
const V3: &str = "charlie-3T8p-secret";

/// The vault instance id of the 1,000-round test: above every id its rounds use (10..1010), so no round runs as
/// the vault itself (which custody refuses as a cycle).
const VAULT_INSTANCE: u64 = 1_000_000;

fn masked(scrub: &Scrub, value: &str) -> bool {
    !scrub
        .text(&format!("token {value} rejected"))
        .contains(value)
}

#[test]
fn rotations_keep_one_previous_generation_and_a_repeat_is_not_a_rotation() {
    let scrub = Scrub::new();
    scrub.register(4, &[V1.as_bytes()]);
    scrub.register(4, &[V2.as_bytes()]);
    assert!(masked(&scrub, V1) && masked(&scrub, V2));
    scrub.register(4, &[V3.as_bytes()]);
    assert!(!masked(&scrub, V1), "the oldest generation is dropped");
    assert!(masked(&scrub, V2) && masked(&scrub, V3));
    scrub.register(4, &[V3.as_bytes()]);
    assert!(
        masked(&scrub, V2),
        "the same value again does not shift the slot"
    );
    scrub.forget(4);
    assert!(!masked(&scrub, V3) && !masked(&scrub, V2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_thousand_secret_needs_on_one_handle_register_once() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", V1)], Some(3_600));
    fx.source("vault", 900, Arc::clone(&vault));
    let scrub = fx.instance(1);
    fx.bind(1, 7, source("vault", "db"));
    let tasks: Vec<_> = (0..64)
        .map(|task| {
            let custody = Arc::clone(&fx.custody);
            tokio::spawn(async move {
                let rounds = if task < 16 { 157 } else { 156 };
                for _ in 0..rounds {
                    let value = custody.resolve(&caller(1), 7).await.expect("resolves");
                    assert_eq!(value.as_slice(), V1.as_bytes());
                }
                rounds
            })
        })
        .collect();
    let mut needs = 0;
    for task in tasks {
        needs += task.await.expect("joins");
    }
    assert_eq!(needs, 10_000);
    assert_eq!(vault.calls(), 1, "one resolve");
    assert_eq!(fx.resolved(1), 1, "one registration");
    assert_eq!(fx.custody.generation(&caller(1), 7), 1);
    assert!(masked(&scrub, V1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_instances_each_register_on_their_first_resolve() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", V1)], Some(3_600));
    fx.source("vault", 900, Arc::clone(&vault));
    let x = fx.instance(1);
    let y = fx.instance(2);
    fx.bind(1, 1, source("vault", "db"));
    fx.bind(2, 5, source("vault", "db"));
    fx.custody.resolve(&caller(1), 1).await.expect("x");
    assert!(masked(&x, V1));
    assert!(
        !masked(&y, V1),
        "nothing is shared with an instance that has not resolved"
    );
    fx.custody.resolve(&caller(2), 5).await.expect("y");
    assert!(masked(&y, V1));
    assert_eq!(
        vault.calls(),
        1,
        "the second came from the source-level cache"
    );
    assert_eq!(
        (fx.resolved(1), fx.resolved(2)),
        (1, 1),
        "each registered on its own miss"
    );
    for _ in 0..100 {
        fx.custody.resolve(&caller(1), 1).await.expect("hit");
        fx.custody.resolve(&caller(2), 5).await.expect("hit");
    }
    assert_eq!(
        (fx.resolved(1), fx.resolved(2)),
        (1, 1),
        "hits register nothing"
    );
    let reopened = fx.instance(3);
    fx.bind(3, 1, source("vault", "db"));
    fx.custody
        .resolve(&caller(3), 1)
        .await
        .expect("the reopened instance");
    assert_eq!(fx.resolved(3), 1);
    assert!(masked(&reopened, V1));
}

/// Parks the first leading miss after it arms, until released.
struct Park {
    armed: Arc<AtomicBool>,
    parked: Arc<Notify>,
    release: Arc<Notify>,
}

impl Park {
    fn install(fx: &Fixture, publish_first: bool) -> Self {
        let park = Park {
            armed: Arc::new(AtomicBool::new(false)),
            parked: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        let (armed, parked, release) = (
            Arc::clone(&park.armed),
            Arc::clone(&park.parked),
            Arc::clone(&park.release),
        );
        fx.custody.set_probe(Some(Probe {
            park: Arc::new(move |_: CustodyKey| -> BoxFut<'static, ()> {
                if !armed.swap(false, Ordering::SeqCst) {
                    return Box::pin(async {});
                }
                let (parked, release) = (Arc::clone(&parked), Arc::clone(&release));
                Box::pin(async move {
                    parked.notify_one();
                    release.notified().await;
                })
            }),
            publish_first,
        }));
        park
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

/// Chain B of instance `id`: resolve, then FAIL and log a line that carries the value.
fn chain_b(fx: &Fixture, id: u64) -> tokio::task::JoinHandle<(String, String, String)> {
    let custody = Arc::clone(&fx.custody);
    let scrub = fx.scrub(id);
    tokio::spawn(async move {
        let value = custody.resolve(&caller(id), 1).await.expect("B resolves");
        let value = String::from(core::str::from_utf8(value.as_slice()).expect("utf-8"));
        let line = format!("token {value} rejected");
        let failed = fail_text(&scrub, &line).into_owned();
        let logged = scrub.text(&line).into_owned();
        (value, failed, logged)
    })
}

/// The window in which B must still be waiting on A. A wrong order lets B finish in microseconds; the first
/// round holds the IF's full 100 ms.
fn window(round: usize) -> Duration {
    if round == 0 {
        Duration::from_millis(100)
    } else {
        Duration::from_millis(2)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publish_waits_for_register_and_the_publish_first_control_is_red() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", V1)], Some(60));
    fx.source("vault", VAULT_INSTANCE, Arc::clone(&vault));
    let park = Park::install(&fx, false);

    // 1,000 rounds: v1 registered, the lease expires on a rotation to v2, chain A misses and parks before its
    // register, chain B of the same instance waits on A and, once A is released, shows v2 masked.
    for round in 0..1_000 {
        let id = 10 + round as u64;
        fx.advance(61);
        vault.set("db", V1);
        fx.instance(id);
        fx.bind(id, 1, source("vault", "db"));
        fx.custody.resolve(&caller(id), 1).await.expect("v1");
        vault.set("db", V2);
        fx.advance(61);
        park.arm();
        let custody = Arc::clone(&fx.custody);
        let a = tokio::spawn(async move { custody.resolve(&caller(id), 1).await.map(|_| ()) });
        park.parked.notified().await;
        let mut b = chain_b(&fx, id);
        assert!(
            tokio::time::timeout(window(round), &mut b).await.is_err(),
            "round {round}: B completed while A was parked before its register"
        );
        park.release.notify_one();
        a.await.expect("A joins").expect("A resolves");
        let (value, failed, logged) = b.await.expect("B joins");
        assert_eq!(value, V2, "round {round}");
        assert_eq!(
            fx.resolved(id),
            2,
            "round {round}: v1 and v2 registered once each"
        );
        for shown in [&failed, &logged] {
            assert!(
                !shown.contains(V2) && !shown.contains(V1),
                "round {round}: {shown}"
            );
            assert!(shown.contains("***"), "round {round}: {shown}");
        }
    }

    // X's first resolve, with no v1: B waits on A's in-flight resolve and shows v1 masked.
    let id = 5_000;
    fx.advance(61);
    vault.set("db", V1);
    fx.instance(id);
    fx.bind(id, 1, source("vault", "db"));
    park.arm();
    let custody = Arc::clone(&fx.custody);
    let a = tokio::spawn(async move { custody.resolve(&caller(id), 1).await.map(|_| ()) });
    park.parked.notified().await;
    let mut b = chain_b(&fx, id);
    assert!(tokio::time::timeout(window(0), &mut b).await.is_err());
    park.release.notify_one();
    a.await.expect("A joins").expect("A resolves");
    let (value, failed, _) = b.await.expect("B joins");
    assert_eq!(value, V1);
    assert!(!failed.contains(V1), "{failed}");
    assert_eq!(fx.resolved(id), 1);

    // A's chain dropped while parked: B becomes the leader, registers, masks; nothing hangs.
    let id = 5_001;
    fx.advance(61);
    vault.set("db", V2);
    fx.instance(id);
    fx.bind(id, 1, source("vault", "db"));
    park.arm();
    let custody = Arc::clone(&fx.custody);
    let a = tokio::spawn(async move { custody.resolve(&caller(id), 1).await.map(|_| ()) });
    park.parked.notified().await;
    let b = chain_b(&fx, id);
    a.abort();
    let (value, failed, logged) = tokio::time::timeout(Duration::from_secs(5), b)
        .await
        .expect("nothing hangs")
        .expect("B joins");
    assert_eq!(value, V2);
    assert!(
        !failed.contains(V2) && !logged.contains(V2),
        "{failed} / {logged}"
    );
    assert_eq!(fx.resolved(id), 1, "only B registered");

    // A's resolve fails: B leads, and the failure is not cached.
    let id = 5_002;
    fx.advance(61);
    vault.set("db", V3);
    fx.instance(id);
    fx.bind(id, 1, source("vault", "db"));
    let gate = vault.gate_next_and_fail();
    let custody = Arc::clone(&fx.custody);
    let a = tokio::spawn(async move { custody.resolve(&caller(id), 1).await.map(|_| ()) });
    while vault.waiting() == 0 {
        tokio::task::yield_now().await;
    }
    let mut b = chain_b(&fx, id);
    assert!(tokio::time::timeout(window(0), &mut b).await.is_err());
    gate.notify_one();
    assert!(a.await.expect("A joins").is_err(), "A's resolve failed");
    let (value, failed, _) = b.await.expect("B joins");
    assert_eq!(value, V3);
    assert!(!failed.contains(V3), "{failed}");
    assert_eq!(fx.resolved(id), 1);

    // Negative control: publishing before register lets B finish while A is parked, with v2 in the clear. The
    // case sees that, so it goes red on any custody that publishes first.
    let park = Park::install(&fx, true);
    let id = 5_003;
    fx.advance(61);
    vault.set("db", V1);
    fx.instance(id);
    fx.bind(id, 1, source("vault", "db"));
    fx.custody.resolve(&caller(id), 1).await.expect("v1");
    vault.set("db", V2);
    fx.advance(61);
    park.arm();
    let custody = Arc::clone(&fx.custody);
    let a = tokio::spawn(async move { custody.resolve(&caller(id), 1).await.map(|_| ()) });
    park.parked.notified().await;
    let b = chain_b(&fx, id);
    let (value, failed, _) = tokio::time::timeout(Duration::from_secs(5), b)
        .await
        .expect("publish-first: B completes while A is parked")
        .expect("B joins");
    assert_eq!(value, V2);
    assert!(
        failed.contains(V2),
        "publish-first must leak v2 for this case to be able to see the wrong order: {failed}"
    );
    park.release.notify_one();
    a.await.expect("A joins").expect("A resolves");
}

/// The custody fixture the custody arms share (C-SCRUB's template arm too): a registry with fixed bindings, scrub
/// sets and secret instances, a counting vault and a clock the arms move.
pub(crate) mod fixture {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use busbar_contract::secret_ref::SecretRef;
    use busbar_contract::secure::SecureVec;
    use busbar_kernel::custody::{Custody, CustodyEvent, CustodyHost, CustodyKey, SecretSource};
    use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
    use busbar_plugin_abi::fail::refused::R_NOT_FOUND;
    use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_abi::types::KindCode;
    use busbar_plugin_loader::ports::secret::{SecretAnswer, SecretPort};
    use busbar_plugin_loader::ports::{CallCx, PortError};
    use tokio::sync::Notify;

    type Audits = Vec<(u64, u32, CustodyEvent)>;

    #[derive(Default)]
    pub(crate) struct World {
        bindings: Mutex<Vec<(CustodyKey, SecretRef)>>,
        scrubs: Mutex<Vec<(u64, Arc<Scrub>)>>,
        sources: Mutex<Vec<(&'static str, SecretSource)>>,
        audits: Mutex<Audits>,
        elapsed_s: AtomicU64,
    }

    pub(crate) struct Host {
        world: Arc<World>,
        base: Instant,
    }

    impl CustodyHost for Host {
        fn binding(&self, key: CustodyKey) -> Option<SecretRef> {
            let bindings = self.world.bindings.lock().expect("bindings");
            bindings
                .iter()
                .find(|(bound, _)| *bound == key)
                .map(|(_, reference)| reference.clone())
        }

        fn scrub(&self, who: &Caller<'_>) -> Option<Arc<Scrub>> {
            let scrubs = self.world.scrubs.lock().expect("scrubs");
            scrubs
                .iter()
                .find(|(instance, _)| *instance == who.instance)
                .map(|(_, scrub)| Arc::clone(scrub))
        }

        fn source(&self, module: &str) -> Option<SecretSource> {
            let sources = self.world.sources.lock().expect("sources");
            sources
                .iter()
                .find(|(name, _)| *name == module)
                .map(|(_, source)| source.clone())
        }

        fn audit(&self, who: &Caller<'_>, handle: u32, event: CustodyEvent) {
            self.world
                .audits
                .lock()
                .expect("audits")
                .push((who.instance, handle, event));
        }

        fn now(&self) -> Instant {
            self.base + Duration::from_secs(self.world.elapsed_s.load(Ordering::SeqCst))
        }
    }

    /// A secret source: answers the value whose name appears in the reference it is handed.
    pub(crate) struct Vault {
        values: Mutex<Vec<(&'static str, &'static str)>>,
        lease_s: Option<u64>,
        calls: AtomicUsize,
        gate: Mutex<Option<Arc<Notify>>>,
        waiting: AtomicUsize,
    }

    impl Vault {
        pub(crate) fn new(
            values: &[(&'static str, &'static str)],
            lease_s: Option<u64>,
        ) -> Arc<Self> {
            Arc::new(Vault {
                values: Mutex::new(values.to_vec()),
                lease_s,
                calls: AtomicUsize::new(0),
                gate: Mutex::new(None),
                waiting: AtomicUsize::new(0),
            })
        }

        pub(crate) fn set(&self, name: &'static str, value: &'static str) {
            let mut values = self.values.lock().expect("values");
            values.retain(|(held, _)| *held != name);
            values.push((name, value));
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        /// The next call waits on the returned gate and then fails (FAILED, F_UNAVAILABLE).
        pub(crate) fn gate_next_and_fail(&self) -> Arc<Notify> {
            let gate = Arc::new(Notify::new());
            *self.gate.lock().expect("gate") = Some(Arc::clone(&gate));
            gate
        }

        /// Calls parked on a gate right now.
        pub(crate) fn waiting(&self) -> usize {
            self.waiting.load(Ordering::SeqCst)
        }
    }

    impl SecretPort for Vault {
        fn resolve<'a>(
            &'a self,
            _cx: CallCx,
            reference: &'a [u8],
        ) -> BoxFut<'a, Result<SecretAnswer, PortError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.lock().expect("gate").take();
            let text = core::str::from_utf8(reference).unwrap_or("");
            let found = {
                let values = self.values.lock().expect("values");
                values
                    .iter()
                    .find(|(name, _)| text.contains(name))
                    .map(|(_, value)| *value)
            };
            Box::pin(async move {
                if let Some(gate) = gate {
                    self.waiting.fetch_add(1, Ordering::SeqCst);
                    gate.notified().await;
                    self.waiting.fetch_sub(1, Ordering::SeqCst);
                    return Err(PortError::Failed {
                        code: F_UNAVAILABLE,
                        text: Box::from("vault unreachable"),
                        retry_after_s: None,
                        backend_status: None,
                        error: None,
                    });
                }
                match found {
                    Some(value) => Ok(SecretAnswer {
                        value: SecureVec::from(value.as_bytes()),
                        lease_s: self.lease_s,
                    }),
                    None => Err(PortError::Refused {
                        code: R_NOT_FOUND,
                        text: Box::from("no such name"),
                        error: None,
                    }),
                }
            })
        }
    }

    pub(crate) struct Fixture {
        world: Arc<World>,
        pub(crate) custody: Arc<Custody<Host>>,
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            let world = Arc::new(World::default());
            let custody = Arc::new(Custody::new(Host {
                world: Arc::clone(&world),
                base: Instant::now(),
            }));
            Fixture { world, custody }
        }

        pub(crate) fn source(&self, module: &'static str, instance: u64, vault: Arc<Vault>) {
            self.world.sources.lock().expect("sources").push((
                module,
                SecretSource {
                    instance,
                    port: vault,
                },
            ));
        }

        /// A new instance and its scrub set (the one its log sink, adapters and audit rows scrub through).
        pub(crate) fn instance(&self, instance: u64) -> Arc<Scrub> {
            let scrub = Arc::new(Scrub::new());
            self.world
                .scrubs
                .lock()
                .expect("scrubs")
                .push((instance, Arc::clone(&scrub)));
            scrub
        }

        pub(crate) fn scrub(&self, instance: u64) -> Arc<Scrub> {
            let scrubs = self.world.scrubs.lock().expect("scrubs");
            scrubs
                .iter()
                .find(|(id, _)| *id == instance)
                .map(|(_, scrub)| Arc::clone(scrub))
                .expect("a live instance")
        }

        pub(crate) fn bind(&self, instance: u64, handle: u32, reference: SecretRef) {
            self.world
                .bindings
                .lock()
                .expect("bindings")
                .push((CustodyKey { instance, handle }, reference));
        }

        pub(crate) fn advance(&self, seconds: u64) {
            self.world.elapsed_s.fetch_add(seconds, Ordering::SeqCst);
        }

        /// Resolves that registered a value for `instance` (custody's `Resolved` row follows every register).
        pub(crate) fn resolved(&self, instance: u64) -> usize {
            self.audited(instance, CustodyEvent::Resolved)
        }

        pub(crate) fn audited(&self, instance: u64, event: CustodyEvent) -> usize {
            let audits = self.world.audits.lock().expect("audits");
            audits
                .iter()
                .filter(|(id, _, seen)| *id == instance && *seen == event)
                .count()
        }
    }

    pub(crate) fn caller(instance: u64) -> Caller<'static> {
        Caller {
            plugin: "fixture",
            kind: KindCode::Plane,
            name: "fixture",
            instance,
            slot: 1,
            chain: 1,
            deadline: Instant::now() + Duration::from_secs(60),
            stack: CallStack::default(),
            out_of_process: false,
            limits: InstanceLimits::default(),
        }
    }

    pub(crate) fn source(module: &str, name: &str) -> SecretRef {
        let json = format!(r#"{{"module":"{module}","settings":{{"name":"{name}"}}}}"#);
        busbar_contract::json::parse(json.as_bytes()).expect("a source reference")
    }

    pub(crate) fn template(text: &str) -> SecretRef {
        let json = format!(
            r#"{{"template":{{"text":"{text}","source":{{"module":"env","setting":"name"}}}}}}"#
        );
        busbar_contract::json::parse(json.as_bytes()).expect("a template reference")
    }
}
