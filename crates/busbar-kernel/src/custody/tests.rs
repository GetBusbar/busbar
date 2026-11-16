// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Custody (IF §12.2): the per-instance cache, its refusals, templates, leases and the scrub registration that
//! goes with every miss. Every fixture answers at once, so each resolve is polled to completion in one go.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
use busbar_plugin_abi::fail::refused::R_DENIED;
use busbar_plugin_abi::host_side::caller::InstanceLimits;
use busbar_plugin_abi::host_side::scrub::{fail_text, needles};
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::ports::secret::SecretAnswer;
use futures::FutureExt;

use super::*;

/// The registry as custody sees it: bindings, scrub sets, secret instances, audit rows and a clock.
#[derive(Default)]
struct World {
    bindings: Mutex<Vec<(CustodyKey, SecretRef)>>,
    scrubs: Mutex<Vec<(u64, Arc<Scrub>)>>,
    sources: Mutex<Vec<(&'static str, SecretSource)>>,
    audits: Mutex<Vec<(u64, u32, CustodyEvent)>>,
    elapsed_s: AtomicU64,
}

struct Host {
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

/// A secret source: answers the first value whose name appears in the reference it is handed.
struct Vault {
    values: Mutex<Vec<(&'static str, &'static str)>>,
    lease_s: Option<u64>,
    calls: AtomicUsize,
    fail: Mutex<Option<PortError>>,
}

impl Vault {
    fn new(values: &[(&'static str, &'static str)], lease_s: Option<u64>) -> Arc<Self> {
        Arc::new(Vault {
            values: Mutex::new(values.to_vec()),
            lease_s,
            calls: AtomicUsize::new(0),
            fail: Mutex::new(None),
        })
    }

    fn set(&self, name: &'static str, value: &'static str) {
        let mut values = self.values.lock().expect("values");
        values.retain(|(held, _)| *held != name);
        values.push((name, value));
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SecretPort for Vault {
    fn resolve<'a>(
        &'a self,
        _cx: CallCx,
        reference: &'a [u8],
    ) -> BoxFut<'a, Result<SecretAnswer, PortError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = match self.fail.lock().expect("fail").take() {
            Some(error) => Err(error),
            None => {
                let text = core::str::from_utf8(reference).unwrap_or("");
                let values = self.values.lock().expect("values");
                match values.iter().find(|(name, _)| text.contains(name)) {
                    Some((_, value)) => Ok(SecretAnswer {
                        value: SecureVec::from(value.as_bytes()),
                        lease_s: self.lease_s,
                    }),
                    None => Err(PortError::Refused {
                        code: R_NOT_FOUND,
                        text: Box::from("no such name"),
                        error: None,
                    }),
                }
            }
        };
        Box::pin(core::future::ready(answer))
    }
}

struct Fixture {
    world: Arc<World>,
    custody: Custody<Host>,
}

impl Fixture {
    fn new() -> Self {
        let world = Arc::new(World::default());
        let custody = Custody::new(Host {
            world: Arc::clone(&world),
            base: Instant::now(),
        });
        Fixture { world, custody }
    }

    fn source(&self, module: &'static str, instance: u64, port: Arc<Vault>) {
        self.world
            .sources
            .lock()
            .expect("sources")
            .push((module, SecretSource { instance, port }));
    }

    fn instance(&self, instance: u64) -> Arc<Scrub> {
        let scrub = Arc::new(Scrub::new());
        self.world
            .scrubs
            .lock()
            .expect("scrubs")
            .push((instance, Arc::clone(&scrub)));
        scrub
    }

    fn bind(&self, instance: u64, handle: u32, reference: SecretRef) {
        self.world
            .bindings
            .lock()
            .expect("bindings")
            .push((CustodyKey { instance, handle }, reference));
    }

    fn resolve(&self, who: &Caller<'_>, handle: u32) -> Result<Arc<SecureVec>, CustodyDenied> {
        self.custody
            .resolve(who, handle)
            .now_or_never()
            .expect("every fixture answers at once")
    }

    fn audits(&self, event: CustodyEvent) -> usize {
        let audits = self.world.audits.lock().expect("audits");
        audits.iter().filter(|(_, _, seen)| *seen == event).count()
    }

    fn advance(&self, seconds: u64) {
        self.world.elapsed_s.fetch_add(seconds, Ordering::SeqCst);
    }
}

fn caller(instance: u64) -> Caller<'static> {
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

fn source(module: &str, name: &str) -> SecretRef {
    let json = format!(r#"{{"module":"{module}","settings":{{"name":"{name}"}}}}"#);
    busbar_contract::json::parse(json.as_bytes()).expect("a source reference")
}

fn template(text: &str) -> SecretRef {
    let json = format!(
        r#"{{"template":{{"text":"{text}","source":{{"module":"env","setting":"name"}}}}}}"#
    );
    busbar_contract::json::parse(json.as_bytes()).expect("a template reference")
}

fn masked(scrub: &Scrub, value: &str) -> bool {
    !scrub
        .text(&format!("token {value} rejected"))
        .contains(value)
}

fn value(resolved: &Arc<SecureVec>) -> &str {
    core::str::from_utf8(resolved.as_slice()).expect("utf-8")
}

#[test]
fn a_hit_serves_the_published_arc_and_registers_nothing_again() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", "sk-live-0001-db")], None);
    fx.source("vault", 50, Arc::clone(&vault));
    let scrub = fx.instance(1);
    fx.bind(1, 3, source("vault", "db"));
    let who = caller(1);
    assert_eq!(fx.custody.generation(&who, 3), 0);
    let first = fx.resolve(&who, 3).expect("resolves");
    let again = fx.resolve(&who, 3).expect("hits");
    assert!(Arc::ptr_eq(&first, &again), "a hit is the published Arc");
    assert_eq!(value(&first), "sk-live-0001-db");
    assert_eq!(vault.calls(), 1);
    assert_eq!(fx.audits(CustodyEvent::Resolved), 1);
    assert_eq!(fx.custody.generation(&who, 3), 1);
    assert!(masked(&scrub, "sk-live-0001-db"));
}

#[test]
fn a_foreign_handle_is_refused_and_audited() {
    let fx = Fixture::new();
    fx.instance(1);
    assert_eq!(
        fx.resolve(&caller(1), 9).err(),
        Some(CustodyDenied::ForeignHandle)
    );
    assert_eq!(fx.audits(CustodyEvent::HandleForeign), 1);
}

#[test]
fn none_is_not_found_and_an_unknown_module_is_no_such_source() {
    let fx = Fixture::new();
    fx.instance(1);
    fx.bind(1, 1, SecretRef::None);
    fx.bind(1, 2, source("nowhere", "db"));
    assert_eq!(
        fx.resolve(&caller(1), 1).err(),
        Some(CustodyDenied::NotFound)
    );
    assert_eq!(
        fx.resolve(&caller(1), 2).err(),
        Some(CustodyDenied::NoSuchSecretSource)
    );
}

#[test]
fn a_self_reference_and_a_full_stack_are_cycles() {
    let fx = Fixture::new();
    fx.source("own", 1, Vault::new(&[("db", "sk-live-0002-db")], None));
    fx.instance(1);
    fx.instance(2);
    fx.bind(1, 1, source("own", "db"));
    fx.bind(2, 1, source("own", "db"));
    assert_eq!(
        fx.resolve(&caller(1), 1).err(),
        Some(CustodyDenied::Cycle),
        "A -> A"
    );
    let mut deep = caller(2);
    deep.stack = CallStack {
        ids: [11, 12, 13, 14],
        depth: 4,
    };
    assert_eq!(
        fx.resolve(&deep, 1).err(),
        Some(CustodyDenied::Cycle),
        "depth 4"
    );
    let mut through = caller(2);
    through.stack = CallStack {
        ids: [1, 0, 0, 0],
        depth: 1,
    };
    assert_eq!(
        fx.resolve(&through, 1).err(),
        Some(CustodyDenied::Cycle),
        "A -> B -> A"
    );
}

#[test]
fn refusals_reach_the_plugin_as_variants_with_no_text() {
    let fx = Fixture::new();
    let vault = Vault::new(&[], None);
    fx.source("vault", 50, Arc::clone(&vault));
    fx.instance(1);
    fx.bind(1, 1, source("vault", "missing"));
    assert_eq!(
        fx.resolve(&caller(1), 1).err(),
        Some(CustodyDenied::NotFound)
    );
    *vault.fail.lock().expect("fail") = Some(PortError::Refused {
        code: R_DENIED,
        text: Box::from("vault said no for vault-prod-7"),
        error: None,
    });
    assert_eq!(fx.resolve(&caller(1), 1).err(), Some(CustodyDenied::Denied));
    *vault.fail.lock().expect("fail") = Some(PortError::Failed {
        code: F_UNAVAILABLE,
        text: Box::from("vault-prod-7 down"),
        retry_after_s: None,
        backend_status: None,
        error: None,
    });
    assert_eq!(
        fx.resolve(&caller(1), 1).err(),
        Some(CustodyDenied::Unavailable)
    );
}

#[test]
fn a_failure_is_never_cached() {
    let fx = Fixture::new();
    let vault = Vault::new(&[], None);
    fx.source("vault", 50, Arc::clone(&vault));
    fx.instance(1);
    fx.bind(1, 1, source("vault", "db"));
    assert_eq!(
        fx.resolve(&caller(1), 1).err(),
        Some(CustodyDenied::NotFound)
    );
    vault.set("db", "sk-live-0003-db");
    assert_eq!(
        value(&fx.resolve(&caller(1), 1).expect("now it resolves")),
        "sk-live-0003-db"
    );
    assert_eq!(vault.calls(), 2);
}

#[test]
fn a_template_registers_its_rendered_value_and_every_fill_in_one_call() {
    let fx = Fixture::new();
    let env = Vault::new(&[("TOKEN", "abc-fill-9q7w"), ("SHORT", "ab")], None);
    fx.source("env", 60, env);
    let scrub = fx.instance(1);
    fx.bind(1, 1, template("Bearer ${TOKEN}"));
    fx.bind(1, 2, template("key ${SHORT}"));
    let rendered = fx.resolve(&caller(1), 1).expect("renders");
    assert_eq!(value(&rendered), "Bearer abc-fill-9q7w");
    assert!(masked(&scrub, "abc-fill-9q7w"), "a fill alone is masked");
    for form in needles(b"abc-fill-9q7w") {
        let form = core::str::from_utf8(&form).expect("ascii");
        assert!(masked(&scrub, form), "{form} survived");
    }
    let shown = fail_text(&scrub, "upstream said abc-fill-9q7w");
    assert!(!shown.contains("abc-fill-9q7w"), "{shown}");
    assert_eq!(fx.audits(CustodyEvent::TooShortToScrub), 0);
    fx.resolve(&caller(1), 2).expect("renders");
    assert_eq!(
        fx.audits(CustodyEvent::TooShortToScrub),
        1,
        "a 2-byte fill is audited"
    );
}

#[test]
fn a_lease_renewal_keeps_the_previous_generation_masked_and_drops_the_one_before() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", "alpha-7Q2x-secret")], Some(60));
    fx.source("vault", 50, Arc::clone(&vault));
    let scrub = fx.instance(1);
    fx.bind(1, 1, source("vault", "db"));
    let who = caller(1);
    fx.resolve(&who, 1).expect("v1");
    vault.set("db", "bravo-9K4m-secret");
    fx.advance(30);
    assert_eq!(
        value(&fx.resolve(&who, 1).expect("v1 still leased")),
        "alpha-7Q2x-secret"
    );
    fx.advance(31);
    assert_eq!(
        value(&fx.resolve(&who, 1).expect("v2")),
        "bravo-9K4m-secret"
    );
    assert_eq!(fx.custody.generation(&who, 1), 2);
    assert!(masked(&scrub, "alpha-7Q2x-secret") && masked(&scrub, "bravo-9K4m-secret"));
    vault.set("db", "charlie-3T8p-secret");
    fx.advance(61);
    fx.resolve(&who, 1).expect("v3");
    assert!(
        !masked(&scrub, "alpha-7Q2x-secret"),
        "two changes old is dropped"
    );
    assert!(masked(&scrub, "bravo-9K4m-secret") && masked(&scrub, "charlie-3T8p-secret"));
}

#[test]
fn each_instance_registers_its_own_first_resolve_even_on_a_source_level_hit() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", "sk-live-0004-db")], Some(300));
    fx.source("vault", 50, Arc::clone(&vault));
    let first = fx.instance(1);
    let second = fx.instance(2);
    fx.bind(1, 1, source("vault", "db"));
    fx.bind(2, 4, source("vault", "db"));
    fx.resolve(&caller(1), 1).expect("instance 1");
    assert!(
        !masked(&second, "sk-live-0004-db"),
        "nothing shared before its own resolve"
    );
    fx.resolve(&caller(2), 4).expect("instance 2");
    assert_eq!(
        vault.calls(),
        1,
        "the leased value came from the source-level cache"
    );
    assert!(masked(&first, "sk-live-0004-db") && masked(&second, "sk-live-0004-db"));
    assert_eq!(fx.audits(CustodyEvent::Resolved), 2);
}

#[test]
fn a_dropped_instance_starts_again_empty() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", "sk-live-0005-db")], None);
    fx.source("vault", 50, Arc::clone(&vault));
    fx.instance(1);
    fx.bind(1, 1, source("vault", "db"));
    fx.resolve(&caller(1), 1).expect("first");
    fx.custody.drop_instance(1);
    assert_eq!(fx.custody.generation(&caller(1), 1), 0);
    fx.resolve(&caller(1), 1).expect("again");
    assert_eq!(
        vault.calls(),
        2,
        "an unleased value is not cached at source level"
    );
}

#[test]
fn no_scrub_set_means_no_value() {
    let fx = Fixture::new();
    fx.source("vault", 50, Vault::new(&[("db", "sk-live-0006-db")], None));
    fx.bind(1, 1, source("vault", "db"));
    assert_eq!(
        fx.resolve(&caller(1), 1).err(),
        Some(CustodyDenied::Unavailable)
    );
}

#[test]
fn resolve_ref_answers_kernel_callers_and_registers_in_no_instance() {
    let fx = Fixture::new();
    fx.source("vault", 50, Vault::new(&[("db", "sk-live-0007-db")], None));
    let scrub = fx.instance(1);
    let reference = source("vault", "db");
    let cx = CallCx {
        deadline: Instant::now() + Duration::from_secs(60),
        request_id: 0,
        stack: CallStack::default(),
    };
    let value = fx
        .custody
        .resolve_ref(cx, &reference)
        .now_or_never()
        .expect("ready")
        .expect("resolves");
    assert_eq!(value.as_slice(), b"sk-live-0007-db");
    assert!(!masked(&scrub, "sk-live-0007-db"));
    assert_eq!(fx.audits(CustodyEvent::Resolved), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_of_one_key_make_one_resolve() {
    struct Slow(AtomicUsize);
    impl SecretPort for Slow {
        fn resolve<'a>(
            &'a self,
            _cx: CallCx,
            _reference: &'a [u8],
        ) -> BoxFut<'a, Result<SecretAnswer, PortError>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(SecretAnswer {
                    value: SecureVec::from(&b"sk-live-0008-db"[..]),
                    lease_s: None,
                })
            })
        }
    }
    let world = Arc::new(World::default());
    let slow = Arc::new(Slow(AtomicUsize::new(0)));
    world.sources.lock().expect("sources").push((
        "vault",
        SecretSource {
            instance: 50,
            port: Arc::clone(&slow) as Arc<dyn SecretPort>,
        },
    ));
    world
        .scrubs
        .lock()
        .expect("scrubs")
        .push((1, Arc::new(Scrub::new())));
    world.bindings.lock().expect("bindings").push((
        CustodyKey {
            instance: 1,
            handle: 1,
        },
        source("vault", "db"),
    ));
    let custody = Arc::new(Custody::new(Host {
        world: Arc::clone(&world),
        base: Instant::now(),
    }));
    let tasks: Vec<_> = (0..64)
        .map(|_| {
            let custody = Arc::clone(&custody);
            tokio::spawn(async move { custody.resolve(&caller(1), 1).await })
        })
        .collect();
    for task in tasks {
        task.await.expect("joins").expect("resolves");
    }
    assert_eq!(slow.0.load(Ordering::SeqCst), 1);
    let resolved = world
        .audits
        .lock()
        .expect("audits")
        .iter()
        .filter(|(_, _, event)| *event == CustodyEvent::Resolved)
        .count();
    assert_eq!(resolved, 1, "one registration for 64 misses");
}
