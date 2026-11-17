// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SECRET-CYCLE (ABI-MIN3-INTERFACE §14): Secret fixtures A -> B -> A: Cycle at the second hop; depth 5 refused.
//!
//! W1-L4 (custody, merged): the arm drives the kernel's real `Custody` over fixed tables. Secret instance A
//! (id 1) and B (id 2) are `SecretPort` fixtures; B's `resolve` makes the nested SECRET Need the way the secret
//! adapter does, carrying the `CallCx` stack it was handed into its `Caller`. The refusal is custody's `Cycle`,
//! found at the second hop (B asking for A, which is already on the stack), and no plugin is called a second time.
//! The depth arm hands custody a full call stack (4 ids): a fifth nested resolve is refused `Cycle` before any
//! secret instance is called.

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::{
    Custody, CustodyDenied, CustodyEvent, CustodyHost, CustodyKey, SecretCustody, SecretSource,
};
use busbar_plugin_abi::fail::refused::R_DENIED;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::types::KindCode;
use busbar_ports::secret::{SecretAnswer, SecretPort};
use busbar_ports::{CallCx, PortError};

/// What custody reads from the registry: bindings, scrub sets, secret instances, and the audit rows it wrote.
#[derive(Default)]
pub(crate) struct World {
    bindings: Mutex<Vec<(CustodyKey, SecretRef)>>,
    scrubs: Mutex<Vec<(u64, Arc<Scrub>)>>,
    sources: Mutex<Vec<(&'static str, SecretSource)>>,
    audits: Mutex<Vec<(u64, u32, CustodyEvent)>>,
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
        self.base
    }
}

/// Drives a future that answers without waiting.
pub(crate) fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("every fixture answers at once"),
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

/// A secret instance that answers a fixed value, counting its calls.
struct Plain {
    calls: AtomicUsize,
}

impl SecretPort for Plain {
    fn resolve<'a>(
        &'a self,
        _cx: CallCx,
        _reference: &'a [u8],
    ) -> BoxFut<'a, Result<SecretAnswer, PortError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(core::future::ready(Ok(SecretAnswer {
            value: SecureVec::from(&b"sk-live-cycle-0001"[..]),
            lease_s: None,
        })))
    }
}

/// A secret instance whose `resolve` makes one nested SECRET Need: it resolves `handle` of its own bindings
/// through custody, carrying the stack it was called with (the adapter copies `cx.stack` into its `Caller`).
struct Nested {
    instance: u64,
    handle: u32,
    custody: Arc<OnceLock<Arc<Custody<Host>>>>,
    inner: Arc<Mutex<Option<CustodyDenied>>>,
    calls: AtomicUsize,
}

impl SecretPort for Nested {
    fn resolve<'a>(
        &'a self,
        cx: CallCx,
        _reference: &'a [u8],
    ) -> BoxFut<'a, Result<SecretAnswer, PortError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let custody = Arc::clone(self.custody.get().expect("custody is wired"));
        let mut who = caller(self.instance);
        who.stack = cx.stack;
        let handle = self.handle;
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            match custody.resolve(&who, handle).await {
                Ok(value) => Ok(SecretAnswer {
                    value: SecureVec::from(value.as_slice()),
                    lease_s: None,
                }),
                Err(denied) => {
                    *inner.lock().expect("inner") = Some(denied);
                    Err(PortError::Refused {
                        code: R_DENIED,
                        text: Box::from("nested"),
                        error: None,
                    })
                }
            }
        })
    }
}

#[test]
fn a_cycle_is_found_at_the_second_hop_and_depth_5_is_refused() {
    let world = Arc::new(World::default());
    let custody = Arc::new(Custody::new(Host {
        world: Arc::clone(&world),
        base: Instant::now(),
    }));
    let wired = Arc::new(OnceLock::new());
    wired.set(Arc::clone(&custody)).ok().expect("wired once");
    let inner = Arc::new(Mutex::new(None));
    // A (instance 1) names B, B (instance 2) names A: A -> B -> A.
    let a = Arc::new(Nested {
        instance: 1,
        handle: 1,
        custody: Arc::clone(&wired),
        inner: Arc::new(Mutex::new(None)),
        calls: AtomicUsize::new(0),
    });
    let b = Arc::new(Nested {
        instance: 2,
        handle: 1,
        custody: Arc::clone(&wired),
        inner: Arc::clone(&inner),
        calls: AtomicUsize::new(0),
    });
    {
        let mut sources = world.sources.lock().expect("sources");
        sources.push((
            "a",
            SecretSource {
                instance: 1,
                port: Arc::clone(&a) as Arc<dyn SecretPort>,
            },
        ));
        sources.push((
            "b",
            SecretSource {
                instance: 2,
                port: Arc::clone(&b) as Arc<dyn SecretPort>,
            },
        ));
        let mut scrubs = world.scrubs.lock().expect("scrubs");
        scrubs.push((1, Arc::new(Scrub::new())));
        scrubs.push((2, Arc::new(Scrub::new())));
        let mut bindings = world.bindings.lock().expect("bindings");
        bindings.push((
            CustodyKey {
                instance: 1,
                handle: 1,
            },
            source("b", "x"),
        ));
        bindings.push((
            CustodyKey {
                instance: 2,
                handle: 1,
            },
            source("a", "x"),
        ));
        // A third instance, bound to the plain source, for the depth arm.
        scrubs.push((3, Arc::new(Scrub::new())));
        bindings.push((
            CustodyKey {
                instance: 3,
                handle: 1,
            },
            source("plain", "x"),
        ));
    }
    let plain = Arc::new(Plain {
        calls: AtomicUsize::new(0),
    });
    world.sources.lock().expect("sources").push((
        "plain",
        SecretSource {
            instance: 50,
            port: Arc::clone(&plain) as Arc<dyn SecretPort>,
        },
    ));

    // Instance 1 resolves its handle: B is called, B's nested Need names A, and custody refuses Cycle there.
    let top = ready(custody.resolve(&caller(1), 1));
    assert!(top.is_err(), "the chain does not resolve");
    assert_eq!(
        *inner.lock().expect("inner"),
        Some(CustodyDenied::Cycle),
        "refused Cycle at the second hop"
    );
    assert_eq!(b.calls.load(Ordering::SeqCst), 1, "B ran once");
    assert_eq!(
        a.calls.load(Ordering::SeqCst),
        0,
        "A is never called back: no recursion"
    );

    // Depth 5: four callers are already on the stack, so the fifth hop is refused before any plugin is called.
    let mut deep = caller(3);
    deep.stack = CallStack {
        ids: [11, 12, 13, 14],
        depth: 4,
    };
    assert_eq!(
        ready(custody.resolve(&deep, 1)).err(),
        Some(CustodyDenied::Cycle),
        "depth 5"
    );
    assert_eq!(
        plain.calls.load(Ordering::SeqCst),
        0,
        "no secret instance was called"
    );
    // One below the ceiling resolves: depth 3 is admitted.
    let mut shallow = caller(3);
    shallow.stack = CallStack {
        ids: [11, 12, 13, 0],
        depth: 3,
    };
    ready(custody.resolve(&shallow, 1)).expect("depth 4 total is allowed");
    assert_eq!(plain.calls.load(Ordering::SeqCst), 1);
}

/// The fixture C-SECRET-FOREIGN shares: one custody, one instance (id 1) with the given handles bound.
pub(crate) fn fixture(bound: &[(u64, u32)]) -> (Arc<Custody<Host>>, Arc<World>) {
    let world = Arc::new(World::default());
    let custody = Arc::new(Custody::new(Host {
        world: Arc::clone(&world),
        base: Instant::now(),
    }));
    let plain = Arc::new(Plain {
        calls: AtomicUsize::new(0),
    });
    world.sources.lock().expect("sources").push((
        "plain",
        SecretSource {
            instance: 50,
            port: plain as Arc<dyn SecretPort>,
        },
    ));
    for &(instance, handle) in bound {
        world
            .scrubs
            .lock()
            .expect("scrubs")
            .push((instance, Arc::new(Scrub::new())));
        world
            .bindings
            .lock()
            .expect("bindings")
            .push((CustodyKey { instance, handle }, source("plain", "x")));
    }
    (custody, world)
}

/// How many `HandleForeign` rows custody wrote.
pub(crate) fn foreign_rows(world: &World) -> usize {
    world
        .audits
        .lock()
        .expect("audits")
        .iter()
        .filter(|(_, _, event)| *event == CustodyEvent::HandleForeign)
        .count()
}
