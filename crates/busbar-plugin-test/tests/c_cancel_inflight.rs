// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-INFLIGHT (ABI-MIN3-INTERFACE §14): Hand-polled boot and reconfigure futures dropped after every poll
//! boundary (§10.5; round 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The sibling test drives the registry's `open_export` (the boot open) and `reconfigure` futures by hand with a
//! counting waker over [`YieldNeeds`], a `FakeNeeds` whose FETCH answer is Pending once, so every NEED step of the
//! fixture's `open` chain ends a poll. It carries arms (a), (b), (d) and (e) for `open` and the reconfigure
//! future as far as the branch can observe them; the arm itself stays ignored for what it cannot.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, ThreadId};

use busbar_plugin_abi::host_side::caller::{Caller, InstanceLimits};
use busbar_plugin_abi::host_side::needs::{
    ConnId, DirNeed, FetchNeed, NeedErr, NeedOut, Needs, OpenNeed, RecordNeed, TlsMode,
};
use busbar_plugin_abi::host_side::HOST;
use busbar_plugin_abi::plugin::{Glue, Plugin};
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::admit::admit_header;
use busbar_plugin_loader::instance::{
    Ceilings, InstanceSpec, OpenError, OpenedPort, Reconfigured, Registry,
};
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::MemBinder;
use busbar_ports::binder::ConfigBinder;

#[test]
#[ignore = "blocked (re-checked 2026-11-16): the pool acquire/release log the case instruments does not exist (busbar-plugin-abi host_side/pool.rs exposes only the misses()/drops() counters, no per-buffer acquire/release hook), so (a)'s order `req`, both OutBufs and `results` released zeroed, then `release`, then the lease, and 'a second chain never reacquires a buffer of the dropped chain before it is released' cannot be observed; arm (c) needs a MIN-3 `migrate` entry, which the branch does not have (busbar-ffi header.rs `entries()` = describe/open/resume/cancel/close; plugin-loader registry.rs `migrate` is the 1.x door path). Arms (a), (b), (d), (e) for `open` and the reconfigure future run as the sibling test below"]
fn every_poll_boundary_drop_cancels_or_closes_exactly_once() {
    todo!("owner: W1-H1 (C-CANCEL-INFLIGHT)")
}

// ---------------------------------------------------------------------------------------------------------
// Shared with c_panic_cancel: a Needs that ends a poll at every FETCH, a counting waker, a registry rig.
// ---------------------------------------------------------------------------------------------------------

/// `FakeNeeds` (every answer from its script, synchronously) whose FETCH future is Pending once, waking its
/// waker, before it answers: a chain's NEED step that FETCHes always ends the driver's poll. `release` calls
/// `on_release` first, so a case can order it against the plugin's own events.
pub(crate) struct YieldNeeds {
    inner: FakeNeeds,
    on_release: fn(),
}

impl YieldNeeds {
    pub(crate) fn new(on_release: fn()) -> Self {
        YieldNeeds {
            inner: FakeNeeds::new(),
            on_release,
        }
    }
}

/// Pending once (after waking the waker), then the wrapped answer.
struct Late<F> {
    parked: bool,
    answer: Pin<Box<F>>,
}

impl<F: Future> Future for Late<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        if !self.parked {
            self.parked = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.answer.as_mut().poll(cx)
    }
}

impl Needs for YieldNeeds {
    fn open(
        &self,
        cx: &Caller<'_>,
        n: OpenNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::open(&self.inner, cx, n, res)
    }

    fn starttls(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        tls: TlsMode<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::starttls(&self.inner, cx, c, tls, res)
    }

    fn write(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        bytes: &[u8],
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::write(&self.inner, cx, c, bytes, res)
    }

    fn read(
        &self,
        cx: &Caller<'_>,
        c: ConnId,
        max: u32,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::read(&self.inner, cx, c, max, res)
    }

    fn close(&self, cx: &Caller<'_>, c: ConnId, reusable: bool) -> impl Future<Output = ()> + Send {
        <FakeNeeds as Needs>::close(&self.inner, cx, c, reusable)
    }

    fn fetch(
        &self,
        cx: &Caller<'_>,
        n: FetchNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        Late {
            parked: false,
            answer: Box::pin(<FakeNeeds as Needs>::fetch(&self.inner, cx, n, res)),
        }
    }

    fn secret(
        &self,
        cx: &Caller<'_>,
        handle: u32,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::secret(&self.inner, cx, handle, res)
    }

    fn record(
        &self,
        cx: &Caller<'_>,
        n: RecordNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::record(&self.inner, cx, n, res)
    }

    fn directory(
        &self,
        cx: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send {
        <FakeNeeds as Needs>::directory(&self.inner, cx, n, res)
    }

    fn release(&self, cx: &Caller<'_>) {
        (self.on_release)();
        <FakeNeeds as Needs>::release(&self.inner, cx);
    }
}

/// A waker that counts its wakes.
pub(crate) struct Wakes(AtomicUsize);

impl std::task::Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A counting waker and its counter.
pub(crate) fn counting_waker() -> (Waker, Arc<Wakes>) {
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    (Waker::from(Arc::clone(&wakes)), wakes)
}

impl Wakes {
    pub(crate) fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// One poll of `fut` with `waker`, on this thread.
pub(crate) fn poll_once<T>(
    fut: &mut Pin<Box<dyn Future<Output = T> + Send + '_>>,
    waker: &Waker,
) -> Poll<T> {
    fut.as_mut().poll(&mut Context::from_waker(waker))
}

/// A `Registry<YieldNeeds>` over the real `HOST` and a `MemBinder`, with `plugin` admitted; and its identity.
pub(crate) fn rig(
    plugin: &'static Plugin,
    on_release: fn(),
) -> (Registry, Arc<YieldNeeds>, String) {
    let binder: Arc<dyn ConfigBinder> = Arc::new(MemBinder::new());
    let process = crate::process_resources();
    let mut images = busbar_plugin_loader::instance::ImagesBuilder::new(
        &HOST,
        Arc::clone(process.slots()),
        Ceilings::DEFAULT,
    );
    let admitted = admit_header(plugin).expect("the fixture image is admitted");
    let identity = admitted.identity().to_owned();
    images
        .admit(admitted)
        .expect("the fixture image is described");
    let needs = Arc::new(YieldNeeds::new(on_release));
    let registry = Registry::new(images.finish(), binder, Arc::clone(process.ids()));
    (registry, needs, identity)
}

/// The spec of instance `name` of `identity` with `config`, no limits, no public URL, no caller upstreams.
pub(crate) fn spec<'a>(identity: &'a str, name: &'a str, config: &'a [u8]) -> InstanceSpec<'a> {
    InstanceSpec {
        store_migration: None,
        purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
        identity,
        name,
        config_json: config,
        limits: InstanceLimits::default(),
        public_url: None,
        caller_upstreams: &[],
    }
}

// ---------------------------------------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------------------------------------

/// An export image whose `open` FETCHes `needs` times (each a NEED step) and then answers OK + INSTANCE, or
/// REFUSED with `"end": "refuse"`. It logs, in one process-wide list: `Cancel` when its open future is dropped
/// before it finished (the plugin side of `cancel(null, tok)`), `Opened` when `open` answered OK, `Close` when
/// the plugin value drops (the plugin side of `close(inst)`), each with the thread it ran on; the rig's
/// `YieldNeeds` logs `Release`. No `unsafe`: the glue is `plugin!`'s output.
pub(crate) mod fixture {
    use std::collections::HashMap;
    use std::sync::{Mutex, PoisonError};
    use std::thread::{self, ThreadId};

    use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID};
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::need::{self, Fetch};
    use busbar_plugin_abi::need::{egress, ChainBytes, TrustHandle};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{tag as record, Records, Reply, Writer};
    use busbar_plugin_abi::Export;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Event {
        Cancel(ThreadId),
        Opened(ThreadId),
        Close(ThreadId),
        Release,
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

    fn note(event: Event) {
        EVENTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }

    /// Every event since the last call, in order.
    pub fn take() -> Vec<Event> {
        std::mem::take(&mut *EVENTS.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The rig's `on_release`.
    pub fn released() {
        note(Event::Release);
    }

    /// Held by the open future across its NEEDs: dropped armed = the future was cancelled.
    struct Armed(bool);

    impl Drop for Armed {
        fn drop(&mut self) {
            if self.0 {
                note(Event::Cancel(thread::current().id()));
            }
        }
    }

    pub struct Inflight;

    impl Drop for Inflight {
        fn drop(&mut self) {
            note(Event::Close(thread::current().id()));
        }
    }

    /// (`needs`, `refuse`) from the config: `{"needs": "<n>", "end": "refuse"}`, both optional.
    fn mode(config: &[u8]) -> Result<(u32, bool), Fail> {
        let map = busbar_contract::json::parse::<HashMap<String, String>>(config)
            .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))?;
        let needs = match map.get("needs") {
            Some(n) => n
                .parse::<u32>()
                .map_err(|_| Fail::refused_because(R_CONFIG, "needs must be a count"))?,
            None => 0,
        };
        Ok((needs, map.get("end").is_some_and(|end| end == "refuse")))
    }

    impl Open for Inflight {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let (needs, refuse) = config.with(mode)?;
            let mut armed = Armed(true);
            for _ in 0..needs {
                let req = Fetch {
                    method: "GET",
                    url: "https://inflight.test/step",
                    headers: &[],
                    body: &[],
                    max_body: 64,
                    trust: TrustHandle::NONE,
                    cert: None,
                    egress: egress::OPEN_WEB,
                };
                let _ = need::fetch(&req).await;
            }
            armed.0 = false;
            if refuse {
                return Err(Fail::refused_because(R_INVALID, "refused by mode"));
            }
            note(Event::Opened(thread::current().id()));
            Ok(Inflight)
        }

        fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            mode(config).map(|_| ())
        }

        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.methods(busbar_plugin_abi::export::M_DELIVER);
            d.item(
                busbar_plugin_abi::export::tag::D_STREAMS,
                &[busbar_plugin_abi::export::STREAM_LOGS as u8],
            );
        }
    }

    impl Export for Inflight {
        async fn deliver(
            &self,
            _h: &'static Host,
            _stream: u32,
            _delivery: u64,
            _attempt: u32,
            _lines: u32,
            batch: ChainBytes,
        ) -> Result<Reply, Fail> {
            let accepted = batch.with(|bytes| {
                Records::new(bytes)
                    .filter(|rec| matches!(rec, Ok(rec) if rec.tag == record::TEXT))
                    .count() as u64
            });
            let mut reply = Reply::new();
            reply
                .put_pod(
                    busbar_plugin_abi::export::tag::ACK,
                    &busbar_plugin_abi::export::Ack { accepted },
                )
                .map_err(Fail::from)?;
            Ok(reply)
        }
    }

    busbar_plugin_abi::plugin!(Export, Inflight, name: "fixture-cancel-inflight");
}

use fixture::Event::{self, Cancel, Close, Opened, Release};

/// Live chains in the fixture image's open slab (`count_live` over `plugin!`'s `GLOBAL`).
fn open_slab_live() -> u32 {
    <fixture::Inflight as Glue>::global().count_live()
}

/// Serialises the arms: the fixture's event list and open slab are process-wide.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn here() -> ThreadId {
    thread::current().id()
}

/// Polls `fut` `n` times; every poll must end Pending with the chain parked in the open slab.
fn pending_polls<T>(
    what: &str,
    fut: &mut Pin<Box<dyn Future<Output = T> + Send + '_>>,
    waker: &Waker,
    n: usize,
) {
    for k in 1..=n {
        assert!(
            poll_once(fut, waker).is_pending(),
            "{what}: poll {k} must end Pending at the step's NEED"
        );
        assert_eq!(
            open_slab_live(),
            1,
            "{what}: after poll {k} exactly one open chain is parked"
        );
        assert!(
            fixture::take().is_empty(),
            "{what}: a NEED step neither cancels, closes nor releases"
        );
    }
}

/// (a) at every boundary: dropped right after the poll whose step answered NEED + TOKEN, the chain is cancelled
/// exactly once, inline on the dropping thread, before `release`, and nothing is closed.
fn assert_cancelled_once(what: &str) {
    assert_eq!(
        fixture::take(),
        [Cancel(here()), Release],
        "{what}: exactly one cancel, inline on the dropping thread, then release; no close"
    );
    assert_eq!(open_slab_live(), 0, "{what}: the open slab holds no chain");
}

#[test]
fn every_open_and_reconfigure_boundary_drop_cancels_or_closes_exactly_once() {
    let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let (registry, needs, identity) = rig(fixture::PLUGIN.plugin(), fixture::released);
    let (waker, wakes) = counting_waker();
    fixture::take();

    // (a): a two-NEED open dropped after the start step's poll, then after the first resume's poll.
    let two = br#"{"needs":"2"}"#;
    for cut in 1..=2 {
        let what = format!("open, dropped after poll {cut}");
        let spec = spec(&identity, "cut", two);
        let mut fut = registry.open_export(
            &spec,
            &needs,
            &busbar_plugin_test::suites::harness::no_refs(),
        );
        pending_polls(&what, &mut fut, &waker, cut);
        drop(fut);
        assert_cancelled_once(&what);
    }

    // (e): the same open driven on: the resume that answered OK + INSTANCE is the poll that built the Instance
    // (Ready in that poll, no Pending between); no cancel; dropping it closes exactly once, inline.
    let before = wakes.count();
    let spec_two = spec(&identity, "two", two);
    let mut fut = registry.open_export(
        &spec_two,
        &needs,
        &busbar_plugin_test::suites::harness::no_refs(),
    );
    pending_polls("open (e)", &mut fut, &waker, 2);
    let port = match poll_once(&mut fut, &waker) {
        Poll::Ready(Ok(port)) => port,
        Poll::Ready(Err(e)) => panic!("open (e): the open answered {e:?}"),
        Poll::Pending => {
            panic!("open (e): the poll whose resume answered OK + INSTANCE must be Ready")
        }
    };
    assert_eq!(
        wakes.count() - before,
        2,
        "open (e): the counting waker saw one wake per NEED boundary"
    );
    assert_eq!(
        fixture::take(),
        [Opened(here()), Release],
        "open (e): OK + INSTANCE after NEEDs: released once, no cancel"
    );
    drop(fut);
    assert!(
        fixture::take().is_empty(),
        "open (e): the finished future holds nothing to cancel or close"
    );
    drop(port);
    assert_eq!(
        fixture::take(),
        [Close(here())],
        "open (e): dropping the Instance closes it exactly once, inline"
    );
    assert_eq!(
        open_slab_live(),
        0,
        "open (e): the open slab holds no chain"
    );

    // (b): a start step that answered OK + INSTANCE: Ready in the first poll; one close on drop, no release.
    let spec_now = spec(&identity, "now", b"{}");
    let mut fut = registry.open_export(
        &spec_now,
        &needs,
        &busbar_plugin_test::suites::harness::no_refs(),
    );
    let port = match poll_once(&mut fut, &waker) {
        Poll::Ready(Ok(port)) => port,
        Poll::Ready(Err(e)) => panic!("open (b): the open answered {e:?}"),
        Poll::Pending => {
            panic!("open (b): the poll whose start answered OK + INSTANCE must be Ready")
        }
    };
    drop(fut);
    assert_eq!(
        fixture::take(),
        [Opened(here())],
        "open (b): no NEED, no release, no cancel"
    );
    drop(port);
    assert_eq!(
        fixture::take(),
        [Close(here())],
        "open (b): exactly one close, inline"
    );

    // (d): REFUSED at the start step and after a NEED: neither cancel nor close.
    for (config, polls, released) in [
        (&br#"{"end":"refuse"}"#[..], 0, false),
        (&br#"{"needs":"1","end":"refuse"}"#[..], 1, true),
    ] {
        let what = format!("open (d) after {polls} NEED(s)");
        let spec = spec(&identity, "refused", config);
        let mut fut = registry.open_export(
            &spec,
            &needs,
            &busbar_plugin_test::suites::harness::no_refs(),
        );
        pending_polls(&what, &mut fut, &waker, polls);
        match poll_once(&mut fut, &waker) {
            Poll::Ready(Err(OpenError::Call(e))) => {
                panic!("{what}: a REFUSED open is the plugin's answer, not {e:?}")
            }
            Poll::Ready(Err(_)) => {}
            Poll::Ready(Ok(_)) => panic!("{what}: the open must be refused"),
            Poll::Pending => panic!("{what}: the REFUSED step's poll must be Ready"),
        }
        drop(fut);
        let expected: &[Event] = if released { &[Release] } else { &[] };
        assert_eq!(
            fixture::take(),
            expected,
            "{what}: neither cancel nor close"
        );
        assert_eq!(open_slab_live(), 0, "{what}: the open slab holds no chain");
    }

    // The reconfigure future: an open instance, then a reconfigure whose open NEEDs, dropped after its poll.
    let spec_live = spec(&identity, "live", b"{}");
    let mut fut = registry.open_export(
        &spec_live,
        &needs,
        &busbar_plugin_test::suites::harness::no_refs(),
    );
    let live = match poll_once(&mut fut, &waker) {
        Poll::Ready(Ok(port)) => port,
        Poll::Ready(Err(e)) => panic!("reconfigure: the first open answered {e:?}"),
        Poll::Pending => panic!("reconfigure: the first open must be Ready"),
    };
    drop(fut);
    fixture::take();
    let patch = br#"{"needs":"1"}"#;
    let mut fut = registry.reconfigure(KindCode::Export, "live", patch, 1);
    pending_polls("reconfigure, dropped", &mut fut, &waker, 1);
    drop(fut);
    assert_cancelled_once("reconfigure, dropped");

    // Driven on, it answers the new instance in the resume's poll; the old one is untouched until dropped.
    let mut fut = registry.reconfigure(KindCode::Export, "live", patch, 1);
    pending_polls("reconfigure (e)", &mut fut, &waker, 1);
    let opened = match poll_once(&mut fut, &waker) {
        Poll::Ready(Ok(Reconfigured::Opened(OpenedPort::Export(port)))) => port,
        Poll::Ready(Ok(_)) => panic!("reconfigure (e): not an opened export"),
        Poll::Ready(Err(e)) => panic!("reconfigure (e): answered {e:?}"),
        Poll::Pending => panic!("reconfigure (e): the resume's poll must be Ready"),
    };
    drop(fut);
    assert_eq!(
        fixture::take(),
        [Opened(here()), Release],
        "reconfigure (e): released once, no cancel, no close"
    );
    drop(opened);
    assert_eq!(
        fixture::take(),
        [Close(here())],
        "reconfigure (e): the new instance closes once"
    );
    drop(live);
    assert_eq!(
        fixture::take(),
        [Close(here())],
        "reconfigure: the old instance closes once"
    );
    assert_eq!(
        open_slab_live(),
        0,
        "reconfigure: the open slab holds no chain"
    );
}
